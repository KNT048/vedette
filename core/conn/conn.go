// Package conn is the store of connections to devices and services (D-93, D-94): HTTP APIs, SSH, RESTCONF, automation
// platforms and MCP servers that response actions and, later, the AI reach. It validates and saves a connection with its
// allow-list and tools, keeps its credential encrypted in core_secret, and answers who may do what with it. Nothing here
// opens a network connection: the transports come with slice 13b-5, and they alone decrypt a credential (internal/cred).
//
// A secret never leaves in any value this package returns: a Connection carries the last 4 characters of a token or
// password, or the fingerprint of the public half of an SSH key, and nothing else.
package conn

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/conn/internal/cred"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// Connection is a saved connection as the API shows it (web/src/features/core/contract.ts Connector).
type Connection struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	Target   string   `json:"target"`
	AssetID  *string  `json:"asset_id"`
	Auth     Auth     `json:"auth"`
	Username *string  `json:"username"`
	Pin      *Pin     `json:"pin"`
	Allow    []string `json:"allow"`
	Tools    []Tool   `json:"tools"`
	Enabled  bool     `json:"enabled"`
	Status   string   `json:"status"`
	LastTest *string  `json:"last_test"`

	// UpdatedAt moves only when a field that decides what a request may do changes (D-93 (4)); it is part of Fingerprint.
	UpdatedAt string `json:"-"`
	secretID  *string
}

func (c Connection) hasSecret() bool { return c.secretID != nil }

// Auth is how the box signs in. Last4 is set for a token or password, KeyFingerprint for an SSH key; never both.
type Auth struct {
	Type           string  `json:"type"`
	Last4          *string `json:"last4"`
	KeyFingerprint *string `json:"key_fingerprint"`
}

// Pin is what the first Test trusted (D-94): the public key of the leaf certificate of an HTTPS server that no public authority
// vouches for (Kind tls_sha256, Value the SHA-256 of its SubjectPublicKeyInfo, 64 hex characters), the fact that a public authority
// did vouch for it (Kind tls_roots, Value "system roots": every later Test requires a valid chain, and a self-signed certificate is
// refused), or the host key of an SSH server (Kind ssh_hostkey, Value "<type> SHA256:..."). Trust on first use happens only while
// there is no pin; "Forget pinned key" (clear_pin) is the way back to a first use.
type Pin struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	FirstSeen string `json:"first_seen"`
}

// Tool is something a connection can do. Read tools only look; a write tool starts off and runs only through an approved
// response action.
type Tool struct {
	Name        string `json:"name"`
	Access      string `json:"access"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// Input is what an administrator sends to add or change a connection.
type Input struct {
	Name     string
	Kind     string
	Target   string
	AssetID  *string
	AuthType string
	Secret   secrets.Value // unset on an edit keeps the saved one; prints, formats and marshals as a placeholder
	Username *string
	ClearPin bool
	Allow    []string
	Enabled  bool
	Tools    []ToolInput // tools not listed keep their state
}

// ToolInput turns one tool on or off. Access may be set for an MCP server only.
type ToolInput struct {
	Name    string
	Enabled bool
	Access  *string
}

// Config wires a Service. DB, Secrets and Audit are required.
type Config struct {
	DB      *store.DB
	Secrets *secrets.Store
	Audit   *audit.Log
	Clock   func() time.Time // nil: time.Now
	// InUse says whether a change made through the connection is still in force on a device (response.ChangesInForce); a
	// connection in that state cannot be deleted. nil: nothing is ever in force.
	InUse func(ctx context.Context, id string) (bool, error)
	// BoxAddrs lists the addresses of the box itself and the subnets that only the box lives in (a /32 or /128 is one address), which
	// no connection may point at (D-94). cmd/vedette builds it from several sources; slice 13b-5 asks it again at dial time. nil: none known.
	BoxAddrs func(ctx context.Context) []netip.Prefix
	// AssetExists says whether an inventory device exists, for the asset a connection is linked to. nil: not checked.
	AssetExists func(ctx context.Context, id string) (bool, error)
}

// Service reads and writes connections.
type Service struct {
	cfg   Config
	now   func() time.Time
	vault *cred.Vault
	// testBudget replaces the time a whole Test may take; tests shorten it. 0 is testBudget(kind).
	testBudget time.Duration
	// roots replaces the system roots in tests (a test cannot add to them); nil in the product.
	roots *x509.CertPool
}

// New returns the Service.
func New(c Config) (*Service, error) {
	if c.DB == nil || c.Secrets == nil || c.Audit == nil {
		return nil, errors.New("conn: Config needs DB, Secrets and Audit")
	}
	// The credential purpose is restricted in c.Secrets: from here on only the vault, which only this package holds, reads it.
	v, err := cred.New(c.Secrets)
	if err != nil {
		return nil, fmt.Errorf("conn: restrict credential purpose: %w", err)
	}
	s := &Service{cfg: c, now: c.Clock, vault: v}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// Fingerprint is what a request remembers of a connection to notice that it changed (response INV-9): id, kind, address and
// the moment a security field last changed. Editing the name, the status or the last test result does not change it;
// editing the secret does.
func Fingerprint(id, kind, target, updatedAt string) string {
	h := sha256.Sum256([]byte(id + "\x00" + kind + "\x00" + target + "\x00" + updatedAt))
	return hex.EncodeToString(h[:16])
}

// Fingerprint of this connection.
func (c Connection) Fingerprint() string { return Fingerprint(c.ID, c.Kind, c.Target, c.UpdatedAt) }

// WriteTools names the write tools that are on.
func WriteTools(c Connection) []string {
	out := []string{}
	for _, t := range c.Tools {
		if t.Access == "write" && t.Enabled {
			out = append(out, t.Name)
		}
	}
	return out
}

// NotReady says in plain words why a request cannot use the connection yet, or "" when it can: it is turned off, or it was
// never tested (so no certificate or host key is pinned and nothing proves the address answers), or the last test failed.
func NotReady(c Connection) string {
	switch {
	case !c.Enabled:
		return "The connection is turned off."
	case c.Status == "untested":
		return "The connection was never tested. Test it first."
	case c.Status != "ok":
		return "The last test of the connection failed."
	case c.Kind == KindSSH && c.Pin == nil:
		return "The SSH host key is not pinned yet. Test the connection first."
	}
	return ""
}

func notFound() *apierr.Error {
	return apierr.New(404, apierr.CodeNotFound, "This connection no longer exists.")
}

// List returns every connection, oldest first.
func (s *Service) List(ctx context.Context) ([]Connection, error) {
	return list(ctx, coredb.New(s.cfg.DB.Reader()))
}

// Get returns one connection; an unknown id is 404 not_found.
func (s *Service) Get(ctx context.Context, id string) (Connection, error) {
	return get(ctx, coredb.New(s.cfg.DB.Reader()), id)
}

// HasEnabled says whether at least one enabled connection exists: requests may go to an address an administrator typed
// (PRIVACY flow 12).
func (s *Service) HasEnabled(ctx context.Context) (bool, error) {
	return coredb.New(s.cfg.DB.Reader()).AnyEnabledConnection(ctx)
}

func (s *Service) env(ctx context.Context, q *coredb.Queries, selfID string) (checkEnv, *error) {
	var first error
	e := checkEnv{
		nameTaken: func(name string) bool {
			taken, err := q.ConnectionNameTaken(ctx, coredb.ConnectionNameTakenParams{NameKey: nameKey(name), ID: selfID})
			if err != nil && first == nil {
				first = err
			}
			return taken
		},
	}
	if s.cfg.BoxAddrs != nil {
		e.box = s.cfg.BoxAddrs(ctx)
	}
	if s.cfg.AssetExists != nil {
		e.assetUnknown = func(id string) bool {
			ok, err := s.cfg.AssetExists(ctx, id)
			if err != nil && first == nil {
				first = err
			}
			return !ok && err == nil
		}
	}
	return e, &first
}

// Create saves a new connection inside the caller's write transaction, with its audit row (connection.create). Write tools
// start off. An invalid input is a 400 *apierr.Error naming the field.
func (s *Service) Create(ctx context.Context, tx *sql.Tx, actor string, in Input) (Connection, error) {
	q := coredb.New(tx)
	env, first := s.env(ctx, q, "")
	chk, verr := check(in, nil, env)
	if *first != nil {
		return Connection{}, fmt.Errorf("conn: check: %w", *first)
	}
	if verr != nil {
		return Connection{}, verr
	}
	n, err := q.CountConnections(ctx)
	if err != nil {
		return Connection{}, fmt.Errorf("conn: count: %w", err)
	}
	if n >= MaxConnections {
		return Connection{}, apierr.New(400, "too_many", fmt.Sprintf("A box holds up to %d connections. Delete one you no longer use.", MaxConnections))
	}
	row := coredb.InsertConnectionParams{
		ID: store.NewID("cn"), Name: chk.name, NameKey: nameKey(chk.name), Kind: chk.kind, Target: chk.target, AssetID: chk.assetID, AuthType: chk.authType,
		Username: chk.username, KeyFp: chk.keyFP, Allow: encodeAllow(chk.allow), Enabled: chk.enabled, Status: "untested",
		UpdatedAt: store.FormatTS(s.now()),
	}
	if chk.secret.IsSet() {
		id, err := s.vault.Seal(ctx, tx, []byte(chk.secret.Reveal()), chk.authType != AuthKey)
		if err != nil {
			return Connection{}, fmt.Errorf("conn: seal secret: %w", err)
		}
		row.SecretID = &id
	}
	if err := q.InsertConnection(ctx, row); err != nil {
		if store.IsUniqueViolation(err) {
			return Connection{}, bad2DuplicateName()
		}
		return Connection{}, fmt.Errorf("conn: insert: %w", err)
	}
	tools := applyTools(builtinTools(chk.kind), chk.tools, chk.kind == KindMCP)
	if err := writeTools(ctx, q, row.ID, tools); err != nil {
		return Connection{}, err
	}
	detail := fmt.Sprintf("%s, %d write tools on", chk.kind, len(WriteTools(Connection{Tools: tools})))
	if chk.secret.IsSet() {
		detail += ", credential set"
	}
	if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: actor, Action: "connection.create", Target: chk.name, Detail: detail}); err != nil {
		return Connection{}, err
	}
	return get(ctx, q, row.ID)
}

func bad2DuplicateName() *apierr.Error {
	return bad("duplicate_name", "Another connection already has this name. Pick a different one.", "name")
}

// Update changes a connection inside the caller's write transaction, with its audit row (connection.update). A blank secret
// keeps the saved one, unless the server (host or port) or the kind changed. The pin is forgotten on ClearPin, on another
// kind or on another host or port, never because the sign-in changed. UpdatedAt moves only when a security field changed.
func (s *Service) Update(ctx context.Context, tx *sql.Tx, actor, id string, in Input) (Connection, error) {
	q := coredb.New(tx)
	cur, err := get(ctx, q, id)
	if err != nil {
		return Connection{}, err
	}
	env, first := s.env(ctx, q, id)
	chk, verr := check(in, &cur, env)
	if *first != nil {
		return Connection{}, fmt.Errorf("conn: check: %w", *first)
	}
	if verr != nil {
		return Connection{}, verr
	}
	next := cur
	next.Name, next.Kind, next.Target, next.AssetID = chk.name, chk.kind, chk.target, chk.assetID
	next.Username, next.Enabled, next.Allow = chk.username, chk.enabled, chk.allow
	next.Auth.Type = chk.authType
	if chk.retarget {
		next.Status = "untested"
	}
	if chk.clearPin || chk.moved {
		next.Pin = nil
	}
	base := cur.Tools
	if chk.kind != cur.Kind {
		base = builtinTools(chk.kind)
	}
	next.Tools = applyTools(base, chk.tools, chk.kind == KindMCP)

	secretChanged, dropSecret := false, (*string)(nil)
	switch {
	case chk.authType == AuthNone:
		if cur.secretID != nil {
			secretChanged, dropSecret = true, cur.secretID
		}
		next.secretID, next.Auth.KeyFingerprint = nil, nil
	case chk.secret.IsSet():
		keep := chk.authType != AuthKey
		if cur.secretID != nil {
			if err := s.vault.Replace(ctx, tx, *cur.secretID, []byte(chk.secret.Reveal()), keep); err != nil {
				return Connection{}, fmt.Errorf("conn: replace secret: %w", err)
			}
		} else {
			sid, err := s.vault.Seal(ctx, tx, []byte(chk.secret.Reveal()), keep)
			if err != nil {
				return Connection{}, fmt.Errorf("conn: seal secret: %w", err)
			}
			next.secretID = &sid
		}
		secretChanged = true
		next.Auth.KeyFingerprint = chk.keyFP
	}

	changed := changedSecurityFields(cur, next, secretChanged)
	next.UpdatedAt = cur.UpdatedAt
	if len(changed) > 0 {
		next.UpdatedAt = s.nextStamp(cur.UpdatedAt)
	}
	n, err := q.UpdateConnection(ctx, updateParams(next))
	if err != nil {
		if store.IsUniqueViolation(err) {
			return Connection{}, bad2DuplicateName()
		}
		return Connection{}, fmt.Errorf("conn: update: %w", err)
	}
	if n == 0 {
		return Connection{}, notFound()
	}
	if dropSecret != nil {
		if err := s.vault.Delete(ctx, tx, *dropSecret); err != nil {
			return Connection{}, fmt.Errorf("conn: delete secret: %w", err)
		}
	}
	if !slices.Equal(cur.Tools, next.Tools) {
		if err := q.DeleteConnectionTools(ctx, id); err != nil {
			return Connection{}, fmt.Errorf("conn: tools: %w", err)
		}
		if err := writeTools(ctx, q, id, next.Tools); err != nil {
			return Connection{}, err
		}
	}
	detail := "no security change"
	if len(changed) > 0 {
		detail = "changed: " + strings.Join(changed, ", ")
	}
	if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: actor, Action: "connection.update", Target: next.Name, Detail: detail}); err != nil {
		return Connection{}, err
	}
	return get(ctx, q, id)
}

// nextStamp is the new updated_at: now, and always later than the old one, so two changes in the same millisecond still
// give two fingerprints.
func (s *Service) nextStamp(old string) string {
	t := s.now().UTC().Truncate(time.Millisecond)
	if o, err := time.Parse(time.RFC3339Nano, old); err == nil && !t.After(o) {
		t = o.Add(time.Millisecond)
	}
	return store.FormatTS(t)
}

// changedSecurityFields names the fields that moved among those that decide what a request may do (D-93 (4)): kind,
// target, sign-in type, user name, the secret, the pin, the allow-list, and a tool's enabled or access. Not the name, the
// linked asset, the connection's own switch, the status or the last test.
func changedSecurityFields(a, b Connection, secretChanged bool) []string {
	var out []string
	add := func(changed bool, name string) {
		if changed {
			out = append(out, name)
		}
	}
	add(a.Kind != b.Kind, "kind")
	add(a.Target != b.Target, "target")
	add(a.Auth.Type != b.Auth.Type, "auth_type")
	add(deref(a.Username) != deref(b.Username), "username")
	add(secretChanged, "secret")
	add(pinValue(a.Pin) != pinValue(b.Pin), "pin") // the value, not only whether there is one: a pin that changed is another server
	add(!slices.Equal(a.Allow, b.Allow), "allow")
	add(!slices.Equal(a.Tools, b.Tools), "tools")
	return out
}

// Delete removes a connection and its secret in the caller's write transaction, with its audit row (connection.delete).
// While a change made through it is still in force on a device it is 409 in_use.
func (s *Service) Delete(ctx context.Context, tx *sql.Tx, actor, id string) error {
	q := coredb.New(tx)
	cur, err := get(ctx, q, id)
	if err != nil {
		return err
	}
	if s.cfg.InUse != nil {
		inUse, err := s.cfg.InUse(ctx, id)
		if err != nil {
			return fmt.Errorf("conn: in use: %w", err)
		}
		if inUse {
			return apierr.New(409, "in_use", "A change made through "+cur.Name+" is still in force. Roll it back in Response, or wait until it expires, then delete the connection.")
		}
	}
	if err := q.DeleteConnectionTools(ctx, id); err != nil {
		return fmt.Errorf("conn: delete tools: %w", err)
	}
	if _, err := q.DeleteConnection(ctx, id); err != nil {
		return fmt.Errorf("conn: delete: %w", err)
	}
	if cur.secretID != nil {
		if err := s.vault.Delete(ctx, tx, *cur.secretID); err != nil {
			return fmt.Errorf("conn: delete secret: %w", err)
		}
	}
	return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: actor, Action: "connection.delete", Target: cur.Name, Detail: cur.Kind})
}

func pinValue(p *Pin) string {
	if p == nil {
		return ""
	}
	return p.Kind + ":" + p.Value
}

// nameKey is what two names are compared by: the name in lower case for every script (Unicode, not only ASCII), so "Ärger API" and
// "ärger API" are one name.
func nameKey(name string) string { return strings.ToLower(name) }
