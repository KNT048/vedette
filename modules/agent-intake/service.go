package agentintake

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
)

// Caps and timings of D-169 (2).
const (
	MaxTokens         = 50
	MaxNodesPerToken  = 500
	MaxNodes          = 5000
	enrollCooldown    = 60 * time.Second // the same (token, host_identifier) cannot enrol again sooner
	auditEnrollEvery  = 24 * time.Hour   // one enrol audit row per node per day
	touchEvery        = time.Minute      // last_seen is written at most this often per node
	NodeSilentDays    = 90               // a node silent this long is deleted by the node-prune job
	expiredTokenGrace = 30 * 24 * time.Hour
	systemActor       = "system"
)

// Config is what New needs. DB, Audit, Sink and Software are required. Secrets and Conn are the Wazuh pull's (slice 4): without both,
// its routes answer 501 and its job does nothing.
type Config struct {
	DB       *store.DB
	Audit    *audit.Log
	Sink     observe.Sink         // the inventory: device observations (core/observe)
	Software observe.SoftwareSink // the inventory: the software list of a device
	Secrets  *secrets.Store       // the Wazuh password (purpose intake_wazuh.password)
	Conn     *conn.Service        // the HTTPS client and address policy of D-94 for the Wazuh server (D-305)
	Clock    func() time.Time
	Log      *slog.Logger
}

// Service is the osquery intake. Create it with New.
type Service struct {
	cfg  Config
	db   *store.DB
	fail *failLimiter
	node *nodeLimiter

	warnMu   sync.Mutex // guards lastWarn and replaced
	lastWarn map[string]time.Time
	replaced map[string]*replaceState // by source address: the last software replace (ingest.go allowReplace)

	wazuhRoots  *x509.CertPool // nil: the system's (tests replace it)
	wazuhSleep  func(ctx context.Context, d time.Duration) error
	wazuhPace   time.Duration
	wazuhBudget func(ctx context.Context) (context.Context, context.CancelFunc) // one pull's time (wazuhPullBudget; tests end it themselves)

	pruneMu   sync.Mutex
	pruneLast time.Time // the previous node-prune run; a long gap means the module was off (or the box down)
	onSince   time.Time // the start of the current unbroken run of node-prune runs
}

// New returns the service.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Sink == nil || cfg.Software == nil {
		return nil, errors.New("agentintake: New needs DB, Audit, Sink and Software")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	s := &Service{cfg: cfg, db: cfg.DB, lastWarn: map[string]time.Time{}, replaced: map[string]*replaceState{}}
	s.fail = newFailLimiter(s.now)
	s.node = newNodeLimiter(s.now)
	s.wazuhSleep, s.wazuhPace = sleepCtx, wazuhPace
	s.wazuhBudget = func(ctx context.Context) (context.Context, context.CancelFunc) {
		return context.WithTimeout(ctx, wazuhPullBudget)
	}
	return s, nil
}

func (s *Service) now() time.Time { return s.cfg.Clock().UTC() }

// errNodeInvalid is every credential failure: an unknown, revoked or expired token, a key that is not (or no longer) a node's, a request
// that is not shaped like one of ours. The handler answers 200 + node_invalid for it and never says which (D-169 (8)).
var errNodeInvalid = errors.New("agentintake: node invalid")

func hashHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// sameHash compares two hex hashes in constant time.
func sameHash(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func newNodeKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("agentintake: node key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil // 256 bits, 43 characters
}

func rateLimited(wait time.Duration) *apierr.Error {
	secs := max(1, int((wait+time.Second-1)/time.Second))
	return apierr.New(429, "rate_limited", "Too many requests. Try again later.").With("retry_after", secs)
}

func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, actor, action, target, detail string) error {
	if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: actor, Action: action, Target: target, Detail: detail}); err != nil {
		return fmt.Errorf("agentintake: audit: %w", err)
	}
	return nil
}

// warnUnmatched logs that a node's connection address is not among the IPv4 it declared, for a node at most once an hour: a node that
// stays unmatched must not fill the log.
func (s *Service) warnUnmatched(ctx context.Context, key string, args ...any) {
	now := s.now()
	s.warnMu.Lock()
	if len(s.lastWarn) > limiterKeys {
		clear(s.lastWarn)
	}
	last, seen := s.lastWarn[key]
	due := !seen || now.Sub(last) >= time.Hour
	if due {
		s.lastWarn[key] = now
	}
	s.warnMu.Unlock()
	if due {
		s.cfg.Log.WarnContext(ctx, "agent-intake: a node's address is not among the IPv4 it declared; nothing written to the inventory", args...)
	}
}

// ---- tokens: look-up ----

// tokenRow is the row of a token found by its secret.
type tokenRow struct {
	id, name string
	expires  time.Time // zero = never
	received time.Time // zero = never
}

func parseTS(s sql.NullString) time.Time {
	if !s.Valid {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s.String)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// tokenBySecret finds the token whose secret hashes to secret's hash; errNodeInvalid when there is none.
func (s *Service) tokenBySecret(ctx context.Context, q querier, secret string) (tokenRow, error) {
	want := hashHex(secret)
	var t tokenRow
	var got string
	var exp, rec sql.NullString
	err := q.QueryRowContext(ctx, `SELECT id, name, token_hash, expires_at, last_received FROM intake_agent_tokens WHERE token_hash = ?`, want).Scan(&t.id, &t.name, &got, &exp, &rec)
	if errors.Is(err, sql.ErrNoRows) {
		return tokenRow{}, errNodeInvalid
	}
	if err != nil {
		return tokenRow{}, fmt.Errorf("agentintake: read token: %w", err)
	}
	if !sameHash(got, want) {
		return tokenRow{}, errNodeInvalid
	}
	t.expires, t.received = parseTS(exp), parseTS(rec)
	return t, nil
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func (t tokenRow) expired(now time.Time) bool { return !t.expires.IsZero() && !now.Before(t.expires) }

// ---- enrol ----

// Enroll exchanges an enrolment token for a node key (D-169 (2)). The key is returned once and only its hash is kept. A bad token is
// errNodeInvalid and counts against the source (429 after 10 a minute); the same (token, host_identifier) cannot enrol again within
// 60 seconds; the caps are 500 nodes per token and 5,000 in all (429 too_many_nodes).
func (s *Service) Enroll(ctx context.Context, src netip.Addr, in enrollIn) (string, error) {
	key := srcKey(src)
	if w := s.fail.blocked(key); w > 0 {
		return "", rateLimited(w)
	}
	bad := func() (string, error) {
		s.fail.fail(key)
		s.logReject(ctx, "enroll", src, "credential")
		return "", errNodeInvalid
	}
	t, err := s.tokenBySecret(ctx, s.db.Reader(), in.secret)
	if errors.Is(err, errNodeInvalid) || (err == nil && t.expired(s.now())) {
		return bad()
	}
	if err != nil {
		return "", err
	}
	nodeKey, err := newNodeKey()
	if err != nil {
		return "", err
	}
	invalid := false
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		t, err := s.tokenBySecret(ctx, tx, in.secret) // again under the writer: a revoke may have come in between
		if err != nil || t.expired(s.now()) {
			invalid = true
			return nil
		}
		return s.enrollTx(ctx, tx, t, in, nodeKey)
	})
	switch {
	case err != nil:
		return "", err
	case invalid:
		return bad()
	}
	return nodeKey, nil
}

func (s *Service) enrollTx(ctx context.Context, tx *sql.Tx, t tokenRow, in enrollIn, nodeKey string) error {
	now := s.now()
	var oldID, oldEnrolled string
	err := tx.QueryRowContext(ctx, `SELECT id, enrolled_at FROM intake_osquery_nodes WHERE token_id = ? AND host_identifier = ?`, t.id, in.hostIdentifier).Scan(&oldID, &oldEnrolled)
	replaced := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("agentintake: read node: %w", err)
	}
	var oldAt time.Time
	if replaced {
		oldAt, _ = time.Parse(time.RFC3339Nano, oldEnrolled)
		if wait := enrollCooldown - now.Sub(oldAt); wait > 0 {
			return rateLimited(wait)
		}
	}
	var perToken, total int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE token_id = ?), count(*) FROM intake_osquery_nodes WHERE id <> ?`, t.id, oldID).Scan(&perToken, &total); err != nil {
		return fmt.Errorf("agentintake: count nodes: %w", err)
	}
	if perToken >= MaxNodesPerToken || total >= MaxNodes {
		return apierr.New(429, "too_many_nodes", "This enrollment token already has the most machines it can have. Revoke it and make a new one.").With("retry_after", 3600)
	}
	if replaced {
		if _, err := tx.ExecContext(ctx, `DELETE FROM intake_osquery_nodes WHERE id = ?`, oldID); err != nil {
			return fmt.Errorf("agentintake: replace node: %w", err)
		}
	}
	ts := store.FormatTS(now)
	if _, err := tx.ExecContext(ctx, `INSERT INTO intake_osquery_nodes (id, token_id, node_key_hash, host_identifier, hostname, platform, osquery_version, enrolled_at, last_seen) VALUES (?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), ?, ?)`,
		store.NewID("node"), t.id, hashHex(nodeKey), in.hostIdentifier, in.hostname, in.platform, in.osqueryVersion, ts, ts); err != nil {
		return fmt.Errorf("agentintake: insert node: %w", err)
	}
	if replaced && now.Sub(oldAt) < auditEnrollEvery { // one audit row per node per day (a flapping client must not fill core_audit)
		return nil
	}
	return s.auditTx(ctx, tx, systemActor, "inventory.agent_enroll", in.hostIdentifier, fmt.Sprintf("token %q, host %q", t.name, in.hostname))
}

// logReject is the server-side line of a refused credential: a reason code and the source address, never the secret or the key.
func (s *Service) logReject(ctx context.Context, op string, src netip.Addr, reason string) {
	s.cfg.Log.InfoContext(ctx, "agent-intake: credential refused", "op", op, "reason", reason, "src", src.String())
}

// ---- nodes: look-up and liveness ----

type nodeRow struct {
	id, tokenID string
	lastSeen    time.Time
	boundIP     netip.Addr
	boundMAC    string
}

// nodeByKey finds the node whose key hashes to the hash of key; errNodeInvalid when there is none.
func (s *Service) nodeByKey(ctx context.Context, key string) (nodeRow, error) {
	want := hashHex(key)
	var n nodeRow
	var got, seen string
	var ip, mac sql.NullString
	err := s.db.Reader().QueryRowContext(ctx, `SELECT id, token_id, node_key_hash, last_seen, bound_ip, bound_mac FROM intake_osquery_nodes WHERE node_key_hash = ?`, want).Scan(&n.id, &n.tokenID, &got, &seen, &ip, &mac)
	if errors.Is(err, sql.ErrNoRows) {
		return nodeRow{}, errNodeInvalid
	}
	if err != nil {
		return nodeRow{}, fmt.Errorf("agentintake: read node: %w", err)
	}
	if !sameHash(got, want) {
		return nodeRow{}, errNodeInvalid
	}
	n.lastSeen, _ = time.Parse(time.RFC3339Nano, seen)
	if ip.Valid {
		n.boundIP, _ = netip.ParseAddr(ip.String)
		n.boundMAC = mac.String
	}
	return n, nil
}

// authNode is the common start of config and log: the source is not blocked, the key is a node's, the node is within its rate.
func (s *Service) authNode(ctx context.Context, op string, src netip.Addr, key string, kind string, perMin int) (nodeRow, error) {
	sk := srcKey(src)
	if w := s.fail.blocked(sk); w > 0 {
		return nodeRow{}, rateLimited(w)
	}
	n, err := s.nodeByKey(ctx, key)
	if errors.Is(err, errNodeInvalid) {
		s.fail.fail(sk)
		s.logReject(ctx, op, src, "node key")
		return nodeRow{}, errNodeInvalid
	}
	if err != nil {
		return nodeRow{}, err
	}
	if ok, wait := s.node.allow(n.id, kind, perMin); !ok {
		return nodeRow{}, rateLimited(wait)
	}
	return n, nil
}

// Config answers a config request: errNodeInvalid for an unknown key, nil for a node that may have its schedule.
func (s *Service) Config(ctx context.Context, src netip.Addr, nodeKey string) error {
	n, err := s.authNode(ctx, "config", src, nodeKey, "config", configPerMin)
	if err != nil {
		return err
	}
	return s.touch(ctx, n)
}

// touch records that the node called, at most once a minute.
func (s *Service) touch(ctx context.Context, n nodeRow) error {
	now := s.now()
	if now.Sub(n.lastSeen) < touchEvery {
		return nil
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE intake_osquery_nodes SET last_seen = ? WHERE id = ?`, store.FormatTS(now), n.id); err != nil {
			return fmt.Errorf("agentintake: touch node: %w", err)
		}
		return nil
	})
}

// ---- status ----

// Status answers the install script's "has this machine reported in yet" (token in the Authorization header). A bad token counts
// against the source like an enrol does. The errors are 403 invalid_token and token_expired as the approved mock has them: the caller
// holds the token and is the person who made it, and the answer carries no data.
func (s *Service) Status(ctx context.Context, src netip.Addr, secret string) (enrolled bool, hosts int, err error) {
	key := srcKey(src)
	if w := s.fail.blocked(key); w > 0 {
		return false, 0, rateLimited(w)
	}
	t, err := s.tokenBySecret(ctx, s.db.Reader(), secret)
	if errors.Is(err, errNodeInvalid) {
		s.fail.fail(key)
		s.logReject(ctx, "status", src, "credential")
		return false, 0, apierr.New(403, "invalid_token", "This enrollment token is not valid. Create a new one in Vedette.")
	}
	if err != nil {
		return false, 0, err
	}
	if t.expired(s.now()) {
		s.fail.fail(key)
		return false, 0, apierr.New(403, "token_expired", "This enrollment token has expired. Create a new one in Vedette.")
	}
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM intake_osquery_nodes WHERE token_id = ?`, t.id).Scan(&hosts); err != nil {
		return false, 0, fmt.Errorf("agentintake: count hosts: %w", err)
	}
	return !t.received.IsZero(), hosts, nil
}
