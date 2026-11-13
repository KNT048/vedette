package sensoractive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/localnet"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/store"
)

// SNMP reads (D-512, INV-10, S-INV-1). An administrator saves SNMP credentials (a v2c community, or a v3 user with SHA or SHA-256
// and AES-128 or no privacy); their secrets are sealed in core/secrets and never leave core except inside an snmp job to the worker
// of the scan container, over the mutual-TLS sensor link. The worker sends read-only GETs of a fixed list of objects; core decides
// everything before that: once per scan window (after the sweep and the queue) every approved device of the confirmed scope that is
// not the box, not added by hand and not set to "never" is read with the credentials whose own scope holds it, in order, until one
// is answered; a Test reads one device with one credential at once. Fragile and unclassified devices are read too: a few GETs are
// gentler than the one gentle scan, and SNMP is how a printer or a UPS tells what it is. Every job writes a probe row (INV-9) before
// anything is sent. What a device answers is parsed in core (snmpmap.go) and recorded with source snmp.

// The purposes of the secrets in core_secret: the community or the v3 authentication password, and the v3 privacy password.
const (
	snmpSecretPurpose = "sa_snmp.secret" //nolint:gosec // G101: the name of a purpose, not a secret
	snmpPrivPurpose   = "sa_snmp.priv"
)

const (
	// maxSNMPCredentials is how many credentials can be saved: an snmp job carries at most this many.
	maxSNMPCredentials = sensorlink.MaxSNMPCredentials
	maxSNMPScope       = 16
	// snmpTestBudget bounds a Test: a v3 read is a discovery and a GET of 2 s each, sent twice; the rest is the worker picking it up.
	snmpTestBudget = 40 * time.Second
	// snmpRoundRun bounds one batch of the window's round (64 devices with up to 4 credentials each).
	snmpRoundRun = time.Hour
	// snmpWait is how long a Test waits for a batch of the window's round to finish before it says busy.
	snmpWait = 30 * time.Second
	// The confidence of what a device states about itself; the kind from a family or a phrase is a little less sure.
	snmpStated = 0.9
	snmpKind   = 0.8
	// Reasons of sa_job rows of kind snmp.
	snmpReasonTest   = "snmp_test"
	snmpReasonWindow = "window"
)

// SNMP reasons and statuses a Test answers with (SnmpTestReason in contract.ts), beside the inventory's refusals it passes on.
const (
	SNMPOK                   = "ok"
	SNMPNotInInventory       = "not_in_inventory"
	SNMPNotApproved          = "not_approved"
	SNMPNotForThisCredential = "not_for_this_credential"
	SNMPUnavailable          = "unavailable"
	SNMPBusy                 = "busy"
)

// SNMPCredential is a saved credential without its secrets (SnmpCredential in contract.ts). Priv is "aes128" or "none" for v3, ""
// for v2c; Auth is "" for v2c.
type SNMPCredential struct {
	ID, Name, Version, Username, Auth, Priv string
	SecretLast4, PrivLast4                  string
	Scope                                   []string
	CreatedAt, LastAnswerAt                 time.Time // LastAnswerAt zero: never
	Answered                                int
}

// SNMPCredentialInput is the form (SnmpCredentialInput in contract.ts). A blank secret on an edit keeps the saved one.
type SNMPCredentialInput struct {
	Name, Version, Username, Auth, Priv   string
	Community, AuthPassword, PrivPassword secrets.Value
	Scope                                 []string
}

// SNMPTestResult is what a Test answers (SnmpTestResult in contract.ts). Answer is set when the device answered.
type SNMPTestResult struct {
	OK       bool
	Reason   string
	Message  string
	DeviceID string
	Answer   *SNMPFacts
}

// snmpRow is a credential as stored.
type snmpRow struct {
	SNMPCredential
	secretID, privID string
}

// snmpRun is the SNMP batch in progress, for SettingsChanged, AssetChanged and Stop.
type snmpRun struct {
	cancel  context.CancelFunc
	targets []netip.Addr
	assets  []string
	picked  bool // a Test: the window does not bind it
}

var (
	snmpUserRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)
	printASCII = regexp.MustCompile(`^[\x20-\x7e]*$`)
)

func bad(code, msg string) *apierr.Error { return apierr.New(400, code, msg) }

// snmpOff is the answer of every credential call when the service was built without secrets (a build that is not wired).
func snmpOff() *apierr.Error {
	return apierr.New(501, apierr.CodeNotImplemented, "SNMP is not available in this build.")
}

// SNMPStatus says whether an SNMP read can be sent now, and if not, why (GET /inventory/snmp).
func (s *Service) SNMPStatus() (ready bool, message string) {
	if s.snmp == nil {
		return false, "SNMP reads are not available in this build"
	}
	if msg := s.snmp.SNMPHealth(); msg != "" {
		return false, msg
	}
	return true, ""
}

// SNMPCredentials lists the saved credentials in the order they are tried: oldest first.
func (s *Service) SNMPCredentials(ctx context.Context) ([]SNMPCredential, error) {
	rows, err := s.snmpRows(ctx, s.db.Reader())
	if err != nil {
		return nil, err
	}
	out := make([]SNMPCredential, len(rows))
	for i, r := range rows {
		out[i] = r.SNMPCredential
	}
	return out, nil
}

const snmpCols = `id, name, version, username, auth, priv, secret_id, secret_last4, priv_secret_id, priv_last4, scope, created_at, last_answer_at, answered`

func (s *Service) snmpRows(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]snmpRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+snmpCols+` FROM sa_snmp ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("sensoractive: read snmp credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []snmpRow
	for rows.Next() {
		r, err := scanSNMPRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func scanSNMPRow(r interface{ Scan(...any) error }) (snmpRow, error) {
	var row snmpRow
	var user, auth, priv, privID, last sql.NullString
	var scope, created string
	if err := r.Scan(&row.ID, &row.Name, &row.Version, &user, &auth, &priv, &row.secretID, &row.SecretLast4, &privID, &row.PrivLast4, &scope, &created, &last, &row.Answered); err != nil {
		return snmpRow{}, fmt.Errorf("sensoractive: read snmp credential: %w", err)
	}
	row.Username, row.Auth, row.privID = user.String, auth.String, privID.String
	if row.Version == sensorlink.SNMPv3 {
		row.Priv = cmpOr(priv.String, "none")
	}
	row.Scope = []string{}
	if err := json.Unmarshal([]byte(scope), &row.Scope); err != nil {
		return snmpRow{}, fmt.Errorf("sensoractive: read snmp credential scope: %w", err)
	}
	row.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	if last.Valid {
		row.LastAnswerAt, _ = time.Parse(time.RFC3339Nano, last.String)
	}
	return row, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (s *Service) snmpRow(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, id string) (*snmpRow, error) {
	r, err := scanSNMPRow(q.QueryRowContext(ctx, `SELECT `+snmpCols+` FROM sa_snmp WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apierr.New(404, "not_found", "There is no SNMP credential with this id.")
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// snmpForm is a checked form.
type snmpForm struct {
	name, version, user, auth, priv string // priv "" for v2c and for v3 without privacy
	secret, privSecret              string // "" = keep the saved one
	scope                           []netip.Prefix
	scopeText                       []string
}

// checkSNMP checks the form against the rules of the contract; prev is the saved credential of an edit, nil for a new one.
func checkSNMP(in SNMPCredentialInput, prev *snmpRow) (snmpForm, *apierr.Error) {
	f := snmpForm{name: strings.TrimSpace(in.Name), version: in.Version}
	if n := utf8.RuneCountInString(f.name); n < 1 || n > 64 || strings.ContainsAny(f.name, "<>") || cleanSNMP(f.name) != f.name {
		return f, bad("bad_name", "Give the credential a name of 1 to 64 characters, without < or >.")
	}
	secret := func(v secrets.Value, lo int, what string) (string, *apierr.Error) {
		t := v.Reveal()
		if t == "" {
			return "", nil
		}
		if len(t) < lo || len(t) > 64 || !printASCII.MatchString(t) {
			return "", bad("bad_secret", fmt.Sprintf("The %s must be %d to 64 printable ASCII characters (letters, digits, punctuation, spaces).", what, lo))
		}
		return t, nil
	}
	sameVersion := prev != nil && prev.Version == in.Version
	var err *apierr.Error
	switch in.Version {
	case sensorlink.SNMPv2c:
		if f.secret, err = secret(in.Community, 1, "community"); err != nil {
			return f, err
		}
		if f.secret == "" && !sameVersion {
			return f, bad("secret_required", "Enter the community.")
		}
	case sensorlink.SNMPv3:
		f.user, f.auth = strings.TrimSpace(in.Username), in.Auth
		if !snmpUserRE.MatchString(f.user) {
			return f, bad("bad_user", "Enter the SNMPv3 user name: letters, digits and . _ @ -, at most 64.")
		}
		if f.auth != sensorlink.SNMPAuthSHA && f.auth != sensorlink.SNMPAuthSHA256 {
			return f, bad("bad_auth", "Choose SHA or SHA-256 for authentication.")
		}
		if f.secret, err = secret(in.AuthPassword, 8, "authentication password"); err != nil {
			return f, err
		}
		if f.secret == "" && !sameVersion {
			return f, bad("secret_required", "Enter the authentication password (at least 8 characters).")
		}
		switch in.Priv {
		case "", sensorlink.SNMPPrivAES128:
			f.priv = sensorlink.SNMPPrivAES128
			if f.privSecret, err = secret(in.PrivPassword, 8, "privacy password"); err != nil {
				return f, err
			}
			if f.privSecret == "" && (!sameVersion || prev.privID == "") {
				return f, bad("secret_required", "Enter the privacy password (at least 8 characters), or choose no privacy.")
			}
		case "none":
		default:
			return f, bad("bad_priv", "Choose AES-128 or no privacy.")
		}
	default:
		return f, bad("bad_version", "Choose SNMP v2c or v3.")
	}
	if len(in.Scope) > maxSNMPScope {
		return f, bad("bad_scope", fmt.Sprintf("List at most %d addresses or ranges.", maxSNMPScope))
	}
	for _, raw := range in.Scope {
		raw = strings.TrimSpace(raw)
		p, perr := netip.ParsePrefix(raw)
		if perr != nil {
			a, aerr := netip.ParseAddr(raw)
			if aerr != nil {
				return f, bad("bad_scope", fmt.Sprintf("%q is not an IPv4 address or range (192.168.1.10 or 192.168.1.0/24).", clip(raw, 40)))
			}
			p = netip.PrefixFrom(a, 32)
		}
		p = p.Masked()
		if !localnet.Prefix(p) {
			return f, bad("bad_scope", fmt.Sprintf("%s is not a local network address (%s).", p, localnet.Names))
		}
		if slices.Contains(f.scope, p) {
			continue
		}
		f.scope = append(f.scope, p)
		if p.Bits() == 32 {
			f.scopeText = append(f.scopeText, p.Addr().String())
		} else {
			f.scopeText = append(f.scopeText, p.String())
		}
	}
	// The scope is required (review M3, runZero's allow list): an operator can approve a device and osquery enrolment approves one,
	// so "every approved device" would hand the community to a laptop someone plugged in and got approved. The admin names the
	// devices a credential belongs to.
	if len(f.scope) == 0 {
		return f, bad("scope_required", "List the addresses or ranges of the devices this credential belongs to (for example 192.168.1.1 or 192.168.1.0/28). It is sent only there, so a device someone plugs in later never receives it.")
	}
	// A saved secret goes only where it was going when it was typed: an edit that sends it to more addresses asks for it again
	// (as a changed Wazuh certificate does, D-308), so a person who can edit the form but never knew the secret cannot point it at
	// a device of their own.
	if prev != nil && (f.secret == "" || (f.priv != "" && f.privSecret == "")) && widens(prev.Scope, f.scope) {
		return f, bad("secret_required", "This credential would be sent to more addresses. Type its community or passwords again to allow that.")
	}
	return f, nil
}

// widens reports whether the new scope reaches an address the old one did not.
func widens(old []string, next []netip.Prefix) bool {
	olds := exclusionPrefixes(old) // an address or a range, as the scope is stored
	for _, p := range next {
		if !slices.ContainsFunc(olds, func(q netip.Prefix) bool { return q.Bits() <= p.Bits() && q.Contains(p.Addr()) }) {
			return true
		}
	}
	return false
}

func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, actor, action, target, detail string) error {
	if s.audit == nil {
		return nil
	}
	if err := s.audit.Append(ctx, tx, audit.Entry{User: actor, Action: action, Target: target, Detail: detail}); err != nil {
		return fmt.Errorf("sensoractive: audit: %w", err)
	}
	return nil
}

func (f snmpForm) words() string {
	w := f.version
	if f.version == sensorlink.SNMPv3 {
		w += " user " + f.user + ", " + f.auth + ", " + cmpOr(f.priv, "no privacy")
	}
	return w + ", scope " + strings.Join(f.scopeText, " ")
}

func nameTaken(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE") && strings.Contains(err.Error(), "sa_snmp.name") {
		return apierr.New(409, "name_taken", "Another SNMP credential has this name.")
	}
	return err
}

// AddSNMP saves a new credential: its secrets sealed in core/secrets, the rest in sa_snmp, one audit row; at most 8.
func (s *Service) AddSNMP(ctx context.Context, actor string, in SNMPCredentialInput) (SNMPCredential, error) {
	if s.secrets == nil {
		return SNMPCredential{}, snmpOff()
	}
	f, aerr := checkSNMP(in, nil)
	if aerr != nil {
		return SNMPCredential{}, aerr
	}
	id := store.NewID("snmp")
	scope, _ := json.Marshal(f.scopeText)
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sa_snmp`).Scan(&n); err != nil {
			return err
		}
		if n >= maxSNMPCredentials {
			return apierr.New(409, "too_many", fmt.Sprintf("At most %d SNMP credentials can be saved. Delete one first.", maxSNMPCredentials))
		}
		secretID, last4, err := s.secrets.Seal(ctx, tx, snmpSecretPurpose, []byte(f.secret), true)
		if err != nil {
			return fmt.Errorf("sensoractive: seal snmp secret: %w", err)
		}
		var privID, privLast4 any = nil, ""
		if f.priv != "" {
			pid, pl4, err := s.secrets.Seal(ctx, tx, snmpPrivPurpose, []byte(f.privSecret), true)
			if err != nil {
				return fmt.Errorf("sensoractive: seal snmp privacy password: %w", err)
			}
			privID, privLast4 = pid, pl4
		}
		now := s.now()
		if _, err := tx.ExecContext(ctx, `INSERT INTO sa_snmp (id, name, version, username, auth, priv, secret_id, secret_last4, priv_secret_id, priv_last4, scope, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, f.name, f.version, nullable(f.user), nullable(f.auth), nullable(f.priv), secretID, last4, privID, privLast4, string(scope), now, now); err != nil {
			return nameTaken(err)
		}
		return s.auditTx(ctx, tx, actor, "inventory.snmp_add", f.name, f.words())
	})
	if err != nil {
		return SNMPCredential{}, err
	}
	r, err := s.snmpRow(ctx, s.db.Reader(), id)
	if err != nil {
		return SNMPCredential{}, err
	}
	return r.SNMPCredential, nil
}

// EditSNMP changes a credential. A blank secret keeps the saved one, unless the version changes or the credential would be sent to
// more addresses (checkSNMP); choosing no privacy deletes the privacy password.
func (s *Service) EditSNMP(ctx context.Context, actor, id string, in SNMPCredentialInput) (SNMPCredential, error) {
	if s.secrets == nil {
		return SNMPCredential{}, snmpOff()
	}
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		prev, err := s.snmpRow(ctx, tx, id)
		if err != nil {
			return err
		}
		f, aerr := checkSNMP(in, prev)
		if aerr != nil {
			return aerr
		}
		last4 := prev.SecretLast4
		if f.secret != "" {
			if last4, err = s.secrets.Replace(ctx, tx, prev.secretID, snmpSecretPurpose, []byte(f.secret), true); err != nil {
				return fmt.Errorf("sensoractive: replace snmp secret: %w", err)
			}
		}
		var privID any
		privLast4 := ""
		switch {
		case f.priv == "" && prev.privID != "":
			if err := s.secrets.Delete(ctx, tx, prev.privID); err != nil {
				return fmt.Errorf("sensoractive: delete snmp privacy password: %w", err)
			}
		case f.priv != "" && prev.privID == "":
			pid, pl4, err := s.secrets.Seal(ctx, tx, snmpPrivPurpose, []byte(f.privSecret), true)
			if err != nil {
				return fmt.Errorf("sensoractive: seal snmp privacy password: %w", err)
			}
			privID, privLast4 = pid, pl4
		case f.priv != "":
			privID, privLast4 = prev.privID, prev.PrivLast4
			if f.privSecret != "" {
				if privLast4, err = s.secrets.Replace(ctx, tx, prev.privID, snmpPrivPurpose, []byte(f.privSecret), true); err != nil {
					return fmt.Errorf("sensoractive: replace snmp privacy password: %w", err)
				}
			}
		}
		scope, _ := json.Marshal(f.scopeText)
		if _, err := tx.ExecContext(ctx, `UPDATE sa_snmp SET name = ?, version = ?, username = ?, auth = ?, priv = ?, secret_last4 = ?, priv_secret_id = ?, priv_last4 = ?, scope = ?, updated_at = ? WHERE id = ?`,
			f.name, f.version, nullable(f.user), nullable(f.auth), nullable(f.priv), last4, privID, privLast4, string(scope), s.now(), id); err != nil {
			return nameTaken(err)
		}
		return s.auditTx(ctx, tx, actor, "inventory.snmp_edit", f.name, f.words())
	})
	if err != nil {
		return SNMPCredential{}, err
	}
	r, err := s.snmpRow(ctx, s.db.Reader(), id)
	if err != nil {
		return SNMPCredential{}, err
	}
	return r.SNMPCredential, nil
}

// DeleteSNMP removes a credential and its secrets in one transaction. What devices said with it stays in the inventory.
func (s *Service) DeleteSNMP(ctx context.Context, actor, id string) error {
	if s.secrets == nil {
		return snmpOff()
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		prev, err := s.snmpRow(ctx, tx, id)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sa_snmp WHERE id = ?`, id); err != nil {
			return fmt.Errorf("sensoractive: delete snmp credential: %w", err)
		}
		for _, sid := range []string{prev.secretID, prev.privID} {
			if sid == "" {
				continue
			}
			if err := s.secrets.Delete(ctx, tx, sid); err != nil {
				return fmt.Errorf("sensoractive: delete snmp secret: %w", err)
			}
		}
		return s.auditTx(ctx, tx, actor, "inventory.snmp_delete", prev.Name, prev.Version)
	})
}

// covers reports whether a credential may be sent to ip: its scope holds ip. An empty scope (no row can have one, checkSNMP) holds
// nothing: fail closed.
func (r snmpRow) covers(ip netip.Addr) bool {
	return slices.ContainsFunc(exclusionPrefixes(r.Scope), func(p netip.Prefix) bool { return p.Contains(ip) }) // an address or a range
}

// snmpPolicy decides whether a device may be read with SNMP at all: "" when it may, else the reason. It is the inventory's
// ScanPolicy without the fragile rule (a fragile or unclassified device is read), plus the device's approval and the box's own
// addresses and decoys (box, from Inventory.BoxIPs: always refused, fragile or not; review L1).
func (s *Service) snmpPolicy(ctx context.Context, assetID string, box []netip.Addr) (Asset, string, error) {
	dec, err := s.inv.ScanPolicy(ctx, assetID)
	if err != nil {
		return Asset{}, "", err
	}
	passive := dec.Reason == reasonFragilePassive || dec.Reason == reasonUnclassifiedPassive
	switch {
	case dec.Never:
		return Asset{}, reasonNever, nil
	case !dec.Allowed && !passive:
		return Asset{}, dec.Reason, nil
	}
	a, err := s.inv.Asset(ctx, assetID)
	if err != nil {
		return Asset{}, "", err
	}
	switch {
	case !a.IP.IsValid():
		return a, "no_ip", nil
	case slices.Contains(box, a.IP):
		return a, reasonBox, nil
	case !a.Approved:
		return a, SNMPNotApproved, nil
	}
	return a, "", nil
}

// snmpRefusals are the refusals of snmpPolicy a Test answers with as they are (SnmpTestReason in contract.ts).
var snmpRefusals = []string{SNMPNotApproved, "out_of_scope", reasonScanningOff, reasonScopeNotConfirmed, "declared_by_hand", reasonBox, reasonNever}

// snmpTarget is one device of a batch and the credentials to try on it, in order (indexes into the batch's credentials).
type snmpTarget struct {
	asset string
	ip    netip.Addr
	creds []int
}

// TestSNMP reads one device with one credential now (POST /inventory/snmp/{id}/test): every rule of the window's round but the
// window. It answers what the device said, recorded in the inventory, or a plain reason; one audit row says who tested what.
func (s *Service) TestSNMP(ctx context.Context, actor, id, ipText string) (SNMPTestResult, error) {
	if s.secrets == nil {
		return SNMPTestResult{}, snmpOff()
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(ipText))
	if err != nil || !ip.Is4() {
		return SNMPTestResult{}, bad("bad_ip", "Enter the IPv4 address of a device, for example 192.168.1.10.")
	}
	cred, err := s.snmpRow(ctx, s.db.Reader(), id)
	if err != nil {
		return SNMPTestResult{}, err
	}
	res, err := s.testSNMP(ctx, *cred, ip)
	if err != nil {
		return SNMPTestResult{}, err
	}
	res.Message = snmpMessage(res.Reason, ip, cred.Version, res.Message)
	res.OK = res.Reason == SNMPOK
	wctx := context.WithoutCancel(ctx) // the test happened: its audit row is written even when the caller has gone
	werr := s.db.Write(wctx, func(tx *sql.Tx) error {
		return s.auditTx(wctx, tx, actor, "inventory.snmp_test", ip.String(), cred.Name+": "+res.Reason)
	})
	return res, werr
}

func (s *Service) testSNMP(ctx context.Context, cred snmpRow, ip netip.Addr) (SNMPTestResult, error) {
	addrs, err := s.inv.Addresses(ctx)
	if err != nil {
		return SNMPTestResult{}, err
	}
	assetID, ok := addrs[ip]
	if !ok {
		return SNMPTestResult{Reason: SNMPNotInInventory}, nil
	}
	res := SNMPTestResult{DeviceID: assetID}
	box, err := s.inv.BoxIPs(ctx)
	if err != nil {
		return SNMPTestResult{}, err
	}
	a, why, err := s.snmpPolicy(ctx, assetID, box)
	switch {
	case errors.Is(err, ErrNotFound):
		return SNMPTestResult{Reason: SNMPNotInInventory}, nil
	case err != nil:
		return SNMPTestResult{}, err
	case why == "no_ip", why == "" && a.IP != ip: // the device moved to another address between the two reads (review L2)
		res.Reason = SNMPNotInInventory
		return res, nil
	case why != "":
		s.blocked(ctx, assetID, why)
		res.Reason = why
		if !slices.Contains(snmpRefusals, why) { // a refusal of the inventory this list does not know yet: say it in words
			res.Reason, res.Message = SNMPUnavailable, "the inventory's scan policy refuses this device ("+why+")"
		}
		return res, nil
	case !cred.covers(ip):
		res.Reason = SNMPNotForThisCredential
		return res, nil
	}
	if ready, msg := s.SNMPStatus(); !ready {
		res.Reason, res.Message = SNMPUnavailable, msg
		return res, nil
	}
	if !s.lockSNMPWithin(ctx, snmpWait) {
		res.Reason = SNMPBusy
		return res, nil
	}
	defer s.snmpMu.Unlock()
	jobID, err := s.startJob(ctx, KindSNMP, snmpReasonTest, 1)
	if err != nil {
		return SNMPTestResult{}, err
	}
	bctx, cancel := context.WithTimeout(ctx, snmpTestBudget)
	defer cancel()
	answers, err := s.snmpBatch(bctx, jobID, []snmpRow{cred}, []snmpTarget{{asset: assetID, ip: ip, creds: []int{0}}}, true)
	s.closeSNMPJob(ctx, jobID, 1, err)
	switch {
	case errors.Is(err, ErrStopped):
		return SNMPTestResult{}, apierr.New(409, "stopped", "The test was stopped: the scan settings changed or the module was turned off.")
	case errors.Is(err, ErrSNMPUnavailable), errors.Is(err, ErrWorkerLost), errors.Is(err, context.DeadlineExceeded):
		_, msg := s.SNMPStatus()
		res.Reason, res.Message = SNMPUnavailable, cmpOr(msg, "the scan worker did not finish the read in time")
		return res, nil
	case err != nil:
		return SNMPTestResult{}, err
	case len(answers) == 0: // the batch's own check dropped it: the device or the credential changed in between
		return SNMPTestResult{}, apierr.New(409, "changed", "The device or the credential changed while the test started. Test again.")
	}
	ans := answers[0]
	res.Reason = ans.Status
	if ans.Status == sensorlink.SNMPStatusOK {
		f := identifySNMP(ans.Values)
		res.Answer = &f
	}
	return res, nil
}

// lockSNMPWithin takes snmpMu, trying for at most d.
func (s *Service) lockSNMPWithin(ctx context.Context, d time.Duration) bool {
	if s.snmpMu.TryLock() {
		return true
	}
	give := time.NewTimer(d)
	defer give.Stop()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-give.C:
			return s.snmpMu.TryLock()
		case <-tick.C:
			if s.snmpMu.TryLock() {
				return true
			}
		}
	}
}

func (s *Service) closeSNMPJob(ctx context.Context, jobID string, targets int, err error) {
	switch {
	case err == nil:
		s.finishJob(ctx, jobID, StatusDone, targets, 0, "")
	case errors.Is(err, ErrStopped):
		s.finishJob(ctx, jobID, StatusStopped, 0, 0, stoppedText)
	default:
		s.finishJob(ctx, jobID, StatusFailed, 0, 0, err.Error())
	}
}

// snmpBatch reads up to 64 devices in one snmp job: the order of INV-1 and INV-9 holds as for nmap: the batch is published first
// (SettingsChanged sees it), then the settings, the window (not for a Test) and the scope are read again for every target, then the
// probe row is written, and only then the secrets are opened and the job handed to the worker. What the devices answered is recorded.
// The caller holds snmpMu.
func (s *Service) snmpBatch(ctx context.Context, jobID string, creds []snmpRow, targets []snmpTarget, picked bool) ([]sensorlink.SNMPAnswer, error) {
	v0 := s.ver.Load()
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	run := &snmpRun{cancel: cancel, picked: picked}
	for _, t := range targets {
		run.targets, run.assets = append(run.targets, t.ip), append(run.assets, t.asset)
	}
	s.mu.Lock()
	s.snmpCur = run
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.snmpCur = nil
		s.mu.Unlock()
	}()

	st, err := s.inv.Settings(rctx)
	if err == nil {
		err = st.allowed()
	}
	if err != nil {
		return nil, s.stopFor(err)
	}
	end, ok := s.windowNow(st)
	if !ok && !picked {
		return nil, ErrStopped
	}
	if !picked { // a round's batch ends with the window, as an nmap run does (INV-3, review M2)
		timeout := min(end.Sub(s.clock()), snmpRoundRun)
		if timeout <= 0 {
			return nil, ErrStopped
		}
		var stop context.CancelFunc
		rctx, stop = context.WithTimeout(rctx, timeout)
		defer stop()
	}
	// The round chose its devices and credentials when it started: read both again now, so a device set to never, no longer
	// approved, moved or deleted, and a credential deleted or narrowed since, gets nothing (review M1, L3).
	if creds, targets, err = s.recheckSNMP(rctx, creds, targets); err != nil {
		if rctx.Err() != nil {
			return nil, ErrStopped
		}
		return nil, err
	}
	if len(targets) == 0 {
		return nil, nil
	}
	sc := newScope(st)
	for _, t := range targets {
		if !sc.contains(t.ip) {
			return nil, ErrStopped
		}
		if in, err := s.inv.InScope(rctx, t.ip); err != nil || !in {
			return nil, ErrStopped
		}
	}
	rate := max(1, min(st.Rate, 1000))
	probeID, err := s.insertSNMPProbe(rctx, jobID, rate, creds, targets)
	if err != nil {
		return nil, err
	}
	if rctx.Err() != nil || s.ver.Load() != v0 {
		s.finishProbe(ctx, probeID, stoppedText)
		return nil, ErrStopped
	}
	job, err := s.snmpJob(rctx, rate, creds, targets)
	if err != nil {
		s.finishProbe(ctx, probeID, "failed: the credentials could not be read")
		return nil, err
	}
	answers, err := s.snmp.RunSNMP(rctx, job)
	var result string
	switch {
	case rctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded):
		result, err = stoppedText, ErrStopped
	case errors.Is(err, ErrSNMPUnavailable):
		result = "failed: snmp_unavailable"
	case errors.Is(err, ErrWorkerLost):
		result = "failed: worker_lost"
	case errors.Is(err, ErrWorkerRefused):
		result = "failed: the worker refused the job"
	case errors.Is(err, ErrResultRejected):
		result = "failed: the worker's result was rejected"
	case err != nil:
		result = "failed: the read did not finish"
	default:
		n := 0
		for _, a := range answers {
			if a.Status == sensorlink.SNMPStatusOK {
				n++
			}
		}
		result = fmt.Sprintf("ok: %d of %d answered", n, len(targets))
	}
	s.finishProbe(ctx, probeID, result)
	if err != nil {
		return nil, err
	}
	return answers, s.recordSNMP(ctx, creds, answers, picked)
}

// recheckSNMP reads the credentials and every target's policy again right before a batch: targets the policy now refuses (never, not
// approved, the box, hand-added, out of scope), that moved to another address or are gone are dropped; credentials deleted since are
// dropped, a narrowed scope is applied, and a credential no remaining target uses is left out of the job.
func (s *Service) recheckSNMP(ctx context.Context, creds []snmpRow, targets []snmpTarget) ([]snmpRow, []snmpTarget, error) {
	rows, err := s.snmpRows(ctx, s.db.Reader())
	if err != nil {
		return nil, nil, err
	}
	box, err := s.inv.BoxIPs(ctx)
	if err != nil {
		return nil, nil, err
	}
	fresh := make([]*snmpRow, len(creds)) // the saved row of each credential of the batch, nil when deleted
	for i, c := range creds {
		if j := slices.IndexFunc(rows, func(r snmpRow) bool { return r.ID == c.ID }); j >= 0 {
			fresh[i] = &rows[j]
		}
	}
	var outCreds []snmpRow
	at := map[int]int{} // index in creds -> index in outCreds
	var out []snmpTarget
	for _, t := range targets {
		a, why, err := s.snmpPolicy(ctx, t.asset, box)
		if errors.Is(err, ErrNotFound) || err == nil && (why != "" || a.IP != t.ip) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		var use []int
		for _, ci := range t.creds {
			if fresh[ci] == nil || !fresh[ci].covers(t.ip) {
				continue
			}
			if _, ok := at[ci]; !ok {
				at[ci] = len(outCreds)
				outCreds = append(outCreds, *fresh[ci])
			}
			use = append(use, at[ci])
		}
		if len(use) > 0 {
			out = append(out, snmpTarget{asset: t.asset, ip: t.ip, creds: use})
		}
	}
	return outCreds, out, nil
}

// snmpJob opens the secrets of the batch's credentials (only here, only for the job) and builds the job of the wire.
func (s *Service) snmpJob(ctx context.Context, rate int, creds []snmpRow, targets []snmpTarget) (sensorlink.SNMPJob, error) {
	job := sensorlink.SNMPJob{Rate: rate}
	for _, c := range creds {
		secret, err := s.secrets.Open(ctx, s.db.Reader(), c.secretID, snmpSecretPurpose)
		if err != nil {
			return job, fmt.Errorf("sensoractive: open snmp secret: %w", err)
		}
		w := sensorlink.SNMPCredential{Version: c.Version}
		switch c.Version {
		case sensorlink.SNMPv2c:
			w.Community = string(secret)
		default:
			w.User, w.Auth, w.AuthPass = c.Username, c.Auth, string(secret)
			if c.privID != "" {
				priv, err := s.secrets.Open(ctx, s.db.Reader(), c.privID, snmpPrivPurpose)
				if err != nil {
					return job, fmt.Errorf("sensoractive: open snmp privacy password: %w", err)
				}
				w.Priv, w.PrivPass = sensorlink.SNMPPrivAES128, string(priv)
			}
		}
		job.Credentials = append(job.Credentials, w)
	}
	for _, t := range targets {
		job.Targets = append(job.Targets, sensorlink.SNMPTarget{IP: t.ip.String(), Credentials: slices.Clone(t.creds)})
	}
	return job, nil
}

// insertSNMPProbe writes the probe row of a batch before anything is sent (INV-9): shape snmp, the pace, the addresses, and in flags
// what was asked and with which credentials (names and versions, never a secret).
func (s *Service) insertSNMPProbe(ctx context.Context, jobID string, rate int, creds []snmpRow, targets []snmpTarget) (int64, error) {
	addrs := make([]netip.Addr, len(targets))
	for i, t := range targets {
		addrs[i] = t.ip
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	names := make([]string, len(creds))
	for i, c := range creds {
		names[i] = c.Name + " (" + c.Version + ")"
	}
	flags := clip("GET sysDescr sysObjectID sysName entPhysical.1 class model softwareRev serialNum; timeout 2s retries 1; credentials: "+strings.Join(names, ", "), 300)
	var id int64
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES (?, ?, 'snmp', ?, ?, ?, ?, 'started')`,
			s.now(), jobID, rate, len(targets), flags, compactTargets(addrs))
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("sensoractive: probe log: %w", err)
	}
	return id, nil
}

// recordSNMP writes what the devices said into the inventory (source snmp) and the credentials' last answer. An observation the
// inventory refuses (a value it does not take) is dropped and the rest of the device's are written.
func (s *Service) recordSNMP(ctx context.Context, creds []snmpRow, answers []sensorlink.SNMPAnswer, picked bool) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	answered := make([]int, len(creds))
	var errs []error
	for _, a := range answers {
		if a.Status != sensorlink.SNMPStatusOK {
			continue
		}
		answered[a.Credential]++
		ip, err := netip.ParseAddr(a.Target)
		if err != nil {
			continue
		}
		obs := snmpObservations(ip, identifySNMP(a.Values))
		for len(obs) > 0 {
			err := s.obs.Record(ctx, obs)
			var rej *observe.ErrRejected
			if errors.As(err, &rej) && rej.Index >= 0 && rej.Index < len(obs) {
				obs = slices.Delete(obs, rej.Index, rej.Index+1)
				continue
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("sensoractive: recording snmp observations: %w", err))
			}
			break
		}
	}
	now := s.now()
	// answered is the count of the window's round; a Test (one device) only says the credential works: at least 1.
	set := `answered = ?`
	if picked {
		set = `answered = max(answered, ?)`
	}
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		for i, c := range creds {
			if answered[i] == 0 {
				continue
			}
			if _, err := tx.ExecContext(ctx, `UPDATE sa_snmp SET last_answer_at = ?, `+set+` WHERE id = ?`, now, answered[i], c.ID); err != nil {
				return err
			}
		}
		return nil
	})
	return errors.Join(append(errs, err)...)
}

// snmpObservations are what an answer says, as observations of the device at ip.
func snmpObservations(ip netip.Addr, f SNMPFacts) []observe.Observation {
	var out []observe.Observation
	add := func(field observe.Field, v string, c float64) {
		if v != "" {
			out = append(out, observe.Observation{AssetHint: observe.AssetHint{IP: ip}, Field: field, Value: v, Source: observe.SNMP, Confidence: c})
		}
	}
	add(observe.Hostname, f.Hostname, snmpStated)
	add(observe.Vendor, f.Vendor, snmpStated)
	add(observe.Model, f.Model, snmpStated)
	add(observe.OS, f.OS, snmpStated)
	add(observe.Kind, f.Kind, snmpKind)
	return out
}

// snmpRoundDue says the window that is open now has had no round of SNMP reads yet (a stopped one does not count, as for the sweep).
func (s *Service) snmpRoundDue(ctx context.Context, start time.Time) (bool, error) {
	var n int
	err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM sa_job WHERE kind = 'snmp' AND reason = ? AND status IN ('running', 'done', 'failed') AND started_at >= ?`,
		snmpReasonWindow, store.FormatTS(start)).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("sensoractive: read jobs: %w", err)
	}
	return n == 0, nil
}

// snmpRound is the window's round of SNMP reads (Tick, after the sweep and the queue): once per window, every device the policy
// lets be read, with the credentials whose scope holds it (in order, at most 4), in batches of 64. The job row is written first, so
// a window with nothing to read is not looked at again every minute.
func (s *Service) snmpRound(ctx context.Context, windowStart time.Time) error {
	if s.snmp == nil || s.secrets == nil {
		return nil
	}
	creds, err := s.snmpRows(ctx, s.db.Reader())
	if err != nil || len(creds) == 0 {
		return err
	}
	if due, err := s.snmpRoundDue(ctx, windowStart); err != nil || !due {
		return err
	}
	if ready, _ := s.SNMPStatus(); !ready {
		return nil // the next Tick tries again
	}
	jobID, err := s.startJob(ctx, KindSNMP, snmpReasonWindow, 0)
	if err != nil {
		return err
	}
	targets, err := s.snmpTargets(ctx, creds)
	if err != nil {
		s.finishJob(ctx, jobID, StatusFailed, 0, 0, err.Error())
		return err
	}
	done := 0
	for batch := range slices.Chunk(targets, sensorlink.MaxSNMPTargets) {
		s.snmpMu.Lock()
		_, err = s.snmpBatch(ctx, jobID, creds, batch, false) // its deadline: the window's end or snmpRoundRun (INV-3, review M2)
		s.snmpMu.Unlock()
		if err != nil {
			break
		}
		done += len(batch)
	}
	s.closeSNMPJob(ctx, jobID, done, err)
	if errors.Is(err, ErrStopped) {
		return nil
	}
	return err
}

// snmpTargets lists the devices of a round, by address, and the credentials to try on each.
func (s *Service) snmpTargets(ctx context.Context, creds []snmpRow) ([]snmpTarget, error) {
	addrs, err := s.inv.Addresses(ctx)
	if err != nil {
		return nil, err
	}
	box, err := s.inv.BoxIPs(ctx)
	if err != nil {
		return nil, err
	}
	ips := make([]netip.Addr, 0, len(addrs))
	for ip := range addrs {
		ips = append(ips, ip)
	}
	slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
	var out []snmpTarget
	for _, ip := range ips {
		var use []int
		for i, c := range creds {
			if c.covers(ip) && len(use) < sensorlink.MaxSNMPTargetTries {
				use = append(use, i)
			}
		}
		if len(use) == 0 || !localnet.Addr(ip) {
			continue
		}
		a, why, err := s.snmpPolicy(ctx, addrs[ip], box)
		if errors.Is(err, ErrNotFound) || err == nil && (why != "" || a.IP != ip) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, snmpTarget{asset: addrs[ip], ip: ip, creds: use})
	}
	return out, nil
}

// snmpChanged is SettingsChanged and AssetChanged for the SNMP batch in progress: it stops when the settings no longer allow it,
// an address left the scope, or (asset != "") one of its devices changed (it may have been set to "never" or deleted). Fail closed.
func (s *Service) snmpChanged(ctx context.Context, asset string) {
	s.mu.Lock()
	run := s.snmpCur
	s.mu.Unlock()
	if run == nil {
		return
	}
	if asset != "" {
		if slices.Contains(run.assets, asset) {
			run.cancel()
		}
		return
	}
	st, err := s.inv.Settings(ctx)
	if err != nil || st.allowed() != nil {
		run.cancel()
		return
	}
	if _, ok := s.windowNow(st); !ok && !run.picked {
		run.cancel()
		return
	}
	sc := newScope(st)
	if slices.ContainsFunc(run.targets, func(t netip.Addr) bool { return !sc.contains(t) }) {
		run.cancel()
	}
}

// snmpMessage is the plain text of a Test's reason (the GUI shows it as it is). extra is a message already set (unavailable).
func snmpMessage(reason string, ip netip.Addr, version, extra string) string {
	switch reason {
	case SNMPOK:
		return fmt.Sprintf("%s answered. What it said is now in the inventory, with source SNMP.", ip)
	case sensorlink.SNMPStatusNoAnswer:
		if version == sensorlink.SNMPv3 {
			return fmt.Sprintf("No answer from %s on UDP 161 within 2 s (sent twice). The device may not run SNMP, a firewall may drop UDP 161, or SNMPv3 is not enabled on it.", ip)
		}
		return fmt.Sprintf("No answer from %s on UDP 161 within 2 s (sent twice). The device may not run SNMP, a firewall may drop UDP 161, or the community is wrong: a device ignores a wrong community instead of saying so.", ip)
	case sensorlink.SNMPStatusAuthFailed:
		return "The device did not accept the v3 user name or password (or the authentication or privacy algorithm differs)."
	case sensorlink.SNMPStatusUnknownUser:
		return "The device does not know this v3 user name."
	case sensorlink.SNMPStatusError:
		return "The device answered with an error, or with a message Vedette could not read."
	case SNMPNotInInventory:
		return fmt.Sprintf("%s is not a device in the inventory. Only devices in the list can be tested.", ip)
	case SNMPNotApproved:
		return fmt.Sprintf("%s is not approved yet. SNMP credentials are sent only to devices a person approved: approve it under Devices, To review, then test again.", ip)
	case "out_of_scope":
		return fmt.Sprintf("%s is outside the scan scope (the LAN ranges and exclusions under Scope and sensors).", ip)
	case SNMPNotForThisCredential:
		return fmt.Sprintf("%s is outside the scope of this credential, so it is never sent there.", ip)
	case reasonScanningOff:
		return "Active scanning is off under Scope and sensors, so nothing is sent."
	case reasonScopeNotConfirmed:
		return "The scan scope commitment is not ticked under Scope and sensors, so nothing is sent."
	case "declared_by_hand":
		return "This device was added by hand: Vedette never probes it."
	case reasonBox:
		return "This is the Vedette box itself (or one of its trap addresses): it is never probed."
	case reasonNever:
		return "This device is set to never be scanned."
	case SNMPUnavailable:
		return "SNMP reads cannot run now: " + extra + "."
	case SNMPBusy:
		return "SNMP reads are running for the scan window right now. Try again in a minute."
	}
	return reason
}
