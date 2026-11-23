package sensoractive

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/localnet"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// SNMP reads (INV-10, S-INV-1). SNMP is set up per device, as a Zabbix host has its SNMP interface: an administrator
// saves on a device its version (a v2c community, or a v3 user with SHA or SHA-256 and AES-128 or no privacy), its UDP port and its
// read address (the device's IP, or its management address: a FortiGate answers on its global VDOM interface). The secrets are
// sealed in core/secrets and never leave core except inside an snmp job to the worker of the scan container, over the mutual-TLS
// sensor link, inside the one target they belong to: a device's secret goes to that device's read address and nowhere else (snmpJob
// refuses any other). The worker sends read-only GETs of a fixed list of objects; core decides everything before that: once per
// scan window (after the sweep and the queue) every device with SNMP set up that the policy lets be read is read, and Check now reads
// one device at once. Fragile and unclassified devices are read too: a few GETs are gentler than the one gentle scan, and SNMP is how
// a printer or a UPS tells what it is. Every job writes a probe row (INV-9) before anything is sent. What a device answers is parsed
// in core (snmpmap.go) and recorded on that device (observe.AssetHint.Device): an answer from the read address never makes, finds
// or joins another device.

// The purposes of the secrets in core_secret: the community or the v3 authentication password, and the v3 privacy password.
const (
	snmpSecretPurpose = "sa_snmp.secret" //nolint:gosec // G101: the name of a purpose, not a secret
	snmpPrivPurpose   = "sa_snmp.priv"
)

const (
	// snmpTestBudget bounds a Check now: a v3 read is a discovery and a GET of 2 s each, sent twice; the rest is the worker picking it up.
	snmpTestBudget = 40 * time.Second
	// snmpRoundRun bounds one batch of the window's round (64 devices).
	snmpRoundRun = time.Hour
	// snmpBatchTries bounds the reads of one batch of a round that device changes stop (#882).
	snmpBatchTries = 4
	// snmpWait is how long a Check now waits for a batch of the window's round to finish before it says busy.
	snmpWait = 30 * time.Second
	// The confidence of what a device states about itself; the kind from a family or a phrase is a little less sure.
	snmpStated = 0.9
	snmpKind   = 0.8
	// Reasons of sa_job rows of kind snmp (snmp_test: a Check now, as the old Test; the history reads it as a person's).
	snmpReasonTest   = "snmp_test"
	snmpReasonWindow = "window"
)

// SNMP reasons a Check now answers with (SnmpReason in contract.ts), beside the read statuses of sensorlink and the inventory's
// refusals it passes on.
const (
	SNMPOK          = "ok"
	SNMPNotSetUp    = "not_set_up"
	SNMPNotApproved = "not_approved"
	SNMPUnavailable = "unavailable"
	SNMPBusy        = "busy"
	SNMPMoved       = "moved"
	SNMPSecretLost  = "secret_lost"
	SNMPNoIP        = "no_ip"
)

// The states of a device's SNMP (SnmpState in contract.ts).
const (
	SNMPWorking      = "working"
	SNMPNotAnswering = "not_answering"
	SNMPWaiting      = "waiting"
)

// SNMPDevice is the SNMP of one device without its secrets (DeviceSnmp in contract.ts). IP and Name are the inventory's.
type SNMPDevice struct {
	DeviceID, Name                string
	IP                            netip.Addr // the device's own address; invalid when none
	State                         string     // working, not_answering, waiting, not_set_up
	ReadFrom                      netip.Addr // invalid when not set up
	ReadFromDefault               bool
	Version, Username, Auth, Priv string // Priv "aes128" or "none" for v3, "" for v2c
	Port                          int    // 0 when not set up
	SecretLast4, PrivLast4        string
	SecretLost                    bool
	LastCheckedAt, LastAnswerAt   time.Time // zero: never
	UpdatedAt                     time.Time
	LastReason                    string // the status of the last read; "" when never read
	Error                         string // plain words for a last read without an answer
	Answer                        *SNMPFacts
	Blocked                       *SNMPBlocked
}

// SNMPBlocked says why nothing is sent to a device now (SnmpBlocked in contract.ts).
type SNMPBlocked struct{ Reason, Message string }

// SNMPInput is the form of a device's SNMP (DeviceSnmpInput in contract.ts). A blank secret on an edit keeps the saved one, unless
// the read address changes. Port 0 is none given: 161. ReadFrom "" is the device's IP. CopyFrom names another device whose settings
// and secrets are copied on the box; then only ReadFrom is read besides it.
type SNMPInput struct {
	CopyFrom, ReadFrom                    string
	Version, Username, Auth, Priv         string
	Community, AuthPassword, PrivPassword secrets.Value
	Port                                  int
}

// SNMPCheckResult is what a Check now answers (SnmpCheckResult in contract.ts). Answer is set when the device answered.
type SNMPCheckResult struct {
	OK      bool
	Reason  string
	Message string
	Answer  *SNMPFacts
	Device  SNMPDevice
}

// SNMPNotice is a change the box made to SNMP settings by itself (SnmpNotice in contract.ts).
type SNMPNotice struct {
	ID   int64
	At   time.Time
	Text string
}

// snmpRow is a device's SNMP settings as stored.
type snmpRow struct {
	AssetID                       string
	ReadFrom                      netip.Addr
	ReadFromDefault               bool
	Version, Username, Auth, Priv string
	SecretLast4, PrivLast4        string
	Port                          int
	CreatedAt, UpdatedAt          time.Time
	LastCheckedAt, LastAnswerAt   time.Time
	LastStatus                    string
	answer                        string // JSON of sensorlink.SNMPValues, "" when none
	secretID, privID              string
	updatedAt                     string // as stored: snmpJob checks the row did not change since the batch read it
}

// snmpRun is the SNMP batch in progress, for SettingsChanged, AssetChanged, an edit of a device's SNMP and Stop.
type snmpRun struct {
	cancel context.CancelFunc
	// changed stops the batch because one of its devices changed (AssetChanged, its SNMP settings edited), with that device as the
	// cause: the round reads the batch again instead of ending.
	changed context.CancelCauseFunc
	// targets and assets are the batch's read addresses and devices: every one it was given until recheckSNMP, then only the ones it
	// still sends to (set under s.mu), so a change to a device the batch dropped does not stop it (#882).
	targets []netip.Addr
	assets  []string
	picked  bool // a Check now: the window does not bind it
	// deadline is when a round's batch stops by itself, the window's end or snmpRoundRun (a shorter window stops it earlier). Set under
	// s.mu once known.
	deadline time.Time
}

var (
	snmpUserRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)
	printASCII = regexp.MustCompile(`^[\x20-\x7e]*$`)
)

func bad(code, msg string) *apierr.Error { return apierr.New(400, code, msg) }

// snmpOff is the answer of every SNMP call when the service was built without secrets (a build that is not wired).
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

// codeSecretLost is the refusal of a saved secret this box cannot open (#847, #868; core/conn, agent-intake and response use the
// same code).
const codeSecretLost = "secret_lost"

// snmpLostText is what a person is told about a device whose saved SNMP secret is sealed under another master key.
const snmpLostText = "The saved SNMP community or password of this device was not restored (the backup was restored without its decryption key, or the box key changed). Open Edit, enter it again and save."

// errSNMPSecretLost is a device's secret found sealed under another master key while a job was built (snmpJob): nothing was sent.
var errSNMPSecretLost = errors.New("the saved SNMP community or password was not restored")

// errSNMPNotReadAddress is a job built for an address that is not the stored read address of the device whose secret it carries
// (snmpJob): refused before any secret is opened.
var errSNMPNotReadAddress = errors.New("sensoractive: an snmp target is not the read address of its device")

// snmpDeviceChanged is ErrStopped for a batch stopped only because one of its devices changed (AssetChanged: it moved, another
// device took its address, a field changed; or its SNMP settings were edited): snmpRound reads the batch again.
type snmpDeviceChanged struct{ asset string }

func (e *snmpDeviceChanged) Error() string {
	return "stopped: device " + e.asset + " of the batch changed"
}
func (e *snmpDeviceChanged) Is(target error) bool { return target == ErrStopped }

// snmpSecretLost is the answer of a Check now, and of an edit or a copy that keeps a secret this box cannot open.
func snmpSecretLost() *apierr.Error {
	return apierr.New(409, codeSecretLost, snmpLostText+" Nothing was sent.")
}

// snmpLost reports whether a saved secret of row r is sealed under another master key (a backup restored without its decryption
// key, or a key file made again: #868). Such a secret is gone for good: the device is skipped until a person types it again (Edit).
// Any other failure to open it is an error, never "lost" (secrets.IsWrongKey). The opened bytes are cleared at once.
func (s *Service) snmpLost(ctx context.Context, q coredb.DBTX, r snmpRow) (bool, error) {
	for _, x := range [...]struct{ id, purpose string }{{r.secretID, snmpSecretPurpose}, {r.privID, snmpPrivPurpose}} {
		if lost, err := s.secretLost(ctx, q, x.id, x.purpose); lost || err != nil {
			return lost, err
		}
	}
	return false, nil
}

// secretLost is snmpLost for one secret; an empty id (no privacy password) is not lost.
func (s *Service) secretLost(ctx context.Context, q coredb.DBTX, id, purpose string) (bool, error) {
	if id == "" {
		return false, nil
	}
	b, err := s.secrets.Open(ctx, q, id, purpose)
	clear(b)
	switch {
	case secrets.IsWrongKey(err):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("sensoractive: open snmp secret: %w", err)
	}
	return false, nil
}

const snmpCols = `asset_id, read_from, read_from_default, version, username, auth, priv, secret_id, secret_last4, priv_secret_id, priv_last4,
	coalesce(port, 161), created_at, updated_at, last_checked_at, last_status, last_answer_at, answer`

type rowsQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// snmpRows reads every device's SNMP settings, by device id.
func (s *Service) snmpRows(ctx context.Context, q rowsQuerier) ([]snmpRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+snmpCols+` FROM sa_snmp_device ORDER BY asset_id`)
	if err != nil {
		return nil, fmt.Errorf("sensoractive: read snmp settings: %w", err)
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
	var user, auth, priv, privID, checked, status, answered, answer sql.NullString
	var readFrom, created string
	if err := r.Scan(&row.AssetID, &readFrom, &row.ReadFromDefault, &row.Version, &user, &auth, &priv, &row.secretID, &row.SecretLast4, &privID,
		&row.PrivLast4, &row.Port, &created, &row.updatedAt, &checked, &status, &answered, &answer); err != nil {
		return snmpRow{}, fmt.Errorf("sensoractive: read snmp settings: %w", err)
	}
	row.Username, row.Auth, row.privID, row.LastStatus, row.answer = user.String, auth.String, privID.String, status.String, answer.String
	if row.Version == sensorlink.SNMPv3 {
		row.Priv = cmp.Or(priv.String, "none")
	}
	row.ReadFrom, _ = netip.ParseAddr(readFrom)
	row.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	row.UpdatedAt, _ = time.Parse(time.RFC3339Nano, row.updatedAt)
	if checked.Valid {
		row.LastCheckedAt, _ = time.Parse(time.RFC3339Nano, checked.String)
	}
	if answered.Valid {
		row.LastAnswerAt, _ = time.Parse(time.RFC3339Nano, answered.String)
	}
	return row, nil
}

// snmpRow reads the SNMP settings of device id; nil when it has none.
func (s *Service) snmpRow(ctx context.Context, q rowQuerier, id string) (*snmpRow, error) {
	r, err := scanSNMPRow(q.QueryRowContext(ctx, `SELECT `+snmpCols+` FROM sa_snmp_device WHERE asset_id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// snmpForm is a checked form; its secrets are plain text, for this call only.
type snmpForm struct {
	version, user, auth, priv string // priv "" for v2c and for v3 without privacy
	secret, privSecret        string // "" = keep the saved one
	port                      int    // 1..65535; 161 when the form gave none
}

// checkSNMP checks the form of a device's SNMP against the rules of the contract; prev is the saved settings of an edit, nil for a
// new one.
func checkSNMP(in SNMPInput, prev *snmpRow) (snmpForm, *apierr.Error) {
	f := snmpForm{version: in.Version, port: cmp.Or(in.Port, sensorlink.SNMPPort)}
	if f.port < 1 || f.port > 65535 {
		return f, bad("bad_port", "The port is a number from 1 to 65535. Leave it empty for 161, the SNMP port.")
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
	return f, nil
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

func (f snmpForm) words(readFrom netip.Addr) string {
	w := f.version + ", read from " + readFrom.String() + ", port " + strconv.Itoa(f.port)
	if f.version == sensorlink.SNMPv3 {
		w += ", user " + f.user + ", " + f.auth + ", " + cmp.Or(f.priv, "no privacy")
	}
	return w
}

// portColumn is the port as stored: NULL for 161.
func portColumn(port int) any {
	if port == sensorlink.SNMPPort {
		return nil
	}
	return port
}

// checkReadFrom checks a read address a person typed: one IPv4 address of a local network (inside or outside the LAN
// ranges: the person set it on this device), not a multicast, broadcast or reserved address, not the network or broadcast address
// of a LAN range, not the box or one of its trap addresses.
func (s *Service) checkReadFrom(ctx context.Context, text string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(text))
	if err != nil || !a.Unmap().Is4() {
		return netip.Addr{}, bad("bad_read_from", "Read from is the IPv4 address the device answers SNMP on, for example 192.168.1.1.")
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Addr{}, bad("bad_read_from", a.String()+" is a multicast, broadcast or reserved address, not the address of one device.")
	}
	if !localnet.Addr(a) {
		return netip.Addr{}, bad("read_from_not_local", fmt.Sprintf("%s is not a local network address (%s): SNMP reads stay on your own networks.", a, localnet.Names))
	}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, p := range prefixes(st.LANRanges) {
		if p.Bits() > 30 || !p.Contains(a) {
			continue
		}
		if a == p.Masked().Addr() || a == lastAddr(p) {
			return netip.Addr{}, bad("bad_read_from", fmt.Sprintf("%s is the network or broadcast address of the LAN range %s, not the address of one device.", a, p.Masked()))
		}
	}
	box, err := s.inv.BoxIPs(ctx)
	if err != nil {
		return netip.Addr{}, err
	}
	if slices.Contains(box, a) {
		return netip.Addr{}, apierr.New(409, "read_from_box", a.String()+" is the Vedette box itself or one of its trap addresses: it is never read.")
	}
	return a, nil
}

// lastAddr is the broadcast address of an IPv4 prefix: every host bit set.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	for i := range b {
		if keep := p.Bits() - 8*i; keep < 8 {
			b[i] |= 0xff >> max(keep, 0)
		}
	}
	return netip.AddrFrom4(b)
}

// deviceName is how a person knows the device in audit rows and notices.
func deviceName(a Asset) string {
	if a.Name != "" {
		return a.Name
	}
	if a.IP.IsValid() {
		return a.IP.String()
	}
	return a.ID
}

// SetSNMP sets up or edits the SNMP of device id (PUT /inventory/snmp/devices/{id}): the form, or a copy of another device's
// settings and secrets made on the box. Saving is the person's consent to read this device: its SNMP source switch is turned on
// first (audited by the inventory; an ignored device is refused there). A blank secret keeps the saved one, unless the read
// address changes: a person who can edit the form but never knew the secret cannot send it to an address of their own (as the
// scopes of before did). One audit row says who set what, never the secret.
func (s *Service) SetSNMP(ctx context.Context, actor, id string, in SNMPInput) (SNMPDevice, error) {
	if s.secrets == nil {
		return SNMPDevice{}, snmpOff()
	}
	a, err := s.inv.Asset(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return SNMPDevice{}, apierr.New(404, "not_found", "There is no device with this id.")
	}
	if err != nil {
		return SNMPDevice{}, err
	}
	box, err := s.inv.BoxIPs(ctx)
	if err != nil {
		return SNMPDevice{}, err
	}
	if a.IP.IsValid() && slices.Contains(box, a.IP) {
		return SNMPDevice{}, apierr.New(409, "box_device", "This is the Vedette box itself: it is never read with SNMP.")
	}
	if !a.IP.IsValid() {
		return SNMPDevice{}, apierr.New(409, SNMPNoIP, "This device has no address yet: SNMP can be set up once a sensor has seen its address.")
	}
	readFrom, deflt := a.IP, true
	if strings.TrimSpace(in.ReadFrom) != "" {
		if readFrom, err = s.checkReadFrom(ctx, in.ReadFrom); err != nil {
			return SNMPDevice{}, err
		}
		deflt = readFrom == a.IP
	} else if slices.Contains(box, readFrom) {
		return SNMPDevice{}, apierr.New(409, "read_from_box", readFrom.String()+" is the Vedette box itself or one of its trap addresses: it is never read.")
	}
	if err := s.readFromFree(ctx, s.db.Reader(), id, readFrom); err != nil {
		return SNMPDevice{}, err
	}
	var src *snmpRow
	var srcName string
	if in.CopyFrom != "" {
		if in.CopyFrom == id {
			return SNMPDevice{}, bad("copy_from_self", "Choose another device to copy from.")
		}
		// A copied secret goes only to the device's own address: sending it to an address a person types needs the secret typed
		// (the same rule as an edit that changes the read address).
		if !deflt {
			return SNMPDevice{}, bad("secret_required", fmt.Sprintf("Copy from sends the saved community or passwords only to this device's own address (%s). To read it at %s, type them instead of copying.", a.IP, readFrom))
		}
		if src, err = s.snmpRow(ctx, s.db.Reader(), in.CopyFrom); err != nil {
			return SNMPDevice{}, err
		}
		if src == nil {
			return SNMPDevice{}, apierr.New(404, "copy_from_not_found", "The device to copy from has no SNMP set up.")
		}
		if lost, _ := s.snmpLost(ctx, s.db.Reader(), *src); lost {
			return SNMPDevice{}, snmpSecretLost()
		}
		srcName = in.CopyFrom
		if sa, err := s.inv.Asset(ctx, in.CopyFrom); err == nil {
			srcName = deviceName(sa)
		}
	} else {
		// The form is checked before the switch is turned on, so a refused save changes nothing; the transaction checks it again.
		prev, err := s.snmpRow(ctx, s.db.Reader(), id)
		if err != nil {
			return SNMPDevice{}, err
		}
		if _, err := s.typedForm(ctx, s.db.Reader(), in, prev, readFrom); err != nil {
			return SNMPDevice{}, err
		}
	}
	// Saving is the person's consent to read this device: its SNMP switch is turned on (audited by the inventory). A device the
	// inventory refuses it for (ignored) is refused before anything is saved.
	if err := s.inv.TurnSNMPOn(ctx, actor, id); err != nil {
		return SNMPDevice{}, err
	}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		prev, err := s.snmpRow(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := s.readFromFree(ctx, tx, id, readFrom); err != nil {
			return err
		}
		var f snmpForm
		if src != nil {
			if f, err = s.copiedForm(ctx, tx, in.CopyFrom, src); err != nil {
				return err
			}
		} else if f, err = s.typedForm(ctx, tx, in, prev, readFrom); err != nil {
			return err
		}
		defer func() { f.secret, f.privSecret = "", "" }()
		return s.saveSNMP(ctx, tx, actor, a, prev, f, readFrom, deflt, srcName)
	})
	if err != nil {
		return SNMPDevice{}, err
	}
	s.snmpSettingsChanged(id)
	return s.SNMPDeviceOf(ctx, id)
}

// typedForm checks the form a person typed against prev, the saved settings (nil for a new one): the rules of checkSNMP, a secret
// typed again when the read address changes, and a kept secret this box can open (#868).
func (s *Service) typedForm(ctx context.Context, q coredb.DBTX, in SNMPInput, prev *snmpRow, readFrom netip.Addr) (snmpForm, error) {
	f, aerr := checkSNMP(in, prev)
	if aerr != nil {
		return f, aerr
	}
	if prev == nil {
		return f, nil
	}
	if prev.ReadFrom != readFrom && (f.secret == "" || (f.priv != "" && f.privSecret == "")) {
		what := "community"
		if f.version == sensorlink.SNMPv3 {
			what = "passwords"
		}
		return f, bad("secret_required", fmt.Sprintf("SNMP reads would go to a new address (%s instead of %s). Type the %s again to allow that.", readFrom, prev.ReadFrom, what))
	}
	if f.secret == "" {
		if lost, _ := s.secretLost(ctx, q, prev.secretID, snmpSecretPurpose); lost {
			return f, snmpSecretLost()
		}
	}
	if f.priv != "" && f.privSecret == "" {
		if lost, _ := s.secretLost(ctx, q, prev.privID, snmpPrivPurpose); lost {
			return f, snmpSecretLost()
		}
	}
	return f, nil
}

// readFromFree refuses a read address another device already reads from (409 read_from_taken, naming it): one address is one
// device's, and the round reads an address once.
func (s *Service) readFromFree(ctx context.Context, q rowQuerier, id string, readFrom netip.Addr) error {
	var other string
	err := q.QueryRowContext(ctx, `SELECT asset_id FROM sa_snmp_device WHERE read_from = ? AND asset_id <> ? LIMIT 1`, readFrom.String(), id).Scan(&other)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("sensoractive: read snmp settings: %w", err)
	}
	name := other
	if a, err := s.inv.Asset(ctx, other); err == nil {
		name = deviceName(a)
	}
	return apierr.New(409, "read_from_taken", fmt.Sprintf("%s is already the SNMP read address of %s. One address is read for one device: change it there first, or choose another address.", readFrom, name))
}

// copiedForm is the form of device from's settings, its secrets opened in the transaction (they are sealed again for the device
// that copies them and never leave core). A secret this box cannot open is 409 secret_lost.
func (s *Service) copiedForm(ctx context.Context, tx *sql.Tx, from string, src *snmpRow) (snmpForm, error) {
	cur, err := s.snmpRow(ctx, tx, from) // read again in the transaction: the settings copied are the ones saved now
	if err != nil {
		return snmpForm{}, err
	}
	if cur == nil {
		return snmpForm{}, apierr.New(404, "copy_from_not_found", "The device to copy from has no SNMP set up.")
	}
	*src = *cur
	f := snmpForm{version: src.Version, user: src.Username, auth: src.Auth, port: src.Port}
	open := func(id, purpose string) (string, error) {
		b, err := s.secrets.Open(ctx, tx, id, purpose)
		defer clear(b)
		if secrets.IsWrongKey(err) {
			return "", snmpSecretLost()
		}
		if err != nil {
			return "", fmt.Errorf("sensoractive: open snmp secret: %w", err)
		}
		return string(b), nil
	}
	if f.secret, err = open(src.secretID, snmpSecretPurpose); err != nil {
		return snmpForm{}, err
	}
	if src.privID != "" {
		f.priv = sensorlink.SNMPPrivAES128
		if f.privSecret, err = open(src.privID, snmpPrivPurpose); err != nil {
			return snmpForm{}, err
		}
	}
	return f, nil
}

// saveSNMP writes a checked form for device a: the secrets sealed (or replaced) in core/secrets, the rest in sa_snmp_device, one
// audit row. A blank secret keeps prev's; one this box cannot open is 409 secret_lost.
func (s *Service) saveSNMP(ctx context.Context, tx *sql.Tx, actor string, a Asset, prev *snmpRow, f snmpForm, readFrom netip.Addr, deflt bool, copied string) error {
	now := s.now()
	var secretID, last4 string
	switch {
	case prev == nil:
		id, l4, err := s.secrets.Seal(ctx, tx, snmpSecretPurpose, []byte(f.secret), true)
		if err != nil {
			return fmt.Errorf("sensoractive: seal snmp secret: %w", err)
		}
		secretID, last4 = id, l4
	case f.secret != "":
		l4, err := s.secrets.Replace(ctx, tx, prev.secretID, snmpSecretPurpose, []byte(f.secret), true)
		if err != nil {
			return fmt.Errorf("sensoractive: replace snmp secret: %w", err)
		}
		secretID, last4 = prev.secretID, l4
	default:
		if lost, _ := s.secretLost(ctx, tx, prev.secretID, snmpSecretPurpose); lost { // another failure to open it: kept, as before
			return snmpSecretLost()
		}
		secretID, last4 = prev.secretID, prev.SecretLast4
	}
	var privID any
	privLast4 := ""
	prevPriv := ""
	if prev != nil {
		prevPriv = prev.privID
	}
	switch {
	case f.priv == "" && prevPriv != "":
		if err := s.secrets.Delete(ctx, tx, prevPriv); err != nil {
			return fmt.Errorf("sensoractive: delete snmp privacy password: %w", err)
		}
	case f.priv != "" && prevPriv == "":
		pid, pl4, err := s.secrets.Seal(ctx, tx, snmpPrivPurpose, []byte(f.privSecret), true)
		if err != nil {
			return fmt.Errorf("sensoractive: seal snmp privacy password: %w", err)
		}
		privID, privLast4 = pid, pl4
	case f.priv != "":
		privID, privLast4 = prevPriv, prev.PrivLast4
		if f.privSecret != "" {
			l4, err := s.secrets.Replace(ctx, tx, prevPriv, snmpPrivPurpose, []byte(f.privSecret), true)
			if err != nil {
				return fmt.Errorf("sensoractive: replace snmp privacy password: %w", err)
			}
			privLast4 = l4
		} else if lost, _ := s.secretLost(ctx, tx, prevPriv, snmpPrivPurpose); lost {
			return snmpSecretLost()
		}
	}
	if prev == nil {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sa_snmp_device (asset_id, read_from, read_from_default, version, username, auth, priv, secret_id, secret_last4,
			priv_secret_id, priv_last4, port, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			a.ID, readFrom.String(), deflt, f.version, nullable(f.user), nullable(f.auth), nullable(f.priv), secretID, last4, privID, privLast4,
			portColumn(f.port), now, now); err != nil {
			return fmt.Errorf("sensoractive: save snmp settings: %w", err)
		}
	} else {
		// A new read address or version starts the state again: what the old one answered is not this one's.
		reset := ""
		if prev.ReadFrom != readFrom || prev.Version != f.version {
			reset = "last_checked_at = NULL, last_status = NULL, last_answer_at = NULL, answer = NULL, "
		}
		if _, err := tx.ExecContext(ctx, `UPDATE sa_snmp_device SET `+reset+`read_from = ?, read_from_default = ?, version = ?, username = ?, auth = ?, priv = ?,
			secret_last4 = ?, priv_secret_id = ?, priv_last4 = ?, port = ?, updated_at = ? WHERE asset_id = ?`,
			readFrom.String(), deflt, f.version, nullable(f.user), nullable(f.auth), nullable(f.priv), last4, privID, privLast4, portColumn(f.port), now,
			a.ID); err != nil {
			return fmt.Errorf("sensoractive: save snmp settings: %w", err)
		}
	}
	detail := f.words(readFrom)
	if copied != "" {
		detail += ", copied from " + copied
	}
	return s.auditTx(ctx, tx, actor, "inventory.snmp_set", deviceName(a), detail)
}

// DeleteSNMP removes the SNMP settings of device id and their secrets in one transaction (DELETE /inventory/snmp/devices/{id}). What
// the device said stays in the inventory; its SNMP switch is left as it is. 404 when it has none.
func (s *Service) DeleteSNMP(ctx context.Context, actor, id string) error {
	if s.secrets == nil {
		return snmpOff()
	}
	name := id
	if a, err := s.inv.Asset(ctx, id); err == nil {
		name = deviceName(a)
	}
	defer s.snmpSettingsChanged(id) // after the delete committed (or failed: a needless stop, retried next round)
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		prev, err := s.snmpRow(ctx, tx, id)
		if err != nil {
			return err
		}
		if prev == nil {
			return apierr.New(404, "not_found", "This device has no SNMP set up.")
		}
		if err := s.dropSNMP(ctx, tx, *prev); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "inventory.snmp_remove", name, prev.Version+", read from "+prev.ReadFrom.String())
	})
}

// dropSNMP deletes a device's settings and their secrets.
func (s *Service) dropSNMP(ctx context.Context, tx *sql.Tx, r snmpRow) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM sa_snmp_device WHERE asset_id = ?`, r.AssetID); err != nil {
		return fmt.Errorf("sensoractive: delete snmp settings: %w", err)
	}
	if s.secrets == nil {
		return nil
	}
	for _, sid := range []string{r.secretID, r.privID} {
		if sid == "" {
			continue
		}
		if err := s.secrets.Delete(ctx, tx, sid); err != nil {
			return fmt.Errorf("sensoractive: delete snmp secret: %w", err)
		}
	}
	return nil
}

// DeviceDeleted is sensor-active's part of deleting a device (core/lifecycle, inside the inventory's write): its queued or waiting
// checks are stopped, its SNMP settings with their secrets and its weekly port record go with it. Its finished runs stay: they are a
// log, with the device id and name they ran on.
func (s *Service) DeviceDeleted(ctx context.Context, tx *sql.Tx, d lifecycle.Delete) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM sa_all_ports WHERE asset_id = ?`, d.Device); err != nil {
		return fmt.Errorf("sensoractive: forget a deleted device: %w", err)
	}
	if err := s.runs.SubjectGoneTx(ctx, tx, ModuleID, "device", d.Device, "The device was deleted"); err != nil {
		return fmt.Errorf("sensoractive: forget a deleted device: %w", err)
	}
	r, err := s.snmpRow(ctx, tx, d.Device)
	if err != nil || r == nil {
		return err
	}
	return s.dropSNMP(ctx, tx, *r)
}

// DeleteCommitted stops an SNMP batch that holds the deleted device.
func (s *Service) DeleteCommitted(_ context.Context, d lifecycle.Delete) {
	s.snmpSettingsChanged(d.Device)
}

// DeviceMerged is sensor-active's part of a merge (core/lifecycle, inside the inventory's write): device m.From was the same machine
// as m.Into. Its runs become Into's (the runs' subject, INV-23: Into's Last checks lists them and its next check compares with
// them); its weekly port record becomes Into's unless Into has its own. A device has one SNMP
// setting: when only From has one it becomes Into's (a read address that was From's IP stays the address it was: if Into is
// elsewhere, nothing is sent until a person sets it, INV-10 (i)); when both have one, the one that works is kept (snmpBetter) and the
// other goes with its secrets, and a notice says which was kept and which removed (sa_snmp_notice, until a person dismisses it).
func (s *Service) DeviceMerged(ctx context.Context, tx *sql.Tx, m lifecycle.Merge) error {
	from, into := m.From, m.Into
	if from == "" || into == "" || from == into {
		return nil
	}
	if err := s.runs.SubjectMovedTx(ctx, tx, ModuleID, "device", from, into); err != nil {
		return fmt.Errorf("sensoractive: merge device checks: %w", err)
	}
	for _, q := range []string{
		`UPDATE OR IGNORE sa_all_ports SET asset_id = ?2 WHERE asset_id = ?1`, // a scan record: into's own stays
		`DELETE FROM sa_all_ports WHERE asset_id = ?1`,
	} {
		if _, err := tx.ExecContext(ctx, q, from, into); err != nil {
			return fmt.Errorf("sensoractive: merge device checks: %w", err)
		}
	}
	f, err := s.snmpRow(ctx, tx, from)
	if err != nil || f == nil {
		return err
	}
	i, err := s.snmpRow(ctx, tx, into)
	if err != nil {
		return err
	}
	if i != nil {
		kept, gone := *i, *f
		if snmpBetter(*f, *i) {
			kept, gone = *f, *i
		}
		if err := s.dropSNMP(ctx, tx, gone); err != nil {
			return err
		}
		text := fmt.Sprintf("%s was merged into %s and both had SNMP settings. Kept: %s. Removed: %s.",
			nameOr(m.FromName, from), nameOr(m.IntoName, into), snmpSummary(kept), snmpSummary(gone))
		if _, err := tx.ExecContext(ctx, `INSERT INTO sa_snmp_notice (at, text) VALUES (?, ?)`, s.now(), clip(text, 2000)); err != nil {
			return fmt.Errorf("sensoractive: note the merged snmp settings: %w", err)
		}
		if kept.AssetID == into {
			return nil
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sa_snmp_device SET asset_id = ?, updated_at = ? WHERE asset_id = ?`, into, s.now(), from); err != nil {
		return fmt.Errorf("sensoractive: merge snmp settings: %w", err)
	}
	return nil
}

// MergeCommitted stops an SNMP batch that holds either device: their settings changed.
func (s *Service) MergeCommitted(_ context.Context, m lifecycle.Merge) {
	s.snmpSettingsChanged(m.From)
	s.snmpSettingsChanged(m.Into)
}

// snmpBetter says SNMP settings a work better than b, so a merge keeps a: the last read answered (ok) over one that did not or never
// ran, then the later answer, then the later save. On a full tie b (the device that stays) keeps its own.
func snmpBetter(a, b snmpRow) bool {
	if ao, bo := a.LastStatus == "ok", b.LastStatus == "ok"; ao != bo {
		return ao
	}
	if !a.LastAnswerAt.Equal(b.LastAnswerAt) {
		return a.LastAnswerAt.After(b.LastAnswerAt)
	}
	return a.UpdatedAt.After(b.UpdatedAt)
}

// snmpSummary names SNMP settings for a person, without any secret: "SNMP v3, user mon, read from 192.0.2.10:161, last answered".
func snmpSummary(r snmpRow) string {
	out := "SNMP " + r.Version
	if r.Username != "" {
		out += ", user " + r.Username
	}
	if r.ReadFrom.IsValid() {
		out += fmt.Sprintf(", read from %s:%d", r.ReadFrom, cmp.Or(r.Port, sensorlink.SNMPPort))
	}
	switch r.LastStatus {
	case "ok":
		out += ", last read answered"
	case "":
		out += ", never read"
	default:
		out += ", last read failed"
	}
	return out
}

func nameOr(name, id string) string { return cmp.Or(name, id) }

// snmpPolicy decides whether a device may be read with SNMP at all: "" when it may, else the reason. It is the inventory's
// SNMPPolicy (the device's own SNMP setting, so a network scan turned off does not stop SNMP, and SNMP turned off stops it) without
// the fragile rule (a fragile or unclassified device is read), plus the device's approval and the box's own addresses and decoys
// (box, from Inventory.BoxIPs: always refused, fragile or not).
func (s *Service) snmpPolicy(ctx context.Context, assetID string, box []netip.Addr) (Asset, string, error) {
	dec, err := s.inv.SNMPPolicy(ctx, assetID)
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
		return a, SNMPNoIP, nil
	case slices.Contains(box, a.IP):
		return a, reasonBox, nil
	case !a.Approved:
		return a, SNMPNotApproved, nil
	}
	return a, "", nil
}

// snmpAllowed is snmpPolicy for the device of r plus the rules of its read address: a read address left to the device's IP
// that the device has since left is not followed (moved: a copied network card looks the same, #829 C4); the read address is never the
// box or a decoy, never outside the local networks, never excluded. sc is the scope of the settings read for this decision.
func (s *Service) snmpAllowed(ctx context.Context, r snmpRow, box []netip.Addr, sc scope) (string, error) {
	a, why, err := s.snmpPolicy(ctx, r.AssetID, box)
	if err != nil || why != "" {
		return why, err
	}
	switch {
	case r.ReadFromDefault && a.IP != r.ReadFrom:
		return SNMPMoved, nil
	case slices.Contains(box, r.ReadFrom):
		return reasonBox, nil
	case !localnet.Addr(r.ReadFrom):
		return "out_of_scope", nil
	case sc.excluded(r.ReadFrom):
		return reasonExcluded, nil
	}
	return "", nil
}

// snmpRefusals are the refusals a Check now answers with as they are (SnmpReason in contract.ts).
var snmpRefusals = []string{SNMPNotApproved, "out_of_scope", reasonScanningOff, reasonScopeNotConfirmed, "declared_by_hand", reasonBox, reasonNever,
	reasonSNMPOff, reasonExcluded, SNMPNoIP, SNMPMoved}

// snmpTarget is one device of a batch: its id, its read address and its settings.
type snmpTarget struct {
	asset string
	ip    netip.Addr
	row   snmpRow
}

// CheckSNMP reads one device now at its read address (POST /inventory/snmp/devices/{id}/check): every rule of the window's round but
// the window. It answers what the device said, recorded on the device, or a plain reason; one audit row says who checked which
// device. 409 not_set_up, and secret_lost when its saved secret this box cannot open: nothing is sent.
func (s *Service) CheckSNMP(ctx context.Context, actor, id string) (SNMPCheckResult, error) {
	if s.secrets == nil {
		return SNMPCheckResult{}, snmpOff()
	}
	a, err := s.inv.Asset(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return SNMPCheckResult{}, apierr.New(404, "not_found", "There is no device with this id.")
	}
	if err != nil {
		return SNMPCheckResult{}, err
	}
	row, err := s.snmpRow(ctx, s.db.Reader(), id)
	if err != nil {
		return SNMPCheckResult{}, err
	}
	if row == nil {
		return SNMPCheckResult{}, apierr.New(409, SNMPNotSetUp, "SNMP is not set up for this device: set it up first.")
	}
	// Only a lost secret is refused here; any other failure to open one is reported where the job is built, as before.
	if lost, _ := s.snmpLost(ctx, s.db.Reader(), *row); lost {
		return SNMPCheckResult{}, snmpSecretLost()
	}
	res, err := s.checkSNMP(ctx, actor, label(a), *row)
	if err != nil {
		return SNMPCheckResult{}, err
	}
	res.Message = snmpMessage(res.Reason, deviceName(a), a.IP, *row, res.Message)
	res.OK = res.Reason == SNMPOK
	wctx := context.WithoutCancel(ctx) // the check happened: its audit row is written even when the caller has gone
	werr := s.db.Write(wctx, func(tx *sql.Tx) error {
		return s.auditTx(wctx, tx, actor, "inventory.snmp_check", deviceName(a), row.ReadFrom.String()+": "+res.Reason)
	})
	if werr != nil {
		return SNMPCheckResult{}, werr
	}
	res.Device, err = s.SNMPDeviceOf(wctx, id)
	return res, err
}

func (s *Service) checkSNMP(ctx context.Context, actor, lbl string, row snmpRow) (SNMPCheckResult, error) {
	box, err := s.inv.BoxIPs(ctx)
	if err != nil {
		return SNMPCheckResult{}, err
	}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return SNMPCheckResult{}, err
	}
	var res SNMPCheckResult
	why, err := s.snmpAllowed(ctx, row, box, newScope(st))
	switch {
	case errors.Is(err, ErrNotFound):
		return SNMPCheckResult{}, apierr.New(404, "not_found", "There is no device with this id.")
	case err != nil:
		return SNMPCheckResult{}, err
	case why != "":
		s.blocked(ctx, row.AssetID, why)
		res.Reason = why
		if !slices.Contains(snmpRefusals, why) { // a refusal of the inventory this list does not know yet: say it in words
			res.Reason, res.Message = SNMPUnavailable, "the inventory's scan policy refuses this device ("+why+")"
		}
		return res, nil
	}
	if ready, msg := s.SNMPStatus(); !ready {
		res.Reason, res.Message = SNMPUnavailable, msg
		return res, nil
	}
	got := make(chan []sensorlink.SNMPAnswer, 1) // the work hands its answers over: the caller may stop waiting before the work ends
	var heard []sensorlink.SNMPAnswer            // the same answers for the run's end (written and read on the run's goroutine)
	ended := func(ctx context.Context, err error) run.Result {
		if err != nil || len(heard) == 0 {
			return snmpResult(ctx, err)
		}
		if a := heard[0]; a.Status != sensorlink.SNMPStatusOK { // the read went out and the device did not answer it
			return run.Result{Status: run.Failed, Error: snmpMessage(a.Status, "", row.ReadFrom, row, "")}
		}
		if x := execOf(ctx); x != nil {
			s.stepProgress(ctx, x, 1, 1, 1)
		}
		return run.Result{}
	}
	err = s.doWork(ctx, run.Spec{Kind: RunSNMP, Title: "SNMP read of " + lbl, Trigger: run.Manual, RequestedBy: actor,
		Subject: &run.Subject{Kind: "device", ID: row.AssetID, Label: lbl}, Steps: []run.StepPlan{{Name: lbl, Total: 1}}},
		func(ctx context.Context) error {
			if !s.lockSNMPWithin(ctx, snmpWait) {
				return errSNMPBusy
			}
			defer s.snmpMu.Unlock()
			jobID, err := s.startJob(ctx, KindSNMP, snmpReasonTest, 1)
			if err != nil {
				return err
			}
			bctx, cancel := context.WithTimeout(ctx, snmpTestBudget)
			defer cancel()
			answers, err := s.snmpBatch(bctx, jobID, []snmpTarget{{asset: row.AssetID, ip: row.ReadFrom, row: row}}, true)
			got <- answers
			heard = answers
			s.closeSNMPJob(ctx, jobID, 1, err)
			return err
		}, ended, snmpWait, "The SNMP reader stayed busy, so this read did not start")
	if errors.Is(err, errSNMPBusy) || errors.Is(err, errNotStarted) {
		res.Reason = SNMPBusy
		return res, nil
	}
	var answers []sensorlink.SNMPAnswer
	select {
	case answers = <-got:
	default:
	}
	switch {
	case errors.Is(err, ErrStopped):
		return SNMPCheckResult{}, apierr.New(409, "stopped", "The check was stopped: the scan settings or this device's SNMP changed, or the module was turned off.")
	case errors.Is(err, errSNMPSecretLost):
		return SNMPCheckResult{}, snmpSecretLost()
	case errors.Is(err, ErrSNMPUnavailable), errors.Is(err, ErrWorkerLost), errors.Is(err, context.DeadlineExceeded):
		_, msg := s.SNMPStatus()
		res.Reason, res.Message = SNMPUnavailable, cmp.Or(msg, "the scan worker did not finish the read in time")
		return res, nil
	case err != nil:
		return SNMPCheckResult{}, err
	case len(answers) == 0: // the batch's own check dropped it: the device or its settings changed in between
		return SNMPCheckResult{}, apierr.New(409, "changed", "The device or its SNMP settings changed while the check started. Check again.")
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

// errSNMPBusy says the SNMP reader was busy with another read for the whole wait of a Check now.
var errSNMPBusy = errors.New("sensoractive: the snmp reader is busy")

// snmpResult is how an snmp_read run ends, from its batch's error.
func snmpResult(ctx context.Context, err error) run.Result {
	switch {
	case err == nil:
		return run.Result{}
	case errors.Is(err, errSNMPBusy):
		return run.Result{Status: run.Failed, Error: "The SNMP reader stayed busy"}
	case errors.Is(err, ErrStopped) && ctx.Err() != nil:
		return run.Result{Status: run.Partial, Error: "stopped"}
	case errors.Is(err, ErrStopped):
		return run.Result{Status: run.Partial, Error: "Stopped: the window closed, the scan settings or a device's SNMP changed"}
	}
	return run.Result{Status: run.Failed, Error: err.Error()}
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
// (SettingsChanged sees it), then the settings, the window (not for a Check now) and the scope are read again for every target, then
// the probe row is written, and only then the secrets are opened and the job handed to the worker. What the devices answered is
// recorded. The caller holds snmpMu. A batch stopped only because one of its devices changed returns *snmpDeviceChanged (an
// ErrStopped).
func (s *Service) snmpBatch(ctx context.Context, jobID string, targets []snmpTarget, picked bool) (_ []sensorlink.SNMPAnswer, err error) {
	v0 := s.ver.Load()
	rctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	run := &snmpRun{cancel: func() { cancel(nil) }, changed: cancel, picked: picked}
	defer func() {
		// The cause of the batch's own context: the first cancel wins, and a deadline that passed first is not a device change.
		var dc *snmpDeviceChanged
		if errors.Is(err, ErrStopped) && ctx.Err() == nil && errors.As(context.Cause(rctx), &dc) {
			err = dc
		}
	}()
	for _, t := range targets {
		run.targets, run.assets = append(run.targets, t.ip), append(run.assets, t.asset)
	}
	if s.beforeSNMPBatch != nil {
		s.beforeSNMPBatch()
	}
	s.mu.Lock()
	s.snmpCur = run
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.snmpCur = nil
		s.mu.Unlock()
	}()
	// The module turned off before the batch registered had nothing to cancel: off is sticky, and Stop sets it before it reads
	// snmpCur, so either Stop saw this run and cancels it, or this sees off (SYS-5, #855).
	if s.off.Load() {
		return nil, ErrStopped
	}

	st, err := s.inv.Settings(rctx)
	if err == nil {
		err = st.allowed()
	}
	if err != nil {
		return nil, s.stopFor(err)
	}
	end, ok := s.windowNow(ctx, st)
	if !ok && !picked {
		return nil, ErrStopped
	}
	if !picked { // a round's batch ends with the window, as an nmap run does (INV-3)
		timeout := min(end.Sub(s.clock()), snmpRoundRun)
		if timeout <= 0 {
			return nil, ErrStopped
		}
		var stop context.CancelFunc
		rctx, stop = context.WithTimeout(rctx, timeout)
		defer stop()
		s.mu.Lock()
		run.deadline = s.clock().Add(timeout) // a window shortened under the batch stops it (snmpChanged, #715)
		s.mu.Unlock()
	}
	// The round chose its devices when it started: read their settings and policy again now, so a device set to never, no longer
	// approved, moved or deleted, or whose SNMP was edited or removed since, gets nothing.
	if targets, err = s.recheckSNMP(rctx, targets, newScope(st)); err != nil {
		if rctx.Err() != nil {
			return nil, ErrStopped
		}
		return nil, err
	}
	if len(targets) == 0 {
		return nil, nil
	}
	// From now on only the devices it still sends to stop it when they change: one the recheck dropped gets nothing whatever
	// it does now, and one it kept that changed after the recheck read it is still listed here, so its change stops the batch. A
	// change of settings between the recheck and the job is caught by snmpJob, which reads each row again with its secrets.
	ips, assets := make([]netip.Addr, len(targets)), make([]string, len(targets))
	for i, t := range targets {
		ips[i], assets[i] = t.ip, t.asset
	}
	s.mu.Lock()
	run.targets, run.assets = ips, assets
	s.mu.Unlock()
	// SNMP reaches past lan_ranges only for a device a person set it up on, never an excluded address: a target the
	// exclusions took since the targets were chosen stops the batch. A target inside lan_ranges is asked again of the inventory,
	// which reads the settings fresh: one it no longer holds (excluded since, or the ranges changed under the batch) stops it too,
	// fail closed.
	sc := newScope(st)
	for _, t := range targets {
		if sc.excluded(t.ip) {
			return nil, ErrStopped
		}
		if !sc.contains(t.ip) {
			continue
		}
		if in, err := s.inv.InScope(rctx, t.ip); err != nil || !in {
			return nil, ErrStopped
		}
	}
	rate := max(1, min(st.Rate, 1000))
	probeID, err := s.insertSNMPProbe(rctx, jobID, rate, targets)
	if err != nil {
		if rctx.Err() != nil { // stopped before the row was written: nothing was sent
			return nil, ErrStopped
		}
		return nil, err
	}
	if rctx.Err() != nil || s.ver.Load() != v0 {
		s.finishProbe(ctx, probeID, stoppedText)
		return nil, ErrStopped
	}
	job, err := s.snmpJob(rctx, rate, targets)
	switch {
	case errors.Is(err, ErrStopped):
		s.finishProbe(ctx, probeID, "stopped: the SNMP settings of a device changed or were removed")
		return nil, ErrStopped
	case err != nil && rctx.Err() != nil:
		s.finishProbe(ctx, probeID, stoppedText)
		return nil, ErrStopped
	case errors.Is(err, errSNMPSecretLost):
		s.finishProbe(ctx, probeID, "failed: a saved SNMP secret was not restored")
		return nil, err
	case errors.Is(err, errSNMPNotReadAddress):
		s.finishProbe(ctx, probeID, "refused: a target was not the read address of its device")
		s.log.ErrorContext(ctx, "sensoractive: an snmp job named an address that is not its device's read address; nothing was sent", "job", jobID)
		return nil, err
	case err != nil:
		s.finishProbe(ctx, probeID, "failed: the SNMP settings could not be read")
		return nil, err
	}
	answers, err := s.snmp.RunSNMP(rctx, job)
	var result string
	var dc *snmpDeviceChanged
	switch {
	case rctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) && errors.As(context.Cause(rctx), &dc):
		result, err = "stopped: a device of the batch moved or changed", ErrStopped
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
	return answers, s.recordSNMP(ctx, targets, answers)
}

// recheckSNMP reads every target's settings and policy again right before a batch: a device whose SNMP was removed, whose read address
// changed, that the policy now refuses (never, not approved, the box, hand-added and off, out of scope, moved) or that is gone is
// dropped; settings edited otherwise are taken as they are now (snmpJob reads them once more with the secrets).
func (s *Service) recheckSNMP(ctx context.Context, targets []snmpTarget, sc scope) ([]snmpTarget, error) {
	rows, err := s.snmpRows(ctx, s.db.Reader())
	if err != nil {
		return nil, err
	}
	box, err := s.inv.BoxIPs(ctx)
	if err != nil {
		return nil, err
	}
	var out []snmpTarget
	for _, t := range targets {
		j := slices.IndexFunc(rows, func(r snmpRow) bool { return r.AssetID == t.asset })
		if j < 0 || rows[j].ReadFrom != t.ip {
			continue
		}
		why, err := s.snmpAllowed(ctx, rows[j], box, sc)
		if errors.Is(err, ErrNotFound) || err == nil && why != "" {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, snmpTarget{asset: t.asset, ip: t.ip, row: rows[j]})
	}
	return out, nil
}

// snmpJob opens the secrets of the batch's devices (only here, only for the job) and builds the job of the wire, each secret inside
// the one target it belongs to.
//
// The secrets are opened in one read transaction that also reads each device's settings again. A target that is not the stored read
// address of its device is refused (errSNMPNotReadAddress): a secret is only ever sent to that one address. Settings edited
// (version, secrets, anything: updated_at) or removed since the batch read them stop the batch (ErrStopped), so a v3 password never
// leaves as a v2c community.
func (s *Service) snmpJob(ctx context.Context, rate int, targets []snmpTarget) (job sensorlink.SNMPJob, err error) {
	job = sensorlink.SNMPJob{Rate: rate}
	tx, err := s.db.Reader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return job, fmt.Errorf("sensoractive: read snmp settings: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	defer func() {
		if err != nil { // nothing half-built leaves this function
			for i := range job.Targets {
				job.Targets[i].Credential = sensorlink.SNMPCredential{}
			}
			job.Targets = nil
		}
	}()
	for _, t := range targets {
		var readFrom, version, secretID, privID, updated string
		err := tx.QueryRowContext(ctx, `SELECT read_from, version, secret_id, coalesce(priv_secret_id, ''), updated_at FROM sa_snmp_device WHERE asset_id = ?`, t.asset).
			Scan(&readFrom, &version, &secretID, &privID, &updated)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return job, ErrStopped
		case err != nil:
			return job, fmt.Errorf("sensoractive: read snmp settings: %w", err)
		case readFrom != t.ip.String() || t.row.ReadFrom != t.ip || t.row.AssetID != t.asset:
			return job, fmt.Errorf("%w (%s, device %s)", errSNMPNotReadAddress, t.ip, t.asset)
		case version != t.row.Version || secretID != t.row.secretID || privID != t.row.privID || updated != t.row.updatedAt:
			return job, ErrStopped
		}
		secret, err := s.secrets.Open(ctx, tx, t.row.secretID, snmpSecretPurpose)
		if secrets.IsWrongKey(err) {
			return job, fmt.Errorf("%w (device %s)", errSNMPSecretLost, t.asset)
		}
		if err != nil {
			return job, fmt.Errorf("sensoractive: open snmp secret: %w", err)
		}
		w := sensorlink.SNMPCredential{Version: t.row.Version}
		if t.row.Port != sensorlink.SNMPPort {
			w.Port = t.row.Port // 161 stays off the wire (sensor-protocol.md section 10)
		}
		switch t.row.Version {
		case sensorlink.SNMPv2c:
			w.Community = string(secret)
		default:
			w.User, w.Auth, w.AuthPass = t.row.Username, t.row.Auth, string(secret)
			if t.row.privID != "" {
				priv, err := s.secrets.Open(ctx, tx, t.row.privID, snmpPrivPurpose)
				if secrets.IsWrongKey(err) {
					return job, fmt.Errorf("%w (device %s)", errSNMPSecretLost, t.asset)
				}
				if err != nil {
					return job, fmt.Errorf("sensoractive: open snmp privacy password: %w", err)
				}
				w.Priv, w.PrivPass = sensorlink.SNMPPrivAES128, string(priv)
				clear(priv)
			}
		}
		clear(secret)
		job.Targets = append(job.Targets, sensorlink.SNMPTarget{IP: t.ip.String(), Credential: w})
	}
	return job, nil
}

// insertSNMPProbe writes the probe row of a batch before anything is sent (INV-9): shape snmp, the pace, the read addresses, and in
// flags what was asked and how (versions and ports, never a secret).
func (s *Service) insertSNMPProbe(ctx context.Context, jobID string, rate int, targets []snmpTarget) (int64, error) {
	addrs := make([]netip.Addr, len(targets))
	ways := map[string]int{}
	for i, t := range targets {
		addrs[i] = t.ip
		ways[fmt.Sprintf("%s UDP %d", t.row.Version, t.row.Port)]++
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	var how []string
	for w, n := range ways {
		how = append(how, fmt.Sprintf("%s ×%d", w, n))
	}
	slices.Sort(how)
	flags := clip("GET sysDescr sysObjectID sysName entPhysical.1 class model softwareRev serialNum mtxrLicVersion.0; timeout 2s retries 1; each device's own settings at its read address: "+strings.Join(how, ", "), 300)
	var id int64
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO sa_probe (time, run_id, shape, rate, hosts, flags, targets, result) VALUES (?, ?, 'snmp', ?, ?, ?, ?, 'started')`,
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

// recordSNMP writes what the devices said into the inventory (source snmp), on the device each read was for (AssetHint.Device:
// never by the read address), and the state of each device's last read. An observation the inventory refuses (a value it does
// not take) is dropped and the rest of the device's are written.
func (s *Service) recordSNMP(ctx context.Context, targets []snmpTarget, answers []sensorlink.SNMPAnswer) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	var errs []error
	for _, a := range answers {
		i := slices.IndexFunc(targets, func(t snmpTarget) bool { return t.ip.String() == a.Target })
		if a.Status != sensorlink.SNMPStatusOK || i < 0 {
			continue
		}
		obs := snmpObservations(targets[i].asset, identifySNMP(a.Values))
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
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		for _, a := range answers {
			i := slices.IndexFunc(targets, func(t snmpTarget) bool { return t.ip.String() == a.Target })
			if i < 0 {
				continue
			}
			// The values stay with the device (cleaned), to show what answered and to read the next unknown layout on the box.
			var answer any
			if a.Status == sensorlink.SNMPStatusOK {
				b, err := json.Marshal(cleanValues(a.Values))
				if err != nil {
					return err
				}
				answer = string(b)
			}
			// Only while the device's read address is still the one read: settings edited meanwhile start their own state.
			if _, err := tx.ExecContext(ctx, `UPDATE sa_snmp_device SET last_checked_at = ?1, last_status = ?2,
				last_answer_at = CASE WHEN ?2 = 'ok' THEN ?1 ELSE last_answer_at END, answer = CASE WHEN ?2 = 'ok' THEN ?3 ELSE answer END
				WHERE asset_id = ?4 AND read_from = ?5`, now, a.Status, answer, targets[i].asset, a.Target); err != nil {
				return err
			}
		}
		return nil
	})
	return errors.Join(append(errs, err)...)
}

// cleanValues is what is kept of an answer: every value cleaned as identifySNMP cleans it (valid UTF-8, no control or format
// character, at most 200 characters).
func cleanValues(v sensorlink.SNMPValues) sensorlink.SNMPValues {
	return sensorlink.SNMPValues{SysDescr: cleanSNMP(v.SysDescr), SysObjectID: cleanSNMP(v.SysObjectID), SysName: cleanSNMP(v.SysName),
		EntClass: cleanSNMP(v.EntClass), EntModel: cleanSNMP(v.EntModel), EntSoftware: cleanSNMP(v.EntSoftware), EntSerial: cleanSNMP(v.EntSerial),
		OSVersion: cleanSNMP(v.OSVersion)}
}

// snmpObservations are what an answer says, as observations of device asset.
func snmpObservations(asset string, f SNMPFacts) []observe.Observation {
	var out []observe.Observation
	add := func(field observe.Field, v string, c float64) {
		if v != "" {
			out = append(out, observe.Observation{AssetHint: observe.AssetHint{Device: asset}, Field: field, Value: v, Source: observe.SNMP, Confidence: c})
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
	err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM core_run WHERE module = ? AND kind = ? AND trigger <> 'manual'
		AND status IN ('running', 'done', 'partial', 'failed') AND queued_at >= ?`, ModuleID, RunSNMP, store.FormatTS(start)).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("sensoractive: read jobs: %w", err)
	}
	return n == 0, nil
}

// snmpRound is the window's round of SNMP reads (Tick, after the sweep and the queue): once per window, every device with SNMP set up
// that the policy lets be read, at its read address, in batches of 64. The job row is written first, so a window with nothing to
// read is not looked at again every minute. A device whose saved secret this box cannot open is left out; while every device
// is so, no round starts (the next Tick checks again, locally), so one typed again is read in the same window.
func (s *Service) snmpRound(ctx context.Context, windowStart time.Time) error {
	if s.snmp == nil || s.secrets == nil {
		return nil
	}
	rows, err := s.snmpRows(ctx, s.db.Reader())
	if err != nil || len(rows) == 0 {
		return err
	}
	if due, err := s.snmpRoundDue(ctx, windowStart); err != nil || !due {
		return err
	}
	if ready, _ := s.SNMPStatus(); !ready {
		return nil // the next Tick tries again
	}
	usable := rows[:0:0]
	var lost []string
	for _, r := range rows {
		// Another failure to open a secret is not "lost": the device stays in, and the batch fails on it as before (snmpJob).
		if gone, _ := s.snmpLost(ctx, s.db.Reader(), r); gone {
			lost = append(lost, r.AssetID)
			continue
		}
		usable = append(usable, r)
	}
	if len(usable) == 0 {
		return nil
	}
	if len(lost) > 0 {
		s.log.WarnContext(ctx, "sensoractive: snmp devices skipped: their saved secret was not restored", "devices", lost)
	}
	var silent []string // the devices that did not answer (written and read on the run's goroutine)
	err = s.doWork(ctx, run.Spec{Kind: RunSNMP, Title: fmt.Sprintf("SNMP read of %d devices", len(usable)), Trigger: run.Schedule,
		Steps: []run.StepPlan{{Name: "SNMP reads", Total: len(usable)}}}, func(ctx context.Context) error {
		var err error
		silent, err = s.roundReads(ctx, usable)
		return err
	}, func(ctx context.Context, err error) run.Result { return s.roundResult(ctx, err, silent, len(usable)) }, 0, "")
	if errors.Is(err, ErrStopped) {
		return nil
	}
	return err
}

// snmpUsable is the devices the window's round reads now: SNMP set up, and a secret this box can open.
func (s *Service) snmpUsable(ctx context.Context) ([]snmpRow, error) {
	rows, err := s.snmpRows(ctx, s.db.Reader())
	if err != nil {
		return nil, err
	}
	usable := rows[:0:0]
	for _, r := range rows {
		if gone, _ := s.snmpLost(ctx, s.db.Reader(), r); !gone {
			usable = append(usable, r)
		}
	}
	return usable, nil
}

// runSNMP is the Run of an snmp_read from what it stored: the window's round that a restart left queued reads the devices as they
// are now; a person's read that a restart left queued did not run (its caller is gone).
func (s *Service) runSNMP(ctx context.Context, x *run.Exec) (run.Result, error) {
	d, err := x.Run(ctx)
	if err != nil {
		return run.Result{}, err
	}
	if d.Trigger != run.Schedule {
		return run.Result{Status: run.Failed, Error: noteLost}, nil
	}
	usable, err := s.snmpUsable(ctx)
	if err != nil {
		return run.Result{}, err
	}
	silent, err := s.roundReads(ctx, usable)
	return s.roundResult(ctx, err, silent, len(usable)), nil
}

// roundResult is how the window's round ends: done when every device it read answered; partly done naming the devices that did not
// (at most three, then how many more), failed when none answered. Its count is the devices that answered (roundReads).
func (s *Service) roundResult(ctx context.Context, err error, silent []string, total int) run.Result {
	if err != nil || len(silent) == 0 {
		return snmpResult(ctx, err)
	}
	names := make([]string, 0, 3)
	for _, id := range silent[:min(3, len(silent))] {
		names = append(names, s.deviceLabel(context.WithoutCancel(ctx), id))
	}
	who := strings.Join(names, ", ")
	if more := len(silent) - len(names); more > 0 {
		who += fmt.Sprintf(" and %d more", more)
	}
	if len(silent) >= total {
		return run.Result{Status: run.Failed, Error: "No device answered over SNMP: " + who}
	}
	return run.Result{Status: run.Partial, Error: "No answer over SNMP from " + who}
}

// roundReads is the work of the window's round: the devices in batches of 64, each batch read again when one of its devices changed.
// The run counts the devices that answered; silent are the ones read that did not.
func (s *Service) roundReads(ctx context.Context, usable []snmpRow) (silent []string, err error) {
	jobID, err := s.startJob(ctx, KindSNMP, snmpReasonWindow, 0)
	if err != nil {
		return nil, err
	}
	targets, err := s.snmpTargets(ctx, usable)
	if err != nil {
		s.finishJob(ctx, jobID, StatusFailed, 0, 0, err.Error())
		return nil, err
	}
	done, answered := 0, 0
	changed := map[string]int{} // the devices whose change stopped a batch of this round, and how many times
	for batch := range slices.Chunk(targets, sensorlink.MaxSNMPTargets) {
		for try := 1; ; try++ {
			s.snmpMu.Lock()
			var answers []sensorlink.SNMPAnswer
			answers, err = s.snmpBatch(ctx, jobID, batch, false) // its deadline: the window's end or snmpRoundRun (INV-3)
			s.snmpMu.Unlock()
			if err == nil {
				for _, t := range batch {
					ok := slices.ContainsFunc(answers, func(a sensorlink.SNMPAnswer) bool {
						return a.Target == t.ip.String() && a.Status == sensorlink.SNMPStatusOK
					})
					if ok {
						answered++
					} else if slices.ContainsFunc(answers, func(a sensorlink.SNMPAnswer) bool { return a.Target == t.ip.String() }) {
						silent = append(silent, t.asset)
					}
				}
			}
			// A batch stopped only because one of its devices changed is read again, not the whole round from its first batch
			// on the next Tick (#882). The new batch checks everything again: a device that moved or is gone since the round
			// started is dropped by its recheck. A device that stops the round a second time is left out of it (the next window
			// reads it), so the round ends however often devices change. A batch stopped snmpBatchTries times is left for the
			// next window and the round goes on with the next batch.
			var dc *snmpDeviceChanged
			if !errors.As(err, &dc) {
				break
			}
			if try == snmpBatchTries {
				s.log.InfoContext(ctx, "sensoractive: snmp batch left for the next window: its devices kept changing", "devices", len(batch))
				batch, err = nil, nil
				break
			}
			if changed[dc.asset]++; changed[dc.asset] > 1 {
				batch = slices.DeleteFunc(slices.Clone(batch), func(t snmpTarget) bool { return t.asset == dc.asset })
			}
			// A device whose settings were edited is read with its new ones: take them again.
			batch = s.freshTargets(ctx, batch)
		}
		if err != nil {
			break
		}
		done += len(batch)
	}
	s.closeSNMPJob(ctx, jobID, done, err)
	if x := execOf(ctx); x != nil {
		s.stepProgress(ctx, x, 1, answered, len(usable))
	}
	return silent, err
}

// freshTargets is a batch with every device's settings read again (an edit stopped it): a device whose SNMP was removed is left out,
// one whose read address changed is read at the new one. Failures keep the batch as it was: the batch's recheck drops what changed.
func (s *Service) freshTargets(ctx context.Context, batch []snmpTarget) []snmpTarget {
	rows, err := s.snmpRows(ctx, s.db.Reader())
	if err != nil {
		return batch
	}
	var out []snmpTarget
	for _, t := range batch {
		if j := slices.IndexFunc(rows, func(r snmpRow) bool { return r.AssetID == t.asset }); j >= 0 {
			out = append(out, snmpTarget{asset: t.asset, ip: rows[j].ReadFrom, row: rows[j]})
		}
	}
	return out
}

// snmpTargets lists the devices of a round that the policy lets be read now, by read address.
func (s *Service) snmpTargets(ctx context.Context, rows []snmpRow) ([]snmpTarget, error) {
	box, err := s.inv.BoxIPs(ctx)
	if err != nil {
		return nil, err
	}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return nil, err
	}
	sc := newScope(st)
	var out []snmpTarget
	seen := map[netip.Addr]bool{} // one read of an address per job (two devices given one management address: the first one)
	for _, r := range rows {
		why, err := s.snmpAllowed(ctx, r, box, sc)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if why != "" {
			if why == SNMPMoved {
				s.log.InfoContext(ctx, "sensoractive: snmp device skipped: it moved away from its read address", "device", r.AssetID, "read_from", r.ReadFrom)
			}
			continue
		}
		if seen[r.ReadFrom] {
			continue
		}
		seen[r.ReadFrom] = true
		out = append(out, snmpTarget{asset: r.AssetID, ip: r.ReadFrom, row: r})
	}
	slices.SortFunc(out, func(a, b snmpTarget) int { return a.ip.Compare(b.ip) })
	return out, nil
}

// snmpChanged is SettingsChanged and AssetChanged for the SNMP batch in progress: it stops when the settings no longer allow it,
// an address left the scope, or (asset != "") one of its devices changed (it may have been set to "never" or deleted). Fail closed.
func (s *Service) snmpChanged(ctx context.Context, asset string) {
	s.mu.Lock()
	run := s.snmpCur
	var held bool
	var targets []netip.Addr
	if run != nil {
		held, targets = slices.Contains(run.assets, asset), slices.Clone(run.targets)
	}
	s.mu.Unlock()
	if run == nil {
		return
	}
	if asset != "" {
		// Devices change all the time (a sensor learns a name, a check records its ports): the batch stops only when the change
		// matters to its read of this device: it may no longer be read (never, not approved, ignored, the box, deleted, out of
		// scope) or it left its read address. Fail closed when that cannot be told.
		if held && !s.stillReadable(ctx, run, asset) {
			run.changed(&snmpDeviceChanged{asset: asset})
		}
		return
	}
	st, err := s.inv.Settings(ctx)
	if err != nil || st.allowed() != nil {
		run.cancel()
		return
	}
	end, ok := s.windowNow(ctx, st)
	s.mu.Lock()
	deadline := run.deadline
	s.mu.Unlock()
	// Outside the window, or a window shortened under the batch: its deadline came from the old end (INV-3, as nmap's
	// SettingsChanged). A Check now is not bound to the window.
	if !run.picked && (!ok || !deadline.IsZero() && end.Before(deadline)) {
		run.cancel()
		return
	}
	sc := newScope(st)
	if slices.ContainsFunc(targets, sc.excluded) { // SNMP: the exclusions, not lan_ranges
		run.cancel()
	}
}

// stillReadable says device asset of the batch may still be read at the address the batch reads it from (recheckSNMP's rules, with
// the settings now); false when it may not, or when that cannot be read.
func (s *Service) stillReadable(ctx context.Context, b *snmpRun, asset string) bool {
	s.mu.Lock()
	i := slices.Index(b.assets, asset)
	var ip netip.Addr
	if i >= 0 && i < len(b.targets) {
		ip = b.targets[i]
	}
	s.mu.Unlock()
	if !ip.IsValid() {
		return false
	}
	st, err := s.inv.Settings(ctx)
	if err != nil || st.allowed() != nil {
		return false
	}
	kept, err := s.recheckSNMP(ctx, []snmpTarget{{asset: asset, ip: ip}}, newScope(st))
	return err == nil && len(kept) == 1
}

// snmpSettingsChanged stops the batch in progress when it holds the device whose SNMP an edit, a removal, a delete or a merge just
// changed: a job already with the worker is cancelled there too. The round reads the batch again with the new
// settings.
func (s *Service) snmpSettingsChanged(asset string) {
	s.mu.Lock()
	run := s.snmpCur
	held := run != nil && slices.Contains(run.assets, asset) // assets is narrowed under s.mu while the batch runs
	s.mu.Unlock()
	if held {
		run.changed(&snmpDeviceChanged{asset: asset})
	}
}

// snmpMessage is the plain text of a reason (the GUI shows it as it is): name and ip are the device's, r its settings. extra is a
// message already set (unavailable).
func snmpMessage(reason, name string, ip netip.Addr, r snmpRow, extra string) string {
	at, port := r.ReadFrom, r.Port
	switch reason {
	case SNMPOK:
		return fmt.Sprintf("%s answered on UDP port %d. What it said is now on this device in the inventory, with source SNMP.", at, port)
	case sensorlink.SNMPStatusNoAnswer:
		if r.Version == sensorlink.SNMPv3 {
			return fmt.Sprintf("No answer from %s on UDP port %d within 2 s (sent twice). The device may not run SNMP there, may answer on another port or another address (set Read from to its management address), a firewall may drop UDP port %d, or SNMPv3 is not enabled on it.", at, port, port)
		}
		return fmt.Sprintf("No answer from %s on UDP port %d within 2 s (sent twice). The device may not run SNMP there, may answer on another port or another address (set Read from to its management address), a firewall may drop UDP port %d, or the community is wrong: a device ignores a wrong community instead of saying so.", at, port, port)
	case sensorlink.SNMPStatusAuthFailed:
		return "The device did not accept the v3 user name or password (or the authentication or privacy algorithm differs)."
	case sensorlink.SNMPStatusUnknownUser:
		return "The device does not know this v3 user name."
	case sensorlink.SNMPStatusError:
		return "The device answered with an error, or with a message Vedette could not read."
	case SNMPNotApproved:
		return fmt.Sprintf("%s is not approved yet. SNMP secrets are sent only to devices a person approved: approve it under Devices, To review, then check again.", cmp.Or(name, "This device"))
	case "out_of_scope":
		if !localnet.Addr(at) {
			return fmt.Sprintf("%s is not a local network address: SNMP reads stay on your own networks.", at)
		}
		return fmt.Sprintf("%s is outside the LAN ranges: turn SNMP on for this device on its page (Sources), or save its SNMP settings again, to read it there. The LAN ranges are not widened for it.", ip)
	case reasonScanningOff:
		return "Active scanning is off under Settings › Scanning › Engines, so nothing is sent."
	case reasonScopeNotConfirmed:
		return "The scan scope commitment is not ticked under Settings › Scanning › Safety, so nothing is sent."
	case "declared_by_hand":
		return "This device was added by hand and its SNMP is not turned on (Sources): save its SNMP settings, or turn SNMP on, to read it."
	case reasonSNMPOff:
		return "SNMP is turned off for this device on its page (Sources), so nothing is sent."
	case reasonExcluded:
		return fmt.Sprintf("%s is on the exclusion list under Settings › Scanning › Safety: Vedette never touches it, not even with SNMP.", at)
	case reasonBox:
		return "This is the Vedette box itself (or one of its trap addresses): it is never probed."
	case reasonNever:
		return "This device is set to never be scanned."
	case SNMPNoIP:
		return "This device has no address in the inventory now, so nothing is sent."
	case SNMPMoved:
		who := cmp.Or(name, "This device")
		return fmt.Sprintf("%s is now at %s, but its SNMP reads go only to %s, the address it had when SNMP was set up. If it is still %s, check on the device itself that %s is its address now (a copied network card looks the same), then open Edit and set Read from to %s (type the community or passwords again). Nothing is sent until then.", who, ip, at, cmp.Or(name, "the same device"), ip, ip)
	case SNMPSecretLost:
		return snmpLostText
	case SNMPUnavailable:
		return "SNMP reads cannot run now: " + extra + "."
	case SNMPBusy:
		return "SNMP reads are running for the scan window right now. Try again in a minute."
	}
	return reason
}
