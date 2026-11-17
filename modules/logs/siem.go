package logs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/secrets"
)

// siemLostMsg is the answer of Test and Save, and the state of the SIEM page, when the saved signing key of the webhook is sealed under
// another master key: a backup restored without its decryption key, or a key file made again (#847). The key is gone for good; typing it
// again seals it under this box's key and forwarding starts again.
const siemLostMsg = "The saved signing key of the SIEM webhook was not restored (the backup was restored without its decryption key, or the box key changed). Enter the signing key again (the one your SIEM checks, or press Generate random and put the new key in the SIEM) and press Save. Nothing is sent to the SIEM until then."

// siemLost uses core/conn's code, so every secret this box cannot open answers with one code the UI handles once (#847).
func siemLost() error { return apierr.New(409, conn.CodeSecretLost, siemLostMsg) }

// SIEM forwarding (L5, S-LOG-3, INV-8..10). The configuration is one row of logs_siem in the main database; the signing key is a
// sealed core_secret (SYS-4) that the API never returns (FORBID-2).

// siemSecretPurpose is the core/secrets purpose of the signing key.
const siemSecretPurpose = "logs_siem.secret"

// SIEM limits.
const (
	minSiemKey   = 16
	maxSiemURL   = 2048
	maxSiemHost  = 253
	maxTestDetal = 300
)

// SiemEvents are the event classes an administrator can forward (SiemEvent of contract.ts).
var SiemEvents = []string{"findings", "alerts", "honeypot", "bad_conn"}

// SiemFormats are the wire formats (INV-9).
var SiemFormats = []string{"syslog", "cef", "json"}

// SiemInput is what PUT /logs/siem carries. Secret empty keeps the saved key.
type SiemInput struct {
	Enabled bool
	Format  string
	Host    string
	Port    int
	Proto   string
	URL     string
	Events  []string
	Secret  string
}

// SiemTestRecord is last_test and the answer of POST /logs/siem/test.
type SiemTestRecord struct {
	At     time.Time `json:"at"`
	OK     bool      `json:"ok"`
	Detail string    `json:"detail"`
}

// SiemView is the configuration as the API shows it (SiemConfig of contract.ts): never the key, only its last four characters.
type SiemView struct {
	Enabled     bool    `json:"enabled"`
	Format      string  `json:"format"`
	Host        string  `json:"host"`
	Port        int     `json:"port"`
	Proto       string  `json:"proto"`
	URL         string  `json:"url"`
	SecretLast4 *string `json:"secret_last4"`
	// SecretLost: a signing key is saved but this box cannot open it (sealed under another master key, #847). Only the JSON webhook
	// signs with it: while the format is json, Test answers 409 secret_lost and the forwarder sends nothing until a key is saved again.
	SecretLost bool            `json:"secret_lost"`
	Events     []string        `json:"events"`
	LastTest   *SiemTestRecord `json:"last_test"`
}

// stopped reports whether this configuration cannot be sent with: the webhook signs every request with a key the box cannot open.
func (v SiemView) stopped() bool { return v.Format == "json" && v.SecretLost }

// siemRow is the stored row plus the opened key (never serialised: secrets.Value redacts itself).
type siemRow struct {
	SiemView
	secretID string
	key      secrets.Value
}

func (s *Service) loadSiem(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, withKey bool) (siemRow, error) {
	var r siemRow
	var enabled int
	var secretID, last4, events, lastTest sql.NullString
	err := q.QueryRowContext(ctx, `SELECT enabled, format, host, port, proto, url, secret_id, secret_last4, events, last_test FROM logs_siem WHERE id = 1`).
		Scan(&enabled, &r.Format, &r.Host, &r.Port, &r.Proto, &r.URL, &secretID, &last4, &events, &lastTest)
	if err != nil {
		return r, fmt.Errorf("logs: reading the SIEM configuration: %w", err)
	}
	r.Enabled = enabled == 1
	r.Events = []string{}
	if err := json.Unmarshal([]byte(events.String), &r.Events); err != nil {
		return r, fmt.Errorf("logs: reading the SIEM configuration: events: %w", err)
	}
	if lastTest.Valid {
		var t SiemTestRecord
		if err := json.Unmarshal([]byte(lastTest.String), &t); err == nil {
			r.LastTest = &t
		}
	}
	if last4.Valid {
		v := last4.String
		r.SecretLast4 = &v
	}
	r.secretID = secretID.String
	if withKey && r.secretID != "" {
		if s.cfg.Secrets == nil {
			return r, errors.New("logs: reading the SIEM key: no secret store is wired")
		}
		pt, err := s.cfg.Secrets.Open(ctx, s.cfg.Config.Reader(), r.secretID, siemSecretPurpose)
		if secrets.IsWrongKey(err) {
			// Sealed under another master key (#847): not an error of the read. The row says so; the callers refuse to send with it.
			r.SecretLost = true
			return r, nil
		}
		if err != nil {
			return r, fmt.Errorf("logs: reading the SIEM key: %w", err)
		}
		r.key = secrets.NewValue(string(pt))
	}
	return r, nil
}

// Siem returns the configuration (GET /logs/siem). It says whether the saved key can be opened (secret_lost), never the key; a key that
// cannot be read for another reason leaves the page as it was (the forwarder and Test report that one).
func (s *Service) Siem(ctx context.Context) (SiemView, error) {
	r, err := s.loadSiem(ctx, s.cfg.Config.Reader(), false)
	if err != nil || r.secretID == "" || s.cfg.Secrets == nil {
		return r.SiemView, err
	}
	_, oerr := s.cfg.Secrets.Open(ctx, s.cfg.Config.Reader(), r.secretID, siemSecretPurpose)
	r.SecretLost = secrets.IsWrongKey(oerr)
	return r.SiemView, nil
}

var siemHostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

var numericLabelRE = regexp.MustCompile(`^(0x[0-9a-f]+|[0-9]+)$`)

// siemTarget checks what the customer typed (SYS-7): the messages are the mock's. A literal address is judged here already; a name is
// judged again after it is resolved, on the socket (siem_send.go), which is the check that counts.
func (s *Service) siemTarget(in SiemInput) (SiemInput, error) {
	in.Host, in.URL = strings.TrimSpace(in.Host), strings.TrimSpace(in.URL)
	if in.Format == "json" {
		u, err := url.Parse(in.URL)
		bad := apierr.New(400, "bad_url", "The webhook URL must start with https:// (or http:// on an internal network). Example: https://siem.company.com/hooks/vedette.")
		if in.URL == "" || err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(in.URL) > maxSiemURL || (u.Scheme != "https" && u.Scheme != "http") {
			return in, bad
		}
		for _, r := range in.URL {
			if r <= ' ' || r > '~' {
				return in, bad
			}
		}
		if p := u.Port(); p != "" && !validPort(p) {
			return in, bad
		}
		port := uint16(443)
		if p := u.Port(); p != "" {
			n, _ := strconv.ParseUint(p, 10, 16) // validPort above
			port = uint16(n)
		} else if u.Scheme == "http" {
			port = 80
		}
		if err := s.checkHost(strings.ToLower(u.Hostname()), port); err != nil {
			return in, err
		}
		in.Host, in.Port, in.Proto = "", 514, "udp"
		return in, nil
	}
	in.URL = ""
	if len(in.Host) > maxSiemHost || (!isIPv4(in.Host) && !siemHostRE.MatchString(in.Host)) {
		return in, apierr.New(400, "bad_host", "The SIEM server must be an IP address or a domain name, for example 192.168.10.50 or siem.company.com.")
	}
	if in.Port < 1 || in.Port > 65535 {
		return in, apierr.New(400, "bad_port", "The port must be a number from 1 to 65535.")
	}
	if !slices.Contains([]string{"udp", "tcp", "tls"}, in.Proto) {
		return in, apierr.New(400, "bad_proto", "Choose UDP, TCP or TLS.")
	}
	if err := s.checkHost(strings.ToLower(in.Host), uint16(in.Port)); err != nil {
		return in, err
	}
	return in, nil
}

func isIPv4(h string) bool {
	a, err := netip.ParseAddr(h)
	return err == nil && a.Is4() && a.String() == h
}

func validPort(p string) bool {
	n := 0
	for _, c := range p {
		if c < '0' || c > '9' || n > 65535 {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n >= 1 && n <= 65535
}

// checkHost refuses, at save time, what no destination may be: a literal address the guard forbids (Vedette itself at port,
// first, for its own sentence), a name that is an address in disguise (2130706433, 0x7f.1) and localhost. Names are resolved only on
// the socket.
func (s *Service) checkHost(host string, port uint16) error {
	blocked := apierr.New(400, "blocked_host", "The SIEM cannot be a link-local, multicast or unspecified address, or a cloud metadata service.")
	own := apierr.New(400, "blocked_host", ownText)
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if a, err := netip.ParseAddr(host); err == nil {
		box, _ := s.boxAddrs() // unknown: judged with what is known; the socket refuses every send until it is known (siemOwn)
		if siemOwn(a, port, box, s.extraSelf(), s.allowLoopback) {
			return own
		}
		if siemForbidden(a) {
			return blocked
		}
		return nil
	}
	labels := strings.Split(host, ".")
	if numericLabelRE.MatchString(labels[len(labels)-1]) {
		return apierr.New(400, "bad_host", "The SIEM server must be an IP address or a domain name, for example 192.168.10.50 or siem.company.com.")
	}
	if !s.allowLoopback && (host == "localhost" || strings.HasSuffix(host, ".localhost")) {
		return own
	}
	return nil
}

// extraSelf is Config.SelfAddrs (nil: none).
func (s *Service) extraSelf() []netip.Addr {
	if s.cfg.SelfAddrs == nil {
		return nil
	}
	return s.cfg.SelfAddrs()
}

func (s *Service) boxAddrs() ([]netip.Addr, bool) {
	if s.cfg.BoxAddrs == nil {
		return nil, true
	}
	return s.cfg.BoxAddrs()
}

// SetSiem saves the configuration (PUT /logs/siem). The key is sealed, the change audited, both in one transaction; the last test is
// forgotten because it described another destination.
func (s *Service) SetSiem(ctx context.Context, user string, in SiemInput) (SiemView, error) {
	if !slices.Contains(SiemFormats, in.Format) {
		return SiemView{}, apierr.New(400, "bad_format", "Choose a format: syslog, CEF or JSON webhook.")
	}
	in, err := s.siemTarget(in)
	if err != nil {
		return SiemView{}, err
	}
	if len(in.Events) == 0 || len(in.Events) > len(SiemEvents) {
		return SiemView{}, apierr.New(400, "bad_events", "Choose at least one event type to forward.")
	}
	events := make([]string, 0, len(in.Events))
	for _, e := range SiemEvents { // stored once each, in the fixed order
		if slices.Contains(in.Events, e) {
			events = append(events, e)
		}
	}
	if len(events) != len(dedupe(in.Events)) {
		return SiemView{}, apierr.New(400, "bad_events", "Choose at least one event type to forward.")
	}
	if in.Secret != "" && utf8.RuneCountInString(in.Secret) < minSiemKey {
		return SiemView{}, apierr.New(400, "bad_secret", "The signing key needs at least 16 characters. Press Generate random if you want a random one.")
	}
	if in.Secret != "" && (len(in.Secret) > 512 || siemText(in.Secret, 512) != in.Secret) {
		return SiemView{}, apierr.New(400, "bad_secret", "The signing key can be at most 512 bytes, with no control characters and no space at either end.")
	}
	if s.cfg.Secrets == nil {
		return SiemView{}, errors.New("logs: saving the SIEM configuration: no secret store is wired")
	}
	var out SiemView
	err = s.cfg.Config.Write(ctx, func(tx *sql.Tx) error {
		cur, err := s.loadSiem(ctx, tx, false)
		if err != nil {
			return err
		}
		// #847: a saved key kept as it is may be one this box cannot open. Only the wrong-key answer counts (any other error of the open
		// leaves the save as it always was); only a save that turns the webhook on with it is refused, since it would sign with nothing.
		// Turning forwarding off, or another URL or events, saves; the answer says the key is still lost.
		lost := false
		if in.Secret == "" && cur.secretID != "" {
			_, oerr := s.cfg.Secrets.Open(ctx, s.cfg.Config.Reader(), cur.secretID, siemSecretPurpose)
			lost = secrets.IsWrongKey(oerr)
		}
		if lost && in.Format == "json" && in.Enabled {
			return siemLost()
		}
		id, last4 := cur.secretID, ""
		if cur.SecretLast4 != nil {
			last4 = *cur.SecretLast4
		}
		switch {
		case in.Secret != "" && id == "":
			if id, _, err = s.cfg.Secrets.Seal(ctx, tx, siemSecretPurpose, []byte(in.Secret), false); err != nil {
				return fmt.Errorf("logs: sealing the SIEM key: %w", err)
			}
			last4 = lastFour(in.Secret)
		case in.Secret != "":
			if _, err = s.cfg.Secrets.Replace(ctx, tx, id, siemSecretPurpose, []byte(in.Secret), false); err != nil {
				return fmt.Errorf("logs: sealing the SIEM key: %w", err)
			}
			last4 = lastFour(in.Secret)
		case in.Format == "json" && id == "":
			return apierr.New(400, "secret_required", "Enter the webhook signing key.")
		}
		ev, _ := json.Marshal(events)
		var l4 any
		if last4 != "" {
			l4 = last4
		}
		var sid any
		if id != "" {
			sid = id
		}
		if _, err := tx.ExecContext(ctx, `UPDATE logs_siem SET enabled = ?, format = ?, host = ?, port = ?, proto = ?, url = ?, secret_id = ?, secret_last4 = ?, events = ?, last_test = NULL WHERE id = 1`,
			boolInt(in.Enabled), in.Format, in.Host, in.Port, in.Proto, in.URL, sid, l4, string(ev)); err != nil {
			return fmt.Errorf("logs: saving the SIEM configuration: %w", err)
		}
		state := "off"
		if in.Enabled {
			state = "on"
		}
		if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "logs.siem_save", Target: siemTargetLabel(in.Format, in.Host, in.Port, in.URL), Detail: in.Format + ", " + state}); err != nil {
			return err
		}
		out = SiemView{Enabled: in.Enabled, Format: in.Format, Host: in.Host, Port: in.Port, Proto: in.Proto, URL: in.URL, Events: events, SecretLost: lost}
		if last4 != "" {
			out.SecretLast4 = &last4
		}
		return nil
	})
	if err != nil {
		return SiemView{}, err
	}
	s.siemChanged()
	return out, nil
}

func dedupe(l []string) []string {
	out := slices.Clone(l)
	slices.Sort(out)
	return slices.Compact(out)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func lastFour(s string) string {
	r := []rune(s)
	if len(r) < 4 {
		return ""
	}
	return string(r[len(r)-4:])
}

// siemTargetLabel is what the audit row names: host:port, or the scheme and host of the webhook (its path often carries a token).
func siemTargetLabel(format, host string, port int, raw string) string {
	if format == "json" {
		if u, err := url.Parse(raw); err == nil {
			return u.Scheme + "://" + u.Host
		}
		return "webhook"
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// TestSiem sends one test record to the saved destination (POST /logs/siem/test, PRE-2, POST-4) and stores the answer as last_test.
// It goes out even while forwarding is off: it is the administrator's own request. The detail is a fixed sentence, never text the
// remote answered with.
func (s *Service) TestSiem(ctx context.Context, user string) (SiemTestRecord, error) {
	cfg, err := s.loadSiem(ctx, s.cfg.Config.Reader(), true)
	if err != nil {
		return SiemTestRecord{}, err
	}
	if cfg.Host == "" && cfg.URL == "" {
		return SiemTestRecord{}, apierr.New(400, "not_configured", "No SIEM destination is saved. Enter and save the configuration before sending a test.")
	}
	if cfg.stopped() {
		// #847: nothing is sent. The attempt is on record like any other test; last_test keeps the last real send (the page says the key
		// is lost from secret_lost).
		if err := s.cfg.Config.Write(ctx, func(tx *sql.Tx) error {
			return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "logs.siem_test", Target: siemTargetLabel(cfg.Format, cfg.Host, cfg.Port, cfg.URL), Detail: "failed: " + conn.CodeSecretLost})
		}); err != nil {
			return SiemTestRecord{}, err
		}
		return SiemTestRecord{}, siemLost()
	}
	rec := newSiemRecord("siem.test", "info", s.now(), siemField{Key: "message", Val: "Vedette SIEM test record"})
	ctx, cancel := context.WithTimeout(ctx, 3*siemTimeout)
	defer cancel()
	detail, sendErr := s.sendOut(ctx, cfg, []siemRecord{rec})
	out := SiemTestRecord{At: s.ts(), OK: sendErr == nil, Detail: clipDetail(detail)}
	if sendErr != nil {
		out.Detail = clipDetail(siemFailure(sendErr, cfg))
	}
	b, _ := json.Marshal(out)
	err = s.cfg.Config.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE logs_siem SET last_test = ? WHERE id = 1`, string(b)); err != nil {
			return fmt.Errorf("logs: saving the SIEM test: %w", err)
		}
		res := "failed"
		if out.OK {
			res = "ok"
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "logs.siem_test", Target: siemTargetLabel(cfg.Format, cfg.Host, cfg.Port, cfg.URL), Detail: res})
	})
	if err != nil {
		return SiemTestRecord{}, err
	}
	return out, nil
}

func clipDetail(d string) string {
	d = siemText(d, maxTestDetal)
	return d
}
