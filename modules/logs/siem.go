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
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
)

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
	Enabled     bool            `json:"enabled"`
	Format      string          `json:"format"`
	Host        string          `json:"host"`
	Port        int             `json:"port"`
	Proto       string          `json:"proto"`
	URL         string          `json:"url"`
	SecretLast4 *string         `json:"secret_last4"`
	Events      []string        `json:"events"`
	LastTest    *SiemTestRecord `json:"last_test"`
}

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
		if err != nil {
			return r, fmt.Errorf("logs: reading the SIEM key: %w", err)
		}
		r.key = secrets.NewValue(string(pt))
	}
	return r, nil
}

// Siem returns the configuration (GET /logs/siem).
func (s *Service) Siem(ctx context.Context) (SiemView, error) {
	r, err := s.loadSiem(ctx, s.cfg.Config.Reader(), false)
	return r.SiemView, err
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
		if err := s.checkHost(strings.ToLower(u.Hostname())); err != nil {
			return in, err
		}
		in.Host, in.Port, in.Proto = "", 514, "udp"
		return in, nil
	}
	in.URL = ""
	if len(in.Host) > maxSiemHost || !(isIPv4(in.Host) || siemHostRE.MatchString(in.Host)) {
		return in, apierr.New(400, "bad_host", "The SIEM server must be an IP address or a domain name, for example 192.168.10.50 or siem.company.com.")
	}
	if in.Port < 1 || in.Port > 65535 {
		return in, apierr.New(400, "bad_port", "The port must be a number from 1 to 65535.")
	}
	if !slices.Contains([]string{"udp", "tcp", "tls"}, in.Proto) {
		return in, apierr.New(400, "bad_proto", "Choose UDP, TCP or TLS.")
	}
	if err := s.checkHost(strings.ToLower(in.Host)); err != nil {
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

// checkHost refuses, at save time, what no destination may be: a literal address the guard forbids, a name that is an address in
// disguise (2130706433, 0x7f.1) and localhost. Names are resolved only on the socket.
func (s *Service) checkHost(host string) error {
	blocked := apierr.New(400, "blocked_host", "The SIEM cannot be this machine, a link-local, multicast or unspecified address, or an address of this box.")
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if a, err := netip.ParseAddr(host); err == nil {
		box, _ := s.boxAddrs()
		if siemForbidden(a, box, s.allowLoopback) {
			return blocked
		}
		return nil
	}
	labels := strings.Split(host, ".")
	if numericLabelRE.MatchString(labels[len(labels)-1]) {
		return apierr.New(400, "bad_host", "The SIEM server must be an IP address or a domain name, for example 192.168.10.50 or siem.company.com.")
	}
	if !s.allowLoopback && (host == "localhost" || strings.HasSuffix(host, ".localhost")) {
		return blocked
	}
	return nil
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
		return SiemView{}, apierr.New(400, "bad_secret", "The signing key needs at least 16 characters. Press Generate if you want a random one.")
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
		out = SiemView{Enabled: in.Enabled, Format: in.Format, Host: in.Host, Port: in.Port, Proto: in.Proto, URL: in.URL, Events: events}
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
