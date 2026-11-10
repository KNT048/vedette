package main

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// The ports of notify wired in cmd/vedette (issue #62 items 1 to 3): the user directory, the code mailer,
// BaseURL, the organization time zone and the device names. Real SQLite, real bus, no network: the email
// channel points at a fake SMTP server on 127.0.0.1.

const (
	testRelayLogin = "relay-login-for-tests"           // not a real credential: the fake server accepts anything
	testUserSecret = "correct horse battery staple 42" // test password of a test user
)

// smtpSink is a fake SMTP server (security "none"): it keeps every message.
type smtpSink struct {
	ln   net.Listener
	mu   sync.Mutex
	msgs []string
}

func newSMTPSink(t *testing.T) *smtpSink {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpSink{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *smtpSink) port() string { _, p, _ := net.SplitHostPort(s.ln.Addr().String()); return p }

func (s *smtpSink) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	say := func(l string) { _, _ = fmt.Fprint(c, l+"\r\n") }
	say("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		up := strings.ToUpper(strings.TrimSpace(line))
		switch up {
		case "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || strings.TrimSpace(l) == "." {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.msgs = append(s.msgs, b.String())
			s.mu.Unlock()
			say("250 queued")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func (s *smtpSink) messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.msgs...)
}

// email saves the email channel of the stack's notify service so that it sends to the sink.
func (s *stack) email(sink *smtpSink, approvers ...notify.Approver) {
	s.t.Helper()
	in := notify.ChannelInput{Enabled: true, MinSeverity: notify.Low, Secret: testRelayLogin, Approvals: len(approvers) > 0, Approvers: approvers,
		Fields: map[string]string{"host": "127.0.0.1", "port": sink.port(), "security": "none", "username": "alerts@acme.example", "from": "alerts@acme.example", "to": "it@acme.example"}}
	if _, err := newNotify(s.d).SaveChannel(s.t.Context(), "admin@acme.example", channel.Email, in); err != nil {
		s.t.Fatal(err)
	}
}

func (s *stack) enableNotify() {
	s.t.Helper()
	if !s.d.Reg.Enabled("notify") {
		s.setModule("notify", true)
	}
}

// addUser creates an account through core/auth, as the admin handler does.
func (s *stack) addUser(email string, role routes.Role) auth.User {
	s.t.Helper()
	hash, err := s.d.Auth.HashPassword(s.t.Context(), testUserSecret, email)
	if err != nil {
		s.t.Fatal(err)
	}
	var u auth.User
	err = s.d.DB.Write(s.t.Context(), func(tx *sql.Tx) error {
		var e error
		u, e = s.d.Auth.CreateUser(s.t.Context(), tx, "admin@acme.example", auth.NewUser{Name: "Test " + string(role), Email: email, Role: role, PasswordHash: hash})
		return e
	})
	if err != nil {
		s.t.Fatal(err)
	}
	return u
}

// manualClock is a clock the test moves.
type manualClock struct{ ns atomic.Int64 }

func newManualClock(t time.Time) *manualClock {
	c := &manualClock{}
	c.ns.Store(t.UnixNano())
	return c
}
func (c *manualClock) now() time.Time          { return time.Unix(0, c.ns.Load()).UTC() }
func (c *manualClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

var codeRE = regexp.MustCompile(`sign-in code is (\d{6})`)

// (a) An email two-step account: the sign-in code goes out through notify's code mailer to the SMTP server of the
// email channel, and signing in with it works. Before the channel exists the account cannot sign in at all (INV-8).
func TestWiringEmailTwoStepCodeGoesThroughNotify(t *testing.T) {
	t.Parallel()
	clock := newManualClock(time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC))
	s := newStackWith(t, func(d *deps) { d.Clock = clock.now; d.BaseURL = "https://box.example:8443" })
	s.enableNotify()
	u := s.addUser("anh@acme.example", routes.Admin)
	ctx := t.Context()
	if _, err := s.d.Auth.StartEmail2FA(ctx, u.ID, "", testUserSecret); err == nil {
		t.Fatal("the email method started while no email channel exists")
	}
	sink := newSMTPSink(t)
	s.email(sink)
	if _, err := s.d.Auth.StartEmail2FA(ctx, u.ID, "", testUserSecret); err != nil {
		t.Fatal(err)
	}
	msgs := sink.messages()
	if len(msgs) != 1 {
		t.Fatalf("%d messages after the start, want 1", len(msgs))
	}
	m := codeRE.FindStringSubmatch(msgs[0])
	if m == nil || !strings.Contains(msgs[0], "anh@acme.example") || !strings.Contains(msgs[0], "https://box.example:8443/login") {
		t.Fatalf("the mailed code is missing, or the recipient or the sign-in link:\n%s", msgs[0])
	}
	if _, err := s.d.Auth.ConfirmEmail2FA(ctx, u.ID, "", m[1]); err != nil {
		t.Fatal(err)
	}

	// Signing in: the first call mails a new code (twofa_required), the second one with it opens the session.
	clock.advance(5 * time.Minute)
	req := auth.LoginRequest{Email: "anh@acme.example", Password: testUserSecret, IP: netip.MustParseAddr("192.168.1.20")}
	if _, err := s.d.Auth.Login(ctx, req); err == nil {
		t.Fatal("password-only sign-in worked for an email two-step account")
	}
	msgs = sink.messages()
	if len(msgs) != 2 {
		t.Fatalf("%d messages after the sign-in prompt, want 2", len(msgs))
	}
	m = codeRE.FindStringSubmatch(msgs[1])
	if m == nil {
		t.Fatalf("no code in the second message:\n%s", msgs[1])
	}
	req.Code = m[1]
	res, err := s.d.Auth.Login(ctx, req)
	if err != nil || res.Session.Token == "" {
		t.Fatalf("sign-in with the mailed code: %v", err)
	}
	// notify counts that account (INV-9) through the user directory.
	view, err := newNotify(s.d).Channels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view.EmailCodeUsers != 1 {
		t.Fatalf("notify counts %d email-code users, want 1", view.EmailCodeUsers)
	}
}

// (b) Quiet hours follow the organization time zone (core_org.timezone, set by PUT /core/general), not the process zone: 16:00 UTC is
// 23:00 in Ho Chi Minh City (inside 22:00-06:30, held) and 11:00 in New York (outside, sent at once). A change
// of the zone applies to the next notice without a restart.
func TestWiringQuietHoursFollowTheOrganizationTimeZone(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 9, 16, 0, 0, 0, time.UTC)
	s := newStackWith(t, func(d *deps) { d.Clock = func() time.Time { return now } })
	s.enableNotify()
	s.email(newSMTPSink(t))
	ctx := t.Context()
	svc := newNotify(s.d)
	if _, err := svc.SaveRules(ctx, "admin@acme.example", notify.Rules{Quiet: notify.Quiet{Enabled: true, From: "22:00", To: "06:30"}, Grouping: notify.Grouping{WindowMin: 15}}); err != nil {
		t.Fatal(err)
	}
	setZone := func(sqlText string) { // the write PUT /core/general does (it needs a signed-in admin row, which this stack's test sessions are not)
		s.t.Helper()
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, sqlText); return err }); err != nil {
			s.t.Fatal(err)
		}
	}
	setZone(`INSERT INTO core_org (id, name, timezone, data_mode, install_id) VALUES (1, 'Acme', 'Asia/Ho_Chi_Minh', 'clean', 'ins-test')`)
	reasons := func(id string) string {
		s.t.Helper()
		if err := svc.Publish(ctx, notify.Notice{ID: id, Kind: notify.KindVuln, Severity: notify.High, Title: "x is being exploited", What: "w", Action: "a", Product: "x", Devices: []string{"fw"}, At: now}); err != nil {
			s.t.Fatal(err)
		}
		var r string
		if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT reason FROM notify_pending WHERE notice_id = ?`, id).Scan(&r); err != nil {
			s.t.Fatal(err)
		}
		return r
	}
	if got := reasons("nt-1"); got != "quiet" {
		t.Fatalf("23:00 in Ho Chi Minh City: reason %q, want quiet", got)
	}
	setZone(`UPDATE core_org SET timezone = 'America/New_York'`)
	if got := reasons("nt-2"); got != "now" {
		t.Fatalf("11:00 in New York: reason %q, want now", got)
	}
}

// (c) The links of approval requests carry the BaseURL host, and without a BaseURL (loopback, dev) an approval
// request is refused: a link that approves an action must point at the real box.
func TestWiringApprovalLinkCarriesBaseURL(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, base string }{{"with", "https://192.168.10.2:8443"}, {"without", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newStackWith(t, func(d *deps) { d.BaseURL = tc.base })
			s.enableNotify()
			op := s.addUser("op@acme.example", routes.Operator)
			sink := newSMTPSink(t)
			s.email(sink, notify.Approver{UserID: op.ID, Address: "op@acme.example"})
			_, err := newNotify(s.d).SendApprovalRequest(t.Context(), notify.ApprovalRequest{ID: "req-1", Title: "Block 203.0.113.9", What: "w", Action: "a",
				Severity: notify.High, Expires: time.Now().Add(time.Hour), Channels: []channel.Type{channel.Email}})
			if tc.base == "" {
				if !errors.Is(err, notify.ErrApprovalUnavailable) {
					t.Fatalf("without a BaseURL: %v, want ErrApprovalUnavailable", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			msgs := sink.messages()
			if len(msgs) == 0 || !strings.Contains(msgs[0], tc.base+"/response") {
				t.Fatalf("the approval mail has no link to %s:\n%v", tc.base, msgs)
			}
		})
	}
}

// (c2) The mailer given to core/auth is the one of notify and it can mail step-up codes (D-98): a mailer without
// SendStepUpCode would make email two-step approval answer 503 twofa_email_unavailable. Without an email channel
// it is not available and refuses to send, so a step-up never falls back to nothing.
func TestWiringCodeMailerIsAStepUpMailer(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.enableNotify()
	m := newNotify(s.d).CodeMailer()
	var _ auth.CodeMailer = m
	sm, ok := any(m).(auth.StepUpMailer)
	if !ok {
		t.Fatal("the notify code mailer does not implement auth.StepUpMailer")
	}
	if m.Available(t.Context()) || sm.SendStepUpCode(t.Context(), "op@acme.example", "123456", "Approve x") == nil {
		t.Fatal("a step-up code was sent without an email channel")
	}
	sink := newSMTPSink(t)
	s.email(sink)
	if err := sm.SendStepUpCode(t.Context(), "op@acme.example", "123456", "Approve x"); err != nil {
		t.Fatal(err)
	}
	if msgs := sink.messages(); len(msgs) != 1 || !strings.Contains(msgs[0], "123456") || !strings.Contains(msgs[0], "Approve x") {
		t.Fatalf("step-up mail: %v", msgs)
	}
}

// (d) A new-device notice names the device the way the inventory does (the name given to it), not its asset id.
func TestWiringDeviceNoticeNamesTheDeviceFromInventory(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.enableNotify()
	r, err := s.d.Inventory.AddDevice(t.Context(), "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", Name: "fw-hanoi", IP: "192.168.30.1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.d.Bus.Publish(t.Context(), events.Event{Name: inventory.EventAssetDiscovered, Data: inventory.AssetEvent{AssetID: r.ID, Notify: true}}); err != nil {
		t.Fatal(err)
	}
	list, err := newNotify(s.d).Incidents(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || !strings.Contains(list[0].Title, "fw-hanoi") || strings.Contains(list[0].Title, r.ID) {
		t.Fatalf("the incident does not name the device: %+v", list)
	}
}

// baseURL: the first -hosts name, else the first certificate name; no link on loopback.
func TestBaseURL(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		hosts  []string
		listen string
		want   string
	}{
		{[]string{"vedette.corp.example", "10.0.0.5"}, "0.0.0.0:443", "https://vedette.corp.example"},
		{[]string{"192.168.10.2"}, ":8443", "https://192.168.10.2:8443"},
		{[]string{"*.corp.example", "localhost", "127.0.0.1", "box.corp.example"}, "10.0.0.5:8443", "https://box.corp.example:8443"},
		{[]string{"fd00::5"}, "[::]:443", "https://[fd00::5]"},
		{[]string{"vedette.corp.example"}, "127.0.0.1:8080", ""},
		{nil, ":8443", ""},
		{[]string{"localhost"}, ":8443", ""},
	} {
		if got := baseURL(tc.hosts, tc.listen); got != tc.want {
			t.Errorf("baseURL(%v, %q) = %q, want %q", tc.hosts, tc.listen, got, tc.want)
		}
	}
}

// hcmZone is the organization time zone of a box whose core_org row says nothing else (the column default): the
// sensor-active tests set their clocks in it, and the window follows it, not the zone of the machine running the test.
var hcmZone = func() *time.Location {
	l, err := time.LoadLocation("Asia/Ho_Chi_Minh")
	if err != nil {
		panic(err)
	}
	return l
}()

// The scan window of sensor-active follows the organization time zone, asked at every use: 02:00 in Ho Chi Minh City
// is inside 01:00-05:00 and is 15:00 in New York, outside it; a change of the zone applies to the next tick.
func TestWiringScanWindowFollowsTheOrganizationTimeZone(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 9, 2, 0, 0, 0, hcmZone) // Monday
	s := newStackWith(t, func(d *deps) { d.Clock = func() time.Time { return now } })
	nm := newFakeNmap(t)
	svc, err := newSensorActive(*s.d, nm.path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	s.saveScope(t)
	setZone := func(q string) {
		t.Helper()
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q); return err }); err != nil {
			t.Fatal(err)
		}
	}
	setZone(`INSERT INTO core_org (id, name, timezone, data_mode, install_id) VALUES (1, 'Acme', 'America/New_York', 'clean', 'ins-test')`) // 15:00 there
	if z := svc.Health(ctx).Zone; z != "America/New_York" {
		t.Fatalf("zone %q", z)
	}
	if err := svc.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got := len(nm.calls(t)); got != 0 {
		t.Fatalf("the window is closed in New York but %d nmap calls ran", got)
	}
	setZone(`UPDATE core_org SET timezone = 'Asia/Ho_Chi_Minh'`) // 02:00 there; no restart
	if z := svc.Health(ctx).Zone; z != "Asia/Ho_Chi_Minh" {
		t.Fatalf("zone after the change %q", z)
	}
	if err := svc.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(nm.calls(t)) == 0 {
		t.Fatal("02:00 in the organization zone is inside the window, but nothing was scanned")
	}
}
