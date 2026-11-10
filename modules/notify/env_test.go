package notify_test

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

const (
	tgToken    = "123456789:AAHexampleExampleExample0123456789ab" // not a real token
	tgSecret   = "AAHexampleExampleExample0123456789ab"
	relayLogin = "not-needed-for-none"
)

// slackURL is an example Incoming Webhook address, assembled at run time so it never looks like a real one.
var slackURL = "https://hooks.slack.com/services/" + "T0EXAMPLE1/" + "B0EXAMPLE1/" + "not-a-real-webhook"

// fakeClock is a settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeNet is the HTTP client of the adapters: it records every request and answers 200 unless a host is told otherwise.
type netCall struct{ Host, Path, Body string }

type fakeNet struct {
	mu     sync.Mutex
	calls  []netCall
	status map[string]int
}

func (f *fakeNet) RoundTrip(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls = append(f.calls, netCall{r.URL.Host, r.URL.Path, string(b)})
	code := f.status[r.URL.Host]
	f.mu.Unlock()
	if code == 0 {
		code = 200
	}
	body := `{"ok":true,"result":{}}`
	if code != 200 {
		body = `{"ok":false,"description":"nope"}`
	}
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: r}, nil
}

func (f *fakeNet) to(host string) []netCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []netCall
	for _, c := range f.calls {
		if c.Host == host {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeNet) total() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

func (f *fakeNet) failTelegram(code int) {
	host := "api.telegram.org"
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status == nil {
		f.status = map[string]int{}
	}
	f.status[host] = code
}

// fakeUsers is the Users interface.
type fakeUsers struct {
	mu        sync.Mutex
	users     map[string]notify.User
	emailCode int
}

func (u *fakeUsers) Lookup(_ context.Context, id string) (notify.User, bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	x, ok := u.users[id]
	return x, ok, nil
}

func (u *fakeUsers) EmailCodeUsers(context.Context) (int, error) { return u.emailCode, nil }

// fakeTokens is the TokenRecorder of the response module.
type fakeTokens struct {
	mu    sync.Mutex
	recs  []notify.Binding
	ids   []notify.TokenID
	addrs []string
	codes []notify.ReplyCode
}

func (f *fakeTokens) RecordReplyCode(_ context.Context, c notify.ReplyCode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codes = append(f.codes, c)
	return nil
}

func (f *fakeTokens) RecordToken(_ context.Context, id notify.TokenID, b notify.Binding, _, address string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recs, f.ids, f.addrs = append(f.recs, b), append(f.ids, id), append(f.addrs, address)
	return nil
}

type env struct {
	t      *testing.T
	db     *store.DB
	svc    *notify.Service
	clock  *fakeClock
	net    *fakeNet
	users  *fakeUsers
	bus    *events.Bus
	tokens *fakeTokens
	sec    *secrets.Store
	seen   *seenEvents
}

type seenEvents struct {
	mu    sync.Mutex
	names []string
}

func (s *seenEvents) count(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, x := range s.names {
		if x == name {
			n++
		}
	}
	return n
}

func (e *env) ctx() context.Context { return e.t.Context() }

func newEnv(t *testing.T, opts ...func(*notify.Config)) *env {
	t.Helper()
	db := storetest.New(t)
	ctx := t.Context()
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "notify", notify.Migrations); err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, db: db, sec: sec, clock: &fakeClock{t: time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)}, net: &fakeNet{}, tokens: &fakeTokens{}, seen: &seenEvents{},
		users: &fakeUsers{users: map[string]notify.User{
			"u-admin": {ID: "u-admin", Email: "admin@acme.example", Role: "admin", Active: true},
			"u-op":    {ID: "u-op", Email: "it@acme.example", Role: "operator", Active: true},
			"u-view":  {ID: "u-view", Email: "director@acme.example", Role: "viewer", Active: true},
			"u-off":   {ID: "u-off", Email: "gone@acme.example", Role: "operator", Active: false},
		}}}
	log := slog.New(slog.DiscardHandler)
	e.bus = events.NewBus(log)
	for _, n := range []string{"notify.incident.created", "notify.message.sent", "notify.message.failed", "notify.channel.changed", "notify.approval.requested"} {
		e.bus.Subscribe(n, func(_ context.Context, ev events.Event) error {
			e.seen.mu.Lock()
			e.seen.names = append(e.seen.names, ev.Name)
			e.seen.mu.Unlock()
			return nil
		})
	}
	cfg := notify.Config{DB: db, Secrets: sec, Audit: audit.New(e.clock.Now), Users: e.users, Log: log, Bus: e.bus, Clock: e.clock.Now, Location: time.UTC,
		BaseURL: "https://box.example:8443", HTTPClient: &http.Client{Transport: e.net}, Tokens: e.tokens}
	for _, o := range opts {
		o(&cfg)
	}
	e.svc, err = notify.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// save stores a channel as admin and fails the test on an error.
func (e *env) save(t channel.Type, in notify.ChannelInput) notify.Channel {
	e.t.Helper()
	c, err := e.svc.SaveChannel(e.ctx(), "admin@acme.example", t, in)
	if err != nil {
		e.t.Fatalf("save %s: %v", t, err)
	}
	return c
}

func (e *env) telegram(floor notify.Severity) {
	e.t.Helper()
	e.save(channel.Telegram, notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": "-1002145678901"}, Secret: tgToken, MinSeverity: floor})
}

func (e *env) slack(floor notify.Severity) {
	e.t.Helper()
	e.save(channel.Slack, notify.ChannelInput{Enabled: true, Fields: map[string]string{"label": "#it-alerts"}, Secret: slackURL, MinSeverity: floor})
}

func (e *env) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.Reader().QueryRowContext(e.ctx(), q, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) flush() {
	e.t.Helper()
	if err := e.svc.Flush(e.ctx()); err != nil {
		e.t.Fatalf("flush: %v", err)
	}
}

func (e *env) write(fn func(tx *sql.Tx) error) {
	e.t.Helper()
	if err := e.db.Write(e.ctx(), fn); err != nil {
		e.t.Fatal(err)
	}
}

// vulnNotice is a matched vulnerability notice.
func (e *env) vulnNotice(id, product, cve string, sev notify.Severity, devices ...string) notify.Notice {
	return notify.Notice{ID: id, Kind: notify.KindVuln, Severity: sev, Product: product, CVEs: []string{cve}, FindingIDs: []string{"f-" + id}, Devices: devices,
		Title: product + " is being exploited (" + cve + ")", What: "Attackers are using " + cve + " right now.", Action: "Install the update.",
		Link: "https://box.example:8443/findings/f-" + id, At: e.clock.Now()}
}

// fakeSMTP is a server for the email channel (security "none" on 127.0.0.1): it keeps every message.
type fakeSMTP struct {
	ln   net.Listener
	mu   sync.Mutex
	msgs []string
	rcpt []string
	// rcptReply, when set, is the whole reply to RCPT (a refusal).
	rcptReply string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSMTP{ln: ln}
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

func (s *fakeSMTP) port() string { _, p, _ := net.SplitHostPort(s.ln.Addr().String()); return p }

func (s *fakeSMTP) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	say := func(s string) { _, _ = fmt.Fprint(c, s+"\r\n") }
	say("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		up := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			say("250 fake")
		case strings.HasPrefix(up, "MAIL"):
			say("250 ok")
		case strings.HasPrefix(up, "RCPT"):
			s.mu.Lock()
			s.rcpt = append(s.rcpt, strings.TrimSpace(line))
			reply := s.rcptReply
			s.mu.Unlock()
			if reply != "" {
				say(reply)
				continue
			}
			say("250 ok")
		case up == "DATA":
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
		case up == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func (s *fakeSMTP) messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.msgs...)
}
func (s *fakeSMTP) recipients() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.rcpt...)
}

// email saves an email channel that points at the fake server.
func (e *env) email(s *fakeSMTP, extra ...func(*notify.ChannelInput)) {
	e.t.Helper()
	in := notify.ChannelInput{Enabled: true, MinSeverity: notify.High, Secret: relayLogin,
		Fields: map[string]string{"host": "127.0.0.1", "port": s.port(), "security": "none", "username": "alerts@acme.example", "from": "alerts@acme.example", "to": "it@acme.example, director@acme.example"}}
	for _, f := range extra {
		f(&in)
	}
	e.save(channel.Email, in)
}
