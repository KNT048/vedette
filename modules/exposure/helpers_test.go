package exposure

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/store"
)

var t0 = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

// Real public addresses are used as sample IPs: the documentation ranges are refused (INV-3). No test
// connects to them; the prober is a fake.
const (
	ipA = "8.8.8.8"
	ipB = "8.8.4.4"
	ipC = "9.9.9.9"
	ipD = "1.1.1.1"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeProber answers the rounds in turn from ips (a loop): "!" is a round with every service down, "~" a round in which
// they did not agree. down makes every round fail. The 2-of-3 rule itself is tested on PublicServiceProber.
type fakeProber struct {
	mu    sync.Mutex
	ips   []string
	down  bool
	calls int
}

func (p *fakeProber) set(ips ...string) { p.mu.Lock(); p.ips, p.down = ips, false; p.mu.Unlock() }
func (p *fakeProber) offline()          { p.mu.Lock(); p.down = true; p.mu.Unlock() }
func (p *fakeProber) count() int        { p.mu.Lock(); defer p.mu.Unlock(); return p.calls }

func (p *fakeProber) Round(context.Context) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.calls
	p.calls++
	if p.down || len(p.ips) == 0 || p.ips[i%len(p.ips)] == "!" {
		return netip.Addr{}, ErrServicesDown
	}
	if p.ips[i%len(p.ips)] == "~" {
		return netip.Addr{}, ErrNoAgreement
	}
	return netip.ParseAddr(p.ips[i%len(p.ips)])
}

type fakeResolver struct {
	mu   sync.Mutex
	txt  map[string][]string
	err  error
	asks []string
}

func (r *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asks = append(r.asks, name)
	if r.err != nil {
		return nil, r.err
	}
	return r.txt[name], nil
}

func (r *fakeResolver) put(name string, vals ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.txt[name] = vals
}

func (r *fakeResolver) lookups() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.asks) }

type fakeRunner struct {
	content Content
	err     error
	calls   int
}

func (r *fakeRunner) Scan(context.Context, ScanTarget) (Content, error) {
	r.calls++
	return r.content, r.err
}

type fakePub struct {
	mu  sync.Mutex
	got []events.Event
}

func (p *fakePub) Publish(_ context.Context, e events.Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.got = append(p.got, e)
	return nil
}

func (p *fakePub) names() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, e := range p.got {
		out = append(out, e.Name)
	}
	return out
}

type env struct {
	t      *testing.T
	db     *store.DB
	svc    *Service
	clock  *fakeClock
	prober *fakeProber
	dns    *fakeResolver
	pub    *fakePub
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := newDB(t)
	e := &env{t: t, db: db, clock: &fakeClock{now: t0}, prober: &fakeProber{ips: []string{ipA}}, dns: &fakeResolver{txt: map[string][]string{}}, pub: &fakePub{}}
	svc, err := NewService(Config{DB: db, Audit: audit.New(e.clock.Now), Resolver: e.dns, Prober: e.prober, Publisher: e.pub, Log: slog.New(slog.DiscardHandler), Clock: e.clock.Now, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

func (e *env) advance(d time.Duration) { e.clock.Advance(d) }

func (e *env) ctx() context.Context { return e.t.Context() }

type auditRow struct{ User, Action, Target, Detail string }

func (e *env) audits() []auditRow {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT user, action, target, coalesce(detail, '') FROM core_audit ORDER BY seq`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []auditRow
	for rows.Next() {
		var a auditRow
		if err := rows.Scan(&a.User, &a.Action, &a.Target, &a.Detail); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func (e *env) auditActions() []string {
	var out []string
	for _, a := range e.audits() {
		out = append(out, a.Action)
	}
	return out
}

func (e *env) count(query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.Reader().QueryRowContext(e.ctx(), query, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// addVerifiedDomain adds acme.example, publishes its TXT record and verifies it.
func (e *env) addVerifiedDomain() TargetView {
	e.t.Helper()
	v, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "acme.example")
	if err != nil {
		e.t.Fatal(err)
	}
	e.dns.put(v.Value, txtRecord(v.Token))
	r, err := e.svc.Verify(e.ctx(), "operator@acme.example", v.ID)
	if err != nil || !r.Verified {
		e.t.Fatalf("verify: %+v %v", r, err)
	}
	return r.Target
}

// detect runs a detection as a person and returns the targets it saw.
func (e *env) detect(ips ...string) []TargetView {
	e.t.Helper()
	e.prober.set(ips...)
	r, err := e.svc.Detect(e.ctx(), "admin@acme.example", true)
	if err != nil {
		e.t.Fatal(err)
	}
	return r.Items
}

func (e *env) target(id string) TargetView {
	e.t.Helper()
	v, err := e.svc.Target(e.ctx(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}

func (e *env) ipValues() []string {
	e.t.Helper()
	all, err := e.svc.Targets(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, v := range all {
		if v.Kind == KindIP {
			out = append(out, v.Value)
		}
	}
	return out
}

func wantAPI(t *testing.T, err error, status int, code string) {
	t.Helper()
	var ae *APIError
	if !errors.As(err, &ae) || ae.HTTP != status || ae.Code != code {
		t.Fatalf("want API error %d %s, got %v", status, code, err)
	}
}

func str(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// commit records the commitment the way an administrator's first Scan now does (D-473), without a scan.
func (e *env) commit(id string) (TargetView, error) {
	e.t.Helper()
	t, err := loadTarget(e.ctx(), e.db.Reader(), id)
	if err != nil {
		return TargetView{}, err
	}
	if err := e.svc.commit(e.ctx(), "admin@acme.example", id, noticeFor(t.Value)); err != nil {
		return TargetView{}, err
	}
	return e.svc.Target(e.ctx(), id)
}
