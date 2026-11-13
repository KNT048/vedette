package reports

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// 2026-11-11 is a Wednesday.
var t0 = time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)

type fakeInv struct{ devs []Device }

func (f *fakeInv) Devices(context.Context) ([]Device, error) { return f.devs, nil }

type fakeFindings struct {
	fs  []Finding
	err error
}

func (f *fakeFindings) All(context.Context) ([]Finding, error) { return f.fs, f.err }

type fakeKEV struct {
	es           []KEVEntry
	at           time.Time
	newN, inUseN int
}

func (f *fakeKEV) Entries(context.Context) ([]KEVEntry, time.Time, error) { return f.es, f.at, nil }

func (f *fakeKEV) NewlyExploited(context.Context) (int, int, error) { return f.newN, f.inUseN, nil }

type fakeMail struct {
	mu    sync.Mutex
	ready bool
	err   error
	sent  []sentMail
}
type sentMail struct {
	to []string
	m  Mail
}

func (f *fakeMail) Ready(context.Context) (bool, string) { return f.ready, "not ready" }
func (f *fakeMail) Send(_ context.Context, to []string, m Mail) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, sentMail{append([]string(nil), to...), m})
	return nil
}
func (f *fakeMail) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.sent) }

type fakeAI struct {
	on    bool
	err   error
	calls []string
	data  [][]Block
}

func (f *fakeAI) Available(string) bool { return f.on }
func (f *fakeAI) Summarize(_ context.Context, _, job, _ string, data []Block) (Summary, error) {
	f.calls = append(f.calls, job)
	f.data = append(f.data, data)
	if f.err != nil {
		return Summary{}, f.err
	}
	return Summary{Paragraphs: []string{"Commentary."}, Model: "m", Profile: "p", TokensIn: 10, TokensOut: 5}, nil
}

type fakeMods map[string]bool

func (f fakeMods) Enabled(id string) bool { return f[id] }

type clockT struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clockT) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clockT) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type env struct {
	t     *testing.T
	db    *store.DB
	svc   *Service
	clock *clockT
	inv   *fakeInv
	fnd   *fakeFindings
	kev   *fakeKEV
	mail  *fakeMail
	ai    *fakeAI
	mods  fakeMods
}

func newDB(t *testing.T) *store.DB {
	t.Helper()
	db := storetest.New(t)
	for _, m := range []storetest.Migration{{Module: "core", FS: core.Migrations}, {Module: "reports", FS: Migrations}} {
		if err := store.Migrate(t.Context(), db, m.Module, m.FS); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, db: newDB(t), clock: &clockT{now: t0}, inv: &fakeInv{}, fnd: &fakeFindings{}, kev: &fakeKEV{}, mail: &fakeMail{ready: true}, ai: &fakeAI{on: true}, mods: fakeMods{"logs": true}}
	svc, err := NewService(Config{DB: e.db, Audit: audit.New(e.clock.Now), Inventory: e.inv, Findings: e.fnd, KEV: e.kev, Mail: e.mail, AI: e.ai, Modules: e.mods,
		OrgName: func(context.Context) (string, error) { return "Acme Ltd", nil }, Zone: func(context.Context) string { return "UTC" },
		Log: slog.New(slog.DiscardHandler), Clock: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

func (e *env) ctx() context.Context { return e.t.Context() }

func (e *env) count(query string) int {
	e.t.Helper()
	var n int
	if err := e.db.Reader().QueryRowContext(e.ctx(), query).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) auditActions() []string {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT action FROM core_audit ORDER BY seq`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

var errBoom = errors.New("boom")
