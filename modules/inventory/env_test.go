package inventory_test

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/inventory"
)

// recorder is a fake event bus: it keeps what was published.
type recorder struct {
	mu     sync.Mutex
	events []inventory.Event
}

func (r *recorder) Publish(_ context.Context, e inventory.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *recorder) named(name string) []inventory.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []inventory.Event
	for _, e := range r.events {
		if e.Name == name {
			out = append(out, e)
		}
	}
	return out
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = nil
}

// fakeKEV serves the embedded product pairs and a CVE table keyed by "vendor|product".
type fakeKEV struct {
	inventory.EmbeddedKEV
	cves map[string][]string
}

func (f fakeKEV) CVEs(_ context.Context, keys []string) ([]string, error) {
	var out []string
	for _, k := range keys {
		out = append(out, f.cves[k]...)
	}
	return out, nil
}

type fakeBox struct{ items []inventory.SoftwareItem }

func (f fakeBox) Packages(context.Context) ([]inventory.SoftwareItem, error) { return f.items, nil }

type fakeFindings map[string]int

func (f fakeFindings) CountByAsset(context.Context) (map[string]int, error) { return f, nil }

type env struct {
	t     *testing.T
	db    *store.DB
	svc   *inventory.Service
	ev    *recorder
	now   time.Time
	findg fakeFindings
}

type opt func(*inventory.Config)

func withKEV(k inventory.KEV) opt         { return func(c *inventory.Config) { c.KEV = k } }
func withBox(b inventory.BoxPackages) opt { return func(c *inventory.Config) { c.Box = b } }

func newEnv(t *testing.T, opts ...opt) *env {
	t.Helper()
	db := storetest.Migrated(t, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "inventory", FS: inventory.Migrations})
	e := &env{t: t, db: db, ev: &recorder{}, now: time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC), findg: fakeFindings{}}
	cfg := inventory.Config{DB: db, Audit: audit.New(nil), Events: e.ev, Findings: e.findg, Clock: func() time.Time { return e.now }}
	for _, o := range opts {
		o(&cfg)
	}
	svc, err := inventory.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

// tick moves the fake clock forward.
func (e *env) tick(d time.Duration) { e.now = e.now.Add(d) }

func (e *env) ctx() context.Context { return e.t.Context() }

// count runs a COUNT query on the database.
func (e *env) count(query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.Reader().QueryRowContext(e.ctx(), query, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", query, err)
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

// addDevice declares a device by hand and returns its id.
func (e *env) addDevice(in inventory.AddInput) string {
	e.t.Helper()
	r, err := e.svc.AddDevice(e.ctx(), "it@acme.example", in)
	if err != nil {
		e.t.Fatalf("AddDevice(%+v): %v", in, err)
	}
	return r.ID
}

// wantAPIError checks err is an API error with the status and code.
func wantAPIError(t *testing.T, err error, status int, code string) {
	t.Helper()
	ae, ok := apierr.As(err)
	if !ok {
		t.Fatalf("error = %v, want an API error %d %s", err, status, code)
	}
	if ae.Status != status || ae.Code != code {
		t.Fatalf("error = %d %s (%s), want %d %s", ae.Status, ae.Code, ae.Message, status, code)
	}
}

func has(list []string, v string) bool { return slices.Contains(list, v) }

func contains(s, sub string) bool { return strings.Contains(s, sub) }

type dbTx = *sql.Tx
