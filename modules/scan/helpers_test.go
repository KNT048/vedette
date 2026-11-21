package scan

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/scan/nucleiout"
)

// t0 is a Tuesday, 10:00 UTC.
var t0 = time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

// fakeInventory answers Scope. writes counts nothing because the interface has no write: INV-11 is structural.
type fakeInventory struct {
	mu    sync.Mutex
	scope Scope
	err   error
	// the shared window, check rate and exclusions, the inventory's (INV-16): what SaveChecks stored, what it was given, and
	// whether each transaction settled committed
	checks  Checks
	saved   []Checks
	settled []bool
	refuse  error
}

// defaultChecks are the shared values of a fresh box: every day 22:00 to 05:00, 5 requests per second, nothing excluded.
func defaultChecks() Checks {
	return Checks{Window: Window{Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "22:00", To: "05:00"}, Rate: 5, Exclusions: []string{}}
}

func (f *fakeInventory) Checks(context.Context) (Checks, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checks, nil
}

func (f *fakeInventory) SaveChecks(_ context.Context, tx *sql.Tx, _ string, c Checks) error {
	if tx == nil {
		return errors.New("no transaction")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse != nil {
		return f.refuse
	}
	f.saved = append(f.saved, c)
	f.checks = c
	return nil
}

func (f *fakeInventory) Settle(_ context.Context, _ *sql.Tx, committed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settled = append(f.settled, committed)
}

func (f *fakeInventory) Scope(context.Context) (Scope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.scope, f.err
}

func (f *fakeInventory) set(s Scope) { f.mu.Lock(); f.scope = s; f.mu.Unlock() }

func (f *fakeInventory) Devices(context.Context) ([]Device, error) { return nil, nil }

func (f *fakeInventory) VulnScanPolicy(context.Context, string, bool) (Decision, error) {
	return Decision{Allowed: true, Reason: "ok"}, nil
}

func (f *fakeInventory) VulnScanPolicies(_ context.Context, ids []string, _ bool) (map[string]Decision, error) {
	out := map[string]Decision{}
	for _, id := range ids {
		out[id] = Decision{Allowed: true, Reason: "ok"}
	}
	return out, nil
}

// fakeEngine is the scanner seam: ready or not.
type fakeEngine struct {
	mu   sync.Mutex
	down error
}

func (f *fakeEngine) Ready(context.Context) error { f.mu.Lock(); defer f.mu.Unlock(); return f.down }
func (f *fakeEngine) setDown(err error)           { f.mu.Lock(); f.down = err; f.mu.Unlock() }

func (f *fakeEngine) Run(context.Context, Job) (nucleiout.Outcome, error) {
	return nucleiout.Outcome{}, nil
}

var errNoHeartbeat = errors.New("no heartbeat from the scan worker for 90 s")

func confirmedScope() Scope {
	return Scope{Networks: []string{"192.168.10.0/24", "192.168.20.0/24"}, ConfirmedAt: "2026-11-01T08:00:00.000Z", ConfirmedBy: "admin@acme.example"}
}

type env struct {
	t      *testing.T
	db     *store.DB
	svc    *Service
	runs   *run.Manager
	clock  *fakeClock
	inv    *fakeInventory
	engine *fakeEngine
}

func newDB(t *testing.T) *store.DB {
	t.Helper()
	db := storetest.New(t)
	for _, m := range []storetest.Migration{{Module: "core", FS: core.Migrations}, {Module: ModuleID, FS: Migrations}} {
		if err := store.Migrate(t.Context(), db, m.Module, m.FS); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// newEnv builds a service whose scope is confirmed and whose scanner is ready; tests change either.
func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, db: newDB(t), clock: &fakeClock{now: t0}, inv: &fakeInventory{scope: confirmedScope(), checks: defaultChecks()}, engine: &fakeEngine{}}
	svc, err := e.rebuild(Config{DB: e.db, Audit: audit.New(e.clock.Now), Inventory: e.inv, Engine: e.engine, Pack: testPack(t), Log: slog.New(slog.DiscardHandler), Clock: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

// rebuild is NewService over a run manager of its own, started: a kind is registered once per manager, and the manager runs the
// kind of the service it was built for, so a test that changes the configuration builds the service again with a new manager and
// the old one ends first.
func (e *env) rebuild(cfg Config) (*Service, error) {
	e.t.Helper()
	if e.runs != nil {
		e.runs.Close()
	}
	m, err := run.New(run.Config{DB: e.db, Audit: cfg.Audit, Clock: e.clock.Now, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		return nil, err
	}
	cfg.Runs = m
	svc, err := NewService(cfg)
	if err != nil {
		return nil, err
	}
	if err := m.Start(e.t.Context()); err != nil {
		return nil, err
	}
	e.t.Cleanup(m.Close)
	e.runs = m
	return svc, nil
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

func wantAPI(t *testing.T, err error, status int, code string) {
	t.Helper()
	var ae *APIError
	if !errors.As(err, &ae) || ae.HTTP != status || ae.Code != code {
		t.Fatalf("want API error %d %s, got %v", status, code, err)
	}
}

// ---- HTTP ----

type scanOnly struct {
	server.Fallback
	*ScanHandlers
}

type httpEnv struct {
	*env
	h    http.Handler
	gate *servertest.Gate
}

func newHTTPEnv(t *testing.T) *httpEnv {
	t.Helper()
	e := newEnv(t)
	gate := servertest.NewGate()
	h, err := server.New(server.Config{
		API:     scanOnly{Fallback: server.Fallback{Log: slog.New(slog.DiscardHandler)}, ScanHandlers: NewScanHandlers(e.svc)},
		Auth:    &servertest.Auth{Users: servertest.StandardUsers()},
		Modules: gate,
		Log:     slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &httpEnv{env: e, h: h, gate: gate}
}

func (e *httpEnv) call(method, path, user, body string) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequestWithContext(e.t.Context(), method, server.Prefix+path, rd)
	r.Header.Set("Content-Type", "application/json")
	if user != "" {
		r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: user, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	r.Header.Set(servertest.CSRFHeader, servertest.CSRFValue)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			e.t.Fatalf("%s %s: not JSON: %v: %s", method, path, err, w.Body)
		}
	}
	return w.Code, out
}

func errOf(b map[string]any) (code, msg string) {
	m, _ := b["error"].(map[string]any)
	code, _ = m["code"].(string)
	msg, _ = m["message"].(string)
	return code, msg
}

// seedRun stores a vulnerability check as an earlier process left it: in status st (an end time when it has ended), started at
// the given time, with one result row (a device item) per id.
func seedRun(ctx context.Context, tx *sql.Tx, id, st, at string, ids ...string) error {
	var ended any
	if st != "running" && st != "stopping" && st != "queued" {
		ended = at
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO core_run (id, module, kind, lane, title, trigger, requested_by, status, total, done, queued_at, started_at, ended_at, updated_at)
VALUES (?1, 'scan', 'vuln_check', 'nuclei', 'Vulnerability check', 'manual', 'x', ?2, ?3, 0, ?4, ?4, ?5, ?4)`, id, st, len(ids), at, ended); err != nil {
		return err
	}
	for i, d := range ids {
		if _, err := tx.ExecContext(ctx, `INSERT INTO core_run_item (run_id, seq, subject_kind, subject_id, label, outcome, note) VALUES (?, ?, 'device', ?, ?, 'not_matched', 'x')`,
			id, i+1, d, itemLabel(d, "192.0.2.1")); err != nil {
			return err
		}
	}
	return nil
}
