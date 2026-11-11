package scan

import (
	"context"
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
	e := &env{t: t, db: newDB(t), clock: &fakeClock{now: t0}, inv: &fakeInventory{scope: confirmedScope()}, engine: &fakeEngine{}}
	svc, err := NewService(Config{DB: e.db, Audit: audit.New(e.clock.Now), Inventory: e.inv, Engine: e.engine, Pack: testPack(t), Log: slog.New(slog.DiscardHandler), Clock: e.clock.Now})
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
