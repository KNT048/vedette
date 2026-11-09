package core_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules"
	"github.com/knt048/vedette/modules/core"
)

// scanStub is a stand-in for the scan module's handler: one route that exists only while scan is on.
type scanStub struct{}

func (scanStub) ScanGetScansConfig(context.Context) (*oas.ScanGetScansConfigOK, error) {
	return &oas.ScanGetScansConfigOK{}, nil
}

type composite struct {
	server.Fallback
	*core.ModuleHandlers
	scanStub
}

// stack is the real wiring of the process, minus sessions: database, audit, registry on the embedded
// manifests, scheduler on the registry, and the HTTP server with the core module handlers.
type stack struct {
	t      *testing.T
	db     *store.DB
	reg    *modreg.Registry
	h      http.Handler
	starts chan struct{} // the scan job started
	ended  chan struct{} // the scan job's context was cancelled
	hist   *jobs.History
}

func newStack(t *testing.T) *stack {
	t.Helper()
	db := migrated(t)
	log := slog.New(slog.DiscardHandler)
	reg, err := modreg.New(t.Context(), modreg.Config{DB: db, Audit: audit.New(nil), Manifests: modules.Manifests, Version: "test", Log: log})
	if err != nil {
		t.Fatal(err)
	}
	s := &stack{t: t, db: db, reg: reg, starts: make(chan struct{}, 16), ended: make(chan struct{}, 16), hist: jobs.NewHistory(db)}
	sched := jobs.New(log, reg, nil, jobs.WithRecorder(s.hist))
	reg.OnChange(sched.ModuleChanged)
	err = sched.Add(jobs.Job{Module: "scan", Name: "probe", Every: time.Hour, Run: func(ctx context.Context) error {
		s.starts <- struct{}{}
		<-ctx.Done()
		s.ended <- struct{}{}
		return ctx.Err()
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); sched.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	s.h, err = server.New(server.Config{
		API:     composite{Fallback: server.Fallback{Log: log}, ModuleHandlers: core.NewModuleHandlers(db, reg)},
		Auth:    &servertest.Auth{Users: servertest.StandardUsers()},
		Modules: reg,
		Log:     log,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *stack) call(method, path, user, body string) (int, map[string]any) {
	s.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequestWithContext(s.t.Context(), method, server.Prefix+path, rd)
	r.Header.Set("Content-Type", "application/json")
	if user != "" {
		r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: user, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	r.Header.Set(servertest.CSRFHeader, servertest.CSRFValue)
	w := httptest.NewRecorder()
	s.h.ServeHTTP(w, r)
	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			s.t.Fatalf("%s %s: body is not JSON: %v: %s", method, path, err, w.Body)
		}
	}
	return w.Code, out
}

func (s *stack) patch(id string, body string) (int, map[string]any) {
	s.t.Helper()
	return s.call("PATCH", "/modules/"+id, "admin", body)
}

func errCode(body map[string]any) string {
	e, _ := body["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

// modulesOf returns id -> module object from a response that has "modules".
func modulesOf(t *testing.T, body map[string]any) map[string]map[string]any {
	t.Helper()
	list, ok := body["modules"].([]any)
	if !ok {
		t.Fatalf("no modules array in %v", body)
	}
	out := map[string]map[string]any{}
	for _, x := range list {
		m := x.(map[string]any)
		out[m["id"].(string)] = m
	}
	return out
}

func (s *stack) enabledInDB(id string) bool {
	s.t.Helper()
	var on bool
	if err := s.db.Reader().QueryRowContext(s.t.Context(), "SELECT enabled FROM core_module WHERE id = ?", id).Scan(&on); err != nil {
		s.t.Fatal(err)
	}
	return on
}

func (s *stack) auditRows(where string) []string {
	s.t.Helper()
	rows, err := s.db.Reader().QueryContext(s.t.Context(), "SELECT user || '|' || action || '|' || target || '|' || coalesce(detail, '') FROM core_audit WHERE "+where+" ORDER BY seq")
	if err != nil {
		s.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var x string
		if err := rows.Scan(&x); err != nil {
			s.t.Fatal(err)
		}
		out = append(out, x)
	}
	return out
}

func (s *stack) waitFor(ch <-chan struct{}, what string) {
	s.t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		s.t.Fatalf("timed out waiting for %s", what)
	}
}

// The ids the SPA knows (web/src/features/core/contract.ts ModuleId); host is a component and is not one.
var spaModuleIDs = []string{
	"core", "feeds", "inventory", "notify", "sensor-passive", "sensor-active", "findings", "mitigation", "exposure", "scan",
	"scan-credentialed", "honeypot", "logs", "agent-intake", "ai", "reports", "mcp-server", "auth-oidc", "response",
}

func TestContract_Modules_ListMatchesTheMockShape(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	code, body := s.call("GET", "/modules", "viewer", "")
	if code != 200 {
		t.Fatalf("GET /modules = %d %v", code, body)
	}
	mods := modulesOf(t, body)
	var ids []string
	for id := range mods {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	want := slices.Clone(spaModuleIDs)
	slices.Sort(want)
	if !slices.Equal(ids, want) {
		t.Fatalf("module ids = %v\nwant %v (host is a component and must not be listed)", ids, want)
	}
	for id, m := range mods {
		if len(m) != 5 {
			t.Errorf("%s has fields %v, want exactly id, enabled, tier, depends, enabled_at", id, m)
		}
		if _, ok := m["depends"].([]any); !ok {
			t.Errorf("%s: depends = %v, want a list (never null)", id, m["depends"])
		}
		on := m["enabled"].(bool)
		at := m["enabled_at"]
		if on != (at != nil) {
			t.Errorf("%s: enabled=%v enabled_at=%v", id, on, at)
		}
		if at != nil {
			if _, err := time.Parse(time.RFC3339, at.(string)); err != nil {
				t.Errorf("%s: enabled_at %v is not a date-time", id, at)
			}
		}
	}
	if mods["core"]["tier"] != "core" || mods["core"]["enabled"] != true || mods["feeds"]["tier"] != "standard" || mods["response"]["enabled"] != false {
		t.Errorf("defaults differ from the manifests: %v %v %v", mods["core"], mods["feeds"], mods["response"])
	}
}

func TestContract_Modules_RolesAndSession(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	if code, b := s.call("GET", "/modules", "", ""); code != 401 || errCode(b) != "unauthenticated" {
		t.Errorf("GET without session: %d %v", code, b)
	}
	for _, user := range []string{"viewer", "operator"} {
		if code, b := s.call("PATCH", "/modules/scan", user, `{"enabled":true}`); code != 403 || errCode(b) != "forbidden" {
			t.Errorf("%s PATCH: %d %v", user, code, b)
		}
	}
	if s.enabledInDB("scan") || s.reg.Enabled("scan") {
		t.Fatal("a refused PATCH changed state")
	}
	// CSRF: the cookie alone is not enough for a state-changing call.
	r := httptest.NewRequestWithContext(t.Context(), "PATCH", server.Prefix+"/modules/scan", strings.NewReader(`{"enabled":true}`))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: "admin", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w := httptest.NewRecorder()
	s.h.ServeHTTP(w, r)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "csrf_invalid") {
		t.Errorf("PATCH without CSRF token: %d %s", w.Code, w.Body)
	}
	for body, wantStatus := range map[string]int{`{"enabled":"yes"}`: 400, `{}`: 400, `{"enabled":true,"with_dependencies":"x"}`: 400, ``: 400} {
		if code, b := s.patch("scan", body); code != wantStatus || errCode(b) != "invalid" {
			t.Errorf("PATCH %q: %d %v", body, code, b)
		}
	}
	if code, b := s.patch("nonexistent", `{"enabled":true}`); code != 404 || errCode(b) != "not_found" {
		t.Errorf("unknown module: %d %v", code, b)
	}
	if code, b := s.patch("host", `{"enabled":false}`); code != 404 || errCode(b) != "not_found" {
		t.Errorf("host is a component, not a switch: %d %v", code, b)
	}
}

// INV-1: a core module cannot be turned off (or on) through the API.
func TestContract_INV1_CoreAlwaysOn(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	for _, body := range []string{`{"enabled":false}`, `{"enabled":true}`, `{"enabled":false,"with_dependencies":true}`} {
		code, b := s.patch("core", body)
		if code != 400 || errCode(b) != "core_module" {
			t.Fatalf("PATCH /modules/core %s = %d %v", body, code, b)
		}
	}
	if !s.reg.Enabled("core") || !s.enabledInDB("core") {
		t.Fatal("core is off")
	}
	// The route table still serves core routes.
	if code, _ := s.call("GET", "/modules", "viewer", ""); code != 200 {
		t.Fatalf("GET /modules after the attempts = %d", code)
	}
	if n := count(t, s.db, "SELECT count(*) FROM core_audit"); n != 0 {
		t.Fatalf("refused requests wrote %d audit rows", n)
	}
}

// INV-3: missing dependencies refuse with the list and change nothing; only with_dependencies enables them.
func TestContract_INV3_MissingDependencies(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	// scan-credentialed needs scan, which is off by default.
	code, b := s.patch("scan-credentialed", `{"enabled":true}`)
	if code != 409 || errCode(b) != "missing_dependencies" {
		t.Fatalf("PATCH = %d %v", code, b)
	}
	e := b["error"].(map[string]any)
	if got, _ := e["missing"].([]any); len(got) != 1 || got[0] != "scan" {
		t.Fatalf("missing = %v, want [scan]", e["missing"])
	}
	if s.enabledInDB("scan") || s.enabledInDB("scan-credentialed") || s.reg.Enabled("scan") {
		t.Fatal("a 409 changed state: dependencies must never be turned on implicitly")
	}
	_, list := s.call("GET", "/modules", "viewer", "")
	if modulesOf(t, list)["scan"]["enabled"] != false {
		t.Fatal("GET shows scan on after a refused request")
	}
	if n := count(t, s.db, "SELECT count(*) FROM core_audit"); n != 0 {
		t.Fatalf("the refusal wrote %d audit rows", n)
	}

	code, b = s.patch("scan-credentialed", `{"enabled":true,"with_dependencies":true}`)
	if code != 200 {
		t.Fatalf("with_dependencies: %d %v", code, b)
	}
	mods := modulesOf(t, b)
	if mods["scan"]["enabled"] != true || mods["scan-credentialed"]["enabled"] != true {
		t.Fatalf("not both on: %v %v", mods["scan"], mods["scan-credentialed"])
	}
	if !s.enabledInDB("scan") || !s.enabledInDB("scan-credentialed") {
		t.Fatal("database disagrees with the response")
	}
	if got := s.auditRows("action = 'module.enable'"); !slices.Equal(got, []string{"admin@acme.example|module.enable|scan-credentialed|also turned on: scan"}) {
		t.Fatalf("audit = %v", got)
	}
}

// INV-4: turning a module off keeps its data, does not cascade, and reports the modules that depend on it.
func TestContract_INV4_DisableDoesNotCascadeOrDropData(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	manifests, err := modreg.Load(modules.Manifests)
	if err != nil {
		t.Fatal(err)
	}
	var wantAffected []string
	for _, m := range manifests {
		if m.Default && slices.Contains(m.Depends, "inventory") {
			wantAffected = append(wantAffected, m.ID)
		}
	}
	if len(wantAffected) == 0 {
		t.Fatal("test premise broken: no default-on module depends on inventory")
	}
	schemaBefore := schema(t, s.db)
	_, before := s.call("GET", "/modules", "viewer", "")
	on := map[string]bool{}
	for id, m := range modulesOf(t, before) {
		on[id] = m["enabled"].(bool)
	}

	code, b := s.patch("inventory", `{"enabled":false}`)
	if code != 200 {
		t.Fatalf("disable: %d %v", code, b)
	}
	got := []string{}
	for _, a := range b["affected"].([]any) {
		got = append(got, a.(string))
	}
	slices.Sort(got)
	slices.Sort(wantAffected)
	if !slices.Equal(got, wantAffected) {
		t.Fatalf("affected = %v, want %v", got, wantAffected)
	}
	for id, m := range modulesOf(t, b) {
		want := on[id]
		if id == "inventory" {
			want = false
		}
		if m["enabled"] != want {
			t.Errorf("%s enabled = %v after disabling inventory, want %v (no cascade)", id, m["enabled"], want)
		}
	}
	if schema(t, s.db) != schemaBefore {
		t.Fatal("disabling a module changed the schema: data must be kept")
	}
	if n := count(t, s.db, "SELECT count(*) FROM core_module WHERE id = 'inventory' AND enabled = 0 AND disabled_at IS NOT NULL"); n != 1 {
		t.Fatalf("the inventory row is gone or not marked off (%d)", n)
	}
	rows := s.auditRows("action = 'module.disable'")
	if len(rows) != 1 || !strings.HasPrefix(rows[0], "admin@acme.example|module.disable|inventory|affected: ") {
		t.Fatalf("audit = %v", rows)
	}
	// Disabling again is harmless and still audited.
	if code, _ := s.patch("inventory", `{"enabled":false}`); code != 200 {
		t.Fatalf("second disable = %d", code)
	}
	if res, err := audit.Verify(t.Context(), s.db.Reader()); err != nil || !res.OK || res.Count != 2 {
		t.Fatalf("audit chain: %+v, %v", res, err)
	}
}

func schema(t *testing.T, db *store.DB) string {
	t.Helper()
	rows, err := db.Reader().QueryContext(t.Context(), "SELECT type || '|' || name || '|' || coalesce(sql, '') FROM sqlite_master ORDER BY 1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var b strings.Builder
	for rows.Next() {
		var x string
		if err := rows.Scan(&x); err != nil {
			t.Fatal(err)
		}
		b.WriteString(x + "\n")
	}
	return b.String()
}

// POST-1: enabling sets enabled_at, writes core_audit in the same step, opens the module's routes and
// starts its jobs, all within the request.
func TestContract_POST1_EnableStartsRoutesAndJobs(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	if code, b := s.call("GET", "/scans/config", "viewer", ""); code != 404 || errCode(b) != "not_found" {
		t.Fatalf("scan route while off: %d %v", code, b)
	}
	select {
	case <-s.starts:
		t.Fatal("a job of an off module ran")
	default:
	}

	code, b := s.patch("scan", `{"enabled":true}`)
	if code != 200 {
		t.Fatalf("enable: %d %v", code, b)
	}
	scan := modulesOf(t, b)["scan"]
	if scan["enabled"] != true || scan["enabled_at"] == nil {
		t.Fatalf("scan = %v", scan)
	}
	at, err := time.Parse(time.RFC3339, scan["enabled_at"].(string))
	if err != nil || time.Since(at) > time.Minute || time.Until(at) > time.Minute {
		t.Fatalf("enabled_at = %v (%v)", scan["enabled_at"], err)
	}
	if a, _ := b["affected"].([]any); a == nil || len(a) != 0 {
		t.Fatalf("affected = %v, want an empty list on enable", b["affected"])
	}
	var dbAt string
	if err := s.db.Reader().QueryRowContext(t.Context(), "SELECT enabled_at FROM core_module WHERE id = 'scan'").Scan(&dbAt); err != nil || dbAt == "" {
		t.Fatalf("core_module.enabled_at = %q, %v", dbAt, err)
	}
	if got := s.auditRows("action = 'module.enable'"); !slices.Equal(got, []string{"admin@acme.example|module.enable|scan|"}) {
		t.Fatalf("audit = %v", got)
	}
	if code, _ := s.call("GET", "/scans/config", "viewer", ""); code != 200 {
		t.Fatalf("scan route after enabling = %d", code)
	}
	s.waitFor(s.starts, "the scan job to start")
}

// POST-2: after a disable the module's route is 404 in the same process, its running job is cancelled,
// and the job does not run again.
func TestContract_POST2_DisableRemovesRoutesAndJobsInTheSameRequest(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	if code, _ := s.patch("scan", `{"enabled":true}`); code != 200 {
		t.Fatal("enable failed")
	}
	s.waitFor(s.starts, "the scan job to start")
	if code, _ := s.call("GET", "/scans/config", "viewer", ""); code != 200 {
		t.Fatal("route not open while on")
	}

	code, b := s.patch("scan", `{"enabled":false}`)
	if code != 200 {
		t.Fatalf("disable: %d %v", code, b)
	}
	// Route gone in the very next request, same process, no restart.
	code, nf := s.call("GET", "/scans/config", "viewer", "")
	if code != 404 || errCode(nf) != "not_found" {
		t.Fatalf("scan route after disable: %d %v", code, nf)
	}
	_, unknown := s.call("GET", "/scans/does-not-exist", "viewer", "")
	if nf["error"].(map[string]any)["message"] != unknown["error"].(map[string]any)["message"] {
		t.Fatal("a disabled module's 404 differs from an unknown route's")
	}
	// The job's context was cancelled by the disable, and the history says so.
	s.waitFor(s.ended, "the running job to be cancelled")
	deadline := time.After(10 * time.Second)
	for {
		runs, err := s.hist.Recent(t.Context(), "scan", "probe", 5)
		if err != nil {
			t.Fatal(err)
		}
		if len(runs) == 1 && runs[0].Status == jobs.StatusCancelled {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("job history = %+v, want one cancelled run", runs)
		case <-time.After(20 * time.Millisecond):
		}
	}
	select {
	case <-s.starts:
		t.Fatal("the job started again while its module is off")
	case <-time.After(100 * time.Millisecond):
	}
	if got := s.auditRows("action = 'module.disable'"); !slices.Equal(got, []string{"admin@acme.example|module.disable|scan|"}) {
		t.Fatalf("audit = %v", got)
	}
	// Turning it back on brings route and job back.
	if code, _ := s.patch("scan", `{"enabled":true}`); code != 200 {
		t.Fatal("re-enable failed")
	}
	if code, _ := s.call("GET", "/scans/config", "viewer", ""); code != 200 {
		t.Fatal("route did not come back")
	}
	s.waitFor(s.starts, "the job to start again")
}
