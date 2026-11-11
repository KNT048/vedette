package reports

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
)

type reportsOnly struct {
	server.Fallback
	*ReportsHandlers
}

type httpEnv struct {
	*env
	h    http.Handler
	gate *servertest.Gate
}

func newHTTPEnv(t *testing.T) *httpEnv {
	t.Helper()
	e := newEnv(t)
	e.seed()
	gate := servertest.NewGate()
	h, err := server.New(server.Config{
		API:     reportsOnly{Fallback: server.Fallback{Log: slog.New(slog.DiscardHandler)}, ReportsHandlers: NewReportsHandlers(e.svc)},
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

func errCode(b map[string]any) string {
	m, _ := b["error"].(map[string]any)
	c, _ := m["code"].(string)
	return c
}

const orgBody = `{"name":"Acme Ltd","tax_code":"0312345678","address":"1 Main Street, Hanoi","sector":"Retail","employees":12,"data_volume":"lt1k","size":"micro","processing_service":false,"contact_name":"An Nguyen","contact_email":"an@acme.example","contact_phone":"0901234567","sensitive":false,"cross_border":false,"processors":false,"level":""}`

// PRE-1 and the table of endpoints in CONTRACT: who may do what, enforced by the server pipeline before any handler runs.
func TestContract_Roles(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.saveSchedule(false, "a@acme.example")
	cases := []struct{ method, path, body, min string }{
		{"GET", "/reports/weekly/preview", "", "viewer"},
		{"GET", "/reports/schedule", "", "viewer"},
		{"GET", "/reports/weekly/history", "", "viewer"},
		{"GET", "/reports/weekly/history/none", "", "viewer"},
		{"GET", "/reports/pdpl", "", "viewer"},
		{"POST", "/reports/weekly/ai-summary", "", "operator"},
		{"POST", "/reports/weekly/send", "", "operator"},
		{"PUT", "/reports/pdpl/org", orgBody, "operator"},
		{"POST", "/reports/pdpl/generate", "", "operator"},
		{"POST", "/reports/pdpl/ai-summary", "", "operator"},
		{"PUT", "/reports/schedule", `{"enabled":false,"day":1,"hour":8,"recipients":[]}`, "admin"},
	}
	rank := map[string]int{"viewer": 0, "operator": 1, "admin": 2}
	if code, _ := e.call("GET", "/reports/schedule", "", ""); code != 401 {
		t.Fatalf("no session: %d", code)
	}
	for _, c := range cases {
		for _, role := range []string{"viewer", "operator", "admin"} {
			code, b := e.call(c.method, c.path, role, c.body)
			if rank[role] < rank[c.min] {
				if code != 403 {
					t.Errorf("%s %s as %s: %d, want 403", c.method, c.path, role, code)
				}
			} else if code == 403 || code == 401 || code >= 500 {
				t.Errorf("%s %s as %s: %d %v", c.method, c.path, role, code, b)
			}
		}
	}
}

func TestHandlers_ModuleOffIs404(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.gate.Set(ModuleID, false)
	for _, p := range [][2]string{{"GET", "/reports/weekly/preview"}, {"POST", "/reports/weekly/send"}, {"GET", "/reports/pdpl"}} {
		if code, _ := e.call(p[0], p[1], "admin", ""); code != 404 {
			t.Errorf("%s %s with the module off: %d", p[0], p[1], code)
		}
	}
	e.gate.Set(ModuleID, true)
	if code, _ := e.call("GET", "/reports/weekly/preview", "admin", ""); code != 200 {
		t.Fatal(code)
	}
}

// The generated decoder checks every response against the OpenAPI schema; these calls prove each body fits it.
func TestHandlers_ResponsesFitTheSchema(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	code, b := e.call("GET", "/reports/weekly/preview", "viewer", "")
	rep, _ := b["report"].(map[string]any)
	if code != 200 || rep == nil || b["ai_available"] != true {
		t.Fatalf("preview: %d %v", code, b)
	}
	if c, _ := rep["counts"].(map[string]any); c["new_findings"] != float64(1) {
		t.Fatalf("counts = %v", c)
	}
	if code, b = e.call("GET", "/reports/schedule", "viewer", ""); code != 200 || b["next_run"] != nil {
		t.Fatalf("schedule: %d %v", code, b)
	}
	if code, b = e.call("PUT", "/reports/schedule", "admin", `{"enabled":true,"day":1,"hour":8,"recipients":["A@acme.example"]}`); code != 200 || b["next_run"] == nil {
		t.Fatalf("save schedule: %d %v", code, b)
	}
	if code, b = e.call("POST", "/reports/weekly/send", "operator", ""); code != 200 || b["status"] != "sent" || b["trigger"] != "manual" {
		t.Fatalf("send: %d %v", code, b)
	}
	id, _ := b["id"].(string)
	if code, b = e.call("GET", "/reports/weekly/history", "viewer", ""); code != 200 || len(b["items"].([]any)) != 1 {
		t.Fatalf("history: %d %v", code, b)
	}
	if code, b = e.call("GET", "/reports/weekly/history/"+id, "viewer", ""); code != 200 || b["report"] == nil {
		t.Fatalf("history entry: %d %v", code, b)
	}
	if code, b = e.call("GET", "/reports/weekly/history/missing", "viewer", ""); code != 404 || errCode(b) != "not_found" {
		t.Fatalf("missing entry: %d %v", code, b)
	}
	if code, b = e.call("POST", "/reports/weekly/ai-summary", "operator", ""); code != 200 || b["model"] != "m" || b["profile"] != "p" {
		t.Fatalf("weekly ai: %d %v", code, b)
	}
	if code, b = e.call("GET", "/reports/pdpl", "viewer", ""); code != 200 || b["org"] != nil || b["report"] != nil {
		t.Fatalf("pdpl clean: %d %v", code, b)
	}
	if code, b = e.call("POST", "/reports/pdpl/generate", "operator", ""); code != 409 || errCode(b) != "org_required" {
		t.Fatalf("generate without org: %d %v", code, b)
	}
	if code, b = e.call("PUT", "/reports/pdpl/org", "operator", orgBody); code != 200 || b["name"] != "Acme Ltd" {
		t.Fatalf("save org: %d %v", code, b)
	}
	if code, b = e.call("POST", "/reports/pdpl/generate", "operator", ""); code != 200 || len(b["measures"].([]any)) != 9 || len(b["obligations"].([]any)) != 7 {
		t.Fatalf("generate: %d %v", code, b)
	}
	if code, b = e.call("POST", "/reports/pdpl/ai-summary", "operator", ""); code != 200 {
		t.Fatalf("pdpl ai: %d %v", code, b)
	}
	if code, b = e.call("GET", "/reports/pdpl", "viewer", ""); code != 200 || b["report"].(map[string]any)["ai_summary"] == nil || b["defaults"].(map[string]any)["name"] != "Acme Ltd" {
		t.Fatalf("pdpl full: %d %v", code, b)
	}
}

func TestHandlers_Errors(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	if code, b := e.call("POST", "/reports/weekly/send", "operator", ""); code != 400 || errCode(b) != "no_recipients" {
		t.Fatalf("send without recipients: %d %v", code, b)
	}
	e.saveSchedule(false, "a@acme.example")
	e.mail.ready = false
	if code, b := e.call("POST", "/reports/weekly/send", "operator", ""); code != 409 || errCode(b) != "email_not_ready" {
		t.Fatalf("send with email not ready: %d %v", code, b)
	}
	if code, b := e.call("PUT", "/reports/schedule", "admin", `{"enabled":true,"day":1,"hour":8,"recipients":[]}`); code != 400 || errCode(b) != "no_recipients" {
		t.Fatalf("on without recipients: %d %v", code, b)
	}
	if code, b := e.call("PUT", "/reports/schedule", "admin", `{"enabled":false,"day":1,"hour":8,"recipients":["bad"]}`); code != 400 || errCode(b) != "invalid_email" {
		t.Fatalf("bad email: %d %v", code, b)
	}
	e.ai.on = false
	if code, b := e.call("POST", "/reports/weekly/ai-summary", "operator", ""); code != 409 || errCode(b) != "ai_unavailable" {
		t.Fatalf("ai off: %d %v", code, b)
	}
	if code, b := e.call("PUT", "/reports/pdpl/org", "operator", strings.Replace(orgBody, `"tax_code":"0312345678"`, `"tax_code":"x"`, 1)); code != 400 || errCode(b) != "invalid_tax_code" {
		t.Fatalf("bad tax code: %d %v", code, b)
	}
	// Unknown fields are not silently dropped.
	if code, _ := e.call("PUT", "/reports/schedule", "admin", `{"enabled":false,"day":1,"hour":8,"recipients":[],"cc":["x@y.example"]}`); code != 400 {
		t.Fatalf("unknown field: %d", code)
	}
}
