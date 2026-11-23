package reports

import (
	"encoding/json"
	"fmt"
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
	e.saveRecipients("a@acme.example")
	def := `{"name":"Security report","options":{"period":"last_7_days","grouping":"device","include_not_added":true,"include_not_relevant":false,"sections":{"summary":true,"handled":true,"open":true,"new":true,"exposure":true,"detections":true,"coverage":true},"charts":true},"recipients":["a@acme.example"]}`
	cases := []struct{ method, path, body, min string }{
		{"GET", "/reports/definition", "", "viewer"},
		{"GET", "/reports/document", "", "viewer"},
		{"GET", "/reports/history", "", "viewer"},
		{"GET", "/reports/history/none", "", "viewer"},
		{"GET", "/reports/pdpl", "", "viewer"},
		{"POST", "/reports/send", "", "operator"},
		{"PUT", "/reports/pdpl/org", orgBody, "operator"},
		{"POST", "/reports/pdpl/generate", "", "operator"},
		{"POST", "/reports/pdpl/ai-summary", "", "operator"},
		{"PUT", "/reports/definition", def, "admin"},
	}
	rank := map[string]int{"viewer": 0, "operator": 1, "admin": 2}
	if code, _ := e.call("GET", "/reports/definition", "", ""); code != 401 {
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
	for _, p := range [][2]string{{"GET", "/reports/document"}, {"POST", "/reports/send"}, {"GET", "/reports/pdpl"}} {
		if code, _ := e.call(p[0], p[1], "admin", ""); code != 404 {
			t.Errorf("%s %s with the module off: %d", p[0], p[1], code)
		}
	}
	e.gate.Set(ModuleID, true)
	if code, _ := e.call("GET", "/reports/document", "admin", ""); code != 200 {
		t.Fatal(code)
	}
}

func list(b map[string]any, key string) []any {
	l, _ := b[key].([]any)
	return l
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// The web contract's conformance script (web/src/features/reports/conformance.test.ts), replayed against the real handlers. Every
// answer goes through the generated encoder, which refuses a body that does not fit the API schema, so each 2xx here is also a check
// of contract.ts.
func TestConformance_TheRealBackendAnswersTheWebContract(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)

	// reads the definition and its schedule key, and only an admin saves it
	code, b := e.call("GET", "/reports/definition", "viewer", "")
	if code != 200 || b["schedule_key"] != "reports.def:"+b["id"].(string) {
		t.Fatalf("definition: %d %v", code, b)
	}
	opts, _ := json.Marshal(b["options"])
	body := func(name, options, recipients string) string {
		return fmt.Sprintf(`{"name":%q,"options":%s,"recipients":%s}`, name, options, recipients)
	}
	if code, b = e.call("PUT", "/reports/definition", "operator", body("Security report", string(opts), `[]`)); code != 403 || errCode(b) != "forbidden" {
		t.Fatalf("operator saves: %d %v", code, b)
	}
	code, b = e.call("PUT", "/reports/definition", "admin", body("Security report", string(opts), `[" Boss@Example.com ","boss@example.com"]`))
	if code != 200 || fmt.Sprint(b["recipients"]) != "[boss@example.com]" {
		t.Fatalf("admin saves: %d %v", code, b)
	}

	// refuses a definition that is not valid and names the field with the contract's code, also where the schema itself refuses it
	many := make([]string, 21)
	for i := range many {
		many[i] = fmt.Sprintf("%q", fmt.Sprintf("u%d@example.com", i))
	}
	noSections := strings.NewReplacer(`"summary":true`, `"summary":false`, `"handled":true`, `"handled":false`, `"open":true`, `"open":false`, `"new":true`, `"new":false`,
		`"exposure":true`, `"exposure":false`, `"detections":true`, `"detections":false`, `"coverage":true`, `"coverage":false`).Replace(string(opts))
	for _, c := range []struct{ body, code, field string }{
		{body(" ", string(opts), `[]`), "invalid_name", "name"},
		{body(strings.Repeat("n", 81), string(opts), `[]`), "invalid_name", "name"},
		{body("R", strings.Replace(string(opts), `"last_7_days"`, `"yearly"`, 1), `[]`), "invalid_period", "options.period"},
		{body("R", strings.Replace(string(opts), `"device"`, `"site"`, 1), `[]`), "invalid_grouping", "options.grouping"},
		{body("R", string(opts), "["+strings.Join(many, ",")+"]"), "invalid_recipients", "recipients"},
		{body("R", string(opts), `["`+strings.Repeat("a", 120)+`@example.com"]`), "invalid_email", "recipients[0]"},
		{body("R", noSections, `[]`), "no_sections", "options.sections"},
		{body("R", string(opts), `["ok@example.com","not-an-email"]`), "invalid_email", "recipients[1]"},
	} {
		code, b := e.call("PUT", "/reports/definition", "admin", c.body)
		if er := obj(b["error"]); code != 400 || er["code"] != c.code || er["field"] != c.field {
			t.Errorf("%s: %d %v", c.code, code, b)
		}
	}
	if code, _ := e.call("PUT", "/reports/definition", "admin", body("R", string(opts), `[]`)[:len(body("R", string(opts), `[]`))-1]+`,"cc":[]}`); code != 400 {
		t.Fatalf("an unknown field is refused: %d", code)
	}

	// makes the document with the saved options: sections, devices not added yet, not relevant, grouping
	code, doc := e.call("GET", "/reports/document", "viewer", "")
	if code != 200 {
		t.Fatalf("document: %d %v", code, doc)
	}
	for _, k := range []string{"summary", "handled", "open", "new", "exposure", "detections", "coverage"} {
		if doc[k] == nil {
			t.Fatalf("section %s missing: %v", k, doc)
		}
	}
	var winrar map[string]any
	notRelevant, notAdded := false, false
	for _, d := range list(obj(doc["handled"]), "devices") {
		for _, it := range list(obj(d), "items") {
			h := obj(obj(it)["handled"])
			if obj(it)["product"] == "WinRAR" {
				winrar = h
			}
			notRelevant = notRelevant || h["resolution"] == "not_relevant"
		}
	}
	if winrar == nil || winrar["resolution"] != "patched" || winrar["via"] != "version_moved" || winrar["by"] != "system" || winrar["from_version"] != "6.24" || winrar["to_version"] != "7.23" {
		t.Fatalf("WinRAR = %v", winrar)
	}
	for _, g := range list(obj(doc["open"]), "groups") {
		for _, f := range list(obj(g), "items") {
			notAdded = notAdded || obj(obj(f)["device"])["added"] == false
		}
	}
	if notRelevant || !notAdded || len(list(obj(doc["summary"]), "first")) > 3 {
		t.Fatalf("defaults: not relevant %v, not added %v", notRelevant, notAdded)
	}
	narrow := strings.NewReplacer(`"grouping":"device"`, `"grouping":"cve"`, `"include_not_added":true`, `"include_not_added":false`,
		`"include_not_relevant":false`, `"include_not_relevant":true`, `"exposure":true`, `"exposure":false`, `"coverage":true`, `"coverage":false`).Replace(string(opts))
	if code, b = e.call("PUT", "/reports/definition", "admin", body("Security report", narrow, `["boss@example.com"]`)); code != 200 {
		t.Fatalf("narrow: %d %v", code, b)
	}
	_, doc = e.call("GET", "/reports/document", "viewer", "")
	if doc["exposure"] != nil || doc["coverage"] != nil || obj(doc["open"])["grouping"] != "cve" {
		t.Fatalf("narrow document: %v", doc)
	}
	for _, g := range list(obj(doc["open"]), "groups") {
		if !strings.HasPrefix(obj(g)["key"].(string), "CVE-") {
			t.Fatalf("group %v", g)
		}
	}

	// sends to the saved recipients and keeps the document exactly as sent
	if code, _ = e.call("POST", "/reports/send", "viewer", ""); code != 403 {
		t.Fatalf("viewer sends: %d", code)
	}
	code, b = e.call("POST", "/reports/send", "operator", "")
	if code != 200 || b["trigger"] != "manual" || b["status"] != "sent" || b["sent_by"] == nil {
		t.Fatalf("send: %d %v", code, b)
	}
	id := b["id"].(string)
	if code, b = e.call("GET", "/reports/history", "viewer", ""); code != 200 || obj(list(b, "items")[0])["id"] != id {
		t.Fatalf("history: %d %v", code, b)
	}
	_, kept := e.call("GET", "/reports/history/"+id, "viewer", "")
	before, _ := json.Marshal(kept["document"])
	if code, b = e.call("PUT", "/reports/definition", "admin", body("Security report", strings.Replace(narrow, `"last_7_days"`, `"last_30_days"`, 1), `["boss@example.com"]`)); code != 200 {
		t.Fatalf("save: %d %v", code, b)
	}
	_, again := e.call("GET", "/reports/history/"+id, "viewer", "")
	after, _ := json.Marshal(again["document"])
	if string(before) != string(after) || obj(obj(again["document"])["period"])["kind"] != "last_7_days" {
		t.Fatalf("the sent document changed")
	}
	if code, b = e.call("GET", "/reports/history/nope", "viewer", ""); code != 404 || errCode(b) != "not_found" {
		t.Fatalf("missing: %d %v", code, b)
	}

	// refuses to send with no recipient
	if code, _ = e.call("PUT", "/reports/definition", "admin", body("Security report", string(opts), `[]`)); code != 200 {
		t.Fatal(code)
	}
	if code, b = e.call("POST", "/reports/send", "operator", ""); code != 400 || errCode(b) != "no_recipients" {
		t.Fatalf("no recipient: %d %v", code, b)
	}
	e.saveRecipients("a@acme.example")
	e.mail.ready = false
	if code, b = e.call("POST", "/reports/send", "operator", ""); code != 409 || errCode(b) != "email_not_ready" {
		t.Fatalf("email not ready: %d %v", code, b)
	}
}

// A clean install answers every read with a valid, empty report: no finding, no target, nothing sent.
func TestConformance_CleanInstall(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.inv.devs, e.views.vs, e.exp.ts, e.det.counts, e.det.top, e.feeds.hs = nil, nil, nil, nil, nil, nil
	code, doc := e.call("GET", "/reports/document", "viewer", "")
	if code != 200 || obj(doc["summary"])["open_now"] != float64(0) || len(list(obj(doc["exposure"]), "targets")) != 0 {
		t.Fatalf("clean document: %d %v", code, doc)
	}
	if code, b := e.call("GET", "/reports/history", "viewer", ""); code != 200 || len(list(b, "items")) != 0 {
		t.Fatalf("clean history: %d %v", code, b)
	}
	e.mods["exposure"], e.mods["notify"] = false, false
	_, doc = e.call("GET", "/reports/document", "viewer", "")
	if obj(doc["exposure"])["module_on"] != false || obj(doc["detections"])["module_on"] != false {
		t.Fatalf("modules off: %v %v", doc["exposure"], doc["detections"])
	}
}

func TestHandlers_Pdpl(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	code, b := e.call("GET", "/reports/pdpl", "viewer", "")
	if code != 200 || b["org"] != nil || b["report"] != nil {
		t.Fatalf("pdpl clean: %d %v", code, b)
	}
	if code, b = e.call("POST", "/reports/pdpl/generate", "operator", ""); code != 409 || errCode(b) != "org_required" {
		t.Fatalf("generate without org: %d %v", code, b)
	}
	if code, b = e.call("PUT", "/reports/pdpl/org", "operator", strings.Replace(orgBody, `"tax_code":"0312345678"`, `"tax_code":"x"`, 1)); code != 400 || errCode(b) != "invalid_tax_code" {
		t.Fatalf("bad tax code: %d %v", code, b)
	}
	if code, b = e.call("PUT", "/reports/pdpl/org", "operator", orgBody); code != 200 || b["name"] != "Acme Ltd" {
		t.Fatalf("save org: %d %v", code, b)
	}
	if code, b = e.call("POST", "/reports/pdpl/generate", "operator", ""); code != 200 || len(list(b, "measures")) != 9 || len(list(b, "obligations")) != 7 {
		t.Fatalf("generate: %d %v", code, b)
	}
	if code, b = e.call("POST", "/reports/pdpl/ai-summary", "operator", ""); code != 200 {
		t.Fatalf("pdpl ai: %d %v", code, b)
	}
	if code, b = e.call("GET", "/reports/pdpl", "viewer", ""); code != 200 || obj(b["report"])["ai_summary"] == nil || obj(b["defaults"])["name"] != "Acme Ltd" {
		t.Fatalf("pdpl full: %d %v", code, b)
	}
	e.ai.on = false
	if code, b = e.call("POST", "/reports/pdpl/ai-summary", "operator", ""); code != 409 || errCode(b) != "ai_unavailable" {
		t.Fatalf("ai off: %d %v", code, b)
	}
}
