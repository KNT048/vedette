package logs

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
)

type logsOnly struct {
	server.Fallback
	*LogsHandlers
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
		API:     logsOnly{Fallback: server.Fallback{Log: slog.New(slog.DiscardHandler)}, LogsHandlers: NewLogsHandlers(e.svc)},
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

const goodSource = `{"kind":"fortigate","name":"FW-HQ","sender_ip":"192.168.10.1","proto":"udp","port":514}`

// Roles come from the route table, the module gate answers 404 when the module is off, and every mutation is an admin's.
func TestContract_PRE1_RolesAndTheModuleGate(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.gate.Set("logs", true)
	for _, tc := range []struct {
		method, path, user, body string
		want                     int
	}{
		{"GET", "/logs/sources", "viewer", "", 200},
		{"GET", "/logs/sources", "", "", 401},
		{"GET", "/logs/events?window=24h", "viewer", "", 200},
		{"GET", "/logs/digest", "viewer", "", 200},
		{"POST", "/logs/sources", "viewer", goodSource, 403},
		{"POST", "/logs/sources", "operator", goodSource, 403},
		{"PUT", "/logs/retention", "operator", `{"days":7}`, 403},
		{"DELETE", "/logs/sources/ls-1", "operator", "", 403},
		{"POST", "/logs/sources", "admin", goodSource, 201},
	} {
		if code, b := e.call(tc.method, tc.path, tc.user, tc.body); code != tc.want {
			t.Errorf("%s %s as %q = %d %v, want %d", tc.method, tc.path, tc.user, code, b, tc.want)
		}
	}
	e.gate.Set("logs", false)
	if code, _ := e.call("GET", "/logs/sources", "admin", ""); code != 404 {
		t.Errorf("module off: %d, want 404", code)
	}
	if count(t, e.cfg, `SELECT count(*) FROM logs_sources`) != 1 {
		t.Error("the data is kept while the module is off")
	}
}

func TestSourcesOverHTTPCarryTheMocksShapeAndCodes(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.gate.Set("logs", true)
	code, b := e.call("POST", "/logs/sources", "admin", goodSource)
	if code != 201 || b["state"] != "never" || b["last_received"] != nil || b["asset_id"] != "a-fw" || b["kind"] != "fortigate" {
		t.Fatalf("%d %v", code, b)
	}
	id, _ := b["id"].(string)
	if code, b := e.call("POST", "/logs/sources", "admin", goodSource); code != 409 || errCode(b) != "duplicate" {
		t.Fatalf("duplicate: %d %v", code, b)
	}
	// limits that contract.ts states are refused by the generated validator first (D-73)
	if code, b := e.call("POST", "/logs/sources", "admin", `{"kind":"fortigate","name":"bad name","sender_ip":"192.168.10.2","proto":"udp","port":514}`); code != 400 || errCode(b) != "invalid" {
		t.Fatalf("name pattern: %d %v", code, b)
	}
	if code, b := e.call("POST", "/logs/sources", "admin", `{"kind":"nope","name":"x","sender_ip":"192.168.10.2","proto":"udp","port":514}`); code != 400 || errCode(b) != "invalid" {
		t.Fatalf("kind enum: %d %v", code, b)
	}
	// what the schema cannot say keeps the mock's code
	if code, b := e.call("POST", "/logs/sources", "admin", `{"kind":"sophos","name":"SF","sender_ip":"192.168.10.3","proto":"tcp","port":514}`); code != 400 || errCode(b) != "bad_proto" {
		t.Fatalf("protocol a kind cannot send: %d %v", code, b)
	}
	if code, b := e.call("PUT", "/logs/sources/"+id, "admin", `{"kind":"fortigate","name":"FW-HQ","sender_ip":"192.168.10.1","proto":"tcp","port":6514}`); code != 200 || b["proto"] != "tcp" {
		t.Fatalf("edit: %d %v", code, b)
	}
	if code, b := e.call("PUT", "/logs/sources/ls-nope", "admin", goodSource); code != 404 || errCode(b) != "not_found" {
		t.Fatalf("edit missing: %d %v", code, b)
	}
	code, b = e.call("GET", "/logs/sources", "viewer", "")
	box, _ := b["box"].(map[string]any)
	if code != 200 || b["retention_days"] != float64(30) || box["hostname"] == nil || len(b["sources"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, b)
	}
	if code, _ := e.call("DELETE", "/logs/sources/"+id, "admin", ""); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, b := e.call("DELETE", "/logs/sources/"+id, "admin", ""); code != 404 || errCode(b) != "not_found" {
		t.Fatalf("delete again: %d %v", code, b)
	}
}

func TestEventsRetentionAndDigestOverHTTP(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.gate.Set("logs", true)
	s := e.add("FW", "192.168.10.1")
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, e.clock.Add(-time.Minute), "hello srcip=10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	code, b := e.call("GET", "/logs/events?window=24h&q=SRCIP", "viewer", "")
	evs, _ := b["events"].([]any)
	if code != 200 || b["total"] != float64(1) || len(evs) != 1 || evs[0].(map[string]any)["source_name"] != "FW" {
		t.Fatalf("%d %v", code, b)
	}
	if code, b := e.call("GET", "/logs/events?window=2h", "viewer", ""); code != 400 || errCode(b) != "invalid" {
		t.Fatalf("window enum: %d %v", code, b)
	}
	if code, b := e.call("GET", "/logs/events?window=24h&q="+strings.Repeat("a", 201), "viewer", ""); code != 400 || errCode(b) != "invalid" {
		t.Fatalf("q of 201 characters: %d %v", code, b)
	}
	if code, b := e.call("PUT", "/logs/retention", "admin", `{"days":90}`); code != 200 || b["retention_days"] != float64(90) {
		t.Fatalf("retention: %d %v", code, b)
	}
	if code, b := e.call("PUT", "/logs/retention", "admin", `{"days":14}`); code != 400 || errCode(b) != "invalid" {
		t.Fatalf("retention enum: %d %v", code, b)
	}
	code, b = e.call("GET", "/logs/digest", "viewer", "")
	if code != 200 || b["lines_24h"] != float64(1) || b["baseline_days"] != float64(7) || len(b["new"].([]any)) != 0 {
		t.Fatalf("digest: %d %v", code, b)
	}
}
