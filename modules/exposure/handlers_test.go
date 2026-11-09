package exposure

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

type exposureOnly struct {
	server.Fallback
	*ExposureHandlers
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
		API:     exposureOnly{Fallback: server.Fallback{Log: slog.New(slog.DiscardHandler)}, ExposureHandlers: NewExposureHandlers(e.svc)},
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

func list(b map[string]any, key string) []any {
	l, _ := b[key].([]any)
	return l
}

// PRE-4: who may do what, enforced by the server pipeline before any handler runs.
func TestContract_PRE4_Roles(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	d := e.addVerifiedDomain()
	cases := []struct {
		method, path, body string
		min                string // the lowest role that gets through
	}{
		{"GET", "/exposure/targets", "", "viewer"},
		{"GET", "/exposure/targets/" + d.ID, "", "viewer"},
		{"GET", "/exposure/targets/" + d.ID + "/snapshots", "", "viewer"},
		{"POST", "/exposure/targets/" + d.ID + "/verify", "", "operator"},
		{"POST", "/exposure/targets/" + d.ID + "/scan", "", "operator"},
		{"POST", "/exposure/targets", `{"value":"new.example"}`, "admin"},
		{"POST", "/exposure/box-ip/verify", "", "admin"},
		{"PUT", "/exposure/box-ip/settings", `{"auto":true,"interval_min":60}`, "admin"},
		{"POST", "/exposure/targets/" + d.ID + "/commitment", `{"confirm":true}`, "admin"},
		{"DELETE", "/exposure/box-ip/ignored/" + ipC, "", "admin"},
		{"DELETE", "/exposure/targets/" + d.ID, "", "admin"},
	}
	rank := map[string]int{"viewer": 0, "operator": 1, "admin": 2}
	if code, _ := e.call("GET", "/exposure/targets", "", ""); code != 401 {
		t.Fatalf("no session: %d", code)
	}
	for _, c := range cases {
		for _, role := range []string{"viewer", "operator", "admin"} {
			code, b := e.call(c.method, c.path, role, c.body)
			if rank[role] < rank[c.min] {
				if code != 403 {
					t.Errorf("%s %s as %s: %d, want 403", c.method, c.path, role, code)
				}
			} else if code == 403 || code == 401 {
				t.Errorf("%s %s as %s: %d %v", c.method, c.path, role, code, b)
			}
		}
	}
}

func TestHandlers_ModuleOffIs404(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.gate.Set(ModuleID, false)
	for _, p := range [][2]string{{"GET", "/exposure/targets"}, {"POST", "/exposure/box-ip/verify"}, {"PUT", "/exposure/box-ip/settings"}} {
		if code, _ := e.call(p[0], p[1], "admin", `{"auto":true,"interval_min":60}`); code != 404 {
			t.Errorf("%s %s with the module off: %d", p[0], p[1], code)
		}
	}
	e.gate.Set(ModuleID, true)
	if code, _ := e.call("GET", "/exposure/targets", "admin", ""); code != 200 {
		t.Fatal(code)
	}
}

func TestHandlers_FlowAndShapes(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)

	code, b := e.call("GET", "/exposure/targets", "viewer", "")
	if code != 200 || len(list(b, "items")) != 0 {
		t.Fatalf("empty list: %d %v", code, b)
	}
	box, _ := b["box_ip"].(map[string]any)
	if box["auto"] != true || box["interval_min"] != float64(60) || box["last_run"] != nil {
		t.Fatalf("box_ip = %v", box)
	}

	code, b = e.call("POST", "/exposure/targets", "admin", `{"value":"Acme.Example"}`)
	if code != 201 || b["value"] != "acme.example" || b["status"] != "unverified" || b["blocked_reason"] != "unverified" || b["scannable"] != false || b["expires_at"] != nil || b["latest"] != nil {
		t.Fatalf("add: %d %v", code, b)
	}
	id, _ := b["id"].(string)
	token, _ := b["token"].(string)
	if len(token) != 16 || !strings.HasPrefix(id, "xt-") {
		t.Fatalf("id %q token %q", id, token)
	}
	if code, b = e.call("POST", "/exposure/targets", "admin", `{"value":"8.8.8.8"}`); code != 400 || errCode(b) != "ip_not_allowed" {
		t.Fatalf("typed IP: %d %v", code, b)
	}
	if code, b = e.call("POST", "/exposure/targets", "admin", `{"value":"acme.example"}`); code != 409 || errCode(b) != "duplicate" {
		t.Fatalf("duplicate: %d %v", code, b)
	}

	// verify: not found first (a normal answer), then found
	code, b = e.call("POST", "/exposure/targets/"+id+"/verify", "operator", "")
	if code != 200 || b["verified"] != false {
		t.Fatalf("verify not found: %d %v", code, b)
	}
	e.dns.put("acme.example", "vedette-verify="+token)
	if code, b = e.call("POST", "/exposure/targets/"+id+"/verify", "operator", ""); code != 200 || b["verified"] != true {
		t.Fatalf("verify: %d %v", code, b)
	}
	// the scan gate, in the API
	if code, b = e.call("POST", "/exposure/targets/"+id+"/scan", "operator", ""); code != 400 || errCode(b) != "commitment_required" {
		t.Fatalf("scan without commitment: %d %v", code, b)
	}
	if code, b = e.call("POST", "/exposure/targets/"+id+"/commitment", "admin", `{"confirm":false}`); code != 400 {
		t.Fatalf("commitment false: %d %v", code, b)
	}
	if code, b = e.call("POST", "/exposure/targets/"+id+"/commitment", "admin", `{"confirm":true}`); code != 200 {
		t.Fatalf("commitment: %d %v", code, b)
	}
	c, _ := b["commitment"].(map[string]any)
	if c["by"] != "admin@acme.example" || b["scannable"] != true || b["blocked_reason"] != nil {
		t.Fatalf("committed target: %v", b)
	}
	code, b = e.call("POST", "/exposure/targets/"+id+"/scan", "operator", "")
	if code != 200 || len(list(b, "hosts")) != 3 || len(list(b, "certs")) != 2 || b["date"] != "2026-11-09" {
		t.Fatalf("scan: %d %v", code, b)
	}
	counts, _ := b["counts"].(map[string]any)
	if counts["subdomains"] != float64(3) || counts["certs_expiring"] != float64(1) {
		t.Fatalf("counts = %v", counts)
	}
	// the record disappears: 409 txt_missing from the API, the runner is not called again
	e.dns.put("acme.example")
	if code, b = e.call("POST", "/exposure/targets/"+id+"/scan", "operator", ""); code != 409 || errCode(b) != "txt_missing" || run.calls != 1 {
		t.Fatalf("scan without the record: %d %v (runner calls %d)", code, b, run.calls)
	}
	e.dns.put("acme.example", "vedette-verify="+token)

	// results
	e.advance(day)
	if code, _ = e.call("POST", "/exposure/targets/"+id+"/scan", "operator", ""); code != 200 {
		t.Fatal(code)
	}
	code, b = e.call("GET", "/exposure/targets/"+id+"/snapshots", "viewer", "")
	if code != 200 || len(list(b, "items")) != 2 {
		t.Fatalf("snapshots: %d %v", code, b)
	}
	if code, b = e.call("GET", "/exposure/targets/"+id+"/snapshots/2026-11-09", "viewer", ""); code != 200 || b["date"] != "2026-11-09" {
		t.Fatalf("snapshot: %d %v", code, b)
	}
	if code, b = e.call("GET", "/exposure/targets/"+id+"/snapshots/2026-01-01", "viewer", ""); code != 404 || errCode(b) != "not_found" {
		t.Fatalf("missing snapshot: %d %v", code, b)
	}
	if code, b = e.call("GET", "/exposure/targets/"+id+"/diff?from=2026-11-09&to=2026-11-10", "viewer", ""); code != 200 || b["from"] != "2026-11-09" || len(list(b, "added")) != 0 {
		t.Fatalf("diff: %d %v", code, b)
	}
	if code, b = e.call("GET", "/exposure/targets/"+id+"/diff?from=2026-11-09&to=2026-11-09", "viewer", ""); code != 400 || errCode(b) != "same_date" {
		t.Fatalf("same date: %d %v", code, b)
	}

	// delete is also how an IP leaves the list
	if code, _ = e.call("DELETE", "/exposure/targets/"+id, "admin", ""); code != 204 {
		t.Fatal(code)
	}
	if code, b = e.call("GET", "/exposure/targets/"+id, "viewer", ""); code != 404 || errCode(b) != "not_found" {
		t.Fatalf("after delete: %d %v", code, b)
	}
	if code, b = e.call("DELETE", "/exposure/targets/"+id, "admin", ""); code != 404 {
		t.Fatalf("second delete: %d %v", code, b)
	}
}

// The scan module is not there yet: the gate decides first, then the answer is 501 (INV-12).
func TestHandlers_ScanWithoutRunnerIs501(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	d := e.committedDomain()
	if code, b := e.call("POST", "/exposure/targets/"+d.ID+"/scan", "operator", ""); code != 501 || errCode(b) != "not_implemented" {
		t.Fatalf("%d %v", code, b)
	}
}

func TestHandlers_DetectNowAndSettings(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.prober.set(ipA, ipB, ipA)
	code, b := e.call("POST", "/exposure/box-ip/verify", "admin", "")
	items := list(b, "items")
	if code != 200 || len(items) != 2 || !strings.HasPrefix(b["message"].(string), "The box reaches the Internet via 2 public IPs: "+ipA+", "+ipB+". Each is verified until") {
		t.Fatalf("detect now: %d %v", code, b)
	}
	first, _ := items[0].(map[string]any)
	if first["kind"] != "ip" || first["status"] != "verified" || first["validity"] != "valid" || first["method"] != "box_egress" || first["blocked_reason"] != "no_commitment" || first["token"] != "" {
		t.Fatalf("item = %v", first)
	}
	// the same call again renews: still 200, same targets
	if code, b = e.call("POST", "/exposure/box-ip/verify", "admin", ""); code != 200 || len(list(b, "items")) != 2 {
		t.Fatalf("detect again: %d %v", code, b)
	}
	if _, b = e.call("GET", "/exposure/targets", "viewer", ""); len(list(b, "items")) != 2 {
		t.Fatalf("list: %v", b)
	}
	// errors of a detection
	e.prober.set("10.0.0.1")
	if code, b = e.call("POST", "/exposure/box-ip/verify", "admin", ""); code != 400 || errCode(b) != "not_public" {
		t.Fatalf("private: %d %v", code, b)
	}
	e.prober.offline()
	if code, b = e.call("POST", "/exposure/box-ip/verify", "admin", ""); code != 502 || errCode(b) != "unreachable" {
		t.Fatalf("down: %d %v", code, b)
	}
	e.prober.set("~")
	if code, b = e.call("POST", "/exposure/box-ip/verify", "admin", ""); code != 502 || errCode(b) != "unreachable" || !strings.Contains(b["error"].(map[string]any)["message"].(string), "did not agree") {
		t.Fatalf("disagree: %d %v", code, b)
	}
	_, b = e.call("GET", "/exposure/targets", "viewer", "")
	if run, _ := b["box_ip"].(map[string]any)["last_run"].(map[string]any); run["ok"] != false {
		t.Fatalf("last_run = %v", run)
	}

	// settings: 1 minute to 24 hours, anything else is 400 bad_interval, and a refusal changes nothing
	for _, n := range []string{"0", "-5", "1441", "100000"} {
		if code, b = e.call("PUT", "/exposure/box-ip/settings", "admin", `{"auto":true,"interval_min":`+n+`}`); code != 400 || errCode(b) != "bad_interval" {
			t.Errorf("interval %s: %d %v", n, code, b)
		}
	}
	if code, b = e.call("PUT", "/exposure/box-ip/settings", "admin", `{"auto":true}`); code != 400 {
		t.Fatalf("missing interval: %d %v", code, b)
	}
	for _, n := range []int{1, 5, 1440} {
		code, b = e.call("PUT", "/exposure/box-ip/settings", "admin", `{"auto":false,"interval_min":`+itoa(n)+`}`)
		if code != 200 || b["auto"] != false || b["interval_min"] != float64(n) {
			t.Fatalf("interval %d: %d %v", n, code, b)
		}
	}
	// the list is kept when auto-detect is off
	if _, b = e.call("GET", "/exposure/targets", "viewer", ""); len(list(b, "items")) != 2 || b["box_ip"].(map[string]any)["auto"] != false {
		t.Fatalf("after switching off: %v", b)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// INV-5 through the API: "Detect now" and "check again" are the attempts of a person.
func TestHandlers_AttemptLimitIs429(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	for i := range MaxAttemptsPerHour {
		if code, b := e.call("POST", "/exposure/box-ip/verify", "admin", ""); code != 200 {
			t.Fatalf("attempt %d: %d %v", i+1, code, b)
		}
	}
	code, b := e.call("POST", "/exposure/box-ip/verify", "admin", "")
	if code != 429 || errCode(b) != "rate_limited" {
		t.Fatalf("11th: %d %v", code, b)
	}
	// the automatic check is not an attempt of a person: it still runs when it is due
	e.advance(61 * time.Minute)
	e.prober.set(ipC)
	if err := e.svc.RunAutoDetect(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := e.ipValues(); len(got) != 2 || got[1] != ipC {
		t.Fatalf("IPs after the automatic check = %v", got)
	}
}
