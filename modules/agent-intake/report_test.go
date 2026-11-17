package agentintake_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
)

// req sends a request as one of servertest's users (viewer, operator, admin), with the CSRF header, and reads the JSON answer.
func (w *world) req(user, method, path string) reply {
	w.t.Helper()
	r := httptest.NewRequestWithContext(w.t.Context(), method, server.Prefix+path, nil)
	r.RemoteAddr = "192.0.2.200:40000"
	r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: user, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	r.Header.Set(servertest.CSRFHeader, servertest.CSRFValue)
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	out := reply{code: rec.Code, header: rec.Header(), raw: rec.Body.String()}
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	}
	return out
}

// queries is the query text of each entry of a config answer.
func (w *world) queries(key string) map[string]string {
	w.t.Helper()
	r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key})
	sch, _ := r.body["schedule"].(map[string]any)
	out := map[string]string{}
	for name, q := range sch {
		out[name], _ = q.(map[string]any)["query"].(string)
	}
	return out
}

// The software queries (an ask speeds them up) and the rest (never).
var (
	softwareQueries = map[string]float64{"deb_packages": 60, "rpm_packages": 60, "programs": 60, "kernel_info": 60, "os_revision": 60}
	otherQueries    = map[string]float64{"os_version": 3600, "system_info": 3600, "interfaces": 3600, "listening_ports": 3600, "listening_ports_windows": 3600}
	hourly          = map[string]float64{
		"deb_packages": 3600, "rpm_packages": 3600, "programs": 3600, "kernel_info": 3600, "os_revision": 3600,
		"os_version": 3600, "system_info": 3600, "interfaces": 3600, "listening_ports": 3600, "listening_ports_windows": 3600,
	}
)

// S-MIT-1 (kien G12 follow-up, INV-23): "I updated it: ask the agent now". An operator's ask gives the device's osquery node the
// first-report interval for its software queries only, with the same query texts; the ask is audited once, an open ask is answered as
// it is, it closes when the software list arrives, a new ask within 10 minutes is 429, and an ask nobody answers ends after 15 minutes.
func TestContract_INV23_AskTheAgentNow(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	key := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, fullLog(key))
	w.clock.Advance(61 * time.Minute) // past the first report's hour
	wantIntervals(t, "before the ask", w.intervals(key), hourly)
	before := w.queries(key)
	d, ok := w.device(peerA)
	if !ok {
		t.Fatal("no device")
	}
	path := "/inventory/agents/devices/" + d.ID + "/report"

	if r := w.req("viewer", "GET", path); r.code != 200 || r.body["agent"] != "osquery" || r.body["asked_at"] != nil || r.body["wazuh_interval_minutes"] != nil {
		t.Fatalf("GET as viewer: %d %s", r.code, r.raw)
	}
	if r := w.req("viewer", "POST", path); r.code != 403 {
		t.Fatalf("POST as viewer: %d %s", r.code, r.raw)
	}
	if r := w.as("", "POST", path, true); r.code != 401 {
		t.Fatalf("POST anonymous: %d", r.code)
	}
	wantIntervals(t, "after refused asks", w.intervals(key), hourly)

	r := w.req("operator", "POST", path)
	if r.code != 200 || r.body["agent"] != "osquery" || r.body["asked_at"] == nil {
		t.Fatalf("ask: %d %s", r.code, r.raw)
	}
	asked := r.body["asked_at"]
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.agent_report_now' AND user = 'it@acme.example' AND target = ?`, d.ID); n != 1 {
		t.Fatalf("audit rows of the ask: %d", n)
	}
	got := w.intervals(key)
	wantIntervals(t, "asked: software", got, softwareQueries)
	wantIntervals(t, "asked: the rest", got, otherQueries)
	for name, q := range w.queries(key) {
		if q != before[name] {
			t.Errorf("the ask changed query %s: %q", name, q)
		}
	}
	if r := w.req("viewer", "GET", path); r.code != 200 || r.body["asked_at"] != asked {
		t.Fatalf("GET while open: %d %s", r.code, r.raw)
	}

	// An open ask is answered as it is: nothing new written, no second audit row.
	w.clock.Advance(time.Minute)
	if r := w.req("operator", "POST", path); r.code != 200 || r.body["asked_at"] != asked {
		t.Fatalf("ask while open: %d %s", r.code, r.raw)
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.agent_report_now'`); n != 1 {
		t.Fatalf("an open ask was audited again: %d rows", n)
	}

	// The list arrives (past the source window of the first list): the ask closes, the node is back on the hourly schedule.
	w.clock.Advance(5 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("deb_packages", debRow("openssh-server", "1:9.6p1-3ubuntu13.6"), debRow("nginx", "1.24.0-2ubuntu7"))))
	wantIntervals(t, "list taken", w.intervals(key), hourly)
	if r := w.req("viewer", "GET", path); r.code != 200 || r.body["asked_at"] != nil {
		t.Fatalf("GET after the list: %d %s", r.code, r.raw)
	}

	// A new ask within 10 minutes of the last one is refused, with its wait.
	if r := w.req("operator", "POST", path); r.code != 429 || r.errCode() != "rate_limited" || r.header.Get("Retry-After") == "" {
		t.Fatalf("ask again at once: %d %s %v", r.code, r.raw, r.header)
	}
	wantIntervals(t, "refused ask", w.intervals(key), hourly)

	// After the cooldown it is taken; nobody answers, and it ends by itself after 15 minutes.
	w.clock.Advance(4 * time.Minute)
	if r := w.req("operator", "POST", path); r.code != 200 || r.body["asked_at"] == nil {
		t.Fatalf("ask after the cooldown: %d %s", r.code, r.raw)
	}
	wantIntervals(t, "second ask", w.intervals(key), softwareQueries)
	w.clock.Advance(14 * time.Minute)
	wantIntervals(t, "second ask, 14 minutes on", w.intervals(key), softwareQueries)
	w.clock.Advance(time.Minute)
	wantIntervals(t, "second ask expired", w.intervals(key), hourly)
	if r := w.req("viewer", "GET", path); r.code != 200 || r.body["asked_at"] != nil {
		t.Fatalf("GET after the window: %d %s", r.code, r.raw)
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.agent_report_now'`); n != 2 {
		t.Fatalf("audit rows of two asks: %d", n)
	}
}

// INV-23: a device Vedette cannot ask (no osquery node of this box: a device only the Wazuh pull reads, or none) gets 409 cannot_ask
// and nothing is written; GET says which, with the Wazuh pull's interval. An unknown device is 404, and both routes are 404 while the
// module is off.
func TestContract_INV23_WazuhAndNoAgentCannotBeAsked(t *testing.T) {
	r := newWzRig(t)
	r.save()
	r.pull()
	d, ok := r.device(ipLinux)
	if !ok {
		t.Fatal("no Wazuh device")
	}
	path := "/inventory/agents/devices/" + d.ID + "/report"
	if g := r.req("viewer", "GET", path); g.code != 200 || g.body["agent"] != "wazuh" || g.body["wazuh_interval_minutes"] != float64(60) || g.body["asked_at"] != nil {
		t.Fatalf("GET of a Wazuh device: %d %s", g.code, g.raw)
	}
	if p := r.req("operator", "POST", path); p.code != 409 || p.errCode() != "cannot_ask" {
		t.Fatalf("ask a Wazuh device: %d %s", p.code, p.raw)
	}
	if n := r.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.agent_report_now'`); n != 0 {
		t.Fatalf("a refused ask was audited: %d", n)
	}

	r.admin("DELETE", "/inventory/agents/wazuh", nil) // no agent of this box reads it any more
	if g := r.req("viewer", "GET", path); g.code != 200 || g.body["agent"] != "none" || g.body["wazuh_interval_minutes"] != nil {
		t.Fatalf("GET after Wazuh was disconnected: %d %s", g.code, g.raw)
	}
	if p := r.req("operator", "POST", path); p.code != 409 || p.errCode() != "cannot_ask" {
		t.Fatalf("ask a device without an agent: %d %s", p.code, p.raw)
	}
	if g := r.req("viewer", "GET", "/inventory/agents/devices/a-nothing/report"); g.code != 404 || g.errCode() != "not_found" {
		t.Fatalf("GET of an unknown device: %d %s", g.code, g.raw)
	}
	if p := r.req("operator", "POST", "/inventory/agents/devices/a-nothing/report"); p.code != 404 {
		t.Fatalf("ask an unknown device: %d %s", p.code, p.raw)
	}
	r.gate.Set("agent-intake", false)
	if g := r.req("viewer", "GET", path); g.code != 404 {
		t.Fatalf("GET while the module is off: %d", g.code)
	}
	if p := r.req("operator", "POST", path); p.code != 404 {
		t.Fatalf("POST while the module is off: %d", p.code)
	}
}
