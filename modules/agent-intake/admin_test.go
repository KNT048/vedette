package agentintake_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
)

// as sends a request as user ("" = nobody) with or without the CSRF header.
func (w *world) as(user, method, path string, csrf bool) reply {
	w.t.Helper()
	if user == "admin" && csrf {
		return w.admin(method, path, nil)
	}
	r := httptest.NewRequestWithContext(w.t.Context(), method, server.Prefix+path, strings.NewReader(`{"name":"x"}`))
	r.RemoteAddr = "192.0.2.200:40000"
	r.Header.Set("Content-Type", "application/json")
	if user != "" {
		r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: user, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	if csrf {
		r.Header.Set(servertest.CSRFHeader, servertest.CSRFValue)
	}
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	out := reply{code: rec.Code, header: rec.Header(), raw: rec.Body.String()}
	return out
}

func tokenList(t *testing.T, r reply) []map[string]any {
	t.Helper()
	l, _ := r.body["tokens"].([]any)
	out := []map[string]any{}
	for _, v := range l {
		out = append(out, v.(map[string]any))
	}
	return out
}

// PRE-1: the three admin operations are for admins only (viewer and operator 403, nobody 401, no CSRF 403) and 404 while the module is off.
func TestAdmin_RoleCSRFAndModuleOff(t *testing.T) {
	w := newWorld(t)
	id, _ := w.token("srv", 7)
	for _, c := range []struct{ method, path string }{
		{"GET", "/inventory/agents"}, {"POST", "/inventory/agents/tokens"}, {"DELETE", "/inventory/agents/tokens/" + id},
	} {
		csrf := c.method != "GET"
		if r := w.as("", c.method, c.path, csrf); r.code != 401 {
			t.Errorf("%s %s anonymous: %d", c.method, c.path, r.code)
		}
		for _, u := range []string{"viewer", "operator"} {
			if r := w.as(u, c.method, c.path, csrf); r.code != 403 {
				t.Errorf("%s %s as %s: %d", c.method, c.path, u, r.code)
			}
		}
		if csrf {
			if r := w.as("admin", c.method, c.path, false); r.code != 403 {
				t.Errorf("%s %s without CSRF: %d", c.method, c.path, r.code)
			}
		}
	}
	if w.count(`SELECT count(*) FROM intake_agent_tokens`) != 1 {
		t.Fatal("a refused request changed the tokens")
	}
	w.gate.Set("agent-intake", false)
	unknown := w.as("admin", "GET", "/inventory/nothing", true)
	for _, c := range []struct{ method, path string }{
		{"GET", "/inventory/agents"}, {"POST", "/inventory/agents/tokens"}, {"DELETE", "/inventory/agents/tokens/" + id},
	} {
		if r := w.admin(c.method, c.path, map[string]any{"name": "x"}); r.code != 404 || r.raw != unknown.raw {
			t.Errorf("%s %s while off: %d %s", c.method, c.path, r.code, r.raw)
		}
	}
	if w.count(`SELECT count(*) FROM intake_agent_tokens`) != 1 {
		t.Fatal("the token went while the module was off")
	}
}

// INV-3, INV-4, INV-9: the secret is in the answer to the create and nowhere else; the audit line has the name and the last four.
func TestAdmin_CreateShowsTheSecretOnce(t *testing.T) {
	w := newWorld(t)
	r := w.admin("POST", "/inventory/agents/tokens", map[string]any{"name": "osquery on SRV-AD"})
	if r.code != 201 {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}
	secret, _ := r.body["secret"].(string)
	tok, _ := r.body["token"].(map[string]any)
	if !regexp.MustCompile(`^vdt_osquery_[a-km-np-z2-9]{32}$`).MatchString(secret) || tok["last4"] != secret[len(secret)-4:] || tok["kind"] != "osquery" || tok["name"] != "osquery on SRV-AD" {
		t.Fatalf("answer: %s", r.raw)
	}
	if tok["hosts"] != float64(0) || tok["last_received"] != nil {
		t.Fatalf("a new token has hosts or a last_received: %s", r.raw)
	}
	exp, err := time.Parse(time.RFC3339Nano, tok["expires_at"].(string))
	if err != nil || exp.Sub(w.clock.Now()) != 7*24*time.Hour {
		t.Fatalf("default expiry: %v %v", tok["expires_at"], err)
	}
	// the list and the page never carry the secret again, only the last four
	page := w.admin("GET", "/inventory/agents", nil)
	if strings.Contains(page.raw, secret) || len(tokenList(t, page)) != 1 || tokenList(t, page)[0]["last4"] != tok["last4"] {
		t.Fatalf("the page after the create: %s", page.raw)
	}
	w.assertNowhere(secret)
	if w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.agent_token_create' AND target = 'osquery on SRV-AD' AND user = 'admin@acme.example' AND detail = ?`, "last4 "+tok["last4"].(string)) != 1 {
		t.Fatal("no audit line for the create, or it has more than the name and the last four")
	}
	if strings.Contains(r.header.Get("Cache-Control"), "public") || r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("the answer that holds a secret has Cache-Control %q", r.header.Get("Cache-Control"))
	}
	// 0 = never expires
	r0 := w.admin("POST", "/inventory/agents/tokens", map[string]any{"name": "forever", "expires_in_days": 0})
	if r0.code != 201 || r0.body["token"].(map[string]any)["expires_at"] != nil {
		t.Fatalf("0 days: %d %s", r0.code, r0.raw)
	}
	r30 := w.admin("POST", "/inventory/agents/tokens", map[string]any{"name": "month", "expires_in_days": 30, "kind": "osquery"})
	if r30.code != 201 {
		t.Fatalf("30 days: %d %s", r30.code, r30.raw)
	}
}

func TestAdmin_CreateChecks(t *testing.T) {
	w := newWorld(t)
	for _, c := range []struct {
		body map[string]any
		code string
	}{
		{map[string]any{"name": ""}, "bad_name"},
		{map[string]any{"name": "   "}, "bad_name"},
		{map[string]any{"name": "<script>"}, "bad_name"},
		{map[string]any{"name": "tab\tname"}, "bad_name"},
		{map[string]any{"name": strings.Repeat("a", 65)}, ""},
		{map[string]any{"name": "x", "expires_in_days": 366}, ""},
		{map[string]any{"name": "x", "expires_in_days": -1}, ""},
		{map[string]any{"name": "x", "kind": "wazuh"}, ""},
		{map[string]any{}, ""},
	} {
		r := w.admin("POST", "/inventory/agents/tokens", c.body)
		if r.code != 400 || (c.code != "" && r.errCode() != c.code) {
			t.Errorf("%v: %d %s", c.body, r.code, r.raw)
		}
	}
	if w.count(`SELECT count(*) FROM intake_agent_tokens`) != 0 {
		t.Fatal("a refused create left a token")
	}
	for i := range 50 {
		if r := w.admin("POST", "/inventory/agents/tokens", map[string]any{"name": fmt.Sprintf("t%d", i)}); r.code != 201 {
			t.Fatalf("token %d: %d %s", i, r.code, r.raw)
		}
	}
	if r := w.admin("POST", "/inventory/agents/tokens", map[string]any{"name": "one too many"}); r.code != 409 || r.errCode() != "too_many_tokens" {
		t.Fatalf("51st token: %d %s", r.code, r.raw)
	}
}

// POST-3: revoke deletes the token and its nodes (their next call is node_invalid), keeps what they delivered, audits, and says 404 for an unknown id.
func TestAdmin_RevokeCutsTheNodesAndKeepsTheData(t *testing.T) {
	w := newWorld(t)
	id, secret := w.token("srv", 7)
	keep, _ := w.token("other", 7)
	key := w.enroll(secret, "srv-1", peerA)
	if r := w.post("/intake/osquery/log", peerA, fullLog(key)); r.code != 200 {
		t.Fatalf("log: %d %s", r.code, r.raw)
	}
	page := w.admin("GET", "/inventory/agents", nil)
	var seen map[string]any
	for _, tk := range tokenList(t, page) {
		if tk["id"] == id {
			seen = tk
		}
	}
	if seen == nil || seen["hosts"] != float64(1) || seen["last_received"] == nil {
		t.Fatalf("hosts and last_received of the token: %v", seen)
	}
	if r := w.admin("DELETE", "/inventory/agents/tokens/"+id, nil); r.code != 204 || r.raw != "" {
		t.Fatalf("revoke: %d %s", r.code, r.raw)
	}
	if r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key}); !r.invalid() {
		t.Fatalf("a node of a revoked token: %s", r.raw)
	}
	if _, ok := w.device(peerA); !ok {
		t.Fatal("the device the node delivered went with the token")
	}
	if w.count(`SELECT count(*) FROM intake_agent_tokens WHERE id = ?`, keep) != 1 {
		t.Fatal("another token went")
	}
	if w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.agent_token_revoke' AND target = 'srv' AND user = 'admin@acme.example'`) != 1 {
		t.Fatal("no audit line for the revoke")
	}
	if r := w.admin("DELETE", "/inventory/agents/tokens/"+id, nil); r.code != 404 || r.errCode() != "not_found" {
		t.Fatalf("revoke twice: %d %s", r.code, r.raw)
	}
	if r := w.admin("DELETE", "/inventory/agents/tokens/tok-nope", nil); r.code != 404 {
		t.Fatalf("unknown id: %d", r.code)
	}
	w.assertNowhere(secret)
}

// The page shows expired tokens (the GUI marks them), no secret, last_received null for a token nobody used, and the Wazuh card from the
// service (null when none).
func TestAdmin_PageShape(t *testing.T) {
	w := newWorld(t)
	page := w.admin("GET", "/inventory/agents", nil)
	if page.code != 200 || len(tokenList(t, page)) != 0 || page.body["wazuh"] != nil {
		t.Fatalf("empty page: %d %s", page.code, page.raw[:min(300, len(page.raw))])
	}
	if page.body["server_url"] != boxURL {
		t.Fatalf("server_url %v", page.body["server_url"])
	}
	_, s1 := w.token("short", 1)
	w.token("never", 0)
	w.clock.Advance(2 * 24 * time.Hour)
	page = w.admin("GET", "/inventory/agents", nil)
	got := tokenList(t, page)
	if len(got) != 2 || strings.Contains(page.raw, s1) || strings.Contains(page.raw, "token_hash") {
		t.Fatalf("tokens: %s", page.raw[:min(600, len(page.raw))])
	}
	byName := map[string]map[string]any{}
	for _, tk := range got {
		byName[tk["name"].(string)] = tk
	}
	if byName["never"]["expires_at"] != nil || byName["short"]["expires_at"] == nil || byName["short"]["last_received"] != nil || byName["short"]["hosts"] != float64(0) {
		t.Fatalf("token fields: %v", byName)
	}
}

// The Wazuh card on the page is what the service has (Service.Wazuh), with the last four characters of the password and never the password.
func TestAdmin_PageCarriesTheWazuhCardWithoutItsPassword(t *testing.T) {
	r := newWzRig(t)
	r.save()
	page := r.admin("GET", "/inventory/agents", nil)
	card, _ := page.body["wazuh"].(map[string]any)
	if page.code != 200 || card == nil || card["username"] != wzUser || card["status"] != "never" || card["interval_minutes"] != float64(60) || card["url"] != r.srv.URL || card["error"] != nil || card["last_sync"] != nil {
		t.Fatalf("card: %d %s", page.code, page.raw[:min(400, len(page.raw))])
	}
	if _, has := card["password"]; has || strings.Contains(page.raw, wzPassword) || card["password_last4"] != wzPassword[len(wzPassword)-4:] {
		t.Fatalf("the card shows more than the last four characters: %v", card)
	}
	r.pull()
	page = r.admin("GET", "/inventory/agents", nil)
	card, _ = page.body["wazuh"].(map[string]any)
	if card["status"] != "connected" || card["last_sync"] == nil {
		t.Fatalf("card after a pull: %v", card)
	}
}

// Prune: the nodes are pruned after 90 days of a job that runs, the time the module is off does not count, and a restart does not start the
// count again (the clock is a row, not memory).
func TestPrune_ClockIsPersistent(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 0)
	key := w.enroll(secret, "srv-1", peerA)
	w.pruneFor(89 * 24 * time.Hour) // the job runs unbroken for 89 days: the node is 89 days silent
	if w.count(`SELECT count(*) FROM intake_osquery_nodes`) != 1 {
		t.Fatal("pruned too early")
	}
	w.clock.Advance(2 * 24 * time.Hour) // the module is off (or the box is down) for 2 days: not silence
	w.pruneFor(12 * time.Hour)          // back on: 89.5 days of running, the node has stayed
	if w.count(`SELECT count(*) FROM intake_osquery_nodes`) != 1 {
		t.Fatal("the 2 days off counted as silence")
	}
	w.pruneFor(2 * 24 * time.Hour) // and 2 more days of running make it 91: now it goes
	if w.count(`SELECT count(*) FROM intake_osquery_nodes`) != 0 {
		t.Fatal("the node was not pruned after 90 days of running")
	}
	if r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key}); !r.invalid() {
		t.Fatalf("a pruned node is still valid: %s", r.raw)
	}
}

func TestPrune_RestartDoesNotStartTheCountAgain(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 0)
	w.enroll(secret, "srv-1", peerA)
	w.pruneFor(60 * 24 * time.Hour)
	for range 3 { // a few restarts of the process: the service is built again on the same database, a few minutes apart
		w.restart()
		w.clock.Advance(5 * time.Minute)
	}
	w.pruneFor(30 * 24 * time.Hour) // 90 days of a job that runs, restarts included
	w.restart()
	w.pruneFor(3 * 24 * time.Hour)
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes`); n != 0 {
		t.Fatalf("a silent node survived 90+ days across restarts (%d)", n)
	}
}

// A node that reports is never pruned, and a node that has not been seen since before the gap is not given more than the gap: last_seen
// moves by the gap and never past now.
func TestPrune_GapMovesLastSeenButNeverPastNow(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 0)
	key := w.enroll(secret, "srv-1", peerA)
	w.pruneFor(time.Hour) // the clock row exists now
	w.clock.Advance(30 * time.Minute)
	if r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key}); r.invalid() { // the node reports: last_seen = now
		t.Fatalf("config: %s", r.raw)
	}
	w.clock.Advance(40 * 24 * time.Hour) // the module was off for 40 days
	if err := w.svc.Prune(t.Context()); err != nil {
		t.Fatal(err)
	}
	now := w.clock.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE last_seen > ?`, now); n != 0 {
		t.Fatalf("%d node(s) have a last_seen after now: seen + gap must stop at now", n)
	}
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE last_seen = ?`, now); n != 1 {
		t.Fatal("the gap was not added to last_seen")
	}
	// the first run after the table exists (no row): nobody is pruned at once, the silence starts now
	w.exec(`DELETE FROM intake_prune_clock`)
	w.exec(`UPDATE intake_osquery_nodes SET last_seen = '2020-01-01T00:00:00.000Z'`)
	if err := w.svc.Prune(t.Context()); err != nil {
		t.Fatal(err)
	}
	if w.count(`SELECT count(*) FROM intake_osquery_nodes`) != 1 {
		t.Fatal("with no clock row the node was pruned at once")
	}
	if w.count(`SELECT count(*) FROM intake_prune_clock WHERE id = 1`) != 1 {
		t.Fatal("the clock row was not written")
	}
}
