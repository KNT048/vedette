package agentintake_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
)

// The Wazuh pull (WP-26 slice 4). A fake Wazuh server API on loopback answers with the shapes of the official OpenAPI spec v4.9.2
// (api/api/spec/spec.yaml); conntest gives it a name the address policy lets through and a self-signed certificate.

const (
	wzUser     = "vedette"
	wzPassword = "Rd0nly-Pass-2026!"
	wzJWT      = "eyJhbGciOiJFUzUxMiJ9.eyJzdWIiOiJ2ZWRldHRlIn0.c2lnbmF0dXJl"
	ipLinux    = "192.0.2.21"
	ipWindows  = "192.0.2.22"
	macLinux   = "52:54:00:11:22:01"
)

type fakeWazuh struct {
	mu        sync.Mutex
	agents    []map[string]any
	netaddr   map[string][]map[string]any
	netiface  map[string][]map[string]any
	packages  map[string][]map[string]any
	forbid    bool // the role lacks syscollector:read
	tooMany   int  // answer this many 429 before the next GET
	expire    bool // answer 401 to the next GET (the token expired)
	logins    int
	onPackage func(ctx context.Context)
}

func newFakeWazuh() *fakeWazuh {
	return &fakeWazuh{
		agents: []map[string]any{
			{"id": "000", "name": "wazuh-manager", "ip": "127.0.0.1", "status": "active", "lastKeepAlive": "9999-12-31T23:59:59Z", "os": map[string]any{"name": "Ubuntu", "version": "22.04.4 LTS", "platform": "ubuntu"}},
			{"id": "001", "name": "web01", "ip": ipLinux, "status": "active", "lastKeepAlive": "2026-11-11T07:59:00Z", "os": map[string]any{"name": "Ubuntu", "version": "24.04.1 LTS", "platform": "ubuntu"}},
			{"id": "002", "name": "WIN-FS01", "ip": ipWindows, "status": "disconnected", "lastKeepAlive": "2026-11-09T10:00:00Z", "os": map[string]any{"name": "Microsoft Windows Server 2022 Standard", "version": "10.0.20348.2700", "platform": "windows", "arch": "x86_64"}},
			{"id": "003", "name": "natted", "ip": "203.0.113.9", "status": "active", "lastKeepAlive": "2026-11-11T07:59:00Z", "os": map[string]any{"name": "Rocky Linux", "version": "9.4", "platform": "rocky"}},
		},
		netaddr: map[string][]map[string]any{
			"000": {{"iface": "eth0", "address": "192.0.2.5", "proto": "ipv4"}},
			"001": {{"iface": "lo", "address": "127.0.0.1", "proto": "ipv4"}, {"iface": "eth0", "address": "fe80::1", "proto": "ipv6"}, {"iface": "eth0", "address": ipLinux, "proto": "ipv4"}},
			"002": {{"iface": "Ethernet0", "address": ipWindows, "proto": "ipv4"}},
			"003": {{"iface": "ens3", "address": "10.0.0.9", "proto": "ipv4"}},
		},
		netiface: map[string][]map[string]any{
			"001": {{"name": "eth0", "mac": macLinux}, {"name": "lo", "mac": "00:00:00:00:00:00"}},
			"002": {{"name": "Ethernet0", "mac": "52:54:00:11:22:02"}},
			"003": {{"name": "ens3", "mac": "52:54:00:11:22:03"}},
		},
		packages: map[string][]map[string]any{
			"001": {
				{"name": "openssh-server", "version": "1:9.6p1-3ubuntu13.5", "vendor": "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>", "format": "deb", "source": "openssh", "architecture": "amd64"},
				{"name": "htop", "version": "3.3.0-4build1", "vendor": "Ubuntu Developers", "format": "deb", "architecture": "amd64"},
				{"name": "core20", "version": "20240416", "vendor": "Canonical", "format": "snap"},
			},
			"002": {{"name": "7-Zip 23.01 (x64)", "version": "23.01", "vendor": "Igor Pavlov", "format": "win"}},
			"003": {{"name": "openssl", "version": "1:3.0.7-27.el9", "vendor": "Rocky", "format": "rpm"}},
		},
	}
}

func page(items []map[string]any, q map[string][]string) map[string]any {
	limit, offset := 500, 0
	if v := q["limit"]; len(v) > 0 {
		limit, _ = strconv.Atoi(v[0])
	}
	if v := q["offset"]; len(v) > 0 {
		offset, _ = strconv.Atoi(v[0])
	}
	if items == nil {
		items = []map[string]any{}
	}
	end := min(len(items), offset+limit)
	sel := items[min(offset, len(items)):end]
	return map[string]any{"data": map[string]any{"affected_items": sel, "total_affected_items": len(items), "total_failed_items": 0, "failed_items": []any{}},
		"message": "All specified syscollector information was returned", "error": 0}
}

func (f *fakeWazuh) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	js := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	if r.Method == http.MethodPost && r.URL.Path == "/security/user/authenticate" {
		f.logins++
		if u, p, ok := r.BasicAuth(); !ok || u != wzUser || p != wzPassword || r.URL.Query().Get("raw") != "true" {
			js(401, map[string]any{"title": "Unauthorized", "detail": "Invalid credentials"})
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, wzJWT)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+wzJWT || f.expire {
		f.expire = false
		js(401, map[string]any{"title": "Unauthorized", "detail": "No authorization token provided"})
		return
	}
	if f.tooMany > 0 {
		f.tooMany--
		w.Header().Set("Retry-After", "2")
		js(429, map[string]any{"title": "Wazuh Error", "detail": "Maximum number of requests per minute reached", "code": 6001})
		return
	}
	q := r.URL.Query()
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.URL.Path == "/":
		js(200, map[string]any{"data": map[string]any{"title": "Wazuh API", "api_version": "v4.9.2", "revision": "40921", "hostname": "wazuh"}, "error": 0})
	case r.URL.Path == "/agents":
		js(200, page(f.agents, q))
	case len(parts) == 3 && parts[0] == "syscollector":
		if f.forbid {
			js(403, map[string]any{"title": "Permission Denied", "detail": "Permission denied: Resource type: agent:id", "error": 4000})
			return
		}
		switch parts[2] {
		case "netaddr":
			js(200, page(f.netaddr[parts[1]], q))
		case "netiface":
			js(200, page(f.netiface[parts[1]], q))
		case "packages":
			if f.onPackage != nil {
				f.onPackage(r.Context())
			}
			js(200, page(f.packages[parts[1]], q))
		default:
			js(404, map[string]any{"title": "Not Found"})
		}
	default:
		js(404, map[string]any{"title": "Not Found"})
	}
}

type wzRig struct {
	*world
	fake   *fakeWazuh
	srv    *conntest.HTTPS
	slept  []time.Duration
	sleepM sync.Mutex
}

func newWzRig(t *testing.T) *wzRig {
	t.Helper()
	r := &wzRig{world: newWorld(t), fake: newFakeWazuh()}
	r.srv = conntest.NewHTTPS(t, r.fake)
	r.svc.SetWazuhForTest(nil, func(ctx context.Context, d time.Duration) error {
		r.sleepM.Lock()
		r.slept = append(r.slept, d)
		r.sleepM.Unlock()
		return ctx.Err()
	})
	return r
}

// admin sends an admin request (session cookie and CSRF header of servertest).
func (w *world) admin(method, path string, body any) reply {
	w.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	r := httptest.NewRequestWithContext(w.t.Context(), method, server.Prefix+path, rd)
	r.RemoteAddr = "192.0.2.200:40000"
	r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: "admin", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	r.Header.Set(servertest.CSRFHeader, servertest.CSRFValue)
	if rd != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	out := reply{code: rec.Code, header: rec.Header(), raw: rec.Body.String()}
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	}
	return out
}

func (r *wzRig) form(pw string) map[string]any {
	f := map[string]any{"url": r.srv.URL, "username": wzUser, "interval_minutes": 60}
	if pw != "" {
		f["password"] = pw
	}
	return f
}

func (r *wzRig) save() {
	r.t.Helper()
	if res := r.admin("PUT", "/inventory/agents/wazuh", r.form(wzPassword)); res.code != 200 {
		r.t.Fatalf("save: %d %s", res.code, res.raw)
	}
}

func (r *wzRig) pull() {
	r.t.Helper()
	if err := r.svc.WazuhPull(r.t.Context()); err != nil {
		r.t.Fatalf("pull: %v", err)
	}
}

func (r *wzRig) state() (status, errText string, agents, packages int) {
	r.t.Helper()
	var e *string
	if err := r.db.Reader().QueryRowContext(r.t.Context(), `SELECT status, error, agents, packages FROM intake_wazuh WHERE id = 1`).Scan(&status, &e, &agents, &packages); err != nil {
		r.t.Fatal(err)
	}
	if e != nil {
		errText = *e
	}
	return
}

// assertWazuhNowhere checks that the password and the JWT are in no table of the module, the audit log or the server log.
func (r *wzRig) assertWazuhNowhere() {
	r.t.Helper()
	for _, s := range []string{wzPassword, wzJWT} {
		r.assertNowhere(s)
		var all *string
		if err := r.db.Reader().QueryRowContext(r.t.Context(), `SELECT group_concat(url || username || password_last4 || tls_pin || coalesce(error, ''), '|') FROM intake_wazuh`).Scan(&all); err != nil {
			r.t.Fatal(err)
		}
		if all != nil && strings.Contains(*all, s) {
			r.t.Fatal("a Wazuh secret is stored in clear in intake_wazuh")
		}
	}
}

func TestWazuh_TestThenSaveTrustOnFirstUse(t *testing.T) {
	r := newWzRig(t)
	res := r.admin("POST", "/inventory/agents/wazuh/test", r.form(wzPassword))
	if res.code != 200 || res.body["ok"] != true || res.body["version"] != "v4.9.2" || res.body["agents"] != float64(4) {
		t.Fatalf("test: %d %s", res.code, res.raw)
	}
	if r.count(`SELECT count(*) FROM intake_wazuh`) != 0 || r.count(`SELECT count(*) FROM core_secret`) != 0 {
		t.Fatal("Test stored something")
	}
	res = r.admin("PUT", "/inventory/agents/wazuh", r.form(wzPassword))
	if res.code != 200 || res.body["status"] != "never" || res.body["password_last4"] != "026!" || res.body["url"] != r.srv.URL || res.body["last_sync"] != nil || res.body["error"] != nil {
		t.Fatalf("save: %d %s", res.code, res.raw)
	}
	var pin string
	if err := r.db.Reader().QueryRowContext(t.Context(), `SELECT tls_pin FROM intake_wazuh`).Scan(&pin); err != nil || pin != r.srv.SPKISHA256() {
		t.Fatalf("pin %q, want the server's key %q (%v)", pin, r.srv.SPKISHA256(), err)
	}
	if r.count(`SELECT count(*) FROM core_secret WHERE purpose = 'intake_wazuh.password'`) != 1 || r.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.wazuh_connect'`) != 1 {
		t.Fatal("no sealed password or no audit row")
	}
	w, err := r.svc.Wazuh(t.Context())
	if err != nil || w == nil || w.PasswordLast4 != "026!" || w.IntervalMinutes != 60 {
		t.Fatalf("Wazuh() = %+v %v", w, err)
	}
	if on, _ := r.svc.WazuhConnected(t.Context()); !on {
		t.Fatal("WazuhConnected false after Save")
	}
	// An edit with the password left blank keeps the saved one (same server).
	f := r.form("")
	f["interval_minutes"] = 15
	if res := r.admin("PUT", "/inventory/agents/wazuh", f); res.code != 200 || res.body["interval_minutes"] != float64(15) || res.body["password_last4"] != "026!" {
		t.Fatalf("edit with a blank password: %d %s", res.code, res.raw)
	}
	r.assertWazuhNowhere()
}

func TestWazuh_FormChecks(t *testing.T) {
	r := newWzRig(t)
	for _, c := range []struct {
		name string
		mod  func(map[string]any)
		code string
	}{
		{"http", func(f map[string]any) { f["url"] = strings.Replace(r.srv.URL, "https", "http", 1) }, "bad_url"},
		{"path", func(f map[string]any) { f["url"] = r.srv.URL + "/api" }, "bad_url"},
		{"user in url", func(f map[string]any) { f["url"] = strings.Replace(r.srv.URL, "https://", "https://u:p@", 1) }, "bad_url"},
		{"query", func(f map[string]any) { f["url"] = r.srv.URL + "?x=1" }, "bad_url"},
		{"loopback", func(f map[string]any) { f["url"] = "https://127.0.0.1:55000" }, "bad_url"},
		{"metadata", func(f map[string]any) { f["url"] = "https://169.254.169.254" }, "bad_url"},
		{"the box", func(f map[string]any) { f["url"] = "https://" + boxAddr + ":55000" }, "bad_url"},
		{"user", func(f map[string]any) { f["username"] = "bad user" }, "bad_username"},
		{"no password", func(f map[string]any) { delete(f, "password") }, "password_required"},
		{"interval", func(f map[string]any) { f["interval_minutes"] = 7 }, "bad_interval"},
	} {
		f := r.form(wzPassword)
		c.mod(f)
		for _, p := range []string{"/inventory/agents/wazuh/test", "/inventory/agents/wazuh"} {
			method := "POST"
			if !strings.HasSuffix(p, "/test") {
				method = "PUT"
			}
			if res := r.admin(method, p, f); res.code != 400 || res.errCode() != c.code {
				t.Errorf("%s %s: %d %s, want 400 %s", c.name, p, res.code, res.raw, c.code)
			}
		}
	}
	if n := len(r.srv.Requests()); n != 0 {
		t.Fatalf("a refused form reached the server (%d requests)", n)
	}
	// The saved password never goes to another address without being typed again.
	r.save()
	other := conntest.NewHTTPS(t, r.fake)
	f := r.form("")
	f["url"] = other.URL
	if res := r.admin("PUT", "/inventory/agents/wazuh", f); res.code != 400 || res.errCode() != "password_required" {
		t.Fatalf("new address with a blank password: %d %s", res.code, res.raw)
	}
	if res := r.admin("POST", "/inventory/agents/wazuh/test", f); res.code != 400 || len(other.Requests()) != 0 {
		t.Fatalf("the saved password went to another address: %d %s", res.code, res.raw)
	}
}

func TestWazuh_AuthForbiddenUnreachable(t *testing.T) {
	r := newWzRig(t)
	if res := r.admin("POST", "/inventory/agents/wazuh/test", r.form("wrong-password")); res.code != 422 || res.errCode() != "wazuh_auth" {
		t.Fatalf("wrong password: %d %s", res.code, res.raw)
	}
	r.fake.forbid = true
	if res := r.admin("PUT", "/inventory/agents/wazuh", r.form(wzPassword)); res.code != 422 || res.errCode() != "wazuh_forbidden" {
		t.Fatalf("no syscollector:read: %d %s", res.code, res.raw)
	}
	if r.count(`SELECT count(*) FROM intake_wazuh`) != 0 {
		t.Fatal("a Save that failed its check stored the connection (PRE-2)")
	}
	f := r.form(wzPassword)
	f["url"] = "https://192.0.2.99:1" // TEST-NET-1: nothing answers
	if res := r.admin("POST", "/inventory/agents/wazuh/test", f); res.code != 502 || res.errCode() != "wazuh_unreachable" {
		t.Fatalf("unreachable: %d %s", res.code, res.raw)
	}
	r.assertWazuhNowhere()
}

func TestWazuh_PullFillsTheInventory(t *testing.T) {
	r := newWzRig(t)
	r.save()
	r.pull()
	st, e, agents, pkgs := r.state()
	if st != "connected" || e != "" || agents != 4 || pkgs != 4 { // openssh, htop (the snap is dropped), 7-Zip and the Windows row (D-546); the NAT'd agent's openssl is not written
		t.Fatalf("state %s %q agents=%d packages=%d", st, e, agents, pkgs)
	}
	d, ok := r.device(ipLinux)
	if !ok || d.Hostname == nil || *d.Hostname != "web01" || d.OS == nil || d.OS.Source != "agent" || d.OS.Value != "Ubuntu 24.04.1 LTS" || d.MAC == nil || *d.MAC != macLinux {
		t.Fatalf("linux device %v %+v host=%v os=%+v mac=%v", ok, d.AssetCore, d.Hostname, d.OS, d.MAC)
	}
	if ssh, ok := swByProduct(d, "OpenSSH"); !ok || ssh.Vendor != "OpenBSD" || *ssh.Version != "9.6p1" || ssh.Source != "agent" || len(ssh.Kev) != 1 {
		t.Fatalf("openssh %+v", ssh)
	}
	if _, ok := swByProduct(d, "core20"); ok {
		t.Fatal("a snap package (outside the supported servers) was written")
	}
	win, ok := r.device(ipWindows)
	if !ok {
		t.Fatal("no Windows device")
	}
	if z, ok := swByProduct(win, "7-Zip"); !ok || z.Vendor != "7-Zip" || *z.Version != "23.01" {
		t.Fatalf("7-zip %+v", win.Software)
	}
	// D-546: the operating system's own row, by the update revision Wazuh's os version carries
	if os, ok := swByProduct(win, "Windows Server 2022"); !ok || os.Vendor != "microsoft" || *os.Version != "10.0.20348.2700" || !slices.Equal(os.Kev, []string{"microsoft|windows"}) {
		t.Fatalf("Windows row %+v", win.Software)
	}
	// The NAT'd agent (its ip is not among its own addresses) and the manager on 127.0.0.1 are skipped: nothing at 203.0.113.9.
	if _, ok := r.device("203.0.113.9"); ok || r.deviceCount() != 2 {
		t.Fatalf("an agent whose address is not its own was written (%d devices)", r.deviceCount())
	}
	// The NAT'd agent was unbound in this first pull: one more pull comes after a minute (TestWazuh_FirstPullRetriesOnceWhenAnAgentHasNoAddressesYet),
	// then the interval rules: not due again until it has passed; a failure does not pull sooner.
	r.clock.Advance(time.Minute)
	r.pull()
	n := len(r.srv.Requests())
	r.clock.Advance(59 * time.Minute)
	r.pull()
	if len(r.srv.Requests()) != n {
		t.Fatal("pulled before the interval")
	}
	r.clock.Advance(2 * time.Minute)
	r.pull()
	if len(r.srv.Requests()) == n {
		t.Fatal("did not pull after the interval")
	}
	r.assertWazuhNowhere()
}

// A Wazuh agent installed a moment ago has no syscollector netaddr/netiface yet (the API answers an empty affected_items, as in the real run of
// 2026-11-12): the first pull cannot bind it, and used to wait a whole interval. It now reads again at the next tick, once; the device appears
// in the same pull that finds its addresses. A later pull that skips an agent does not go back to a one-minute rhythm (last_sync is set).
func TestWazuh_FirstPullRetriesOnceWhenAnAgentHasNoAddressesYet(t *testing.T) {
	r := newWzRig(t)
	r.fake.netaddr["001"], r.fake.netiface["001"] = nil, nil // web01 has not reported yet
	r.save()
	r.pull()
	if _, ok := r.device(ipLinux); ok {
		t.Fatal("an agent without addresses was written")
	}
	// The agent's syscollector reports; one minute later (not an interval) the same Service pulls again and the device is there.
	r.fake.mu.Lock()
	r.fake.netaddr["001"] = []map[string]any{{"iface": "eth0", "address": ipLinux, "proto": "ipv4"}}
	r.fake.netiface["001"] = []map[string]any{{"name": "eth0", "mac": macLinux}}
	r.fake.mu.Unlock()
	r.clock.Advance(time.Minute)
	r.pull()
	d, ok := r.device(ipLinux)
	if !ok || d.MAC == nil || *d.MAC != macLinux {
		t.Fatalf("the device did not appear in the pull after one minute: %v %+v", ok, d.AssetCore)
	}
	// The NAT'd agent is still unbound, but that was the one retry: the next pull is an interval away.
	n := len(r.srv.Requests())
	r.clock.Advance(time.Minute)
	r.pull()
	if len(r.srv.Requests()) != n {
		t.Fatal("pulled again after a minute although the one retry was already used")
	}
}

// Nothing unbound in the first pull: no early retry, the interval rules from the start.
func TestWazuh_FirstPullWithEveryAgentBoundWaitsTheInterval(t *testing.T) {
	r := newWzRig(t)
	r.fake.agents = r.fake.agents[:3:3] // without the NAT'd agent 003
	r.save()
	r.pull()
	n := len(r.srv.Requests())
	r.clock.Advance(time.Minute)
	r.pull()
	if len(r.srv.Requests()) != n {
		t.Fatal("pulled again after a minute with every agent bound")
	}
}

// FORBID-4: one POST (the login), GETs on the allow-list, nothing else, whatever the account may do.
func TestWazuh_FORBID4_ReadOnlyCalls(t *testing.T) {
	r := newWzRig(t)
	r.save()
	r.pull()
	reqs := r.srv.Requests()
	if len(reqs) < 10 {
		t.Fatalf("only %d requests", len(reqs))
	}
	for _, q := range reqs {
		if !agentintake.AllowedWazuhCall(q.Method, q.Path) {
			t.Errorf("call outside the allow-list: %s %s", q.Method, q.Path)
		}
		if q.Method == http.MethodPost && q.Path != "/security/user/authenticate" {
			t.Errorf("a write: %s %s", q.Method, q.Path)
		}
		if len(q.Body) != 0 {
			t.Errorf("%s %s carried a body", q.Method, q.Path)
		}
	}
	for _, c := range []struct {
		m, p string
		ok   bool
	}{
		{"POST", "/security/user/authenticate", true}, {"GET", "/", true}, {"GET", "/agents", true},
		{"GET", "/syscollector/001/packages", true}, {"GET", "/syscollector/001/netaddr", true}, {"GET", "/syscollector/001/netiface", true},
		{"GET", "/syscollector/001/os", false}, {"GET", "/syscollector/../agents", false}, {"GET", "/syscollector/1/packages", false},
		{"PUT", "/agents", false}, {"DELETE", "/agents", false}, {"POST", "/agents", false}, {"PUT", "/active-response", false},
		{"GET", "/security/users", false}, {"GET", "/manager/configuration", false}, {"POST", "/", false},
	} {
		if agentintake.AllowedWazuhCall(c.m, c.p) != c.ok {
			t.Errorf("allowed(%s %s) != %v", c.m, c.p, c.ok)
		}
	}
}

// A certificate that changed stops the pull before the password is sent; Save is the act of trusting the new one (D-308).
func TestWazuh_PinMismatchStopsThePull(t *testing.T) {
	r := newWzRig(t)
	r.save()
	r.pull()
	r.srv.Rotate(t)
	before := r.fake.logins
	r.clock.Advance(61 * time.Minute)
	r.pull()
	st, e, agents, _ := r.state()
	if st != "error" || !strings.Contains(e, "certificate changed") || !strings.Contains(e, "type the password again") || agents != 4 {
		t.Fatalf("after a new certificate: %s %q agents=%d", st, e, agents)
	}
	if r.fake.logins != before {
		t.Fatal("the password was sent to a server whose key is not the pinned one")
	}
	// Test with the saved password (blank field) holds to the pin too.
	if res := r.admin("POST", "/inventory/agents/wazuh/test", r.form("")); res.code != 502 || res.errCode() != "wazuh_tls" || r.fake.logins != before {
		t.Fatalf("test with the saved password and a new certificate: %d %s", res.code, res.raw)
	}
	// Save with the password left blank does not send the saved password to the new key: it asks for the password (round 1, MEDIUM-1).
	if res := r.admin("PUT", "/inventory/agents/wazuh", r.form("")); res.code != 400 || res.errCode() != "password_required" || r.fake.logins != before {
		t.Fatalf("save with a blank password after the change: %d %s", res.code, res.raw)
	}
	// Save with the password typed again re-runs the first-use decision and pins the new key; the next pull works.
	if res := r.admin("PUT", "/inventory/agents/wazuh", r.form(wzPassword)); res.code != 200 || res.body["status"] != "connected" || res.body["error"] != nil {
		t.Fatalf("save after the change: %d %s", res.code, res.raw)
	}
	var pin string
	_ = r.db.Reader().QueryRowContext(t.Context(), `SELECT tls_pin FROM intake_wazuh`).Scan(&pin)
	if pin != r.srv.SPKISHA256() {
		t.Fatal("Save did not pin the new key")
	}
	r.pull()
	if st, _, _, _ := r.state(); st != "connected" {
		t.Fatalf("pull after re-pinning: %s", st)
	}
}

func TestWazuh_PublicRootsAreKeptAsTheRule(t *testing.T) {
	r := newWzRig(t)
	r.svc.SetWazuhForTest(r.srv.Roots(), func(ctx context.Context, _ time.Duration) error { return ctx.Err() })
	r.save()
	var pin string
	_ = r.db.Reader().QueryRowContext(t.Context(), `SELECT tls_pin FROM intake_wazuh`).Scan(&pin)
	if pin != "system" {
		t.Fatalf("pin %q, want system", pin)
	}
	r.svc.SetWazuhForTest(nil, func(ctx context.Context, _ time.Duration) error { return ctx.Err() }) // the authority no longer vouches
	r.pull()
	if st, e, _, _ := r.state(); st != "error" || !strings.Contains(e, "certificate changed") {
		t.Fatalf("a certificate no authority vouches for any more: %s %q", st, e)
	}
}

// An agent whose package list comes back empty (syscollector off) keeps what is known (D-169 (13)).
func TestWazuh_EmptyPackageListNeverWipes(t *testing.T) {
	r := newWzRig(t)
	r.save()
	r.pull()
	r.fake.mu.Lock()
	r.fake.packages["001"] = nil
	r.fake.mu.Unlock()
	r.clock.Advance(61 * time.Minute)
	r.pull()
	d, _ := r.device(ipLinux)
	if _, ok := swByProduct(d, "OpenSSH"); !ok {
		t.Fatal("an empty package list wiped the device's software")
	}
}

// Lesson 1 of slice 2: the MAC an agent reports is only an observation; it cannot move the agent's packages onto another device.
func TestWazuh_MACClaimCannotWriteOnAnotherDevice(t *testing.T) {
	r := newWzRig(t)
	const victimIP, victimMAC = "192.0.2.50", "52:54:00:de:ad:01"
	hint := observe.AssetHint{IP: netip.MustParseAddr(victimIP), MAC: victimMAC}
	if err := r.inv.Record(t.Context(), []observe.Observation{{AssetHint: hint, Field: observe.Hostname, Value: "dc01", Source: observe.Agent, Confidence: 0.95}}); err != nil {
		t.Fatal(err)
	}
	if err := r.inv.ReplaceSoftware(t.Context(), hint, observe.Agent, []observe.Software{{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "8.0p1", KevKeys: []string{"openbsd|openssh"}, Confidence: 0.95}}); err != nil {
		t.Fatal(err)
	}
	r.fake.mu.Lock()
	r.fake.netiface["001"] = []map[string]any{{"name": "eth0", "mac": victimMAC}}
	r.fake.mu.Unlock()
	r.save()
	r.pull()
	v, ok := r.device(victimIP)
	if !ok || v.Hostname == nil || *v.Hostname != "dc01" || len(v.Software) != 1 || *v.Software[0].Version != "8.0p1" {
		t.Fatalf("the victim was changed: %+v %v", v.Software, v.Hostname)
	}
	a, ok := r.device(ipLinux)
	if !ok || (a.MAC != nil && *a.MAC == victimMAC) {
		t.Fatalf("the agent's device took the victim's MAC: %v", a.MAC)
	}
}

func TestWazuh_RetriesTooManyRequestsAndAnExpiredToken(t *testing.T) {
	r := newWzRig(t)
	r.save()
	r.fake.mu.Lock()
	r.fake.tooMany, r.fake.expire = 2, true
	logins := r.fake.logins
	r.fake.mu.Unlock()
	r.pull()
	if st, e, _, _ := r.state(); st != "connected" {
		t.Fatalf("after 429s and a 401: %s %q", st, e)
	}
	if r.fake.logins != logins+2 { // the pull's login, and one more after the 401
		t.Fatalf("logins %d, want %d", r.fake.logins, logins+2)
	}
	if fmt.Sprint(r.slept) != "[2s 2s]" {
		t.Fatalf("waits %v, want the Retry-After of the two 429s", r.slept)
	}
	// A manager that keeps answering 429 ends the pull with an error, never a tight loop.
	r.fake.mu.Lock()
	r.fake.tooMany = 1000
	r.fake.mu.Unlock()
	r.clock.Advance(61 * time.Minute)
	r.pull()
	if st, e, _, _ := r.state(); st != "error" || !strings.Contains(e, "Could not reach") {
		t.Fatalf("a manager that keeps refusing: %s %q", st, e)
	}
}

// A Save while a pull runs wins: the pull's result is not written over the new connection.
func TestWazuh_SaveDuringAPullWins(t *testing.T) {
	r := newWzRig(t)
	r.save()
	r.fake.mu.Lock()
	r.fake.onPackage = func(ctx context.Context) { // a Save commits while the pull runs
		if err := r.db.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE intake_wazuh SET generation = generation + 1`)
			return err
		}); err != nil {
			t.Error(err)
		}
	}
	r.fake.mu.Unlock()
	r.pull()
	if st, _, agents, _ := r.state(); st != "never" || agents != 0 {
		t.Fatalf("a pull wrote its result over a newer Save: %s agents=%d", st, agents)
	}
}

func TestWazuh_DeleteRemovesThePassword(t *testing.T) {
	r := newWzRig(t)
	if res := r.admin("DELETE", "/inventory/agents/wazuh", nil); res.code != 404 || res.errCode() != "not_found" {
		t.Fatalf("delete with nothing saved: %d %s", res.code, res.raw)
	}
	r.save()
	r.pull()
	if res := r.admin("DELETE", "/inventory/agents/wazuh", nil); res.code != 204 {
		t.Fatalf("delete: %d %s", res.code, res.raw)
	}
	if r.count(`SELECT count(*) FROM intake_wazuh`) != 0 || r.count(`SELECT count(*) FROM core_secret`) != 0 || r.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.wazuh_disconnect'`) != 1 {
		t.Fatal("the connection, its password or the audit row")
	}
	if _, ok := r.device(ipLinux); !ok {
		t.Fatal("data already pulled was deleted with the connection")
	}
	n := len(r.srv.Requests())
	r.clock.Advance(2 * time.Hour)
	r.pull()
	if len(r.srv.Requests()) != n {
		t.Fatal("pulled after the connection was deleted")
	}
	if res := r.admin("POST", "/inventory/agents/wazuh/sample-data", nil); res.code != 404 {
		t.Fatalf("sample-data in the real build: %d (INV-10)", res.code)
	}
}

func TestWazuh_SYS5_ModuleOffIs404(t *testing.T) {
	r := newWzRig(t)
	r.save()
	r.gate.Set("agent-intake", false)
	unknown := r.admin("GET", "/inventory/agents/nothing", nil)
	for _, c := range []struct{ m, p string }{{"PUT", "/inventory/agents/wazuh"}, {"POST", "/inventory/agents/wazuh/test"}, {"DELETE", "/inventory/agents/wazuh"}} {
		if res := r.admin(c.m, c.p, r.form(wzPassword)); res.code != 404 || res.raw != unknown.raw {
			t.Errorf("%s %s while off: %d %s", c.m, c.p, res.code, res.raw)
		}
	}
	if r.count(`SELECT count(*) FROM intake_wazuh`) != 1 || r.count(`SELECT count(*) FROM core_secret`) != 1 {
		t.Fatal("data lost while off")
	}
	for _, j := range r.svc.Jobs() {
		if j.Housekeeping {
			t.Errorf("job %s is Housekeeping: it would run while the module is off", j.Name)
		}
	}
}

// Round 1, MEDIUM-4: a disconnected agent not heard of for more than 7 days, and the older of two agents on one address (a reinstall
// leaves the old id behind), are not read: their old packages would land on whoever has that address now.
func TestWazuh_StaleAndDuplicateAgentsAreSkipped(t *testing.T) {
	r := newWzRig(t)
	r.fake.mu.Lock()
	r.fake.agents[2]["lastKeepAlive"] = "2026-10-01T10:00:00Z" // WIN-FS01, disconnected for six weeks
	r.fake.agents = append(r.fake.agents, map[string]any{"id": "004", "name": "web01-old", "ip": ipLinux, "status": "disconnected", "lastKeepAlive": "2026-11-10T07:00:00Z", "os": map[string]any{"name": "Ubuntu", "version": "20.04", "platform": "ubuntu"}})
	r.fake.netaddr["004"] = r.fake.netaddr["001"]
	r.fake.netiface["004"] = r.fake.netiface["001"]
	r.fake.packages["004"] = []map[string]any{{"name": "nginx", "version": "1.18.0-0ubuntu1", "format": "deb", "source": "nginx"}}
	r.fake.mu.Unlock()
	r.save()
	r.pull()
	if _, ok := r.device(ipWindows); ok {
		t.Fatal("a disconnected agent not heard of for six weeks was written")
	}
	d, _ := r.device(ipLinux)
	if _, ok := swByProduct(d, "nginx"); ok || d.Hostname == nil || *d.Hostname != "web01" {
		t.Fatalf("the older agent on the same address was written: host=%v %+v", d.Hostname, d.Software)
	}
	for _, q := range r.srv.Requests() {
		if strings.HasPrefix(q.Path, "/syscollector/002/") || strings.HasPrefix(q.Path, "/syscollector/004/") || strings.HasPrefix(q.Path, "/syscollector/000/packages") {
			t.Errorf("a skipped agent was read: %s", q.Path)
		}
	}
}

// Round 1, MEDIUM-3: a pass that does not fit in one pull's budget goes on at the next tick from the agent after the last one done.
// The budget runs out while the second agent's package page is being read; the test ends it itself, so no real time is waited on.
func TestWazuh_ALongPassGoesOnAtTheNextTick(t *testing.T) {
	r := newWzRig(t)
	r.save()
	var endBudget context.CancelFunc
	r.svc.SetWazuhBudgetForTest(func(ctx context.Context) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(ctx)
		r.fake.mu.Lock() // the fake's handler reads it under the same lock
		endBudget = cancel
		r.fake.mu.Unlock()
		return ctx, cancel
	})
	pages := 0
	r.fake.mu.Lock()
	r.fake.onPackage = func(ctx context.Context) { // called under the fake's lock, one request at a time
		if pages++; pages == 2 {
			endBudget()  // the budget runs out during the second agent's package page
			<-ctx.Done() // the client gives up on the request
		}
	}
	r.fake.mu.Unlock()
	r.pull()
	var resume *string
	var pass int
	if err := r.db.Reader().QueryRowContext(t.Context(), `SELECT resume_after, pass_packages FROM intake_wazuh`).Scan(&resume, &pass); err != nil {
		t.Fatal(err)
	}
	if st, e, _, _ := r.state(); st != "connected" || e != "" || resume == nil || *resume != "001" || pass != 2 {
		t.Fatalf("after a pass cut by the budget: %s %q resume=%v pass=%d", st, e, resume, pass)
	}
	r.fake.mu.Lock() // the cut request may still be in the fake's handler
	r.fake.onPackage = nil
	r.fake.mu.Unlock()
	r.svc.SetWazuhBudgetForTest(nil)
	r.clock.Advance(time.Minute) // the next tick, not the next interval
	r.pull()
	st, _, agents, pkgs := r.state()
	if st != "connected" || agents != 4 || pkgs != 4 { // with the Windows agent's operating-system row (D-546)
		t.Fatalf("after the pass ended: %s agents=%d packages=%d", st, agents, pkgs)
	}
	n := 0
	for _, q := range r.srv.Requests() {
		if q.Path == "/syscollector/001/packages" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("agent 001 was read %d times in one pass", n)
	}
	if err := r.db.Reader().QueryRowContext(t.Context(), `SELECT resume_after FROM intake_wazuh`).Scan(&resume); err != nil || resume != nil {
		t.Fatalf("resume_after after the pass: %v %v", resume, err)
	}
}
