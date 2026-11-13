package core_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/modules/core"
)

func setupBody(code string) map[string]any {
	return map[string]any{
		"setup_code": code, "org": "Acme Co",
		"admin":  map[string]any{"name": "Ann Admin", "email": "admin@acme.example", "password": authtest.Password},
		"lan":    []string{"192.168.10.0/24", "10.1.0.0/16"},
		"bundle": "smb", "commitment": true,
	}
}

// openSetup runs the start-up step that makes the setup code and returns it.
func (w *world) openSetup() string {
	w.t.Helper()
	code, err := w.h.EnsureSetupCode(w.t.Context())
	if err != nil || code == "" {
		w.t.Fatalf("EnsureSetupCode = %q, %v", code, err)
	}
	return code
}

func TestContract_INV15_SetupStatusAndModuleListBeforeSetup(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c := w.client()
	r := c.get("/setup")
	wantOK(t, r, 200)
	if r.JSON["complete"] != false || r.JSON["org"] != "" || r.JSON["data_mode"] != "clean" {
		t.Fatalf("GET /setup = %s", r.Raw)
	}
	r = c.get("/core/setup/modules")
	wantOK(t, r, 200)
	mods, _ := r.JSON["modules"].([]any)
	if len(mods) < 15 {
		t.Fatalf("GET /core/setup/modules = %s", r.Raw)
	}
	first, _ := mods[0].(map[string]any)
	if first["id"] != "core" || first["tier"] != "core" {
		t.Fatalf("first module = %v", first)
	}
	if _, has := first["enabled"]; has {
		t.Fatal("the public module list says which modules are on")
	}
	if r := c.get("/core/auth-options"); r.Code != 200 || r.JSON["oidc"] != false {
		t.Fatalf("GET /core/auth-options = %s", r.Raw)
	}
}

// D-75: the code is judged first; a wrong code, a missing code and a code of another box are the same refusal.
func TestContract_INV15_SetupCodeIsRequired(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	code := w.openSetup()
	c := w.client()
	for name, in := range map[string]string{"missing": "", "wrong": "AAAAA-AAAAA-AAAAA-AAAAA", "prefix": code[:12], "longer": code + "A", "spaces": "  "} {
		b := setupBody(in)
		if in == "" {
			delete(b, "setup_code")
		}
		wantStatus(t, c.post("/core/setup", b), 403, "invalid_setup_code")
		_ = name
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_user"); n != 0 {
		t.Fatalf("a refused setup created %d users", n)
	}
	// A wrong code says nothing about the other fields: bad fields with a wrong code are still the code error.
	bad := setupBody("nope")
	bad["org"] = ""
	wantStatus(t, c.post("/core/setup", bad), 403, "invalid_setup_code")
	// The code is accepted without case, spaces or hyphens.
	typed := strings.ToLower(strings.ReplaceAll(code, "-", " "))
	wantOK(t, c.post("/core/setup", setupBody(typed)), 200)
}

func TestContract_INV15_SetupWrongCodeAttemptsAreRateLimited(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	code := w.openSetup()
	c := w.client()
	for range 10 {
		wantStatus(t, c.post("/core/setup", setupBody("AAAAA-AAAAA-AAAAA-AAAAA")), 403, "invalid_setup_code")
	}
	r := c.post("/core/setup", setupBody("AAAAA-AAAAA-AAAAA-AAAAA"))
	wantStatus(t, r, 429, "rate_limited")
	if r.Header.Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
	// Even the right code waits: the counter is shared, there is no way to tell the owner from a guesser.
	wantStatus(t, c.post("/core/setup", setupBody(code)), 429, "rate_limited")
}

func TestContract_INV15_SetupFieldErrors(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	code := w.openSetup()
	c := w.client()
	mod := func(f func(b map[string]any)) map[string]any { b := setupBody(code); f(b); return b }
	adm := func(k string, v any) map[string]any {
		return mod(func(b map[string]any) { a := b["admin"].(map[string]any); a[k] = v })
	}
	tests := []struct {
		name   string
		body   map[string]any
		status int
		code   string
	}{
		{"org short", mod(func(b map[string]any) { b["org"] = "A" }), 400, "invalid_org"},
		{"org missing", mod(func(b map[string]any) { delete(b, "org") }), 400, "invalid_org"},
		{"org control", mod(func(b map[string]any) { b["org"] = "Acme\x07Co" }), 400, "invalid_org"},
		{"org long", mod(func(b map[string]any) { b["org"] = strings.Repeat("x", 81) }), 400, "invalid_org"},
		{"name empty", adm("name", "  "), 400, "invalid_name"},
		{"name long", adm("name", strings.Repeat("n", 81)), 400, "invalid_name"},
		{"email bad", adm("email", "not-an-email"), 400, "invalid_email"},
		{"password short", adm("password", "short"), 400, "weak_password"},
		{"no lan", mod(func(b map[string]any) { b["lan"] = []string{} }), 400, "invalid_lan"},
		{"blank lan", mod(func(b map[string]any) { b["lan"] = []string{" ", ""} }), 400, "invalid_lan"},
		{"17 lan", mod(func(b map[string]any) {
			var l []string
			for i := range 17 {
				l = append(l, "10."+string(rune('0'+i/10))+"."+string(rune('0'+i%10))+".0/24")
			}
			b["lan"] = l
		}), 400, "invalid_lan"},
		{"lan not cidr", mod(func(b map[string]any) { b["lan"] = []string{"192.168.10.0"} }), 400, "invalid_lan"},
		{"lan ipv6", mod(func(b map[string]any) { b["lan"] = []string{"fd00::/8"} }), 400, "invalid_lan"},
		{"lan prefix 33", mod(func(b map[string]any) { b["lan"] = []string{"10.0.0.0/33"} }), 400, "invalid_lan"},
		{"lan public", mod(func(b map[string]any) { b["lan"] = []string{"8.8.8.0/24"} }), 400, "public_range"},
		{"lan covers the internet", mod(func(b map[string]any) { b["lan"] = []string{"10.0.0.0/0"} }), 400, "public_range"},
		{"lan 172.32", mod(func(b map[string]any) { b["lan"] = []string{"172.32.0.0/16"} }), 400, "public_range"},
		{"bundle missing", mod(func(b map[string]any) { delete(b, "bundle") }), 400, "invalid_bundle"},
		// The contract enum stops an unknown module id before the handler sees it.
		{"custom unknown module", mod(func(b map[string]any) { b["bundle"] = "custom"; b["modules"] = []string{"feeds", "nope"} }), 400, "invalid"},
		{"custom missing deps", mod(func(b map[string]any) { b["bundle"] = "custom"; b["modules"] = []string{"reports"} }), 400, "missing_dependencies"},
		{"sample", map[string]any{"sample": true}, 400, "sample_unavailable"},
	}
	for _, tc := range tests {
		wantStatus(t, c.post("/core/setup", tc.body), tc.status, tc.code)
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_org") + w.env.Count(t, "SELECT count(*) FROM core_user"); n != 0 {
		t.Fatalf("refused setups left %d rows behind", n)
	}
	// missing_dependencies names what is missing.
	r := c.post("/core/setup", mod(func(b map[string]any) { b["bundle"] = "custom"; b["modules"] = []string{"reports"} }))
	if m, _ := r.JSON["error"].(map[string]any)["missing"].([]any); len(m) == 0 {
		t.Fatalf("missing = %s", r.Raw)
	}
}

// The happy path: organization, first administrator, a session, the bundle, the audit row, the code gone.
func TestContract_INV15_SetupHappyPath(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	code := w.openSetup()
	c := w.client()
	r := c.post("/core/setup", setupBody(code))
	wantOK(t, r, 200)
	if r.JSON["ok"] != true {
		t.Fatalf("setup = %s", r.Raw)
	}
	if !c.signedIn() || c.cookie("__Host-vedette_csrf") == nil {
		t.Fatal("setup did not sign the administrator in")
	}
	me := c.get("/me")
	wantOK(t, me, 200)
	if me.str("email") != "admin@acme.example" || me.str("role") != "admin" || me.str("org") != "Acme Co" || me.JSON["twofa"] != false || me.JSON["twofa_method"] != nil {
		t.Fatalf("/me = %s", me.Raw)
	}
	if st := c.get("/setup"); st.JSON["complete"] != true || st.str("org") != "Acme Co" || st.str("data_mode") != "clean" {
		t.Fatalf("GET /setup after = %s", st.Raw)
	}
	on := map[string]bool{}
	mods, _ := c.get("/modules").JSON["modules"].([]any)
	for _, m := range mods {
		mm := m.(map[string]any)
		on[mm["id"].(string)] = mm["enabled"] == true
	}
	for _, id := range []string{"core", "feeds", "inventory", "notify", "sensor-passive", "findings", "mitigation", "honeypot", "reports"} {
		if !on[id] {
			t.Errorf("%s should be on in the small bundle", id)
		}
	}
	for _, id := range []string{"sensor-active", "scan", "exposure", "logs", "ai", "response", "mcp-server"} {
		if on[id] {
			t.Errorf("%s should be off in the small bundle", id)
		}
	}
	if !w.reg.Enabled("notify") || w.reg.Enabled("ai") {
		t.Fatal("the registry cache did not follow the commit")
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'core.setup' AND target = 'Acme Co' AND detail LIKE 'bundle smb, 2 ranges%commitment confirmed'"); n != 1 {
		t.Fatal("no core.setup audit row")
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'user.create' AND user = 'admin@acme.example'"); n != 1 {
		t.Fatal("no user.create audit row")
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_secret WHERE purpose = 'core_setup_code'"); n != 0 {
		t.Fatal("the setup code survived the setup")
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_setting WHERE key = 'setup.scope' AND value LIKE '%192.168.10.0/24%' AND value LIKE '%true%'"); n != 1 {
		t.Fatal("the LAN ranges and the commitment were not kept")
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_org WHERE id = 1 AND setup_complete = 1 AND data_mode = 'clean' AND install_id <> ''"); n != 1 {
		t.Fatal("core_org row is wrong")
	}
	// INV-15: only once. The same request again, and a fresh start, find setup done.
	wantStatus(t, w.client().post("/core/setup", setupBody(code)), 409, "already_setup")
	if code2, err := w.h.EnsureSetupCode(t.Context()); err != nil || code2 != "" {
		t.Fatalf("EnsureSetupCode after setup = %q, %v", code2, err)
	}
	// The password is stored hashed only, and no secret reached the logs.
	for _, s := range []string{authtest.Password, code} {
		if strings.Contains(w.logs.String(), s) {
			t.Fatal("a secret reached the logs")
		}
	}
}

// A custom bundle turns on exactly the chosen modules (and what they need), and the medium bundle adds to the small one.
func TestContract_INV15_SetupBundles(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		bundle  string
		mods    []string
		on, off []string
	}{
		"medium": {"mid", nil, []string{"scan", "ai", "logs", "exposure", "sensor-active", "feeds"}, []string{"response", "scan-credentialed", "mcp-server"}},
		"custom": {"custom", []string{"feeds", "notify", "inventory", "reports"}, []string{"feeds", "notify", "inventory", "reports", "core"}, []string{"findings", "honeypot", "sensor-passive"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			code := w.openSetup()
			b := setupBody(code)
			b["bundle"] = tc.bundle
			if tc.mods != nil {
				b["modules"] = tc.mods
			}
			c := w.client()
			wantOK(t, c.post("/core/setup", b), 200)
			for _, id := range tc.on {
				if !w.reg.Enabled(id) {
					t.Errorf("%s is off", id)
				}
			}
			for _, id := range tc.off {
				if w.reg.Enabled(id) {
					t.Errorf("%s is on", id)
				}
			}
		})
	}
}

// The module lists of the bundles are written twice (web and Go): they must not drift.
func TestBundlesMatchTheWebList(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../web/src/features/core/bundles.ts")
	if err != nil {
		t.Fatal(err)
	}
	for _, bundle := range []string{"smb", "mid"} {
		// Read the TS arrays: const SMB: ModuleId[] = [...]; const MID = [...SMB, ...]
		got := tsBundle(t, string(b), bundle)
		// A fresh world per bundle: setup runs once.
		ww := newWorld(t)
		req := setupBody(ww.openSetup())
		req["bundle"] = bundle
		wantOK(t, ww.client().post("/core/setup", req), 200)
		for _, s := range ww.reg.List() {
			want := s.Tier == "core"
			for _, id := range got {
				want = want || id == s.ID
			}
			if s.Enabled != want {
				t.Errorf("bundle %s: module %s enabled=%v, the web list says %v", bundle, s.ID, s.Enabled, want)
			}
		}
	}
}

// D-381: on a container-only install the bundles leave out what cannot run there (the honeypot), the lists say which
// modules are not available and the install kind, and a custom setup that names the honeypot is refused.
func TestSetupOnContainerOnly(t *testing.T) {
	t.Parallel()
	w := newWorldKind(t, true, nil)
	c := w.client()
	r := c.get("/core/setup/modules")
	wantOK(t, r, 200)
	if r.JSON["install"] != "container" {
		t.Fatalf("install = %v", r.JSON["install"])
	}
	for _, m := range r.JSON["modules"].([]any) {
		m := m.(map[string]any)
		if want := m["id"] != "honeypot" && m["id"] != "scan-credentialed"; m["available"] != want {
			t.Errorf("%v: available = %v", m["id"], m["available"])
		}
	}
	custom := setupBody(w.openSetup())
	custom["bundle"], custom["modules"] = "custom", []string{"feeds", "inventory", "honeypot"}
	if r := c.post("/core/setup", custom); r.Code != 409 || r.code() != "not_appliance" {
		t.Fatalf("custom with honeypot = %d %s", r.Code, r.Raw)
	}
	wantOK(t, c.post("/core/setup", setupBody(w.openSetup())), 200)
	if w.reg.Enabled("honeypot") || !w.reg.Enabled("sensor-passive") {
		t.Fatal("the small business bundle turned the honeypot on, or left the rest off")
	}
	r = c.get("/modules")
	wantOK(t, r, 200)
	if r.JSON["install"] != "container" {
		t.Fatalf("GET /modules install = %v", r.JSON["install"])
	}
	if r := c.patch("/modules/honeypot", map[string]any{"enabled": true}); r.Code != 409 || r.code() != "not_appliance" {
		t.Fatalf("PATCH /modules/honeypot = %d %s", r.Code, r.Raw)
	}
}

func tsBundle(t *testing.T, src, name string) []string {
	t.Helper()
	line := ""
	for _, l := range strings.Split(src, "\n") {
		if strings.HasPrefix(l, "const "+strings.ToUpper(name[:3])) || (name == "smb" && strings.HasPrefix(l, "const SMB")) || (name == "mid" && strings.HasPrefix(l, "const MID")) {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no %s list in bundles.ts", name)
	}
	var ids []string
	for _, part := range strings.Split(line[strings.Index(line, "=")+1:], ",") {
		part = strings.TrimSpace(strings.Trim(strings.TrimSpace(part), "[]"))
		if strings.HasPrefix(part, "...") {
			ids = append(ids, tsBundle(t, src, "smb")...)
			continue
		}
		if p := strings.Trim(part, "'"); p != "" && strings.HasPrefix(part, "'") {
			ids = append(ids, p)
		}
	}
	return ids
}

// Review of WP-04b part 2 (M3, D-75 amended): wrong setup codes are counted per client address, so a
// stranger who reaches the port before the owner cannot keep setup closed for everyone. (One global counter
// let 10 wrong guesses, then one per lifted wait, answer 429 to the owner at another address with the right code.)
func TestSetup_ACodeGuesserCannotLockTheOwnerOut(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	code := w.openSetup()
	attacker := w.client()
	attacker.remote = "198.51.100.66:4444"
	for range 10 {
		wantStatus(t, attacker.post("/core/setup", setupBody("AAAAA-AAAAA-AAAAA-AAAAA")), 403, "invalid_setup_code")
	}
	wantStatus(t, attacker.post("/core/setup", setupBody("AAAAA-AAAAA-AAAAA-AAAAA")), 429, "rate_limited") // the guesser is the one who waits
	owner := w.client()                                                                                    // another machine on the LAN, holding the code from the box's log
	r := owner.post("/core/setup", setupBody(code))
	if r.Code != 200 {
		t.Fatalf("the owner with the right code from another address = %d %s: one guesser keeps setup closed", r.Code, r.Raw)
	}
}

// INV-15, the order of the mock: after setup every POST /core/setup is 409 already_setup, sample or not.
func TestSetup_SampleAfterSetupIsAlreadySetup(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.setupAdmin()
	wantStatus(t, w.client().post("/core/setup", map[string]any{"sample": true}), 409, "already_setup")
	// Before setup the build has no sample data.
	w2 := newWorld(t)
	w2.openSetup()
	wantStatus(t, w2.client().post("/core/setup", map[string]any{"sample": true}), 400, "sample_unavailable")
}

// Concurrent setups with the right code create exactly one administrator, and every loser is told the truth:
// 409 already_setup (or 503 server_busy when the hashing slots are taken), never 403 invalid_setup_code for a
// code that was right but already used up by the winner.
func TestSetup_ConcurrentSetupsCreateOneAdminAndLosersAreTold409(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	code := w.openSetup()
	const n = 6
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := setupBody(code)
			b["admin"] = map[string]any{"name": "Admin", "email": fmt.Sprintf("admin%d@acme.example", i), "password": authtest.Password}
			c := w.client()
			c.remote = fmt.Sprintf("192.0.2.%d:5000", 20+i)
			codes[i] = c.post("/core/setup", b).Code
		}()
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		switch c {
		case 200:
			ok++
		case 409, 503:
		default:
			t.Errorf("unexpected status %d in %v", c, codes)
		}
	}
	if ok != 1 || w.env.Count(t, "SELECT count(*) FROM core_user") != 1 || w.env.Count(t, "SELECT count(*) FROM core_org") != 1 {
		t.Fatalf("statuses %v: %d users", codes, w.env.Count(t, "SELECT count(*) FROM core_user"))
	}
}

// The organization name refuses invisible format characters (a zero-width space cannot be typed back for the
// purge confirmation), at setup as well as in general settings.
func TestSetup_OrganizationNameRefusesInvisibleFormatCharacters(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	code := w.openSetup()
	b := setupBody(code)
	b["org"] = "Acme\u200B Co"
	wantStatus(t, w.client().post("/core/setup", b), 400, "invalid_org")
	b = setupBody(code)
	b["admin"] = map[string]any{"name": "Ann\u202Enimda", "email": "admin@acme.example", "password": authtest.Password}
	wantStatus(t, w.client().post("/core/setup", b), 400, "invalid_name")
}

// attrsOf is a Set-Cookie line without its value: the flags and the lifetime a browser acts on.
func attrsOf(t *testing.T, r reply, name string) string {
	t.Helper()
	for _, line := range r.Header.Values("Set-Cookie") {
		if n, rest, _ := strings.Cut(line, "="); n == name {
			_, attrs, _ := strings.Cut(rest, ";")
			return attrs
		}
	}
	return ""
}

// Finishing setup signs the new administrator in as a password sign-in does: the same two cookies with the same
// flags and lifetime, no device cookie (that one is for two-step trusted devices), and the session works for a
// read and for a CSRF-protected write. A setup that fails sets no cookie.
func TestSetup_SignsTheAdministratorInLikeASignIn(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	code := w.openSetup()

	bad := w.client()
	for _, body := range []map[string]any{
		setupBody("AAAAA-AAAAA-AAAAA-AAAAA"),
		func() map[string]any { b := setupBody(code); b["lan"] = []string{"8.8.8.0/24"}; return b }(),
		func() map[string]any { b := setupBody(code); b["org"] = ""; return b }(),
	} {
		r := bad.post("/core/setup", body)
		if r.Code < 400 || len(r.Header.Values("Set-Cookie")) != 0 || bad.signedIn() {
			t.Fatalf("failed setup = %d %s, cookies %v", r.Code, r.Raw, r.Header.Values("Set-Cookie"))
		}
	}

	c := w.client()
	setup := c.post("/core/setup", setupBody(code))
	wantOK(t, setup, 200)
	if n := len(setup.Header.Values("Set-Cookie")); n != 2 || c.cookie(auth.CookieDevice) != nil {
		t.Fatalf("setup set %d cookies (device cookie %v)", n, c.cookie(auth.CookieDevice))
	}
	login := w.client().login("admin@acme.example")
	wantOK(t, login, 200)
	for _, name := range []string{auth.CookieSession, auth.CookieCSRF} {
		got, want := attrsOf(t, setup, name), attrsOf(t, login, name)
		if got == "" || got != want {
			t.Errorf("%s after setup: %q, after sign-in: %q", name, got, want)
		}
	}
	wantOK(t, c.get("/me"), 200)
	wantOK(t, c.patch("/core/privacy", map[string]any{"telemetry": false}), 200)
	noCSRF := c.request("PATCH", "/core/privacy", map[string]any{"telemetry": true}, func(r *http.Request) { r.Header.Del(auth.HeaderCSRF) })
	wantStatus(t, noCSRF, 403, "csrf_invalid")
	// Setup runs once, and a second try neither signs anyone in nor changes the first account.
	again := w.client()
	r := again.post("/core/setup", setupBody(code))
	wantStatus(t, r, 409, "already_setup")
	if again.signedIn() || len(r.Header.Values("Set-Cookie")) != 0 {
		t.Fatal("a second setup set cookies")
	}
	// One sign-in row from setup itself, one from the sign-in above; and the setup row.
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.login' AND user = 'admin@acme.example'"); n != 2 {
		t.Errorf("auth.login rows = %d, want 2", n)
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'core.setup'"); n != 1 {
		t.Errorf("core.setup rows = %d", n)
	}
}

// Session fixation: cookies the browser already holds when it finishes setup are replaced, never adopted.
func TestSetup_DoesNotAdoptAPlantedSession(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	code := w.openSetup()
	c := w.client()
	c.jar[auth.CookieSession] = &http.Cookie{Name: auth.CookieSession, Value: "planted-session-token-planted-session-token", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	c.jar[auth.CookieCSRF] = &http.Cookie{Name: auth.CookieCSRF, Value: "planted-csrf-token-planted-csrf-token", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	logStart := w.logs.Len()
	wantOK(t, c.post("/core/setup", setupBody(code)), 200)
	sess, csrf := c.cookie(auth.CookieSession), c.cookie(auth.CookieCSRF)
	if sess == nil || csrf == nil || strings.HasPrefix(sess.Value, "planted") || strings.HasPrefix(csrf.Value, "planted") {
		t.Fatalf("setup kept a planted cookie: %v %v", sess, csrf)
	}
	attacker := w.client()
	attacker.jar[auth.CookieSession] = &http.Cookie{Name: auth.CookieSession, Value: "planted-session-token-planted-session-token", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	wantStatus(t, attacker.get("/me"), 401, "unauthenticated")
	if n := w.env.Count(t, "SELECT count(*) FROM core_session"); n != 1 {
		t.Errorf("sessions after setup = %d", n)
	}
	// The setup code is single-use: gone from core_secret in the same transaction.
	if n := w.env.Count(t, "SELECT count(*) FROM core_secret WHERE purpose = 'core_setup_code'"); n != 0 {
		t.Errorf("setup code rows after setup = %d", n)
	}
	// Nothing secret reaches the log during setup.
	logged := w.logs.String()[logStart:]
	for _, s := range []string{authtest.Password, code, sess.Value, csrf.Value} {
		if strings.Contains(logged, s) {
			t.Errorf("setup logged a secret (%q...)", s[:4])
		}
	}
	// The setup code cannot be reused for a second administrator.
	r := w.client().post("/core/setup", func() map[string]any {
		b := setupBody(code)
		b["admin"] = map[string]any{"name": "Eve", "email": "eve@acme.example", "password": authtest.Password}
		return b
	}())
	wantStatus(t, r, 409, "already_setup")
	if n := w.env.Count(t, "SELECT count(*) FROM core_user"); n != 1 {
		t.Errorf("users = %d", n)
	}
}

// fakeScope is the inventory port of setup: it writes a row in the setup's own transaction (so the test sees whether that commit
// carried it), may refuse the ranges, and records what it was given and how the transaction ended.
type fakeScope struct {
	mu        sync.Mutex
	refuse    *apierr.Error
	actor     string
	lan       []string
	confirmed bool
	settled   []bool
	sameTx    bool
}

func (f *fakeScope) SetupScope(ctx context.Context, tx *sql.Tx, actor string, lan []string, confirmed bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actor, f.lan, f.confirmed = actor, lan, confirmed
	if _, err := tx.ExecContext(ctx, `INSERT INTO core_setting (key, value, updated_at, updated_by) VALUES ('test.scope', '1', '2026-11-12T00:00:00.000Z', 'test')`); err != nil {
		return err
	}
	var n int
	f.sameTx = tx.QueryRowContext(ctx, `SELECT count(*) FROM core_org`).Scan(&n) == nil && n == 1 // the org of this setup, not yet committed
	if f.refuse != nil {
		return f.refuse
	}
	return nil
}

func (f *fakeScope) Settle(_ context.Context, _ *sql.Tx, committed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settled = append(f.settled, committed)
}

// #350: the LAN ranges and the commitment of the wizard reach the inventory port inside the setup's one transaction, with the
// administrator as the one who confirmed, and the port is settled once with the commit.
func TestContract_INV15_SetupGivesTheRangesToTheInventory(t *testing.T) {
	t.Parallel()
	f := &fakeScope{}
	w := newWorldWith(t, func(hc *core.HandlersConfig) { hc.Scope = f })
	wantOK(t, w.client().post("/core/setup", setupBody(w.openSetup())), 200)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.actor != "admin@acme.example" || !slices.Equal(f.lan, []string{"192.168.10.0/24", "10.1.0.0/16"}) || !f.confirmed || !f.sameTx {
		t.Fatalf("port got actor %q lan %v confirmed %v in the setup transaction %v", f.actor, f.lan, f.confirmed, f.sameTx)
	}
	if !slices.Equal(f.settled, []bool{true}) {
		t.Fatalf("settled %v, want one commit", f.settled)
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_setting WHERE key = 'test.scope'"); n != 1 {
		t.Fatal("the port's write did not commit with the setup")
	}
}

// The inventory refuses the ranges (INV-6 of inventory, for example an overlap): the whole setup is refused with its code, nothing
// of the setup is kept, the setup code still works, and the port is settled as rolled back.
func TestContract_INV15_SetupFailsWhenTheInventoryRefusesTheRanges(t *testing.T) {
	t.Parallel()
	f := &fakeScope{refuse: apierr.New(400, "overlap_range", "Range 192.168.10.0/24 overlaps 192.168.0.0/16.")}
	w := newWorldWith(t, func(hc *core.HandlersConfig) { hc.Scope = f })
	code := w.openSetup()
	c := w.client()
	wantStatus(t, c.post("/core/setup", setupBody(code)), 400, "overlap_range")
	if c.signedIn() {
		t.Fatal("a refused setup signed someone in")
	}
	for _, q := range []string{"SELECT count(*) FROM core_org", "SELECT count(*) FROM core_user", "SELECT count(*) FROM core_setting WHERE key IN ('setup.scope', 'test.scope')",
		"SELECT count(*) FROM core_audit WHERE action IN ('core.setup', 'user.create')"} {
		if n := w.env.Count(t, q); n != 0 {
			t.Errorf("%s = %d after a refused setup", q, n)
		}
	}
	f.mu.Lock()
	settled := slices.Clone(f.settled)
	f.refuse = nil
	f.mu.Unlock()
	if !slices.Equal(settled, []bool{false}) {
		t.Fatalf("settled %v, want one rollback", settled)
	}
	wantOK(t, c.post("/core/setup", setupBody(code)), 200) // the code was not used up
}

// Overlapping ranges are refused with the field checks, before the bundle and before anything is written or handed to the inventory;
// the same range with host bits is one range (D-298).
func TestContract_INV15_SetupRefusesOverlappingRangesUpFront(t *testing.T) {
	t.Parallel()
	f := &fakeScope{}
	w := newWorldWith(t, func(hc *core.HandlersConfig) { hc.Scope = f })
	code := w.openSetup()
	b := setupBody(code)
	b["lan"], b["bundle"], b["modules"] = []string{"192.168.0.0/16", "192.168.10.0/24"}, "custom", []string{"scan"} // scan alone lacks its dependencies
	wantStatus(t, w.client().post("/core/setup", b), 400, "overlap_range")
	f.mu.Lock()
	called := f.actor != "" || len(f.settled) != 0
	f.mu.Unlock()
	if called {
		t.Fatal("the inventory port was reached for ranges the field checks refuse")
	}
	b = setupBody(code)
	b["lan"] = []string{"192.168.1.0/24", "192.168.1.7/24"}
	wantOK(t, w.client().post("/core/setup", b), 200)
	f.mu.Lock()
	defer f.mu.Unlock()
	if !slices.Equal(f.lan, []string{"192.168.1.0/24"}) {
		t.Fatalf("port got %v, want the one range", f.lan)
	}
}

// D-405 (walk 4): while setup is open the network step is offered the box's own network (host bits cleared); a public or absent
// address, a box with no BoxLAN (container-only) and a box already set up give null.
func TestContract_INV15_SetupOffersTheBoxNetwork(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		lan  func(context.Context) (netip.Prefix, bool)
		want any
	}{
		{"private", func(context.Context) (netip.Prefix, bool) { return netip.MustParsePrefix("192.168.18.141/24"), true }, "192.168.18.0/24"},
		{"public", func(context.Context) (netip.Prefix, bool) { return netip.MustParsePrefix("203.0.113.5/24"), true }, nil},
		{"none", func(context.Context) (netip.Prefix, bool) { return netip.Prefix{}, false }, nil},
		{"no host", nil, nil},
	} {
		w := newWorldWith(t, func(hc *core.HandlersConfig) { hc.BoxLAN = tc.lan })
		r := w.client().get("/core/setup/modules")
		wantOK(t, r, 200)
		if got, has := r.JSON["lan"]; !has || got != tc.want {
			t.Errorf("%s: lan = %v (present %v), want %v", tc.name, got, has, tc.want)
		}
		if tc.name == "private" {
			wantOK(t, w.client().post("/core/setup", setupBody(w.openSetup())), 200)
			if got := w.client().get("/core/setup/modules").JSON["lan"]; got != nil {
				t.Errorf("after setup lan = %v, want null", got)
			}
		}
	}
}
