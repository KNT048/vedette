package core_test

import (
	"os"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/auth/authtest"
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
	if !c.signedIn() || c.cookie("vedette_csrf") == nil {
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
