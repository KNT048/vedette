package ai_test

import (
	"context"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
)

// The security review of slice 1 (PR #123): M1, M2 and L1 to L5.

func saved(a *api, body string) string { return a.addProfile(body)["id"].(string) }

func withID(id, body string) string { return `{"id":"` + id + `",` + body[1:] }

func noKey(body string) string { return strings.Replace(body, `"api_key":"`+keyA+`",`, "", 1) }

func moveTo(body, from, to string) string { return strings.Replace(body, from, to, 1) }

func TestContract_INV1_StoredKeyGoesOnlyToTheAddressItWasSavedFor(t *testing.T) {
	a := newAPI(t)
	id := saved(a, cloudBody("Claude", keyA))
	base := noKey(cloudBody("Claude", keyA))
	// the test endpoint: a saved profile, no key in the body, another address: refused before any request is made
	for name, to := range map[string]string{
		"other host":   "https://evil.example.com",
		"other port":   "https://api.anthropic.com:8443",
		"other scheme": "http://api.anthropic.com",
		"subdomain":    "https://api.anthropic.com.evil.example",
		"userinfo":     "https://api.anthropic.com@evil.example",
	} {
		before := a.fake.total()
		got, m, raw := a.do("POST", "/ai/profiles/test", "admin", withID(id, moveTo(base, "https://api.anthropic.com", to)))
		if got != 400 {
			t.Errorf("%s: test = %d %s", name, got, raw)
		}
		if c := errCode(m); c != "key_required" && c != "invalid_base_url" {
			t.Errorf("%s: code %s", name, c)
		}
		if a.fake.total() != before {
			t.Errorf("%s: the provider was called", name)
		}
	}
	m := a.want("POST", "/ai/profiles/test", "admin", withID(id, moveTo(base, "https://api.anthropic.com", "https://evil.example.com")), 400, "key_required")
	if msg := m["error"].(map[string]any)["message"].(string); msg != "Changing the address needs the API key entered again." {
		t.Fatalf("message = %q", msg)
	}
	for _, k := range a.fake.keysSeen() {
		if k == keyA {
			t.Fatal("the stored key reached a call for another address")
		}
	}
	// the same origin (another path, upper-case host, an explicit default port) still uses the stored key
	for _, to := range []string{"https://api.anthropic.com/v1", "https://API.Anthropic.com", "https://api.anthropic.com:443"} {
		a.want("POST", "/ai/profiles/test", "admin", withID(id, moveTo(base, "https://api.anthropic.com", to)), 200, "")
	}
	if keys := a.fake.keysSeen(); len(keys) == 0 || keys[len(keys)-1] != keyA {
		t.Fatalf("keys seen = %v", keys)
	}
	// a new key may go to a new address
	a.want("POST", "/ai/profiles/test", "admin", withID(id, moveTo(cloudBody("Claude", keyB), "https://api.anthropic.com", "https://llm.example.com")), 200, "")
	if keys := a.fake.keysSeen(); keys[len(keys)-1] != keyB {
		t.Fatalf("keys seen = %v", keys)
	}
}

func TestContract_INV1_EditingTheAddressNeedsTheKeyAgain(t *testing.T) {
	a := newAPI(t)
	id := saved(a, cloudBody("Claude", keyA))
	base := noKey(cloudBody("Claude", keyA))
	m := a.want("PUT", "/ai/profiles/"+id, "admin", moveTo(base, "https://api.anthropic.com", "https://evil.example.com"), 400, "key_required")
	if msg := m["error"].(map[string]any)["message"].(string); msg != "Changing the address needs the API key entered again." {
		t.Fatalf("message = %q", msg)
	}
	list := a.want("GET", "/ai/profiles", "viewer", "", 200, "")["items"].([]any)
	if p := list[0].(map[string]any); p["base_url"] != "https://api.anthropic.com" || p["key_last4"] != "1111" {
		t.Fatalf("the refused edit changed the profile: %v", p)
	}
	// a new key with the new address is fine; the old key is replaced, not sent anywhere
	got := a.want("PUT", "/ai/profiles/"+id, "admin", moveTo(cloudBody("Claude", keyB), "https://api.anthropic.com", "https://llm.example.com"), 200, "")
	if got["base_url"] != "https://llm.example.com" || got["key_last4"] != "2222" {
		t.Fatalf("edit = %v", got)
	}
	// the same origin keeps the key
	got = a.want("PUT", "/ai/profiles/"+id, "admin", moveTo(noKey(cloudBody("Claude", keyB)), "https://api.anthropic.com", "https://llm.example.com/v2"), 200, "")
	if got["key_last4"] != "2222" {
		t.Fatalf("same origin = %v", got)
	}
	// an internal profile: another address drops its optional key (it is not sent), it does not fail
	in := a.addProfile(strings.Replace(internalBody("Local"), `"location":"internal"`, `"location":"internal","api_key":"`+keyA+`"`, 1))
	if in["key_last4"] != "1111" {
		t.Fatalf("internal with key = %v", in)
	}
	moved := a.want("PUT", "/ai/profiles/"+in["id"].(string), "admin", strings.Replace(internalBody("Local"), "192.168.10.5", "192.168.10.6", 1), 200, "")
	if moved["key_last4"] != nil {
		t.Fatalf("the key of an internal profile followed it to a new address: %v", moved)
	}
}

func TestContract_INV20_AuditNamesTheHost(t *testing.T) {
	a := newAPI(t)
	id := saved(a, cloudBody("Claude", keyA))
	a.want("PUT", "/ai/profiles/"+id, "admin", moveTo(cloudBody("Claude", keyB), "https://api.anthropic.com", "https://user:pw@llm.example.com:8443/v1?x=1"), 400, "invalid_base_url")
	a.want("PUT", "/ai/profiles/"+id, "admin", moveTo(cloudBody("Claude", keyB), "https://api.anthropic.com", "https://llm.example.com:8443/v1"), 200, "")
	a.want("POST", "/ai/profiles/test", "admin", moveTo(cloudBody("Draft", keyA), "https://api.anthropic.com", "https://other.example.com"), 200, "")
	rows := a.auditRows()
	want := []string{"ai.profile.add Claude anthropic, cloud, model=claude-haiku-5-5, host=api.anthropic.com, key set", "ai.profile.edit Claude anthropic, cloud, model=claude-haiku-5-5, host=llm.example.com:8443, key changed", "ai.test Draft model=claude-haiku-5-5, host=other.example.com, result=ok"}
	if len(rows) != len(want) {
		t.Fatalf("audit = %q", rows)
	}
	for i, w := range want {
		if rows[i] != w {
			t.Errorf("audit row %d = %q, want %q", i, rows[i], w)
		}
		if strings.Contains(rows[i], "pw") || strings.Contains(rows[i], "/v1") {
			t.Errorf("audit row %d holds more than the host: %q", i, rows[i])
		}
	}
}

func TestContract_INV20_TestAuditSurvivesACancelledRequest(t *testing.T) {
	for name, fail := range map[string]error{"answer": nil, "error": &provider.Error{Kind: provider.ErrNetwork}} {
		t.Run(name, func(t *testing.T) {
			a := newAPI(t)
			ctx, cancel := context.WithCancel(a.ctx())
			defer cancel()
			a.fake.setOnCall(cancel) // the client goes away while the key is on its way
			if fail != nil {
				a.fake.failWith("Draft", fail)
			}
			_, _ = a.svc.TestProfile(ctx, "admin@acme.example", ai.ProfileInput{Name: "Draft", Kind: "anthropic", APIStyle: provider.StyleAnthropic, BaseURL: "https://api.anthropic.com", Model: "claude-haiku-5-5", APIKey: keyA, Location: ai.LocationCloud})
			if a.fake.total() == 0 {
				t.Fatal("the probe never ran")
			}
			rows := a.auditRows()
			if len(rows) != 1 || !strings.HasPrefix(rows[0], "ai.test Draft") || !strings.Contains(rows[0], "host=api.anthropic.com") {
				t.Fatalf("audit after a cancelled request = %q", rows)
			}
		})
	}
}

func TestContract_PRE3_ProviderRefusalsAreTold(t *testing.T) {
	a := newAPI(t)
	body := cloudBody("Draft", keyA)
	probe := func(err error, status int, code string) string {
		a.fake.failWith("Draft", err)
		m := a.want("POST", "/ai/profiles/test", "admin", body, status, code)
		return m["error"].(map[string]any)["message"].(string)
	}
	if msg := probe(&provider.Error{Kind: provider.ErrAuth, Status: 401}, 401, "key_rejected"); !strings.Contains(msg, "rejected the key") {
		t.Errorf("401: %q", msg)
	}
	// 403 means the key was understood but is not allowed here: not "rejected (401)"
	if msg := probe(&provider.Error{Kind: provider.ErrAuth, Status: 403}, 502, "provider_error"); strings.Contains(msg, "401") || !strings.Contains(msg, "403") || !strings.Contains(msg, "permission") {
		t.Errorf("403: %q", msg)
	}
	if msg := probe(&provider.Error{Kind: provider.ErrRateLimited, Status: 429}, 502, "provider_error"); !strings.Contains(msg, "rate-limiting") || !strings.Contains(msg, "try again later") {
		t.Errorf("429: %q", msg)
	}
	if msg := probe(&provider.Error{Kind: provider.ErrNoWorkspace, Status: 400}, 502, "provider_error"); !strings.Contains(msg, "not tied to a workspace") {
		t.Errorf("workspace: %q", msg)
	}
	probe(&provider.Error{Kind: provider.ErrServer, Status: 500}, 502, "provider_error")
	probe(&provider.Error{Kind: provider.ErrBadResponse}, 502, "provider_error")
	// the provider truly cannot be reached: dial error or timeout
	probe(&provider.Error{Kind: provider.ErrNetwork}, 502, "unreachable")
	probe(&provider.Error{Kind: provider.ErrTimeout}, 502, "unreachable")
}

func TestContract_PRE3_DraftTestChecksTheNameAndTheKind(t *testing.T) {
	a := newAPI(t)
	a.addProfile(cloudBody("Claude", keyA))
	a.want("POST", "/ai/profiles/test", "admin", cloudBody("claude", keyB), 400, "duplicate_name")
	// a saved profile tested under its own name is not a duplicate of itself
	id := a.profileIDOf("Claude")
	a.want("POST", "/ai/profiles/test", "admin", withID(id, noKey(cloudBody("Claude", keyA))), 200, "")
	// an unknown kind: ogen answers first when it can; the service says invalid_kind when it is asked directly
	before := a.fake.total()
	_, err := a.svc.TestProfile(a.ctx(), "admin@acme.example", ai.ProfileInput{Name: "X", Kind: "bogus", APIStyle: provider.StyleOpenAI, BaseURL: "https://api.example.com", Model: "m-1", APIKey: keyA, Location: ai.LocationCloud})
	if ae, ok := apierr.As(err); !ok || ae.Code != "invalid_kind" {
		t.Fatalf("unknown kind = %v", err)
	}
	if a.fake.total() != before {
		t.Fatal("a draft of an unknown kind reached the provider")
	}
}

func (a *api) profileIDOf(name string) string {
	a.t.Helper()
	for _, p := range a.want("GET", "/ai/profiles", "viewer", "", 200, "")["items"].([]any) {
		if p.(map[string]any)["name"] == name {
			return p.(map[string]any)["id"].(string)
		}
	}
	a.t.Fatalf("no profile %q", name)
	return ""
}

func TestContract_INV4_ConnectionTestsCountAgainstTheCap(t *testing.T) {
	a := newAPI(t)
	a.want("PUT", "/ai/config", "admin", `{"tier":"min","daily_cap":1000,"redact_pii":true}`, 200, "")
	a.fake.setProbeUsage(600, 400) // every request of a probe uses 1,000 tokens
	a.want("POST", "/ai/profiles/test", "admin", cloudBody("Draft", keyA), 200, "")
	calls := a.fake.total()
	m := a.want("POST", "/ai/profiles/test", "admin", cloudBody("Draft", keyA), 429, "daily_cap")
	if a.fake.total() != calls {
		t.Fatal("a test past the cap reached the provider")
	}
	if msg := m["error"].(map[string]any)["message"].(string); !strings.Contains(msg, "1,000 token cap") {
		t.Fatalf("message = %q", msg)
	}
	// at a higher level a probe that passes the cap lowers the level, and the drop is recorded like any other
	a2 := newAPI(t)
	a2.want("PUT", "/ai/config", "admin", `{"tier":"max","daily_cap":1000,"redact_pii":true}`, 200, "")
	a2.fake.setProbeUsage(600, 400)
	a2.want("POST", "/ai/profiles/test", "admin", cloudBody("Draft", keyA), 200, "")
	if cfg := a2.want("GET", "/ai/config", "viewer", "", 200, ""); cfg["tier"] == "max" {
		t.Fatalf("tier = %v", cfg["tier"])
	}
	var n int
	if err := a2.db.Reader().QueryRowContext(a2.ctx(), `SELECT COUNT(*) FROM core_audit WHERE action = 'ai.downgrade'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("downgrade audit rows = %d, %v", n, err)
	}
}

func TestContract_INV3_NoAddressThatReachesTheBoxItselfOrTheNeighbourhood(t *testing.T) {
	a := newAPI(t)
	refused := map[string]string{
		"metadata, internal":    strings.Replace(internalBody("a"), "http://192.168.10.5:11434/v1", "http://169.254.169.254/latest", 1),
		"link-local, internal":  strings.Replace(internalBody("b"), "192.168.10.5", "169.254.10.10", 1),
		"link-local v6":         strings.Replace(internalBody("c"), "http://192.168.10.5:11434/v1", "http://[fe80::1]:11434/v1", 1),
		"ec2 v6 metadata":       strings.Replace(internalBody("d"), "http://192.168.10.5:11434/v1", "http://[fd00:ec2::254]/", 1),
		"multicast":             strings.Replace(internalBody("e"), "192.168.10.5", "224.0.0.251", 1),
		"unspecified":           strings.Replace(internalBody("f"), "192.168.10.5", "0.0.0.0", 1),
		"cloud metadata":        strings.Replace(cloudBody("g", keyA), "https://api.anthropic.com", "https://169.254.169.254", 1),
		"cloud loopback":        strings.Replace(cloudBody("h", keyA), "https://api.anthropic.com", "https://127.0.0.1:8443", 1),
		"cloud private":         strings.Replace(cloudBody("i", keyA), "https://api.anthropic.com", "https://10.1.2.3", 1),
		"cloud CGNAT":           strings.Replace(cloudBody("j", keyA), "https://api.anthropic.com", "https://100.64.0.5", 1),
		"cloud ULA":             strings.Replace(cloudBody("k", keyA), "https://api.anthropic.com", "https://[fd12:3456::1]", 1),
		"cloud localhost":       strings.Replace(cloudBody("l", keyA), "https://api.anthropic.com", "https://localhost:8443", 1),
		"cloud mapped loopback": strings.Replace(cloudBody("m", keyA), "https://api.anthropic.com", "https://[::ffff:127.0.0.1]", 1),
	}
	for name, body := range refused {
		for _, call := range []struct{ method, path string }{{"POST", "/ai/profiles"}, {"POST", "/ai/profiles/test"}} {
			got, m, raw := a.do(call.method, call.path, "admin", body)
			if got != 400 || errCode(m) != "invalid_base_url" {
				t.Errorf("%s %s: %d %s", name, call.path, got, raw)
			}
		}
	}
	if a.fake.total() != 0 {
		t.Fatal("a refused address reached the provider")
	}
	// local servers stay possible for internal profiles: loopback and the private ranges
	for _, ok := range []string{"http://127.0.0.1:11434/v1", "http://[::1]:11434/v1", "http://10.0.0.7:8000/v1", "http://100.64.1.1:8000/v1"} {
		a.want("POST", "/ai/profiles", "admin", strings.Replace(internalBody("n-"+ok[7:12]), "http://192.168.10.5:11434/v1", ok, 1), 200, "")
	}
	// editing into a refused address is refused as well
	id := a.profileIDOf("n-127.0")
	a.want("PUT", "/ai/profiles/"+id, "admin", strings.Replace(internalBody("n-127.0"), "192.168.10.5", "169.254.169.254", 1), 400, "invalid_base_url")
}

func TestContract_L2_ABadSavedStateDoesNotStopTheBox(t *testing.T) {
	deg := func(s *ai.Service) string {
		t.Helper()
		d, ok := any(s).(interface{ Degraded() string })
		if !ok {
			t.Fatal("the service does not report that it is degraded")
		}
		return d.Degraded()
	}
	t.Run("a stored profile that the rules now refuse", func(t *testing.T) {
		a := newAPI(t)
		// a public address on an internal profile: what an older version, or a hand edit, could have left
		if err := a.exec(`INSERT INTO ai_profile (id, name, name_key, kind, api_style, base_url, model, location, daily_cap, created_at, updated_at)
			VALUES ('prof-old', 'Old', 'old', 'openai-compatible', 'openai', 'http://8.8.8.8:11434/v1', 'm-1', 'internal', 5000, '2026-11-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z')`); err != nil {
			t.Fatal(err)
		}
		svc, err := a.newServiceWith(a.sec)
		if err != nil {
			t.Fatalf("the box must start: %v", err)
		}
		if deg(svc) == "" {
			t.Fatal("not reported as degraded")
		}
		a.svc = svc
		h := &api{env: a.env, h: a.env.handler(servertest.NewGate())}
		if list := h.want("GET", "/ai/profiles", "viewer", "", 200, "")["items"].([]any); len(list) != 0 {
			t.Fatalf("profiles = %v", list)
		}
		if cfg := h.want("GET", "/ai/config", "viewer", "", 200, ""); cfg["configured"] != false {
			t.Fatalf("config = %v", cfg)
		}
		// nothing can be changed on top of a state that was not loaded: the stored rows would be overwritten blind
		m := h.want("POST", "/ai/profiles", "admin", cloudBody("New", keyA), 409, "ai_unavailable")
		if msg := m["error"].(map[string]any)["message"].(string); !strings.Contains(msg, "could not be loaded") {
			t.Fatalf("message = %q", msg)
		}
		h.want("PUT", "/ai/config", "admin", `{"tier":"min","daily_cap":5000,"redact_pii":true}`, 409, "ai_unavailable")
		h.want("PUT", "/ai/assignments", "admin", assignBody(false, map[string][2]string{}), 409, "ai_unavailable")
		if svc.Config().JobsReady["explain-finding"] {
			t.Fatal("a degraded service must not run jobs")
		}
	})
	t.Run("a key that cannot be opened", func(t *testing.T) {
		a := newAPI(t)
		a.addProfile(cloudBody("Claude", keyA))
		other, err := secrets.New([]byte("ffffffffffffffffffffffffffffffff"))
		if err != nil {
			t.Fatal(err)
		}
		svc, err := a.newServiceWith(other)
		if err != nil {
			t.Fatalf("the box must start: %v", err)
		}
		if deg(svc) == "" || svc.Config().JobsReady["explain-finding"] {
			t.Fatal("not degraded")
		}
	})
	t.Run("a sound state is not degraded", func(t *testing.T) {
		a := newAPI(t)
		a.addProfile(cloudBody("Claude", keyA))
		if d := deg(a.svc); d != "" {
			t.Fatalf("degraded: %q", d)
		}
	})
}
