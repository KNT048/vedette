package ai_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
	"github.com/knt048/vedette/modules/core"
)

// Slice 1 of WP-25: profiles, keys, assignments and the shared settings (S-AI-1).

func TestMigrationsUsePrefix(t *testing.T) {
	storetest.AssertMigrationsUsePrefix(t, "ai", ai.Migrations, "ai_", storetest.Migration{Module: "core", FS: core.Migrations})
}

func TestRolesAndModuleGate(t *testing.T) {
	gate := servertest.NewGate()
	a := newAPIGate(t, gate)
	a.want("GET", "/ai/profiles", "", "", 401, "unauthenticated")
	for _, p := range []string{"/ai/config", "/ai/profiles", "/ai/assignments", "/ai/assignments/suggestion?internal_only=false"} {
		a.want("GET", p, "viewer", "", 200, "")
	}
	a.want("POST", "/ai/profiles", "operator", cloudBody("X", keyA), 403, "forbidden")
	a.want("PUT", "/ai/config", "operator", `{"tier":"med","daily_cap":60000,"redact_pii":true}`, 403, "forbidden")
	a.want("PUT", "/ai/assignments", "operator", `{"internal_only":false,"jobs":{}}`, 403, "forbidden")
	a.want("POST", "/ai/profiles/test", "operator", cloudBody("X", keyA), 403, "forbidden")
	a.want("DELETE", "/ai/profiles/p-1", "viewer", "", 403, "forbidden")
	gate.Set("ai", false)
	a.want("GET", "/ai/config", "admin", "", 404, "")
	a.want("POST", "/ai/profiles", "admin", cloudBody("X", keyA), 404, "")
	gate.Set("ai", true)
	a.want("GET", "/ai/config", "admin", "", 200, "")
}

func TestContract_INV1_KeyOnlyAsLast4(t *testing.T) {
	a := newAPI(t)
	p := a.addProfile(cloudBody("Claude", keyA))
	if p["key_last4"] != "1111" || p["usable"] != true || p["used_today"] != float64(0) {
		t.Fatalf("profile = %v", p)
	}
	for _, path := range []string{"/ai/profiles", "/ai/config", "/ai/assignments"} {
		_, _, raw := a.do("GET", path, "admin", "")
		if strings.Contains(raw, keyA) || strings.Contains(raw, "AAAA1111") {
			t.Fatalf("%s returned the key: %s", path, raw)
		}
	}
	// the key is encrypted in core_secret with its own purpose and appears nowhere else in the database
	var n int
	if err := a.db.Reader().QueryRowContext(a.ctx(), `SELECT COUNT(*) FROM core_secret WHERE purpose = 'ai_profile.api_key' AND last4 = '1111' AND instr(ciphertext, ?) = 0`, keyA).Scan(&n); err != nil || n != 1 {
		t.Fatalf("sealed secrets = %d, %v", n, err)
	}
	for _, q := range []string{
		`SELECT COUNT(*) FROM ai_profile WHERE instr(name || base_url || model || coalesce(secret_id,'') || coalesce(key_last4,''), ?) > 0`,
		`SELECT COUNT(*) FROM core_audit WHERE instr(user || action || target || detail, ?) > 0`,
	} {
		if err := a.db.Reader().QueryRowContext(a.ctx(), q, "AAAA1111").Scan(&n); err != nil || n != 0 {
			t.Fatalf("the key is in the database (%d, %v) via %s", n, err, q)
		}
	}
	// a blank key on edit keeps the old key
	id := p["id"].(string)
	got := a.want("PUT", "/ai/profiles/"+id, "admin", strings.Replace(cloudBody("Claude renamed", ""), `"api_key":"",`, "", 1), 200, "")
	if got["key_last4"] != "1111" || got["name"] != "Claude renamed" {
		t.Fatalf("after blank-key edit = %v", got)
	}
	// a new key replaces it in place
	got = a.want("PUT", "/ai/profiles/"+id, "admin", cloudBody("Claude renamed", keyB), 200, "")
	if got["key_last4"] != "2222" {
		t.Fatalf("after key change = %v", got)
	}
	if err := a.db.Reader().QueryRowContext(a.ctx(), `SELECT COUNT(*) FROM core_secret WHERE purpose = 'ai_profile.api_key'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("secrets after a key change = %d, %v", n, err)
	}
	// changing the provider type needs the key again
	body := strings.NewReplacer(`"kind":"anthropic"`, `"kind":"openai"`, `"api_style":"anthropic"`, `"api_style":"openai"`, `"api_key":"`+keyA+`",`, ``).Replace(cloudBody("Claude renamed", keyA))
	a.want("PUT", "/ai/profiles/"+id, "admin", body, 400, "key_required")
	// deleting the profile deletes its secret in the same transaction
	a.want("DELETE", "/ai/profiles/"+id, "admin", "", 200, "")
	if err := a.db.Reader().QueryRowContext(a.ctx(), `SELECT COUNT(*) FROM core_secret WHERE purpose = 'ai_profile.api_key'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("secrets after delete = %d, %v", n, err)
	}
}

func TestContract_INV1_UsableNeedsKeyOrInternal(t *testing.T) {
	a := newAPI(t)
	a.want("POST", "/ai/profiles", "admin", strings.Replace(cloudBody("NoKey", ""), `"api_key":"",`, "", 1), 400, "key_required")
	a.want("POST", "/ai/profiles", "admin", cloudBody("Short", "abc"), 400, "invalid_key")
	a.want("POST", "/ai/profiles", "admin", cloudBody("Spaced", "has a space in it"), 400, "invalid_key")
	p := a.addProfile(internalBody("Ollama"))
	if p["key_last4"] != nil || p["usable"] != true {
		t.Fatalf("internal profile without key = %v", p)
	}
}

func TestContract_INV3_InternalLabelIsEnforced(t *testing.T) {
	a := newAPI(t)
	for name, body := range map[string]string{
		"public IP":      strings.Replace(internalBody("a"), "192.168.10.5", "8.8.8.8", 1),
		"http for cloud": strings.Replace(cloudBody("b", keyA), "https://api.anthropic.com", "http://api.anthropic.com", 1),
		"user in url":    strings.Replace(internalBody("c"), "http://", "http://user:hunter2pw@", 1),
		"cloud kind":     strings.Replace(internalBody("d"), `"kind":"openai-compatible","api_style":"openai"`, `"kind":"openai","api_style":"openai"`, 1),
	} {
		got, m, raw := a.do("POST", "/ai/profiles", "admin", body)
		if got != 400 || (errCode(m) != "invalid_base_url" && errCode(m) != "invalid_location") {
			t.Errorf("%s: %d %s", name, got, raw)
		}
		if strings.Contains(raw, "hunter2pw") {
			t.Errorf("%s: the error repeats the password: %s", name, raw)
		}
	}
	// a name is allowed; the dialer checks where it points at connect time
	a.want("POST", "/ai/profiles", "admin", strings.Replace(internalBody("e"), "http://192.168.10.5:11434/v1", "http://ollama.lan:11434/v1", 1), 200, "")
}

func TestContract_INV3_InternalOnlyNeverReachesCloud(t *testing.T) {
	a := newAPI(t)
	c := a.addProfile(cloudBody("Claude", keyA))["id"].(string)
	i := a.addProfile(internalBody("Ollama"))["id"].(string)
	// a new profile becomes the primary of every job that has none, where the rule allows it
	asg := a.want("GET", "/ai/assignments", "viewer", "", 200, "")
	jobs := asg["jobs"].(map[string]any)
	if len(jobs) != 10 || jobs["explain-finding"].(map[string]any)["primary"] != c || jobs["log-digest"].(map[string]any)["primary"] != c {
		t.Fatalf("assignments after adding profiles = %v", asg)
	}
	// turning the rule on while a cloud profile holds an internal-data job is refused with the privacy_rule code
	m := a.want("PUT", "/ai/assignments", "admin", assignBody(true, map[string][2]string{"log-digest": {c, ""}}), 400, "privacy_rule")
	if msg := m["error"].(map[string]any)["message"].(string); !strings.Contains(msg, "Claude") || !strings.Contains(msg, "log summaries") {
		t.Fatalf("message = %q", msg)
	}
	// internal profiles for the internal-data jobs and the cloud profile for the public ones: saved
	all := map[string][2]string{}
	for _, j := range ai.Jobs() {
		if j.CarriesInternalData() {
			all[string(j)] = [2]string{i, ""}
		} else {
			all[string(j)] = [2]string{c, i}
		}
	}
	a.want("PUT", "/ai/assignments", "admin", assignBody(true, all), 200, "")
	cfg := a.want("GET", "/ai/config", "viewer", "", 200, "")
	for j, ready := range cfg["jobs_ready"].(map[string]any) {
		if ready != true {
			t.Errorf("job %s is not ready: %v", j, cfg)
		}
	}
	// the edit that would send an internal-data job to the cloud is refused too
	edit := strings.Replace(internalBody("Ollama"), `"kind":"openai-compatible"`, `"kind":"custom"`, 1)
	edit = strings.Replace(edit, `"location":"internal"`, `"location":"cloud","api_key":"`+keyA+`"`, 1)
	edit = strings.Replace(edit, "http://192.168.10.5:11434/v1", "https://llm.example.com/v1", 1)
	a.want("PUT", "/ai/profiles/"+i, "admin", edit, 400, "privacy_rule")
	// a cloud profile cannot be assigned to an internal-data job under the rule
	a.want("PUT", "/ai/assignments", "admin", assignBody(true, map[string][2]string{"ask-my-data": {c, ""}}), 400, "privacy_rule")
}

func assignBody(internalOnly bool, jobs map[string][2]string) string {
	var parts []string
	for j, s := range jobs {
		f := func(v string) string {
			if v == "" {
				return "null"
			}
			return `"` + v + `"`
		}
		parts = append(parts, fmt.Sprintf(`"%s":{"primary":%s,"fallback":%s}`, j, f(s[0]), f(s[1])))
	}
	return fmt.Sprintf(`{"internal_only":%t,"jobs":{%s}}`, internalOnly, strings.Join(parts, ","))
}

func TestContract_INV2_AssignmentRules(t *testing.T) {
	a := newAPI(t)
	p1 := a.addProfile(cloudBody("One", keyA))["id"].(string)
	p2 := a.addProfile(cloudBody("Two", keyB))["id"].(string)
	a.want("PUT", "/ai/assignments", "admin", assignBody(false, map[string][2]string{"cve-news": {"", p2}}), 400, "fallback_without_primary")
	a.want("PUT", "/ai/assignments", "admin", assignBody(false, map[string][2]string{"cve-news": {p1, p1}}), 400, "same_profile")
	a.want("PUT", "/ai/assignments", "admin", assignBody(false, map[string][2]string{"cve-news": {"p-missing", ""}}), 400, "unknown_profile")
	// jobs left out of the body are unassigned: all ten are always in the answer
	got := a.want("PUT", "/ai/assignments", "admin", assignBody(false, map[string][2]string{"cve-news": {p1, p2}}), 200, "")
	jobs := got["jobs"].(map[string]any)
	if len(jobs) != 10 || jobs["cve-news"].(map[string]any)["fallback"] != p2 || jobs["log-digest"].(map[string]any)["primary"] != nil {
		t.Fatalf("assignments = %v", got)
	}
	// saved assignments survive a restart
	again := newAPIOver(a.env)
	back := again.want("GET", "/ai/assignments", "viewer", "", 200, "")
	if back["jobs"].(map[string]any)["cve-news"].(map[string]any)["primary"] != p1 {
		t.Fatalf("after restart = %v", back)
	}
	cfg := again.want("GET", "/ai/config", "viewer", "", 200, "")
	ready := cfg["jobs_ready"].(map[string]any)
	if ready["cve-news"] != true || ready["log-digest"] != false || cfg["configured"] != true {
		t.Fatalf("config = %v", cfg)
	}
}

func newAPIOver(e *env) *api {
	e.svc = e.newService()
	return &api{env: e, h: e.handler(servertest.NewGate())}
}

func TestContract_POST4_DeletingAnAssignedProfile(t *testing.T) {
	a := newAPI(t)
	p1 := a.addProfile(cloudBody("One", keyA))["id"].(string)
	p2 := a.addProfile(cloudBody("Two", keyB))["id"].(string)
	a.want("PUT", "/ai/assignments", "admin", assignBody(false, map[string][2]string{"cve-news": {p1, p2}, "log-digest": {p2, p1}, "ask-my-data": {p2, ""}}), 200, "")
	got := a.want("DELETE", "/ai/profiles/"+p1, "admin", "", 200, "")
	if cleared := fmt.Sprint(got["cleared_jobs"]); cleared != "[cve-news log-digest]" {
		t.Fatalf("cleared_jobs = %s", cleared)
	}
	jobs := a.want("GET", "/ai/assignments", "viewer", "", 200, "")["jobs"].(map[string]any)
	// the primary is gone: the job keeps its fallback as the primary; a fallback that is gone just leaves
	if s := jobs["cve-news"].(map[string]any); s["primary"] != p2 || s["fallback"] != nil {
		t.Fatalf("cve-news = %v", s)
	}
	if s := jobs["log-digest"].(map[string]any); s["primary"] != p2 || s["fallback"] != nil {
		t.Fatalf("log-digest = %v", s)
	}
	a.want("DELETE", "/ai/profiles/"+p1, "admin", "", 404, "not_found")
	var n int
	if err := a.db.Reader().QueryRowContext(a.ctx(), `SELECT COUNT(*) FROM ai_assignment`).Scan(&n); err != nil || n != 10 {
		t.Fatalf("assignment rows = %d, %v", n, err)
	}
}

func TestProfileRules(t *testing.T) {
	a := newAPI(t)
	a.addProfile(cloudBody("Claude", keyA))
	a.want("POST", "/ai/profiles", "admin", cloudBody("claude", keyB), 400, "duplicate_name")
	a.want("POST", "/ai/profiles", "admin", strings.Replace(cloudBody("N", keyA), "claude-haiku-5-5", "bad model!", 1), 400, "invalid_model")
	a.want("POST", "/ai/profiles", "admin", strings.Replace(cloudBody("N", keyA), "https://api.anthropic.com", "not a url", 1), 400, "invalid_base_url")
	a.want("POST", "/ai/profiles", "admin", strings.Replace(cloudBody("N", keyA), `"kind":"anthropic"`, `"kind":"custom"`, 1), 200, "") // custom may speak any style
	a.want("PUT", "/ai/profiles/p-missing", "admin", cloudBody("N2", keyA), 404, "not_found")
	for i := 0; i < 12; i++ {
		got, m, _ := a.do("POST", "/ai/profiles", "admin", cloudBody(fmt.Sprintf("extra %d", i), keyA))
		if got != 200 {
			if errCode(m) != "too_many" || i != 10 {
				t.Fatalf("add %d = %d %v", i, got, m)
			}
			return
		}
	}
	t.Fatal("no limit on the number of profiles")
}

func TestContract_INV4_ConfigAndEstimates(t *testing.T) {
	a := newAPI(t)
	got := a.want("GET", "/ai/config", "viewer", "", 200, "")
	est := got["tier_estimates"].(map[string]any)
	if got["configured"] != false || got["tier"] != "med" || got["daily_cap"] != float64(60000) || got["redact_pii"] != true || est["min"] != float64(10000) || est["med"] != float64(60000) || est["max"] != nil {
		t.Fatalf("default config = %v", got)
	}
	put := a.want("PUT", "/ai/config", "admin", `{"tier":"max","daily_cap":250000,"redact_pii":false}`, 200, "")
	if put["tier"] != "max" || put["daily_cap"] != float64(250000) || put["redact_pii"] != false {
		t.Fatalf("saved config = %v", put)
	}
	a.want("PUT", "/ai/config", "admin", `{"tier":"max","daily_cap":999,"redact_pii":false}`, 400, "")
	a.want("PUT", "/ai/config", "admin", `{"tier":"huge","daily_cap":5000,"redact_pii":false}`, 400, "")
	a.want("PUT", "/ai/config", "admin", `{"tier":"max","daily_cap":5000001,"redact_pii":false}`, 400, "")
	back := newAPIOver(a.env).want("GET", "/ai/config", "viewer", "", 200, "")
	if back["tier"] != "max" || back["daily_cap"] != float64(250000) || back["redact_pii"] != false {
		t.Fatalf("after restart = %v", back)
	}
	a.want("POST", "/ai/profiles", "admin", strings.Replace(cloudBody("N", keyA), `"daily_cap":60000`, `"daily_cap":999`, 1), 400, "")
}

func TestContract_PRE3_ProfileTest(t *testing.T) {
	a := newAPI(t)
	got := a.want("POST", "/ai/profiles/test", "admin", cloudBody("Draft", keyA), 200, "")
	caps := got["capabilities"].(map[string]any)
	// three requests (plain, with a tool, with a JSON format) of 14 in and 3 out each: the test reports all three, as the meter counts them
	if got["ok"] != true || got["tokens_in"] != float64(42) || got["tokens_out"] != float64(9) || caps["tools"] != true || caps["structured"] != true || got["latency_ms"] == nil {
		t.Fatalf("test result = %v", got)
	}
	a.fake.setCaps(false, false)
	got = a.want("POST", "/ai/profiles/test", "admin", cloudBody("Draft", keyA), 200, "")
	if caps := got["capabilities"].(map[string]any); caps["tools"] != false || caps["structured"] != false || got["tokens_in"] != float64(14) {
		t.Fatalf("capabilities = %v", got)
	}
	// a saved profile is tested with its stored key when the body has none
	p := a.addProfile(cloudBody("Saved", keyA))
	a.fake.failWith("Saved", &provider.Error{Kind: provider.ErrAuth, Status: 401})
	body := `{"id":"` + p["id"].(string) + `",` + strings.Replace(cloudBody("Saved", ""), `"api_key":"",`, "", 1)[1:]
	_, m, raw := a.do("POST", "/ai/profiles/test", "admin", body)
	if errCode(m) != "key_rejected" || strings.Contains(raw, "AAAA1111") {
		t.Fatalf("saved profile test = %s", raw)
	}
	a.fake.failWith("Saved", &provider.Error{Kind: provider.ErrNetwork})
	a.want("POST", "/ai/profiles/test", "admin", body, 502, "unreachable")
	a.fake.failWith("Saved", &provider.Error{Kind: provider.ErrServer, Status: 500})
	a.want("POST", "/ai/profiles/test", "admin", body, 502, "provider_error")
	a.want("POST", "/ai/profiles/test", "admin", `{"id":"p-missing",`+strings.Replace(cloudBody("x", ""), `"api_key":"",`, "", 1)[1:], 404, "not_found")
	// a draft that breaks a rule is refused before any request is made
	before := a.fake.total()
	a.want("POST", "/ai/profiles/test", "admin", strings.Replace(cloudBody("D", keyA), "https://api.anthropic.com", "http://api.anthropic.com", 1), 400, "invalid_base_url")
	if a.fake.total() != before {
		t.Fatal("an invalid draft reached the provider")
	}
	// the test is audited without the key, and counts in the usage of the profile
	for _, row := range a.auditRows() {
		if strings.Contains(row, keyA) {
			t.Fatalf("audit row holds the key: %s", row)
		}
	}
	a.fake.failWith("Saved", nil)
	a.want("POST", "/ai/profiles/test", "admin", body, 200, "")
	list := a.want("GET", "/ai/profiles", "viewer", "", 200, "")["items"].([]any)
	if used := list[0].(map[string]any)["used_today"]; used != float64(14+3) {
		t.Fatalf("used_today = %v, want the one probe call that got an answer", used)
	}
}

func TestContract_INV20_EveryChangeIsAudited(t *testing.T) {
	a := newAPI(t)
	p := a.addProfile(cloudBody("Claude", keyA))["id"].(string)
	a.want("PUT", "/ai/profiles/"+p, "admin", cloudBody("Claude 2", keyB), 200, "")
	a.want("PUT", "/ai/assignments", "admin", assignBody(false, map[string][2]string{"cve-news": {p, ""}}), 200, "")
	a.want("PUT", "/ai/config", "admin", `{"tier":"min","daily_cap":10000,"redact_pii":true}`, 200, "")
	a.want("POST", "/ai/profiles/test", "admin", cloudBody("Draft", keyA), 200, "")
	a.want("DELETE", "/ai/profiles/"+p, "admin", "", 200, "")
	// refused changes leave no row
	a.want("POST", "/ai/profiles", "admin", cloudBody("Bad", "x"), 400, "invalid_key")
	got := a.auditRows()
	want := []string{"ai.profile.add Claude", "ai.profile.edit Claude 2", "ai.assign jobs", "ai.config tier", "ai.test Draft", "ai.profile.remove Claude 2"}
	if len(got) != len(want) {
		t.Fatalf("audit rows = %q", got)
	}
	for i, w := range want {
		if !strings.HasPrefix(got[i], w) {
			t.Errorf("audit row %d = %q, want prefix %q", i, got[i], w)
		}
		if strings.Contains(got[i], keyA) || strings.Contains(got[i], keyB) {
			t.Errorf("audit row %d holds a key", i)
		}
	}
	var user string
	if err := a.db.Reader().QueryRowContext(a.ctx(), `SELECT user FROM core_audit WHERE action = 'ai.profile.add'`).Scan(&user); err != nil || user != "admin@acme.example" {
		t.Fatalf("audit user = %q, %v", user, err)
	}
}

func TestAssignmentSuggestion(t *testing.T) {
	a := newAPI(t)
	haiku := a.addProfile(cloudBody("Haiku", keyA))["id"].(string)
	opus := a.addProfile(strings.Replace(cloudBody("Opus", keyB), "claude-haiku-5-5", "claude-opus-5", 1))["id"].(string)
	local := a.addProfile(internalBody("Local"))["id"].(string)
	got := a.want("GET", "/ai/assignments/suggestion?internal_only=false", "viewer", "", 200, "")
	jobs := got["jobs"].(map[string]any)
	pick := func(j string) any { return jobs[j].(map[string]any)["primary"] }
	if got["internal_only"] != false || pick("log-digest") != local || pick("cve-news") != haiku || pick("explain-finding") != opus {
		t.Fatalf("suggestion = %v (haiku %s opus %s local %s)", got, haiku, opus, local)
	}
	got = a.want("GET", "/ai/assignments/suggestion?internal_only=true", "viewer", "", 200, "")
	jobs = got["jobs"].(map[string]any)
	if got["internal_only"] != true || pick("explain-finding") != local || jobs["explain-finding"].(map[string]any)["fallback"] != nil || pick("cve-news") == nil {
		t.Fatalf("suggestion under the rule = %v", got)
	}
	// the suggestion is never saved
	if cur := a.want("GET", "/ai/assignments", "viewer", "", 200, ""); cur["internal_only"] != false {
		t.Fatalf("assignments changed: %v", cur)
	}
	a.want("GET", "/ai/assignments/suggestion", "viewer", "", http.StatusBadRequest, "")
}

func TestPRE3_AnthropicKeyWithoutWorkspaceSaysWhatToDo(t *testing.T) {
	a := newAPI(t)
	a.fake.failWith("Draft", &provider.Error{Kind: provider.ErrNoWorkspace, Status: 400})
	m := a.want("POST", "/ai/profiles/test", "admin", cloudBody("Draft", keyA), 502, "provider_error")
	msg := m["error"].(map[string]any)["message"].(string)
	if !strings.Contains(msg, "not tied to a workspace") || !strings.Contains(msg, "inside a workspace") || strings.Contains(msg, "AAAA1111") {
		t.Fatalf("message = %q", msg)
	}
}

// response-plan runs by itself and sends device data, so a new profile is not assigned to it on its own (D-181).
func TestFirstProfileIsNotAssignedToTheAutomaticResponsePlanJob(t *testing.T) {
	a := newAPI(t)
	p := a.addProfile(cloudBody("One", keyA))["id"].(string)
	jobs := a.want("GET", "/ai/assignments", "viewer", "", 200, "")["jobs"].(map[string]any)
	if s := jobs["response-plan"].(map[string]any); s["primary"] != nil {
		t.Fatalf("response-plan = %v", s)
	}
	if s := jobs["ask-my-data"].(map[string]any); s["primary"] != p {
		t.Fatalf("ask-my-data = %v", s)
	}
}

func TestSuggestionDoesNotFillTheAutomaticResponsePlanJob(t *testing.T) {
	a := newAPI(t)
	a.addProfile(cloudBody("One", keyA))
	jobs := a.want("GET", "/ai/assignments/suggestion?internal_only=false", "viewer", "", 200, "")["jobs"].(map[string]any)
	if s := jobs["response-plan"].(map[string]any); s["primary"] != nil {
		t.Fatalf("response-plan = %v", s)
	}
	if s := jobs["ask-my-data"].(map[string]any); s["primary"] == nil {
		t.Fatalf("ask-my-data = %v", s)
	}
}
