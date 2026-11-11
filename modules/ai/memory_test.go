package ai_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
)

// Slice 4b of WP-25: memory and skills (S-AI-7, INV-8, INV-20). The GUI mock is the contract.

func memBody(text string) string {
	raw, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// suggest puts a waiting suggestion in the table, as the producer of slice 5 will: nothing in 4b creates one.
func (a *api) suggest(id, text string) {
	a.t.Helper()
	if err := a.exec(fmt.Sprintf(`INSERT INTO ai_memory_suggestion (id, text, created_at, evidence) VALUES (%q, %q, '2026-11-10T03:00:00.000Z', 'log summary of 7 Nov')`, id, text)); err != nil {
		a.t.Fatal(err)
	}
}

func (a *api) memoryView() map[string]any { return a.want("GET", "/ai/memory", "admin", "", 200, "") }

func (a *api) addMemory(text string) map[string]any {
	a.t.Helper()
	return a.want("POST", "/ai/memory", "admin", memBody(text), 200, "")
}

// planRequest runs one response-plan call and returns what the provider received.
func (a *api) planRequest(job ai.Job, id string) provider.Request {
	a.t.Helper()
	a.want("PUT", "/ai/assignments", "admin", assignBody(false, map[string][2]string{string(job): {id, ""}}), 200, "")
	_, err := a.newService().RunJob(a.ctx(), ai.JobSpec{Job: job, Actor: "system", Task: "Do it.", Question: "Go.",
		Data: []ai.DataBlock{{Kind: ai.DataLog, Source: "x", Text: "a log line"}}, Schema: &provider.Schema{Name: "s", JSON: []byte(`{"type":"object"}`)}, MaxTokens: 100})
	if err != nil {
		a.t.Fatal(err)
	}
	return a.fake.lastRequest(a.t)
}

func TestMemoryRolesAndModuleGate(t *testing.T) {
	gate := servertest.NewGate()
	a := newAPIGate(t, gate)
	routes := [][2]string{
		{"GET", "/ai/memory"}, {"POST", "/ai/memory"}, {"PUT", "/ai/memory/mem-x"}, {"DELETE", "/ai/memory/mem-x"}, {"PUT", "/ai/memory/settings"},
		{"POST", "/ai/memory/suggestions/sg-x/accept"}, {"POST", "/ai/memory/suggestions/sg-x/reject"},
		{"GET", "/ai/skills"}, {"PUT", "/ai/skills/log-digest"},
	}
	for _, r := range routes {
		a.want(r[0], r[1], "", "{}", 401, "unauthenticated")
		for _, u := range []string{"viewer", "operator"} {
			a.want(r[0], r[1], u, "{}", 403, "forbidden")
		}
	}
	a.want("GET", "/ai/memory", "admin", "", 200, "")
	a.want("GET", "/ai/skills", "admin", "", 200, "")
	gate.Set("ai", false)
	for _, r := range routes {
		if status, _, body := a.do(r[0], r[1], "admin", memBody("Name every device.")); status != 404 {
			t.Errorf("%s %s with the module off = %d, want 404: %s", r[0], r[1], status, body)
		}
	}
	gate.Set("ai", true)
	a.want("GET", "/ai/memory", "admin", "", 200, "")
}

func TestContract_INV8_MemoryCrudAndShape(t *testing.T) {
	a := newAPI(t)
	v := a.memoryView()
	if v["suggest_enabled"] != false || len(v["items"].([]any)) != 0 || len(v["suggestions"].([]any)) != 0 {
		t.Fatalf("empty view = %v", v)
	}
	m := a.addMemory("  NAS-PHOTOS is reachable\n from the   Internet. ")
	id := m["id"].(string)
	if m["text"] != "NAS-PHOTOS is reachable from the Internet." || m["source"] != "user" || m["enabled"] != true || m["last_used_at"] != nil || id == "" || m["created_at"] == "" {
		t.Fatalf("memory = %v", m)
	}
	second := a.addMemory("The camera VLAN is 192.168.20.0/24.")["id"].(string)
	if items := a.memoryView()["items"].([]any); len(items) != 2 || items[0].(map[string]any)["id"] != second {
		t.Fatalf("newest first expected: %v", items)
	}
	e := a.want("PUT", "/ai/memory/"+id, "admin", `{"enabled":false}`, 200, "")
	if e["enabled"] != false || e["text"] != "NAS-PHOTOS is reachable from the Internet." || e["source"] != "user" {
		t.Fatalf("patched = %v", e)
	}
	e = a.want("PUT", "/ai/memory/"+id, "admin", `{"text":"NAS-PHOTOS is not reachable."}`, 200, "")
	if e["text"] != "NAS-PHOTOS is not reachable." || e["enabled"] != false {
		t.Fatalf("patched = %v", e)
	}
	a.want("PUT", "/ai/memory/"+id, "admin", `{}`, 200, "") // nothing to change is not an error, as the mock
	b := &api{env: a.env, h: a.handler(servertest.NewGate())}
	a.svc = a.newService() // a restart loses nothing
	if items := b.memoryView()["items"].([]any); len(items) != 2 {
		t.Fatalf("after a restart: %v", items)
	}
	if status, _, raw := b.do("DELETE", "/ai/memory/"+id, "admin", ""); status != 204 {
		t.Fatalf("delete = %d %s", status, raw)
	}
	b.want("DELETE", "/ai/memory/"+id, "admin", "", 404, "not_found")
	b.want("PUT", "/ai/memory/"+id, "admin", `{"enabled":true}`, 404, "not_found")
	b.want("PUT", "/ai/memory/mem-missing", "admin", memBody("Something to remember."), 404, "not_found")
	rows := strings.Join(b.auditRows(), "\n")
	for _, want := range []string{"ai.memory.add " + id, "ai.memory.add " + second, "ai.memory.edit " + id, "ai.memory.remove " + id} {
		if !strings.Contains(rows, want) {
			t.Errorf("audit lacks %q: %s", want, rows)
		}
	}
	if strings.Contains(rows, "reachable") {
		t.Errorf("the audit log holds the text of a memory: %s", rows)
	}
}

func TestContract_INV8_MemoryLimitsAndStrictJSON(t *testing.T) {
	a := newAPI(t)
	for _, n := range []int{0, 1, 2, 301, 1000} {
		a.want("POST", "/ai/memory", "admin", memBody(strings.Repeat("x", n)), 400, "") // the length of the text is also in the schema, which answers first
	}
	for _, s := range []string{"abc\u200bdef", "abc\u202edef", "abc\x00def", "   ab   "} {
		a.want("POST", "/ai/memory", "admin", memBody(s), 400, "invalid_memory")
	}
	a.addMemory(strings.Repeat("é", 3))
	id := a.addMemory(strings.Repeat("é", 300))["id"].(string) // characters, not bytes
	a.want("PUT", "/ai/memory/"+id, "admin", memBody("ab"), 400, "")
	a.want("PUT", "/ai/memory/"+id, "admin", memBody("abc\u200bdef"), 400, "invalid_memory")
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/ai/memory", `{"text":"Something to remember.","source":"ai"}`},
		{"POST", "/ai/memory", `{"text":"Something to remember.","enabled":false}`},
		{"POST", "/ai/memory", `{"text":"Something to remember."} {"x":1}`},
		{"POST", "/ai/memory", `[]`},
		{"PUT", "/ai/memory/" + id, `{"text":"Something to remember.","id":"mem-evil"}`},
		{"PUT", "/ai/memory/" + id, `{"enabled":"yes"}`},
		{"PUT", "/ai/memory/settings", `{"suggest_enabled":true,"x":1}`},
		{"PUT", "/ai/memory/settings", `{}`},
		{"PUT", "/ai/memory/settings", `{"suggest_enabled":"on"}`},
	} {
		if status, _, raw := a.do(c.method, c.path, "admin", c.body); status != 400 {
			t.Errorf("%s %s %s = %d, want 400: %s", c.method, c.path, c.body, status, raw)
		}
	}
	if n := len(a.memoryView()["items"].([]any)); n != 2 {
		t.Fatalf("refused requests wrote something: %d", n)
	}
	for i := 2; i < 100; i++ {
		a.addMemory(fmt.Sprintf("Memory number %d.", i))
	}
	a.want("POST", "/ai/memory", "admin", memBody("One too many."), 400, "too_many")
	// the database refuses the 101st too, whatever the code says
	if err := a.exec(`INSERT INTO ai_memory (id, text, source, created_at, enabled) VALUES ('mem-x', 'abc', 'user', '2026-11-10T03:00:00.000Z', 1)`); err == nil {
		t.Fatal("the table took a 101st memory")
	}
}

func TestContract_INV8_SuggestionsAcceptRejectAndSettings(t *testing.T) {
	a := newAPI(t)
	a.suggest("sg-1", "The accounting team uses the file server over SMB.")
	a.suggest("sg-2", "Backups run every night at 01:00.")
	v := a.memoryView()
	sg := v["suggestions"].([]any)
	if len(sg) != 2 || len(v["items"].([]any)) != 0 || sg[0].(map[string]any)["evidence"] != "log summary of 7 Nov" || sg[0].(map[string]any)["id"] != "sg-1" {
		t.Fatalf("view = %v", v)
	}
	m := a.want("POST", "/ai/memory/suggestions/sg-1/accept", "admin", "", 200, "")
	if m["source"] != "ai" || m["enabled"] != true || m["text"] != "The accounting team uses the file server over SMB." || m["id"] == "sg-1" {
		t.Fatalf("accepted = %v", m)
	}
	if status, _, raw := a.do("POST", "/ai/memory/suggestions/sg-2/reject", "admin", ""); status != 204 {
		t.Fatalf("reject = %d %s", status, raw)
	}
	v = a.memoryView()
	if len(v["suggestions"].([]any)) != 0 || len(v["items"].([]any)) != 1 {
		t.Fatalf("view = %v", v)
	}
	a.want("POST", "/ai/memory/suggestions/sg-1/accept", "admin", "", 404, "not_found")
	a.want("POST", "/ai/memory/suggestions/sg-2/accept", "admin", "", 404, "not_found")
	a.want("POST", "/ai/memory/suggestions/sg-2/reject", "admin", "", 404, "not_found")
	a.want("POST", "/ai/memory/suggestions/sg-none/reject", "admin", "", 404, "not_found")
	if n := len(a.memoryView()["items"].([]any)); n != 1 {
		t.Fatalf("a repeated accept made another memory: %d", n)
	}
	// settings: the view comes back
	v = a.want("PUT", "/ai/memory/settings", "admin", `{"suggest_enabled":true}`, 200, "")
	if v["suggest_enabled"] != true || len(v["items"].([]any)) != 1 {
		t.Fatalf("settings view = %v", v)
	}
	a.svc = a.newService()
	if a.memoryView()["suggest_enabled"] != true {
		t.Fatal("the switch did not survive a restart")
	}
	rows := strings.Join(a.auditRows(), "\n")
	for _, want := range []string{"ai.memory.accept " + m["id"].(string), "ai.memory.reject sg-2", "ai.memory.settings suggest on"} {
		if !strings.Contains(rows, want) {
			t.Errorf("audit lacks %q: %s", want, rows)
		}
	}
	// a full memory keeps the suggestion waiting
	for i := 1; i < 100; i++ {
		a.addMemory(fmt.Sprintf("Memory number %d.", i))
	}
	a.suggest("sg-3", "One more thing to remember.")
	a.want("POST", "/ai/memory/suggestions/sg-3/accept", "admin", "", 400, "too_many")
	if len(a.memoryView()["suggestions"].([]any)) != 1 {
		t.Fatal("the suggestion was lost")
	}
}

func TestContract_INV8_AcceptAndRejectAreRaceSafe(t *testing.T) {
	a := newAPI(t)
	a.suggest("sg-1", "The accounting team uses the file server over SMB.")
	a.suggest("sg-2", "Backups run every night at 01:00.")
	var wg sync.WaitGroup
	var acc, gone atomic.Int32
	count := func(status int) {
		switch status {
		case 200, 204:
			acc.Add(1)
		case 404:
			gone.Add(1)
		default:
			t.Errorf("status %d", status)
		}
	}
	for range 12 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			s, _, _ := a.do("POST", "/ai/memory/suggestions/sg-1/accept", "admin", "")
			count(s)
		}()
		go func() {
			defer wg.Done()
			s, _, _ := a.do("POST", "/ai/memory/suggestions/sg-2/reject", "admin", "")
			count(s)
		}()
	}
	wg.Wait()
	if acc.Load() != 2 || gone.Load() != 22 {
		t.Fatalf("ok = %d, 404 = %d, want 2 and 22", acc.Load(), gone.Load())
	}
	if n := len(a.memoryView()["items"].([]any)); n != 1 {
		t.Fatalf("memories = %d, want 1", n)
	}
	// accept and reject racing on the same suggestion: one wins, the other is a 404
	for i := range 5 {
		id := fmt.Sprintf("sg-r%d", i)
		a.suggest(id, "Raced suggestion "+id)
		var wins atomic.Int32
		var w2 sync.WaitGroup
		for _, act := range []string{"accept", "reject"} {
			w2.Add(1)
			go func() {
				defer w2.Done()
				if s, _, _ := a.do("POST", "/ai/memory/suggestions/"+id+"/"+act, "admin", ""); s != 404 {
					wins.Add(1)
				}
			}()
		}
		w2.Wait()
		if wins.Load() != 1 {
			t.Fatalf("%s: %d winners", id, wins.Load())
		}
	}
}

func TestContract_INV8_AiSuggestsOnlyWhenAllowed(t *testing.T) {
	a := newAPI(t)
	if err := a.svc.SuggestMemory(a.ctx(), "The accounting team uses the file server over SMB.", "log summary of 7 Nov"); err == nil {
		t.Fatal("a suggestion was stored while suggestions are off")
	}
	if n := len(a.memoryView()["suggestions"].([]any)); n != 0 {
		t.Fatalf("suggestions = %d", n)
	}
	a.want("PUT", "/ai/memory/settings", "admin", `{"suggest_enabled":true}`, 200, "")
	if err := a.svc.SuggestMemory(a.ctx(), "The accounting team uses the file server over SMB.", "log summary of 7 Nov"); err != nil {
		t.Fatal(err)
	}
	if err := a.svc.SuggestMemory(a.ctx(), "  The accounting team uses the file server over SMB. ", "again"); err != nil { // the same text twice is one suggestion
		t.Fatal(err)
	}
	a.addMemory("Backups run every night at 01:00.")
	if err := a.svc.SuggestMemory(a.ctx(), "Backups run every night at 01:00.", "again"); err != nil { // already remembered
		t.Fatal(err)
	}
	for _, bad := range [][2]string{{"no", "evidence"}, {"A fine suggestion.", ""}, {"abc\u200bdef", "x"}, {"A fine suggestion.", "a\u200bb"}, {strings.Repeat("x", 301), "x"}} {
		if err := a.svc.SuggestMemory(a.ctx(), bad[0], bad[1]); err == nil {
			t.Errorf("SuggestMemory(%q, %q) was accepted", bad[0], bad[1])
		}
	}
	if sg := a.memoryView()["suggestions"].([]any); len(sg) != 1 {
		t.Fatalf("suggestions = %v", sg)
	}
	a.want("PUT", "/ai/memory/settings", "admin", `{"suggest_enabled":false}`, 200, "")
	if err := a.svc.SuggestMemory(a.ctx(), "Another fact about the network.", "x"); err == nil {
		t.Fatal("a suggestion was stored after the switch went off")
	}
	a.want("PUT", "/ai/memory/settings", "admin", `{"suggest_enabled":true}`, 200, "")
	for i := 1; i < 50; i++ {
		if err := a.svc.SuggestMemory(a.ctx(), fmt.Sprintf("Suggested fact number %d.", i), "x"); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.svc.SuggestMemory(a.ctx(), "One suggestion too many.", "x"); err == nil {
		t.Fatal("the 51st waiting suggestion was stored")
	}
	if rows := strings.Join(a.auditRows(), "\n"); !strings.Contains(rows, "ai.memory.suggest") {
		t.Errorf("the audit log lacks the suggestion: %s", rows)
	}
}

// INV-8: only a memory an administrator wrote or accepted, and left on, reaches the provider; it goes as fenced data, never in the
// instructions, and after the before-AI hooks.
func TestContract_INV8_OnlyAcceptedMemoryReachesTheProvider(t *testing.T) {
	a := newAPI(t)
	id := a.withProfile()
	a.suggest("sg-pending", "PENDING-FACT is waiting for an answer.")
	a.suggest("sg-rejected", "REJECTED-FACT was refused.")
	a.suggest("sg-accepted", "ACCEPTED-FACT was approved.")
	a.want("POST", "/ai/memory/suggestions/sg-rejected/reject", "admin", "", 204, "")
	a.want("POST", "/ai/memory/suggestions/sg-accepted/accept", "admin", "", 200, "")
	a.addMemory("TYPED-FACT was written by hand.")
	off := a.addMemory("DISABLED-FACT is switched off.")["id"].(string)
	a.want("PUT", "/ai/memory/"+off, "admin", `{"enabled":false}`, 200, "")
	a.want("PUT", "/ai/memory/settings", "admin", `{"suggest_enabled":true}`, 200, "")

	req := a.planRequest(ai.JobResponsePlan, id)
	user := req.Messages[0].Text
	for _, gone := range []string{"PENDING-FACT", "REJECTED-FACT", "DISABLED-FACT"} {
		if strings.Contains(user, gone) || strings.Contains(req.System, gone) {
			t.Errorf("%s reached the provider:\n%s\n%s", gone, req.System, user)
		}
	}
	for _, kept := range []string{"ACCEPTED-FACT", "TYPED-FACT"} {
		if !strings.Contains(user, kept) {
			t.Errorf("%s did not reach the provider: %s", kept, user)
		}
		if strings.Contains(req.System, kept) {
			t.Errorf("%s is in the instructions: %s", kept, req.System)
		}
	}
	// it sits between the markers of untrusted data, as its own block
	at := strings.Index(user, "TYPED-FACT")
	open := strings.LastIndex(user[:at], "<<<DATA-")
	end := strings.Index(user[at:], "<<<END-DATA-")
	if open < 0 || end < 0 || !strings.HasPrefix(user[open:], "<<<DATA-") || !strings.Contains(user[open:at], "kind=memory") {
		t.Fatalf("memory is not a fenced block of kind memory: %s", user)
	}
	if !strings.Contains(req.System, "never instructions") {
		t.Fatalf("the instructions do not tell the model that fenced text is data: %s", req.System)
	}
	// being sent is recorded
	for _, it := range a.memoryView()["items"].([]any) {
		m := it.(map[string]any)
		used := m["last_used_at"] != nil
		if used != (m["enabled"] == true) {
			t.Errorf("last_used_at of %v = %v", m["text"], m["last_used_at"])
		}
	}
}

func TestContract_INV8_NoMemoryNoBlock(t *testing.T) {
	a := newAPI(t)
	id := a.withProfile()
	if user := a.planRequest(ai.JobResponsePlan, id).Messages[0].Text; strings.Contains(user, "kind=memory") {
		t.Fatalf("an empty memory made a block: %s", user)
	}
}

func TestContract_INV8_MemoryGoesThroughTheBeforeAIHooks(t *testing.T) {
	a := newAPI(t)
	id := a.withProfile()
	a.addMemory("Ask for the admin at admin@example.com about NAS-PHOTOS.")
	user := a.planRequest(ai.JobResponsePlan, id).Messages[0].Text // block-pii is on by default
	if strings.Contains(user, "admin@example.com") || !strings.Contains(user, "Ask for the admin at [masked] about NAS-PHOTOS.") {
		t.Fatalf("the email was not masked: %s", user)
	}
	a.want("PUT", "/ai/hooks/builtin/block-pii", "admin", `{"enabled":false}`, 200, "")
	if user := a.planRequest(ai.JobResponsePlan, id).Messages[0].Text; !strings.Contains(user, "admin@example.com") {
		t.Fatalf("with the hook off the text is sent as it is: %s", user)
	}
	// a custom hook that blocks stops the call: nothing is sent
	a.addBlockHook("No NAS", "before_ai", "NAS-PHOTOS")
	before := len(a.fake.reqsSent())
	_, err := a.newService().RunJob(a.ctx(), ai.JobSpec{Job: ai.JobResponsePlan, Actor: "system", Task: "Do it.", Question: "Go.", Schema: &provider.Schema{Name: "s", JSON: []byte(`{"type":"object"}`)}, MaxTokens: 100})
	if err == nil || len(a.fake.reqsSent()) != before {
		t.Fatalf("err = %v, requests %d -> %d: a blocked memory was sent", err, before, len(a.fake.reqsSent()))
	}
}

// Memory is internal data: a job that sends only public text (CVE news, advisory translation) must not carry it to a cloud profile.
func TestContract_INV8_MemoryDoesNotGoWithPublicJobs(t *testing.T) {
	a := newAPI(t)
	id := a.withProfile()
	a.addMemory("INTERNAL-FACT about the camera VLAN.")
	for _, j := range []ai.Job{ai.JobCVENews, ai.JobTranslateAdvisory} {
		req := a.planRequest(j, id)
		if strings.Contains(req.Messages[0].Text, "INTERNAL-FACT") || strings.Contains(req.System, "INTERNAL-FACT") {
			t.Errorf("%s carried memory", j)
		}
	}
	if !strings.Contains(a.planRequest(ai.JobLogDigest, id).Messages[0].Text, "INTERNAL-FACT") {
		t.Error("log-digest did not carry memory")
	}
}

func (f *fakeProviders) reqsSent() []provider.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]provider.Request(nil), f.reqs...)
}
