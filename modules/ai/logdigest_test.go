package ai_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/knt048/vedette/modules/ai"
)

// The AI log digest (S-AI-4, INV-3, INV-6, INV-12, D-221).

// fakeLogs is the digest of the logs module as the port hands it over.
type fakeLogs struct {
	mu   sync.Mutex
	on   bool
	data ai.LogDigestData
	err  error
}

func (f *fakeLogs) read(context.Context) (ai.LogDigestData, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.data, f.on, f.err
}

func (f *fakeLogs) set(d ai.LogDigestData) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data = d
}

func someDigest() ai.LogDigestData {
	name := "PC-ACCOUNTS-03"
	return ai.LogDigestData{Lines24h: 5230, BaselineDays: 7,
		New:            []ai.LogDigestNew{{Signature: "sshd: Failed password for invalid user <*> from <ip> port <n>", SourceName: "FW-HQ", Count: 1240, FirstSeen: "2026-11-10T01:00:00Z"}},
		Spikes:         []ai.LogDigestSpike{{Signature: "kernel: DROP IN=eth0 SRC=<ip>", SourceName: "FW-HQ", Count: 9000, BaselinePerDay: 120}},
		BadConnections: []ai.LogDigestBadConn{{TS: "2026-11-10T02:00:00Z", AssetName: &name, SrcIP: "192.168.10.103", Dest: "185.220.101.47", DestKind: "ip", SeenVia: "span_flow", Feeds: []string{"tor-exit"}, Confidence: 0.92}}}
}

const goodDigest = `{"summary":"Look at PC-ACCOUNTS-03 first.","items":[{"severity":"high","title":"PC-ACCOUNTS-03 connects to a listed address","evidence":["185.220.101.47 (tor-exit), seen via span_flow"],"recommendation":"Isolate the device and scan it."},{"severity":"info","title":"New kind of line from FW-HQ","evidence":[],"recommendation":"Check the logon failures."}]}`

func (a *api) digest(method, user string, status int, code string) map[string]any {
	a.t.Helper()
	return a.want(method, "/ai/logs/digest", user, "", status, code)
}

func digestOf(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	d, ok := m["digest"].(map[string]any)
	if !ok {
		t.Fatalf("digest = %v", m["digest"])
	}
	return d
}

func TestLogDigestRunsAndIsCached(t *testing.T) {
	a := newAPI(t)
	a.logs.set(someDigest())
	// nothing generated yet: GET says so without an AI call
	if m := a.digest("GET", "viewer", 200, ""); m["digest"] != nil || a.fake.total() != 0 {
		t.Fatalf("GET before = %v, calls %d", m, a.fake.total())
	}
	// no profile: the documented 409, the viewer cannot generate
	a.digest("POST", "viewer", 403, "")
	a.digest("POST", "operator", 409, "ai_unavailable")
	a.addProfile(cloudBody("Claude", keyA))
	a.fake.setAnswer(goodDigest)
	d := digestOf(t, a.digest("POST", "operator", 200, ""))
	items := d["items"].([]any)
	if d["summary"] != "Look at PC-ACCOUNTS-03 first." || len(items) != 2 || d["empty"] != false || d["profile"] != "Claude" || d["tier"] != "med" || len(d["tool_calls"].([]any)) != 0 {
		t.Fatalf("digest = %v", d)
	}
	if first := items[0].(map[string]any); first["severity"] != "high" || first["evidence"].([]any)[0] == "" {
		t.Fatalf("item = %v", first)
	}
	calls := a.fake.total()
	// GET returns the stored result with no AI call (INV-6), and so does a second POST from the same inputs
	if got := digestOf(t, a.digest("GET", "viewer", 200, "")); got["generated_at"] != d["generated_at"] || got["summary"] != d["summary"] {
		t.Fatalf("GET = %v", got)
	}
	a.digest("POST", "operator", 200, "")
	if a.fake.total() != calls {
		t.Fatalf("calls %d -> %d: the same inputs were sent again", calls, a.fake.total())
	}
	// other counts are other inputs
	next := someDigest()
	next.Lines24h++
	a.logs.set(next)
	a.digest("POST", "operator", 200, "")
	if a.fake.total() != calls+1 {
		t.Fatalf("calls = %d, want %d", a.fake.total(), calls+1)
	}
	// the call is in the log of calls and the activity log, with counts and no content
	rows := a.activity()
	last := rows[len(rows)-1]
	if last.Job != "log-digest" || last.Result != ai.ResultOK || !strings.Contains(last.Summary, "1 new kinds of line, 1 spikes, 1 bad connections") || strings.Contains(last.Summary, "PC-ACCOUNTS") {
		t.Fatalf("row = %+v", last)
	}
}

func TestLogDigestSendsKindsAndCountsNeverLines(t *testing.T) {
	a := newAPI(t)
	a.addProfile(cloudBody("Claude", keyA))
	a.fake.setAnswer(goodDigest)
	// the answer of logs as JSON, with the sample line of every item and extra fields: the port type has no field for them
	raw := `{"generated_at":"2026-11-10T03:00:00Z","lines_24h":10,"baseline_days":7,"new":[{"id":"n1","signature":"sshd: Failed password for <*>","source_id":"src1","source_name":"FW-HQ","count":3,"first_seen":"2026-11-10T01:00:00Z","sample":"<34>Nov 10 sshd[1]: Failed password for root from 10.9.8.7 SAMPLELINEMARK"}],"spikes":[{"id":"s1","signature":"drop","source_id":"src1","source_name":"FW-HQ","count":5,"baseline_per_day":1.5,"sample":"SAMPLELINEMARK2"}],"bad_connections":[]}`
	var in ai.LogDigestData
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatal(err)
	}
	a.logs.set(in)
	a.digest("POST", "operator", 200, "")
	sent := fmt.Sprintf("%+v", a.fake.lastRequest(t))
	for _, want := range []string{"Failed password for <*>", "FW-HQ", "3 lines"} {
		if !strings.Contains(sent, want) {
			t.Errorf("the request lacks %q", want)
		}
	}
	for _, bad := range []string{"SAMPLELINEMARK", "10.9.8.7", "sample"} {
		if strings.Contains(sent, bad) {
			t.Errorf("the request carries %q", bad)
		}
	}
}

func TestLogDigestTextIsBoundedAndCheckedByTheHooks(t *testing.T) {
	a := newAPI(t)
	a.addProfile(cloudBody("Claude", keyA))
	a.fake.setAnswer(goodDigest)
	d := someDigest()
	d.New = nil
	for i := 0; i < 100; i++ {
		d.New = append(d.New, ai.LogDigestNew{Signature: strings.Repeat("x", 5000) + " admin@example.com", SourceName: strings.Repeat("n", 500), Count: i})
	}
	a.logs.set(d)
	a.digest("POST", "operator", 200, "")
	sent := fmt.Sprintf("%+v", a.fake.lastRequest(t))
	if strings.Contains(sent, "admin@example.com") {
		t.Errorf("an email address in a signature reached the provider")
	}
	if n := strings.Count(sent, "xxxxxxxxxx"); n == 0 || len(sent) > 20000 || strings.Contains(sent, strings.Repeat("x", 201)) {
		t.Errorf("the request is not bounded: %d bytes", len(sent))
	}
	// a hook that blocks stops the call before the provider
	a.addBlockHook("No Tor", "before_ai", "tor-exit")
	calls := a.fake.total()
	a.logs.set(someDigest())
	a.digest("POST", "operator", 409, "ai_unavailable")
	if a.fake.total() != calls {
		t.Fatalf("the provider was asked after a block")
	}
}

func TestLogDigestEmptyAsksNothing(t *testing.T) {
	a := newAPI(t)
	a.addProfile(cloudBody("Claude", keyA))
	a.fake.setAnswer(goodDigest)
	for _, m := range []map[string]any{a.digest("GET", "viewer", 200, ""), a.digest("POST", "operator", 200, "")} {
		d := digestOf(t, m)
		if d["empty"] != true || d["tokens"].(map[string]any)["input"] != float64(0) || !strings.Contains(d["summary"].(string), "no log events") {
			t.Fatalf("digest = %v", d)
		}
	}
	if a.fake.total() != 0 || len(a.activity()) != 0 {
		t.Fatalf("an empty digest asked the AI: %d calls", a.fake.total())
	}
}

func TestLogDigestModuleOffAndErrors(t *testing.T) {
	a := newAPI(t)
	a.addProfile(cloudBody("Claude", keyA))
	a.fake.setAnswer(goodDigest)
	a.logs.set(someDigest())
	a.logs.mu.Lock()
	a.logs.on = false
	a.logs.mu.Unlock()
	for _, m := range []string{"GET", "POST"} {
		msg := a.digest(m, "operator", 409, "ai_unavailable")["error"].(map[string]any)["message"].(string)
		if !strings.Contains(msg, "logs module") {
			t.Errorf("%s message = %q", m, msg)
		}
	}
	a.logs.mu.Lock()
	a.logs.on, a.logs.err = true, errors.New("disk on fire")
	a.logs.mu.Unlock()
	if code, _, raw := a.do("POST", "/ai/logs/digest", "operator", ""); code != 500 || strings.Contains(raw, "fire") {
		t.Fatalf("a read error = %d %s", code, raw)
	}
	if a.fake.total() != 0 {
		t.Fatal("the AI was asked without a digest")
	}
}

func TestLogDigestBadAnswersAreDiscarded(t *testing.T) {
	a := newAPI(t)
	a.addProfile(cloudBody("Claude", keyA))
	a.logs.set(someDigest())
	for name, ans := range map[string]string{
		"not json":      "here is the digest",
		"unknown field": `{"summary":"s","items":[],"extra":1}`,
		"missing items": `{"summary":"s"}`,
		"bad severity":  `{"summary":"s","items":[{"severity":"critical","title":"t","evidence":[],"recommendation":"r"}]}`,
		"empty summary": `{"summary":" ","items":[]}`,
	} {
		a.fake.setAnswer(ans)
		a.digest("POST", "operator", 409, "ai_unavailable")
		if got := a.digest("GET", "viewer", 200, ""); got["digest"] != nil {
			t.Errorf("%s: a bad answer was stored: %v", name, got)
		}
	}
	runs := a.want("GET", "/ai/runs", "viewer", "", 200, "")["items"].([]any)
	if runs[0].(map[string]any)["status"] != "schema_error" {
		t.Fatalf("runs[0] = %v", runs[0])
	}
}

func TestLogDigestInternalDataOnlyGoesToInternalProfiles(t *testing.T) {
	a := newAPI(t)
	c := a.addProfile(cloudBody("Claude", keyA))["id"].(string)
	i := a.addProfile(internalBody("Ollama"))["id"].(string)
	a.fake.setAnswer(goodDigest)
	a.logs.set(someDigest())
	a.assign(true, ai.JobLogDigest, i, "")
	a.digest("POST", "operator", 200, "")
	if a.fake.called("Claude") != 0 || a.fake.called("Ollama") != 1 {
		t.Fatalf("calls: Claude %d, Ollama %d", a.fake.called("Claude"), a.fake.called("Ollama"))
	}
	// the cloud profile as the only choice is refused by the rule before the digest is read
	a.want("PUT", "/ai/assignments", "admin", assignBody(true, map[string][2]string{"log-digest": {c, ""}}), 400, "privacy_rule")
}

func TestLogDigestAnswerGoesThroughTheAfterAIHooks(t *testing.T) {
	a := newAPI(t)
	a.addProfile(cloudBody("Claude", keyA))
	a.logs.set(someDigest())
	a.addBlockHook("No mail", "after_ai", "boss@example.com")
	a.fake.setAnswer(strings.Replace(goodDigest, "Isolate the device and scan it.", "Mail the report to boss@example.com now.", 1))
	a.digest("POST", "operator", 409, "ai_unavailable")
	if got := a.digest("GET", "viewer", 200, ""); got["digest"] != nil {
		t.Fatalf("a blocked answer was stored: %v", got)
	}
	rows := a.activity()
	if last := rows[len(rows)-1]; last.Result != ai.ResultBlockedByHook || last.Job != "log-digest" {
		t.Fatalf("row = %+v", last)
	}
}
