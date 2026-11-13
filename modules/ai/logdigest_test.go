package ai_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
)

// The AI log digest (S-AI-4, INV-3, INV-6, INV-12, D-221).

// fakeLogs is the digest of the logs module as the port hands it over.
type fakeLogs struct {
	mu     sync.Mutex
	on     bool
	data   ai.LogDigestData
	err    error
	around ai.LogAroundData
	asked  []string // the address and range of each events_around read
}

func (f *fakeLogs) readAround(_ context.Context, ip netip.Addr, from, to time.Time) (ai.LogAroundData, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, fmt.Sprintf("%s %s %s", ip, from.Format(time.RFC3339), to.Format(time.RFC3339)))
	return f.around, f.on, nil
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

// A connection the firewall blocked reaches the AI as a blocked attempt, not as a connection (D-227): the answer of logs carries the mark.
// An unmarked hit is not claimed to have gone through (the line may not say), and a SPAN DNS answer is a lookup.
func TestLogDigestSaysABlockedAttempt(t *testing.T) {
	a := newAPI(t)
	a.addProfile(cloudBody("Claude", keyA))
	a.fake.setAnswer(goodDigest)
	raw := `{"lines_24h":2,"baseline_days":7,"new":[],"spikes":[],"bad_connections":[` +
		`{"ts":"2026-11-10T02:00:00Z","src_ip":"192.168.1.50","dest":"185.220.101.47","dest_kind":"ip","seen_via":"syslog:FW-HQ","feeds":["tor-exit"],"confidence":0.9,"blocked":true},` +
		`{"ts":"2026-11-10T02:05:00Z","src_ip":"192.168.1.51","dest":"91.92.240.11","dest_kind":"ip","seen_via":"syslog:FW-HQ","feeds":["ipsum"],"confidence":0.6,"blocked":false},` +
		`{"ts":"2026-11-10T02:06:00Z","src_ip":"192.168.1.52","dest":"bad.example.net","dest_kind":"domain","seen_via":"span_dns","feeds":["hagezi"],"confidence":0.8,"blocked":false}]}`
	var in ai.LogDigestData
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatal(err)
	}
	a.logs.set(in)
	a.digest("POST", "operator", 200, "")
	sent := fmt.Sprintf("%+v", a.fake.lastRequest(t))
	for _, want := range []string{"blocked attempt (stopped by the device that logged it): a device that is not in the inventory, IP 192.168.1.50, to 185.220.101.47", "not marked blocked (it went through, or the log does not say): a device that is not in the inventory, IP 192.168.1.51, to 91.92.240.11",
		"DNS lookup (the name was looked up; no connection is known): a device that is not in the inventory, IP 192.168.1.52, to bad.example.net"} {
		if !strings.Contains(sent, want) {
			t.Errorf("the request lacks %q", want)
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
	a.digest("POST", "operator", 409, "blocked_by_hook")
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
		a.digest("POST", "operator", 502, "ai_bad_format")
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
	a.digest("POST", "operator", 409, "blocked_by_hook")
	if got := a.digest("GET", "viewer", 200, ""); got["digest"] != nil {
		t.Fatalf("a blocked answer was stored: %v", got)
	}
	rows := a.activity()
	if last := rows[len(rows)-1]; last.Result != ai.ResultBlockedByHook || last.Job != "log-digest" {
		t.Fatalf("row = %+v", last)
	}
}

// The documents of the knowledge base the call would carry are part of the inputs of a stored digest (INV-6b, D-221): adding one makes
// the next POST ask again, and the document reaches the request.
func TestLogDigestCacheKeyFollowsTheDocuments(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile()
	id := a.addProfile(cloudBody("Claude", keyA))["id"].(string)
	a.fake.setAnswer(goodDigest)
	a.assign(false, ai.JobLogDigest, id, "")
	a.logs.set(someDigest())
	a.digest("POST", "operator", 200, "")
	calls := a.fake.total()
	a.digest("POST", "operator", 200, "")
	if a.fake.total() != calls {
		t.Fatal("no cache with no documents")
	}
	a.kbAdd("fw.md", []byte("FW-HQ is the firewall of the head office; logon failures from it go to the IT team on call."), `["log-digest"]`)
	a.digest("POST", "operator", 200, "")
	if a.fake.total() != calls+1 {
		t.Fatalf("calls = %d, want %d: a stored digest was served after a document was added", a.fake.total(), calls+1)
	}
	if user := a.fake.lastRequest(t).Messages[0].Text; !strings.Contains(user, "IT team on call") {
		t.Fatalf("the document did not reach the digest: %s", user)
	}
	a.digest("POST", "operator", 200, "")
	if a.fake.total() != calls+1 {
		t.Fatal("not cached again")
	}
}

// With the logs module off, GET says so (409) also when a digest was stored before: a stored digest is not served for logs that are off.
func TestLogDigestGetWithLogsOffIgnoresAStoredDigest(t *testing.T) {
	a := newAPI(t)
	a.addProfile(cloudBody("Claude", keyA))
	a.fake.setAnswer(goodDigest)
	a.logs.set(someDigest())
	a.digest("POST", "operator", 200, "")
	digestOf(t, a.digest("GET", "viewer", 200, ""))
	a.logs.mu.Lock()
	a.logs.on = false
	a.logs.mu.Unlock()
	a.digest("GET", "viewer", 409, "ai_unavailable")
}

// Counts are written with thousands separators, so a 9-digit count is a number of lines, not an identity number the hooks block.
func TestLogDigestBigCountsAreNotBlockedAsIDNumbers(t *testing.T) {
	a := newAPI(t)
	a.addProfile(cloudBody("Claude", keyA))
	a.fake.setAnswer(goodDigest)
	d := someDigest()
	d.Lines24h = 123456789
	d.New[0].Count = 987654321
	a.logs.set(d)
	a.digest("POST", "operator", 200, "")
	if user := a.fake.lastRequest(t).Messages[0].Text; !strings.Contains(user, "123,456,789") || !strings.Contains(user, "987,654,321 lines") {
		t.Fatalf("request = %s", user)
	}
}

// Log investigation (S-AI-4 at the maximum level, D-223): the model may check points with read-only tools, one of which counts what
// the logs say about an address; the calls are shown with the digest and recorded in the activity row.
func TestLogInvestigateAtMaxChecksPointsWithReadTools(t *testing.T) {
	a := newAPI(t)
	a.logs.set(someDigest())
	a.logs.around = ai.LogAroundData{Lines: 1240, Kinds: []ai.LogAroundKind{{Signature: "sshd: Failed password for invalid user <*> from <ip> port <n>", SourceName: "FW-HQ", Count: 1240}}}
	a.addProfile(cloudBody("Claude", keyA))
	a.want("PUT", "/ai/config", "admin", `{"tier":"max","daily_cap":1000000,"redact_pii":true}`, 200, "")
	a.fake.play(turn{calls: []provider.ToolCall{call("events_around", `{"ip":"::ffff:203.0.113.9","minutes":60}`)}}, turn{text: "```json\n" + goodDigest + "\n```"})
	d := digestOf(t, a.digest("POST", "operator", 200, ""))
	calls := d["tool_calls"].([]any)
	if len(calls) != 1 || calls[0].(map[string]any)["tool"] != "events_around" || calls[0].(map[string]any)["result"] != "1,240 lines of 1 kind, 0 bad connections" ||
		!strings.Contains(d["cadence"].(string), "read-only tools") || d["summary"] != "Look at PC-ACCOUNTS-03 first." {
		t.Fatalf("digest = %v", d)
	}
	if got := strings.Join(a.logs.asked, ";"); got != "203.0.113.9 2026-11-10T02:00:00Z 2026-11-10T03:00:00Z" {
		t.Fatalf("asked %q", got)
	}
	reqs := a.fake.askRequests()
	var offered []string
	for _, td := range reqs[len(reqs)-2].Tools {
		offered = append(offered, td.Name)
	}
	if strings.Join(offered, ",") != "events_around,lookup_cve,lookup_ioc,search_assets" || reqs[len(reqs)-2].Schema != nil {
		t.Fatalf("offered %v, schema %v", offered, reqs[len(reqs)-2].Schema)
	}
	if res := toolResults(reqs[len(reqs)-1]); len(res) != 1 || !strings.Contains(res[0].Content, `"lines":"1,240"`) {
		t.Fatalf("tool result = %+v", res)
	}
	rows := a.activity()
	if last := rows[len(rows)-1]; last.Job != "log-investigate" || len(last.Tools) != 1 || last.Tools[0].Name != "events_around" {
		t.Fatalf("row = %+v", last)
	}
	// the stored digest keeps its calls
	if got := digestOf(t, a.digest("GET", "viewer", 200, "")); len(got["tool_calls"].([]any)) != 1 {
		t.Fatalf("GET = %v", got)
	}
	// a fenced answer is taken out of its block before the after_ai hooks walk its strings: an escaped word is still stopped
	a.want("POST", "/ai/hooks", "admin", hookJSON("No payroll", "after_ai", "keywords", "payroll", "block", "Payroll is out of scope."), 200, "")
	next := someDigest()
	next.Lines24h++
	a.logs.set(next)
	a.fake.play(turn{text: "```json\n" + strings.Replace(goodDigest, "Look at PC-ACCOUNTS-03 first.", `Look at the p\u0061yroll server first.`, 1) + "\n```"})
	a.digest("POST", "operator", 409, "blocked_by_hook")
	// Log investigation that cannot run (its skill off): the plain digest, and the level says why no tool was used
	a.want("PUT", "/ai/skills/log-investigate", "admin", `{"enabled":false}`, 200, "")
	a.fake.setAnswer(goodDigest)
	d = digestOf(t, a.digest("POST", "operator", 200, ""))
	if len(d["tool_calls"].([]any)) != 0 || !strings.Contains(d["cadence"].(string), "no read-only tools were used") || len(a.fake.lastRequest(t).Tools) != 0 {
		t.Fatalf("digest = %v", d)
	}
	if rows := a.activity(); rows[len(rows)-1].Job != "log-digest" {
		t.Fatalf("row = %+v", rows[len(rows)-1])
	}
}

// The log digest is the first maker of memory suggestions (INV-8, D-223): only while an administrator allows them, at most two, and
// each waits in the list for an accept.
func TestLogDigestSuggestsMemoriesOnlyWhenAllowed(t *testing.T) {
	a := newAPI(t)
	a.logs.set(someDigest())
	a.addProfile(cloudBody("Claude", keyA))
	a.fake.setAnswer(goodDigest)
	a.digest("POST", "operator", 200, "")
	if sch := string(a.fake.lastRequest(t).Schema.JSON); strings.Contains(sch, "remember") {
		t.Fatalf("suggestions are off, the schema asks for them: %s", sch)
	}
	a.want("PUT", "/ai/memory/settings", "admin", `{"suggest_enabled":true}`, 200, "")
	a.fake.setAnswer(strings.Replace(goodDigest, `{"summary"`, `{"remember":["The NAS makes a backup every night at 01:00.","FW-HQ is the only firewall.","A third one."],"summary"`, 1))
	if d := digestOf(t, a.digest("POST", "operator", 200, "")); d["memories_suggested"] != float64(2) {
		t.Fatalf("memories_suggested = %v", d["memories_suggested"])
	}
	if sch := string(a.fake.lastRequest(t).Schema.JSON); !strings.Contains(sch, `"required":["summary","items","remember"]`) {
		t.Fatalf("schema = %s", sch)
	}
	sg := a.want("GET", "/ai/memory", "admin", "", 200, "")["suggestions"].([]any)
	if len(sg) != 2 || sg[0].(map[string]any)["evidence"] != "From the log summary of 10 Nov 2026" {
		t.Fatalf("suggestions = %v", sg)
	}
	if items := a.want("GET", "/ai/memory", "admin", "", 200, "")["items"].([]any); len(items) != 0 {
		t.Fatalf("a suggestion became memory without an accept: %v", items)
	}
}

// An item that names exactly one device of the bad connections sent gets the box's id of that device; the model never makes one (D-428).
func TestLogDigestLinksItemsToDevicesFromTheBoxOwnIds(t *testing.T) {
	a := newAPI(t)
	a.addProfile(cloudBody("Claude", keyA))
	d := someDigest()
	id, other, name2 := "a-pc03", "a-srv", "SRV-FILE"
	d.BadConnections[0].AssetID = &id
	d.BadConnections = append(d.BadConnections, ai.LogDigestBadConn{TS: "2026-11-10T02:05:00Z", AssetName: &name2, SrcIP: "192.168.10.50", Dest: "185.220.101.48", DestKind: "ip", SeenVia: "span_flow", Feeds: []string{"tor-exit"}, AssetID: &other})
	a.logs.set(d)
	a.fake.setAnswer(`{"summary":"Look first.","items":[` +
		`{"severity":"high","title":"PC-ACCOUNTS-03 connects to a listed address","evidence":[],"recommendation":"Isolate it."},` +
		`{"severity":"high","title":"Two devices","evidence":["PC-ACCOUNTS-03 and 192.168.10.50 talk to listed addresses"],"recommendation":"Isolate them."},` +
		`{"severity":"medium","title":"Unknown device PC-ACCOUNTS-030","evidence":[],"recommendation":"Look."},` +
		`{"severity":"info","title":"By address","evidence":["192.168.10.50 sent 3 packets"],"recommendation":"Look."}]}`)
	items := digestOf(t, a.digest("POST", "operator", 200, ""))["items"].([]any)
	want := []any{"a-pc03", nil, nil, "a-srv"}
	for i, w := range want {
		if got := items[i].(map[string]any)["asset_id"]; got != w {
			t.Errorf("item %d asset_id = %v, want %v", i, got, w)
		}
	}
	if raw, _ := json.Marshal(a.fake.lastRequest(t)); strings.Contains(string(raw), "a-pc03") {
		t.Fatalf("a device id went to the provider: %s", raw)
	}
}

// Two POSTs with the same inputs at once call the AI once: the second waits for the first and reads what it stored.
func TestLogDigestTwoAtOnceAskTheAIOnce(t *testing.T) {
	a := newAPI(t)
	a.addProfile(cloudBody("Claude", keyA))
	a.logs.set(someDigest())
	a.fake.setAnswer(goodDigest)
	in, release := make(chan struct{}, 1), make(chan struct{})
	a.fake.setOnCall(func() {
		select {
		case in <- struct{}{}:
			<-release // the first call is held inside the provider
		default:
		}
	})
	codes := make(chan int, 2)
	post := func() {
		code, _, _ := a.do("POST", "/ai/logs/digest", "operator", "")
		codes <- code
	}
	go post()
	<-in
	go post()
	for range 2000 { // let the second reach the slot (it must not reach the provider)
		runtime.Gosched()
	}
	close(release)
	for range 2 {
		if code := <-codes; code != 200 {
			t.Fatalf("POST = %d", code)
		}
	}
	if n := a.fake.total(); n != 1 {
		t.Fatalf("the provider was called %d times, want 1", n)
	}
}

// With the module registry at hand, a stored digest is served without the aggregate of the logs; a module that is off is still 409.
func TestLogDigestGetServesAStoredDigestWithoutReadingTheLogs(t *testing.T) {
	a := newAPI(t)
	a.addProfile(cloudBody("Claude", keyA))
	a.fake.setAnswer(goodDigest)
	a.logs.set(someDigest())
	a.digest("POST", "operator", 200, "")
	reg := &fakeRegistry{on: true}
	reads := 0
	svc, err := ai.New(a.ctx(), ai.Config{DB: a.db, Secrets: a.sec, Audit: audit.New(a.clock.Now), Log: slog.New(slog.DiscardHandler), Clock: a.clock.Now, Factory: a.fake.factory, Modules: reg,
		LogDigest: func(ctx context.Context) (ai.LogDigestData, bool, error) { reads++; return a.logs.read(ctx) }})
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.CachedLogDigest(a.ctx())
	if err != nil || got == nil || got.Summary != "Look at PC-ACCOUNTS-03 first." || reads != 0 {
		t.Fatalf("got %+v err %v, logs read %d times", got, err, reads)
	}
	reg.on = false
	if _, err := svc.CachedLogDigest(a.ctx()); err == nil || reads != 0 {
		t.Fatalf("logs off: err %v, logs read %d times", err, reads)
	}
}

type fakeRegistry struct{ on bool }

func (r *fakeRegistry) Enabled(string) bool { return r.on }
