package ai_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
)

// betaBox is the data of kien's beta box on 13 Nov 2026 (customer walk 1, W1-27): 24 devices, 126 open findings, 88 of them on one
// iPhone, 20 on a hand-added "Microsoft" device without an IP.
func betaBox() ([]ai.AssetRow, []ai.FindingRow) {
	var assets []ai.AssetRow
	add := func(id, name, ip, kind, vendor, model, os string, ports, sw []string) {
		assets = append(assets, ai.AssetRow{ID: id, Name: name, IP: ip, Kind: kind, Vendor: vendor, Model: model, OS: os, Approved: true, Ports: ports, Software: sw,
			FirstSeen: "2026-11-13T04:10:00Z", LastSeen: "2026-11-13T07:15:00Z", Origin: "discovered", SeenBy: "sensor"})
	}
	add("a-iphoneqv2kq7xg3ajx4hrnzl5o2m", "iPhone", "192.168.18.107", "iot", "Apple", "", "", nil, []string{"Apple iOS 27.2.1"})
	add("a-fbaf5191cc174626a85b812bc3d7", "fbaf5191-cc17-4626-a85b-812bc3d7b83b", "192.168.18.112", "", "Apple", "Mac14,2", "", nil, nil)
	add("a-android0iaek47kd7ql2xq3vbn5p", "android_i0iaek47", "192.168.18.120", "computer", "Xiaomi", "", "", nil, nil)
	add("a-router1d2k3l4m5n6o7p8q9r0s1t", "Unknown 192.168.18.1", "192.168.18.1", "", "", "", "", nil, nil)
	add("a-gkctzfflxjbuykut7vepwo2knm", "brw4cd577b12cf2", "192.168.18.30", "printer", "CHONGQING FUGUI ELECTRONICS", "", "", []string{"80/tcp http", "631/tcp ipp"}, nil)
	add("a-vft3ogd7ltrhtxbhrmdlbuduhu", "Juniper Networks EX4200-48T", "", "switch", "Juniper Networks", "EX4200-48T", "Junos 15.1R7.9", nil, []string{"Juniper Junos OS 15.1R7.9"})
	add("a-2ka3ceq6ajcdc7wd6brjukgybm", "Fortinet", "192.168.18.252", "", "Fortinet", "", "", nil, nil)
	add("a-forti251xk2l3m4n5o6p7q8r9s0", "Fortinet 192.168.18.251", "192.168.18.251", "", "Fortinet", "", "", nil, nil)
	add("a-bynhcmc01k2l3m4n5o6p7q8r9s0", "byn-hcmc-01", "192.168.18.21", "computer", "Dell", "OptiPlex 7090", "Microsoft Windows 11 21H2", []string{"135/tcp msrpc", "445/tcp microsoft-ds", "3389/tcp ms-wbt-server"}, nil)
	add("a-microsoftm2n3o4p5q6r7s8t9u0", "Microsoft", "", "", "Microsoft", "", "", nil, []string{"Microsoft Office"})
	add("a-ciscoc1d2e3f4g5h6i7j8k9l0m1", "Cisco", "", "", "Cisco", "", "", nil, []string{"Cisco BroadWorks"})
	add("a-grandstreamg2h3i4j5k6l7m8n9", "192.168.18.109", "192.168.18.109", "phone", "Grandstream Networks, Inc.", "GXP2170", "", []string{"80/tcp http", "5060/udp sip"}, nil)
	for i := range 12 {
		add(fmt.Sprintf("a-host%02dk2l3m4n5o6p7q8r9s0t1", i), fmt.Sprintf("192.168.18.%d", 40+i), fmt.Sprintf("192.168.18.%d", 40+i), "", []string{"HP", "Dell", "VMware", "Hikvision"}[i%4], "", "", nil, nil)
	}
	var findings []ai.FindingRow
	addF := func(n int, a ai.AssetRow, cve func(int) string, sev func(int) string, basis string) {
		for i := range n {
			findings = append(findings, ai.FindingRow{ID: fmt.Sprintf("f-%s%03d", a.ID[2:14], i), AssetID: a.ID, Asset: a.Name, AssetIP: a.IP, CVE: cve(i), Status: "suspected",
				Severity: sev(i), Basis: basis, Confidence: 0.5, FirstSeen: "2026-11-13T06:38:00Z", LastSeen: "2026-11-13T07:15:00Z"})
		}
	}
	twoSev := func(i int) string { return []string{"critical", "high"}[i%2] }
	addF(88, assets[0], func(i int) string { return fmt.Sprintf("CVE-20%02d-%d", 16+i%10, 4600+i) }, twoSev, "product")
	addF(20, assets[9], func(i int) string { return fmt.Sprintf("CVE-20%02d-%d", 9+i%17, 21500+i) }, twoSev, "product")
	addF(7, assets[5], func(i int) string { return fmt.Sprintf("CVE-2023-368%02d", 44+i) }, twoSev, "version")
	addF(9, assets[10], func(i int) string { return fmt.Sprintf("CVE-2020-%d", 3950+i) }, twoSev, "product")
	addF(2, assets[11], func(i int) string { return fmt.Sprintf("CVE-2020-%d", 5730+i) }, func(int) string { return "high" }, "product")
	return assets, findings
}

// requestTokens estimates what a provider counts as the input of one request: the system prompt, the tool definitions and the whole
// conversation so far, which every turn sends again. Three bytes a token, as the router estimates (JSON with ids is close to it).
func requestTokens(r provider.Request) int {
	n := len(r.System)
	for _, m := range r.Messages {
		n += len(m.Text)
		for _, c := range m.ToolCalls {
			n += len(c.Name) + len(c.Arguments)
		}
		for _, t := range m.ToolResults {
			n += len(t.Content)
		}
	}
	for _, t := range r.Tools {
		n += len(t.Name) + len(t.Description) + len(t.InputSchema)
	}
	return n / 3
}

func inputTokens(reqs []provider.Request) (perTurn []int, total int) {
	for _, r := range reqs {
		perTurn = append(perTurn, requestTokens(r))
		total += requestTokens(r)
	}
	return perTurn, total
}

// W1-27: one question on the beta box sent 25,579 input tokens and used up the day's cap. Measured here with the same data: a
// typical question (the findings and the devices, one finding in detail, the answer) was about 10,400 and a model that asks for 50
// rows twice about 28,300; now they are under 8,000 and 20,000, and the counts say 126 and 88, not the length of a page.
func TestAskBetaBoxQuestionStaysInBudget(t *testing.T) {
	const q = "Which of my devices is most at risk right now, and what should I do first?"
	a := newAskAPI(t)
	a.fake.sizedUsage = true
	a.data.assets, a.data.findings = betaBox()
	a.fake.play(
		turn{calls: []provider.ToolCall{call("list_findings", `{}`), call("search_assets", `{}`)}},
		turn{calls: []provider.ToolCall{call("get_finding", `{"id":"f-iphoneqv2kq7x000"}`)}},
		turn{text: "The iPhone has the most findings.\n\nCheck its iOS version first."})
	a.ask(q, 200, "")
	reqs := a.fake.askRequests()
	per, total := inputTokens(reqs)
	if total > 8000 {
		t.Errorf("a typical question sends about %d input tokens (per turn %v), want at most 8,000", total, per)
	}
	res := toolResults(reqs[1])
	if len(res) != 2 {
		t.Fatalf("tool results = %+v", res)
	}
	for _, want := range []string{`"matching_findings":126`, `"device":"iPhone","findings":88`, `"by_severity":{"critical":63,"high":63}`, `126 findings (showing 10)`} {
		if !strings.Contains(res[0].Content, want) {
			t.Errorf("list_findings does not say %s: %s", want, res[0].Content)
		}
	}
	if !strings.Contains(res[1].Content, `"matching_devices":24`) || !strings.Contains(res[1].Content, `24 devices (showing 10)`) {
		t.Errorf("search_assets does not give the total: %s", res[1].Content)
	}

	// a model that asks for everything: the input budget stops the tools of the third turn and the answer comes from what it has
	b := newAskAPI(t)
	b.fake.sizedUsage = true
	b.data.assets, b.data.findings = betaBox()
	b.fake.play(
		turn{calls: []provider.ToolCall{call("list_findings", `{}`), call("search_assets", `{}`)}},
		turn{calls: []provider.ToolCall{call("list_findings", `{"severity":"critical","limit":50}`), call("search_assets", `{"limit":50}`)}},
		turn{calls: []provider.ToolCall{call("get_finding", `{"id":"f-iphoneqv2kq7x000"}`), call("get_finding", `{"id":"f-vft3ogd7ltrh000"}`)}},
		turn{text: "The iPhone has the most findings.\n\nCheck its iOS version first."})
	b.ask(q, 200, "")
	reqs = b.fake.askRequests()
	per, total = inputTokens(reqs)
	if total > 20000 {
		t.Errorf("a greedy question sends about %d input tokens (per turn %v), want at most 20,000", total, per)
	}
	if res := toolResults(reqs[3]); len(res) != 2 || !res[0].IsError || !strings.Contains(res[0].Content, "tool limit") {
		t.Errorf("the third turn's calls ran over the budget: %+v", res)
	}
	t.Logf("input tokens per turn %v, total %d", per, total)
}

// W1-27: the question itself used the cap up partway through. The person is told that, with the tokens it used, not "the cap is used
// up" as if it had been refused before it was sent; the run log says the cap stopped it, not "Bad format".
func TestAskTheCapRunningOutPartwaySaysSo(t *testing.T) {
	a := newAskAPI(t)
	a.want("PUT", "/ai/config", "admin", `{"tier":"min","monthly_budget":1000,"redact_pii":true}`, 200, "")
	a.fake.usageIn, a.fake.usageOut = 600, 3
	c := call("list_findings", `{}`)
	a.fake.play(turn{calls: []provider.ToolCall{c}}, turn{calls: []provider.ToolCall{c}}, turn{text: "Never reached."})
	m := a.ask("Which of my devices is most at risk?", 429, "budget_reached")
	msg := m["error"].(map[string]any)["message"].(string)
	if !strings.Contains(msg, "did not finish: this request used 1,206 tokens before it stopped") || !strings.Contains(msg, "this month's AI budget of 1,000 tokens is used up, so AI jobs are stopped until it renews on ") || !strings.Contains(msg, "raise the budget in Settings, AI assistant") {
		t.Fatalf("message = %q", msg)
	}
	if a.fake.total() != 2 {
		t.Fatalf("provider calls = %d", a.fake.total())
	}
	last := lastOf(a.activity())
	if last.TokensIn != 1200 || !strings.Contains(last.Summary, "ran out partway through") {
		t.Fatalf("row = %+v", last.ActivityEntry)
	}
	runs := a.want("GET", "/ai/runs", "viewer", "", 200, "")["items"].([]any)
	if st := runs[0].(map[string]any)["status"]; st != "capped" {
		t.Fatalf("run status = %v", st)
	}
	// now the cap is used up before anything is sent: that one says so
	m = a.ask("Which of my devices is most at risk?", 429, "budget_reached")
	if msg := m["error"].(map[string]any)["message"].(string); !strings.HasPrefix(msg, "This month's AI budget of 1,000 tokens is used up") {
		t.Fatalf("message = %q", msg)
	}
}

// A question that failed for its own reason and used the cap up doing so: the reason first, then that the AI is now paused.
func TestAskAFailureThatUsedTheCapUpNamesBoth(t *testing.T) {
	a := newAskAPI(t)
	a.want("PUT", "/ai/config", "admin", `{"tier":"min","monthly_budget":1000,"redact_pii":true}`, 200, "")
	a.fake.usageIn, a.fake.usageOut = 600, 3
	a.fake.play(turn{calls: []provider.ToolCall{call("list_findings", `{}`)}}, turn{text: "  "}) // an empty answer: not in the format
	m := a.ask("Which of my devices is most at risk?", 502, "ai_bad_format")
	msg := m["error"].(map[string]any)["message"].(string)
	if !strings.HasPrefix(msg, "The AI answered, but not in the format") || !strings.Contains(msg, "This request used 1,206 tokens, and this month's AI budget of 1,000 tokens is used up") {
		t.Fatalf("message = %q", msg)
	}
	// the same failure with room left under the cap says nothing of the cap
	b := newAskAPI(t)
	b.fake.play(turn{calls: []provider.ToolCall{call("list_findings", `{}`)}}, turn{text: "  "})
	m = b.ask("Which of my devices is most at risk?", 502, "ai_bad_format")
	if msg := m["error"].(map[string]any)["message"].(string); strings.Contains(msg, "cap") {
		t.Fatalf("message = %q", msg)
	}
}

// The same with the profile's own cap: the profile is named, and the run log says the cap stopped it.
func TestAskTheProfileCapRunningOutPartwaySaysSo(t *testing.T) {
	a := newAPI(t)
	a.addProfile(strings.Replace(cloudBody("Claude", keyA), `"monthly_budget":60000`, `"monthly_budget":1000`, 1))
	a.fake.usageIn, a.fake.usageOut = 600, 3
	c := call("list_findings", `{}`)
	a.fake.play(turn{calls: []provider.ToolCall{c}}, turn{calls: []provider.ToolCall{c}}, turn{text: "Never reached."})
	m := a.ask("Which of my devices is most at risk?", 429, "budget_reached")
	if msg := m["error"].(map[string]any)["message"].(string); !strings.Contains(msg, "the monthly budget of the profile Claude ran out partway through (this request used 1,206 tokens") {
		t.Fatalf("message = %q", msg)
	}
	runs := a.want("GET", "/ai/runs", "viewer", "", 200, "")["items"].([]any)
	if st := runs[0].(map[string]any)["status"]; st != "capped" {
		t.Fatalf("run status = %v", st)
	}
}

// D-531: a question the budget stopped partway lowers no level: the budget is a stop rule at 100 %, not a slide through the levels,
// for the shared budget and for a profile's own one alike; no ai_downgrade row, no ai.downgrade audit line, the tier stays.
func TestAskStoppedPartwayLowersNoLevel(t *testing.T) {
	c := call("list_findings", `{}`)
	for _, tc := range []struct {
		name, config, profileCap, want string
	}{
		{"shared budget", `{"tier":"med","monthly_budget":1000,"redact_pii":true}`, "60000", "med"},
		{"profile budget", `{"tier":"max","monthly_budget":1000,"redact_pii":true}`, "1000", "max"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newAPI(t)
			a.addProfile(strings.Replace(cloudBody("Claude", keyA), `"monthly_budget":60000`, `"monthly_budget":`+tc.profileCap, 1))
			a.want("PUT", "/ai/config", "admin", tc.config, 200, "")
			a.fake.usageIn, a.fake.usageOut = 600, 3
			a.fake.play(turn{calls: []provider.ToolCall{c}}, turn{calls: []provider.ToolCall{c}}, turn{text: "Never reached."})
			a.ask("Which of my devices is most at risk?", 429, "budget_reached")
			u := a.want("GET", "/ai/usage", "viewer", "", 200, "")
			if dg := u["downgrades"].([]any); len(dg) != 0 || u["tier"] != tc.want {
				t.Fatalf("usage = %v", u)
			}
			if rows := a.auditRows(); containsPrefix(rows, "ai.downgrade") {
				t.Fatalf("audit = %v", rows)
			}
		})
	}
}

// A list whose totals alone come near the cap (device names that grow when escaped) keeps its totals and note first and whole: the
// per-device counts and the rows give way, and the result is never cut by the loop.
func TestAskListKeepsItsTotalsWhenTheHeadIsLarge(t *testing.T) {
	a := newAskAPI(t)
	var findings []ai.FindingRow
	for i := range 30 {
		name := fmt.Sprintf("%02d", i) + strings.Repeat("<", 78) // each "<" is written as <: 480 bytes a name
		findings = append(findings, ai.FindingRow{ID: fmt.Sprintf("f-%d", i), AssetID: fmt.Sprintf("a-%d", i), Asset: name, AssetIP: "10.0.0.1", CVE: "CVE-2024-1111", Status: "suspected", Severity: "high", Basis: "product"})
	}
	a.data.findings = findings
	a.fake.play(turn{calls: []provider.ToolCall{call("list_findings", `{}`)}}, turn{text: "Thirty findings."})
	a.ask("How many findings are open?", 200, "")
	res := toolResults(a.fake.askRequests()[1])
	if len(res) != 1 || strings.Contains(res[0].Content, "[result truncated]") {
		t.Fatalf("result = %+v", res)
	}
	body := res[0].Content[strings.Index(res[0].Content, "{"):]
	if !strings.HasPrefix(body, `{"matching_findings":30,"shown":`) || !strings.Contains(body, "devices by count") || !strings.Contains(body, `"devices_with_findings":30`) {
		t.Fatalf("result = %s", body)
	}
}

// lookup_cve says how many devices the CVE matches and how many it lists.
func TestAskLookupCVEGivesTheDeviceTotal(t *testing.T) {
	a := newAskAPI(t)
	var many []ai.AssetFact
	for i := range 25 {
		many = append(many, ai.AssetFact{Name: fmt.Sprintf("NAS-%02d", i), IP: fmt.Sprintf("10.0.0.%d", i), Kind: "nas", Basis: "product", Status: "open"})
	}
	a.facts.mu.Lock()
	a.facts.assets["CVE-2022-27593"] = many
	a.facts.mu.Unlock()
	a.fake.play(turn{calls: []provider.ToolCall{call("lookup_cve", `{"cve":"CVE-2022-27593"}`)}}, turn{text: "Twenty-five devices."})
	a.ask("Which devices does CVE-2022-27593 hit?", 200, "")
	res := toolResults(a.fake.askRequests()[1])
	if len(res) != 1 || !strings.Contains(res[0].Content, `"matching_devices_total":25,"shown":20`) || !strings.Contains(res[0].Content, `25 devices (showing 20)`) {
		t.Fatalf("result = %+v", res)
	}
}

// Closed findings (status=any) come after the open ones, whatever their severity.
func TestAskListFindingsPutsOpenOnesFirst(t *testing.T) {
	a := newAskAPI(t)
	a.data.findings = []ai.FindingRow{
		{ID: "f-closed", AssetID: "a-1", Asset: "PC-1", CVE: "CVE-2020-0001", Status: "false_positive", Severity: "critical", Basis: "scan"},
		{ID: "f-open", AssetID: "a-1", Asset: "PC-1", CVE: "CVE-2024-0002", Status: "suspected", Severity: "high", Basis: "product"},
	}
	a.fake.play(turn{calls: []provider.ToolCall{call("list_findings", `{"status":"any"}`)}}, turn{text: "One open."})
	a.ask("What is open?", 200, "")
	c := toolResults(a.fake.askRequests()[1])[0].Content
	if strings.Index(c, "f-open") > strings.Index(c, "f-closed") {
		t.Fatalf("result = %s", c)
	}
}

// When the budget kept data from the model, the answer ends with the box's line saying so; otherwise it does not.
func TestAskSaysWhenDataWasLeftOut(t *testing.T) {
	a := newAskAPI(t)
	a.fake.sizedUsage = true
	a.data.assets, a.data.findings = betaBox()
	big := []provider.ToolCall{call("list_findings", `{"limit":50}`), call("search_assets", `{"limit":50}`)}
	a.fake.play(turn{calls: big}, turn{calls: big}, turn{calls: big}, turn{text: "The iPhone has the most findings."})
	got := a.ask("Which of my devices is most at risk?", 200, "")
	if ans := list(got["answer"]); len(ans) != 2 || !strings.HasPrefix(ans[1].(string), "Some data was left out to stay within the token budget") {
		t.Fatalf("answer = %v", ans)
	}
	b := newAskAPI(t)
	b.fake.play(turn{calls: []provider.ToolCall{call("list_findings", `{}`)}}, turn{text: "Two open findings."})
	if ans := list(b.ask("Which of my devices is most at risk?", 200, "")["answer"]); len(ans) != 1 {
		t.Fatalf("answer = %v", ans)
	}
}
