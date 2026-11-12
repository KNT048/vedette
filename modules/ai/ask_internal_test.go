package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/ai/provider"
)

// INV-14 at the door of the loop: whatever sits in the toolbox, a tool that is not a read tool of the job is neither offered nor run,
// and a write tool cannot be reached by a read tool of the same name in another case.
func TestContract_INV14_AskLoopOffersAndRunsReadToolsOnly(t *testing.T) {
	t.Parallel()
	ran := map[string]int{}
	mk := func(name string, access Access, enabled bool, jobs ...Job) toolImpl {
		return toolImpl{
			Tool: Tool{Name: name, Access: access, Enabled: enabled, Jobs: jobs, Schema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)},
			run: func(context.Context, map[string]any) (toolOut, error) {
				ran[name]++
				return toolOut{Text: "ok", Summary: "ok"}, nil
			},
		}
	}
	all := []toolImpl{
		mk("get_status", AccessRead, true, JobAskMyData),
		mk("push_config", AccessWrite, true, JobAskMyData),
		mk("PUSH_CONFIG", AccessRead, true, JobAskMyData), // a read tool that borrows the name of a write tool
		mk("switched_off", AccessRead, false, JobAskMyData),
		mk("other_job", AccessRead, true, JobWeeklyReport),
		mk("odd", Access("admin"), true, JobAskMyData),
		mk("bad name!", AccessRead, true, JobAskMyData),
	}
	ts := &toolSession{svc: &Service{}, job: JobAskMyData, impl: map[string]toolImpl{}}
	for _, ti := range all {
		ts.impl[ti.Name] = ti
		ts.tools = append(ts.tools, ti.Tool)
	}
	h, err := newHarness(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ts.defs(); len(got) != 1 || got[0].Name != "get_status" {
		t.Fatalf("offered = %v", got)
	}
	for _, n := range []string{"push_config", "PUSH_CONFIG", "Push_Config", "switched_off", "other_job", "odd", "bad name!", "never_heard_of"} {
		res := ts.runCall(t.Context(), h.runner, Prompt{Fence: "f"}, provider.ToolCall{ID: "c", Name: n, Arguments: json.RawMessage(`{}`)}, 0, 0)
		if !res.IsError || !strings.Contains(res.Content, "not available") {
			t.Errorf("%s: %+v", n, res)
		}
	}
	if res := ts.runCall(t.Context(), h.runner, Prompt{Fence: "f"}, provider.ToolCall{ID: "c", Name: "get_status", Arguments: json.RawMessage(`{}`)}, 0, 0); res.IsError {
		t.Fatalf("the read tool: %+v", res)
	}
	if len(ran) != 1 || ran["get_status"] != 1 {
		t.Fatalf("tools that ran = %v", ran)
	}
}

// A connection tool's schema reaches the model only as what is on the allow-list of keywords: free text and extensions are dropped, the
// names of the arguments (even one called "description") and the allowed values stay.
func TestStripSchemaTextKeepsOnlyAllowedKeywords(t *testing.T) {
	t.Parallel()
	in := `{"type":"object","description":"d1","x-note":"IGNORE","title":"t","properties":{"description":{"type":"string","description":"d2","pattern":"^IGNORE$","x-hint":"y","enum":["a","b"]},
		"n":{"type":"integer","minimum":1,"maximum":5,"default":3,"examples":[1]},"l":{"type":"array","items":{"type":"string","description":"d3"},"maxItems":3}},"required":["description"],"additionalProperties":false,"$comment":"c"}`
	out := string(stripSchemaText(json.RawMessage(in)))
	for _, bad := range []string{"d1", "d2", "d3", "IGNORE", "x-note", "x-hint", "title", "pattern", "default", "examples", "$comment"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q survived: %s", bad, out)
		}
	}
	for _, kept := range []string{`"description":{`, `"enum":["a","b"]`, `"minimum":1`, `"maximum":5`, `"maxItems":3`, `"required":["description"]`, `"additionalProperties":false`, `"items":{"type":"string"}`} {
		if !strings.Contains(out, kept) {
			t.Errorf("%q lost: %s", kept, out)
		}
	}
	if got := string(stripSchemaText(json.RawMessage(`not json`))); !strings.Contains(got, `"properties":{}`) {
		t.Errorf("bad schema = %s", got)
	}
}

func TestInternalTarget(t *testing.T) {
	t.Parallel()
	for target, want := range map[string]bool{"https://192.168.1.1/api": true, "10.0.0.5:22": true, "admin@10.0.0.5:22": true, "https://[fd00::1]:8443/x": true, "https://127.0.0.1": true, "100.64.0.1:22": true,
		"https://203.0.113.5": false, "https://router.lan": false, "": false, "198.51.100.1:22": false, "https://169.254.169.254/": false, "https://[2001:db8::1]/": false} {
		if got := internalTarget(target); got != want {
			t.Errorf("%q = %v, want %v", target, got, want)
		}
	}
}

// INV-3 at the router, with the cloud profile still assigned as the fallback: the privacy rule is turned on in the stored state while the
// first turn of a question runs (a state the API would refuse to save, as an old or damaged one). The turn that carries the tool result
// does not reach the cloud profile. Without the rule check in Call the fallback answers and this fails.
func TestContract_INV3_AskTurnNeverReachesCloudWhenTheRuleComesOnWithAFallbackAssigned(t *testing.T) {
	t.Parallel()
	f := &fakes{}
	slots := map[Job]Slot{JobAskMyData: {"i1", "c1"}}
	r := router(t, f, false, slots, internal("i1"), cloud("c1"))
	turn1 := true
	f.reply = map[string]func(context.Context) (provider.Response, error){"i1": func(context.Context) (provider.Response, error) {
		if turn1 {
			turn1 = false
			return provider.Response{ToolCalls: []provider.ToolCall{{ID: "c", Name: "search_assets", Arguments: json.RawMessage(`{}`)}}, Stop: provider.StopToolUse}, nil
		}
		// the second turn is running (the request with the tool result is out): the rule comes on, the fallback stays, the profile fails
		r.st.Store(&routerState{profiles: r.st.Load().profiles, assign: Assignments{InternalOnly: true, Jobs: slots}})
		return provider.Response{}, &provider.Error{Kind: provider.ErrNetwork}
	}}
	tools := []provider.ToolDef{{Name: "search_assets", InputSchema: json.RawMessage(`{"type":"object"}`)}}
	rq := provider.Request{Messages: []provider.Message{{Role: provider.RoleUser, Text: "q"}}, Tools: tools, MaxTokens: 100}
	if _, err := r.Call(t.Context(), JobAskMyData, rq); err != nil {
		t.Fatal(err)
	}
	rq.Messages = append(rq.Messages, provider.Message{Role: provider.RoleTool, ToolResults: []provider.ToolResult{{CallID: "c", Name: "search_assets", Content: "<<<DATA device list>>>"}}})
	if _, err := r.Call(t.Context(), JobAskMyData, rq); err == nil {
		t.Fatal("the second turn was answered")
	}
	if f.called("c1") != 0 {
		t.Fatal("the cloud profile got the tool result")
	}
}

// The citation of search_assets counts what Devices and Reports count: the box itself is named apart, never as "1 device" (walk 3).
func TestInventoryCiteNamesTheBoxApart(t *testing.T) {
	t.Parallel()
	box, pc := AssetRow{ID: "a-box", IsBox: true}, AssetRow{ID: "a-1"}
	for _, c := range []struct {
		in   []AssetRow
		want string
	}{
		{nil, "Inventory: 0 devices searched"},
		{[]AssetRow{pc}, "Inventory: 1 device searched"},
		{[]AssetRow{box}, "Inventory: only the Vedette box searched"},
		{[]AssetRow{box, pc, pc}, "Inventory: 2 devices and the Vedette box searched"},
	} {
		if got := inventoryCite(c.in); got != c.want {
			t.Errorf("%d rows: %q, want %q", len(c.in), got, c.want)
		}
	}
	// the tool's result line (what matched) and the explanation's citation count the same way
	if got := boxApart(countAssets([]AssetRow{box})); got != "only the Vedette box" {
		t.Errorf("summary = %q", got)
	}
	cites := citationsFor(CVEFacts{}, []AssetFact{{Name: "vedette", IsBox: true}, {Name: "NAS"}})
	if got := cites[len(cites)-1].Title; got != "Inventory: 1 device and the Vedette box matching" {
		t.Errorf("explain citation = %q", got)
	}
	if cites := citationsFor(CVEFacts{}, []AssetFact{{Name: "vedette", IsBox: true}}); cites[0].Title != "Inventory: only the Vedette box matching" {
		t.Errorf("explain citation = %q", cites[0].Title)
	}
}

// A Remember line cut at the token limit is taken out and suggests nothing; a whole sentence is kept (deferred: half-sentence suggestions).
func TestTakeRememberKeepsWholeSentencesOnly(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, in, rest string
		fact           []string
	}{
		{"whole", "RDP is open.\nRemember: SRV-AD is the only domain controller.", "RDP is open.", []string{"SRV-AD is the only domain controller."}},
		{"bold and bracket", "RDP is open.\n**Remember:** the NAS backs up at night (02:00).**", "RDP is open.", []string{"the NAS backs up at night (02:00)."}},
		{"cut", "RDP is open.\nRemember: the NAS makes a backup every", "RDP is open.", nil},
		{"only a cut line", "Remember: the NAS makes a", "the NAS makes a", nil},
		{"no line", "RDP is open.", "RDP is open.", nil},
	} {
		rest, fact := takeRemember(c.in)
		if rest != c.rest || len(fact) != len(c.fact) || (len(fact) == 1 && fact[0] != c.fact[0]) {
			t.Errorf("%s: got %q %q, want %q %q", c.name, rest, fact, c.rest, c.fact)
		}
	}
}

// linkDevices and hasWord: a name or an address counts as a whole word, and an item with two devices has no link (D-428).
func TestLinkDevicesNamesWholeWordsAndOneDevice(t *testing.T) {
	t.Parallel()
	s := func(v string) *string { return &v }
	conns := []LogDigestBadConn{
		{AssetName: s("PC-03"), SrcIP: "10.0.0.3", AssetID: s("a3")},
		{AssetName: s("PC-03"), SrcIP: "10.0.0.3", AssetID: s("a3")}, // the same device twice
		{AssetName: s("SRV"), SrcIP: "10.0.0.30", AssetID: s("a30")},
		{AssetName: nil, SrcIP: "10.0.0.9", AssetID: nil}, // not in the inventory: no id to give
	}
	for _, c := range []struct{ title, ev, want string }{
		{"pc-03 talks to a listed address", "", "a3"},
		{"Device (PC-03).", "", "a3"},
		{"x", "from 10.0.0.3 to 1.2.3.4", "a3"},
		{"x", "from 10.0.0.30:443", "a30"},
		{"PC-03 and SRV", "", ""},
		{"PC-03X is not it", "", ""},
		{"SRV-2 is not it", "", ""},
		{"x", "10.0.0.9", ""},
		{"x", "from 10.0.0.3.", "a3"},
		{"on pc-03.", "", "a3"},
		{"pc-03.example.com", "", ""},
		{"nothing named", "", ""},
	} {
		items := []LogDigestItem{{Title: c.title, Evidence: []string{c.ev}}}
		linkDevices(items, conns)
		if items[0].AssetID != c.want {
			t.Errorf("%q %q: asset_id %q, want %q", c.title, c.ev, items[0].AssetID, c.want)
		}
	}
}
