package ai_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
)

func strongBody(name, key string) string {
	return `{"name":"` + name + `","kind":"anthropic","api_style":"anthropic","base_url":"https://api.anthropic.com","model":"claude-sonnet-5-5","api_key":"` + key + `","location":"cloud","monthly_budget":6000000}`
}

// researchSetup adds a quick and a strong profile and routes the research job to them (quick first); mode sets the research mode.
func researchSetup(t *testing.T, mode string, strong bool) *api {
	t.Helper()
	a := newAPI(t)
	quick := a.addProfile(`{"name":"Quick","kind":"anthropic","api_style":"anthropic","base_url":"https://api.anthropic.com","model":"claude-haiku-5-5","api_key":"` + keyA + `","location":"cloud","monthly_budget":6000000}`)["id"].(string)
	slot := `{"primary":"` + quick + `","fallback":null}`
	if strong {
		s := a.addProfile(strongBody("Strong", keyB))["id"].(string)
		slot = `{"primary":"` + quick + `","fallback":"` + s + `"}`
	}
	a.want("PUT", "/ai/assignments", "admin", `{"internal_only":false,"jobs":{"research-cves":`+slot+`}}`, 200, "")
	a.want("PUT", "/ai/config", "admin", `{"tier":"med","monthly_budget":6000000,"redact_pii":true,"research_mode":"`+mode+`"}`, 200, "")
	return a
}

// layerAnswers answers each profile with its own verdict, and the provider's tools returning text (web mode).
type layerAnswers struct {
	mu    sync.Mutex
	by    map[string]string   // profile name -> the answer's JSON
	texts map[string][]string // profile name -> the text its web tools returned
	calls []string
}

func (l *layerAnswers) answer(_ context.Context, p ai.Profile, _ provider.Request) (provider.Response, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, p.Name)
	return provider.Response{Text: "Let me check.\n" + l.by[p.Name], Usage: provider.Usage{InputTokens: 1000, OutputTokens: 100}, Stop: provider.StopEnd,
		Web: provider.WebUse{Searches: 1, Fetched: []string{"https://example.com/sa"}, Texts: l.texts[p.Name]}}, nil
}

func verdict(v, conf, quote string) string {
	b, _ := json.Marshal(ai.ResearchVerdict{Verdict: v, Confidence: conf, Basis: "stated", URL: "https://example.com/sa", Quote: quote, Reason: "r", Trap: "third-party CNA"})
	return string(b)
}

const vendorSentence = "Widget releases 4.0 through 4.2.0 are affected; 4.2.1 fixes the issue."

var researchReq = ai.ResearchRequest{CVE: "CVE-2099-81001", Vendor: "acme", Product: "Widget", Line: "4", Versions: "4.1.3", Platforms: []string{"windows workstation"},
	Digest: "CVE CVE-2099-81001\nRecord assigner: vulncheck (not the vendor)\nCNA row: acme widget: affected 4.1.0 [cna, third-party]"}

// Escalation per mode: balanced escalates an unsure or unchecked quick answer to the strong layer and keeps a checked one; economy is the
// quick layer only; thorough is the strong layer only; with no second profile balanced stays on the quick answer and says why.
func TestResearch_EscalationPerMode(t *testing.T) {
	cases := []struct {
		name, mode   string
		strongSlot   bool
		quick        string
		quickText    []string
		wantCalls    []string
		wantLayer    string
		wantNote     bool
		wantVerdict  string
		wantQuoteChk string
	}{
		{"balanced keeps a checked affected", ai.ResearchBalanced, true, verdict("affected", "high", vendorSentence), []string{"Page: " + vendorSentence},
			[]string{"Quick"}, ai.LayerQuick, false, "affected", ai.QuoteTool},
		{"balanced escalates unsure", ai.ResearchBalanced, true, verdict("unsure", "medium", ""), nil, []string{"Quick", "Strong"}, ai.LayerStrong, false, "affected", ai.QuoteTool},
		{"balanced escalates an unchecked not affected", ai.ResearchBalanced, true, verdict("not_affected", "high", "Only 3.x is affected by this flaw in the widget."), nil,
			[]string{"Quick", "Strong"}, ai.LayerStrong, false, "affected", ai.QuoteTool},
		{"economy is quick only", ai.ResearchEconomy, true, verdict("unsure", "low", ""), nil, []string{"Quick"}, ai.LayerQuick, false, "unsure", ai.QuoteNone},
		{"thorough is strong only", ai.ResearchThorough, true, verdict("unsure", "low", ""), nil, []string{"Strong"}, ai.LayerStrong, false, "affected", ai.QuoteTool},
		{"balanced without a second profile", ai.ResearchBalanced, false, verdict("unsure", "low", ""), nil, []string{"Quick"}, ai.LayerQuick, true, "unsure", ai.QuoteNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := researchSetup(t, c.mode, c.strongSlot)
			la := &layerAnswers{by: map[string]string{"Quick": c.quick, "Strong": verdict("affected", "high", vendorSentence)},
				texts: map[string][]string{"Quick": c.quickText, "Strong": {"The advisory says: " + vendorSentence}}}
			a.fake.research = la.answer
			ans, err := a.svc.Research(a.ctx(), "it@acme.example", researchReq)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(la.calls, c.wantCalls) {
				t.Errorf("calls %v, want %v", la.calls, c.wantCalls)
			}
			if ans.Layer != c.wantLayer || ans.Verdict != c.wantVerdict || ans.QuoteCheck != c.wantQuoteChk || (ans.Note != "") != c.wantNote {
				t.Errorf("answer layer %s verdict %s quote %s note %q", ans.Layer, ans.Verdict, ans.QuoteCheck, ans.Note)
			}
			if len(ans.Steps) != len(c.wantCalls) || ans.Tokens() != 1100*len(c.wantCalls) {
				t.Errorf("steps %+v tokens %d", ans.Steps, ans.Tokens())
			}
			for _, st := range ans.Steps {
				if st.ActivityID == "" || st.Web != "provider" || st.Searches != 1 || !slices.Equal(st.Pages, []string{"https://example.com/sa"}) {
					t.Errorf("step %+v", st)
				}
			}
			rows := a.activity()
			if len(rows) != len(c.wantCalls) || rows[0].Job != string(ai.JobResearchCVEs) {
				t.Errorf("activity %+v", rows)
			}
			req := a.fake.reqs[len(a.fake.reqs)-1]
			if req.Web == nil || req.Web.Searches == 0 || req.Web.Fetches == 0 {
				t.Errorf("web tools not capped: %+v", req.Web)
			}
			if !strings.Contains(req.Messages[0].Text, "4.1.3") || !strings.Contains(req.Messages[0].Text, "windows workstation") || !strings.Contains(req.System, "third-party CNA") {
				t.Error("the request lacks the version, the platform or the trap checklist")
			}
		})
	}
}

// pageServer serves the pages of the research tests, with hosts that resolve to private, loopback and public addresses.
func pageServer(t *testing.T, a *api) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/sa":
			_, _ = w.Write([]byte("<html><body><h1>CVE-2099-81001</h1><p>" + vendorSentence + "</p></body></html>"))
		case "/to-lan":
			http.Redirect(w, r, "https://lan.example/sa", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	a.svc.SetPageServer(srv, func(_ context.Context, host string) ([]netip.Addr, error) {
		if ip, err := netip.ParseAddr(host); err == nil {
			return []netip.Addr{ip}, nil
		}
		switch host {
		case "lan.example":
			return []netip.Addr{netip.MustParseAddr("192.168.1.10")}, nil
		case "loop.example":
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
}

// The quote check: a quote in the text the provider's tools returned is checked there; one they did not return is looked up on a live
// fetch of the cited page by the box; one found nowhere is not_found, and balanced escalates it.
func TestResearch_QuoteCheckOnToolTextThenLiveFetch(t *testing.T) {
	a := researchSetup(t, ai.ResearchEconomy, false)
	pageServer(t, a)
	la := &layerAnswers{by: map[string]string{"Quick": verdict("affected", "high", vendorSentence)}, texts: map[string][]string{}}
	a.fake.research = la.answer
	ans, err := a.svc.Research(a.ctx(), "it@acme.example", researchReq)
	if err != nil {
		t.Fatal(err)
	}
	if ans.QuoteCheck != ai.QuoteLive || !strings.Contains(ans.QuotedText, "4.2.1 fixes") {
		t.Errorf("live check: %s %q", ans.QuoteCheck, ans.QuotedText)
	}
	la.texts["Quick"] = []string{"Widget releases 4.0 through 4.2.0 are **affected**; 4.2.1 fixes the issue."} // folded: nbsp, Markdown
	if ans, _ = a.svc.Research(a.ctx(), "it@acme.example", researchReq); ans.QuoteCheck != ai.QuoteTool {
		t.Errorf("tool check: %s", ans.QuoteCheck)
	}
	la.texts["Quick"] = nil
	la.by["Quick"] = verdict("affected", "high", "A sentence the vendor never wrote about the widget at all.")
	if ans, _ = a.svc.Research(a.ctx(), "it@acme.example", researchReq); ans.QuoteCheck != ai.QuoteNotFound || ans.QuotedText != "" {
		t.Errorf("made-up quote: %s", ans.QuoteCheck)
	}
}

// A profile without web tools of its own gets the box's fetch_page tool: the box reads public HTTPS pages itself and refuses private,
// LAN and loopback addresses and a redirect to one, within the layer's page cap.
func TestResearch_FetchPageRefusesPrivateAddresses(t *testing.T) {
	a := newAPI(t)
	id := a.addProfile(internalBody("Local"))["id"].(string)
	a.want("PUT", "/ai/assignments", "admin", `{"internal_only":false,"jobs":{"research-cves":{"primary":"`+id+`","fallback":null}}}`, 200, "")
	pageServer(t, a)
	var results []provider.ToolResult
	turn := 0
	a.fake.research = func(_ context.Context, _ ai.Profile, req provider.Request) (provider.Response, error) {
		if req.Web != nil || req.Schema != nil || len(req.Tools) != 1 || req.Tools[0].Name != "fetch_page" {
			t.Errorf("request: web %v schema %v tools %v", req.Web, req.Schema, req.Tools)
		}
		turn++
		if turn == 1 {
			var calls []provider.ToolCall
			for i, u := range []string{"https://lan.example/sa", "https://loop.example/sa", "https://127.0.0.1/sa", "https://10.1.2.3/sa", "https://example.com/to-lan", "http://vendor.example/sa", "https://example.com/sa"} {
				calls = append(calls, provider.ToolCall{ID: string(rune('a' + i)), Name: "fetch_page", Arguments: json.RawMessage(`{"url":"` + u + `"}`)})
			}
			return provider.Response{ToolCalls: calls, Usage: provider.Usage{InputTokens: 10, OutputTokens: 5}, Stop: provider.StopToolUse}, nil
		}
		results = req.Messages[len(req.Messages)-1].ToolResults
		return provider.Response{Text: "```json\n" + verdict("affected", "high", vendorSentence) + "\n```", Usage: provider.Usage{InputTokens: 10, OutputTokens: 5}, Stop: provider.StopEnd}, nil
	}
	ans, err := a.svc.Research(a.ctx(), "it@acme.example", researchReq)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 7 {
		t.Fatalf("%d results", len(results))
	}
	// economy is not set: balanced; the quick layer may read 4 pages, so the last calls hit the cap
	for i, r := range results[:4] {
		if !r.IsError || !strings.Contains(r.Content, "public internet address") {
			t.Errorf("call %d: %v %q, want a refused private address", i, r.IsError, r.Content)
		}
	}
	for i, r := range results[4:] {
		if !r.IsError || strings.Contains(r.Content, vendorSentence) {
			t.Errorf("call %d past the cap or refused: %v %q", i+4, r.IsError, r.Content)
		}
	}
	if ans.QuoteCheck != ai.QuoteLive || ans.Steps[0].Web != "box" {
		t.Errorf("answer %+v", ans)
	}
}

// A redirect to a LAN address and a plain-http page are refused even within the cap; a public page is read and fenced.
func TestResearch_FetchPageRedirectToLANIsRefused(t *testing.T) {
	a := newAPI(t)
	id := a.addProfile(internalBody("Local"))["id"].(string)
	a.want("PUT", "/ai/assignments", "admin", `{"internal_only":false,"jobs":{"research-cves":{"primary":"`+id+`","fallback":null}}}`, 200, "")
	pageServer(t, a)
	var results []provider.ToolResult
	turn := 0
	a.fake.research = func(_ context.Context, _ ai.Profile, req provider.Request) (provider.Response, error) {
		turn++
		if turn == 1 {
			var calls []provider.ToolCall
			for i, u := range []string{"https://example.com/to-lan", "http://vendor.example/sa", "https://example.com/sa"} {
				calls = append(calls, provider.ToolCall{ID: string(rune('a' + i)), Name: "fetch_page", Arguments: json.RawMessage(`{"url":"` + u + `"}`)})
			}
			return provider.Response{ToolCalls: calls, Usage: provider.Usage{InputTokens: 10, OutputTokens: 5}, Stop: provider.StopToolUse}, nil
		}
		results = req.Messages[len(req.Messages)-1].ToolResults
		return provider.Response{Text: verdict("affected", "high", vendorSentence), Usage: provider.Usage{InputTokens: 10, OutputTokens: 5}, Stop: provider.StopEnd}, nil
	}
	ans, err := a.svc.Research(a.ctx(), "it@acme.example", researchReq)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 || !results[0].IsError || !strings.Contains(results[0].Content, "public internet address") && !strings.Contains(results[0].Content, "redirected") || !results[1].IsError ||
		results[2].IsError || !strings.Contains(results[2].Content, vendorSentence) || !strings.Contains(results[2].Content, "<<<DATA-") {
		t.Fatalf("results %+v", results)
	}
	if ans.QuoteCheck != ai.QuoteTool || !slices.Equal(ans.Steps[0].Pages, []string{"https://example.com/sa"}) {
		t.Errorf("answer %+v", ans)
	}
}

// The automatic research has the reading's switch and daily number and its own share of the month's tokens; a person's research is
// held only by the budget.
func TestResearch_AutomaticHasItsSwitchAndShare(t *testing.T) {
	a := researchSetup(t, ai.ResearchEconomy, false)
	la := &layerAnswers{by: map[string]string{"Quick": verdict("unsure", "low", "")}}
	a.fake.research = la.answer
	a.want("PUT", "/ai/config", "admin", `{"tier":"med","monthly_budget":6000000,"redact_pii":true,"research_share":1}`, 200, "")
	a.fake.usageIn = 0
	if _, err := a.svc.Research(a.ctx(), "system", researchReq); err != nil {
		t.Fatal(err)
	}
	// 1 % of 6,000,000 is 60,000 tokens; each call spends 1,100: push past it with person's calls
	for range 60 {
		a.clock.Add(3 * time.Second) // a person's pace: below the job's runaway fuse
		if _, err := a.svc.Research(a.ctx(), "it@acme.example", researchReq); err != nil {
			t.Fatal(err)
		}
	}
	n := len(la.calls)
	if _, err := a.svc.Research(a.ctx(), "system", researchReq); err == nil || !strings.Contains(err.Error(), "research share") {
		t.Errorf("past the share: %v", err)
	}
	if len(la.calls) != n {
		t.Error("an automatic call past the share was sent")
	}
	m := a.want("GET", "/ai/config", "viewer", "", 200, "")
	if m["research_used_month"].(float64) < 60000 || m["research_mode"] != "economy" || m["research_share"] != 1.0 {
		t.Errorf("config %v", m)
	}
	a.want("PUT", "/ai/config", "admin", `{"tier":"med","monthly_budget":6000000,"redact_pii":true,"auto_read":false}`, 200, "")
	if _, err := a.svc.Research(a.ctx(), "system", researchReq); err == nil || !strings.Contains(err.Error(), "switched off") {
		t.Errorf("switched off: %v", err)
	}
}

// A research is public text plus the product asked about: never an administrator's memory or a knowledge document, and the record and
// pages the box read go through the customer's own hooks only, while the question (the inventory's product and version) goes through
// every hook.
func TestResearch_PublicTextOnlyAndTheCustomersHooks(t *testing.T) {
	a := researchSetup(t, ai.ResearchEconomy, false)
	a.addMemory("Our core router CORE-RTR-01 runs Junos OS 21.4R3-S6 at 10.20.0.1")
	a.kbIndexProfile()
	a.kbAdd("routers.md", []byte("# Routers\n\nCORE-RTR-01 runs Widget 4.1 and is reachable on the management VLAN.\n"), "[]")
	la := &layerAnswers{by: map[string]string{"Quick": verdict("unsure", "low", "")}}
	a.fake.research = la.answer
	page := "Vulnerability Note VU#644655. Widget 4.1 is affected. Contact cert@cert.org.\n\n412-268-5800\n\n324\n\n324\n\nRelease songs and movies."
	req := researchReq
	req.Pages = []ai.RefPage{{URL: "https://www.kb.cert.org/vuls/id/644655", Status: "ok", Text: page}}
	if _, err := a.svc.Research(a.ctx(), "system", req); err != nil {
		t.Fatalf("a public page was refused: %v", err)
	}
	sent := a.fake.reqs[len(a.fake.reqs)-1]
	all := sent.System + sent.Messages[0].Text
	for _, never := range []string{"CORE-RTR-01", "10.20.0.1", "management VLAN", "kind=memory", "kind=document"} {
		if strings.Contains(all, never) {
			t.Errorf("%q reached the provider of a research", never)
		}
	}
	for _, want := range []string{"412-268-5800", "cert@cert.org", "songs"} {
		if !strings.Contains(sent.Messages[0].Text, want) {
			t.Errorf("%q of the public page did not reach the provider as the page states it", want)
		}
	}
	n := len(a.fake.reqs)
	idReq := req
	idReq.Product = "Widget 079201234567"
	if _, err := a.svc.Research(a.ctx(), "system", idReq); err == nil || !strings.Contains(err.Error(), "ID number") {
		t.Errorf("an ID number in the product asked about: %v, want the call stopped", err)
	}
	a.addBlockHook("No VU notes", "before_ai", "VU#644655")
	if _, err := a.svc.Research(a.ctx(), "system", req); err == nil || !strings.Contains(err.Error(), "hook") {
		t.Errorf("a customer's hook matching the page: %v, want the call stopped", err)
	}
	if len(a.fake.reqs) != n {
		t.Error("a call a hook stopped was sent")
	}
}

// The automatic research is paced below the job's runaway fuse, so a person's "Research deeper" in the same minute is never refused,
// and it has the daily number of automatic calls.
func TestResearch_AutomaticPaceAndDailyNumber(t *testing.T) {
	a := researchSetup(t, ai.ResearchEconomy, false)
	la := &layerAnswers{by: map[string]string{"Quick": verdict("unsure", "low", "")}}
	a.fake.research = la.answer
	a.want("PUT", "/ai/config", "admin", `{"tier":"med","monthly_budget":150000000,"redact_pii":true,"auto_read":true,"daily_reads":45}`, 200, "")
	var at []time.Time
	for i := range 45 {
		if _, err := a.svc.Research(a.ctx(), "system", researchReq); err != nil {
			t.Fatalf("automatic call %d: %v", i+1, err)
		}
		at = append(at, a.clock.Now())
		if i%3 == 2 {
			deeper := researchReq
			deeper.Deeper = true
			if _, err := a.svc.Research(a.ctx(), "it@acme.example", deeper); err != nil {
				t.Fatalf("a person's call after %d automatic calls was refused: %v", i+1, err)
			}
		}
	}
	for i := 20; i < len(at); i++ {
		if d := at[i].Sub(at[i-20]); d < time.Minute {
			t.Fatalf("21 automatic calls within %s: want at most 20 in any minute", d)
		}
	}
	n := len(la.calls)
	if _, err := a.svc.Research(a.ctx(), "system", researchReq); err == nil || !strings.Contains(err.Error(), "used up") {
		t.Errorf("past the daily number: %v", err)
	}
	if len(la.calls) != n {
		t.Error("a call past the daily number was sent")
	}
}

// A quote counts as checked only when the whole of it is in the text: a quote whose first words are the vendor's sentence but whose end
// the model wrote itself (here a release the vendor never named) is not a checked quote, whatever the share of words that match.
func TestResearch_QuoteWithAMadeUpEndIsNotChecked(t *testing.T) {
	a := researchSetup(t, ai.ResearchEconomy, false)
	pageServer(t, a)
	const real = "Widget releases 4.0 through 4.2.0 are affected by this issue"
	la := &layerAnswers{by: map[string]string{"Quick": verdict("affected", "high", real+" and 4.1.3")},
		texts: map[string][]string{"Quick": {"Advisory for CVE-2099-81001. " + real + ". Update to 4.2.1."}}}
	a.fake.research = la.answer
	ans, err := a.svc.Research(a.ctx(), "it@acme.example", researchReq)
	if err != nil {
		t.Fatal(err)
	}
	if ai.QuoteChecked(ans.QuoteCheck) {
		t.Errorf("quote check %s: a quote whose end is not in the text was taken as checked", ans.QuoteCheck)
	}
	la.by["Quick"] = verdict("affected", "high", real)
	if ans, _ = a.svc.Research(a.ctx(), "it@acme.example", researchReq); ans.QuoteCheck != ai.QuoteTool {
		t.Errorf("the whole sentence: %s", ans.QuoteCheck)
	}
}

// A turn the provider pauses is sent again with the whole assistant content so far (earlier searches and results kept), and the
// layer's caps hold across the continuations: each resend offers only the searches and fetches left, none once a cap is used up.
func TestResearch_PausedTurnKeepsResultsAndCaps(t *testing.T) {
	a := researchSetup(t, ai.ResearchEconomy, false) // economy quick: 2 searches, 3 fetches
	turn := 0
	var seen []provider.Request
	a.fake.research = func(_ context.Context, _ ai.Profile, req provider.Request) (provider.Response, error) {
		turn++
		seen = append(seen, req)
		switch turn {
		case 1:
			return provider.Response{Raw: json.RawMessage(`[{"type":"text","text":"first part"}]`), Usage: provider.Usage{InputTokens: 10, OutputTokens: 1}, Stop: provider.StopPause,
				Web: provider.WebUse{Searches: 1, Fetched: []string{"https://example.com/a", "https://example.com/b"}}}, nil
		case 2:
			return provider.Response{Raw: json.RawMessage(`[{"type":"text","text":"second part"}]`), Usage: provider.Usage{InputTokens: 10, OutputTokens: 1}, Stop: provider.StopPause,
				Web: provider.WebUse{Searches: 1, Fetched: []string{"https://example.com/c"}}}, nil
		}
		return provider.Response{Text: verdict("unsure", "low", ""), Usage: provider.Usage{InputTokens: 10, OutputTokens: 1}, Stop: provider.StopEnd}, nil
	}
	if _, err := a.svc.Research(a.ctx(), "it@acme.example", researchReq); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 {
		t.Fatalf("%d requests", len(seen))
	}
	if w := seen[0].Web; w == nil || w.Searches != 2 || w.Fetches != 3 {
		t.Errorf("first request caps %+v", w)
	}
	if w := seen[1].Web; w == nil || w.Searches != 1 || w.Fetches != 1 {
		t.Errorf("second request caps %+v, want what is left (1 search, 1 fetch)", w)
	}
	if w := seen[2].Web; w != nil && (w.Searches > 0 || w.Fetches > 0) {
		t.Errorf("third request still offers web tools %+v after the caps were used up", w)
	}
	last := seen[2].Messages
	if len(last) != 2 || last[1].Role != provider.RoleAssistant || !strings.Contains(string(last[1].Raw), "first part") || !strings.Contains(string(last[1].Raw), "second part") {
		t.Errorf("the last resend lost earlier content: %+v", last)
	}
}
