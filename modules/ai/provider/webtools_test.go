package provider

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// The provider's own web tools (Anthropic server tools): sent capped, what they returned is kept for the box's quote check, a paused
// turn says so, and any other provider refuses such a request before anything is sent.
func TestAnthropicWebToolsAreCappedAndTheirTextIsKept(t *testing.T) {
	var got captured
	reply := `{"type":"message","model":"m-1","stop_reason":"end_turn","usage":{"input_tokens":900,"output_tokens":40,"server_tool_use":{"web_search_requests":2}},
	"content":[{"type":"text","text":"Looking."},
	{"type":"server_tool_use","id":"s1","name":"web_search","input":{"query":"acme widget CVE-2026-1111 fixed"}},
	{"type":"web_search_tool_result","tool_use_id":"s1","content":[{"type":"web_search_result","url":"https://acme.example/sa","title":"Acme security advisory SA-1 for the widget product","encrypted_content":"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"}]},
	{"type":"server_tool_use","id":"f1","name":"web_fetch","input":{"url":"https://acme.example/sa"}},
	{"type":"web_fetch_tool_result","tool_use_id":"f1","content":{"type":"web_fetch_result","url":"https://acme.example/sa","content":{"type":"document","source":{"type":"text","media_type":"text/plain","data":"Widget 4.2.1 fixes CVE-2026-1111; every 4.x release before it is affected."}}}},
	{"type":"server_tool_use","id":"f2","name":"web_fetch","input":{"url":"https://gone.example/"}},
	{"type":"web_fetch_tool_result","tool_use_id":"f2","content":{"type":"web_fetch_tool_error","error_code":"url_not_accessible"}},
	{"type":"text","text":"{\"verdict\":\"affected\"}","citations":[{"type":"web_search_result_location","url":"https://acme.example/sa","cited_text":"every 4.x release before it is affected according to the vendor"}]}]}`
	p := must(t, cfg(StyleAnthropic, serve(t, 200, reply, &got).URL))
	req := simpleReq
	req.Web = &WebTools{Searches: 3, Fetches: 4, PageTokens: 6000}
	res, err := p.Complete(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	tools, _ := got.body["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("tools sent: %v", got.body["tools"])
	}
	search, fetch := tools[0].(map[string]any), tools[1].(map[string]any)
	if search["type"] != anWebSearch || search["max_uses"] != float64(3) || fetch["type"] != anWebFetch || fetch["max_uses"] != float64(4) || fetch["max_content_tokens"] != float64(6000) {
		t.Fatalf("caps: %v %v", search, fetch)
	}
	if res.Web.Searches != 2 || !slices.Equal(res.Web.Queries, []string{"acme widget CVE-2026-1111 fixed"}) ||
		!slices.Equal(res.Web.Fetched, []string{"https://acme.example/sa", "https://gone.example/"}) || !slices.Equal(res.Web.Errors, []string{"url_not_accessible"}) {
		t.Fatalf("web use: %+v", res.Web)
	}
	joined := strings.Join(res.Web.Texts, "\n")
	for _, want := range []string{"Widget 4.2.1 fixes CVE-2026-1111", "Acme security advisory SA-1", "according to the vendor"} {
		if !strings.Contains(joined, want) {
			t.Errorf("tool text %q not kept: %q", want, joined)
		}
	}
	if strings.Contains(joined, "ZZZZ") {
		t.Error("encrypted search content was kept as text")
	}
	if !strings.HasSuffix(res.Text, `{"verdict":"affected"}`) {
		t.Errorf("text %q", res.Text)
	}
}

func TestAnthropicPausedTurn(t *testing.T) {
	reply := `{"type":"message","model":"m-1","stop_reason":"pause_turn","usage":{"input_tokens":5,"output_tokens":1},"content":[{"type":"text","text":"…"}]}`
	res, err := must(t, cfg(StyleAnthropic, serve(t, 200, reply, nil).URL)).Complete(t.Context(), simpleReq)
	if err != nil || res.Stop != StopPause {
		t.Fatalf("%v %v", res.Stop, err)
	}
}

func TestOtherProvidersRefuseWebTools(t *testing.T) {
	for _, style := range []APIStyle{StyleOpenAI, StyleGemini} {
		var got captured
		srv := serve(t, 200, `{}`, &got)
		req := simpleReq
		req.Web = &WebTools{Searches: 1, Fetches: 1, PageTokens: 1000}
		if _, err := must(t, cfg(style, srv.URL)).Complete(t.Context(), req); !errors.Is(err, ErrNoWebTools) {
			t.Errorf("%s: %v", style, err)
		}
		if got.path != "" {
			t.Errorf("%s: a request was sent", style)
		}
	}
}
