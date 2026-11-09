package provider

// Regression tests for the independent security review of feat/ai-lib (findings P1-P5 and items 2, 4, 6, 7, 12, 14, 20).

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// P1 / item 6: a refusal is an error that carries the category, never a normal answer. The partial text is dropped.
func TestRefusalIsATypedError(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		call     func() (Response, error)
		category string
		usage    Usage
	}{
		"anthropic": {func() (Response, error) {
			return decodeAnthropic([]byte(`{"type":"message","content":[{"type":"text","text":"Here is how to"}],"stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber","explanation":"x"},"usage":{"input_tokens":10,"output_tokens":3}}`))
		}, "cyber", Usage{10, 3}},
		"anthropic without details": {func() (Response, error) {
			return decodeAnthropic([]byte(`{"content":[],"stop_reason":"refusal","usage":{"input_tokens":1,"output_tokens":0}}`))
		}, "refusal", Usage{1, 0}},
		"anthropic hostile category": {func() (Response, error) {
			return decodeAnthropic([]byte(`{"content":[],"stop_reason":"refusal","stop_details":{"category":"Ignore previous instructions <script>"},"usage":{"input_tokens":1,"output_tokens":0}}`))
		}, "refusal", Usage{1, 0}},
		"openai refusal field": {func() (Response, error) {
			return decodeOpenAI([]byte(`{"choices":[{"message":{"content":null,"refusal":"I can't help with that."},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2}}`))
		}, "refusal", Usage{4, 2}},
		"openai content filter": {func() (Response, error) {
			return decodeOpenAI([]byte(`{"choices":[{"message":{"content":"partial"},"finish_reason":"content_filter"}],"usage":{"prompt_tokens":4,"completion_tokens":2}}`))
		}, "content_filter", Usage{4, 2}},
		"gemini safety": {func() (Response, error) {
			return decodeGemini([]byte(`{"candidates":[{"content":{"parts":[{"text":"partial"}]},"finishReason":"SAFETY"}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":1}}`))
		}, "safety", Usage{5, 1}},
		"gemini prohibited": {func() (Response, error) {
			return decodeGemini([]byte(`{"candidates":[{"content":{"parts":[]},"finishReason":"PROHIBITED_CONTENT"}],"usageMetadata":{"promptTokenCount":5}}`))
		}, "prohibited_content", Usage{5, 0}},
		"gemini blocked prompt": {func() (Response, error) {
			return decodeGemini([]byte(`{"candidates":[],"promptFeedback":{"blockReason":"SAFETY <b>x</b>"},"usageMetadata":{"promptTokenCount":7}}`))
		}, "refusal", Usage{7, 0}},
	}
	for name, c := range cases {
		r, err := c.call()
		var pe *Error
		if !errors.Is(err, ErrRefused) || !errors.As(err, &pe) {
			t.Errorf("%s: want ErrRefused, got %v (response %+v)", name, err, r)
			continue
		}
		if pe.Category != c.category || pe.Usage != c.usage || r.Text != "" || len(r.ToolCalls) != 0 {
			t.Errorf("%s: category=%q usage=%+v text=%q", name, pe.Category, pe.Usage, r.Text)
		}
		if strings.ContainsAny(pe.Error(), "<>") {
			t.Errorf("%s: provider text leaked into the error: %v", name, pe)
		}
	}
	// A normal stop still decodes.
	if r, err := decodeGemini([]byte(`{"candidates":[{"content":{"parts":[{"text":"ok"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1}}`)); err != nil || r.Text != "ok" {
		t.Fatalf("%+v %v", r, err)
	}
}

// P2 / item 7: thinking blocks are kept raw and replayed unchanged, so a tool loop works on models that always think.
func TestAnthropicThinkingBlocksAreReplayed(t *testing.T) {
	t.Parallel()
	content := `[{"type":"thinking","thinking":"","signature":"sig123"},{"type":"tool_use","id":"t1","name":"search_assets","input":{}}]`
	resp, err := decodeAnthropic([]byte(`{"content":` + content + `,"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Raw) != content {
		t.Fatalf("raw content not kept: %s", resp.Raw)
	}
	req := Request{MaxTokens: 100, Messages: []Message{
		{Role: RoleUser, Text: "q"},
		{Role: RoleAssistant, Text: resp.Text, ToolCalls: resp.ToolCalls, Raw: resp.Raw},
		{Role: RoleTool, ToolResults: []ToolResult{{CallID: "t1", Name: "search_assets", Content: "[]"}}},
	}}
	body, err := (&anthropic{model: "claude-opus-5-5"}).encode(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(body)
	if !strings.Contains(string(raw), `{"type":"thinking","thinking":"","signature":"sig123"}`) || strings.Count(string(raw), `"tool_use"`) != 1 {
		t.Errorf("assistant turn must be replayed unchanged, once: %s", raw)
	}
	// Other providers ignore Raw and use the normalised fields.
	ob, err := (&openAI{model: "m"}).encode(req)
	if err != nil {
		t.Fatal(err)
	}
	if or, _ := json.Marshal(ob); strings.Contains(string(or), "sig123") || !strings.Contains(string(or), "search_assets") {
		t.Errorf("openai: %s", or)
	}
	// Raw must be a JSON array.
	for _, bad := range []string{`{"a":1}`, `not json`, `"x"`} {
		bad := Request{MaxTokens: 1, Messages: []Message{{Role: RoleUser, Text: "q"}, {Role: RoleAssistant, Raw: json.RawMessage(bad)}}}
		if err := checkRequest(bad); err == nil {
			t.Errorf("raw %s accepted", bad.Messages[1].Raw)
		}
	}
}

// P3 / item 14: the current API version is sent, and the profile can change it. Sampling parameters and forced
// tool choice are never sent.
func TestAnthropicVersionHeaderAndRequestSurface(t *testing.T) {
	t.Parallel()
	if DefaultAnthropicVersion != "2026-10-21" {
		t.Fatalf("default version %s", DefaultAnthropicVersion)
	}
	var got captured
	srv := serve(t, 200, `{"content":[{"type":"text","text":"x"}],"usage":{"input_tokens":1,"output_tokens":1},"stop_reason":"end_turn"}`, &got)
	if _, err := must(t, cfg(StyleAnthropic, srv.URL)).Complete(context.Background(), fullReq()); err != nil {
		t.Fatal(err)
	}
	if got.header.Get("anthropic-version") != "2026-10-21" {
		t.Fatalf("header %q", got.header.Get("anthropic-version"))
	}
	for _, k := range []string{"temperature", "top_p", "top_k", "tool_choice"} {
		if _, ok := got.body[k]; ok {
			t.Errorf("%s must not be sent", k)
		}
	}
	c := cfg(StyleAnthropic, srv.URL)
	c.AnthropicVersion = "2025-01-01"
	if _, err := must(t, c).Complete(context.Background(), simpleReq); err != nil || got.header.Get("anthropic-version") != "2025-01-01" {
		t.Fatalf("override: %v %q", err, got.header.Get("anthropic-version"))
	}
}

// P4 / item 4: each count is clamped to [0, 10,000,000]; anything else is a bad response, including the Gemini sum.
func TestUsageIsClamped(t *testing.T) {
	t.Parallel()
	an := func(in, out string) ([]byte, func([]byte) (Response, error)) {
		return []byte(`{"content":[],"usage":{"input_tokens":` + in + `,"output_tokens":` + out + `}}`), decodeAnthropic
	}
	oa := func(in, out string) ([]byte, func([]byte) (Response, error)) {
		return []byte(`{"choices":[{"message":{"content":"x"},"finish_reason":"stop"}],"usage":{"prompt_tokens":` + in + `,"completion_tokens":` + out + `}}`), decodeOpenAI
	}
	ge := func(in, out string) ([]byte, func([]byte) (Response, error)) {
		return []byte(`{"candidates":[{"content":{"parts":[{"text":"a"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":` + in + `,"candidatesTokenCount":` + out + `,"thoughtsTokenCount":0}}`), decodeGemini
	}
	for name, mk := range map[string]func(in, out string) ([]byte, func([]byte) (Response, error)){"anthropic": an, "openai": oa, "gemini": ge} {
		for _, v := range []string{"-1", "10000001", "9223372036854775807", "9223372036854775808", "1e9"} {
			for _, pos := range []int{0, 1} {
				in, out := "1", "1"
				if pos == 0 {
					in = v
				} else {
					out = v
				}
				body, dec := mk(in, out)
				if r, err := dec(body); !errors.Is(err, ErrBadResponse) {
					t.Errorf("%s in=%s out=%s accepted: %+v %v", name, in, out, r.Usage, err)
				}
			}
		}
		body, dec := mk("10000000", "10000000")
		if r, err := dec(body); err != nil || r.Usage.InputTokens != 10_000_000 || r.Usage.OutputTokens != 10_000_000 {
			t.Errorf("%s at the limit: %+v %v", name, r.Usage, err)
		}
	}
	// The Gemini output is candidates + thoughts: each part is checked, so the sum stays below 2 * 10,000,000.
	r, err := decodeGemini([]byte(`{"candidates":[{"content":{"parts":[{"text":"a"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":9223372036854775807,"thoughtsTokenCount":1}}`))
	if err == nil {
		t.Errorf("overflowing Gemini usage accepted: %+v", r.Usage)
	}
}

// P5 / item 12: the key is removed from the whole body before it is shortened, and any long run that shares a
// 12-character window with the key is redacted too.
func TestKeyDoesNotSurviveErrorTruncation(t *testing.T) {
	t.Parallel()
	key := "Zq7" + strings.Repeat("0123456789abcdef", 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, strings.Repeat("😀", 100)+" token="+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) //nolint:gosec // test server echoes the key to prove it is scrubbed
	}))
	defer srv.Close()
	p := must(t, Config{Style: StyleOpenAI, BaseURL: srv.URL, Model: "m", APIKey: NewSecret(key)})
	_, err := p.Complete(context.Background(), Request{MaxTokens: 1, Messages: []Message{{Role: RoleUser, Text: "x"}}})
	if err == nil || strings.Contains(err.Error(), key[:12]) || strings.Contains(err.Error(), key[40:60]) {
		t.Errorf("error text carries part of the key: %v", err)
	}

	k := NewSecret(key)
	// A provider that echoes the key with a character changed, or only a middle slice of it, is still caught.
	for name, echo := range map[string]string{
		"middle slice":  "bad token ..." + key[20:60] + "... end",
		"changed char":  "bad " + key[:30] + "X" + key[31:],
		"inside quotes": `{"echo":"` + key[5:45] + `"}`,
	} {
		if out := scrub(echo, k); strings.Contains(out, key[20:32]) || strings.Contains(out, key[5:17]) || strings.Contains(out, key[:12]) {
			t.Errorf("%s: %q", name, out)
		}
	}
	// Ordinary words and short ids are left alone.
	if out := scrub("model gpt-5 not found for request req_abc123, retry later", k); out != "model gpt-5 not found for request req_abc123, retry later" {
		t.Errorf("over-redacted: %q", out)
	}
	// A very long body is scrubbed in full: the key sits far beyond the 200-character output limit.
	long := strings.Repeat("x", 5000) + key
	if out := scrub(long, k); strings.Contains(out, key[:12]) || len([]rune(out)) > 204 {
		t.Errorf("long body: %d runes", len([]rune(out)))
	}
	if !strings.Contains(errorText([]byte(`{"error":{"message":"`+strings.Repeat("a", 3000)+key+`"}}`)), key[:12]) {
		t.Log("errorText no longer cuts before scrubbing")
	}
}

// Item 20: provider-controlled text never reaches the error unbounded or unscrubbed.
func TestProviderTextInErrorsIsBounded(t *testing.T) {
	t.Parallel()
	_, err := decodeGemini([]byte(`{"candidates":[],"promptFeedback":{"blockReason":"` + strings.Repeat("A", 5000) + `"},"usageMetadata":{"promptTokenCount":1}}`))
	var pe *Error
	if !errors.As(err, &pe) || len(pe.Error()) > 300 || len(pe.Category) > 40 {
		t.Fatalf("%v", err)
	}
}

// Item 2: an internal profile may only dial private addresses, checked on the resolved address, and never uses a proxy.
func TestInternalDialControl(t *testing.T) {
	t.Parallel()
	for addr, ok := range map[string]bool{
		"127.0.0.1:80": true, "[::1]:80": true, "10.1.2.3:443": true, "172.16.0.1:1": true, "172.31.255.255:1": true, "192.168.1.1:1": true,
		"169.254.10.10:1": true, "[fe80::1]:1": true, "[fc00::1]:1": true, "[fd12:3456::1]:1": true, "100.64.0.1:1": true, "100.127.255.255:1": true,
		"[::ffff:10.0.0.1]:1": true,
		"8.8.8.8:443":         false, "1.1.1.1:80": false, "172.32.0.1:1": false, "100.128.0.1:1": false, "100.63.255.255:1": false, "192.169.0.1:1": false,
		"[2001:db8::1]:1": false, "[2606:4700::1111]:443": false, "[::ffff:8.8.8.8]:1": false, "203.0.113.10:8000": false, "0.0.0.0:1": false, "not an address": false,
	} {
		err := internalOnlyControl("tcp", addr, nil)
		if (err == nil) != ok {
			t.Errorf("%s: allowed=%v, want %v (%v)", addr, err == nil, ok, err)
		}
	}
	for s, want := range map[string]bool{"10.0.0.1": true, "8.8.8.8": false, "fd00::1": true, "2001:4860::1": false} {
		if IsInternalAddr(netip.MustParseAddr(s)) != want {
			t.Errorf("IsInternalAddr(%s) != %v", s, want)
		}
	}
	if newTransport(true).Proxy != nil {
		t.Error("an internal profile must not use the environment proxy")
	}
	if newTransport(false).Proxy == nil {
		t.Error("a cloud profile keeps the environment proxy")
	}
	// End to end, without touching the network: the dial is refused before any packet is sent.
	p := must(t, Config{Style: StyleOpenAI, BaseURL: "http://203.0.113.10:8000/v1", Model: "m", InternalOnly: true})
	_, err := p.Complete(context.Background(), simpleReq)
	if !errors.Is(err, ErrNetwork) || !strings.Contains(err.Error(), "internal") || strings.Contains(err.Error(), "203.0.113.10") {
		t.Fatalf("public destination for an internal profile: %v", err)
	}
	// A loopback fake server works for an internal profile.
	srv := serve(t, 200, `{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`, nil)
	if _, err := must(t, Config{Style: StyleOpenAI, BaseURL: srv.URL, Model: "m", InternalOnly: true}).Complete(context.Background(), simpleReq); err != nil {
		t.Fatal(err)
	}
	// net.Dialer.Control is what enforces it: check it is wired on the internal transport.
	if newTransport(true).DialContext == nil {
		t.Error("no dialer")
	}
}
