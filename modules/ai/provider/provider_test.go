package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testKey = "sk-test-SECRET-0123456789"

type captured struct {
	path   string
	query  string
	header http.Header
	body   map[string]any
}

// serve starts a fake provider that records the request and answers with status and body.
func serve(t *testing.T, status int, reply string, got *captured) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got != nil {
			b, _ := io.ReadAll(r.Body)
			got.path, got.query, got.header = r.URL.Path, r.URL.RawQuery, r.Header.Clone()
			got.body = map[string]any{}
			_ = json.Unmarshal(b, &got.body)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cfg(style APIStyle, base string) Config {
	return Config{Style: style, BaseURL: base, Model: "m-1", APIKey: NewSecret(testKey)}
}

func must(t *testing.T, c Config) Provider {
	t.Helper()
	p, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var simpleReq = Request{System: "be brief", Messages: []Message{{Role: RoleUser, Text: "hi"}}, MaxTokens: 100}

const toolSchema = `{"type":"object","properties":{"ip":{"type":"string"}},"required":["ip"]}`

func fullReq() Request {
	return Request{
		System: "sys",
		Messages: []Message{
			{Role: RoleUser, Text: "which hosts?"},
			{Role: RoleAssistant, Text: "checking", ToolCalls: []ToolCall{{ID: "c1", Name: "search_assets", Arguments: json.RawMessage(`{"ip":"10.0.0.1"}`)}}},
			{Role: RoleTool, ToolResults: []ToolResult{{CallID: "c1", Name: "search_assets", Content: "1 device"}}},
		},
		Tools:     []ToolDef{{Name: "search_assets", Description: "Find devices", InputSchema: json.RawMessage(toolSchema)}},
		Schema:    &Schema{Name: "answer", JSON: json.RawMessage(`{"type":"object","properties":{"a":{"type":"string"}}}`)},
		MaxTokens: 500,
	}
}

func TestAnthropicWireFormat(t *testing.T) {
	t.Parallel()
	var got captured
	srv := serve(t, 200, `{"id":"msg_1","type":"message","role":"assistant","model":"m-1-actual","content":[{"type":"text","text":"Hello "},{"type":"text","text":"world"},{"type":"tool_use","id":"tu_1","name":"search_assets","input":{"ip":"10.0.0.2"}}],"stop_reason":"tool_use","usage":{"input_tokens":12,"output_tokens":7}}`, &got)
	resp, err := must(t, cfg(StyleAnthropic, srv.URL+"/")).Complete(context.Background(), fullReq())
	if err != nil {
		t.Fatal(err)
	}
	if got.path != "/v1/messages" || got.header.Get("x-api-key") != testKey || got.header.Get("anthropic-version") != DefaultAnthropicVersion {
		t.Fatalf("path/headers wrong: %s %v", got.path, got.header)
	}
	if got.header.Get("Authorization") != "" {
		t.Fatal("anthropic must not send a bearer header")
	}
	b := got.body
	if b["model"] != "m-1" || b["max_tokens"] != float64(500) || b["system"] != "sys" {
		t.Fatalf("body: %v", b)
	}
	msgs := b["messages"].([]any)
	asst := msgs[1].(map[string]any)["content"].([]any)
	if asst[1].(map[string]any)["type"] != "tool_use" || asst[1].(map[string]any)["input"].(map[string]any)["ip"] != "10.0.0.1" {
		t.Fatalf("assistant tool_use not encoded: %v", asst)
	}
	res := msgs[2].(map[string]any)
	if res["role"] != "user" || res["content"].([]any)[0].(map[string]any)["tool_use_id"] != "c1" {
		t.Fatalf("tool_result not encoded: %v", res)
	}
	if b["tools"].([]any)[0].(map[string]any)["input_schema"] == nil {
		t.Fatal("tool schema missing")
	}
	if b["output_config"].(map[string]any)["format"].(map[string]any)["type"] != "json_schema" {
		t.Fatalf("structured output missing: %v", b["output_config"])
	}
	want := Response{Text: "Hello world", Usage: Usage{12, 7}, Stop: StopToolUse, Model: "m-1-actual"}
	if resp.Text != want.Text || resp.Usage != want.Usage || resp.Stop != want.Stop || resp.Model != want.Model {
		t.Fatalf("response: %+v", resp)
	}
	if len(resp.ToolCalls) != 1 || resp.ToolCalls[0].ID != "tu_1" || string(resp.ToolCalls[0].Arguments) != `{"ip":"10.0.0.2"}` {
		t.Fatalf("tool calls: %+v", resp.ToolCalls)
	}
}

func TestOpenAIWireFormat(t *testing.T) {
	t.Parallel()
	reply := `{"model":"gpt-x","choices":[{"message":{"content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"search_assets","arguments":"{\"ip\":\"10.0.0.3\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":20,"completion_tokens":5}}`
	for _, compat := range []bool{false, true} {
		var got captured
		srv := serve(t, 200, reply, &got)
		c := cfg(StyleOpenAI, srv.URL+"/v1")
		c.CompatMode = compat
		resp, err := must(t, c).Complete(context.Background(), fullReq())
		if err != nil {
			t.Fatal(err)
		}
		if got.path != "/v1/chat/completions" || got.header.Get("Authorization") != "Bearer "+testKey {
			t.Fatalf("path/headers: %s %v", got.path, got.header)
		}
		_, hasOld := got.body["max_tokens"]
		_, hasNew := got.body["max_completion_tokens"]
		if hasOld != compat || hasNew == compat {
			t.Fatalf("compat=%v but max_tokens=%v max_completion_tokens=%v", compat, hasOld, hasNew)
		}
		msgs := got.body["messages"].([]any)
		if msgs[0].(map[string]any)["role"] != "system" || msgs[3].(map[string]any)["role"] != "tool" || msgs[3].(map[string]any)["tool_call_id"] != "c1" {
			t.Fatalf("messages: %v", msgs)
		}
		fn := msgs[2].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)["function"].(map[string]any)
		if fn["arguments"] != `{"ip":"10.0.0.1"}` {
			t.Fatalf("arguments must be a JSON string: %v", fn)
		}
		if got.body["response_format"].(map[string]any)["type"] != "json_schema" || got.body["tools"] == nil {
			t.Fatalf("tools/response_format missing: %v", got.body)
		}
		if resp.Stop != StopToolUse || resp.Usage != (Usage{20, 5}) || resp.ToolCalls[0].ID != "call_1" || string(resp.ToolCalls[0].Arguments) != `{"ip":"10.0.0.3"}` {
			t.Fatalf("response: %+v", resp)
		}
	}
}

func TestOpenAICompatibleWithoutKey(t *testing.T) {
	t.Parallel()
	var got captured
	srv := serve(t, 200, `{"model":"qwen3:8b","choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1}}`, &got)
	p := must(t, Config{Style: StyleOpenAI, BaseURL: srv.URL + "/v1", Model: "qwen3:8b", CompatMode: true})
	resp, err := p.Complete(context.Background(), simpleReq)
	if err != nil || resp.Text != "ok" || resp.Stop != StopEnd {
		t.Fatalf("%+v %v", resp, err)
	}
	if _, ok := got.header["Authorization"]; ok {
		t.Fatal("no key: no Authorization header")
	}
}

func TestGeminiWireFormat(t *testing.T) {
	t.Parallel()
	var got captured
	srv := serve(t, 200, `{"candidates":[{"content":{"parts":[{"text":"thinking...","thought":true},{"text":"Answer."},{"functionCall":{"name":"search_assets","args":{"ip":"10.0.0.4"}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":30,"candidatesTokenCount":4,"thoughtsTokenCount":6},"modelVersion":"gem-1"}`, &got)
	c := cfg(StyleGemini, srv.URL)
	c.Model = "models/gem-1"
	resp, err := must(t, c).Complete(context.Background(), fullReq())
	if err != nil {
		t.Fatal(err)
	}
	if got.path != "/v1beta/models/gem-1:generateContent" || got.header.Get("x-goog-api-key") != testKey || got.query != "" {
		t.Fatalf("path/key placement: %s ?%s %v", got.path, got.query, got.header)
	}
	if strings.Contains(fmt.Sprint(got.body), testKey) {
		t.Fatal("key must not be in the body")
	}
	if got.body["systemInstruction"] == nil || got.body["tools"].([]any)[0].(map[string]any)["functionDeclarations"] == nil {
		t.Fatalf("body: %v", got.body)
	}
	gen := got.body["generationConfig"].(map[string]any)
	if gen["maxOutputTokens"] != float64(500) || gen["responseMimeType"] != "application/json" || gen["responseJsonSchema"] == nil {
		t.Fatalf("generationConfig: %v", gen)
	}
	contents := got.body["contents"].([]any)
	if contents[1].(map[string]any)["role"] != "model" || contents[2].(map[string]any)["parts"].([]any)[0].(map[string]any)["functionResponse"] == nil {
		t.Fatalf("contents: %v", contents)
	}
	if resp.Text != "Answer." || resp.Usage != (Usage{30, 10}) || resp.Stop != StopToolUse || resp.ToolCalls[0].Name != "search_assets" || resp.Model != "gem-1" {
		t.Fatalf("response: %+v", resp)
	}
}

func TestCustomProfileStyles(t *testing.T) {
	t.Parallel()
	for kind, want := range map[string]APIStyle{"anthropic": StyleAnthropic, "openai": StyleOpenAI, "openai-compatible": StyleOpenAI, "gemini": StyleGemini} {
		if got, err := StyleForKind(kind, ""); err != nil || got != want {
			t.Errorf("%s: %v %v", kind, got, err)
		}
	}
	if got, err := StyleForKind("custom", StyleGemini); err != nil || got != StyleGemini {
		t.Errorf("custom gemini: %v %v", got, err)
	}
	for _, bad := range [][2]string{{"custom", ""}, {"custom", "grpc"}, {"nope", "openai"}} {
		if _, err := StyleForKind(bad[0], APIStyle(bad[1])); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	// A custom profile pointing at an Anthropic-style gateway on a sub-path keeps the path.
	var got captured
	srv := serve(t, 200, `{"content":[{"type":"text","text":"x"}],"usage":{"input_tokens":1,"output_tokens":1},"stop_reason":"end_turn"}`, &got)
	if _, err := must(t, cfg(StyleAnthropic, srv.URL+"/gateway/anthropic")).Complete(context.Background(), simpleReq); err != nil {
		t.Fatal(err)
	}
	if got.path != "/gateway/anthropic/v1/messages" {
		t.Fatalf("path %s", got.path)
	}
}

func TestErrorClassification(t *testing.T) {
	t.Parallel()
	body := `{"error":{"type":"x","message":"nope for ` + testKey + `"}}`
	cases := []struct {
		status int
		want   error
	}{
		{400, ErrRequest}, {401, ErrAuth}, {403, ErrAuth}, {404, ErrRequest}, {408, ErrTimeout}, {429, ErrRateLimited},
		{500, ErrServer}, {503, ErrServer}, {529, ErrServer}, {504, ErrTimeout}, {302, ErrRequest},
	}
	for _, style := range []APIStyle{StyleAnthropic, StyleOpenAI, StyleGemini} {
		for _, c := range cases {
			t.Run(fmt.Sprintf("%s/%d", style, c.status), func(t *testing.T) {
				t.Parallel()
				srv := serve(t, c.status, body, nil)
				_, err := must(t, cfg(style, srv.URL)).Complete(context.Background(), simpleReq)
				if !errors.Is(err, c.want) {
					t.Fatalf("got %v, want %v", err, c.want)
				}
				var pe *Error
				if !errors.As(err, &pe) || pe.Status != c.status {
					t.Fatalf("status not kept: %v", err)
				}
				if strings.Contains(err.Error(), testKey) || strings.Contains(err.Error(), srv.URL) {
					t.Fatalf("error leaks key or URL: %v", err)
				}
			})
		}
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	_, err := must(t, cfg(StyleAnthropic, srv.URL)).Complete(context.Background(), simpleReq)
	if !errors.Is(err, ErrRequest) || hits.Load() != 0 {
		t.Fatalf("redirect followed or not rejected: %v hits=%d", err, hits.Load())
	}
}

func TestTimeoutAndCancel(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	c := cfg(StyleOpenAI, srv.URL)
	c.Timeout = 30 * time.Millisecond
	if _, err := must(t, c).Complete(context.Background(), simpleReq); !errors.Is(err, ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
	// The caller cancelling is not a provider failure.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := must(t, cfg(StyleOpenAI, srv.URL)).Complete(ctx, simpleReq); !errors.Is(err, context.Canceled) || errors.Is(err, ErrTimeout) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestNetworkErrorHidesURLAndKey(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close()
	_, err := must(t, cfg(StyleGemini, base)).Complete(context.Background(), simpleReq)
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("got %v", err)
	}
	u, _ := url.Parse(base)
	if strings.Contains(err.Error(), u.Host) || strings.Contains(err.Error(), testKey) {
		t.Fatalf("error leaks host or key: %v", err)
	}
}

func TestOversizedAndMalformedBodies(t *testing.T) {
	t.Parallel()
	big := `{"content":[{"type":"text","text":"` + strings.Repeat("a", 2000) + `"}],"usage":{"input_tokens":1,"output_tokens":1}}`
	c := cfg(StyleAnthropic, serve(t, 200, big, nil).URL)
	c.MaxResponseBytes = 1000
	if _, err := must(t, c).Complete(context.Background(), simpleReq); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized: %v", err)
	}
	// An oversized error body is also capped, and the message stays short.
	c = cfg(StyleOpenAI, serve(t, 500, strings.Repeat("x", 100000), nil).URL)
	c.MaxResponseBytes = 1000
	if _, err := must(t, c).Complete(context.Background(), simpleReq); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized error body: %v", err)
	}
	for _, style := range []APIStyle{StyleAnthropic, StyleOpenAI, StyleGemini} {
		for name, reply := range map[string]string{
			"not json": "<html>", "empty": "", "truncated": `{"content":[{"type":"te`, "wrong shape": `[1,2,3]`, "empty object": `{}`,
			"error in 200": `{"type":"error","error":{"message":"overloaded"}}`, "negative usage": `{"content":[],"choices":[{}],"candidates":[{}],"usage":{"input_tokens":-1,"output_tokens":1,"prompt_tokens":-1,"completion_tokens":1},"usageMetadata":{"promptTokenCount":-1}}`,
		} {
			_, err := must(t, cfg(style, serve(t, 200, reply, nil).URL)).Complete(context.Background(), simpleReq)
			if !errors.Is(err, ErrBadResponse) {
				t.Errorf("%s/%s: want ErrBadResponse, got %v", style, name, err)
			}
		}
	}
}

func TestDecodersRejectBadToolCalls(t *testing.T) {
	t.Parallel()
	bad := map[string]func([]byte) (Response, error){
		`{"content":[{"type":"tool_use","id":"1","name":"x","input":[1]}],"usage":{"input_tokens":1,"output_tokens":1}}`:                                         decodeAnthropic,
		`{"content":[{"type":"tool_use","id":"1","name":"","input":{}}],"usage":{"input_tokens":1,"output_tokens":1}}`:                                           decodeAnthropic,
		`{"choices":[{"message":{"tool_calls":[{"id":"1","function":{"name":"x","arguments":"not json"}}]}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`: decodeOpenAI,
		`{"choices":[{"message":{"tool_calls":[{"id":"1","function":{"name":"x","arguments":"[1]"}}]}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`:      decodeOpenAI,
		`{"candidates":[{"content":{"parts":[{"functionCall":{"name":"x","args":"str"}}]}}],"usageMetadata":{"promptTokenCount":1}}`:                             decodeGemini,
		`{"candidates":[],"promptFeedback":{"blockReason":"SAFETY"},"usageMetadata":{"promptTokenCount":1}}`:                                                     decodeGemini,
	}
	for body, dec := range bad {
		if _, err := dec([]byte(body)); !errors.Is(err, ErrBadResponse) {
			t.Errorf("accepted %s: %v", body, err)
		}
	}
	// Empty tool arguments become {}.
	r, err := decodeOpenAI([]byte(`{"choices":[{"message":{"tool_calls":[{"id":"1","function":{"name":"x","arguments":""}}]}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	if err != nil || string(r.ToolCalls[0].Arguments) != "{}" {
		t.Fatalf("%v %+v", err, r)
	}
}

func TestStopReasons(t *testing.T) {
	t.Parallel()
	a := func(s string) StopReason {
		r, err := decodeAnthropic([]byte(`{"content":[],"stop_reason":"` + s + `","usage":{"input_tokens":1,"output_tokens":1}}`))
		if err != nil {
			t.Fatal(err)
		}
		return r.Stop
	}
	if a("end_turn") != StopEnd || a("stop_sequence") != StopEnd || a("max_tokens") != StopMaxTokens || a("refusal") != StopOther || a("pause_turn") != StopOther {
		t.Fatal("anthropic stop reasons")
	}
	o := func(s string) StopReason {
		r, _ := decodeOpenAI([]byte(`{"choices":[{"message":{"content":"x"},"finish_reason":"` + s + `"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
		return r.Stop
	}
	if o("stop") != StopEnd || o("length") != StopMaxTokens || o("content_filter") != StopOther {
		t.Fatal("openai stop reasons")
	}
	g := func(s string) StopReason {
		r, _ := decodeGemini([]byte(`{"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"` + s + `"}],"usageMetadata":{"promptTokenCount":1}}`))
		return r.Stop
	}
	if g("STOP") != StopEnd || g("MAX_TOKENS") != StopMaxTokens || g("SAFETY") != StopOther {
		t.Fatal("gemini stop reasons")
	}
}

func TestRequestAndConfigValidation(t *testing.T) {
	t.Parallel()
	srv := serve(t, 200, `{}`, nil)
	p := must(t, cfg(StyleAnthropic, srv.URL))
	for name, r := range map[string]Request{
		"no max tokens": {Messages: simpleReq.Messages},
		"no messages":   {MaxTokens: 10},
		"bad tool":      {Messages: simpleReq.Messages, MaxTokens: 10, Tools: []ToolDef{{Name: ""}}},
		"bad schema":    {Messages: simpleReq.Messages, MaxTokens: 10, Schema: &Schema{Name: "s", JSON: json.RawMessage(`{`)}},
		"bad args":      {MaxTokens: 10, Messages: []Message{{Role: RoleAssistant, ToolCalls: []ToolCall{{Name: "x", Arguments: json.RawMessage(`[1]`)}}}}},
		"bad role":      {MaxTokens: 10, Messages: []Message{{Role: "robot", Text: "x"}}},
	} {
		if _, err := p.Complete(context.Background(), r); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for _, base := range []string{"", "ftp://x", "https://", "https://u:p@host", "https://host?key=1", "https://host#x", "not a url", "//host"} {
		if _, err := New(cfg(StyleOpenAI, base)); err == nil {
			t.Errorf("base %q accepted", base)
		}
	}
	for _, model := range []string{"", "has space", strings.Repeat("a", 81), "a\nb"} {
		c := cfg(StyleOpenAI, srv.URL)
		c.Model = model
		if _, err := New(c); err == nil {
			t.Errorf("model %q accepted", model)
		}
	}
	if _, err := New(cfg(StyleGemini, srv.URL+"/x")); err != nil {
		t.Fatal(err)
	}
	c := cfg(StyleGemini, srv.URL)
	c.Model = "a/b"
	if _, err := New(c); err == nil {
		t.Error("gemini model with slash accepted")
	}
	if _, err := New(cfg("grpc", srv.URL)); err == nil {
		t.Error("unknown style accepted")
	}
	if DefaultBaseURL("anthropic") == "" || DefaultBaseURL("openai") == "" || DefaultBaseURL("gemini") == "" || DefaultBaseURL("custom") != "" {
		t.Error("default base URLs")
	}
}

// INV-1 / SYS-4: the key never appears in formatted output, logs, JSON, provider structs or errors.
func TestContract_INV1_KeyNeverLeaks(t *testing.T) {
	t.Parallel()
	s := NewSecret(testKey)
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		if out := fmt.Sprintf(f, s); strings.Contains(out, "SECRET") || strings.Contains(out, "0123") {
			t.Errorf("%s leaks: %s", f, out)
		}
	}
	type holder struct {
		Name string
		Key  Secret
		key  Secret
	}
	h := holder{"p", s, s}
	// Includes the unexported field: fmt cannot call String() there, so the type itself must hide the text.
	if out := fmt.Sprintf("%v %+v %#v", h, &h, h); strings.Contains(out, "SECRET") || strings.Contains(out, "0123456789") {
		t.Errorf("holder leaks: %s", out)
	}
	if j, err := json.Marshal(h); err != nil || strings.Contains(string(j), "SECRET") {
		t.Errorf("json leaks: %s %v", j, err)
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", slog.Any("key", s), slog.Any("holder", h), slog.Group("g", slog.Any("k", s)))
	if strings.Contains(buf.String(), "SECRET") {
		t.Errorf("slog leaks: %s", buf.String())
	}
	if s.Last4() != "6789" || NewSecret("abc").Last4() != "" || NewSecret("").IsSet() {
		t.Error("Last4/IsSet")
	}
	srv := serve(t, 200, `{}`, nil)
	for _, st := range []APIStyle{StyleAnthropic, StyleOpenAI, StyleGemini} {
		p := must(t, cfg(st, srv.URL))
		if out := fmt.Sprintf("%v %+v %#v %s", p, p, p, p); strings.Contains(out, "SECRET") || strings.Contains(out, srv.URL) {
			t.Errorf("%s provider prints secrets: %s", st, out)
		}
	}
	if scrub("bad key "+testKey+" and sk-proj-abcdef123456 and AIzaSyABCDEFGHIJKL; disk-usage ok", s) != "bad key [redacted] and [redacted] and [redacted]; disk-usage ok" {
		t.Errorf("scrub: %q", scrub("bad key "+testKey+" and sk-proj-abcdef123456 and AIzaSyABCDEFGHIJKL; disk-usage ok", s))
	}
	if got := scrub(strings.Repeat("é", 500)+"\n\x00", Secret{}); len([]rune(got)) > 204 || strings.ContainsAny(got, "\n\x00") {
		t.Errorf("scrub does not cap or clean: %d", len([]rune(got)))
	}
}

type probeFake struct {
	rejectTools, plainSchema bool
	calls                    []Request
}

func (f *probeFake) Complete(_ context.Context, r Request) (Response, error) {
	f.calls = append(f.calls, r)
	switch {
	case len(r.Tools) > 0 && f.rejectTools:
		return Response{}, &Error{Kind: ErrRequest, Status: 400}
	case r.Schema != nil && f.plainSchema:
		return Response{Text: "sure, here you go"}, nil
	case r.Schema != nil:
		return Response{Text: `{"ok":true}`}, nil
	}
	return Response{Text: "ok", Usage: Usage{14, 3}}, nil
}

func TestProbeReportsLatencyTokensAndCapabilities(t *testing.T) {
	t.Parallel()
	tick := time.Unix(0, 0)
	now := func() time.Time { tick = tick.Add(180 * time.Millisecond); return tick }
	r, err := Probe(context.Background(), &probeFake{}, now)
	if err != nil || r.Latency != 180*time.Millisecond || r.TokensIn != 14 || r.TokensOut != 3 || !r.Tools || !r.Structured {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = Probe(context.Background(), &probeFake{rejectTools: true, plainSchema: true}, now)
	if err != nil || r.Tools || r.Structured {
		t.Fatalf("capabilities must be false when not proven: %+v %v", r, err)
	}
	// A failing basic call is the error; no capability probing follows.
	f := errProvider{err: &Error{Kind: ErrAuth, Status: 401}}
	if _, err := Probe(context.Background(), f, now); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v", err)
	}
}

type errProvider struct{ err error }

func (e errProvider) Complete(context.Context, Request) (Response, error) { return Response{}, e.err }

func TestProbeEndToEnd(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["tools"] != nil {
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"error":{"message":"tools unsupported"}}`)
			return
		}
		text := "ok"
		if b["response_format"] != nil {
			text = `{"ok":true}`
		}
		_, _ = fmt.Fprintf(w, `{"model":"m","choices":[{"message":{"content":%q},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":2}}`, text)
	}))
	defer srv.Close()
	res, err := Probe(context.Background(), must(t, cfg(StyleOpenAI, srv.URL)), time.Now)
	if err != nil || res.Tools || !res.Structured || res.TokensIn != 9 || res.TokensOut != 2 {
		t.Fatalf("%+v %v", res, err)
	}
}

func FuzzDecodeAnthropic(f *testing.F) {
	fuzzDecoder(f, decodeAnthropic, `{"content":[{"type":"text","text":"a"},{"type":"tool_use","id":"1","name":"n","input":{"x":1}}],"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":2}}`)
}
func FuzzDecodeOpenAI(f *testing.F) {
	fuzzDecoder(f, decodeOpenAI, `{"choices":[{"message":{"content":"a","tool_calls":[{"id":"1","function":{"name":"n","arguments":"{\"x\":1}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":2}}`)
}
func FuzzDecodeGemini(f *testing.F) {
	fuzzDecoder(f, decodeGemini, `{"candidates":[{"content":{"parts":[{"text":"a"},{"functionCall":{"name":"n","args":{"x":1}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":2}}`)
}

// fuzzDecoder checks the decoder contract on arbitrary bytes: no panic; either an ErrBadResponse or a
// response with sane usage and tool-call arguments that are JSON objects.
func fuzzDecoder(f *testing.F, dec func([]byte) (Response, error), seed string) {
	f.Add([]byte(seed))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := dec(data)
		if err != nil {
			if !errors.Is(err, ErrBadResponse) {
				t.Fatalf("unexpected error kind: %v", err)
			}
			return
		}
		if r.Usage.InputTokens < 0 || r.Usage.OutputTokens < 0 {
			t.Fatalf("negative usage: %+v", r.Usage)
		}
		for _, c := range r.ToolCalls {
			var m map[string]any
			if c.Name == "" || json.Unmarshal(c.Arguments, &m) != nil {
				t.Fatalf("bad tool call accepted: %+v", c)
			}
		}
	})
}
