package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func listCfg(style APIStyle, base string) ModelsConfig {
	return ModelsConfig{Style: style, BaseURL: base, APIKey: NewSecret(testKey)}
}

func TestListModelsOpenAIKeepsOnlyCleanSortedIDs(t *testing.T) {
	t.Parallel()
	var got captured
	srv := serve(t, 200, `{"data":[{"id":"zed-1"},{"id":"alpha"},{"id":"alpha"},{"id":"bad id <script>"},{"id":""},{"id":"qwen3:8b"},{"nope":1}]}`, &got)
	ids, err := ListModels(context.Background(), listCfg(StyleOpenAI, srv.URL+"/v1"))
	if err != nil || strings.Join(ids, ",") != "alpha,qwen3:8b,zed-1" {
		t.Fatalf("%v %v", ids, err)
	}
	if got.path != "/v1/models" || got.header.Get("Authorization") != "Bearer "+testKey {
		t.Fatalf("request: %s %v", got.path, got.header)
	}
}

func TestListModelsCapsTheCount(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString(`{"data":[`)
	for i := range 500 {
		fmt.Fprintf(&b, `%s{"id":"m-%04d"}`, map[bool]string{true: "", false: ","}[i == 0], i)
	}
	b.WriteString(`]}`)
	ids, err := ListModels(context.Background(), listCfg(StyleOpenAI, serve(t, 200, b.String(), nil).URL))
	if err != nil || len(ids) != maxListedModel {
		t.Fatalf("%d %v", len(ids), err)
	}
}

func TestListModelsFailures(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		status int
		body   string
		want   error
	}{
		"rejected key": {401, `{"error":{"message":"bad key"}}`, ErrAuth},
		"huge body":    {200, `{"data":[` + strings.Repeat(`{"id":"a"},`, 120_000) + `{"id":"b"}]}`, ErrTooLarge},
		"not json":     {200, `<html>hello</html>`, ErrBadResponse},
		"wrong shape":  {200, `{"hello":"world"}`, ErrBadResponse},
		"server error": {500, `oops`, ErrServer},
	} {
		_, err := ListModels(context.Background(), listCfg(StyleOpenAI, serve(t, c.status, c.body, nil).URL))
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), testKey) {
			t.Errorf("%s: the key is in the error", name)
		}
	}
}

// A redirect is never followed: the key would travel to the new host, which may be a private address.
func TestListModelsDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var hit atomic.Bool
	inner := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) }))
	t.Cleanup(inner.Close)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, inner.URL+"/v1/models", http.StatusFound)
	}))
	t.Cleanup(redir.Close)
	if _, err := ListModels(context.Background(), listCfg(StyleOpenAI, redir.URL+"/v1")); err == nil || hit.Load() {
		t.Fatalf("redirect followed or accepted: %v hit=%v", err, hit.Load())
	}
}

func TestListModelsRefusesVedetteItself(t *testing.T) { //nolint:paralleltest // switches ownMayDialLoopback
	ownMayDialLoopback = false
	t.Cleanup(func() { ownMayDialLoopback = true })
	var hit atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) }))
	t.Cleanup(srv.Close)
	for _, internal := range []bool{true, false} {
		c := listCfg(StyleOpenAI, srv.URL+"/v1")
		c.InternalOnly = internal
		if _, err := ListModels(context.Background(), c); !errors.Is(err, ErrOwnAddress) || hit.Load() {
			t.Errorf("internal=%v: %v hit=%v", internal, err, hit.Load())
		}
	}
}

func TestModelsURLPerStyle(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		style      APIStyle
		base, want string
	}{
		{StyleOpenAI, "https://api.openai.com/v1", "https://api.openai.com/v1/models"},
		{StyleOpenAI, "https://opencode.ai/inference/openai/v1", "https://opencode.ai/inference/v1/models"}, // OpenCode: the family segment goes
		{StyleOpenAI, "https://api.groq.com/openai/v1", "https://api.groq.com/openai/v1/models"},            // not OpenCode: the list is under the chat path
		{StyleOpenAI, "https://res.openai.azure.com/openai/v1", "https://res.openai.azure.com/openai/v1/models"},
		{StyleOpenAI, "https://evil.example/inference/openai/v1", "https://evil.example/inference/openai/v1/models"},
		{StyleOpenAI, "http://10.0.0.5:11434/v1/", "http://10.0.0.5:11434/v1/models"},
		{StyleAnthropic, "https://api.anthropic.com", "https://api.anthropic.com/v1/models?limit=1000"},
		{StyleGemini, "https://generativelanguage.googleapis.com", "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1000"},
		{StyleGemini, "https://generativelanguage.googleapis.com/v1beta", "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1000"}, // saved by the first preset
		{StyleGemini, "https://generativelanguage.googleapis.com/v1beta/v1beta", "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1000"},
	} {
		base, err := ParseBaseURL(c.base)
		if err != nil {
			t.Fatal(err)
		}
		if u, _ := modelsURL(base, c.style); u.String() != c.want {
			t.Errorf("%s: %s, want %s", c.base, u.String(), c.want)
		}
	}
}

func TestListModelsGeminiNamesAndKeyHeader(t *testing.T) {
	t.Parallel()
	var got captured
	srv := serve(t, 200, `{"models":[{"name":"models/gem-1","supportedGenerationMethods":["generateContent"]},{"name":"models/embed-1","supportedGenerationMethods":["embedContent"]}]}`, &got)
	ids, err := ListModels(context.Background(), listCfg(StyleGemini, srv.URL+"/v1beta"))
	if err != nil || strings.Join(ids, ",") != "gem-1" || got.header.Get("x-goog-api-key") != testKey || got.query != "pageSize=1000" {
		t.Fatalf("%v %v %v %s", ids, err, got.header, got.query)
	}
}

// The first Gemini preset ended with /v1beta and the client adds /v1beta itself.
func TestGeminiBaseEndingInV1betaDoesNotDoubleThePath(t *testing.T) {
	t.Parallel()
	var got captured
	srv := serve(t, 200, `{"candidates":[{"content":{"parts":[{"text":"ok"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":1}}`, &got)
	u, _ := url.Parse(srv.URL)
	if _, err := must(t, cfg(StyleGemini, u.String()+"/v1beta")).Complete(context.Background(), simpleReq); err != nil {
		t.Fatal(err)
	}
	if got.path != "/v1beta/models/m-1:generateContent" {
		t.Fatalf("path %s", got.path)
	}
}
