package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	defaultTimeout   = 60 * time.Second
	defaultMaxBody   = 4 << 20 // response cap: a model answer is far below this
	maxErrBodyInText = 512
)

var modelRE = regexp.MustCompile(`^[\w.:/-]{1,80}$`)

// Config describes one connection to a provider. The model and key come from the AI profile; nothing is
// defaulted here except the public base URL of the three native APIs (see DefaultBaseURL).
type Config struct {
	Style   APIStyle
	BaseURL string // no user info, no query; "http" only makes sense for servers inside the network (checked by the ai package)
	Model   string
	APIKey  Secret
	// CompatMode sends max_tokens instead of max_completion_tokens (Ollama, vLLM, gateways). OpenAI style only.
	CompatMode bool
	// AnthropicVersion overrides the anthropic-version header. Empty = DefaultAnthropicVersion.
	AnthropicVersion string
	// Timeout bounds one call. Zero = 60 s. The caller's context can only make it shorter.
	Timeout time.Duration
	// MaxResponseBytes caps the body read from the provider. Zero = 4 MiB.
	MaxResponseBytes int64
}

// DefaultAnthropicVersion is the stable Messages API version header value.
const DefaultAnthropicVersion = "2023-06-01"

// DefaultBaseURL returns the public endpoint of a native API, or "" for kinds that always need a base URL.
func DefaultBaseURL(kind string) string {
	switch kind {
	case "anthropic":
		return "https://api.anthropic.com"
	case "openai":
		return "https://api.openai.com/v1"
	case "gemini":
		return "https://generativelanguage.googleapis.com"
	}
	return ""
}

// StyleForKind maps a profile kind to its wire format. "custom" needs the style chosen by the user.
func StyleForKind(kind string, custom APIStyle) (APIStyle, error) {
	switch kind {
	case "anthropic":
		return StyleAnthropic, nil
	case "openai", "openai-compatible":
		return StyleOpenAI, nil
	case "gemini":
		return StyleGemini, nil
	case "custom":
		switch custom {
		case StyleAnthropic, StyleOpenAI, StyleGemini:
			return custom, nil
		}
		return "", errors.New("provider: a custom profile must say which API style the server speaks (openai, anthropic or gemini)")
	}
	return "", fmt.Errorf("provider: unknown provider kind %q", kind)
}

// New builds a Provider. It validates the configuration; it makes no network call.
func New(c Config) (Provider, error) {
	base, err := ParseBaseURL(c.BaseURL)
	if err != nil {
		return nil, err
	}
	if !modelRE.MatchString(c.Model) {
		return nil, errors.New("provider: the model name may only contain letters, digits, dots, dashes, colons and slashes (80 characters at most)")
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultTimeout
	}
	if c.MaxResponseBytes <= 0 {
		c.MaxResponseBytes = defaultMaxBody
	}
	if c.AnthropicVersion == "" {
		c.AnthropicVersion = DefaultAnthropicVersion
	}
	h := &httpClient{
		base: base, key: c.APIKey, timeout: c.Timeout, maxBody: c.MaxResponseBytes,
		// Never follow redirects: a custom header such as x-api-key would travel to the new host.
		c: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	switch c.Style {
	case StyleAnthropic:
		return &anthropic{h: h, model: c.Model, version: c.AnthropicVersion}, nil
	case StyleOpenAI:
		return &openAI{h: h, model: c.Model, compat: c.CompatMode}, nil
	case StyleGemini:
		m := strings.TrimPrefix(c.Model, "models/")
		if strings.Contains(m, "/") || m == "" {
			return nil, errors.New("provider: a Gemini model name must not contain a slash")
		}
		return &gemini{h: h, model: m}, nil
	}
	return nil, fmt.Errorf("provider: unknown API style %q", c.Style)
}

// ParseBaseURL checks a base URL: http or https, a host, no user info, no query, no fragment. It returns it
// without a trailing slash.
func ParseBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("provider: the server address is not valid; enter it in full, for example https://api.anthropic.com")
	}
	if u.User != nil {
		return nil, errors.New("provider: the server address must not contain a user name or password; enter the API key in its own field")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, errors.New("provider: the server address must not contain a query or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

type httpClient struct {
	base    *url.URL
	key     Secret
	timeout time.Duration
	maxBody int64
	c       *http.Client
}

// post sends a JSON body to base+path and returns the (size-capped) body of a 2xx answer.
// Every other outcome is an error whose message never contains the key or the URL.
func (h *httpClient) post(ctx context.Context, path string, headers map[string]string, body any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("ai provider: encode request: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	u := *h.base
	u.Path += path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, newErr(ErrRequest, 0, "request could not be built", h.key)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.c.Do(req)
	if err != nil {
		return nil, h.transportErr(ctx, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, h.maxBody+1))
	if err != nil {
		return nil, h.transportErr(ctx, err)
	}
	if int64(len(data)) > h.maxBody {
		return nil, newErr(ErrTooLarge, resp.StatusCode, fmt.Sprintf("more than %d bytes", h.maxBody), h.key)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return data, nil
	}
	return nil, statusErr(resp.StatusCode, data, h.key)
}

func (h *httpClient) transportErr(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return ctx.Err() // the caller gave up; not a provider failure
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return newErr(ErrTimeout, 0, "", h.key)
	}
	// The text of a dial error names the address (and a url.Error the whole URL), so none of it is kept.
	return newErr(ErrNetwork, 0, "connection failed", h.key)
}

func statusErr(status int, body []byte, key Secret) *Error {
	kind := ErrRequest
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		kind = ErrAuth
	case status == http.StatusTooManyRequests:
		kind = ErrRateLimited
	case status == http.StatusRequestTimeout || status == http.StatusGatewayTimeout:
		kind = ErrTimeout
	case status >= 500:
		kind = ErrServer
	}
	return newErr(kind, status, errorText(body), key)
}

// errorText pulls a message out of the common error shapes ({"error":{"message":..}}, {"error":"..."}),
// falling back to the start of the raw body.
func errorText(body []byte) string {
	if len(body) > maxErrBodyInText {
		body = body[:maxErrBodyInText]
	}
	var e struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && len(e.Error) > 0 {
		var s string
		if json.Unmarshal(e.Error, &s) == nil {
			return s
		}
		var o struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(e.Error, &o) == nil && o.Message != "" {
			return o.Message
		}
	}
	return string(body)
}

func checkRequest(r Request) error {
	if r.MaxTokens <= 0 {
		return errors.New("provider: max tokens must be positive")
	}
	if len(r.Messages) == 0 {
		return errors.New("provider: a request needs at least one message")
	}
	for _, t := range r.Tools {
		if t.Name == "" || (len(t.InputSchema) > 0 && !json.Valid(t.InputSchema)) {
			return errors.New("provider: a tool needs a name and a valid JSON schema")
		}
	}
	if r.Schema != nil && !json.Valid(r.Schema.JSON) {
		return errors.New("provider: the output schema is not valid JSON")
	}
	return nil
}

func schemaOrEmpty(s json.RawMessage) json.RawMessage {
	if len(s) == 0 {
		return json.RawMessage(`{"type":"object","properties":{}}`)
	}
	return s
}

// object checks that raw is a JSON object (tool arguments) and normalises empty input to {}.
func object(raw json.RawMessage) (json.RawMessage, bool) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || string(t) == "null" {
		return json.RawMessage(`{}`), true
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(t, &m) != nil {
		return nil, false
	}
	return t, true
}

func badResponse(msg string) error { return &Error{Kind: ErrBadResponse, Message: msg} }
