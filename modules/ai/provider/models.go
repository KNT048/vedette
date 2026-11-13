package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	modelsTimeout  = 15 * time.Second
	modelsMaxBody  = 1 << 20 // a list of model names; a provider with more than 1 MiB of it is not answering this question
	maxListedModel = 300     // names kept; the dialog shows a list a person can read, free text stays possible
)

// ModelsConfig is one model-list call. It is a Config without the model: the list is asked before one is chosen.
type ModelsConfig struct {
	Style            APIStyle
	BaseURL          string
	APIKey           Secret
	InternalOnly     bool
	Own              OwnSources
	AnthropicVersion string
}

// modelsURL is the provider's model endpoint for a base URL. OpenAI style: {base}/models, except behind a gateway that puts the API
// family in the path (OpenCode: chat at /inference/openai/v1, models at /inference/v1/models), where the family segment goes.
func modelsURL(base *url.URL, style APIStyle) (u url.URL, headers func(Secret, string) map[string]string) {
	u = *base
	switch style {
	case StyleAnthropic:
		u.Path += "/v1/models"
		u.RawQuery = "limit=1000"
		return u, func(k Secret, ver string) map[string]string {
			return map[string]string{"x-api-key": k.Reveal(), "anthropic-version": ver}
		}
	case StyleGemini:
		u.Path = geminiRoot(u.Path) + "/v1beta/models"
		u.RawQuery = "pageSize=1000"
		return u, func(k Secret, _ string) map[string]string { return map[string]string{"x-goog-api-key": k.Reveal()} }
	}
	// OpenCode puts the API family in the chat path (/inference/openai/v1) but lists every family at /inference/v1/models. Only that
	// host: Groq (/openai/v1/models) and Azure serve the list under the same path as the chat.
	if p, ok := strings.CutSuffix(u.Path, "/openai/v1"); ok && strings.EqualFold(u.Hostname(), "opencode.ai") {
		u.Path = p + "/v1"
	}
	u.Path += "/models"
	return u, func(k Secret, _ string) map[string]string {
		if !k.IsSet() {
			return nil
		}
		return map[string]string{"Authorization": "Bearer " + k.Reveal()}
	}
}

// ListModels asks the provider which models it offers. It uses the same transport as every AI call (the dial-time address rules, own
// address D-446, no redirects, no environment proxy for an internal profile), a 15 s timeout and a 1 MiB cap. The answer is untrusted:
// only ids that pass the model-name rule are kept, de-duplicated, sorted, at most 300.
func ListModels(ctx context.Context, c ModelsConfig) ([]string, error) {
	base, err := ParseBaseURL(c.BaseURL)
	if err != nil {
		return nil, err
	}
	if c.AnthropicVersion == "" {
		c.AnthropicVersion = DefaultAnthropicVersion
	}
	h := &httpClient{
		base: base, key: c.APIKey, timeout: modelsTimeout, maxBody: modelsMaxBody,
		c: &http.Client{Transport: newTransport(c.InternalOnly, base, c.Own), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	u, hdr := modelsURL(base, c.Style)
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, newErr(ErrRequest, 0, "request could not be built", h.key)
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range hdr(c.APIKey, c.AnthropicVersion) {
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, statusErr(resp.StatusCode, data, h.key)
	}
	return decodeModels(data)
}

// decodeModels reads {"data":[{"id"}]} (OpenAI, Anthropic) or {"models":[{"name":"models/x"}]} (Gemini). Anything else is a bad response.
func decodeModels(data []byte) ([]string, error) {
	var doc struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Models []struct {
			Name    string   `json:"name"`
			Methods []string `json:"supportedGenerationMethods"`
		} `json:"models"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, badResponse("the model list is not JSON")
	}
	var raw []string
	for _, d := range doc.Data {
		raw = append(raw, d.ID)
	}
	for _, m := range doc.Models {
		if len(m.Methods) > 0 && !slices.Contains(m.Methods, "generateContent") {
			continue
		}
		raw = append(raw, strings.TrimPrefix(m.Name, "models/"))
	}
	if doc.Data == nil && doc.Models == nil {
		return nil, badResponse("the model list has no models field")
	}
	seen := map[string]bool{}
	var out []string
	for _, id := range raw {
		if !utf8.ValidString(id) || !modelRE.MatchString(id) || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	if len(out) > maxListedModel {
		out = out[:maxListedModel]
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// geminiRoot drops trailing /v1beta segments from a Gemini base path: the client adds /v1beta itself, and the first preset ended with it
// (a profile saved that way would otherwise call /v1beta/v1beta/...).
func geminiRoot(path string) string {
	for strings.HasSuffix(path, "/v1beta") {
		path = strings.TrimSuffix(path, "/v1beta")
	}
	return path
}
