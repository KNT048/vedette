package ai_test

import (
	"strings"
	"testing"
)

// D-475: the model list is asked through the same checks as a connection test, and is refused before any request when the address or
// the key would not pass one.
func TestContract_ModelList_RefusedBeforeAnyRequest(t *testing.T) {
	a := newAPI(t)
	const own = `{"kind":"openai-compatible","api_style":"openai","base_url":"http://127.0.0.1:11434/v1","location":"internal"}`
	a.want("POST", "/ai/profiles/models", "admin", own, 400, "invalid_base_url")
	a.want("POST", "/ai/profiles/models", "admin", `{"kind":"custom","api_style":"openai","base_url":"http://example.com/v1","location":"cloud","api_key":"`+keyA+`"}`, 400, "invalid_base_url")
	a.want("POST", "/ai/profiles/models", "admin", `{"kind":"custom","api_style":"openai","base_url":"https://opencode.ai/inference/openai/v1","location":"cloud"}`, 400, "key_required")
	a.want("POST", "/ai/profiles/models", "operator", own, 403, "")
	a.want("POST", "/ai/profiles/models", "viewer", own, 403, "")
}

// INV-1 for the model list: a saved profile's key goes only to the address it was saved for, and no refusal repeats the key.
func TestContract_ModelList_StoredKeyGoesOnlyToTheAddressItWasSavedFor(t *testing.T) {
	a := newAPI(t)
	id := saved(a, cloudBody("Claude", keyA))
	body := func(base string) string {
		return `{"id":"` + id + `","kind":"anthropic","api_style":"anthropic","base_url":"` + base + `","location":"cloud"}`
	}
	for name, to := range map[string]string{
		"other host":   "https://evil.example.com",
		"other port":   "https://api.anthropic.com:8443",
		"other scheme": "http://api.anthropic.com",
		"subdomain":    "https://api.anthropic.com.evil.example",
		"userinfo":     "https://api.anthropic.com@evil.example",
	} {
		before := a.fake.total()
		got, m, raw := a.do("POST", "/ai/profiles/models", "admin", body(to))
		if got != 400 {
			t.Errorf("%s: models = %d %s", name, got, raw)
		}
		if c := errCode(m); c != "key_required" && c != "invalid_base_url" {
			t.Errorf("%s: code %s", name, c)
		}
		if strings.Contains(raw, keyA) {
			t.Errorf("%s: the key is in the answer", name)
		}
		if a.fake.total() != before {
			t.Errorf("%s: the provider was called", name)
		}
	}
	for _, row := range a.auditRows() {
		if strings.Contains(row, keyA) {
			t.Fatalf("the key is in an audit row: %s", row)
		}
	}
	a.want("POST", "/ai/profiles/models", "admin", body("https://evil.example.com"), 400, "key_required")
}

// The call dials an address the admin typed: at most 10 a minute per admin.
func TestContract_ModelList_IsRateLimitedPerAdmin(t *testing.T) {
	a := newAPI(t)
	const own = `{"kind":"openai-compatible","api_style":"openai","base_url":"http://127.0.0.1:11434/v1","location":"internal"}`
	for range 10 {
		a.want("POST", "/ai/profiles/models", "admin", own, 400, "invalid_base_url")
	}
	a.want("POST", "/ai/profiles/models", "admin", own, 429, "rate_limited")
}
