package ai_test

import "testing"

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
