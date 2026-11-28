package provider

import (
	"context"
	"encoding/json"
	"strings"
)

// anthropic speaks the Messages API: POST {base}/v1/messages with x-api-key and anthropic-version.
type anthropic struct {
	h       *httpClient
	model   string
	version string
}

func (a *anthropic) String() string { return "provider(anthropic)" } // keeps %v from printing the key

func (a *anthropic) Complete(ctx context.Context, r Request) (Response, error) {
	if err := checkRequest(r); err != nil {
		return Response{}, err
	}
	body, err := a.encode(r)
	if err != nil {
		return Response{}, err
	}
	data, err := a.h.post(ctx, "/v1/messages", map[string]string{
		"x-api-key": a.h.key.Reveal(), "anthropic-version": a.version,
	}, body)
	if err != nil {
		return Response{}, noWorkspace(err)
	}
	return decodeAnthropic(data)
}

type anBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   string          `json:"content,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
}

// The versions of Anthropic's server tools for web search and page fetch.
const (
	anWebSearch = "web_search_20260209"
	anWebFetch  = "web_fetch_20260209"
)

// anBlockIn is a content block as the provider sends it: a server tool's result carries an object or an array as its content, and a
// text block may carry citations with the source text it cites.
type anBlockIn struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
	Citations []struct {
		CitedText string `json:"cited_text"`
		URL       string `json:"url"`
	} `json:"citations,omitempty"`
}

type anMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

func (a *anthropic) encode(r Request) (map[string]any, error) {
	msgs := make([]anMessage, 0, len(r.Messages))
	for _, m := range r.Messages {
		switch m.Role {
		case RoleUser:
			msgs = append(msgs, anMessage{"user", m.Text})
		case RoleAssistant:
			if len(m.Raw) > 0 { // replay the provider's own blocks unchanged, thinking blocks included
				msgs = append(msgs, anMessage{"assistant", m.Raw})
				continue
			}
			if len(m.ToolCalls) == 0 {
				msgs = append(msgs, anMessage{"assistant", m.Text})
				continue
			}
			var bl []anBlock
			if m.Text != "" {
				bl = append(bl, anBlock{Type: "text", Text: m.Text})
			}
			for _, c := range m.ToolCalls {
				in, ok := object(c.Arguments)
				if !ok {
					return nil, badResponse("tool call arguments are not a JSON object")
				}
				bl = append(bl, anBlock{Type: "tool_use", ID: c.ID, Name: c.Name, Input: in})
			}
			msgs = append(msgs, anMessage{"assistant", bl})
		case RoleTool:
			bl := make([]anBlock, 0, len(m.ToolResults))
			for _, t := range m.ToolResults {
				bl = append(bl, anBlock{Type: "tool_result", ToolUseID: t.CallID, Content: t.Content, IsError: t.IsError})
			}
			msgs = append(msgs, anMessage{"user", bl})
		default:
			return nil, badResponse("unknown message role")
		}
	}
	body := map[string]any{"model": a.model, "max_tokens": r.MaxTokens, "messages": msgs}
	if r.System != "" {
		body["system"] = r.System
	}
	if len(r.Tools) > 0 || r.Web != nil {
		ts := make([]map[string]any, 0, len(r.Tools)+2)
		for _, t := range r.Tools {
			ts = append(ts, map[string]any{"name": t.Name, "description": t.Description, "input_schema": schemaOrEmpty(t.InputSchema)})
		}
		if w := r.Web; w != nil { // the provider's own tools, capped per request
			if w.Searches > 0 {
				ts = append(ts, map[string]any{"type": anWebSearch, "name": "web_search", "max_uses": w.Searches})
			}
			if w.Fetches > 0 {
				ts = append(ts, map[string]any{"type": anWebFetch, "name": "web_fetch", "max_uses": w.Fetches, "max_content_tokens": max(w.PageTokens, 1000)})
			}
		}
		body["tools"] = ts
	}
	if r.Schema != nil {
		body["output_config"] = map[string]any{"format": map[string]any{"type": "json_schema", "schema": r.Schema.JSON}}
	}
	return body, nil
}

// decodeAnthropic turns a Messages API body into a Response. It fails closed: anything unexpected is ErrBadResponse.
// A refusal (stop_reason "refusal") is returned as ErrRefused with the category and the usage; its content is dropped.
func decodeAnthropic(data []byte) (Response, error) {
	var w struct {
		Type        string          `json:"type"`
		Content     json.RawMessage `json:"content"`
		Stop        string          `json:"stop_reason"`
		StopDetails *struct {
			Category string `json:"category"`
		} `json:"stop_details"`
		Model string `json:"model"`
		Usage struct {
			In     *int `json:"input_tokens"`
			Out    *int `json:"output_tokens"`
			Server *struct {
				Searches int `json:"web_search_requests"`
			} `json:"server_tool_use"`
		} `json:"usage"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &w); err != nil {
		return Response{}, badResponse("body is not JSON")
	}
	if w.Error != nil || w.Type == "error" {
		return Response{}, badResponse("the provider sent an error inside a successful answer")
	}
	var blocks []anBlockIn
	if w.Content == nil || json.Unmarshal(w.Content, &blocks) != nil {
		return Response{}, badResponse("missing content")
	}
	u, ok := usage(w.Usage.In, w.Usage.Out)
	if !ok {
		return Response{}, badResponse("missing or out-of-range token usage")
	}
	if w.Stop == "refusal" {
		cat := ""
		if w.StopDetails != nil {
			cat = w.StopDetails.Category
		}
		return Response{}, refusal(cat, u)
	}
	res := Response{Model: w.Model, Usage: u, Raw: append(json.RawMessage(nil), w.Content...)}
	if w.Usage.Server != nil && w.Usage.Server.Searches > 0 && w.Usage.Server.Searches <= 1000 {
		res.Web.Searches = w.Usage.Server.Searches
	}
	var text strings.Builder
	for _, b := range blocks {
		switch b.Type {
		case "text":
			text.WriteString(b.Text)
			for _, c := range b.Citations {
				if len(c.CitedText) > 0 {
					res.Web.Texts = append(res.Web.Texts, c.CitedText)
				}
			}
		case "server_tool_use":
			var in struct {
				Query string `json:"query"`
				URL   string `json:"url"`
			}
			_ = json.Unmarshal(b.Input, &in)
			switch {
			case b.Name == "web_search" && in.Query != "":
				res.Web.Queries = append(res.Web.Queries, in.Query)
			case b.Name == "web_fetch" && in.URL != "":
				res.Web.Fetched = append(res.Web.Fetched, in.URL)
			}
		case "web_search_tool_result", "web_fetch_tool_result":
			var c any
			if json.Unmarshal(b.Content, &c) == nil {
				if m, ok := c.(map[string]any); ok {
					if code, ok := m["error_code"].(string); ok && code != "" {
						res.Web.Errors = append(res.Web.Errors, code)
					}
				}
				collectToolText(c, &res.Web.Texts)
			}
		case "tool_use":
			in, ok := object(b.Input)
			if b.Name == "" || !ok {
				return Response{}, badResponse("malformed tool call")
			}
			res.ToolCalls = append(res.ToolCalls, ToolCall{ID: b.ID, Name: b.Name, Arguments: in})
		}
	}
	res.Text = text.String()
	switch w.Stop {
	case "end_turn", "stop_sequence":
		res.Stop = StopEnd
	case "max_tokens":
		res.Stop = StopMaxTokens
	case "tool_use":
		res.Stop = StopToolUse
	case "pause_turn":
		res.Stop = StopPause
	default:
		res.Stop = StopOther
	}
	return res, nil
}

// collectToolText adds every text a server tool returned (a fetched document, a search result's title or snippet) of at least 40 bytes:
// what the model could read, so the box can look a quote up in it. Encrypted search content and base64 sources are skipped.
func collectToolText(x any, out *[]string) {
	switch v := x.(type) {
	case string:
		if len(v) >= 40 && len(*out) < maxToolTexts {
			*out = append(*out, v)
		}
	case map[string]any:
		if v["type"] == "base64" {
			return
		}
		for k, e := range v {
			if k == "encrypted_content" || k == "encrypted_index" {
				continue
			}
			collectToolText(e, out)
		}
	case []any:
		for _, e := range v {
			collectToolText(e, out)
		}
	}
}

// maxToolTexts bounds the texts kept from one response.
const maxToolTexts = 200
