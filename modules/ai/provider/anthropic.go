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
		return Response{}, err
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
	if len(r.Tools) > 0 {
		ts := make([]map[string]any, 0, len(r.Tools))
		for _, t := range r.Tools {
			ts = append(ts, map[string]any{"name": t.Name, "description": t.Description, "input_schema": schemaOrEmpty(t.InputSchema)})
		}
		body["tools"] = ts
	}
	if r.Schema != nil {
		body["output_config"] = map[string]any{"format": map[string]any{"type": "json_schema", "schema": r.Schema.JSON}}
	}
	return body, nil
}

// decodeAnthropic turns a Messages API body into a Response. It fails closed: anything unexpected is ErrBadResponse.
func decodeAnthropic(data []byte) (Response, error) {
	var w struct {
		Type    string          `json:"type"`
		Content json.RawMessage `json:"content"`
		Stop    string          `json:"stop_reason"`
		Model   string          `json:"model"`
		Usage   struct {
			In  *int `json:"input_tokens"`
			Out *int `json:"output_tokens"`
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
	var blocks []anBlock
	if w.Content == nil || json.Unmarshal(w.Content, &blocks) != nil {
		return Response{}, badResponse("missing content")
	}
	if w.Usage.In == nil || w.Usage.Out == nil || *w.Usage.In < 0 || *w.Usage.Out < 0 {
		return Response{}, badResponse("missing or negative token usage")
	}
	res := Response{Model: w.Model, Usage: Usage{*w.Usage.In, *w.Usage.Out}}
	var text strings.Builder
	for _, b := range blocks {
		switch b.Type {
		case "text":
			text.WriteString(b.Text)
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
	default:
		res.Stop = StopOther
	}
	return res, nil
}
