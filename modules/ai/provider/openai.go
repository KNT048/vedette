package provider

import (
	"context"
	"encoding/json"
)

// openAI speaks Chat Completions: POST {base}/chat/completions with a bearer key (omitted when there is
// none, as for a local Ollama). The base URL includes the version path, e.g. https://api.openai.com/v1.
type openAI struct {
	h      *httpClient
	model  string
	compat bool
}

func (o *openAI) String() string { return "provider(openai)" }

func (o *openAI) Complete(ctx context.Context, r Request) (Response, error) {
	if err := checkRequest(r); err != nil {
		return Response{}, err
	}
	body, err := o.encode(r)
	if err != nil {
		return Response{}, err
	}
	headers := map[string]string{}
	if o.h.key.IsSet() {
		headers["Authorization"] = "Bearer " + o.h.key.Reveal()
	}
	data, err := o.h.post(ctx, "/chat/completions", headers, body)
	if err != nil {
		return Response{}, err
	}
	return decodeOpenAI(data)
}

type oaiToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type oaiMessage struct {
	Role       string        `json:"role"`
	Content    *string       `json:"content"`
	ToolCalls  []oaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
}

func (o *openAI) encode(r Request) (map[string]any, error) {
	var msgs []oaiMessage
	str := func(s string) *string { return &s }
	if r.System != "" {
		msgs = append(msgs, oaiMessage{Role: "system", Content: str(r.System)})
	}
	for _, m := range r.Messages {
		switch m.Role {
		case RoleUser:
			msgs = append(msgs, oaiMessage{Role: "user", Content: str(m.Text)})
		case RoleAssistant:
			am := oaiMessage{Role: "assistant"}
			if m.Text != "" || len(m.ToolCalls) == 0 {
				am.Content = str(m.Text)
			}
			for _, c := range m.ToolCalls {
				in, ok := object(c.Arguments)
				if !ok {
					return nil, badResponse("tool call arguments are not a JSON object")
				}
				tc := oaiToolCall{ID: c.ID, Type: "function"}
				tc.Function.Name, tc.Function.Arguments = c.Name, string(in)
				am.ToolCalls = append(am.ToolCalls, tc)
			}
			msgs = append(msgs, am)
		case RoleTool:
			for _, t := range m.ToolResults {
				msgs = append(msgs, oaiMessage{Role: "tool", ToolCallID: t.CallID, Content: str(t.Content)})
			}
		default:
			return nil, badResponse("unknown message role")
		}
	}
	body := map[string]any{"model": o.model, "messages": msgs}
	if o.compat {
		body["max_tokens"] = r.MaxTokens
	} else {
		body["max_completion_tokens"] = r.MaxTokens
	}
	if len(r.Tools) > 0 {
		ts := make([]map[string]any, 0, len(r.Tools))
		for _, t := range r.Tools {
			ts = append(ts, map[string]any{"type": "function", "function": map[string]any{
				"name": t.Name, "description": t.Description, "parameters": schemaOrEmpty(t.InputSchema)}})
		}
		body["tools"] = ts
	}
	if r.Schema != nil {
		body["response_format"] = map[string]any{"type": "json_schema", "json_schema": map[string]any{
			"name": r.Schema.Name, "schema": r.Schema.JSON, "strict": true}}
	}
	return body, nil
}

// decodeOpenAI turns a Chat Completions body into a Response; anything unexpected is ErrBadResponse.
// message.refusal and finish_reason content_filter are refusals: ErrRefused, content dropped.
func decodeOpenAI(data []byte) (Response, error) {
	var w struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content   *string       `json:"content"`
				Refusal   *string       `json:"refusal"`
				ToolCalls []oaiToolCall `json:"tool_calls"`
			} `json:"message"`
			Finish string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			In  *int `json:"prompt_tokens"`
			Out *int `json:"completion_tokens"`
		} `json:"usage"`
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(data, &w); err != nil {
		return Response{}, badResponse("body is not JSON")
	}
	if len(w.Error) > 0 && string(w.Error) != "null" {
		return Response{}, badResponse("the provider sent an error inside a successful answer")
	}
	if len(w.Choices) == 0 {
		return Response{}, badResponse("no choices")
	}
	u, ok := usage(w.Usage.In, w.Usage.Out)
	if !ok {
		return Response{}, badResponse("missing or out-of-range token usage")
	}
	c := w.Choices[0]
	if c.Message.Refusal != nil && *c.Message.Refusal != "" {
		return Response{}, refusal("refusal", u)
	}
	if c.Finish == "content_filter" {
		return Response{}, refusal("content_filter", u)
	}
	res := Response{Model: w.Model, Usage: u}
	if c.Message.Content != nil {
		res.Text = *c.Message.Content
	}
	for _, tc := range c.Message.ToolCalls {
		args, ok := object(json.RawMessage(tc.Function.Arguments))
		if tc.Function.Name == "" || !ok {
			return Response{}, badResponse("malformed tool call")
		}
		res.ToolCalls = append(res.ToolCalls, ToolCall{ID: tc.ID, Name: tc.Function.Name, Arguments: args})
	}
	switch {
	case len(res.ToolCalls) > 0 || c.Finish == "tool_calls":
		res.Stop = StopToolUse
	case c.Finish == "stop":
		res.Stop = StopEnd
	case c.Finish == "length":
		res.Stop = StopMaxTokens
	default:
		res.Stop = StopOther
	}
	return res, nil
}
