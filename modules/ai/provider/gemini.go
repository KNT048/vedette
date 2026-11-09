package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// gemini speaks generateContent: POST {base}/v1beta/models/{model}:generateContent. The key goes in the
// x-goog-api-key header, never in the query string, so it cannot end up in a URL or an error message.
type gemini struct {
	h     *httpClient
	model string
}

func (g *gemini) String() string { return "provider(gemini)" }

func (g *gemini) Complete(ctx context.Context, r Request) (Response, error) {
	if err := checkRequest(r); err != nil {
		return Response{}, err
	}
	body, err := g.encode(r)
	if err != nil {
		return Response{}, err
	}
	path := "/v1beta/models/" + url.PathEscape(g.model) + ":generateContent"
	data, err := g.h.post(ctx, path, map[string]string{"x-goog-api-key": g.h.key.Reveal()}, body)
	if err != nil {
		return Response{}, err
	}
	return decodeGemini(data)
}

type gemPart struct {
	Text             string       `json:"text,omitempty"`
	FunctionCall     *gemCall     `json:"functionCall,omitempty"`
	FunctionResponse *gemResponse `json:"functionResponse,omitempty"`
	Thought          bool         `json:"thought,omitempty"`
}

type gemCall struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
}

type gemResponse struct {
	Name     string         `json:"name"`
	Response map[string]any `json:"response"`
}

type gemContent struct {
	Role  string    `json:"role,omitempty"`
	Parts []gemPart `json:"parts"`
}

func (g *gemini) encode(r Request) (map[string]any, error) {
	var contents []gemContent
	for _, m := range r.Messages {
		switch m.Role {
		case RoleUser:
			contents = append(contents, gemContent{Role: "user", Parts: []gemPart{{Text: m.Text}}})
		case RoleAssistant:
			var parts []gemPart
			if m.Text != "" || len(m.ToolCalls) == 0 {
				parts = append(parts, gemPart{Text: m.Text})
			}
			for _, c := range m.ToolCalls {
				in, ok := object(c.Arguments)
				if !ok {
					return nil, badResponse("tool call arguments are not a JSON object")
				}
				parts = append(parts, gemPart{FunctionCall: &gemCall{Name: c.Name, Args: in}})
			}
			contents = append(contents, gemContent{Role: "model", Parts: parts})
		case RoleTool:
			var parts []gemPart
			for _, t := range m.ToolResults {
				key := "result"
				if t.IsError {
					key = "error"
				}
				parts = append(parts, gemPart{FunctionResponse: &gemResponse{Name: t.Name, Response: map[string]any{key: t.Content}}})
			}
			contents = append(contents, gemContent{Role: "user", Parts: parts})
		default:
			return nil, badResponse("unknown message role")
		}
	}
	gen := map[string]any{"maxOutputTokens": r.MaxTokens}
	if r.Schema != nil {
		gen["responseMimeType"] = "application/json"
		gen["responseJsonSchema"] = r.Schema.JSON
	}
	body := map[string]any{"contents": contents, "generationConfig": gen}
	if r.System != "" {
		body["systemInstruction"] = gemContent{Parts: []gemPart{{Text: r.System}}}
	}
	if len(r.Tools) > 0 {
		decls := make([]map[string]any, 0, len(r.Tools))
		for _, t := range r.Tools {
			decls = append(decls, map[string]any{"name": t.Name, "description": t.Description, "parametersJsonSchema": schemaOrEmpty(t.InputSchema)})
		}
		body["tools"] = []map[string]any{{"functionDeclarations": decls}}
	}
	return body, nil
}

// geminiRefusals are the finishReason values that mean the model declined for safety or policy reasons.
var geminiRefusals = map[string]bool{"SAFETY": true, "BLOCKLIST": true, "PROHIBITED_CONTENT": true, "SPII": true, "IMAGE_SAFETY": true}

// decodeGemini turns a generateContent body into a Response; anything unexpected is ErrBadResponse.
// A safety finish or a blocked prompt is ErrRefused (category from the finish or block reason), content dropped.
func decodeGemini(data []byte) (Response, error) {
	var w struct {
		Candidates []struct {
			Content struct {
				Parts []gemPart `json:"parts"`
			} `json:"content"`
			Finish string `json:"finishReason"`
		} `json:"candidates"`
		Usage struct {
			In      *int `json:"promptTokenCount"`
			Out     int  `json:"candidatesTokenCount"`
			Thought int  `json:"thoughtsTokenCount"`
		} `json:"usageMetadata"`
		Model    string `json:"modelVersion"`
		Feedback struct {
			Block string `json:"blockReason"`
		} `json:"promptFeedback"`
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(data, &w); err != nil {
		return Response{}, badResponse("body is not JSON")
	}
	if len(w.Error) > 0 && string(w.Error) != "null" {
		return Response{}, badResponse("the provider sent an error inside a successful answer")
	}
	// Each part is range-checked before the output (candidates plus billed thinking) is summed, so the sum cannot overflow.
	out := w.Usage.Out
	var u Usage
	usageOK := false
	if w.Usage.In != nil {
		if o, ok := usage(w.Usage.In, &out); ok && w.Usage.Thought >= 0 && w.Usage.Thought <= MaxUsageTokens {
			u, usageOK = Usage{o.InputTokens, o.OutputTokens + w.Usage.Thought}, true
		}
	}
	if len(w.Candidates) == 0 {
		if w.Feedback.Block != "" {
			return Response{}, refusal(w.Feedback.Block, u) // usage is whatever was reported; a block may report none
		}
		return Response{}, badResponse("no candidates")
	}
	c := w.Candidates[0]
	if geminiRefusals[c.Finish] {
		return Response{}, refusal(c.Finish, u)
	}
	if !usageOK {
		return Response{}, badResponse("missing or out-of-range token usage")
	}
	// Thinking tokens are billed as output.
	res := Response{Model: w.Model, Usage: u}
	var text strings.Builder
	for i, p := range c.Content.Parts {
		switch {
		case p.FunctionCall != nil:
			args, ok := object(p.FunctionCall.Args)
			if p.FunctionCall.Name == "" || !ok {
				return Response{}, badResponse("malformed tool call")
			}
			// Gemini has no call ids; results are matched by name, so a synthetic id is enough.
			res.ToolCalls = append(res.ToolCalls, ToolCall{ID: fmt.Sprintf("%s-%d", p.FunctionCall.Name, i), Name: p.FunctionCall.Name, Arguments: args})
		case !p.Thought:
			text.WriteString(p.Text)
		}
	}
	res.Text = text.String()
	switch {
	case len(res.ToolCalls) > 0:
		res.Stop = StopToolUse
	case c.Finish == "STOP":
		res.Stop = StopEnd
	case c.Finish == "MAX_TOKENS":
		res.Stop = StopMaxTokens
	default:
		res.Stop = StopOther
	}
	return res, nil
}
