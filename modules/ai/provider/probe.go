package provider

import (
	"context"
	"encoding/json"
	"time"
)

// ProbeResult is what "test this profile" reports (PRE-3, `POST /ai/profiles/test`).
type ProbeResult struct {
	Latency   time.Duration
	TokensIn  int
	TokensOut int
	// Capabilities found by trying: a feature counts only when the provider accepted a request using it.
	Tools      bool
	Structured bool
}

var (
	probeTool   = ToolDef{Name: "ping", Description: "Does nothing.", InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)}
	probeSchema = &Schema{Name: "probe", JSON: json.RawMessage(`{"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"],"additionalProperties":false}`)}
)

// Probe sends a tiny prompt (latency and tokens come from this call; a failure is returned as the error),
// then two more tiny requests to learn whether the server accepts tool definitions and structured output.
// now is injected so tests need no real clock.
func Probe(ctx context.Context, p Provider, now func() time.Time) (ProbeResult, error) {
	base := Request{System: "Answer with one word.", Messages: []Message{{Role: RoleUser, Text: "Say ok."}}, MaxTokens: 16}
	start := now()
	resp, err := p.Complete(ctx, base)
	if err != nil {
		return ProbeResult{}, err
	}
	res := ProbeResult{Latency: now().Sub(start), TokensIn: resp.Usage.InputTokens, TokensOut: resp.Usage.OutputTokens}

	withTool := base
	withTool.Tools = []ToolDef{probeTool}
	_, err = p.Complete(ctx, withTool)
	res.Tools = err == nil

	withSchema := base
	withSchema.Schema = probeSchema
	withSchema.MaxTokens = 32
	if r, err := p.Complete(ctx, withSchema); err == nil {
		var v map[string]any
		res.Structured = json.Unmarshal([]byte(r.Text), &v) == nil
	}
	return res, nil
}
