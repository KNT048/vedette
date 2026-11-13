package ai_test

import (
	"context"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
)

// stops reads the stop column of ai_activity, oldest first ("" for NULL).
func (a *api) stops() []string {
	a.t.Helper()
	rows, err := a.db.Reader().QueryContext(a.ctx(), `SELECT COALESCE(stop, '') FROM ai_activity ORDER BY seq`)
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			a.t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// jobLimits returns the output limits of the requests the provider got that carried a schema other than the probe's.
func (a *api) jobLimits() []int {
	var out []int
	for _, r := range a.fake.askRequests() {
		if r.Schema != nil && r.Schema.Name != "probe" {
			out = append(out, r.MaxTokens)
		}
	}
	return out
}

// Beta 0.1.0-beta.1: Claude Haiku 5.5 spent the 1,000-token limit (thinking included) and every explanation was cut. A cut answer is asked
// again once with twice the limit; the second, whole answer is used and both are counted.
func TestACutAnswerIsAskedAgainWithAHigherLimit(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.fake.cutNext(1)
	got := a.explain("CVE-2022-27593", 200, "")
	if got["why"] == nil {
		t.Fatalf("explanation = %v", got)
	}
	if l := a.jobLimits(); len(l) != 2 || l[0] != 6000 || l[1] != 12000 {
		t.Fatalf("limits sent = %v, want [6000 12000]", l)
	}
	rows := a.activity()
	last := rows[len(rows)-1]
	if last.Result != ai.ResultOK || last.TokensOut != 6000+3 {
		t.Fatalf("row = %+v, want ok with the tokens of both answers", last.ActivityEntry)
	}
	if s := a.stops(); s[len(s)-1] != "end" {
		t.Fatalf("stop = %v", s)
	}
}

// Cut twice: one true message, not "the format", not "no profile"; the row says why and keeps every token.
func TestAnAnswerCutTwiceSaysItWasCutOff(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.fake.cutNext(2)
	m := a.explain("CVE-2022-27593", 502, "ai_cut_off")
	msg := m["error"].(map[string]any)["message"].(string)
	if !strings.Contains(msg, "The AI's answer was cut off at the output limit (12,000 tokens)") || strings.Contains(msg, "format") || strings.Contains(msg, "profile is assigned") {
		t.Fatalf("message = %q", msg)
	}
	rows := a.activity()
	last := rows[len(rows)-1]
	if last.Result != ai.ResultError || !strings.Contains(last.Summary, "cut off at the output limit") || last.TokensOut != 6000+12000 {
		t.Fatalf("row = %+v", last.ActivityEntry)
	}
	if s := a.stops(); s[len(s)-1] != "max_tokens" {
		t.Fatalf("stop = %v", s)
	}
	if l := a.jobLimits(); len(l) != 2 {
		t.Fatalf("limits sent = %v, want one retry only", l)
	}
	// nothing was stored: the next call asks again
	a.explain("CVE-2022-27593", 200, "")
}

// A whole answer in the wrong format is a format error with its own code, and the row records that the model finished.
func TestAWrongFormatIsNotCalledCutOff(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.fake.setAnswer(`{"why":1}`)
	m := a.explain("CVE-2022-27593", 502, "ai_bad_format")
	if msg := m["error"].(map[string]any)["message"].(string); !strings.Contains(msg, "not in the format") || strings.Contains(msg, "cut off") {
		t.Fatalf("message = %q", msg)
	}
	if s := a.stops(); s[len(s)-1] != "end" {
		t.Fatalf("stop = %v", s)
	}
	if l := a.jobLimits(); len(l) != 1 {
		t.Fatalf("limits sent = %v: a whole answer is not asked again", l)
	}
}

// A turn of the tool loop cut at the limit runs none of its (perhaps half-written) tool calls; cut again after the retry, the
// question ends with the cut-off message.
func TestAskACutTurnRunsNoTool(t *testing.T) {
	a := newAskAPI(t)
	a.fake.mu.Lock()
	a.fake.script = func(_ context.Context, _ ai.Profile, req provider.Request) (provider.Response, error) {
		return provider.Response{ToolCalls: []provider.ToolCall{call("search_assets", `{"te`)}, Stop: provider.StopMaxTokens, Usage: provider.Usage{InputTokens: 5, OutputTokens: req.MaxTokens}}, nil
	}
	a.fake.mu.Unlock()
	a.ask("Which machines still expose RDP?", 502, "ai_cut_off")
	if a.data.readCount() != 0 {
		t.Fatal("a tool of a cut turn ran")
	}
	reqs := a.fake.askRequests()
	if len(reqs) != 2 || reqs[0].MaxTokens != 6000 || reqs[1].MaxTokens != 12000 {
		t.Fatalf("requests = %d", len(reqs))
	}
}

// A provider error names the profile, the HTTP status and the provider's words, scrubbed of anything key-shaped.
func TestAProviderErrorSaysWhatTheProviderSaid(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.fake.failWith("Claude", &provider.Error{Kind: provider.ErrRequest, Status: 400, Message: "max_tokens: 64000 > 32000, which is the maximum for this model (key sk-ant-api03-abcdefgh)"})
	m := a.explain("CVE-2022-27593", 502, "provider_error")
	msg := m["error"].(map[string]any)["message"].(string)
	if !strings.Contains(msg, "Claude: provider refused the request (HTTP 400): max_tokens: 64000 > 32000") || strings.Contains(msg, "sk-ant") {
		t.Fatalf("message = %q", msg)
	}
}
