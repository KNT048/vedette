package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/modules/ai/provider"
)

// The tool loop (S-AI-5, INV-14, INV-21, D-211). The model is offered read tools only (ForModel); a call by any other name is refused
// by Offered and nothing runs. Each call goes through the before_tool hooks on its arguments, runs under a deadline, and its result is
// capped, run through the before-AI hooks on its own (a result a hook stops is replaced by a short note and the call goes on, as for
// memory and knowledge pieces) and sent back as fenced data (WrapToolResult). The loop is bounded in turns, calls, bytes and time.
const (
	askMaxRounds       = 6                // turns in which tools run; the two after that only take an answer
	askMaxTurns        = askMaxRounds + 2 // model turns in all
	askMaxCalls        = 12               // tool calls of one question
	askMaxCallsPerTurn = 4
	askMaxRecorded     = 24              // calls written to the activity row and the answer
	askDefaultTimeout  = 2 * time.Minute // the whole question: every model turn and every tool
)

// errAskDeadline: the question used up its time. The parent context is still alive.
var errAskDeadline = errors.New("ai: the question ran out of time")

// toolSession is one question's tool loop: the tools offered, what was called and what came of it.
type toolSession struct {
	svc   *Service
	job   Job
	tools []Tool              // what ForModel and Offered are asked
	impl  map[string]toolImpl // by tool name
	// outcomes, read by the caller after the loop
	calls []AskToolCall
	acts  []ActivityTool
	hits  []HookHit
	names []string
	table *AskTable
	cites []Citation
	// bookkeeping
	n         int // calls so far, refused ones too
	bytesSent int
}

func (s *Service) newToolSession(ctx context.Context, job Job) *toolSession {
	ts := &toolSession{svc: s, job: job, impl: map[string]toolImpl{}}
	for _, t := range append(s.productTools(), s.connectionTools(ctx)...) {
		if _, dup := ts.impl[t.Name]; dup {
			continue
		}
		ts.impl[t.Name] = t
		ts.tools = append(ts.tools, t.Tool)
	}
	return ts
}

func (ts *toolSession) defs() []provider.ToolDef { return ForModel(ts.job, ts.tools) }

// cite adds a source once; the box writes them, the model never does.
func (ts *toolSession) cite(title string) {
	if title == "" || len(ts.cites) >= 6 {
		return
	}
	for _, c := range ts.cites {
		if c.Title == title {
			return
		}
	}
	ts.cites = append(ts.cites, Citation{Title: title})
}

func (ts *toolSession) addHits(r HookResult) {
	ts.hits = append(ts.hits, r.Hits...)
	ts.names = append(ts.names, r.Names()...)
}

func hookNameList(r HookResult) string {
	var parts []string
	for _, n := range r.Names() {
		parts = append(parts, clipRunes(cleanText(n), 60))
	}
	return strings.Join(parts, ", ")
}

const refusedLimit = "The tool limit for this question was reached, so this call did not run. Answer now from the results you already have."

// runCall runs one call of the model and returns the message it gets back. It never returns an error: whatever goes wrong becomes a
// short result, so the model can still answer, and the call is recorded.
func (ts *toolSession) runCall(ctx context.Context, hooks *HookRunner, prompt Prompt, tc provider.ToolCall, turn, inTurn int) provider.ToolResult {
	res := provider.ToolResult{CallID: tc.ID, Name: tc.Name}
	shownName := clipRunes(cleanText(tc.Name), 64)
	rawArgs := strings.TrimSpace(string(tc.Arguments))
	record := func(result string, act *ActivityTool) {
		if len(ts.calls) >= askMaxRecorded { // a model that floods calls fills no more than this many lines of a row
			return
		}
		ts.calls = append(ts.calls, AskToolCall{Tool: shownName, Args: SummarizeArgs(rawArgs), Result: result})
		if act != nil {
			ts.acts = append(ts.acts, *act)
		}
	}
	fail := func(msg string) provider.ToolResult {
		res.Content, res.IsError = msg, true
		return res
	}
	ts.n++
	// the offer is the only authority: a name that ForModel did not offer (a write tool, a disabled or invented one) never runs
	t, offered := Offered(ts.job, ts.tools, tc.Name)
	impl, known := ts.impl[tc.Name]
	if !offered || !known || impl.Name != t.Name {
		record("not available", nil)
		return fail("That tool is not available. Use only the tools you were given.")
	}
	act := func(outcome string) *ActivityTool {
		return &ActivityTool{Name: t.Name, Access: AccessRead, Args: argsNote(rawArgs, outcome)}
	}
	if turn >= askMaxRounds || ts.n > askMaxCalls || inTurn >= askMaxCallsPerTurn {
		record("limit reached", act("skipped"))
		return fail(refusedLimit)
	}

	// before_tool hooks on the arguments; a mask that leaves no valid JSON object is a refusal
	hctx, cancel := context.WithTimeout(ctx, ts.svc.hookTimeout())
	pre, err := hooks.CheckTool(hctx, AccessRead, rawArgs)
	cancel()
	if err != nil || pre.Outcome == OutcomeBlocked || pre.Outcome == OutcomeHeld {
		ts.addHits(pre)
		who := hookNameList(pre)
		if who == "" {
			who = "the hooks"
		}
		record("withheld by hook "+who, act("withheld"))
		return fail("This call was stopped by a rule of the company and did not run.")
	}
	ts.addHits(pre)
	args := pre.Text
	if args == "" {
		args = "{}"
	}
	parse := impl.parse
	if parse == nil {
		parse = parseObject
	}
	parsed, perr := parse(json.RawMessage(args))
	if perr != nil {
		record("invalid arguments", act("error"))
		return fail("Invalid arguments: " + clipRunes(cleanText(perr.Error()), 200))
	}

	rctx, rcancel := context.WithTimeout(ctx, 20*time.Second)
	out, err := impl.run(rctx, parsed)
	rcancel()
	if err != nil {
		var tf errToolFailed
		var bad errBadArgs
		msg := "The tool failed."
		switch {
		case errors.As(err, &bad):
			msg = "Invalid arguments: " + bad.msg
		case errors.As(err, &tf):
			msg = "The tool failed: " + tf.msg
		}
		record("error", act("error"))
		return fail(msg)
	}

	text := out.Text
	if len(text) > askResultBytes {
		cut := askResultBytes
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		text = text[:cut] + "\n[result truncated]"
	}
	// the result goes through the before-AI hooks alone, so a pattern cannot match across two results and one result cannot stop
	// the question (INV-12, INV-21)
	hctx, cancel = context.WithTimeout(ctx, ts.svc.hookTimeout())
	chk, err := hooks.Run(hctx, BeforeAI, text)
	cancel()
	outcome, summary := "ok", out.Summary
	switch {
	case err != nil:
		return ts.withheld(res, record, act, "could not be checked in time", "the hooks")
	case chk.Outcome == OutcomeBlocked || chk.Outcome == OutcomeHeld:
		ts.addHits(chk)
		return ts.withheld(res, record, act, "was stopped by a rule of the company", hookNameList(chk))
	case chk.Outcome == OutcomeMasked:
		ts.addHits(chk)
		outcome, summary = "masked", out.Summary+" (masked by a hook)"
		text = chk.Text
	}
	hctx, cancel = context.WithTimeout(ctx, ts.svc.hookTimeout())
	wrapped, wr, err := WrapToolResult(hctx, hooks, prompt, t.Name, text)
	cancel()
	if err != nil || wr.Outcome == OutcomeBlocked || wr.Outcome == OutcomeHeld {
		ts.addHits(wr)
		return ts.withheld(res, record, act, "could not be passed on safely", "the hooks")
	}
	ts.addHits(wr)
	if ts.bytesSent+len(wrapped) > askTotalBytes {
		record("size limit reached", act("skipped"))
		return fail("The total size of tool results for this question was reached, so this result was not sent. Answer from what you have.")
	}
	ts.bytesSent += len(wrapped)
	if wr.Outcome == OutcomeMasked {
		outcome = "masked"
	}
	// the table is the box's: from the newest list result that went to the model whole
	if outcome == "ok" && out.Table != nil {
		ts.table = out.Table
	}
	if outcome == "ok" {
		ts.cite(out.Cite)
	}
	record(summary, act(outcome))
	res.Content = wrapped
	return res
}

func (ts *toolSession) withheld(res provider.ToolResult, record func(string, *ActivityTool), act func(string) *ActivityTool, why, who string) provider.ToolResult {
	record("withheld by hook "+who, act("withheld"))
	res.Content = fmt.Sprintf("[This result %s (%s) and was not sent. Tell the person that the box held it back.]", why, who)
	res.IsError = true
	return res
}

// parseObject reads the arguments of a connection tool: one JSON object. The reader (core/conn/read) checks the names, types and sizes
// against the tool's own schema and refuses what does not fit; this is the edge of the box.
func parseObject(raw json.RawMessage) (map[string]any, error) {
	if len(raw) > askMaxArgs {
		return nil, errBadArgs{"the arguments are too long"}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil || dec.More() {
		return nil, errBadArgs{"the arguments must be one JSON object"}
	}
	return m, nil
}

// argsNote is what the activity row says of a call: a short scrubbed form of the arguments, their hash and how it ended. Never the
// result.
func argsNote(raw, outcome string) string {
	return fmt.Sprintf("%s [%s #%s]", SummarizeArgs(raw), outcome, HashContent(raw)[:10])
}

// converse is the model side of the loop: it asks, runs the tools the model calls, and asks again until the model answers with text.
// Every turn goes through the router, so the privacy rule and the caps apply to each one (INV-3, INV-4): a turn that carries tool
// results is a turn that carries internal data. The tokens of all turns are added; the other fields are those of the last answer.
func (s *Service) converse(ctx context.Context, spec JobSpec, hooks *HookRunner, prompt Prompt, req provider.Request) (CallResult, error) {
	ts := spec.tools
	timeout := s.cfg.AskTimeout
	if timeout <= 0 {
		timeout = askDefaultTimeout
	}
	lctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req.Tools = ts.defs()
	msgs := append([]provider.Message(nil), req.Messages...)
	var (
		last     CallResult
		attempts []Attempt
		down     *Downgrade
		usage    provider.Usage
	)
	merged := func() CallResult {
		out := last
		out.Attempts, out.Downgrade = attempts, down
		out.Response.Usage = usage
		return out
	}
	for turn := range askMaxTurns {
		req.Messages = msgs
		res, err := s.router.Call(lctx, spec.Job, req)
		attempts, down = append(attempts, res.Attempts...), firstDowngrade(down, res.Downgrade)
		if err != nil {
			if lctx.Err() != nil && ctx.Err() == nil {
				err = errAskDeadline
			}
			return merged(), err
		}
		usage.InputTokens += res.Response.Usage.InputTokens
		usage.OutputTokens += res.Response.Usage.OutputTokens
		last = res
		calls := res.Response.ToolCalls
		if len(calls) == 0 || (turn >= askMaxTurns-1 && strings.TrimSpace(res.Response.Text) != "") {
			return merged(), nil
		}
		if turn == askMaxTurns-1 {
			return merged(), ErrBadOutput // the last turn still asks for tools and says nothing
		}
		msgs = append(msgs, provider.Message{Role: provider.RoleAssistant, Text: res.Response.Text, ToolCalls: calls, Raw: res.Response.Raw})
		results := make([]provider.ToolResult, 0, len(calls))
		for i, tc := range calls {
			results = append(results, ts.runCall(lctx, hooks, prompt, tc, turn, i))
		}
		msgs = append(msgs, provider.Message{Role: provider.RoleTool, ToolResults: results})
	}
	return merged(), ErrBadOutput
}

// note says, for the activity row, how many calls were made and how many did not run (counts only).
func (ts *toolSession) note() string {
	if ts == nil {
		return ""
	}
	held, refused := 0, 0
	for _, c := range ts.calls {
		switch {
		case strings.HasPrefix(c.Result, "withheld"):
			held++
		case c.Result == "not available" || c.Result == "limit reached" || c.Result == "size limit reached" || c.Result == "invalid arguments" || c.Result == "error":
			refused++
		}
	}
	n := " with " + plural(len(ts.calls), "tool call", "tool calls")
	if held > 0 {
		n += fmt.Sprintf(", %d held back by a hook", held)
	}
	if refused > 0 {
		n += fmt.Sprintf(", %d did not run", refused)
	}
	return n
}
