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
// memory and knowledge pieces) and sent back as fenced data (WrapToolResult). The loop is bounded in turns, calls, bytes, input tokens
// and time (D-211, D-482).
const (
	askMaxRounds = 4                // turns in which tools run; the two after that only take an answer
	askMaxTurns  = askMaxRounds + 2 // model turns in all
	askMaxCalls  = 8                // tool calls of one question
	// askInputBudget: every turn sends the whole conversation again, so the input of a question grows with each turn. After the first
	// turn, the tools of a turn run only while the input spent so far plus twice that turn's own input (the next turn costs at least as
	// much, and the answer after it as much again) stays within this; otherwise the model is told to answer from what it has.
	askInputBudget     = 16_000
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
	hits  []AskHook // labelled with the step (tool call or tool result) and the tool
	names []string
	table *AskTable
	cites []Citation
	// bookkeeping
	n         int // calls so far, refused ones too
	bytesSent int
	spent     bool // the input budget of the question allows no further tool turn (askInputBudget)
	leftOut   bool // a call did not run, or its result was not sent, to keep within the budget of the question (tokens or bytes)
}

func (s *Service) newToolSession(ctx context.Context, job Job) *toolSession {
	ts := &toolSession{svc: s, job: job, impl: map[string]toolImpl{}}
	tools := s.productTools()
	if job == JobAskMyData { // log investigation reads the box only (D-223): the connections are not listed, and not asked
		tools = append(tools, s.connectionTools(ctx)...)
	}
	for _, t := range tools {
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

func (ts *toolSession) addHits(r HookResult, step, tool string) {
	ts.hits = append(ts.hits, stepHooks(step, tool, r.Hits)...)
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
	// What is stored and shown of the arguments is what the hooks let through: until they have run it is a placeholder, so raw text
	// the model wrote never reaches the answer, the history or the activity row (M1).
	shownArgs := "[not run]"
	record := func(result string, act *ActivityTool) {
		if len(ts.calls) >= askMaxRecorded { // a model that floods calls fills no more than this many lines of a row
			return
		}
		ts.calls = append(ts.calls, AskToolCall{Tool: shownName, Args: SummarizeArgs(shownArgs), Result: result})
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
		return &ActivityTool{Name: t.Name, Access: AccessRead, Args: argsNote(shownArgs, outcome)}
	}
	if turn >= askMaxRounds || ts.n > askMaxCalls || inTurn >= askMaxCallsPerTurn || ts.spent {
		ts.leftOut = ts.leftOut || ts.spent
		record("limit reached", act("skipped"))
		return fail(refusedLimit)
	}

	// a connection tool sends the arguments to that connection: refused when the privacy rule is on and the connection is not inside
	// the network, even if the rule was turned on after the tools were listed (D-212)
	if impl.ConnectorID != "" && ts.svc.snap.Load().assign.InternalOnly && !impl.internal {
		record("not available", act("skipped"))
		return fail("That tool is not available. Use only the tools you were given.")
	}

	// The arguments are the model's words, so they go through the hooks like a question: written out once as canonical JSON (a \u
	// escape cannot hide a word from a pattern), the personal-data hook first, then the before_tool hooks. A mask that leaves no
	// valid JSON object is a refusal.
	canon, cerr := canonicalJSON(tc.Arguments)
	if cerr != nil {
		shownArgs = "[invalid]"
		record("invalid arguments", act("error"))
		return fail("Invalid arguments: the arguments must be one JSON object")
	}
	hctx, cancel := context.WithTimeout(ctx, ts.svc.hookTimeout())
	pii, err := hooks.RunPersonalData(hctx, canon)
	var pre HookResult
	if err == nil && pii.Outcome != OutcomeBlocked && pii.Outcome != OutcomeHeld {
		pre, err = hooks.CheckTool(hctx, AccessRead, pii.Text)
	}
	cancel()
	for _, r := range []HookResult{pii, pre} {
		ts.addHits(r, StepToolCall, t.Name)
	}
	stopped := pii
	if pii.Outcome != OutcomeBlocked && pii.Outcome != OutcomeHeld {
		stopped = pre
	}
	if err != nil || stopped.Outcome == OutcomeBlocked || stopped.Outcome == OutcomeHeld {
		who := hookNameList(stopped)
		if who == "" {
			who = "the hooks"
		}
		shownArgs = "[withheld by hook " + who + "]"
		record("withheld by hook "+who, act("withheld"))
		return fail("This call was stopped by a rule of the company and did not run.")
	}
	args := pre.Text
	shownArgs = args
	if args == "" {
		args = "{}"
		shownArgs = args
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
		ts.addHits(chk, StepToolResult, t.Name)
		return ts.withheld(res, record, act, "was stopped by a rule of the company", hookNameList(chk))
	case chk.Outcome == OutcomeMasked:
		ts.addHits(chk, StepToolResult, t.Name)
		outcome, summary = "masked", out.Summary+" (masked by a hook)"
		text = chk.Text
	}
	hctx, cancel = context.WithTimeout(ctx, ts.svc.hookTimeout())
	wrapped, wr, err := WrapToolResult(hctx, hooks, prompt, t.Name, text)
	cancel()
	if err != nil || wr.Outcome == OutcomeBlocked || wr.Outcome == OutcomeHeld {
		ts.addHits(wr, StepToolResult, t.Name)
		return ts.withheld(res, record, act, "could not be passed on safely", "the hooks")
	}
	ts.addHits(wr, StepToolResult, t.Name)
	if ts.bytesSent+len(wrapped) > askTotalBytes {
		ts.leftOut = true
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
func argsNote(shown, outcome string) string {
	return fmt.Sprintf("%s [%s #%s]", SummarizeArgs(shown), outcome, HashContent(shown)[:10])
}

// canonicalJSON writes the arguments of a call as one JSON object with sorted keys and no escaping of readable characters.
func canonicalJSON(raw json.RawMessage) (string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return "{}", nil
	}
	if len(raw) > askMaxArgs {
		return "", errBadArgs{"the arguments are too long"}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil || dec.More() {
		return "", errBadArgs{"the arguments must be one JSON object"}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return "", errBadArgs{"the arguments must be one JSON object"}
	}
	return strings.TrimSuffix(b.String(), "\n"), nil
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
	// Providers differ on structured output together with tools (Gemini 2.x refuses the pair), so a job with a schema asks for the
	// JSON in its task and its strict Check reads the last answer (D-223).
	req.Schema = nil
	msgs := append([]provider.Message(nil), req.Messages...)
	var (
		last     CallResult
		attempts []Attempt
		usage    provider.Usage
	)
	merged := func() CallResult {
		out := last
		out.Attempts = attempts
		out.Response.Usage = usage
		return out
	}
	for turn := range askMaxTurns {
		req.Messages = msgs
		res, err := s.router.Call(lctx, spec.Job, req)
		attempts = append(attempts, res.Attempts...)
		if err != nil {
			// a turn cut at the limit whose retry could not be made still spent its tokens
			usage.InputTokens += res.Response.Usage.InputTokens
			usage.OutputTokens += res.Response.Usage.OutputTokens
			if lctx.Err() != nil && ctx.Err() == nil {
				err = errAskDeadline
			}
			return merged(), err
		}
		usage.InputTokens += res.Response.Usage.InputTokens
		usage.OutputTokens += res.Response.Usage.OutputTokens
		last = res
		calls := res.Response.ToolCalls
		if res.Response.Stop == provider.StopMaxTokens { // cut at the output limit even after the router's retry: the calls in it may be
			return merged(), nil // half written, so none runs; RunJob names the cut answer
		}
		if len(calls) == 0 || (turn >= askMaxTurns-1 && strings.TrimSpace(res.Response.Text) != "") {
			return merged(), nil
		}
		if turn == askMaxTurns-1 {
			return merged(), ErrBadOutput // the last turn still asks for tools and says nothing
		}
		ts.spent = turn > 0 && usage.InputTokens+2*res.Response.Usage.InputTokens > askInputBudget
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
