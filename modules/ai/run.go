package ai

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/chain/chainhead"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/ai/provider"
)

// ErrBadOutput means the model answered, but not in the format the job asked for (POST-5 status schema_error). The answer is not shown
// and not stored; the call is still logged with its tokens.
var ErrBadOutput = errors.New("ai: the answer does not match the expected format")

// JobSpec describes one call of a job. The caller supplies the job's own instructions and its data; RunJob adds everything that
// belongs to every call: the built-in rules, the before and after hooks, the fenced untrusted data, routing with fallback, the
// token meter, and the activity row.
type JobSpec struct {
	Job   Job
	Actor string // email of the person who asked, "system" for a scheduled job
	Task  string // the job's instructions (skill prompt)
	// Question is what is asked, and Data the untrusted text that goes with it (feed items, device data, log lines): Data is the
	// only way untrusted text reaches the prompt, between the per-call markers (INV-21).
	Question string
	Data     []DataBlock
	// KnowledgeQuery is the text the documents of the knowledge base are searched with (S-AI-7); "" = the question and the data.
	KnowledgeQuery string
	knowledge      *knowCall // the passages a caller retrieved already; nil = RunJob retrieves
	// tools is the read-tool loop of a job that lets the model read the box (ask-my-data, D-211); nil = one call, no tools.
	tools *toolSession
	// AnswerWhenBlocked makes an answer that an after_ai hook stops a result (JobResult.Blocked, text = the hook's message) instead of
	// a 409; the row of the call still says blocked_by_hook.
	AnswerWhenBlocked bool
	Schema            *provider.Schema
	MaxTokens         int
	Summary           string // what the activity row says on success; no secrets, no customer data
	// Check validates the answer before anything is stored; an error is ErrBadOutput.
	Check func(text string) error
	// Store runs in the same transaction as the activity row, so a result and its record commit together.
	Store func(ctx context.Context, tx *sql.Tx, r JobResult) error
}

// JobResult is the answer of one call.
type JobResult struct {
	Text       string
	Model      string
	Profile    string
	TokensIn   int
	TokensOut  int
	Fallback   bool
	ActivityID string
	// Hits are the hooks that acted on the answer (after_ai); Blocked is set when one stopped it (AnswerWhenBlocked); Downgrade is the
	// automatic drop of the token level this call caused, if any.
	Hits      []HookHit
	Blocked   bool
	Downgrade *Downgrade
	// Documents are the file names of the knowledge documents whose pieces went with the call (S-AI-7), for the answer's sources.
	Documents []string
}

func apiUnavailable(msg string) error { return apierr.New(http.StatusConflict, "ai_unavailable", msg) }

// The errors of a call that was made, or stopped by a rule, each with its own code so neither the API nor the page calls them "not set
// up" (ai_unavailable, which stays for: module off, no profile, none assigned, the privacy rule, a skill turned off).
func apiBlocked(msg string) error   { return apierr.New(http.StatusConflict, "blocked_by_hook", msg) }
func apiCutOff(msg string) error    { return apierr.New(http.StatusBadGateway, "ai_cut_off", msg) }
func apiBadFormat(msg string) error { return apierr.New(http.StatusBadGateway, "ai_bad_format", msg) }
func apiTimeout(msg string) error   { return apierr.New(http.StatusGatewayTimeout, "ai_timeout", msg) }

// hooksHint ends every message about a hook: what the person can do, and who can change the hook.
const hooksHint = " Rephrase and try again; an administrator can adjust the hooks in Settings, AI assistant, Hooks."

// unavailable says why no profile can run the job, in the words of the mock (INV-3: never a silent switch to cloud).
func (s *Service) unavailable(job Job, reasons []string) error {
	sn := s.snap.Load()
	usable := false
	for _, p := range sn.profiles {
		usable = usable || p.Usable()
	}
	switch {
	case !usable:
		return apiUnavailable("No AI profile is set up. An administrator adds one in Settings, AI assistant.")
	case len(reasons) == 0:
		return apiUnavailable(fmt.Sprintf("No AI profile is assigned to %s. Assign one in Settings, AI assistant.", job.Name()))
	}
	for _, r := range reasons {
		if strings.Contains(r, "privacy rule") {
			return apiUnavailable(fmt.Sprintf("This job sends internal data, but the privacy rule only allows internal AI profiles for it. Assign an internal profile for %s or switch the rule off in Settings, AI assistant.", job.Name()))
		}
	}
	return apiUnavailable(fmt.Sprintf("No AI profile could answer %s (%s). Check the profiles in Settings, AI assistant, or add a fallback.", job.Name(), strings.Join(reasons, "; ")))
}

// Ready reports why a job cannot run now: nil when its skill is on and a profile is assigned, usable and allowed for it.
func (s *Service) Ready(job Job) error {
	if err := s.skillOff(job); err != nil {
		return err
	}
	cands, reasons := s.router.Candidates(job)
	if len(cands) > 0 {
		return nil
	}
	return s.unavailable(job, reasons)
}

// attemptReasons lists, per profile tried, why it did not answer. A provider error is named by its kind only: its own text is
// not shown to the person who asked.
func attemptReasons(res CallResult, ue *UnavailableError) []string {
	var out []string
	for _, a := range res.Attempts {
		var pe *provider.Error
		switch {
		case errors.As(a.Err, &pe):
			out = append(out, a.Profile+": "+pe.Kind.Error())
		case a.Err != nil:
			out = append(out, a.Profile+": "+a.Err.Error())
		}
	}
	if len(out) == 0 && ue != nil {
		out = ue.Reasons
	}
	return out
}

// appendActivity adds one row to ai_activity inside tx and moves the chain head (INV-17, INV-18). The caller holds the write
// transaction, which serialises the chain.
func (s *Service) appendActivity(ctx context.Context, tx *sql.Tx, e ActivityEntry) (ActivityEntry, error) {
	prev := Genesis
	err := tx.QueryRowContext(ctx, `SELECT hash FROM ai_activity ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	// No row means a new log. A prune never removes the newest row (chainhead.Prune), so the table is not empty after one.
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ActivityEntry{}, fmt.Errorf("ai: read activity head: %w", err)
	}
	now := s.cfg.Clock()
	e.ID, e.TS = store.NewID("act"), FormatTS(now)
	e.Summary = clipRunes(e.Summary, 600)
	sealed, err := Seal(prev, e)
	if err != nil {
		return ActivityEntry{}, err
	}
	hooks, _ := json.Marshal(sealed.Hooks)
	tools, _ := json.Marshal(sealed.Tools)
	var links any
	if len(sealed.Links) > 0 {
		b, _ := json.Marshal(sealed.Links)
		links = string(b)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO ai_activity (id, ts, job, profile, profile_id, outcome, stop, retried, model, trigger, hooks, tools, input_hash, output_hash, summary, tokens_in, tokens_out, result, links, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sealed.ID, sealed.TS, sealed.Job, sealed.Profile, nullable(e.ProfileID), nullable(e.Outcome), nullable(e.Stop), e.Retried, sealed.Model, sealed.Trigger, string(hooks), string(tools), sealed.InputHash, sealed.OutputHash, sealed.Summary,
		sealed.TokensIn, sealed.TokensOut, string(sealed.Result), links, sealed.PrevHash, sealed.Hash); err != nil {
		return ActivityEntry{}, fmt.Errorf("ai: write activity: %w", err)
	}
	if err := chainhead.Advance(ctx, tx, "ai_activity", sealed.Hash, now); err != nil {
		return ActivityEntry{}, err
	}
	return sealed, nil
}

// record writes the activity row of a call that produced no stored result (blocked, capped, failed).
func (s *Service) record(ctx context.Context, e ActivityEntry) error {
	ctx, cancel := detached(ctx)
	defer cancel()
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := s.appendActivity(ctx, tx, e)
		return err
	})
}

// writeTimeout bounds a write that must happen even though the request that caused it is gone.
const writeTimeout = 10 * time.Second

// detached returns a context that outlives the request but not by long. Once the request has reached the provider, the device
// data has left the box and the tokens are spent, so the activity row (INV-17) is written whether or not anybody still waits.
func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
}

// guard runs the before_ai hooks on the question and on every data block, separately, so a mask never touches the markers around
// them. Any block, hold or failed run stops the call (fail closed): nothing is sent. stop says which part was stopped (the question,
// or the data from a named source) and why; matched is set when a hook matched it (a rephrase or a change of the hook helps), not
// when the hooks could not run.
func (s *Service) guard(ctx context.Context, hooks *HookRunner, spec JobSpec) (question string, data []DataBlock, names []string, stop string, matched bool) {
	// The same deadline as the after_ai pass, for the whole pass: a hook that cannot finish is a block (fail closed).
	ctx, cancel := context.WithTimeout(ctx, s.hookTimeout())
	defer cancel()
	run := func(text, where string) (string, bool) {
		r, err := hooks.Run(ctx, BeforeAI, text)
		if errors.Is(err, ErrHookInputTooLarge) {
			stop = "The text of " + where + " is too long to check against the hooks, so it was not sent."
			return "", false
		}
		if err != nil {
			stop = "The text of " + where + " could not be checked against the hooks in time, so it was not sent. Try again."
			return "", false
		}
		names = append(names, r.Names()...)
		if r.Outcome == OutcomeBlocked || r.Outcome == OutcomeHeld {
			stop, matched = "a hook stopped "+where+". "+r.Text, true
			return "", false
		}
		return r.Text, true
	}
	q, ok := run(spec.Question, "the question")
	if !ok {
		return "", nil, dedupe(names), stop, matched
	}
	for _, d := range spec.Data {
		t, ok := run(d.Text, fmt.Sprintf("the data sent with it (%s)", clipRunes(cleanLine(d.Source, 80), 80)))
		if !ok {
			return "", nil, dedupe(names), stop, matched
		}
		d.Text = t
		data = append(data, d)
	}
	return q, data, dedupe(names), "", false
}

func dedupe(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, n := range in {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// RunJob runs one job call (S-AI-2, S-AI-6): hooks, prompt, routing, meter, hooks again on the answer, the format check, and one
// activity row for the call, written with the result in one transaction. Errors that a person should see are *apierr.Error:
// 409 ai_unavailable (also when a hook stopped the request or the answer was not usable) and 429 daily_cap.
func (s *Service) RunJob(ctx context.Context, spec JobSpec) (JobResult, error) {
	if !spec.Job.Valid() || spec.Actor == "" || spec.MaxTokens <= 0 {
		return JobResult{}, fmt.Errorf("ai: run job: invalid spec")
	}
	if err := s.Ready(spec.Job); err != nil {
		return JobResult{}, err // nothing was attempted: no activity row
	}
	trigger := "user:" + spec.Actor
	if spec.Actor == "system" {
		trigger = "system:schedule"
	}
	entry := ActivityEntry{Job: string(spec.Job), Trigger: trigger, Hooks: []string{}, InputHash: HashContent(""), OutputHash: HashContent(""), Result: ResultError}

	// One generation of the rules and hooks for the whole call: the answer is checked by the hooks that checked the question.
	har := s.harness.Load()
	hooks := har.runner
	// What an administrator keeps in memory goes with the data, line by line through the before-AI hooks (INV-8): a line a hook stops
	// is left out and named in the row, the rest is sent.
	mem, err := s.memoryForCall(ctx, hooks, spec.Job)
	if err != nil {
		return JobResult{}, err
	}
	// The memory block is not in guard's pass: each of its lines was checked by these same hooks, and a second pass over the joined
	// block would let a pattern match across a line break and stop the call for two memories that touch. It is added after the pass,
	// first, with the same fencing as any data block.
	// The documents of the knowledge base come the same way: pieces found for this job, each one through the hooks alone, added after
	// the pass as a data block (S-AI-7, INV-10).
	know := spec.knowledge // already retrieved by a caller that needed it for its cache key (explain): one retrieval, one hook pass
	if know == nil {
		k, err := s.knowledgeForCall(ctx, hooks, spec.Job, knowledgeQuery(spec))
		if err != nil {
			return JobResult{}, err
		}
		know = &k
	}
	question, data, hookNames, stop, matched := s.guard(ctx, hooks, spec)
	entry.Hooks = dedupe(append(append(append(append(hookNames, mem.names...), mem.leftNames...), know.names...), know.leftNames...))
	if stop == "" && len(know.refs) > 0 {
		data = append([]DataBlock{know.block}, data...)
	}
	if stop == "" && len(mem.ids) > 0 {
		data = append([]DataBlock{mem.block}, data...)
	}
	if stop != "" {
		entry.Result, entry.Summary, entry.InputHash = ResultBlockedByHook, "Not sent: "+stop, HashContent(stop)
		if err := s.record(ctx, entry); err != nil {
			return JobResult{}, err
		}
		msg := "The AI was not asked: " + stop
		if matched {
			msg += hooksHint
		}
		return JobResult{}, apiBlocked(msg)
	}
	prompt, err := PromptBuilder{}.Build(PromptInput{Job: spec.Job, Task: spec.Task, Rules: har.rules, Question: question, Data: data, WithTools: spec.tools != nil})
	if err != nil {
		return JobResult{}, fmt.Errorf("ai: build prompt: %w", err)
	}
	entry.InputHash = HashContent(prompt.System + "\n" + prompt.User)
	req := provider.Request{System: prompt.System, Messages: []provider.Message{{Role: provider.RoleUser, Text: prompt.User}}, Schema: spec.Schema, MaxTokens: spec.MaxTokens}

	var res CallResult
	if spec.tools != nil {
		res, err = s.converse(ctx, spec, hooks, prompt, req)
		entry.Tools = spec.tools.acts
		entry.Hooks = dedupe(append(entry.Hooks, spec.tools.names...))
		if err != nil && res.Profile != "" { // a turn answered before the failure: its tokens are spent and its profile is known
			entry.Profile, entry.ProfileID, entry.Model = res.Profile, res.ProfileID, res.Model
			entry.TokensIn, entry.TokensOut = res.Response.Usage.InputTokens, res.Response.Usage.OutputTokens
		}
	} else {
		res, err = s.router.Call(ctx, spec.Job, req)
	}
	if err != nil {
		s.touchSent(ctx, mem.ids, res)
		return JobResult{}, s.capNote(s.failed(ctx, spec, entry, res, err), res)
	}
	if spec.tools != nil && spec.Schema != nil {
		// the tool loop asks for the JSON without structured output (D-223): out of a code block before the hooks walk its strings, so a
		// \u escape cannot hide a word from an after_ai pattern
		res.Response.Text = unfence(res.Response.Text)
	}
	entry.Profile, entry.ProfileID, entry.Model, entry.TokensIn, entry.TokensOut = res.Profile, res.ProfileID, res.Model, res.Response.Usage.InputTokens, res.Response.Usage.OutputTokens
	entry.Stop, entry.Retried = string(res.Response.Stop), retrySent(res)
	entry.OutputHash = HashContent(res.Response.Text)
	entry.Result = ResultOK
	if res.Fallback {
		entry.Result = ResultFallbackUsed
	}

	// The answer is here and the tokens are spent: the checks and the row that follow run even if the caller has gone. The hooks get
	// their own deadline, so slow hooks cannot use up the time of the activity row (INV-17), which has a fresh one.
	// An answer cut at the output limit (also after the router's one retry with a higher limit) is half an answer: it is not checked,
	// not shown and not stored, and it is named as what it is, not as a format error.
	cut := res.Response.Stop == provider.StopMaxTokens
	var after HookResult
	var herr error
	if !cut {
		hctx, hcancel := context.WithTimeout(context.WithoutCancel(ctx), s.hookTimeout())
		structured := spec.Schema != nil && spec.Check != nil && spec.Check(res.Response.Text) == nil // the format is checked first; a bad answer is refused below
		after, herr = afterHooks(hctx, hooks, structured, res.Response.Text)
		hcancel()
	}
	entry.Hooks = dedupe(append(entry.Hooks, after.Names()...))
	wctx, wcancel := detached(ctx)
	defer wcancel()
	text := after.Text
	var bad error
	blocked := false
	switch {
	case cut:
		limit := spec.MaxTokens
		if res.Retried {
			limit = retryLimit(spec.MaxTokens)
		}
		entry.Result, entry.Summary = ResultError, fmt.Sprintf("The answer was cut off at the output limit (%s tokens) and was discarded.", number(limit))
		bad = apiCutOff(fmt.Sprintf("The AI's answer was cut off at the output limit (%s tokens), so it was not used. Try again; if it keeps happening, use a model for %s that writes shorter answers.", number(limit), spec.Job.Name()))
	case herr != nil:
		entry.Result, entry.Summary, bad = ResultBlockedByHook, "The answer was not used: it could not be checked against the hooks.", apiBlocked("The AI answered, but the answer could not be checked against the hooks in time, so it was not used. Try again.")
	case (after.Outcome == OutcomeBlocked || after.Outcome == OutcomeHeld) && spec.AnswerWhenBlocked:
		entry.Result, entry.Summary, blocked = ResultBlockedByHook, "The answer was not used: "+after.Text, true
	case after.Outcome == OutcomeBlocked || after.Outcome == OutcomeHeld:
		entry.Result, entry.Summary, bad = ResultBlockedByHook, "The answer was not used: "+after.Text, apiBlocked("The AI answered, but a hook stopped the answer: "+after.Text+hooksHint)
	case spec.Check != nil && spec.Check(text) != nil:
		entry.Result, entry.Summary, bad = ResultError, "The answer did not match the expected format and was discarded.", apiBadFormat("The AI answered, but not in the format Vedette needs, so the answer was discarded. Try again, or use a stronger model for this job.")
	}
	var id string
	storeFailed := false
	werr := s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		ctx := wctx
		if bad == nil && !blocked {
			entry.Summary = spec.Summary + spec.tools.note() + leftOutNote(mem.left) + knowledgeNote(*know)
			if res.Fallback {
				entry.Summary += " (answered by the fallback profile)"
			}
		}
		sealed, err := s.appendActivity(ctx, tx, entry)
		if err != nil {
			return err
		}
		id = sealed.ID
		if err := touchMemory(ctx, tx, mem.ids, store.FormatTS(s.cfg.Clock())); err != nil {
			return err
		}
		if res.Downgrade != nil {
			if err := s.writeDowngrade(ctx, tx, spec.Actor, res.Downgrade); err != nil {
				return err
			}
		}
		if bad == nil && spec.Store != nil {
			if err := spec.Store(ctx, tx, JobResult{Text: text, Model: res.Model, Profile: res.Profile, TokensIn: entry.TokensIn, TokensOut: entry.TokensOut, Fallback: res.Fallback, ActivityID: id,
				Hits: after.Hits, Blocked: blocked, Downgrade: res.Downgrade, Documents: know.docs}); err != nil {
				storeFailed = true
				return err
			}
		}
		return nil
	})
	if werr != nil {
		if storeFailed {
			// The result and the row commit together, so both were rolled back; the call happened, so it still gets a row that says
			// the answer was not kept.
			entry.Result, entry.Summary = ResultError, "The answer was not stored: the result could not be written."
			_ = s.record(ctx, entry)
		}
		return JobResult{}, werr
	}
	if bad != nil {
		return JobResult{}, s.capNote(bad, res)
	}
	return JobResult{Text: text, Model: res.Model, Profile: res.Profile, TokensIn: entry.TokensIn, TokensOut: entry.TokensOut, Fallback: res.Fallback, ActivityID: id,
		Hits: after.Hits, Blocked: blocked, Downgrade: res.Downgrade, Documents: know.docs}, nil
}

// leftOutNote names the memories a hook kept out of the call (ids, never text).
func leftOutNote(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return " (memory left out because a hook stopped it: " + strings.Join(ids, ", ") + ")"
}

// touchSent records the use of the memories when a request was actually sent to a provider but no answer came back: the text has
// left the box all the same. A write that fails is logged, not returned: the caller already has an error to report.
func (s *Service) touchSent(ctx context.Context, ids []string, res CallResult) {
	sent := false
	for _, a := range res.Attempts {
		sent = sent || !a.Skipped
	}
	if !sent || len(ids) == 0 {
		return
	}
	wctx, cancel := detached(ctx)
	defer cancel()
	if err := s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		return touchMemory(wctx, tx, ids, store.FormatTS(s.cfg.Clock()))
	}); err != nil {
		s.cfg.Log.WarnContext(ctx, "ai: could not record the use of memory", "error", err)
	}
}

// recordSpent writes the row of a call that spent tokens and got no answer, with the drop of the level those tokens caused (INV-4:
// ai_downgrade and the ai.downgrade audit line), in one transaction.
func (s *Service) recordSpent(ctx context.Context, spec JobSpec, entry ActivityEntry, res CallResult) error {
	if res.Downgrade == nil {
		return s.record(ctx, entry)
	}
	wctx, cancel := detached(ctx)
	defer cancel()
	return s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		if _, err := s.appendActivity(wctx, tx, entry); err != nil {
			return err
		}
		return s.writeDowngrade(wctx, tx, spec.Actor, res.Downgrade)
	})
}

// spentTokens is what the requests of a call used, all turns of a tool loop together.
func spentTokens(res CallResult) int {
	return res.Response.Usage.InputTokens + res.Response.Usage.OutputTokens
}

// profileCappedLast returns the profile whose own daily cap stopped the last turn of a call, when every profile of that turn was skipped
// before a request was sent and one of them for its cap; "" otherwise. The turns before it are the attempts up to the last answered one.
func profileCappedLast(res CallResult) string {
	name := ""
	for i := len(res.Attempts) - 1; i >= 0; i-- {
		a := res.Attempts[i]
		if !a.Skipped {
			if a.Err != nil {
				return "" // a request of the last turn was sent and failed: the provider's failure, not the cap
			}
			break
		}
		if errors.Is(a.Err, errProfileCapSkip) && name == "" {
			name = a.Profile
		}
	}
	return name
}

// capNote adds to the error of a call that failed after it spent tokens that today's cap is now used up, when that call is what used
// it up: the person reads what went wrong first, then why the AI is paused (W1-27). A refusal by the cap itself says so already.
func (s *Service) capNote(err error, res CallResult) error {
	e, ok := apierr.As(err)
	if !ok || e.Code == "daily_cap" || spentTokens(res) == 0 || !s.meter.UsedUp() {
		return err
	}
	out := *e
	out.Message = fmt.Sprintf("%s This request used %s tokens, and today's %s token cap is now used up: the AI is paused until tomorrow unless an administrator raises the cap in Settings, AI assistant.",
		strings.TrimSpace(e.Message), number(spentTokens(res)), number(s.snap.Load().cfg.DailyCap))
	return &out
}

// capSummary is the activity summary of a call the daily cap stopped (outcome capped).
const capSummary = "Not sent: today's token cap is used up and the level is already the minimum."

// notSent is the outcome of a call whose every attempt was skipped before a request was sent: capped when a profile's own daily cap
// was one of the reasons, otherwise not_sent. "" when a request was sent.
func notSent(res CallResult) string {
	out := OutcomeNotSent
	for _, a := range res.Attempts {
		if !a.Skipped {
			return ""
		}
		if errors.Is(a.Err, errProfileCapSkip) {
			out = OutcomeCapped
		}
	}
	return out
}

// failed records a call that got no answer and returns the error the person sees.
func (s *Service) failed(ctx context.Context, spec JobSpec, entry ActivityEntry, res CallResult, err error) error {
	if ctx.Err() != nil {
		// The caller gave up (a closed tab, a timeout). If the request had reached the provider the data has left the box and tokens
		// may be spent, so the call still gets its row; if it had not, nothing was sent and there is nothing to record.
		if len(res.Attempts) > 0 {
			// say which profile the request went to: the last attempt that sent a request is the one running when the caller left
			for i := len(res.Attempts) - 1; i >= 0; i-- {
				if last := res.Attempts[i]; !last.Skipped {
					entry.Profile, entry.ProfileID, entry.Model = last.Profile, last.ProfileID, last.Model
					break
				}
			}
			entry.Summary = "The request was cancelled while the AI was being asked."
			if rerr := s.record(ctx, entry); rerr != nil {
				return rerr
			}
		}
		return err
	}
	// the question's own deadline is what ran out, even when it ran out during the retry of a cut answer
	if a, ok := failedRetry(res); ok && !errors.Is(err, errAskDeadline) {
		return s.retryFailed(ctx, spec, entry, res, a)
	}
	var ue *UnavailableError
	switch {
	case errors.Is(err, errAskDeadline), errors.Is(err, ErrBadOutput) && spec.tools != nil:
		// the question ran out of time, or the model kept asking for tools and never answered: the calls that were made keep their row
		s.nameLastProfile(&entry, res)
		entry.Summary = "Stopped: the question used up its time."
		out := apiTimeout("The AI did not finish in time. Try again, or use a faster profile for this job.")
		if spec.Job == JobAskMyData {
			out = apiTimeout("The AI did not finish in time. Ask a narrower question, or use a faster profile for this job.")
		}
		if !errors.Is(err, errAskDeadline) {
			entry.Summary = "Stopped: the AI kept asking for tools and gave no answer."
			out = apiBadFormat("The AI kept asking for data and gave no answer. Try again, or use a stronger model for this job.")
		}
		if rerr := s.recordSpent(ctx, spec, entry, res); rerr != nil {
			return rerr
		}
		return out
	case spec.tools != nil && errors.As(err, &ue) && toolsRefused(res):
		entry.Summary = "No profile accepted tool calls: " + strings.Join(attemptReasons(res, ue), "; ")
		if rerr := s.record(ctx, entry); rerr != nil {
			return rerr
		}
		return apiUnavailable("The AI profile did not accept tool calls, which " + spec.Job.Name() + " needs. Use a model that supports tools; Settings, AI assistant shows what a connection test found.")
	case errors.Is(err, ErrCapped) && spentTokens(res) > 0:
		// earlier turns of this call were sent and pushed the meter over the cap, so the next one could not be: this call used the cap up,
		// it did not find it used up (W1-27)
		s.nameLastProfile(&entry, res)
		entry.Summary = fmt.Sprintf("Stopped: today's token cap ran out partway through, after %s tokens; no answer.", number(spentTokens(res)))
		entry.Outcome = OutcomeCapped
		if rerr := s.recordSpent(ctx, spec, entry, res); rerr != nil {
			return rerr
		}
		return apierr.New(http.StatusTooManyRequests, "daily_cap", fmt.Sprintf("The AI did not finish: today's %s token cap ran out partway through (this request used %s tokens before it stopped), so there is no answer. Raise the cap in Settings, AI assistant, or wait until tomorrow.",
			number(s.snap.Load().cfg.DailyCap), number(spentTokens(res))))
	case errors.As(err, &ue) && spentTokens(res) > 0 && profileCappedLast(res) != "":
		// the same with a profile's own cap: no other profile could take the next turn
		s.nameLastProfile(&entry, res)
		name := profileCappedLast(res)
		entry.Summary = fmt.Sprintf("Stopped: the profile's own daily token cap ran out partway through, after %s tokens; no answer.", number(spentTokens(res)))
		entry.Outcome = OutcomeCapped
		if rerr := s.recordSpent(ctx, spec, entry, res); rerr != nil {
			return rerr
		}
		return apierr.New(http.StatusTooManyRequests, "daily_cap", fmt.Sprintf("The AI did not finish: the daily token cap of the profile %s ran out partway through (this request used %s tokens before it stopped), so there is no answer. Raise the profile's cap or add a fallback profile in Settings, AI assistant, or wait until tomorrow.",
			name, number(spentTokens(res))))
	case errors.Is(err, ErrCapped):
		entry.Summary, entry.Outcome = capSummary, OutcomeCapped
		if rerr := s.record(ctx, entry); rerr != nil {
			return rerr
		}
		return apierr.New(http.StatusTooManyRequests, "daily_cap", fmt.Sprintf("Today's %s token cap is used up and the tier is already the minimum. Raise the cap in Settings, AI assistant, or wait until tomorrow.", number(s.snap.Load().cfg.DailyCap)))
	case errors.As(err, &ue):
		reasons := attemptReasons(res, ue)
		if len(res.Attempts) == 0 { // never attempted (settings changed under us): no request, no row
			return s.unavailable(spec.Job, reasons)
		}
		entry.Summary = "No profile answered: " + strings.Join(reasons, "; ")
		if out := notSent(res); out != "" { // every profile was skipped: no request left the box
			entry.Summary, entry.Outcome = "Not sent: no AI profile could take the call: "+strings.Join(reasons, "; "), out
		}
		if rerr := s.recordSpent(ctx, spec, entry, res); rerr != nil {
			return rerr
		}
		if perr := providerFailure(spec.Job, res); perr != nil {
			return perr
		}
		return s.unavailable(spec.Job, reasons)
	}
	return err
}

// retrySent reports whether a second request of a cut answer reached the provider (ai_activity.retried).
func retrySent(res CallResult) bool {
	for _, a := range res.Attempts {
		if a.Retry && !a.Skipped {
			return true
		}
	}
	return false
}

// failedRetry returns the retry of a cut answer when it is the attempt that ended the call with an error.
func failedRetry(res CallResult) (Attempt, bool) {
	if n := len(res.Attempts); n > 0 && res.Attempts[n-1].Retry && res.Attempts[n-1].Err != nil {
		return res.Attempts[n-1], true
	}
	return Attempt{}, false
}

// retryFailed records a call whose answer was cut at the output limit and whose second request, with a higher limit, could not be
// made (a cap) or failed (the provider), and says that, with the cap's or the provider's own code rather than "cut off".
func (s *Service) retryFailed(ctx context.Context, spec JobSpec, entry ActivityEntry, res CallResult, a Attempt) error {
	entry.Profile, entry.ProfileID, entry.Model = a.Profile, a.ProfileID, a.Model
	entry.TokensIn, entry.TokensOut = res.Response.Usage.InputTokens, res.Response.Usage.OutputTokens
	entry.Stop, entry.Retried = string(provider.StopMaxTokens), !a.Skipped
	cut := fmt.Sprintf("The AI's answer was cut off at the output limit (%s tokens)", number(spec.MaxTokens))
	var out error
	switch {
	case errors.Is(a.Err, ErrCapped):
		entry.Summary = "The answer was cut off at the output limit; today's token cap left no room to ask again."
		out = apierr.New(http.StatusTooManyRequests, "daily_cap", fmt.Sprintf("%s, and today's %s token cap is used up, so it was not asked again. Raise the cap in Settings, AI assistant, or wait until tomorrow.", cut, number(s.snap.Load().cfg.DailyCap)))
	case errors.Is(a.Err, ErrProfileCapped):
		entry.Summary = "The answer was cut off at the output limit; the profile's own daily cap left no room to ask again."
		out = apierr.New(http.StatusTooManyRequests, "daily_cap", fmt.Sprintf("%s, and the daily token cap of the profile %s is used up, so it was not asked again. Raise the profile's cap in Settings, AI assistant, or wait until tomorrow.", cut, a.Profile))
	default:
		entry.Summary = "The answer was cut off at the output limit, and asking again with a higher limit failed."
		out = providerFailure(spec.Job, CallResult{Attempts: []Attempt{a}})
	}
	wctx, cancel := detached(ctx) // the first request was answered: its tokens are spent and the row is written
	defer cancel()
	if rerr := s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		if _, err := s.appendActivity(wctx, tx, entry); err != nil {
			return err
		}
		if res.Downgrade != nil {
			return s.writeDowngrade(wctx, tx, spec.Actor, res.Downgrade)
		}
		return nil
	}); rerr != nil {
		return rerr
	}
	return out
}

// providerFailure is the error of a call whose requests reached a provider and got an error back, instead of "no profile could
// answer": the profile, the kind, the HTTP status and the provider's own message (provider.Error scrubs it of keys and cuts it to 200
// characters). nil when no request was sent. Every sent request timing out is ai_timeout, every one unreachable is unreachable, any
// other mix is provider_error.
func providerFailure(job Job, res CallResult) error {
	var parts []string
	sent, timeouts, network := 0, 0, 0
	for _, a := range res.Attempts {
		if a.Skipped || a.Err == nil { // an earlier turn of a tool loop that was answered is not a failure
			continue
		}
		sent++
		var pe *provider.Error
		if !errors.As(a.Err, &pe) {
			parts = append(parts, a.Profile+": "+cleanLine(a.Err.Error(), 200))
			continue
		}
		switch {
		case errors.Is(pe, provider.ErrTimeout):
			timeouts++
		case errors.Is(pe, provider.ErrNetwork):
			network++
		}
		p := a.Profile + ": " + pe.Kind.Error()
		if pe.Status != 0 {
			p += fmt.Sprintf(" (HTTP %d)", pe.Status)
		}
		if pe.Category != "" {
			p += " (" + pe.Category + ")"
		}
		if m := cleanLine(provider.Scrub(pe.Message), 200); m != "" {
			p += ": " + m
		}
		parts = append(parts, p)
	}
	if sent == 0 {
		return nil
	}
	detail := strings.Join(parts, "; ")
	switch {
	case timeouts == sent:
		return apiTimeout(fmt.Sprintf("The AI provider did not answer %s in time (%s). Try again, or use a faster profile for this job.", job.Name(), detail))
	case network == sent:
		return apierr.New(http.StatusBadGateway, "unreachable", fmt.Sprintf("Could not reach the AI provider for %s (%s). Check the address of the profile, the box's network and the firewall.", job.Name(), detail))
	}
	return apierr.New(http.StatusBadGateway, "provider_error", fmt.Sprintf("The AI provider returned an error for %s (%s). Check the profile in Settings, AI assistant; the test there shows what the provider accepts.", job.Name(), detail))
}

// nameLastProfile fills the profile of the row from the last attempt that sent a request, when no answer did.
func (s *Service) nameLastProfile(entry *ActivityEntry, res CallResult) {
	if entry.Profile != "" {
		return
	}
	for i := len(res.Attempts) - 1; i >= 0; i-- {
		if a := res.Attempts[i]; !a.Skipped {
			entry.Profile, entry.ProfileID, entry.Model = a.Profile, a.ProfileID, a.Model
			return
		}
	}
}

// toolsRefused reports whether every request that was sent was refused by the provider as a bad request: what a profile that does not
// take tools answers (provider.ErrRequest), and nothing else did.
func toolsRefused(res CallResult) bool {
	sent := 0
	for _, a := range res.Attempts {
		if a.Skipped {
			continue
		}
		sent++
		if !errors.Is(a.Err, provider.ErrRequest) {
			return false
		}
	}
	return sent > 0
}

// writeDowngrade records an automatic drop of the token level in ai_downgrade and in the audit log (INV-4).
func (s *Service) writeDowngrade(ctx context.Context, tx *sql.Tx, actor string, d *Downgrade) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO ai_downgrade (id, ts, from_tier, to_tier, reason) VALUES (?, ?, ?, ?, ?)`,
		store.NewID("dg"), FormatTS(d.At), string(d.From), string(d.To), clipRunes(d.Reason, 300)); err != nil {
		return fmt.Errorf("ai: write downgrade: %w", err)
	}
	return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: actor, Action: "ai.downgrade", Target: string(d.From) + "->" + string(d.To), Detail: clipRunes(d.Reason, 300)})
}
