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
	Schema         *provider.Schema
	MaxTokens      int
	Summary        string // what the activity row says on success; no secrets, no customer data
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
}

func apiUnavailable(msg string) error { return apierr.New(http.StatusConflict, "ai_unavailable", msg) }

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
	if _, err := tx.ExecContext(ctx, `INSERT INTO ai_activity (id, ts, job, profile, profile_id, model, trigger, hooks, tools, input_hash, output_hash, summary, tokens_in, tokens_out, result, links, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sealed.ID, sealed.TS, sealed.Job, sealed.Profile, nullable(e.ProfileID), sealed.Model, sealed.Trigger, string(hooks), string(tools), sealed.InputHash, sealed.OutputHash, sealed.Summary,
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
// them. Any block, hold or failed run stops the call (fail closed): nothing is sent.
func (s *Service) guard(ctx context.Context, hooks *HookRunner, spec JobSpec) (question string, data []DataBlock, names []string, stop string) {
	// The same deadline as the after_ai pass, for the whole pass: a hook that cannot finish is a block (fail closed).
	ctx, cancel := context.WithTimeout(ctx, s.hookTimeout())
	defer cancel()
	run := func(text string) (string, bool) {
		r, err := hooks.Run(ctx, BeforeAI, text)
		if errors.Is(err, ErrHookInputTooLarge) {
			stop = "The text is too long to check against the hooks, so it was not sent."
			return "", false
		}
		if err != nil {
			stop = "The text could not be checked against the hooks in time, so it was not sent."
			return "", false
		}
		names = append(names, r.Names()...)
		if r.Outcome == OutcomeBlocked || r.Outcome == OutcomeHeld {
			stop = r.Text
			return "", false
		}
		return r.Text, true
	}
	q, ok := run(spec.Question)
	if !ok {
		return "", nil, dedupe(names), stop
	}
	for _, d := range spec.Data {
		t, ok := run(d.Text)
		if !ok {
			return "", nil, dedupe(names), stop
		}
		d.Text = t
		data = append(data, d)
	}
	return q, data, dedupe(names), ""
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
	question, data, hookNames, stop := s.guard(ctx, hooks, spec)
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
		return JobResult{}, apiUnavailable("The AI was not asked: " + stop)
	}
	prompt, err := PromptBuilder{}.Build(PromptInput{Job: spec.Job, Task: spec.Task, Rules: har.rules, Question: question, Data: data})
	if err != nil {
		return JobResult{}, fmt.Errorf("ai: build prompt: %w", err)
	}
	entry.InputHash = HashContent(prompt.System + "\n" + prompt.User)
	req := provider.Request{System: prompt.System, Messages: []provider.Message{{Role: provider.RoleUser, Text: prompt.User}}, Schema: spec.Schema, MaxTokens: spec.MaxTokens}

	res, err := s.router.Call(ctx, spec.Job, req)
	if err != nil {
		s.touchSent(ctx, mem.ids, res)
		return JobResult{}, s.failed(ctx, spec, entry, res, err)
	}
	entry.Profile, entry.ProfileID, entry.Model, entry.TokensIn, entry.TokensOut = res.Profile, res.ProfileID, res.Model, res.Response.Usage.InputTokens, res.Response.Usage.OutputTokens
	entry.OutputHash = HashContent(res.Response.Text)
	entry.Result = ResultOK
	if res.Fallback {
		entry.Result = ResultFallbackUsed
	}

	// The answer is here and the tokens are spent: the checks and the row that follow run even if the caller has gone. The hooks get
	// their own deadline, so slow hooks cannot use up the time of the activity row (INV-17), which has a fresh one.
	hctx, hcancel := context.WithTimeout(context.WithoutCancel(ctx), s.hookTimeout())
	structured := spec.Schema != nil && spec.Check != nil && spec.Check(res.Response.Text) == nil // the format is checked first; a bad answer is refused below
	after, herr := afterHooks(hctx, hooks, structured, res.Response.Text)
	hcancel()
	entry.Hooks = dedupe(append(entry.Hooks, after.Names()...))
	wctx, wcancel := detached(ctx)
	defer wcancel()
	text := after.Text
	var bad error
	switch {
	case herr != nil:
		entry.Result, entry.Summary, bad = ResultBlockedByHook, "The answer was not used: it could not be checked against the hooks.", apiUnavailable("The AI answered, but the answer could not be checked, so it was not used.")
	case after.Outcome == OutcomeBlocked || after.Outcome == OutcomeHeld:
		entry.Result, entry.Summary, bad = ResultBlockedByHook, "The answer was not used: "+after.Text, apiUnavailable("The AI answered, but a rule stopped the answer: "+after.Text)
	case spec.Check != nil && spec.Check(text) != nil:
		entry.Result, entry.Summary, bad = ResultError, "The answer did not match the expected format and was discarded.", apiUnavailable("The AI answered, but not in the format Vedette needs, so the answer was discarded. Try again, or use a stronger model for this job.")
	}
	var id string
	storeFailed := false
	werr := s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		ctx := wctx
		if bad == nil {
			entry.Summary = spec.Summary + leftOutNote(mem.left) + knowledgeNote(*know)
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
			if err := spec.Store(ctx, tx, JobResult{Text: text, Model: res.Model, Profile: res.Profile, TokensIn: entry.TokensIn, TokensOut: entry.TokensOut, Fallback: res.Fallback, ActivityID: id}); err != nil {
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
		return JobResult{}, bad
	}
	return JobResult{Text: text, Model: res.Model, Profile: res.Profile, TokensIn: entry.TokensIn, TokensOut: entry.TokensOut, Fallback: res.Fallback, ActivityID: id}, nil
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

// failed records a call that got no answer and returns the error the person sees.
func (s *Service) failed(ctx context.Context, spec JobSpec, entry ActivityEntry, res CallResult, err error) error {
	if ctx.Err() != nil {
		// The caller gave up (a closed tab, a timeout). If the request had reached the provider the data has left the box and tokens
		// may be spent, so the call still gets its row; if it had not, nothing was sent and there is nothing to record.
		if len(res.Attempts) > 0 {
			// say which profile the request went to: the last attempt that sent a request is the one running when the caller left
			for i := len(res.Attempts) - 1; i >= 0; i-- {
				if last := res.Attempts[i]; !last.Skipped {
					entry.Profile, entry.ProfileID = last.Profile, last.ProfileID
					if st, ok := s.snap.Load().find(last.ProfileID); ok {
						entry.Model = st.Model
					}
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
	var ue *UnavailableError
	switch {
	case errors.Is(err, ErrCapped):
		entry.Summary = "Not sent: today's token cap is used up and the level is already the minimum."
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
		if res.Downgrade != nil {
			// the failed attempts still used tokens and may have lowered the level: keep both facts
			if rerr := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
				if _, err := s.appendActivity(ctx, tx, entry); err != nil {
					return err
				}
				return s.writeDowngrade(ctx, tx, spec.Actor, res.Downgrade)
			}); rerr != nil {
				return rerr
			}
		} else if rerr := s.record(ctx, entry); rerr != nil {
			return rerr
		}
		return s.unavailable(spec.Job, reasons)
	}
	return err
}

// writeDowngrade records an automatic drop of the token level in ai_downgrade and in the audit log (INV-4).
func (s *Service) writeDowngrade(ctx context.Context, tx *sql.Tx, actor string, d *Downgrade) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO ai_downgrade (id, ts, from_tier, to_tier, reason) VALUES (?, ?, ?, ?, ?)`,
		store.NewID("dg"), FormatTS(d.At), string(d.From), string(d.To), clipRunes(d.Reason, 300)); err != nil {
		return fmt.Errorf("ai: write downgrade: %w", err)
	}
	return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: actor, Action: "ai.downgrade", Target: string(d.From) + "->" + string(d.To), Detail: clipRunes(d.Reason, 300)})
}
