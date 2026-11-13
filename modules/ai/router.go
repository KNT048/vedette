package ai

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/modules/ai/provider"
)

// ErrUnavailable means no profile could answer the job. The error text lists a reason per profile; it is
// what the API shows as 409 `ai_unavailable`. The router never "helps" by trying a profile the privacy
// rule excludes (INV-3).
var ErrUnavailable = errors.New("ai: no AI profile is available for this job")

// errProfileCapSkip is the reason of an attempt skipped because the profile has used its own monthly budget (Meter.Reserve said
// ErrProfileCapped); the run log reads such a call as capped (notSent).
var errProfileCapSkip = errors.New("monthly budget reached")

// errProfileHeldSkip is the reason of an attempt skipped because calls in flight hold the rest of the profile's own budget
// (ErrProfileHeld): not used up, busy for a moment.
var errProfileHeldSkip = errors.New("the rest of its monthly budget is held by AI calls in flight")

// ErrCapped means this month's shared token budget is used up (D-531).
var ErrCapped = errors.New("ai: this month's AI token budget is used up")

// UnavailableError carries why every candidate was rejected.
type UnavailableError struct {
	Job     Job
	Reasons []string
}

func (e *UnavailableError) Error() string {
	return fmt.Sprintf("ai: no AI profile could answer %s (%s)", e.Job.Name(), strings.Join(e.Reasons, "; "))
}
func (e *UnavailableError) Unwrap() error { return ErrUnavailable }

// Attempt is one profile tried for a call, for the activity log and the run record.
type Attempt struct {
	ProfileID, Profile string
	Model              string // the model of the profile when the attempt was made (an edit during the call does not change it)
	Err                error  // nil on success; a provider error (safe to show) or a skip reason
	Skipped            bool   // true when no request was sent (cap, privacy, build error, changed settings)
	// Retry marks the second request of an answer cut at the output limit (Router.retryCut): Err nil = it was answered; Skipped with
	// Err = the caps left no room for it; Err alone = the provider failed it.
	Retry bool
}

// Refused reports whether the attempt ended in a model refusal (provider.ErrRefused).
func (a Attempt) Refused() bool { return errors.Is(a.Err, provider.ErrRefused) }

// CallResult is what the router returns for one job call (INV-2, INV-5).
type CallResult struct {
	Response  provider.Response
	ProfileID string
	Profile   string // profile name
	Model     string // model of the profile
	Fallback  bool   // true when the fallback profile answered
	Downgrade *Downgrade
	Attempts  []Attempt // filled on failure too
	// Retried is set when the first answer was cut at the output limit and the call was sent once more with a higher limit
	// (retryLimit) and answered; Response is then the second answer, Usage the tokens of both.
	Retried bool
}

// MaxAnswerTokens is the ceiling of the output limit of one request, also after a retry: a request with a higher limit risks the
// call timeout of a non-streaming request (CallTimeout) on a slow model.
const MaxAnswerTokens = 16000

// retryLimit is the output limit of the second request of a call whose first answer was cut at the limit: twice the first, up to
// MaxAnswerTokens. It equals n when n is already at the ceiling (no retry then).
func retryLimit(n int) int { return max(n, min(2*n, MaxAnswerTokens)) }

// RouterConfig wires the router.
type RouterConfig struct {
	Profiles    []Profile
	Assignments Assignments
	Meter       *Meter
	// Factory builds the client of a profile; nil = Profile.Provider. Tests inject fakes here.
	Factory func(Profile) (provider.Provider, error)
	// CallTimeout bounds one attempt. Zero = 90 s. The caller's context can only shorten it.
	CallTimeout time.Duration
}

// routerState is one immutable generation of the settings. SetConfig swaps it atomically.
type routerState struct {
	profiles map[string]Profile
	assign   Assignments
}

// Router resolves a job to its primary and fallback profile and calls them in order.
type Router struct {
	st      atomic.Pointer[routerState]
	meter   *Meter
	factory func(Profile) (provider.Provider, error)
	timeout time.Duration
}

func newState(profiles []Profile, a Assignments) (*routerState, error) {
	st := &routerState{profiles: map[string]Profile{}, assign: a}
	for _, p := range profiles {
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("ai: profile %q: %w", p.Name, err)
		}
		st.profiles[p.ID] = p
	}
	if err := a.Validate(st.profiles); err != nil {
		return nil, err
	}
	return st, nil
}

// NewRouter checks every profile and the assignments first (an internal profile must really be internal, a
// cloud profile must not carry internal data under the privacy rule), so a router never starts with a state
// the rules forbid.
func NewRouter(c RouterConfig) (*Router, error) {
	if c.Meter == nil {
		return nil, errors.New("ai: router needs a meter")
	}
	st, err := newState(c.Profiles, c.Assignments)
	if err != nil {
		return nil, err
	}
	r := &Router{meter: c.Meter, factory: c.Factory, timeout: c.CallTimeout}
	r.st.Store(st)
	if r.factory == nil {
		r.factory = Profile.Provider
	}
	if r.timeout <= 0 {
		r.timeout = 90 * time.Second
	}
	return r, nil
}

// SetConfig replaces profiles and assignments after a change in Settings. It validates like NewRouter and, if it
// passes, takes effect at once, also for calls already running: each attempt re-checks the current settings, so
// turning the privacy rule on stops an in-flight fallback from reaching a cloud profile.
func (r *Router) SetConfig(profiles []Profile, a Assignments) error {
	st, err := newState(profiles, a)
	if err != nil {
		return err
	}
	r.st.Store(st)
	return nil
}

type candidate struct {
	p        Profile
	fallback bool
}

// Candidates returns the profiles that may receive the job, primary first, and the reasons the others were
// left out. It applies the privacy rule (INV-3) for the job's own data class.
func (r *Router) Candidates(job Job) (cands []Profile, reasons []string) {
	cs, rs := candidates(r.st.Load(), job, job.CarriesInternalData())
	for _, c := range cs {
		cands = append(cands, c.p)
	}
	return cands, rs
}

func candidates(st *routerState, job Job, carriesInternal bool) (cs []candidate, reasons []string) {
	slot := st.assign.Jobs[job]
	for i, id := range []string{slot.Primary, slot.Fallback} {
		if id == "" {
			continue
		}
		p, ok := st.profiles[id]
		switch {
		case !ok:
			reasons = append(reasons, "profile no longer exists")
		case !p.Usable():
			reasons = append(reasons, p.Name+": no API key")
		case !st.assign.AllowedFor(carriesInternal, p):
			reasons = append(reasons, p.Name+": runs in the cloud, but this request sends internal data and the privacy rule only allows internal profiles")
		default:
			cs = append(cs, candidate{p, i == 1})
		}
	}
	return cs, reasons
}

// carriesInternalData: a job that works on the customer's logs or devices carries internal data, and so does
// any request that offers tools or returns tool results, whatever the job says (tools read the box).
func carriesInternalData(job Job, req provider.Request) bool {
	if job.CarriesInternalData() || len(req.Tools) > 0 {
		return true
	}
	for _, m := range req.Messages {
		if len(m.ToolResults) > 0 || len(m.ToolCalls) > 0 {
			return true
		}
	}
	return false
}

// estimateTokens is the share reserved before a call: the whole request at 3 bytes per token plus the
// largest answer the call may produce.
func estimateTokens(req provider.Request) int {
	n := len(req.System)
	for _, m := range req.Messages {
		n += len(m.Text) + len(m.Raw)
		for _, c := range m.ToolCalls {
			n += len(c.Name) + len(c.Arguments)
		}
		for _, t := range m.ToolResults {
			n += len(t.Content)
		}
	}
	for _, t := range req.Tools {
		n += len(t.Name) + len(t.Description) + len(t.InputSchema)
	}
	return n/3 + 1 + req.MaxTokens
}

// Call sends req for job to the first profile that may and can answer.
//
// A profile is skipped, and the next one tried, when it is not allowed (privacy rule), has used its own monthly
// cap, cannot be built, or fails (error, timeout, rate limit, refusal). The privacy rule is checked against the
// current settings right before each request, so a settings change during the call (turning internal_only on)
// applies to the next attempt. If nothing remains the error is ErrUnavailable with a reason per profile.
// A cancelled or expired caller context stops the loop and is returned as is.
//
// Tokens are held (Meter.Reserve) before the request and settled after it, also when the call failed but
// the provider reported usage.
func (r *Router) Call(ctx context.Context, job Job, req provider.Request) (CallResult, error) {
	var res CallResult
	if !job.Valid() {
		return res, fmt.Errorf("ai: unknown job %q", job)
	}
	st := r.st.Load()
	carries := carriesInternalData(job, req)
	cs, reasons := candidates(st, job, carries)
	if len(cs) == 0 {
		if len(reasons) == 0 {
			reasons = []string{"no profile is assigned to this job"}
		}
		return res, &UnavailableError{Job: job, Reasons: reasons}
	}
	est := estimateTokens(req)
	for _, c := range cs {
		p := c.p
		skipErr := func(why error) {
			reasons = append(reasons, p.Name+": "+why.Error())
			res.Attempts = append(res.Attempts, Attempt{ProfileID: p.ID, Profile: p.Name, Model: p.Model, Err: why, Skipped: true})
		}
		skip := func(why string) { skipErr(errors.New(why)) }
		if cur := r.st.Load(); cur != st { // the settings changed while this call was running
			np, ok := current(cur, job, c, carries)
			if !ok {
				skip("the settings changed")
				continue
			}
			p = np
		}
		if !r.st.Load().assign.AllowedFor(carries, p) { // defence in depth for INV-3, on the settings in force now
			skip("not allowed by the privacy rule")
			continue
		}
		cl, err := r.factory(p)
		if err != nil {
			skip("cannot connect: profile settings are not valid")
			continue
		}
		hold, err := r.meter.Reserve(p.ID, p.MonthlyBudget, est)
		if errors.Is(err, ErrCapped) {
			return res, fmt.Errorf("%w: raise the monthly budget in Settings, AI assistant, or wait for next month", ErrCapped)
		}
		if errors.Is(err, ErrBudgetHeld) {
			return res, err
		}
		if errors.Is(err, ErrProfileHeld) {
			skipErr(errProfileHeldSkip)
			continue
		}
		if err != nil {
			skipErr(errProfileCapSkip)
			continue
		}
		actx, cancel := context.WithTimeout(ctx, r.timeout)
		resp, err := cl.Complete(actx, req)
		cancel()
		if err != nil {
			var pe *provider.Error
			if errors.As(err, &pe) {
				res.Downgrade = firstDowngrade(res.Downgrade, hold.Settle(pe.Usage.InputTokens, pe.Usage.OutputTokens))
			} else {
				hold.Cancel()
			}
			// The request was handed to the provider, so the attempt counts, also when the caller has gone: the caller records it.
			res.Attempts = append(res.Attempts, Attempt{ProfileID: p.ID, Profile: p.Name, Model: p.Model, Err: err})
			if ctx.Err() != nil { // the caller gave up or ran out of time: do not burn the fallback
				return res, ctx.Err()
			}
			reasons = append(reasons, p.Name+": "+err.Error())
			continue
		}
		res.Attempts = append(res.Attempts, Attempt{ProfileID: p.ID, Profile: p.Name, Model: p.Model})
		res.Response, res.ProfileID, res.Profile, res.Model, res.Fallback = resp, p.ID, p.Name, p.Model, c.fallback
		res.Downgrade = firstDowngrade(res.Downgrade, hold.Settle(resp.Usage.InputTokens, resp.Usage.OutputTokens))
		if resp.Stop == provider.StopMaxTokens {
			if err := r.retryCut(ctx, &res, cl, p, req, carries); err != nil {
				return res, err
			}
		}
		return res, nil
	}
	return res, &UnavailableError{Job: job, Reasons: reasons}
}

// retryCut sends a request whose answer was cut at the output limit once more to the same profile, with retryLimit (a model that
// thinks before it answers can spend the first limit on thinking). It is held against the caps and checked against the privacy rule
// like any request, and it gets twice the call timeout: it may write twice as much, and a slow or local model must not be cut by the
// clock instead (the caller's context still bounds it). The second answer replaces the first, whether or not it is cut too (RunJob
// refuses a cut answer); the tokens of both are counted and the retry is an Attempt. It returns why a retry could not be made or
// failed (ErrCapped, ErrProfileCapped, the provider's error), with res still holding the cut answer: the caller says that, not "cut
// off". Nothing is returned when the limit is already the ceiling, the caller has gone, or the privacy rule now refuses the profile:
// the cut answer stands.
func (r *Router) retryCut(ctx context.Context, res *CallResult, cl provider.Provider, p Profile, req provider.Request, carries bool) error {
	more := req
	more.MaxTokens = retryLimit(req.MaxTokens)
	if more.MaxTokens == req.MaxTokens || ctx.Err() != nil || !r.st.Load().assign.AllowedFor(carries, p) {
		return nil
	}
	attempt := Attempt{ProfileID: p.ID, Profile: p.Name, Model: p.Model, Retry: true}
	hold, err := r.meter.Reserve(p.ID, p.MonthlyBudget, estimateTokens(more))
	if err != nil {
		if errors.Is(err, ErrCapped) {
			err = fmt.Errorf("%w: raise the monthly budget in Settings, AI assistant, or wait for next month", ErrCapped)
		}
		attempt.Err, attempt.Skipped = err, true
		res.Attempts = append(res.Attempts, attempt)
		return err
	}
	actx, cancel := context.WithTimeout(ctx, 2*r.timeout)
	resp, err := cl.Complete(actx, more)
	cancel()
	first := res.Response.Usage
	if err != nil {
		var pe *provider.Error
		if errors.As(err, &pe) {
			res.Downgrade = firstDowngrade(res.Downgrade, hold.Settle(pe.Usage.InputTokens, pe.Usage.OutputTokens))
			res.Response.Usage = provider.Usage{InputTokens: first.InputTokens + pe.Usage.InputTokens, OutputTokens: first.OutputTokens + pe.Usage.OutputTokens}
		} else {
			hold.Cancel()
		}
		attempt.Err = err
		res.Attempts = append(res.Attempts, attempt)
		return err
	}
	res.Downgrade = firstDowngrade(res.Downgrade, hold.Settle(resp.Usage.InputTokens, resp.Usage.OutputTokens))
	resp.Usage = provider.Usage{InputTokens: first.InputTokens + resp.Usage.InputTokens, OutputTokens: first.OutputTokens + resp.Usage.OutputTokens}
	res.Response, res.Retried = resp, true
	res.Attempts = append(res.Attempts, attempt)
	return nil
}

// firstDowngrade keeps the earliest record when several attempts of one call each lowered the level.
func firstDowngrade(a, b *Downgrade) *Downgrade {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	a.To = b.To
	return a
}

// current looks the candidate up again in newer settings: it must still be assigned to the job and, with the
// fresh profile data (location, key), still be allowed.
func current(st *routerState, job Job, c candidate, carries bool) (Profile, bool) {
	p, ok := st.profiles[c.p.ID]
	if !ok {
		return Profile{}, false
	}
	slot := st.assign.Jobs[job]
	if (c.fallback && slot.Fallback != p.ID) || (!c.fallback && slot.Primary != p.ID) {
		return Profile{}, false
	}
	return p, st.assign.AllowedFor(carries, p)
}

// probeEstimate is the share held against the caps for one connection test: three tiny requests.
const probeEstimate = 200

// Probe tests a profile with the tiny prompts of provider.Probe. Like every call it is checked against the caps before any
// request is sent (ErrCapped, ErrProfileCapped) and counted after (INV-4, PRE-3): the tokens of all three requests, also of those
// that failed with known usage, are settled together, and the result reports that sum also when the test failed (what the provider
// bills for the test, not the first request only; the caller writes it to the activity log, which the meter is seeded from). It returns the downgrade if the test lowered the level, so the caller can record it. The prompts hold no
// customer data, so the privacy rule does not apply. p.MonthlyBudget is the cap checked for the profile.
func (r *Router) Probe(ctx context.Context, p Profile, now func() time.Time) (provider.ProbeResult, *Downgrade, error) {
	cl, err := r.factory(p)
	if err != nil {
		return provider.ProbeResult{}, nil, err
	}
	hold, err := r.meter.Reserve(p.ID, p.MonthlyBudget, probeEstimate)
	if err != nil {
		return provider.ProbeResult{}, nil, err
	}
	cp := &countingProvider{inner: cl}
	res, perr := provider.Probe(ctx, cp, now)
	res.TokensIn, res.TokensOut = cp.in, cp.out
	return res, hold.Settle(cp.in, cp.out), perr
}

// countingProvider adds up the usage of the calls made through it, failed ones with known usage included.
type countingProvider struct {
	inner   provider.Provider
	in, out int
}

func (c *countingProvider) Complete(ctx context.Context, req provider.Request) (provider.Response, error) {
	resp, err := c.inner.Complete(ctx, req)
	var pe *provider.Error
	switch {
	case err == nil:
		c.in, c.out = c.in+resp.Usage.InputTokens, c.out+resp.Usage.OutputTokens
	case errors.As(err, &pe):
		c.in, c.out = c.in+pe.Usage.InputTokens, c.out+pe.Usage.OutputTokens
	}
	return resp, err
}
