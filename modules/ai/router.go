package ai

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kiennt048/vedette/modules/ai/provider"
)

// ErrUnavailable means no profile could answer the job. The error text lists a reason per profile; it is
// what the API shows as 409 `ai_unavailable`. The router never "helps" by trying a profile the privacy
// rule excludes (INV-3).
var ErrUnavailable = errors.New("ai: no AI profile is available for this job")

// ErrCapped means today's shared token cap is used up and the level is already the minimum.
var ErrCapped = errors.New("ai: the daily token cap is used up")

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
	Err                error // nil on success; a provider error (safe to show) or a skip reason
	Skipped            bool  // true when no request was sent (cap, privacy, build error, changed settings)
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
}

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
// A profile is skipped, and the next one tried, when it is not allowed (privacy rule), has used its own daily
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
		skip := func(why string) {
			reasons = append(reasons, p.Name+": "+why)
			res.Attempts = append(res.Attempts, Attempt{ProfileID: p.ID, Profile: p.Name, Err: errors.New(why), Skipped: true})
		}
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
		hold, err := r.meter.Reserve(p.ID, p.DailyCap, est)
		if errors.Is(err, ErrCapped) {
			return res, fmt.Errorf("%w: raise the cap in Settings, AI assistant, or wait until tomorrow", ErrCapped)
		}
		if err != nil {
			skip("daily cap reached")
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
			if ctx.Err() != nil { // the caller gave up or ran out of time: do not burn the fallback
				return res, ctx.Err()
			}
			reasons = append(reasons, p.Name+": "+err.Error())
			res.Attempts = append(res.Attempts, Attempt{ProfileID: p.ID, Profile: p.Name, Err: err})
			continue
		}
		res.Attempts = append(res.Attempts, Attempt{ProfileID: p.ID, Profile: p.Name})
		res.Response, res.ProfileID, res.Profile, res.Model, res.Fallback = resp, p.ID, p.Name, p.Model, c.fallback
		res.Downgrade = firstDowngrade(res.Downgrade, hold.Settle(resp.Usage.InputTokens, resp.Usage.OutputTokens))
		return res, nil
	}
	return res, &UnavailableError{Job: job, Reasons: reasons}
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

// Probe tests a profile with the tiny prompts of provider.Probe and meters them like any other call, so the
// connection test is part of the daily count (PRE-3). The prompts hold no customer data, so the privacy rule
// does not apply.
func (r *Router) Probe(ctx context.Context, p Profile, now func() time.Time) (provider.ProbeResult, error) {
	cl, err := r.factory(p)
	if err != nil {
		return provider.ProbeResult{}, err
	}
	return provider.Probe(ctx, meteredProvider{cl, r.meter, p.ID}, now)
}

// meteredProvider counts the usage of every call, failed ones with known usage included.
type meteredProvider struct {
	inner   provider.Provider
	meter   *Meter
	profile string
}

func (m meteredProvider) Complete(ctx context.Context, req provider.Request) (provider.Response, error) {
	resp, err := m.inner.Complete(ctx, req)
	var pe *provider.Error
	switch {
	case err == nil:
		m.meter.Record(m.profile, resp.Usage.InputTokens, resp.Usage.OutputTokens)
	case errors.As(err, &pe):
		m.meter.Record(m.profile, pe.Usage.InputTokens, pe.Usage.OutputTokens)
	}
	return resp, err
}
