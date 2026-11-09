package ai

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	Skipped            bool  // true when no request was sent (cap, privacy, build error)
}

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

// RouterConfig wires the router. Build a new Router when profiles or assignments change; a Router is
// immutable apart from the shared Meter.
type RouterConfig struct {
	Profiles    []Profile
	Assignments Assignments
	Meter       *Meter
	// Factory builds the client of a profile; nil = Profile.Provider. Tests inject fakes here.
	Factory func(Profile) (provider.Provider, error)
	// CallTimeout bounds one attempt. Zero = 90 s. The caller's context can only shorten it.
	CallTimeout time.Duration
}

// Router resolves a job to its primary and fallback profile and calls them in order.
type Router struct {
	profiles map[string]Profile
	assign   Assignments
	meter    *Meter
	factory  func(Profile) (provider.Provider, error)
	timeout  time.Duration
}

// NewRouter checks the assignments against the profiles first, so a router never starts with a state the
// privacy rule forbids.
func NewRouter(c RouterConfig) (*Router, error) {
	if c.Meter == nil {
		return nil, errors.New("ai: router needs a meter")
	}
	r := &Router{profiles: map[string]Profile{}, assign: c.Assignments, meter: c.Meter, factory: c.Factory, timeout: c.CallTimeout}
	for _, p := range c.Profiles {
		r.profiles[p.ID] = p
	}
	if err := c.Assignments.Validate(r.profiles); err != nil {
		return nil, err
	}
	if r.factory == nil {
		r.factory = Profile.Provider
	}
	if r.timeout <= 0 {
		r.timeout = 90 * time.Second
	}
	return r, nil
}

type candidate struct {
	p        Profile
	fallback bool
}

// Candidates returns the profiles that may receive the job, primary first, and the reasons the others were
// left out. It applies the privacy rule (INV-3).
func (r *Router) Candidates(job Job) (cands []Profile, reasons []string) {
	cs, rs := r.candidates(job)
	for _, c := range cs {
		cands = append(cands, c.p)
	}
	return cands, rs
}

func (r *Router) candidates(job Job) (cs []candidate, reasons []string) {
	slot := r.assign.Jobs[job]
	for i, id := range []string{slot.Primary, slot.Fallback} {
		if id == "" {
			continue
		}
		p, ok := r.profiles[id]
		switch {
		case !ok:
			reasons = append(reasons, "profile no longer exists")
		case !p.Usable():
			reasons = append(reasons, p.Name+": no API key")
		case !r.assign.Allowed(job, p):
			reasons = append(reasons, p.Name+": runs in the cloud, but this job sends internal data and the privacy rule only allows internal profiles")
		default:
			cs = append(cs, candidate{p, i == 1})
		}
	}
	return cs, reasons
}

// Call sends req for job to the first profile that may and can answer.
//
// A profile is skipped, and the next one tried, when it is not allowed (privacy rule), has used its own daily
// cap, cannot be built, or fails (error, timeout, rate limit). The privacy rule is checked again right
// before each request, so even a changed or corrupted candidate list cannot reach a cloud profile with
// internal data. If nothing remains the error is ErrUnavailable with a reason per profile.
// A cancelled or expired caller context stops the loop and is returned as is.
func (r *Router) Call(ctx context.Context, job Job, req provider.Request) (CallResult, error) {
	var res CallResult
	if !job.Valid() {
		return res, fmt.Errorf("ai: unknown job %q", job)
	}
	cs, reasons := r.candidates(job)
	if len(cs) == 0 {
		if len(reasons) == 0 {
			reasons = []string{"no profile is assigned to this job"}
		}
		return res, &UnavailableError{Job: job, Reasons: reasons}
	}
	if r.meter.Exhausted() {
		return res, fmt.Errorf("%w: raise the cap in Settings, AI assistant, or wait until tomorrow", ErrCapped)
	}
	for _, c := range cs {
		p := c.p
		skip := func(why string) {
			reasons = append(reasons, p.Name+": "+why)
			res.Attempts = append(res.Attempts, Attempt{ProfileID: p.ID, Profile: p.Name, Err: errors.New(why), Skipped: true})
		}
		if !r.assign.Allowed(job, p) { // defence in depth for INV-3
			skip("not allowed by the privacy rule")
			continue
		}
		if r.meter.ProfileUsed(p.ID) >= p.DailyCap {
			skip("daily cap reached")
			continue
		}
		cl, err := r.factory(p)
		if err != nil {
			skip("cannot connect: profile settings are not valid")
			continue
		}
		actx, cancel := context.WithTimeout(ctx, r.timeout)
		resp, err := cl.Complete(actx, req)
		cancel()
		if err != nil {
			if ctx.Err() != nil { // the caller gave up or ran out of time: do not burn the fallback
				return res, ctx.Err()
			}
			reasons = append(reasons, p.Name+": "+err.Error())
			res.Attempts = append(res.Attempts, Attempt{ProfileID: p.ID, Profile: p.Name, Err: err})
			continue
		}
		res.Attempts = append(res.Attempts, Attempt{ProfileID: p.ID, Profile: p.Name})
		res.Response, res.ProfileID, res.Profile, res.Model, res.Fallback = resp, p.ID, p.Name, p.Model, c.fallback
		res.Downgrade = r.meter.Record(p.ID, resp.Usage.InputTokens, resp.Usage.OutputTokens)
		return res, nil
	}
	return res, &UnavailableError{Job: job, Reasons: reasons}
}
