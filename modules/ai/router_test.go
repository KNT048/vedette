package ai

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/ai/provider"
)

const key = "sk-test-0123456789"

func internal(id string) Profile {
	return Profile{ID: id, Name: "Local " + id, Kind: "openai-compatible", BaseURL: "http://localhost:11434/v1", Model: "qwen3:8b", Location: LocationInternal, MonthlyBudget: 300_000}
}

func cloud(id string) Profile {
	return Profile{ID: id, Name: "Cloud " + id, Kind: "anthropic", BaseURL: "https://api.anthropic.com", Model: "m-1", APIKey: provider.NewSecret(key), Location: LocationCloud, MonthlyBudget: 60_000}
}

// fakes records which profiles were called and answers per profile.
type fakes struct {
	mu    sync.Mutex
	calls []string
	reply map[string]func(ctx context.Context) (provider.Response, error)
}

func (f *fakes) factory(p Profile) (provider.Provider, error) {
	return fakeProvider{f, p.ID}, nil
}

func (f *fakes) called(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == id {
			n++
		}
	}
	return n
}

type fakeProvider struct {
	f  *fakes
	id string
}

func (p fakeProvider) Complete(ctx context.Context, _ provider.Request) (provider.Response, error) {
	p.f.mu.Lock()
	p.f.calls = append(p.f.calls, p.id)
	fn := p.f.reply[p.id]
	p.f.mu.Unlock()
	if fn == nil {
		return provider.Response{Text: "from " + p.id, Usage: provider.Usage{InputTokens: 100, OutputTokens: 50}, Model: "actual"}, nil
	}
	return fn(ctx)
}

var req = provider.Request{Messages: []provider.Message{{Role: provider.RoleUser, Text: "hi"}}, MaxTokens: 100}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newMeter(t *testing.T, c *clock, tier Tier, capTokens int) *Meter {
	t.Helper()
	m, err := NewMeter(MeterConfig{Clock: c.now, Location: time.FixedZone("ICT", 7*3600), GlobalCap: capTokens, Tier: tier})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func startClock() *clock { return &clock{time.Date(2026, 11, 9, 5, 0, 0, 0, time.UTC)} }

func router(t *testing.T, f *fakes, internalOnly bool, slots map[Job]Slot, ps ...Profile) *Router {
	t.Helper()
	r, err := NewRouter(RouterConfig{Profiles: ps, Assignments: Assignments{InternalOnly: internalOnly, Jobs: slots}, Meter: newMeter(t, startClock(), TierMed, 1_000_000), Factory: f.factory, CallTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func failWith(err error) func(context.Context) (provider.Response, error) {
	return func(context.Context) (provider.Response, error) { return provider.Response{}, err }
}

func TestRoutingPrimaryAnswers(t *testing.T) {
	t.Parallel()
	f := &fakes{}
	r := router(t, f, false, map[Job]Slot{JobExplainFinding: {"c1", "i1"}}, cloud("c1"), internal("i1"))
	res, err := r.Call(context.Background(), JobExplainFinding, req)
	if err != nil || res.ProfileID != "c1" || res.Fallback || res.Profile != "Cloud c1" || res.Model != "m-1" || res.Response.Text != "from c1" {
		t.Fatalf("%+v %v", res, err)
	}
	if f.called("i1") != 0 {
		t.Fatal("fallback must not be called when the primary answers")
	}
}

// INV-2: error, timeout and the profile's own cap all move the job to the fallback and say so.
func TestContract_INV2_FallbackOnErrorTimeoutAndProfileCap(t *testing.T) {
	t.Parallel()
	slots := map[Job]Slot{JobAskMyData: {"c1", "i1"}}
	t.Run("provider error", func(t *testing.T) {
		t.Parallel()
		f := &fakes{reply: map[string]func(context.Context) (provider.Response, error){"c1": failWith(&provider.Error{Kind: provider.ErrRateLimited, Status: 429})}}
		res, err := router(t, f, false, slots, cloud("c1"), internal("i1")).Call(context.Background(), JobAskMyData, req)
		if err != nil || !res.Fallback || res.ProfileID != "i1" || len(res.Attempts) != 2 || !errors.Is(res.Attempts[0].Err, provider.ErrRateLimited) {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		f := &fakes{reply: map[string]func(context.Context) (provider.Response, error){"c1": func(ctx context.Context) (provider.Response, error) {
			<-ctx.Done()
			return provider.Response{}, &provider.Error{Kind: provider.ErrTimeout}
		}}}
		res, err := router(t, f, false, slots, cloud("c1"), internal("i1")).Call(context.Background(), JobAskMyData, req)
		if err != nil || !res.Fallback || res.ProfileID != "i1" {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("profile cap", func(t *testing.T) {
		t.Parallel()
		f := &fakes{}
		r := router(t, f, false, slots, cloud("c1"), internal("i1"))
		r.meter.Seed(map[string]int{"c1": 60_000})
		res, err := r.Call(context.Background(), JobAskMyData, req)
		if err != nil || !res.Fallback || res.ProfileID != "i1" || f.called("c1") != 0 || !res.Attempts[0].Skipped {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("all fail", func(t *testing.T) {
		t.Parallel()
		e := failWith(&provider.Error{Kind: provider.ErrServer, Status: 500})
		f := &fakes{reply: map[string]func(context.Context) (provider.Response, error){"c1": e, "i1": e}}
		res, err := router(t, f, false, slots, cloud("c1"), internal("i1")).Call(context.Background(), JobAskMyData, req)
		var ue *UnavailableError
		if !errors.Is(err, ErrUnavailable) || !errors.As(err, &ue) || len(ue.Reasons) != 2 || len(res.Attempts) != 2 {
			t.Fatalf("%+v %v", res, err)
		}
		if strings.Contains(err.Error(), key) {
			t.Fatal("error leaks the key")
		}
	})
	t.Run("caller cancel does not burn the fallback", func(t *testing.T) {
		t.Parallel()
		f := &fakes{reply: map[string]func(context.Context) (provider.Response, error){"c1": failWith(context.Canceled)}}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := router(t, f, false, slots, cloud("c1"), internal("i1")).Call(ctx, JobAskMyData, req)
		if !errors.Is(err, context.Canceled) || f.called("i1") != 0 {
			t.Fatalf("%v calls=%v", err, f.calls)
		}
	})
	t.Run("no assignment", func(t *testing.T) {
		t.Parallel()
		_, err := router(t, &fakes{}, false, nil, cloud("c1")).Call(context.Background(), JobAskMyData, req)
		if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "no profile is assigned") {
			t.Fatalf("%v", err)
		}
	})
	if _, err := router(t, &fakes{}, false, nil).Call(context.Background(), "nope", req); err == nil {
		t.Fatal("unknown job accepted")
	}
}

// INV-3: with internal_only on, jobs that carry internal data reach only internal profiles, at assignment
// time and at call time, including failover. A cloud profile is never used silently.
func TestContract_INV3_InternalOnlyNeverReachesCloud(t *testing.T) {
	t.Parallel()
	ps := map[string]Profile{"c1": cloud("c1"), "i1": internal("i1"), "i2": internal("i2")}
	list := []Profile{ps["c1"], ps["i1"], ps["i2"]}
	boom := failWith(&provider.Error{Kind: provider.ErrServer, Status: 503})

	// 1. Assignment validation refuses a cloud profile for every job that carries internal data, in either slot.
	for _, job := range Jobs() {
		for _, slot := range []Slot{{"c1", ""}, {"i1", "c1"}} {
			a := Assignments{InternalOnly: true, Jobs: map[Job]Slot{job: slot}}
			err := a.Validate(ps)
			var ae *AssignmentError
			if job.CarriesInternalData() {
				if !errors.As(err, &ae) || ae.Code != "privacy_rule" || !errors.Is(err, ErrInvalidAssignment) {
					t.Errorf("%s %v: want privacy_rule, got %v", job, slot, err)
				}
			} else if err != nil {
				t.Errorf("%s carries no internal data but was refused: %v", job, err)
			}
			if _, err := NewRouter(RouterConfig{Profiles: list, Assignments: a, Meter: newMeter(t, startClock(), TierMed, 5000)}); (err != nil) != job.CarriesInternalData() {
				t.Errorf("%s: router start must follow validation, got %v", job, err)
			}
		}
	}
	if (Assignments{InternalOnly: false, Jobs: map[Job]Slot{JobLogDigest: {"c1", "i1"}}}).Validate(ps) != nil {
		t.Error("rule off: cloud must be assignable")
	}

	// 2. Call time, even if an illegal state somehow exists (the Router is built by hand, skipping Validate).
	for _, job := range Jobs() {
		if !job.CarriesInternalData() {
			continue
		}
		f := &fakes{reply: map[string]func(context.Context) (provider.Response, error){"i1": boom}}
		r := rawRouter(f, Assignments{InternalOnly: true, Jobs: map[Job]Slot{job: {"i1", "c1"}}}, ps)
		_, err := r.Call(context.Background(), job, req)
		if !errors.Is(err, ErrUnavailable) || f.called("c1") != 0 {
			t.Errorf("%s: internal primary failed, cloud fallback must not be tried: err=%v calls=%v", job, err, f.calls)
		}
		if !strings.Contains(err.Error(), "privacy rule") {
			t.Errorf("%s: the reason must name the privacy rule: %v", job, err)
		}
		// Cloud primary, internal fallback under the rule: the cloud profile is skipped, never called.
		f = &fakes{}
		r.st.Load().assign.Jobs[job] = Slot{"c1", "i2"}
		res, err := r.Call(context.Background(), job, req)
		if err != nil || res.ProfileID != "i2" || f.called("c1") != 0 {
			t.Errorf("%s: %+v %v %v", job, res, err, f.calls)
		}
		// Only a cloud profile assigned: refuse, never fall silently to cloud.
		r.st.Load().assign.Jobs[job] = Slot{"c1", ""}
		f.calls = nil
		if _, err := r.Call(context.Background(), job, req); !errors.Is(err, ErrUnavailable) || len(f.calls) != 0 {
			t.Errorf("%s: want ErrUnavailable and no call, got %v %v", job, err, f.calls)
		}
	}

	// 3. Public-data jobs may use cloud under the rule; a failing internal primary may fail over to cloud there.
	f := &fakes{reply: map[string]func(context.Context) (provider.Response, error){"i1": boom}}
	r := router(t, f, true, map[Job]Slot{JobCVENews: {"i1", "c1"}}, list...)
	if res, err := r.Call(context.Background(), JobCVENews, req); err != nil || res.ProfileID != "c1" || !res.Fallback {
		t.Fatalf("cve-news with rule on: %+v %v", res, err)
	}

	// 4. Failover between internal profiles still works under the rule.
	f = &fakes{reply: map[string]func(context.Context) (provider.Response, error){"i1": boom}}
	r = router(t, f, true, map[Job]Slot{JobLogDigest: {"i1", "i2"}}, list...)
	if res, err := r.Call(context.Background(), JobLogDigest, req); err != nil || res.ProfileID != "i2" || !res.Fallback || f.called("c1") != 0 {
		t.Fatalf("internal failover: %+v %v", res, err)
	}
}

func TestContract_INV5_ResultCarriesModelProfileAndTokens(t *testing.T) {
	t.Parallel()
	res, err := router(t, &fakes{}, false, map[Job]Slot{JobLogDigest: {"i1", ""}}, internal("i1")).Call(context.Background(), JobLogDigest, req)
	if err != nil || res.Profile == "" || res.Model == "" || res.Response.Usage.InputTokens != 100 || res.Response.Usage.OutputTokens != 50 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestRouterUsesTheMeter(t *testing.T) {
	t.Parallel()
	c := startClock()
	m := newMeter(t, c, TierMax, 1000)
	f := &fakes{}
	r, err := NewRouter(RouterConfig{Profiles: []Profile{internal("i1")}, Assignments: Assignments{Jobs: map[Job]Slot{JobLogDigest: {"i1", ""}}}, Meter: m, Factory: f.factory})
	if err != nil {
		t.Fatal(err)
	}
	for range 40 { // each call is 150 tokens: the 7th takes the total past the budget of 1000 (D-531)
		res, err := r.Call(context.Background(), JobLogDigest, req)
		if errors.Is(err, ErrCapped) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if res.Downgrade != nil || m.Tier() != TierMax {
			t.Fatalf("the budget lowered the level: %+v %s", res.Downgrade, m.Tier())
		}
	}
	if _, err := r.Call(context.Background(), JobLogDigest, req); !errors.Is(err, ErrCapped) {
		t.Fatalf("after the budget: %v", err)
	}
	if f.called("i1") != 7 { // the 7th call takes the total past the budget; the 8th is refused at any level
		t.Fatalf("provider calls: %d", f.called("i1"))
	}
}

func TestNewRouterNeedsMeterAndValidAssignments(t *testing.T) {
	t.Parallel()
	if _, err := NewRouter(RouterConfig{}); err == nil {
		t.Fatal("no meter accepted")
	}
	m := newMeter(t, startClock(), TierMin, 5000)
	cases := map[string]struct {
		slots map[Job]Slot
		code  string
	}{
		"unknown profile":     {map[Job]Slot{JobLogDigest: {"zz", ""}}, "unknown_profile"},
		"fallback no primary": {map[Job]Slot{JobLogDigest: {"", "i1"}}, "fallback_without_primary"},
		"same profile":        {map[Job]Slot{JobLogDigest: {"i1", "i1"}}, "same_profile"},
		"unknown job":         {map[Job]Slot{"nope": {"i1", ""}}, "unknown_job"},
	}
	for name, c := range cases {
		_, err := NewRouter(RouterConfig{Profiles: []Profile{internal("i1")}, Assignments: Assignments{Jobs: c.slots}, Meter: m})
		var ae *AssignmentError
		if !errors.As(err, &ae) || ae.Code != c.code {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// rawRouter builds a Router without validation, to prove the call path holds even when a state the rules forbid exists.
func rawRouter(f *fakes, a Assignments, ps map[string]Profile) *Router {
	m, _ := NewMeter(MeterConfig{Clock: startClock().now, Location: time.UTC, GlobalCap: 5000, Tier: TierMed})
	r := &Router{meter: m, factory: f.factory, timeout: time.Second}
	r.st.Store(&routerState{profiles: ps, assign: a})
	return r
}

func TestAssignmentsRejectProfileWithoutKey(t *testing.T) {
	t.Parallel()
	nokey := cloud("nokey")
	nokey.APIKey = provider.Secret{}
	err := Assignments{Jobs: map[Job]Slot{JobLogDigest: {"nokey", ""}}}.Validate(map[string]Profile{"nokey": nokey})
	var ae *AssignmentError
	if !errors.As(err, &ae) || ae.Code != "profile_unusable" {
		t.Fatalf("%v", err)
	}
}
