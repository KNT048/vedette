package ai

// Regression tests for the independent security review of feat/ai-lib: findings F1, F3, F4, F13 and items
// 1 (router part), 2, 5, 6, 14, 19.

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/ai/provider"
)

// F1 / item 2: "internal" is not just a label. A literal public IP is refused when the profile is saved, http is
// only for internal profiles, and the provider of an internal profile cannot dial a public address.
func TestContract_INV3_InternalLabelIsEnforced(t *testing.T) {
	t.Parallel()
	mk := func(base string, loc Location) Profile {
		return Profile{ID: "x", Name: "Looks local", Kind: "openai-compatible", BaseURL: base, Model: "gpt-5", APIKey: provider.NewSecret("sk-live-0123456789"), Location: loc, DailyCap: 10_000}
	}
	for base, ok := range map[string]bool{
		"http://203.0.113.10:8000/v1": false, "https://8.8.8.8/v1": false, "http://[2001:db8::1]/v1": false, "http://100.128.0.1/v1": false,
		"http://10.0.0.5:11434/v1": true, "http://172.16.1.1/v1": true, "http://192.168.1.20/v1": true, "http://100.64.0.9/v1": true,
		"http://127.0.0.1:8000/v1": true, "http://[::1]:8000/v1": true, "http://[fd00::5]/v1": true, "http://169.254.1.1/v1": false, "http://[fe80::1]/v1": false, "http://169.254.169.254/v1": false, "http://[fd00:ec2::254]/v1": false, "http://224.0.0.1/v1": false, "http://0.0.0.0/v1": false,
		// A name is allowed (an Ollama box on a LAN name is normal): the dialer checks where it resolves.
		"http://ollama.lan:11434/v1": true, "http://ollama/v1": true, "https://llm.corp.example.com/v1": true,
	} {
		err := mk(base, LocationInternal).Validate()
		if (err == nil) != ok {
			t.Errorf("internal %s: accepted=%v, want %v (%v)", base, err == nil, ok, err)
		}
	}
	// The same public IP is fine for a cloud profile (a gateway), but not over http.
	if err := mk("https://203.0.113.10/v1", LocationCloud).Validate(); err != nil {
		t.Errorf("cloud https IP: %v", err)
	}
	if err := mk("http://203.0.113.10/v1", LocationCloud).Validate(); err == nil {
		t.Error("http for a cloud profile accepted")
	}
	// An internal profile, even built without Validate, cannot reach a public address (no packet is sent).
	p := mk("http://203.0.113.10:9/v1", LocationInternal)
	cl, err := p.Provider()
	if err != nil {
		t.Fatal(err)
	}
	_, err = cl.Complete(context.Background(), req)
	if !errors.Is(err, provider.ErrNetwork) || !strings.Contains(err.Error(), "internal") {
		t.Fatalf("public destination for an internal profile: %v", err)
	}
	// NewRouter re-validates every profile: a mislabelled or native-kind internal profile never starts a router.
	m := newMeter(t, startClock(), TierMed, 5000)
	for name, bad := range map[string]Profile{
		"public IP labelled internal": mk("http://203.0.113.10:8000/v1", LocationInternal),
		"native kind internal":        {ID: "x", Name: "n", Kind: "anthropic", BaseURL: "https://api.anthropic.com", Model: "m", Location: LocationInternal, DailyCap: 5000},
		"cloud over http":             mk("http://api.example.com/v1", LocationCloud),
	} {
		if _, err := NewRouter(RouterConfig{Profiles: []Profile{bad}, Meter: m}); err == nil {
			t.Errorf("%s: router started", name)
		}
		r := router(t, &fakes{}, false, nil)
		if err := r.SetConfig([]Profile{bad}, Assignments{}); err == nil {
			t.Errorf("%s: SetConfig accepted", name)
		}
	}
}

// The anthropic-version header comes from the profile (item 14).
func TestProfileAnthropicVersion(t *testing.T) {
	t.Parallel()
	if err := (Profile{ID: "x", Name: "n", Kind: "custom", APIStyle: provider.StyleAnthropic, BaseURL: "http://10.0.0.5", Model: "m", Location: LocationInternal, DailyCap: 5000, AnthropicVersion: "last year"}).Validate(); err == nil {
		t.Fatal("bad version accepted")
	}
	for _, v := range []string{"", "2025-01-01"} {
		p := Profile{ID: "x", Name: "n", Kind: "custom", APIStyle: provider.StyleAnthropic, BaseURL: "http://10.0.0.5", Model: "m", Location: LocationInternal, DailyCap: 5000, AnthropicVersion: v}
		if err := p.Validate(); err != nil {
			t.Errorf("version %q: %v", v, err)
		}
		if _, err := p.Provider(); err != nil {
			t.Errorf("version %q: %v", v, err)
		}
	}
}

// F3 / item 5: counts that overflow cannot make the counter negative, so one answer cannot reset the cap.
func TestContract_INV4_MeterSaturates(t *testing.T) {
	t.Parallel()
	c := startClock()
	m := newMeter(t, c, TierMin, 1000)
	m.Record("p", 5000, 0)
	if !m.Exhausted() {
		t.Fatal("precondition")
	}
	m.Record("p", math.MaxInt-100, 0)
	m.Record("p", math.MaxInt, math.MaxInt)
	m.Record("p", -50, -50)
	if m.Used() < 0 || m.ProfileUsed("p") < 0 || !m.Exhausted() {
		t.Fatalf("used=%d exhausted=%v", m.Used(), m.Exhausted())
	}
	m.Seed(map[string]int{"a": math.MaxInt, "b": math.MaxInt})
	if m.Used() != math.MaxInt || !m.Exhausted() {
		t.Fatalf("seed overflow: %d", m.Used())
	}
}

// F4 / item 5: a clock that steps back never starts a new day.
func TestContract_INV4_ClockBackwardsKeepsUsage(t *testing.T) {
	t.Parallel()
	c := &clock{time.Date(2026, 11, 9, 0, 0, 30, 0, time.UTC)}
	m, _ := NewMeter(MeterConfig{Clock: c.now, Location: time.UTC, GlobalCap: 1000, Tier: TierMin})
	m.Record("p", 5000, 0)
	c.t = c.t.Add(-time.Minute) // 23:59:30 the day before
	if m.Used() != 5000 {
		t.Fatalf("usage after a step back: %d", m.Used())
	}
	c.t = c.t.Add(2 * time.Minute) // 00:01:30 again
	if m.Used() != 5000 || !m.Exhausted() {
		t.Fatalf("usage after the clock came forward again: used=%d exhausted=%v", m.Used(), m.Exhausted())
	}
	c.t = time.Date(2026, 11, 10, 0, 0, 1, 0, time.UTC) // a real new day still resets
	if m.Used() != 0 || m.Exhausted() {
		t.Fatalf("new day: %d", m.Used())
	}
}

// F13 / item 5: after a restart the level follows the usage, never upward; Seed and live recording agree.
func TestContract_INV4_RestartKeepsTheDowngrade(t *testing.T) {
	t.Parallel()
	c := startClock()
	live := newMeter(t, c, TierMax, 1000)
	for _, n := range []int{400, 700, 800, 900, 2000, 300} {
		before := live.Tier()
		live.Record("p", n, 0)
		restarted := newMeter(t, c, TierMax, 1000)
		restarted.Seed(map[string]int{"p": live.Used()})
		if restarted.Tier() != live.Tier() || restarted.Exhausted() != live.Exhausted() {
			t.Fatalf("after %d tokens: live %s/%v, restarted %s/%v", live.Used(), live.Tier(), live.Exhausted(), restarted.Tier(), restarted.Exhausted())
		}
		if rank(live.Tier()) > rank(before) {
			t.Fatalf("level rose from %s to %s", before, live.Tier())
		}
	}
	if live.Tier() != TierMin || !live.Exhausted() {
		t.Fatalf("%s %v", live.Tier(), live.Exhausted())
	}
	// One call far over the cap lowers several levels at once, in one record.
	m := newMeter(t, c, TierMax, 1000)
	if d := m.Record("p", 2500, 0); d == nil || d.From != TierMax || d.To != TierMin {
		t.Fatalf("far over the cap: %+v", d)
	}
	// An admin raising the cap lifts the level again (it is a deliberate action, not a restart).
	if err := m.SetConfig(TierMax, 5000); err != nil || m.Tier() != TierMax {
		t.Fatalf("%v %s", err, m.Tier())
	}
}

func rank(t Tier) int { return map[Tier]int{TierMin: 0, TierMed: 1, TierMax: 2}[t] }

// Item 5: the caps are checked and held under one lock, so concurrent calls cannot all pass.
func TestContract_INV4_ReservationStopsConcurrentOvershoot(t *testing.T) {
	t.Parallel()
	c := startClock()
	m := newMeter(t, c, TierMin, 1000)
	var passed, capped int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.Reserve("p", 1_000_000, 600)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				passed++
			} else if errors.Is(err, ErrCapped) {
				capped++
			}
		}()
	}
	wg.Wait()
	if passed != 2 || capped != 62 { // the first two holds (1200) cover the cap of 1000; the rest are refused
		t.Fatalf("passed=%d capped=%d", passed, capped)
	}

	// Per-profile cap, same idea; a different profile is not affected.
	m = newMeter(t, c, TierMax, 1_000_000)
	var ok int
	for range 10 {
		if _, err := m.Reserve("p", 1000, 600); err == nil {
			ok++
		} else if !errors.Is(err, ErrProfileCapped) {
			t.Fatal(err)
		}
	}
	if ok != 2 {
		t.Fatalf("profile cap let %d through", ok)
	}
	if _, err := m.Reserve("q", 1000, 600); err != nil {
		t.Fatalf("other profile: %v", err)
	}

	// Settling replaces the estimate with the real usage; cancelling counts nothing; both are idempotent.
	m = newMeter(t, c, TierMax, 1_000_000)
	h1, _ := m.Reserve("p", 10_000, 700)
	h2, _ := m.Reserve("p", 10_000, 700)
	h1.Settle(100, 20)
	h1.Settle(5000, 5000)
	h2.Cancel()
	h2.Settle(5000, 5000)
	if m.Used() != 120 || m.ProfileUsed("p") != 120 {
		t.Fatalf("used=%d", m.Used())
	}
	if _, err := m.Reserve("p", 10_000, 9_000); err != nil { // nothing left held
		t.Fatalf("holds were not released: %v", err)
	}
}

// Item 5: a failed call whose usage is known (a refusal) is counted; one with no usage is not; the profile test is counted.
func TestFailedCallsAndProbeAreMetered(t *testing.T) {
	t.Parallel()
	refuse := &provider.Error{Kind: provider.ErrRefused, Category: "cyber", Usage: provider.Usage{InputTokens: 100, OutputTokens: 50}}
	f := &fakes{reply: map[string]func(context.Context) (provider.Response, error){"c1": failWith(refuse)}}
	r := router(t, f, false, map[Job]Slot{JobAskMyData: {"c1", "i1"}}, cloud("c1"), internal("i1"))
	res, err := r.Call(context.Background(), JobAskMyData, req)
	if err != nil || !res.Fallback || res.ProfileID != "i1" || !res.Attempts[0].Refused() || res.Attempts[1].Refused() {
		t.Fatalf("%+v %v", res, err)
	}
	if got := r.meter.ProfileUsed("c1"); got != 150 {
		t.Fatalf("refused call usage: %d", got)
	}
	if got := r.meter.ProfileUsed("i1"); got != 150 {
		t.Fatalf("answered call usage: %d", got)
	}
	f.reply["c1"] = failWith(&provider.Error{Kind: provider.ErrServer, Status: 500})
	if _, err := r.Call(context.Background(), JobAskMyData, req); err != nil {
		t.Fatal(err)
	}
	if got := r.meter.ProfileUsed("c1"); got != 150 {
		t.Fatalf("a failure with no usage was counted: %d", got)
	}

	// The connection test goes through the meter.
	before := r.meter.Used()
	pr, _, err := r.Probe(context.Background(), internal("i1"), time.Now)
	// three requests of 100 in and 50 out: the result reports all three, the same tokens the meter counts (walk 3)
	if err != nil || !pr.Tools || pr.TokensIn != 300 || pr.TokensOut != 150 {
		t.Fatalf("%+v %v", pr, err)
	}
	if got := r.meter.Used() - before; got != pr.TokensIn+pr.TokensOut {
		t.Fatalf("probe metered %d, reported %d", got, pr.TokensIn+pr.TokensOut)
	}
}

// Item 1 (router part): a request that carries tools or tool results holds the customer's data whatever the job says.
func TestContract_INV3_ToolsMeanInternalData(t *testing.T) {
	t.Parallel()
	slots := map[Job]Slot{JobCVENews: {"c1", ""}}
	ps := []Profile{cloud("c1"), internal("i1")}
	// Without tools cve-news may use the cloud profile under the rule.
	f := &fakes{}
	if res, err := router(t, f, true, slots, ps...).Call(context.Background(), JobCVENews, req); err != nil || res.ProfileID != "c1" {
		t.Fatalf("%+v %v", res, err)
	}
	withTools := req
	withTools.Tools = []provider.ToolDef{{Name: "query_logs"}}
	withResults := provider.Request{MaxTokens: 100, Messages: []provider.Message{{Role: provider.RoleUser, Text: "q"}, {Role: provider.RoleTool, ToolResults: []provider.ToolResult{{CallID: "1", Content: "log lines"}}}}}
	for name, rq := range map[string]provider.Request{"tools": withTools, "tool results": withResults} {
		f = &fakes{}
		_, err := router(t, f, true, slots, ps...).Call(context.Background(), JobCVENews, rq)
		if !errors.Is(err, ErrUnavailable) || f.called("c1") != 0 {
			t.Errorf("%s: cloud profile reached with tool data: err=%v calls=%v", name, err, f.calls)
		}
		// With an internal fallback the call goes there.
		f = &fakes{}
		res, err := router(t, f, true, map[Job]Slot{JobCVENews: {"c1", "i1"}}, ps...).Call(context.Background(), JobCVENews, rq)
		if err != nil || res.ProfileID != "i1" || f.called("c1") != 0 {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
	// With the rule off nothing changes.
	if _, err := router(t, &fakes{}, false, slots, ps...).Call(context.Background(), JobCVENews, withTools); err != nil {
		t.Fatal(err)
	}
}

// Item 19: turning internal_only on while a call is in flight stops its fallback from reaching a cloud profile.
func TestContract_INV3_SettingsChangeReachesRunningCalls(t *testing.T) {
	t.Parallel()
	slots := map[Job]Slot{JobLogDigest: {"i1", "c1"}}
	ps := []Profile{internal("i1"), cloud("c1")}
	f := &fakes{}
	r := router(t, f, false, slots, ps...)
	f.reply = map[string]func(context.Context) (provider.Response, error){"i1": func(context.Context) (provider.Response, error) {
		// While the primary is answering (and failing), the administrator turns the privacy rule on.
		if err := r.SetConfig(ps, Assignments{InternalOnly: true, Jobs: map[Job]Slot{JobLogDigest: {"i1", ""}}}); err != nil {
			t.Error(err)
		}
		return provider.Response{}, &provider.Error{Kind: provider.ErrServer, Status: 503}
	}}
	_, err := r.Call(context.Background(), JobLogDigest, req)
	if !errors.Is(err, ErrUnavailable) || f.called("c1") != 0 {
		t.Fatalf("the cloud fallback was used after the rule was turned on: err=%v calls=%v", err, f.calls)
	}
	// A settings change that only moves the fallback to another internal profile is honoured too.
	ps2 := []Profile{internal("i1"), internal("i2"), cloud("c1")}
	f = &fakes{}
	r = router(t, f, false, map[Job]Slot{JobLogDigest: {"i1", "c1"}}, ps2...)
	f.reply = map[string]func(context.Context) (provider.Response, error){"i1": func(context.Context) (provider.Response, error) {
		_ = r.SetConfig(ps2, Assignments{InternalOnly: true, Jobs: map[Job]Slot{JobLogDigest: {"i1", "i2"}}})
		return provider.Response{}, &provider.Error{Kind: provider.ErrServer, Status: 503}
	}}
	res, err := r.Call(context.Background(), JobLogDigest, req)
	if err == nil && res.ProfileID == "c1" {
		t.Fatal("cloud used")
	}
	if f.called("c1") != 0 {
		t.Fatalf("calls %v", f.calls)
	}
	// SetConfig that breaks the rules is refused and leaves the old settings in force.
	if err := r.SetConfig(ps2, Assignments{InternalOnly: true, Jobs: map[Job]Slot{JobLogDigest: {"c1", ""}}}); err == nil {
		t.Fatal("illegal settings accepted")
	}
}
