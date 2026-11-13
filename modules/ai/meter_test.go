package ai

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/ai/provider"
)

func TestContract_INV4_TokenMeterMonthlyBudget(t *testing.T) {
	t.Parallel()
	// Budget range for the shared budget and for a profile (1,000..150,000,000 tokens a month, D-531).
	for n, ok := range map[int]bool{0: false, 999: false, 1000: true, 6_000_000: true, 150_000_000: true, 150_000_001: false, -5: false} {
		if ValidMonthlyBudget(n) != ok {
			t.Errorf("ValidMonthlyBudget(%d) != %v", n, ok)
		}
	}
	c := startClock()
	if _, err := NewMeter(MeterConfig{Clock: c.now, Location: time.UTC, GlobalCap: 999, Tier: TierMed}); err == nil {
		t.Error("budget below 1000 accepted")
	}
	if _, err := NewMeter(MeterConfig{Clock: c.now, Location: time.UTC, GlobalCap: 5000, Tier: "huge"}); err == nil {
		t.Error("unknown level accepted")
	}
	if _, err := NewMeter(MeterConfig{GlobalCap: 5000, Tier: TierMin}); err == nil {
		t.Error("missing clock accepted")
	}

	m := newMeter(t, c, TierMax, 1000)
	m.Record("a", 400, 100)
	if m.Tier() != TierMax || m.Used() != 500 || m.Exhausted() {
		t.Fatalf("under the budget: %v %d", m.Tier(), m.Used())
	}
	if _, err := m.Reserve("a", 5000, 500); err != nil { // 500 used, nothing held: allowed
		t.Fatalf("under the budget: %v", err)
	}
	if _, err := m.Reserve("b", 5000, 10); !errors.Is(err, ErrBudgetHeld) { // 500 used + 500 held = the budget: calls in flight count
		t.Fatalf("holds count against the budget, as held, not used up: %v", err)
	}
	if m.UsedUp() {
		t.Fatal("holds alone made the budget used up")
	}
	m2 := newMeter(t, c, TierMax, 1000)
	m2.Record("a", 1000, 0)
	if m2.Tier() != TierMax {
		t.Fatalf("at the budget the level stays: %v", m2.Tier())
	}
	if !m2.Exhausted() || !m2.UsedUp() {
		t.Fatal("at 100 % of the budget no call may go, at any level")
	}
	if _, err := m2.Reserve("a", 5000, 1); !errors.Is(err, ErrCapped) {
		t.Fatalf("reserve at the budget: %v", err)
	}
	m2.Record("b", 2500, 0)
	if m2.Tier() != TierMax {
		t.Fatalf("far over the budget the level still stays (D-531): %v", m2.Tier())
	}
	if m2.ProfileUsed("a") != 1000 || m2.ProfileUsed("b") != 2500 || m2.ProfileUsed("none") != 0 {
		t.Fatalf("per profile: a=%d b=%d", m2.ProfileUsed("a"), m2.ProfileUsed("b"))
	}
	// a profile's own budget refuses that profile only
	m3 := newMeter(t, c, TierMed, 100_000)
	m3.Record("p", 2000, 0)
	if _, err := m3.Reserve("p", 2000, 1); !errors.Is(err, ErrProfileCapped) {
		t.Fatalf("profile budget: %v", err)
	}
	if _, err := m3.Reserve("q", 2000, 1); err != nil {
		t.Fatalf("another profile: %v", err)
	}
	// Negative token counts from a broken provider cannot lower the total.
	m4 := newMeter(t, c, TierMed, 5000)
	m4.Record("x", -50, -50)
	if m4.Used() != 0 {
		t.Fatalf("negative counted: %d", m4.Used())
	}
	if n, ok := TierMin.EstimatePerDay(); !ok || n != 10_000 {
		t.Error("min estimate")
	}
	if n, ok := TierMed.EstimatePerDay(); !ok || n != 60_000 {
		t.Error("med estimate")
	}
	if _, ok := TierMax.EstimatePerDay(); ok {
		t.Error("max has no estimate")
	}
}

// Review of #688: "used up" is said of tokens spent only. Holds of calls in flight refuse with ErrBudgetHeld / ErrProfileHeld while
// the spent tokens are below the budget; a hold taken in one month and settled in the next does not lower the new month's holds.
func TestMeterHoldsAreNotUsedUp(t *testing.T) {
	t.Parallel()
	c := startClock()
	m := newMeter(t, c, TierMed, 100_000)
	m.Record("a", 90_000, 0)
	if !m.Reached(80) || m.Reached(91) || m.UsedUp() {
		t.Fatalf("90 %% spent: reached80=%v reached91=%v usedUp=%v", m.Reached(80), m.Reached(91), m.UsedUp())
	}
	ask, err := m.Reserve("a", 1_000_000, 12_000) // an Ask in flight holds the last 10 %
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Reserve("b", 1_000_000, 10); !errors.Is(err, ErrBudgetHeld) {
		t.Fatalf("held, not used up: %v", err)
	}
	ask.Settle(1000, 500)
	if _, err := m.Reserve("b", 1_000_000, 10); err != nil {
		t.Fatalf("after the Ask settled the next call may go: %v", err)
	}
	// a profile's own budget, the same way
	p := newMeter(t, c, TierMed, 1_000_000)
	p.Record("p", 500, 0)
	h, _ := p.Reserve("p", 1000, 600)
	if _, err := p.Reserve("p", 1000, 10); !errors.Is(err, ErrProfileHeld) {
		t.Fatalf("profile held: %v", err)
	}
	h.Cancel()
	p.Record("p", 600, 0)
	if _, err := p.Reserve("p", 1000, 10); !errors.Is(err, ErrProfileCapped) {
		t.Fatalf("profile used up: %v", err)
	}

	// month rollover: a hold from last month settled now counts its tokens but leaves this month's holds alone
	r := newMeter(t, c, TierMed, 100_000)
	old, _ := r.Reserve("a", 1_000_000, 5000)
	c.t = c.t.Add(32 * 24 * time.Hour)
	cur, _ := r.Reserve("a", 1_000_000, 99_950)
	old.Settle(100, 0)
	if _, err := r.Reserve("b", 1_000_000, 10); !errors.Is(err, ErrBudgetHeld) {
		t.Fatalf("the old hold lowered this month's holds: %v", err)
	}
	cur.Cancel()
	if r.Used() != 100 {
		t.Fatalf("used = %d", r.Used())
	}
}

// The month is the box's local month, not UTC: 16:59 UTC on 30 November is 23:59 in Ho Chi Minh City, 17:01 UTC is 1 December. A
// day boundary inside a month resets nothing (no daily cap, D-531).
func TestMeterMonthBoundaryInBoxTimeZone(t *testing.T) {
	t.Parallel()
	c := &clock{time.Date(2026, 11, 9, 16, 59, 0, 0, time.UTC)}
	m := newMeter(t, c, TierMax, 1000)
	m.Record("a", 900, 0)
	c.t = time.Date(2026, 11, 9, 17, 1, 0, 0, time.UTC) // 00:01 local on 10 Nov: a new day, the same month
	if m.Used() != 900 || m.ProfileUsed("a") != 900 {
		t.Fatalf("a new day must not reset the month: used=%d", m.Used())
	}
	m.Record("a", 200, 0)
	if !m.Exhausted() {
		t.Fatal("over the budget within the month")
	}
	if got := m.Renews(); !got.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, m.loc)) {
		t.Fatalf("renews = %v", got)
	}
	c.t = time.Date(2026, 11, 30, 16, 59, 0, 0, time.UTC) // 23:59 local on 30 Nov
	if !m.Exhausted() {
		t.Fatal("still November locally")
	}
	c.t = time.Date(2026, 11, 30, 17, 1, 0, 0, time.UTC) // 00:01 local on 1 Dec
	if m.Used() != 0 || m.ProfileUsed("a") != 0 || m.Exhausted() {
		t.Fatalf("counters must reset at local midnight of the 1st: used=%d", m.Used())
	}
	// The same instant in UTC would still be November: prove the zone matters.
	utc, _ := NewMeter(MeterConfig{Clock: c.now, Location: time.UTC, GlobalCap: 1000, Tier: TierMax})
	utc.Record("a", 10, 0)
	c.t = c.t.Add(10 * time.Minute)
	if utc.Used() != 10 {
		t.Fatalf("UTC meter must keep counting at 17:11 UTC, got %d", utc.Used())
	}
	// A clock that steps back does not start a new month.
	c.t = time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	if m.Used() != 0 {
		t.Fatalf("a clock that went back reset nothing new: %d", m.Used())
	}
}

func TestMeterSeedAndSetConfig(t *testing.T) {
	t.Parallel()
	c := startClock()
	m := newMeter(t, c, TierMed, 1000)
	m.Seed(map[string]int{"a": 700, "b": 400, "neg": -5})
	if m.Used() != 1100 || m.ProfileUsed("a") != 700 || m.ProfileUsed("neg") != 0 {
		t.Fatalf("seed: %d", m.Used())
	}
	if err := m.SetConfig(TierMax, 10); err == nil {
		t.Fatal("bad cap accepted")
	}
	if err := m.SetConfig(TierMax, 5000); err != nil || m.Tier() != TierMax {
		t.Fatalf("set config: %v %v", err, m.Tier())
	}
}

func TestLoadLocation(t *testing.T) {
	t.Parallel()
	loc, err := LoadLocation("")
	if err != nil {
		t.Fatal(err)
	}
	if _, off := time.Date(2026, 11, 9, 0, 0, 0, 0, loc).Zone(); off != 7*3600 {
		t.Fatalf("default zone offset %d", off)
	}
	if _, err := LoadLocation("Mars/Olympus"); err == nil {
		t.Fatal("bad zone accepted")
	}
}

func TestProfileValidate(t *testing.T) {
	t.Parallel()
	ok := cloud("c")
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	mut := func(f func(*Profile)) Profile { p := cloud("c"); f(&p); return p }
	cases := map[string]struct {
		p    Profile
		code string
	}{
		"empty name":        {mut(func(p *Profile) { p.Name = " " }), "invalid_name"},
		"long name":         {mut(func(p *Profile) { p.Name = strings.Repeat("n", 41) }), "invalid_name"},
		"bad kind":          {mut(func(p *Profile) { p.Kind = "x" }), "invalid_kind"},
		"custom no style":   {mut(func(p *Profile) { p.Kind = "custom" }), "invalid_style"},
		"bad location":      {mut(func(p *Profile) { p.Location = "moon" }), "invalid_location"},
		"anthropic on lan":  {mut(func(p *Profile) { p.Location = LocationInternal }), "invalid_location"},
		"no host":           {mut(func(p *Profile) { p.BaseURL = "api.anthropic.com" }), "invalid_base_url"},
		"user in url":       {mut(func(p *Profile) { p.BaseURL = "https://u:p@api.anthropic.com" }), "invalid_base_url"},
		"key in query":      {mut(func(p *Profile) { p.BaseURL = "https://api.anthropic.com?key=abc" }), "invalid_base_url"},
		"http for cloud":    {mut(func(p *Profile) { p.BaseURL = "http://api.anthropic.com" }), "invalid_base_url"},
		"bad model":         {mut(func(p *Profile) { p.Model = "a b" }), "invalid_model"},
		"empty model":       {mut(func(p *Profile) { p.Model = "" }), "invalid_model"},
		"short key":         {mut(func(p *Profile) { p.APIKey = provider.NewSecret("short") }), "invalid_key"},
		"key with space":    {mut(func(p *Profile) { p.APIKey = provider.NewSecret("sk-abc def-123456") }), "invalid_key"},
		"cloud without key": {mut(func(p *Profile) { p.APIKey = provider.Secret{} }), "key_required"},
		"cap too low":       {mut(func(p *Profile) { p.MonthlyBudget = 999 }), "invalid_cap"},
		"cap too high":      {mut(func(p *Profile) { p.MonthlyBudget = 150_000_001 }), "invalid_cap"},
	}
	for name, c := range cases {
		err := c.p.Validate()
		var pe *ProfileError
		isPE := errors.As(err, &pe)
		if !isPE || pe.Code != c.code {
			t.Errorf("%s: want %s, got %v", name, c.code, err)
		}
	}
	// Internal profiles: http allowed, key optional (INV-1), custom with a chosen style.
	for _, p := range []Profile{internal("i"), {ID: "x", Name: "gw", Kind: "custom", APIStyle: provider.StyleAnthropic, BaseURL: "http://10.0.0.5:8080", Model: "m", Location: LocationInternal, MonthlyBudget: 1000}} {
		if err := p.Validate(); err != nil || !p.Usable() {
			t.Errorf("%s: %v usable=%v", p.Name, err, p.Usable())
		}
	}
	if cloud("c").Usable() != true || mut(func(p *Profile) { p.APIKey = provider.Secret{} }).Usable() {
		t.Error("usable = key or internal")
	}
}

func TestProfileProviderMapping(t *testing.T) {
	t.Parallel()
	for _, p := range []Profile{cloud("a"), internal("b"),
		{ID: "g", Name: "g", Kind: "gemini", BaseURL: "https://generativelanguage.googleapis.com", Model: "gem", APIKey: provider.NewSecret(key), Location: LocationCloud, MonthlyBudget: 1000},
		{ID: "o", Name: "o", Kind: "openai", BaseURL: "https://api.openai.com/v1", Model: "gpt", APIKey: provider.NewSecret(key), Location: LocationCloud, MonthlyBudget: 1000}} {
		if _, err := p.Provider(); err != nil {
			t.Errorf("%s: %v", p.Kind, err)
		}
	}
	bad := cloud("a")
	bad.Kind = "x"
	if _, err := bad.Provider(); err == nil || strings.Contains(err.Error(), key) {
		t.Errorf("bad kind: %v", err)
	}
}
