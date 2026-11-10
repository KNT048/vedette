package ai

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/ai/provider"
)

func TestContract_INV4_TokenMeterCapsAndDowngrade(t *testing.T) {
	t.Parallel()
	// Cap range for the shared cap and for a profile (1,000..5,000,000).
	for n, ok := range map[int]bool{0: false, 999: false, 1000: true, 60_000: true, 5_000_000: true, 5_000_001: false, -5: false} {
		if ValidDailyCap(n) != ok {
			t.Errorf("ValidDailyCap(%d) != %v", n, ok)
		}
	}
	c := startClock()
	if _, err := NewMeter(MeterConfig{Clock: c.now, Location: time.UTC, GlobalCap: 999, Tier: TierMed}); err == nil {
		t.Error("cap below 1000 accepted")
	}
	if _, err := NewMeter(MeterConfig{Clock: c.now, Location: time.UTC, GlobalCap: 5000, Tier: "huge"}); err == nil {
		t.Error("unknown level accepted")
	}
	if _, err := NewMeter(MeterConfig{GlobalCap: 5000, Tier: TierMin}); err == nil {
		t.Error("missing clock accepted")
	}

	m := newMeter(t, c, TierMax, 1000)
	if d := m.Record("a", 400, 100); d != nil || m.Tier() != TierMax || m.Used() != 500 {
		t.Fatalf("under the cap: %v %v %d", d, m.Tier(), m.Used())
	}
	if d := m.Record("a", 500, 0); d != nil { // exactly at the cap is not over it
		t.Fatalf("at the cap: %+v", d)
	}
	d := m.Record("b", 1, 0)
	if d == nil || d.From != TierMax || d.To != TierMed || !strings.Contains(d.Reason, "1000") || !d.At.Equal(c.t) {
		t.Fatalf("first downgrade: %+v", d)
	}
	if d := m.Record("b", 1, 0); d != nil || m.Tier() != TierMed { // still within 2 x cap: one level down is enough
		t.Fatalf("no second record inside the second cap: %+v %v", d, m.Tier())
	}
	if d := m.Record("b", 999, 0); d == nil || d.From != TierMed || d.To != TierMin { // total 2001
		t.Fatalf("second downgrade: %+v", d)
	}
	if d := m.Record("b", 1, 0); d != nil || m.Tier() != TierMin {
		t.Fatalf("min stays min, no record: %+v", d)
	}
	if !m.Exhausted() {
		t.Fatal("at min and over the cap, no more calls")
	}
	if m.ProfileUsed("a") != 1000 || m.ProfileUsed("b") != 1002 || m.ProfileUsed("none") != 0 {
		t.Fatalf("per profile: a=%d b=%d", m.ProfileUsed("a"), m.ProfileUsed("b"))
	}
	// Levels only move down by themselves.
	for _, tier := range []Tier{TierMin, TierMed, TierMax} {
		if tier.Lower() != map[Tier]Tier{TierMin: TierMin, TierMed: TierMin, TierMax: TierMed}[tier] {
			t.Errorf("Lower(%s)", tier)
		}
	}
	// Negative token counts from a broken provider cannot lower the total.
	m2 := newMeter(t, c, TierMed, 5000)
	m2.Record("x", -50, -50)
	if m2.Used() != 0 {
		t.Fatalf("negative counted: %d", m2.Used())
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

// The day is the box's local day, not UTC: 16:59 UTC is 23:59 in Ho Chi Minh City, 17:01 UTC is the next day.
func TestMeterDayBoundaryInBoxTimeZone(t *testing.T) {
	t.Parallel()
	c := &clock{time.Date(2026, 11, 9, 16, 59, 0, 0, time.UTC)}
	m := newMeter(t, c, TierMax, 1000)
	m.Record("a", 900, 0)
	m.Record("a", 200, 0) // downgrade to med
	if m.Tier() != TierMed || m.Used() != 1100 {
		t.Fatalf("%v %d", m.Tier(), m.Used())
	}
	c.t = time.Date(2026, 11, 9, 17, 1, 0, 0, time.UTC) // 00:01 local on 10 Nov
	if m.Used() != 0 || m.ProfileUsed("a") != 0 {
		t.Fatalf("counters must reset at local midnight: used=%d", m.Used())
	}
	if m.Tier() != TierMax {
		t.Fatalf("a downgrade lasts until the end of the local day, got %v", m.Tier())
	}
	if m.Exhausted() {
		t.Fatal("new day, not exhausted")
	}
	// The same instant in UTC would still be the same day: prove the zone matters.
	utc, _ := NewMeter(MeterConfig{Clock: c.now, Location: time.UTC, GlobalCap: 1000, Tier: TierMax})
	utc.Record("a", 10, 0)
	c.t = c.t.Add(10 * time.Minute)
	if utc.Used() != 10 {
		t.Fatalf("UTC meter must keep counting at 17:11 UTC, got %d", utc.Used())
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
		"cap too low":       {mut(func(p *Profile) { p.DailyCap = 999 }), "invalid_cap"},
		"cap too high":      {mut(func(p *Profile) { p.DailyCap = 5_000_001 }), "invalid_cap"},
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
	for _, p := range []Profile{internal("i"), {ID: "x", Name: "gw", Kind: "custom", APIStyle: provider.StyleAnthropic, BaseURL: "http://10.0.0.5:8080", Model: "m", Location: LocationInternal, DailyCap: 1000}} {
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
		{ID: "g", Name: "g", Kind: "gemini", BaseURL: "https://generativelanguage.googleapis.com", Model: "gem", APIKey: provider.NewSecret(key), Location: LocationCloud, DailyCap: 1000},
		{ID: "o", Name: "o", Kind: "openai", BaseURL: "https://api.openai.com/v1", Model: "gpt", APIKey: provider.NewSecret(key), Location: LocationCloud, DailyCap: 1000}} {
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
