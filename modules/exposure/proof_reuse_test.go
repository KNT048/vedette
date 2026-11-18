package exposure

import (
	"strings"
	"testing"
	"time"
)

// The reported case: git.example.com was proved by a record on example.com (its registered domain); adding example.com itself is covered
// by that record: no second record, no new step, and the message says where the record is.
func TestReuse_ARecordOnTheRegisteredDomainCoversTheDomainItself(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	git := e.add("admin@acme.example", "git.example.com")
	e.dns.put("example.com", "v=spf1 -all", txtRecord(git.Token))
	if r := e.verify(git.ID); !r.Verified {
		t.Fatalf("git: %+v", r)
	}
	root := e.add("admin@acme.example", "example.com")
	v := e.target(root.ID)
	if v.Status != "verified" || v.LastCheck == nil || !v.LastCheck.OK {
		t.Fatalf("example.com after the add: %s %+v", v.Status, v.LastCheck)
	}
	if want := "Ownership already proven by the TXT record at example.com (checked "; !strings.HasPrefix(v.LastCheck.Message, want) {
		t.Fatalf("message %q", v.LastCheck.Message)
	}
	// a name under it, added later, is covered too, and the scan gate agrees (the record is looked up again)
	www := e.add("admin@acme.example", "www.example.com")
	if e.target(www.ID).Status != "verified" {
		t.Fatalf("www: %+v", e.target(www.ID))
	}
	if _, why, err := e.svc.CheckScannable(e.ctx(), "scan", root.ID); err != nil || why == BlockedTxtMissing || why == BlockedUnverified {
		t.Fatalf("gate: %v %v", why, err)
	}
	// the record removed: the next check of the covered name finds nothing, and the gate says so
	e.dns.put("example.com", "v=spf1 -all")
	if r := e.verify(root.ID); r.Verified {
		t.Fatalf("the record is gone but example.com stays proved: %+v", r)
	}
}

// A target added before the proof that covers it is covered when that proof is found.
func TestReuse_ATargetAddedBeforeTheProofIsCoveredWhenItIsFound(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	root := e.add("admin@acme.example", "example.com")
	git := e.add("admin@acme.example", "git.example.com")
	if e.target(root.ID).Status != "unverified" {
		t.Fatal("example.com verified with no record")
	}
	e.dns.put("example.com", txtRecord(git.Token))
	if r := e.verify(git.ID); !r.Verified {
		t.Fatalf("%+v", r)
	}
	if v := e.target(root.ID); v.Status != "verified" || !strings.HasPrefix(v.LastCheck.Message, "Ownership already proven by the TXT record at example.com") {
		t.Fatalf("%s %+v", v.Status, v.LastCheck)
	}
}

// What a proof covers, by where the record sits: the registered domain covers it and every name under it; a subdomain covers that name
// and the names under it, never its parent, its siblings, a name that only ends with the same letters, or anything across a public suffix.
func TestReuse_WhatEachProofCovers(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		donor, at string // the donor target and the name its record sits on
		covered   []string
		not       []string
	}{
		{"git.example.com", "example.com",
			[]string{"example.com", "www.example.com", "a.b.example.com", "Mail.EXAMPLE.com"},
			[]string{"example.com.evil.net", "notexample.com", "evil-example.com", "example.co.uk", "example.org", "xample.com"}},
		{"a.sub.example.com", "sub.example.com",
			[]string{"sub.example.com", "b.sub.example.com", "c.d.sub.example.com"},
			[]string{"example.com", "other.example.com", "www.example.com", "subexample.com", "sub.example.com.evil.net", "xsub.example.com"}},
		{"a.b.example.co.uk", "example.co.uk",
			[]string{"example.co.uk", "www.example.co.uk"},
			[]string{"co.uk", "other.co.uk", "example.com", "example.uk"}},
		{"git.xn--bcher-kva.de", "xn--bcher-kva.de",
			[]string{"xn--bcher-kva.de", "shop.xn--bcher-kva.de"},
			[]string{"xn--bcher-kvb.de", "bcher.de"}},
	} {
		t.Run(c.at, func(t *testing.T) {
			t.Parallel()
			e, _ := newProofEnv(t)
			donor := e.add("admin@acme.example", c.donor)
			e.dns.put(c.at, txtRecord(donor.Token))
			if r := e.verify(donor.ID); !r.Verified {
				t.Fatalf("the donor: %+v", r)
			}
			for _, n := range c.covered {
				if v := e.add("admin@acme.example", n); e.target(v.ID).Status != "verified" {
					t.Errorf("%s is not covered by the record on %s: %+v", n, c.at, e.target(v.ID).LastCheck)
				}
			}
			for _, n := range c.not {
				v, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", n)
				if err != nil { // a public suffix is refused outright: never a target
					continue
				}
				if s := e.target(v.ID).Status; s != "unverified" {
					t.Errorf("%s is covered by the record on %s: %+v", n, c.at, e.target(v.ID).LastCheck)
				}
			}
		})
	}
}

// The forms a name can be typed in are the target's own: upper case is folded, and a trailing dot, a scheme, a path or a Unicode name
// is refused, so none of them is a second spelling that slips past the rule.
func TestReuse_NamesAreNormalisedAsTargetsAre(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	donor := e.add("admin@acme.example", "git.example.com")
	e.dns.put("example.com", txtRecord(donor.Token))
	e.verify(donor.ID)
	v, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "  WWW.EXAMPLE.COM ")
	if err != nil || v.Value != "www.example.com" || e.target(v.ID).Status != "verified" {
		t.Fatalf("%+v %v", v, err)
	}
	for _, n := range []string{"shop.example.com.", "https://shop.example.com", "shop.example.com/x", "shöp.example.com", "shop.example.com.evil.net."} {
		if v, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", n); err == nil {
			t.Errorf("%q became the target %q", n, v.Value)
		}
	}
}

// reuses is the one place that decides which stored proofs count: each way a proof must not count, one by one.
func TestReuse_OnlyAPassingUnexpiredProofOfADomainOnAProperNameCounts(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	ok := func(value, at string) Target {
		return Target{ID: "xt-" + value, Kind: KindDomain, Value: value, Token: "tok", VerifiedAt: now.Add(-time.Hour),
			LastCheck: &Check{At: "2026-11-18T09:00:00.000Z", OK: true, ProofName: at}}
	}
	count := func(name string, ts ...Target) int { return len(reuses(name, ts, now)) }
	if count("example.com", ok("git.example.com", "example.com")) != 1 {
		t.Fatal("a good proof does not count")
	}
	for name, d := range map[string]Target{
		"an older release stored no name":    ok("git.example.com", ""),
		"the record was on the name itself":  ok("git.example.com", "git.example.com"),
		"a name that is not above the donor": ok("git.example.com", "mail.example.com"),
		"a public suffix":                    ok("git.example.co.uk", "co.uk"),
		"a private public suffix":            ok("x.github.io", "github.io"),
		"a suffix of the string only":        ok("git.example.com", "xample.com"),
		"the check failed": func() Target {
			x := ok("git.example.com", "example.com")
			x.LastCheck.OK = false
			return x
		}(),
		"never verified": func() Target { x := ok("git.example.com", "example.com"); x.VerifiedAt = time.Time{}; return x }(),
		"an IP": func() Target {
			x := ok("203.0.113.9", "example.com")
			x.Kind = KindIP
			return x
		}(),
		"no check": func() Target { x := ok("git.example.com", "example.com"); x.LastCheck = nil; return x }(),
	} {
		if n := count("example.com", d); n != 0 {
			t.Errorf("%s: counted", name)
		}
	}
	for _, name := range []string{"co.uk", "github.io", "other.github.io", "x.co.uk"} {
		if n := count(name, ok("git.example.com", "example.com"), ok("a.x.github.io", "x.github.io"), ok("a.example.co.uk", "example.co.uk")); n != 0 && name != "x.co.uk" {
			t.Errorf("%s: %d proofs cover a name on or across a public suffix", name, n)
		}
	}
	if count("x.co.uk", ok("a.example.co.uk", "example.co.uk")) != 0 {
		t.Error("a proof of example.co.uk covers x.co.uk")
	}
	if count("other.github.io", ok("a.x.github.io", "x.github.io")) != 0 {
		t.Error("a proof of x.github.io covers other.github.io")
	}
}

// Domain checks are limited per target, every DomainCheckEvery, and say in seconds when the next one is allowed; they do not use up the
// hour of the box (Detect now and the check of an IP).
func TestVerify_ADomainIsCheckedEvery30SecondsPerTarget(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	a, b := e.add("admin@acme.example", "a.example.com"), e.add("admin@acme.example", "b.example.com")
	check := func(id string) error { _, err := e.svc.Verify(e.ctx(), "operator@acme.example", id); return err }
	if err := check(a.ID); err != nil {
		t.Fatal(err)
	}
	e.advance(10 * time.Second)
	err := check(a.ID)
	wantAPI(t, err, 429, "rate_limited")
	if !strings.Contains(err.Error(), "allowed in 20 seconds") {
		t.Fatalf("message: %v", err)
	}
	if err := check(b.ID); err != nil { // another target is not held back
		t.Fatalf("another target: %v", err)
	}
	e.advance(20 * time.Second)
	if err := check(a.ID); err != nil {
		t.Fatalf("after 30 seconds: %v", err)
	}
	for range 25 { // far more than the old 10 an hour, 30 seconds apart
		e.advance(DomainCheckEvery)
		if err := check(a.ID); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.count(`SELECT count(*) FROM exp_attempt`); n != 0 {
		t.Fatalf("%d attempts of the box's hour used by domain checks", n)
	}
}
