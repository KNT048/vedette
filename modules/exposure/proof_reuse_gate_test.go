package exposure

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// reuseWorld is git.example.com proved by its token on example.com, with example.com, www.example.com and a.b.example.com added after it
// (each covered at its add).
func reuseWorld(t *testing.T) (e *env, git, root, www TargetView) {
	t.Helper()
	e, _ = newProofEnv(t)
	git = e.add("admin@acme.example", "git.example.com")
	e.dns.put("example.com", "v=spf1 -all", txtRecord(git.Token))
	if r := e.verify(git.ID); !r.Verified {
		t.Fatalf("git: %+v", r)
	}
	root = e.add("admin@acme.example", "example.com")
	www = e.add("admin@acme.example", "www.example.com")
	for _, v := range []TargetView{root, www} {
		if e.target(v.ID).Status != "verified" {
			t.Fatalf("%s is not covered: %+v", v.Value, e.target(v.ID).LastCheck)
		}
	}
	return e, git, root, www
}

// The gate of a covered name hands the executors the donor's domain and token and the name the record sits on, and the web and deep
// steps accept exactly that: one rule at every gate.
func TestReuse_TheGateHandsTheExecutorsTheDonorsProof(t *testing.T) {
	t.Parallel()
	e, git, root, www := reuseWorld(t)
	run := &fakeRunner{content: Content{}}
	e.svc.SetRunner(run)
	for _, v := range []TargetView{root, www} {
		if _, err := e.commit(v.ID); err != nil {
			t.Fatal(err)
		}
		e.advance(time.Minute)
		if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", v.ID); err != nil {
			t.Fatalf("%s: %v", v.Value, err)
		}
		if p := run.last.Proof; p == nil || p.Domain != "git.example.com" || p.Token != git.Token || p.ProofAt != "example.com" || run.last.Value != v.Value {
			t.Errorf("%s: scan target %+v proof %+v", v.Value, run.last, run.last.Proof)
		}
	}
}

// The deep step of a covered name carries the donor as the domain and the shared name as ProofAt, for the name itself and for the names under it.
func TestReuse_TheDeepStepOfACoveredNameCarriesTheDonor(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t) // the targets get random tokens: the fake fence would give every domain the same one
	git, err := d.svc.AddDomain(d.ctx(), "admin@acme.example", "git.zone.example")
	if err != nil {
		t.Fatal(err)
	}
	d.dns.put("zone.example", txtRecord(git.Token))
	if r := d.verify(git.ID); !r.Verified {
		t.Fatalf("%+v", r)
	}
	root, err := d.svc.AddDomain(d.ctx(), "admin@acme.example", "zone.example")
	if err != nil {
		t.Fatal(err)
	}
	if v := d.target(root.ID); v.Status != "verified" {
		t.Fatalf("zone.example is not covered at its add: %+v", v.LastCheck)
	}
	if _, err := d.commit(root.ID); err != nil {
		t.Fatal(err)
	}
	d.acceptTerms(root.ID, false)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.dns.point("zone.example", ipB)
	d.dns.point("www.zone.example", ipB)
	st := ScanTarget{ID: root.ID, Kind: KindDomain, Value: "zone.example", User: "admin@acme.example", Mode: ScanMode{Full: true}}
	out, why, err := d.svc.deepGate(d.ctx(), st, netip.MustParseAddr(ipB), []string{"zone.example", "www.zone.example"})
	if err != nil || why != "" || out.Domain == nil || out.Domain.Domain != "git.zone.example" || out.Domain.ProofAt != "zone.example" || out.Domain.Name != "zone.example" {
		t.Fatalf("scope %+v %q %v", out.Domain, why, err)
	}
	// the donor deleted since the gate: the step is refused, not sent with a token whose record nobody stands behind
	if err := d.svc.Delete(d.ctx(), "admin@acme.example", git.ID); err != nil {
		t.Fatal(err)
	}
	if out, why, err = d.svc.deepGate(d.ctx(), st, netip.MustParseAddr(ipB), []string{"zone.example"}); err != nil || out.Domain != nil || why == "" {
		t.Fatalf("after the donor was deleted: %+v %q %v", out.Domain, why, err)
	}
}

// What a covered name needs at its gate: the record there now (removed: a warning inside the 90 days of its last pass), the donor still
// on the box (deleted: a person withdrew the proof, refused at once), and nothing about the donor's own last check.
func TestReuse_TheGateAsksTheRecordNowAndTheDonorNow(t *testing.T) {
	t.Parallel()
	e, git, root, www := reuseWorld(t)
	// the donor's own check fails once (a timeout): the covered names stay covered, the record is what counts
	e.advance(time.Minute)
	e.dns.err = context.DeadlineExceeded
	if r := e.verify(git.ID); r.Verified {
		t.Fatalf("a failing lookup proved git: %+v", r)
	}
	e.dns.err = nil
	for _, v := range []TargetView{root, www} {
		if ok, why, err := e.svc.CheckScannable(e.ctx(), "scan", v.ID); err != nil || why == BlockedUnverified || !e.target(v.ID).LastCheck.OK {
			t.Errorf("%s after a failed check of the donor: %v %v %v", v.Value, ok, why, err)
		}
	}
	// the record removed: the gate of the covered name records the failed check and lets it through inside its 90 days
	e.dns.put("example.com", "v=spf1 -all")
	if ok, why, _ := e.svc.CheckScannable(e.ctx(), "scan", www.ID); why == BlockedUnverified || why == BlockedExpired || e.target(www.ID).LastCheck.OK {
		t.Fatalf("record removed: %v %v", ok, why)
	}
	// the record back, the donor deleted: refused again, and the message says which donor's record it looked for
	e.dns.put("example.com", txtRecord(git.Token))
	if _, why, _ := e.svc.CheckScannable(e.ctx(), "scan", www.ID); why == BlockedUnverified || !e.target(www.ID).LastCheck.OK {
		t.Fatalf("record back: %v", why)
	}
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", git.ID); err != nil {
		t.Fatal(err)
	}
	if _, why, _ := e.svc.CheckScannable(e.ctx(), "scan", www.ID); why != BlockedUnverified {
		t.Fatalf("donor deleted: %v", why)
	}
}

// A covered name does not depend on where the donor's own check last found its record: the donor adding its token on a nearer name too
// (the alternative host) changes nothing for the names above it.
func TestReuse_ANearerRecordOfTheDonorDoesNotDropTheCoverage(t *testing.T) {
	t.Parallel()
	e, git, root, www := reuseWorld(t)
	e.dns.put("git.example.com", txtRecord(git.Token))
	if r := e.verify(git.ID); !r.Verified {
		t.Fatalf("%+v", r)
	}
	for _, v := range []TargetView{root, www} {
		if r := e.verify(v.ID); !r.Verified || !strings.HasPrefix(r.Message, "Ownership already proven by the TXT record at example.com") {
			t.Errorf("%s: %+v", v.Value, r)
		}
		if _, _, _ = e.svc.CheckScannable(e.ctx(), "scan", v.ID); !e.target(v.ID).LastCheck.OK {
			t.Errorf("%s: the gate refuses", v.Value)
		}
	}
}

// A record reached through a CNAME, or answered by a wildcard, proves nothing for a covered name either (the same rule as the executors).
func TestReuse_ARecordThroughACNAMEOrAWildcardCoversNothing(t *testing.T) {
	t.Parallel()
	e, d := newProofEnv(t)
	git := e.add("admin@acme.example", "git.example.com")
	root := e.add("admin@acme.example", "example.com")
	d.cname["example.com"] = "lb.lapsed-vendor.example"
	e.dns.put("lb.lapsed-vendor.example", txtRecord(git.Token))
	r := e.verify(root.ID)
	if r.Verified || strings.Contains(r.Message, "Ownership already proven") {
		t.Fatalf("through a CNAME: %+v", r)
	}
	if !strings.Contains(r.Message, "git.example.com's token on example.com") {
		t.Fatalf("the message does not name the donor's record it looked for: %q", r.Message)
	}
	delete(d.cname, "example.com")
	delete(e.dns.txt, "lb.lapsed-vendor.example")
	d.wildTXT["example.com"] = []string{txtRecord(git.Token)}
	if r := e.verify(root.ID); r.Verified {
		t.Fatalf("through a wildcard: %+v", r)
	}
}

// A DNS owner who points a name somewhere else gains nothing: another box's token, a token on a public suffix, a record on a sibling
// zone, or on a name only alike never covers a name.
func TestReuse_ForeignRecordsCoverNothing(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	git := e.add("admin@acme.example", "git.example.com")
	root := e.add("admin@acme.example", "example.com")
	other := e.add("admin@acme.example", "www.example.org")
	e.dns.put("example.com", txtRecord("0123456789abcdef")) // another box's token
	e.dns.put("com", txtRecord(git.Token))                  // a public suffix
	e.dns.put("example.org", txtRecord(git.Token))          // another zone: git is not under it
	e.dns.put("notexample.com", txtRecord(git.Token))       // a name that only ends alike
	e.dns.put("_vedette-verify.example.org", txtRecord(git.Token))
	for _, v := range []TargetView{root, other} {
		if r := e.verify(v.ID); r.Verified {
			t.Errorf("%s: %+v", v.Value, r)
		}
	}
	e.dns.mu.Lock()
	asked := append([]string(nil), e.dns.asks...)
	e.dns.mu.Unlock()
	for _, n := range asked {
		if n == "com" || n == "_vedette-verify.com" {
			t.Errorf("a public suffix was asked: %v", asked)
		}
	}
}

// The donor deleted, or given a new token, between the lookup and the write of the check: the covered name is not proved.
func TestReuse_ADonorRemovedDuringTheCheckProvesNothing(t *testing.T) {
	t.Parallel()
	e, d := newProofEnv(t)
	git := e.add("admin@acme.example", "git.example.com")
	root := e.add("admin@acme.example", "example.com")
	e.dns.put("example.com", txtRecord(git.Token))
	d.onTXT = func(name string) {
		if name == "example.com" {
			d.onTXT = nil
			if err := e.svc.Delete(context.WithoutCancel(e.ctx()), "admin@acme.example", git.ID); err != nil {
				t.Error(err)
			}
		}
	}
	r := e.verify(root.ID)
	if r.Verified || !strings.Contains(r.Message, "The TXT record of git.example.com on example.com covered this name, but git.example.com was removed") {
		t.Fatalf("%+v", r)
	}
}

// Other names under the proven one are covered when the proof is found, and the others stay as they are.
func TestReuse_TheNamesUnderTheProofAreCoveredWhenItIsFound(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	root := e.add("admin@acme.example", "example.com")
	deep := e.add("admin@acme.example", "a.b.example.com")
	mail := e.add("admin@acme.example", "mail.example.org")
	git := e.add("admin@acme.example", "git.example.com")
	e.dns.put("example.com", txtRecord(git.Token))
	if r := e.verify(git.ID); !r.Verified {
		t.Fatalf("%+v", r)
	}
	for _, v := range []TargetView{root, deep} {
		if e.target(v.ID).Status != "verified" {
			t.Errorf("%s: %+v", v.Value, e.target(v.ID).LastCheck)
		}
	}
	if e.target(mail.ID).Status == "verified" {
		t.Error("another zone covered")
	}
	if p := e.target(root.ID).Proof; p == nil || p.CoveredBy == nil || *p.CoveredBy != "git.example.com" {
		t.Fatalf("covered_by: %+v", p)
	}
}

// The same name is looked up once per check however many targets' tokens are looked for on it, and the lookups of a failed check too.
func TestReuse_TheSameNameIsLookedUpOnceInACheck(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	for _, n := range []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"} {
		e.add("admin@acme.example", n)
	}
	root := e.add("admin@acme.example", "example.com")
	e.dns.mu.Lock()
	e.dns.asks = nil
	e.dns.mu.Unlock()
	if r := e.verify(root.ID); r.Verified {
		t.Fatalf("%+v", r)
	}
	e.dns.mu.Lock()
	defer e.dns.mu.Unlock()
	seen := map[string]int{}
	for _, n := range e.dns.asks {
		seen[n]++
	}
	for n, c := range seen {
		if c != 1 {
			t.Errorf("%s asked %d times in one check (%v)", n, c, e.dns.asks)
		}
	}
}

// The box-wide bound: a burst of DomainCheckBurst checks across targets, then one more every DomainCheckRefill, however many targets they
// are spread over; it says in seconds when the next one is allowed, and is no attempt of the box's hour.
func TestVerify_TheBoxBoundsTheDomainChecksPeopleTrigger(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	var ids []string
	for i := range MaxTargets {
		ids = append(ids, e.add("admin@acme.example", string(rune('a'+i))+".example.org").ID)
	}
	check := func(id string) error { _, err := e.svc.Verify(e.ctx(), "operator@acme.example", id); return err }
	for _, id := range ids[:DomainCheckBurst] {
		if err := check(id); err != nil {
			t.Fatalf("within the burst: %v", err)
		}
	}
	e.advance(DomainCheckEvery + time.Second) // every target is on a fresh slot of its own: only the box-wide bound can refuse now
	refilled := int((DomainCheckEvery + time.Second) / DomainCheckRefill)
	for _, id := range ids[:refilled] {
		if err := check(id); err != nil {
			t.Fatalf("a refilled check: %v", err)
		}
	}
	err := check(ids[refilled])
	wantAPI(t, err, 429, "rate_limited")
	if !strings.Contains(err.Error(), "Many ownership checks") || !strings.Contains(err.Error(), "second") {
		t.Fatalf("message: %v", err)
	}
	e.advance(DomainCheckRefill)
	if err := check(ids[refilled]); err != nil {
		t.Fatalf("one more after a refill: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM exp_attempt`); n != 0 {
		t.Fatalf("%d attempts of the box's hour used by domain checks", n)
	}
}

// The check of a name just added counts against the box-wide bound too; with the bound used up the add still works, the name waits
// unverified, and a check a moment later covers it.
func TestVerify_ANameAddedWhileTheBoxIsOverTheBoundWaits(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	git := e.add("admin@acme.example", "git.example.com")
	e.dns.put("example.com", txtRecord(git.Token))
	if r := e.verify(git.ID); !r.Verified {
		t.Fatalf("%+v", r)
	}
	for range DomainCheckBurst { // a loop of adds and checks used the bound up
		_ = e.svc.domainCheckAllowed("loop", false)
	}
	root := e.add("admin@acme.example", "example.com")
	if v := e.target(root.ID); v.Status == "verified" {
		t.Fatalf("checked beyond the bound: %+v", v.LastCheck)
	}
	e.advance(DomainCheckRefill)
	if r := e.verify(root.ID); !r.Verified {
		t.Fatalf("%+v", r)
	}
}

// Another target's token on the apex covers the name (the record is the box's, looked up now); a token of no target of this box does not.
func TestReuse_AnotherTargetsTokenOnTheApexCoversOnlyWhenItIsATarget(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	git := e.add("admin@acme.example", "git.example.net")
	www := e.add("admin@acme.example", "www.example.net")
	e.dns.put("example.net", txtRecord(www.Token))
	if r := e.verify(git.ID); !r.Verified || !strings.Contains(r.Message, "Ownership already proven by the TXT record at example.net") {
		t.Fatalf("%+v", r)
	}
	e.dns.put("example.net", txtRecord("0123456789abcdef"))
	if r := e.verify(git.ID); r.Verified || !strings.Contains(r.Message, "example.net: one TXT record, not this one") {
		t.Fatalf("%+v", r)
	}
}

// Ten subdomains and a donor added last with its token on the apex: every one is scannable at its own gate, and a name added later is
// covered at its add (no cap on the donors a check looks for).
func TestReuse_TenSubdomainsAndALateDonorAreAllScannable(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	var subs []TargetView
	for i := range 10 {
		subs = append(subs, e.add("admin@acme.example", string(rune('a'+i))+".example.com"))
	}
	donor := e.add("admin@acme.example", "git.example.com")
	e.dns.put("example.com", txtRecord(donor.Token))
	if r := e.verify(donor.ID); !r.Verified {
		t.Fatalf("%+v", r)
	}
	for _, v := range subs {
		if e.target(v.ID).Status != "verified" {
			t.Errorf("%s not covered", v.Value)
		}
		if _, why, err := e.svc.CheckScannable(e.ctx(), "scan", v.ID); err != nil || !e.target(v.ID).LastCheck.OK || why == BlockedUnverified {
			t.Errorf("%s: its own gate refuses: %v %v", v.Value, why, err)
		}
	}
	late := e.add("admin@acme.example", "late.example.com")
	if e.target(late.ID).Status != "verified" {
		t.Fatalf("a name added later: %+v", e.target(late.ID).LastCheck)
	}
	if _, why, err := e.svc.CheckScannable(e.ctx(), "scan", late.ID); err != nil || !e.target(late.ID).LastCheck.OK {
		t.Fatalf("late: %v %v", why, err)
	}
}

// A donor under a private suffix below the checked registered domain is never a donor: the executors would refuse that shape.
func TestReuse_ADonorAcrossAPrivateSuffixDoesNotVerifyTheParent(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	bucket := e.add("admin@acme.example", "bucket.s3.amazonaws.com")
	parent, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "amazonaws.com")
	if err == nil {
		e.dns.put("amazonaws.com", txtRecord(bucket.Token))
		if r := e.verify(parent.ID); r.Verified {
			t.Fatalf("verified across a private suffix: %+v", r)
		}
	}
	if got := reuseCands(Target{ID: "x", Kind: KindDomain, Value: "example.com"}, proofChain("example.com"), []Target{{ID: "b", Kind: KindDomain, Value: "b.s3.amazonaws.com"}}); len(got) != 0 {
		t.Fatalf("candidates: %v", got)
	}
}

// The wait the box-wide bound states is never 0 seconds, and the refill is exact: one more check every DomainCheckRefill, however the
// checks are spaced.
func TestVerify_TheBoxBoundRefillsExactlyAndNeverSaysZeroSeconds(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	for range DomainCheckBurst {
		if err := e.svc.domainCheckAllowed("a", false); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 { // polled every second: the refill after ten of them must let one through, and no wait says 0 seconds
		for range int(DomainCheckRefill/time.Second) - 1 {
			e.advance(time.Second)
			err := e.svc.domainCheckAllowed("a", false)
			if err == nil || strings.Contains(err.Error(), "in 0 second") {
				t.Fatalf("%v", err)
			}
		}
		e.advance(time.Second)
		if err := e.svc.domainCheckAllowed("a", false); err != nil {
			t.Fatalf("after a full refill: %v", err)
		}
	}
}

// A name covered by the record of a donor with an older random token passes its check and the message names the bound value to add.
func TestReuse_ADonorWithAnOlderTokenNamesTheBoundValue(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	donor := e.add("admin@acme.example", "git.example.com") // random token: no fence at add time
	root := e.add("admin@acme.example", "example.com")
	e.svc.cfg.DomainFence = &fakeFence{}
	e.dns.put("example.com", txtRecord(donor.Token))
	r := e.verify(root.ID)
	if !r.Verified || !strings.Contains(r.Message, "The record is git.example.com's, whose token is older") || !strings.Contains(r.Message, "add the TXT record vedette-verify="+deepToken+" on example.com too") {
		t.Fatalf("%+v", r)
	}
}
