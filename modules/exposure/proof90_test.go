package exposure

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// A proof that passed holds ValidDays (90 days) from its last pass. A later check that does not find it (a lookup that failed, or a
// record or file that is gone) is a warning on the target, never a block, until those 90 days run out; an IP the box no longer goes out
// through stays scannable for the same 90 days. A proof a person withdraws (the target that proved it is removed) stops scans at once.

// lookupTimedOut is what the resolver answers while the box's network is down: no answer, which is not "no such record".
var lookupTimedOut = &net.DNSError{Err: "i/o timeout", Name: "acme.example", IsTimeout: true}

func (e *env) dnsFails(err error) {
	e.dns.mu.Lock()
	e.dns.err = err
	e.dns.mu.Unlock()
}

func (e *env) node(id string) NodeView {
	e.t.Helper()
	n, err := e.svc.Node(e.ctx(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return n
}

// warned says the target's last check failed and says until when the earlier proof still holds.
func warned(t *testing.T, v TargetView, until string) {
	t.Helper()
	if v.LastCheck == nil || v.LastCheck.OK || !strings.Contains(v.LastCheck.Message, "stays valid until "+until) {
		t.Fatalf("the failed check is a warning that says until when the proof holds: %+v", v.LastCheck)
	}
	if !v.Scannable || v.BlockedReason != nil {
		t.Fatalf("a proof inside its 90 days is not blocked: %+v", v)
	}
}

func TestContract_INV1_AFailedTXTLookupWithin90DaysDoesNotBlockTheScan(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	v := e.committedDomain() // proved at t0: valid until 7 Feb 2027
	e.advance(20 * 24 * time.Hour)
	e.dnsFails(lookupTimedOut)
	if ok, why := e.scannable(v.ID); !ok || why != "" {
		t.Fatalf("a DNS time-out refused a domain proved 20 days ago: %v %q", ok, why)
	}
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", v.ID); err != nil || run.calls != 1 {
		t.Fatalf("Scan now during a DNS fault: %v, runner calls %d", err, run.calls)
	}
	warned(t, e.target(v.ID), "7 Feb 2027")
	if n := e.node(v.ID); n.Proof.State != ProofProven || n.Blocked != nil || n.Proof.ExpiresAt == nil {
		t.Fatalf("node: %+v blocked %v", n.Proof, n.Blocked)
	}
}

// The rule covers a record that is positively gone too (NXDOMAIN or no such TXT): a warning, not a block, inside the 90 days.
func TestContract_INV1_ARecordThatIsGoneWithin90DaysIsAWarning(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	v := e.committedDomain()
	e.advance(24 * time.Hour)
	e.dns.put(v.Value) // the record is removed
	if ok, why := e.scannable(v.ID); !ok || why != "" {
		t.Fatalf("%v %q", ok, why)
	}
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", v.ID); err != nil || run.calls != 1 {
		t.Fatalf("%v, runner calls %d", err, run.calls)
	}
	warned(t, e.target(v.ID), "7 Feb 2027")
}

func TestContract_INV4_ADomainProofThatDidNotPassFor90DaysExpiresAndAPassRenewsIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	v := e.committedDomain()
	e.dnsFails(lookupTimedOut)
	e.advance(91 * 24 * time.Hour)
	if ok, why := e.scannable(v.ID); ok || why != BlockedExpired {
		t.Fatalf("91 days without a pass: %v %q", ok, why)
	}
	_, err := e.svc.Scan(e.ctx(), "operator@acme.example", v.ID)
	wantAPI(t, err, 409, "expired")
	if run.calls != 0 || e.target(v.ID).Status != statusExpired {
		t.Fatalf("runner calls %d, %+v", run.calls, e.target(v.ID))
	}
	// the record answers again: the check right before the scan is a new proof, for 90 days from now
	e.dnsFails(nil)
	if ok, why := e.scannable(v.ID); !ok || why != "" {
		t.Fatalf("the record is back: %v %q", ok, why)
	}
	if got, want := str(e.target(v.ID).ExpiresAt), e.clock.Now().Add(90*24*time.Hour).Format("2006-01-02T15:04:05.000Z"); got != want {
		t.Fatalf("expires %s, want %s", got, want)
	}
}

func TestContract_INV4_EveryPassRenewsADomainFor90Days(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.committedDomain()
	e.advance(80 * 24 * time.Hour)
	if ok, _ := e.scannable(v.ID); !ok {
		t.Fatal("not scannable at 80 days")
	}
	e.advance(80 * 24 * time.Hour)
	e.dnsFails(lookupTimedOut)
	if ok, why := e.scannable(v.ID); !ok || why != "" {
		t.Fatalf("the pass at 80 days renewed it: %v %q", ok, why)
	}
}

// The box checks a domain's record by itself before its proof runs out, like a typed IP's file.
func TestContract_INV4_TheBoxChecksADomainByItselfBeforeItsProofRunsOut(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.addVerifiedDomain()
	asked := e.dns.lookups()
	e.advance(60 * 24 * time.Hour)
	if err := e.svc.RunProofRecheck(e.ctx()); err != nil || e.dns.lookups() != asked {
		t.Fatalf("nothing is due 30 days before expiry: %v, %d lookups", err, e.dns.lookups()-asked)
	}
	e.advance(25 * 24 * time.Hour) // 5 days left
	if err := e.svc.RunProofRecheck(e.ctx()); err != nil || e.dns.lookups() == asked {
		t.Fatalf("the check was due: %v", err)
	}
	if got, want := str(e.target(v.ID).ExpiresAt), e.clock.Now().Add(90*24*time.Hour).Format("2006-01-02T15:04:05.000Z"); got != want {
		t.Fatalf("renewed by itself: expires %s, want %s", got, want)
	}
}

// An office with two Internet lines: IP A is proved, then the box goes out through B. A stays scannable for 90 days from its last
// sighting; the page says the box does not go out through it now.
func TestContract_INV13_AnIPProvedWithin90DaysStaysScannableAfterTheBoxMoved(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	a := e.committedIP(ipA)
	e.advance(time.Minute)
	e.fullAs(ipB)
	if ok, why := e.scannable(a.ID); !ok || why != "" {
		t.Fatalf("A after the box moved to B: %v %q", ok, why)
	}
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", a.ID); err != nil || run.calls != 1 {
		t.Fatalf("Scan now of A: %v, runner calls %d", err, run.calls)
	}
	if n := e.node(a.ID); n.Proof.State != ProofNotCurrent || n.Blocked != nil {
		t.Fatalf("the node says the box does not use it now, and does not block: %+v %v", n.Proof, n.Blocked)
	}
	if v := e.target(a.ID); !v.Scannable || v.BlockedReason != nil {
		t.Fatalf("%+v", v)
	}
	e.advance(89 * 24 * time.Hour)
	if ok, why := e.scannable(a.ID); !ok || why != "" {
		t.Fatalf("89 days after the last sighting: %v %q", ok, why)
	}
	e.advance(2 * 24 * time.Hour)
	if ok, why := e.scannable(a.ID); ok || why != BlockedExpired {
		t.Fatalf("91 days after the last sighting: %v %q", ok, why)
	}
}

func TestTypedIP_AProofNotFoundWithin90DaysIsAWarningAndTheScanGoesOn(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	run := &fakeRunner{content: Content{Ports: []PortRow{{IP: ipC, Port: 443, Service: "https"}}}}
	w.svc.SetRunner(run)
	v := w.addIP(ipC)
	w.files.serve(ipC, "http", v.Token)
	w.verify(v.ID)
	if _, err := w.commit(v.ID); err != nil {
		t.Fatal(err)
	}
	w.files.remove()
	if code, err := w.scanErr(v.ID); err != nil || run.calls != 1 {
		t.Fatalf("scan code %q (%v), runner calls %d", code, err, run.calls)
	}
	warned(t, w.target(v.ID), "7 Feb 2027")
	if ok, why := w.scannable(v.ID); !ok || why != "" {
		t.Fatalf("%v %q", ok, why)
	}
}

// Removing the target whose record proved another one is a person withdrawing that proof: the other one is unproved at once.
func TestContract_INV1_RemovingTheTargetWhoseRecordCoveredAnotherWithdrawsTheProof(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	child := e.add("alice@acme.example", "git.example.org")
	parent := e.add("bob@acme.example", "example.org")
	e.dns.put("example.org", txtRecord(parent.Token))
	if !e.verify(parent.ID).Verified || e.target(child.ID).Status != statusVerified {
		t.Fatal("the parent's record does not cover the child")
	}
	if _, err := e.commit(child.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", parent.ID); err != nil {
		t.Fatal(err)
	}
	if ok, why := e.scannable(child.ID); ok || why != BlockedUnverified {
		t.Fatalf("the covering target was removed: %v %q", ok, why)
	}
}

// ---- the class: every check of ownership right before a scan follows the one rule ----

type recheckCase struct {
	name    string
	prepare func(t *testing.T) (e *env, id string, ip string, fail func()) // a proved, committed target and what makes its check fail
}

func recheckCases() []recheckCase {
	domain := func(failWith func(e *env, v TargetView)) func(t *testing.T) (*env, string, string, func()) {
		return func(t *testing.T) (*env, string, string, func()) {
			e := newEnv(t)
			e.svc.SetRunner(&fakeRunner{content: sampleContent()})
			v := e.committedDomain()
			e.acceptTerms(v.ID, false)
			return e, v.ID, "", func() { failWith(e, v) }
		}
	}
	return []recheckCase{
		{"domain, DNS lookup fails", domain(func(e *env, _ TargetView) { e.dnsFails(lookupTimedOut) })},
		{"domain, record gone", domain(func(e *env, v TargetView) { e.dns.put(v.Value) })},
		{"typed IP, proof file gone", func(t *testing.T) (*env, string, string, func()) {
			w := newIPWorld(t)
			w.svc.SetRunner(&fakeRunner{content: Content{}})
			v := w.addIP(ipC)
			w.files.serve(ipC, "http", v.Token)
			w.verify(v.ID)
			if _, err := w.commit(v.ID); err != nil {
				t.Fatal(err)
			}
			return w.env, v.ID, ipC, func() { w.files.remove() }
		}},
		{"box IP, box goes out through another IP", func(t *testing.T) (*env, string, string, func()) {
			e := newEnv(t)
			e.svc.SetRunner(&fakeRunner{content: sampleContent()})
			a := e.committedIP(ipA)
			return e, a.ID, ipA, func() { e.advance(time.Minute); e.fullAs(ipB) }
		}},
	}
}

// refusals asks every place that decides on ownership right before something is sent, and counts those that refuse.
func refusals(t *testing.T, e *env, id, ip string) (refused, asked int) {
	t.Helper()
	ask := func(no bool) {
		asked++
		if no {
			refused++
		}
	}
	ok, _ := e.scannable(id) // the scan module, for a scheduled scan or a domain's address
	ask(!ok)
	e.advance(ScanEvery)
	_, err := e.svc.Scan(e.ctx(), "operator@acme.example", id) // Scan now: the gate when the run starts
	var ae *APIError
	ask(errors.As(err, &ae) && ae.HTTP == 409)
	ask(!e.target(id).Scannable) // what the page and the schedule read from the stored state
	if ip != "" {
		yes, err := e.svc.ScannableIP(e.ctx(), scanModule, netip.MustParseAddr(ip)) // a domain's scan that reaches this address
		if err != nil {
			t.Fatal(err)
		}
		ask(!yes)
	} else {
		st := ScanTarget{ID: id, Kind: KindDomain, Value: "acme.example", User: scanModule, Mode: ScanMode{Full: true}}
		_, why, err := e.svc.deepGate(e.ctx(), st, netip.MustParseAddr(ipD), nil) // the deep part, right before each step
		if err != nil {
			t.Fatal(err)
		}
		ask(why == deepGone)
	}
	return refused, asked
}

func TestClass_EveryOwnershipRecheckBeforeAScanFollowsOneRule(t *testing.T) {
	t.Parallel()
	inside, outside, total := 0, 0, 0
	for _, c := range recheckCases() {
		e, id, ip, fail := c.prepare(t)
		e.advance(24 * time.Hour)
		fail()
		r, n := refusals(t, e, id, ip)
		inside += r
		total += n
		if r != 0 {
			t.Errorf("%s: %d of %d checks refused a proof inside its 90 days", c.name, r, n)
		}
		e.advance(90 * 24 * time.Hour)
		if r, n := refusals(t, e, id, ip); r != n {
			t.Errorf("%s: %d of %d checks refused a proof older than 90 days", c.name, r, n)
		} else {
			outside += r
		}
	}
	t.Logf("refused inside the 90 days: %d of %d; refused after them: %d of %d", inside, total, outside, total)
}

func (e *env) loadTarget(id string) Target {
	e.t.Helper()
	t, err := loadTarget(e.ctx(), e.db.Reader(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return t
}
