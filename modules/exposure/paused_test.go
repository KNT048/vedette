package exposure

import (
	"testing"
	"time"
)

// "The box does not go out through this IP now" (not_current) rests on what is stored, not on a 5-minute window (INV-13): the latest
// full check that got an answer did not see it, and nothing has seen it since. A light check or a failed check never sets it. It is a
// warning on the target: the IP stays scannable until its ValidDays run out (INV-4).

func (e *env) isPaused(id string) bool {
	e.t.Helper()
	n, err := e.svc.Node(e.ctx(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	if v := e.target(id); v.BlockedReason != nil && *v.BlockedReason != BlockedNoCommitment && str(v.Validity) != validityExpired {
		e.t.Fatalf("an IP inside its days is blocked: %v", *v.BlockedReason)
	}
	return n.Proof.State == ProofNotCurrent
}

// light runs one automatic light check (one round) that sees ips[0]; its error is an outcome, not a failure of the test.
func (e *env) light(ip string) {
	e.t.Helper()
	e.prober.set(ip)
	if _, err := e.svc.Detect(e.ctx(), SystemUser, false); err != nil && !isOutcome(err) {
		e.t.Fatal(err)
	}
}

// fullAs runs a full check (all rounds) as a person; a failed check is an outcome.
func (e *env) fullAs(ips ...string) {
	e.t.Helper()
	e.prober.set(ips...)
	if _, err := e.svc.Detect(e.ctx(), "admin@acme.example", true); err != nil && !isOutcome(err) {
		e.t.Fatal(err)
	}
}

func TestContract_INV13_FullCheckWithoutTheIPPausesItAndItStays(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.committedIP(ipA)
	if e.isPaused(a.ID) {
		t.Fatal("a seen IP is paused")
	}
	e.advance(time.Minute)
	e.fullAs(ipB)
	if !e.isPaused(a.ID) {
		t.Fatal("a full check that did not see A did not pause it")
	}
	calls := e.prober.count()
	for _, d := range []time.Duration{10 * time.Minute, 3 * time.Hour, 20 * 24 * time.Hour} {
		e.advance(d)
		if !e.isPaused(a.ID) {
			t.Fatalf("paused state gone after %v with no check in between", d)
		}
	}
	if e.prober.count() != calls {
		t.Fatal("reading the state probed the network")
	}
	// the tree says the same, and the IP stays scannable with its own validity
	tree, err := e.svc.Tree(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range tree.Items {
		if x.ID == a.ID && (x.Proof.State != ProofNotCurrent || x.Blocked != nil) {
			t.Fatalf("tree: %+v", x)
		}
	}
}

func TestContract_INV13_LightCheckNeverPausesButCanClear(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.committedIP(ipA)
	e.advance(time.Minute)
	e.light(ipB) // a light check sees one IP only: it may miss a load-balanced one
	if e.isPaused(a.ID) {
		t.Fatal("a light check that did not see A paused it")
	}
	e.advance(time.Minute)
	e.fullAs(ipB)
	if !e.isPaused(a.ID) {
		t.Fatal("full check did not pause A")
	}
	e.advance(time.Minute)
	e.light(ipB) // still not A: unchanged
	if !e.isPaused(a.ID) {
		t.Fatal("a light check without A cleared the pause")
	}
	e.advance(10 * time.Minute)
	e.light(ipA) // a light check that sees it clears it
	if e.isPaused(a.ID) {
		t.Fatal("a light check that saw A did not clear the pause")
	}
	e.advance(time.Hour)
	if e.isPaused(a.ID) {
		t.Fatal("the pause came back by itself")
	}
}

func TestContract_INV13_LaterFullCheckThatSeesItClears(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.committedIP(ipA)
	e.advance(time.Minute)
	e.fullAs(ipB)
	if !e.isPaused(a.ID) {
		t.Fatal("not paused")
	}
	e.advance(10 * time.Minute)
	e.fullAs(ipA, ipB) // a load balancer: both seen
	if e.isPaused(a.ID) || e.isPaused(e.detectedID(ipB)) {
		t.Fatal("a full check that saw both left one paused")
	}
}

func TestContract_INV13_FailedCheckChangesNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.committedIP(ipA)
	e.advance(time.Minute)
	e.fullAs("!") // every service down
	e.advance(time.Minute)
	e.fullAs("~") // the services never agree
	if e.isPaused(a.ID) {
		t.Fatal("a failed full check paused a seen IP")
	}
	e.advance(time.Minute)
	e.fullAs(ipB)
	if !e.isPaused(a.ID) {
		t.Fatal("not paused")
	}
	e.advance(time.Minute)
	e.fullAs("!")
	e.advance(time.Minute)
	e.fullAs("~")
	e.advance(10 * time.Minute)
	if !e.isPaused(a.ID) {
		t.Fatal("a failed full check cleared the pause")
	}
}

// detectedID returns the id of the IP target with this value.
func (e *env) detectedID(ip string) string {
	e.t.Helper()
	all, err := e.svc.Targets(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	for _, x := range all {
		if x.Value == ip {
			return x.ID
		}
	}
	e.t.Fatalf("no target %s", ip)
	return ""
}
