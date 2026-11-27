package findings

import (
	"testing"
	"time"
)

// The reporting window: a finding of a CVE that leaves the window closes as not relevant via outside_window (by Vedette, with its
// event and audit row, never deleted), and opens again when the CVE is back inside it. Both match paths do it: the pass over every
// device and the match of one device.
func TestWindow_AFindingOutsideTheWindowClosesAndOpensAgain(t *testing.T) {
	t.Parallel()
	for _, pass := range []bool{true, false} {
		e := newEnv(t)
		match := func() {
			t.Helper()
			var err error
			if pass {
				_, err = e.svc.Reconcile(t.Context())
			} else {
				_, err = e.svc.OnMatchChanged(t.Context(), "a-1")
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		e.feeds.vulns = []Vuln{qnapRanged}
		match()
		if f := e.only(t); f.State != StateOpen || !f.Detected {
			t.Fatalf("seeded: %+v", f)
		}
		e.advance(time.Hour)
		old := qnapRanged
		old.OutsideWindow = true
		e.feeds.vulns = []Vuln{old}
		match()
		f := e.only(t)
		if f.State != StateHandled || f.Resolution != ResolutionNotRelevant || f.Via != ViaOutsideWindow || f.ResolvedBy != SystemUser || f.Detected {
			t.Fatalf("pass %v: outside the window: %+v", pass, f)
		}
		if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.status' AND detail LIKE '%outside the reporting window%'`); n != 1 {
			t.Fatalf("pass %v: %d audit rows of the close", pass, n)
		}
		match() // set aside again: nothing changes
		if g := e.only(t); g.UpdatedAt != f.UpdatedAt {
			t.Fatalf("pass %v: a second pass wrote %+v", pass, g)
		}
		e.advance(time.Hour)
		e.feeds.vulns = []Vuln{qnapRanged} // every age reported, or the CVE is exploited now
		match()
		if f := e.only(t); f.State != StateOpen || !f.Detected {
			t.Fatalf("pass %v: back inside the window: %+v", pass, f)
		}
	}
}

// A finding a person confirmed stays open outside the window: a flaw proved on the device is reported whatever its age.
func TestWindow_AConfirmedFindingStaysOpen(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.feeds.vulns = []Vuln{qnapRanged}
	id := e.seed()
	e.advance(time.Hour)
	if _, err := e.svc.ConfirmFromScan(t.Context(), "a-1", qnapRanged.CVE, scanEv("t1")); err != nil {
		t.Fatal(err)
	}
	e.advance(time.Hour)
	old := qnapRanged
	old.OutsideWindow = true
	e.feeds.vulns = []Vuln{old}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f := e.only(t); f.ID != id || f.State != StateOpen {
		t.Fatalf("confirmed by a safe check, outside the window: %+v", f)
	}
}

// A CVE outside the window is no question either: the device without a version is asked nothing about it, and the coverage counts it
// apart from the pairs.
func TestWindow_NoQuestionAndCountedApart(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.inv.match["a-1"] = nas("")
	e.feeds.vulns = []Vuln{qnapRanged}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_question`); n == 0 {
		t.Fatal("no question about a device without a version: the test asks nothing")
	}
	old := qnapRanged
	old.OutsideWindow = true
	e.feeds.vulns = []Vuln{old, qnapVuln2()}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE cve = 'CVE-2022-27593' OR detail LIKE '%CVE-2022-27593%'`); n != 0 {
		t.Fatalf("%d questions about a CVE outside the window", n)
	}
	c, ok, err := e.svc.Coverage(t.Context())
	if err != nil || !ok || c.OutsideWindow != 1 {
		t.Fatalf("coverage %+v %v %v", c, ok, err)
	}
}

// qnapVuln2 is another CVE of the product inside the window, so the pass has something to match.
func qnapVuln2() Vuln {
	v := qnapRanged
	v.CVE = "CVE-2022-27594"
	return v
}
