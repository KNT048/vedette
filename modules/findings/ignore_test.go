package findings

import (
	"strings"
	"testing"
	"time"
)

// D-630: Ignore closes only an open finding, with the person in the note; Stop ignoring reopens only a finding Ignore closed.
func TestFinding_IgnoreCloseAndUnignoreReopen(t *testing.T) {
	t.Parallel()
	closed, h, ok := suspected().IgnoreClose("it@acme.example", t0)
	if !ok || closed.Status != StatusNotRelevant || closed.ResolvedBy != SystemUser || closed.ResolutionReason != "" ||
		closed.ResolutionNote != "Closed by Vedette: the device was ignored by it@acme.example." || closed.Validate() != nil || !closed.ClosedForIgnore() {
		t.Fatalf("closed = %+v %v", closed, ok)
	}
	if h.User != SystemUser || h.Action != string(StatusNotRelevant) || h.Note != closed.ResolutionNote {
		t.Fatalf("history = %+v", h)
	}
	re, h, ok := closed.UnignoreReopen("it@acme.example", t0.Add(time.Hour))
	if !ok || re.Status != StatusSuspected || re.ResolvedBy != "" || re.ResolutionNote != "" || re.Validate() != nil {
		t.Fatalf("reopened = %+v %v", re, ok)
	}
	if h.User != SystemUser || h.Action != "reopened" || !strings.Contains(h.Note, "it@acme.example stopped ignoring it") {
		t.Fatalf("history = %+v", h)
	}
	scan := suspected()
	scan.Status, scan.Basis, scan.Evidence = StatusConfirmed, BasisScan, &Evidence{Template: "t", CheckedAt: t0}
	if c, _, _ := scan.IgnoreClose("ann", t0); func() bool { r, _, _ := c.UnignoreReopen("ann", t0); return r.Status != StatusConfirmed }() {
		t.Fatal("a confirmed finding does not reopen as confirmed")
	}
	// what a person settled, and Vedette's own D-530 close, are never touched
	person, _, err := suspected().Apply(ActionFalsePositive, "not this model", "ann", t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := person.IgnoreClose("ann", t0); ok {
		t.Fatal("Ignore closed a person's decision again")
	}
	if _, _, ok := person.UnignoreReopen("ann", t0); ok {
		t.Fatal("Stop ignoring reopened a person's decision")
	}
	auto, _, _ := suspected().AutoResolve("1.2 is outside every range", t0)
	if _, _, ok := auto.UnignoreReopen("ann", t0); ok {
		t.Fatal("Stop ignoring reopened Vedette's not-affected close")
	}
	// a person who closes the ignored finding again owns it
	byPerson := closed
	byPerson.ResolvedBy = "ann"
	if _, _, ok := byPerson.UnignoreReopen("ann", t0); ok {
		t.Fatal("Stop ignoring reopened a finding a person closed")
	}
}

// D-630 through the service: open findings close with history, audit and a status_changed event that notify ignores; a person's
// decision keeps its status; Stop ignoring reopens only what Ignore closed. A risk acceptance of a device nobody watches does not
// expire (no alert) until the device is watched again.
func TestService_IgnoreClosesOpenFindingsAndKeepsDecisions(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.feeds.vulns = append(e.feeds.vulns, Vuln{CVE: "CVE-2024-0001", Vendor: "QNAP", Product: "Photo Station"})
	res, err := e.svc.OnMatchChanged(t.Context(), "a-1")
	if err != nil || len(res.Created) != 2 {
		t.Fatalf("seed: %+v %v", res, err)
	}
	open, decided := res.Created[0], res.Created[1]
	if _, err := e.svc.SetStatus(t.Context(), decided, ActionFalsePositive, "not this model", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	e.pub.take()

	n, err := e.svc.OnAssetIgnored(t.Context(), "a-1", "it@acme.example")
	if err != nil || n != 1 {
		t.Fatalf("ignore closed %d, %v", n, err)
	}
	if ev := e.pub.take(); len(ev) != 1 || ev[0].Payload != (StatusChangedEvent{FindingID: open, From: StatusSuspected, To: StatusNotRelevant, Reason: ReasonDeviceIgnored}) {
		t.Fatalf("events = %+v", ev)
	}
	if r, _ := e.svc.Get(t.Context(), open); r.Status != StatusNotRelevant || r.ResolutionNote != "Closed by Vedette: the device was ignored by it@acme.example." {
		t.Fatalf("closed = %+v", r.Finding)
	}
	if r, _ := e.svc.Get(t.Context(), decided); r.Status != StatusFalsePositive || r.ResolutionNote != "not this model" {
		t.Fatalf("a person's decision changed: %+v", r.Finding)
	}
	if e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.status' AND detail LIKE '%device_ignored%'`) != 1 {
		t.Fatal("no audit row for the close")
	}
	if n, _ := e.svc.OnAssetIgnored(t.Context(), "a-1", "it@acme.example"); n != 0 {
		t.Fatalf("ignoring again closed %d", n)
	}

	n, err = e.svc.OnAssetUnignored(t.Context(), "a-1", "it@acme.example")
	if err != nil || n != 1 {
		t.Fatalf("stop ignoring reopened %d, %v", n, err)
	}
	if ev := e.pub.take(); len(ev) != 1 || ev[0].Payload != (StatusChangedEvent{FindingID: open, From: StatusNotRelevant, To: StatusSuspected, Reason: ReasonDeviceWatched}) {
		t.Fatalf("events = %+v", ev)
	}
	if r, _ := e.svc.Get(t.Context(), decided); r.Status != StatusFalsePositive {
		t.Fatalf("Stop ignoring reopened a person's decision: %+v", r.Finding)
	}

	// a risk acceptance of an ignored device holds past its day, then expires once the device is watched again
	until := dayOf(t0).AddDate(0, 0, 1)
	if _, _, err := e.svc.setStatusMany(t.Context(), []string{open}, ActionAcceptRisk, "March window", "it@acme.example", until); err != nil {
		t.Fatal(err)
	}
	a1 := e.inv.match["a-1"]
	e.inv.mu.Lock()
	delete(e.inv.match, "a-1") // the inventory no longer matches it: ignored
	e.inv.mu.Unlock()
	e.advance(3 * 24 * time.Hour)
	if r, err := e.svc.Reconcile(t.Context()); err != nil || r.Expired != 0 || r.Orphans != 0 {
		t.Fatalf("reconcile while ignored = %+v %v", r, err)
	}
	e.inv.mu.Lock()
	e.inv.match["a-1"] = a1
	e.inv.mu.Unlock()
	if r, err := e.svc.Reconcile(t.Context()); err != nil || r.Expired != 1 {
		t.Fatalf("reconcile once watched = %+v %v", r, err)
	}
}
