package findings

import (
	"errors"
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
	e.feeds.vulns = append(e.feeds.vulns, Vuln{CVE: "CVE-2024-0001", Vendor: "QNAP", Product: "Photo Station", HasTemplate: true})
	res, err := e.svc.OnMatchChanged(t.Context(), "a-1")
	if err != nil || len(res.Created) != 2 {
		t.Fatalf("seed: %+v %v", res, err)
	}
	open, decided := res.Created[0], res.Created[1]
	if _, err := e.svc.SetStatus(t.Context(), decided, ActionFalsePositive, "not this model", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	if n, _ := e.svc.OnAssetIgnored(t.Context(), "a-1", "it@acme.example"); n != 0 {
		t.Fatalf("an event for a device that is not ignored (any more) closed %d", n) // checked inside the write (review r1 L3)
	}
	e.ignoreA1(true)

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

	e.ignoreA1(false)
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
	e.ignoreA1(true)
	e.advance(3 * 24 * time.Hour)
	if r, err := e.svc.Reconcile(t.Context()); err != nil || r.Expired != 0 || r.Orphans != 0 {
		t.Fatalf("reconcile while ignored = %+v %v", r, err)
	}
	if r, _ := e.svc.Get(t.Context(), decided); r.Status != StatusFalsePositive {
		t.Fatalf("the reconcile of an ignored device changed a person's decision: %+v", r.Finding)
	}
	e.ignoreA1(false)
	if r, err := e.svc.Reconcile(t.Context()); err != nil || r.Expired != 1 {
		t.Fatalf("reconcile once watched = %+v %v", r, err)
	}
}

// ignoreA1 says the test device a-1 is ignored (or watched again) as the inventory does: in IgnoredIDs/IsIgnored and out of
// MatchInput/AssetIDs.
func (e *env) ignoreA1(on bool) {
	const id = "a-1"
	e.inv.mu.Lock()
	defer e.inv.mu.Unlock()
	if e.inv.ignored == nil {
		e.inv.ignored = map[string]bool{}
	}
	if e.parked == nil {
		e.parked = map[string]Asset{}
	}
	if on {
		e.inv.ignored[id] = true
		e.parked[id] = e.inv.match[id]
		delete(e.inv.match, id)
		return
	}
	delete(e.inv.ignored, id)
	if a, ok := e.parked[id]; ok {
		e.inv.match[id] = a
	}
}

// D-630, review r1 M2 of #945: the hourly reconcile does the work of a lost inventory.asset.ignored (close the open findings of an
// ignored device, no notice) and of a lost .unignored (reopen what Ignore closed on a watched device); a match that raced the Ignore
// writes nothing (L3).
func TestService_ReconcileHealsALostIgnoreEitherWay(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.feeds.vulns = append(e.feeds.vulns, Vuln{CVE: "CVE-2024-0001", Vendor: "QNAP", Product: "Photo Station", HasTemplate: true})
	res, err := e.svc.OnMatchChanged(t.Context(), "a-1")
	if err != nil || len(res.Created) != 2 {
		t.Fatalf("seed: %+v %v", res, err)
	}
	asset := e.inv.match["a-1"]
	e.pub.take()
	e.ignoreA1(true) // the event is lost
	if up, err := e.svc.UpsertFromMatch(t.Context(), asset, e.feeds.vulns); err != nil || len(up.Created) != 0 {
		t.Fatalf("a match read before the Ignore wrote %+v %v", up, err)
	}
	r, err := e.svc.Reconcile(t.Context())
	if err != nil || r.IgnoreHealed != 2 || r.Orphans != 0 {
		t.Fatalf("reconcile of an ignored device = %+v %v", r, err)
	}
	for _, id := range res.Created {
		if f, _ := e.svc.Get(t.Context(), id); !f.ClosedForIgnore() || f.ResolutionNote != IgnoredNote+"." {
			t.Fatalf("not closed for the ignore: %+v", f.Finding)
		}
	}
	for _, ev := range e.pub.take() {
		if p, ok := ev.Payload.(StatusChangedEvent); !ok || p.Reason != ReasonDeviceIgnored {
			t.Fatalf("event %+v", ev)
		}
	}
	if r, err := e.svc.Reconcile(t.Context()); err != nil || r.IgnoreHealed != 0 {
		t.Fatalf("a second pass = %+v %v", r, err)
	}
	e.ignoreA1(false) // the event is lost again
	if r, err := e.svc.Reconcile(t.Context()); err != nil || r.IgnoreHealed != 2 {
		t.Fatalf("reconcile of a watched device = %+v %v", r, err)
	}
	for _, id := range res.Created {
		if f, _ := e.svc.Get(t.Context(), id); !f.Status.Open() {
			t.Fatalf("not reopened: %+v", f.Finding)
		}
	}
}

// Review r2 N1 of #945: when the ignored devices cannot be read the hourly pass still matches the watched devices (and says the
// error), and only skips what needs that list: no ignore close, no orphan pass (an ignored device would look deleted).
func TestService_ReconcileWithoutTheIgnoredListStillMatchesWatchedDevices(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.feeds.vulns = append(e.feeds.vulns, Vuln{CVE: "CVE-2024-0001", Vendor: "QNAP", Product: "Photo Station", HasTemplate: true})
	// review r1 L3 of #948: an ignored device (a-2, still known to the inventory) and a deleted one (a-9) with open findings
	seed := func(id string) {
		t.Helper()
		a := nas("6.1.1")
		a.ID = id
		e.inv.mu.Lock()
		e.inv.match[id] = a
		e.inv.mu.Unlock()
		if res, err := e.svc.OnMatchChanged(t.Context(), id); err != nil || len(res.Created) != 2 {
			t.Fatalf("seed %s: %+v %v", id, res, err)
		}
		e.inv.mu.Lock()
		delete(e.inv.match, id) // out of AssetIDs and MatchInput, as the inventory leaves an ignored or deleted device out
		e.inv.mu.Unlock()
	}
	seed("a-2")
	seed("a-9")
	e.inv.mu.Lock()
	e.inv.assets["a-2"] = AssetView{ID: "a-2", IP: "192.168.10.22", Kind: "phone"} // ignored: the inventory still has it (Assets)
	e.inv.ignored = map[string]bool{"a-2": true}
	e.inv.ignoredErr = errors.New("disk busy")
	e.inv.mu.Unlock()
	r, err := e.svc.Reconcile(t.Context())
	if err == nil || !strings.Contains(err.Error(), "disk busy") {
		t.Fatalf("the failed read is not reported: %v", err)
	}
	if r.Devices != 1 || r.Created != 2 || r.IgnoreHealed != 0 {
		t.Fatalf("reconcile without the ignored list = %+v", r)
	}
	if r.Orphans != 2 || e.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'a-9'`) != 0 {
		t.Fatalf("the deleted device's findings stay: %+v", r)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'a-2' AND status = 'suspected'`); n != 2 {
		t.Fatalf("the ignored device's findings = %d open, want 2 left for the next pass (never removed, not closed without the list)", n)
	}
	e.inv.mu.Lock()
	e.inv.ignoredErr = nil
	e.inv.mu.Unlock()
	if r, err := e.svc.Reconcile(t.Context()); err != nil || r.IgnoreHealed != 2 || r.Orphans != 0 {
		t.Fatalf("the next pass = %+v %v", r, err)
	}
}

// Review r2 N3 of #945: a scan result that lands after the Ignore (the run started before) leaves the closed finding as it is: the
// same record back, no history row, no event.
func TestService_AScanResultAfterTheIgnoreChangesNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.feeds.vulns = append(e.feeds.vulns, Vuln{CVE: "CVE-2024-0001", Vendor: "QNAP", Product: "Photo Station", HasTemplate: true})
	res, err := e.svc.OnMatchChanged(t.Context(), "a-1")
	if err != nil || len(res.Created) == 0 {
		t.Fatalf("seed: %+v %v", res, err)
	}
	e.ignoreA1(true)
	if n, err := e.svc.OnAssetIgnored(t.Context(), "a-1", "it@acme.example"); err != nil || n == 0 {
		t.Fatalf("ignore closed %d, %v", n, err)
	}
	before, err := e.svc.Get(t.Context(), res.Created[0])
	if err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	got, err := e.svc.ConfirmFromScan(t.Context(), "a-1", before.CVE, Evidence{Template: before.CVE, CheckedAt: t0, Summary: "matched"})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := e.svc.Get(t.Context(), before.ID)
	if got.Status != StatusNotRelevant || after.Status != StatusNotRelevant || len(after.History) != len(before.History) || !after.ClosedForIgnore() {
		t.Fatalf("a scan after the Ignore changed the finding: returned %+v, stored %+v", got.Finding, after.Finding)
	}
	if ev := e.pub.take(); len(ev) != 0 {
		t.Fatalf("events = %+v", ev)
	}
}
