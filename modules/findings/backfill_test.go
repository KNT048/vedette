package findings

import (
	"slices"
	"testing"
	"time"
)

// The first full pass after the device-version rule arrived: open findings that the rule alone confirms are recorded in their
// history but send no status change each; the pass ends with one summary (findings, devices, CVEs), and afterwards a finding the
// device's stated version confirms is told on its own again. A second pass sends no second summary.
func TestReconcile_FirstPassSendsOneSummaryNotOneNoticeEach(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	agentNAS := nas("6.1.1")
	agentNAS.Software[0].Source = "agent"
	qnap := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.1.2"}})
	qnap.DateAdded, qnap.Published = fortiVulns()[0].DateAdded, fortiVulns()[0].Published
	vulns := append(fortiVulns(), qnap)
	e.feeds.vulns = vulns
	fw := fortiSNMP("7.2.13")
	fw.ID = "a-2"
	e.inv.mu.Lock()
	e.inv.match = map[string]Asset{"a-1": agentNAS, "a-2": fw}
	e.inv.mu.Unlock()

	// before the upgrade: the same devices made suspected findings (a person's entry, nmap's banner), as the old rule did
	banner := fortiRow("nmap")
	banner.ID = "a-2"
	typed := nas("6.1.1")
	typed.Software[0].Source = "manual"
	for _, a := range []Asset{typed, banner} {
		if _, err := e.svc.UpsertFromMatch(t.Context(), a, vulns); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE status = 'suspected'`); n != 3 {
		t.Fatalf("suspected before: %d", n)
	}
	e.pub.take()

	e.advance(time.Hour)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE status = 'confirmed' AND basis = 'version'`); n != 3 {
		t.Fatalf("confirmed after the first pass: %d", n)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding_history WHERE action = 'confirmed' AND user = 'system' AND note = '` + DeviceConfirmedNote + `'`); n != 3 {
		t.Fatalf("history rows: %d", n)
	}
	var summaries []DeviceBackfillEvent
	for _, p := range e.pub.take() {
		switch p.Name {
		case EventStatusChanged:
			t.Fatalf("a finding the new rule alone confirmed sent its own event: %+v", p.Payload)
		case EventDeviceBackfill:
			summaries = append(summaries, p.Payload.(DeviceBackfillEvent))
		}
	}
	if len(summaries) != 1 {
		t.Fatalf("summaries %+v", summaries)
	}
	s := summaries[0]
	if s.Findings != 3 || s.Devices != 2 || s.CVEs != 3 || len(s.FindingIDs) != 3 || s.Severity == "" ||
		!slices.Contains(s.CVEList, "CVE-2025-61624") || !slices.Contains(s.CVEList, "CVE-2022-27593") {
		t.Fatalf("summary %+v", s)
	}
	if n := e.count(`SELECT (SELECT count(*) FROM fnd_device_backfill_pending) + (SELECT count(*) FROM fnd_device_backfill)`); n != 0 {
		t.Fatalf("the first-pass marker and list are not empty: %d", n)
	}

	// a second pass: nothing more to tell
	e.advance(time.Hour)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if ev := e.pub.take(); len(ev) != 0 {
		t.Fatalf("second pass sent %+v", ev)
	}

	// after the first pass a change of the device's stated version is a real change: told on its own
	e.inv.mu.Lock()
	e.inv.match["a-2"] = banner
	e.inv.mu.Unlock()
	e.advance(time.Hour)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	e.inv.mu.Lock()
	e.inv.match["a-2"] = fw
	e.inv.mu.Unlock()
	e.advance(time.Hour)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	var told []StatusChangedEvent
	for _, p := range e.pub.take() {
		if p.Name == EventDeviceBackfill {
			t.Fatalf("a second summary: %+v", p.Payload)
		}
		if p.Name == EventStatusChanged {
			told = append(told, p.Payload.(StatusChangedEvent))
		}
	}
	if len(told) != 2 || told[0].To != StatusConfirmed || told[0].Reason != ReasonDeviceVersion {
		t.Fatalf("events after the first pass %+v", told)
	}
}

// A new box: the first pass has nothing to summarise, sends nothing and removes the marker.
func TestReconcile_FirstPassOnANewBoxSendsNoSummary(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, p := range e.pub.take() {
		if p.Name == EventDeviceBackfill {
			t.Fatalf("summary on a new box: %+v", p.Payload)
		}
	}
	if n := e.count(`SELECT count(*) FROM fnd_device_backfill_pending`); n != 0 {
		t.Fatalf("marker left: %d", n)
	}
}
