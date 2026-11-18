package findings

import (
	"errors"
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

// The first pass with an exploited list ends the first pass even when something failed (a device that fails every pass must not
// silence every later confirmation); a pass without the list does not, but a box with no finding at all drops the marker even then,
// so a fresh install never sends the summary.
func TestReconcile_FirstPassEndsWithTheExploitedList(t *testing.T) {
	t.Parallel()
	marker := func(e *env) int { return e.count(`SELECT count(*) FROM fnd_device_backfill_pending`) }
	fresh := newEnv(t)
	fresh.feeds.vulns = nil // no exploited list yet and no finding: the marker goes
	if _, err := fresh.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := marker(fresh); n != 0 {
		t.Fatalf("a box with no finding kept the marker: %d", n)
	}

	e := newEnv(t)
	e.seed() // a finding exists
	e.feeds.vulns = nil
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := marker(e); n != 1 {
		t.Fatalf("a pass with no exploited list ended the first pass: %d", n)
	}
	e.feeds.vulns = []Vuln{qnapScanned()}
	e.inv.mu.Lock()
	e.inv.ignoredErr = errors.New("inventory busy")
	e.inv.mu.Unlock()
	if _, err := e.svc.Reconcile(t.Context()); err == nil {
		t.Fatal("the pass with an error reported none")
	}
	if n := marker(e); n != 0 {
		t.Fatalf("a pass with the exploited list and an error kept the marker: %d", n)
	}
}

// A device that fails every pass: the first pass with the exploited list still sends the summary of what it recorded and ends; the
// next confirmation by a device's stated version is told on its own.
func TestReconcile_ADeviceThatAlwaysFailsDoesNotHoldTheMarker(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	vulns := fortiVulns()
	e.feeds.vulns = vulns
	banner := fortiRow("nmap")
	if _, err := e.svc.UpsertFromMatch(t.Context(), banner, vulns); err != nil { // suspected before the rule
		t.Fatal(err)
	}
	e.pub.take()
	e.inv.mu.Lock()
	e.inv.match = map[string]Asset{"a-1": fortiSNMP("7.2.13"), "a-bad": {ID: "a-bad", Name: "broken"}}
	e.inv.matchErr = map[string]error{"a-bad": errors.New("the device cannot be read")}
	e.inv.mu.Unlock()
	e.advance(time.Hour)
	if _, err := e.svc.Reconcile(t.Context()); err == nil {
		t.Fatal("the failing device reported no error")
	}
	var summaries int
	for _, p := range e.pub.take() {
		switch p.Name {
		case EventStatusChanged:
			t.Fatalf("a first-pass confirmation sent its own event: %+v", p.Payload)
		case EventDeviceBackfill:
			summaries++
			if s := p.Payload.(DeviceBackfillEvent); s.Findings != 2 || s.Devices != 1 {
				t.Fatalf("summary %+v", s)
			}
		}
	}
	if summaries != 1 || e.count(`SELECT count(*) FROM fnd_device_backfill_pending`) != 0 {
		t.Fatalf("summaries %d, marker %d", summaries, e.count(`SELECT count(*) FROM fnd_device_backfill_pending`))
	}
	// later: the banner again, then SNMP again: told on its own, while a-bad still fails
	e.inv.mu.Lock()
	e.inv.match["a-1"] = banner
	e.inv.mu.Unlock()
	e.advance(time.Hour)
	_, _ = e.svc.Reconcile(t.Context())
	e.pub.take()
	e.inv.mu.Lock()
	e.inv.match["a-1"] = fortiSNMP("7.2.13")
	e.inv.mu.Unlock()
	e.advance(time.Hour)
	_, _ = e.svc.Reconcile(t.Context())
	var told int
	for _, p := range e.pub.take() {
		if p.Name == EventStatusChanged && p.Payload.(StatusChangedEvent).Reason == ReasonDeviceVersion && p.Payload.(StatusChangedEvent).To == StatusConfirmed {
			told++
		}
	}
	if told != 2 {
		t.Fatalf("confirmations after the first pass told: %d", told)
	}
}
