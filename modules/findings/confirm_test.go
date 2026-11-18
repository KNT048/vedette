package findings

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/orgtime"
)

// A person confirms a suspected finding: the status, the basis, the history line, the audit row and the event.
func TestConfirmByPerson_WritesHistoryAuditAndEvent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	e.advance(time.Minute)
	r, err := e.svc.ConfirmByPerson(t.Context(), id, "  checked on the web console  ", "it@acme.example")
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusConfirmed || r.Basis != BasisPerson || r.Evidence == nil {
		t.Fatalf("finding = %+v", r)
	}
	h := r.History[len(r.History)-1]
	if h.User != "it@acme.example" || h.Note != "Confirmed by it@acme.example: checked on the web console" {
		t.Fatalf("history = %+v", h)
	}
	if got := e.auditActions(); got[len(got)-1] != "findings.confirm" {
		t.Fatalf("audit = %v", got)
	}
	// no status_changed: a person's own click sends no notice and starts no response
	if ev := e.pub.take(); len(ev) != 0 {
		t.Fatalf("events = %+v", ev)
	}
}

func TestConfirmByPerson_NeedsANoteAndASuspectedFinding(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	before := e.count(`SELECT count(*) FROM core_audit`)
	for _, c := range []struct {
		name, id, note string
		want           *APIError
	}{
		{"no note", id, "  ", ErrConfirmNoteRequired},
		{"two characters", id, "ok", ErrConfirmNoteRequired},
		{"too long", id, strings.Repeat("a", MaxNote+1), ErrNoteTooLong},
		{"unknown", "f-nope", "checked", ErrNotFound},
	} {
		if _, err := e.svc.ConfirmByPerson(t.Context(), c.id, c.note, "it@acme.example"); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	if r, _ := e.svc.Get(t.Context(), id); r.Status != StatusSuspected || r.Basis == BasisPerson || e.count(`SELECT count(*) FROM core_audit`) != before {
		t.Fatalf("a refused confirm changed something: %+v", r)
	}
	if _, err := e.svc.ConfirmByPerson(t.Context(), id, "checked", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ConfirmByPerson(t.Context(), id, "again", "it@acme.example"); !errors.Is(err, ErrNotSuspected) {
		t.Fatalf("a confirmed finding was confirmed again: %v", err)
	}
}

// The matcher never takes the confirmation back: a re-run with version evidence leaves the finding confirmed and its basis person.
func TestConfirmByPerson_MatcherRerunKeepsIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	if _, err := e.svc.ConfirmByPerson(t.Context(), id, "checked", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	e.advance(time.Hour)
	vuln := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.1.2"}})
	if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{vuln}); err != nil {
		t.Fatal(err)
	}
	r, _ := e.svc.Get(t.Context(), id)
	if r.Status != StatusConfirmed || r.Basis != BasisPerson {
		t.Fatalf("the matcher changed a person's confirmation: %+v", r)
	}
	for _, a := range e.auditActions() {
		if a == "findings.basis_raised" {
			t.Fatalf("audit has %s", a)
		}
	}
}

func TestUnconfirmByPerson_ReturnsToSuspectedWithItsOldBasis(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed() // basis product
	if _, err := e.svc.ConfirmByPerson(t.Context(), id, "checked", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	r, err := e.svc.UnconfirmByPerson(t.Context(), id, "it@acme.example")
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusSuspected || r.Basis != BasisProduct {
		t.Fatalf("finding = %+v", r)
	}
	if h := r.History[len(r.History)-1]; h.Action != ActionConfirmUndone || h.User != "it@acme.example" || !strings.Contains(h.Note, "Confirmation undone by it@acme.example") {
		t.Fatalf("history = %+v", h)
	}
	if got := e.auditActions(); got[len(got)-1] != "findings.unconfirm" {
		t.Fatalf("audit = %v", got)
	}
	// nothing to undo now
	if _, err := e.svc.UnconfirmByPerson(t.Context(), id, "it@acme.example"); !errors.Is(err, ErrNotConfirmedByHand) {
		t.Fatalf("err = %v", err)
	}
}

// A scan's proof is not a person's to undo, and a scan over a person's confirmation takes it over (basis scan).
func TestUnconfirmByPerson_RefusesAScansConfirmation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	if _, err := e.svc.ConfirmFromScan(t.Context(), "a-1", "CVE-2022-27593", scanEvidence()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UnconfirmByPerson(t.Context(), id, "it@acme.example"); !errors.Is(err, ErrNotConfirmedByHand) {
		t.Fatalf("err = %v", err)
	}
	if _, err := e.svc.ConfirmByPerson(t.Context(), id, "checked", "it@acme.example"); !errors.Is(err, ErrNotSuspected) {
		t.Fatalf("err = %v", err)
	}
}

// A person-confirmed finding that is closed and reopened is confirmed again, like a scan-confirmed one.
func TestConfirmByPerson_ReopenIsConfirmed(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	if _, err := e.svc.ConfirmByPerson(t.Context(), id, "checked", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetStatus(t.Context(), id, ActionPatched, "updated", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	r, err := e.svc.SetStatus(t.Context(), id, ActionReopen, "", "it@acme.example")
	if err != nil || r.Status != StatusConfirmed || r.Basis != BasisPerson {
		t.Fatalf("reopen = %+v err=%v", r, err)
	}
}

// Home's counts and the list read the status, so a person's confirmation counts as confirmed everywhere.
func TestConfirmByPerson_CountsAsConfirmed(t *testing.T) {
	t.Parallel()
	e, h, _ := sumEnv(t)
	id := e.seed()
	if s := mustSummary(t, h); s.Open.Total != 1 || s.Open.Confirmed != 0 {
		t.Fatalf("before = %+v", s.Open)
	}
	if _, err := e.svc.ConfirmByPerson(t.Context(), id, "checked", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	if s := mustSummary(t, h); s.Open.Total != 1 || s.Open.Confirmed != 1 {
		t.Fatalf("after = %+v", s.Open)
	}
	if n, _ := e.svc.CountByAsset(t.Context()); n["a-1"] != 1 {
		t.Fatalf("count by asset = %v", n)
	}
}

// Every basis the matcher or a person can give is known to the lifecycle checks (the class: a new basis nobody handled).
func TestEveryBasisIsHandledByTheLifecycle(t *testing.T) {
	t.Parallel()
	for _, b := range []Basis{BasisProduct, BasisVersion, BasisPerson, BasisScan} {
		if rank(b) == 0 {
			t.Errorf("basis %q has no rank", b)
		}
		f := Finding{Status: b2status(b), Severity: SeverityHigh, Confidence: 0.9, Basis: b,
			Evidence: &Evidence{Summary: "s", Template: "t", CheckedAt: t0}}
		if err := f.Validate(); err != nil {
			t.Errorf("basis %q: %v", b, err)
		}
		if got, want := f.OpenStatus(), b2status(b); got != want {
			t.Errorf("basis %q reopens to %s, want %s", b, got, want)
		}
	}
}

func b2status(b Basis) Status {
	if b == BasisScan || b == BasisPerson {
		return StatusConfirmed
	}
	return StatusSuspected
}

// The sentence says, from real facts, why a finding is only suspected and what would confirm it: first the automatic ways (the device
// reports its version itself; a safe check, only when one exists for the CVE), last a person.
func TestWhySuspected(t *testing.T) {
	t.Parallel()
	banner := &KnownVersion{Software: "web server", Version: "2.4.49", Source: VersionByScan}
	fresh, old := t0.Add(-7*24*time.Hour-5*time.Hour), t0.Add(-16*24*time.Hour) // a weekly read is fresh; 16 days is not
	snmp := &KnownVersion{Software: "edge firewall OS", Version: "7.2.13", Source: VersionBySNMP, SeenAt: &fresh}
	staleSNMP := &KnownVersion{Software: "edge firewall OS", Version: "7.2.13", Source: VersionBySNMP, SeenAt: &old}
	const scanHead = "Version match only: A network scan (a guess from what a service answers) states web server 2.4.49, inside NVD's affected range."
	const device = " It is confirmed by itself once the device reports its version: turn on SNMP for the device, or install the agent on it."
	const last = " Last, confirm it yourself."
	for _, c := range []struct {
		name            string
		basis           Basis
		known           *KnownVersion
		checkKnown, has bool
		reach           string
		want            string
	}{
		{"outside the ranges", BasisVersion, banner, true, true, ScanOutside,
			scanHead + device + " A safe vulnerability check exists for this CVE: run the check to confirm it (none has run: the device is outside the confirmed scan ranges)." + last},
		{"scan off", BasisVersion, banner, true, true, ScanOff,
			scanHead + device + " A safe vulnerability check exists for this CVE: run the check to confirm it (none has run: network scanning is off)." + last},
		{"no ranges confirmed", BasisVersion, banner, true, true, ScanNoRanges,
			scanHead + device + " A safe vulnerability check exists for this CVE: run the check to confirm it (none has run: no scan ranges are confirmed yet)." + last},
		{"added by hand", BasisVersion, banner, true, true, ScanByHand,
			scanHead + device + " A safe vulnerability check exists for this CVE: run the check to confirm it (none has run: the device was added by hand and is not scanned)." + last},
		{"device scan off", BasisVersion, banner, true, true, ScanDeviceOff,
			scanHead + device + " A safe vulnerability check exists for this CVE: run the check to confirm it (none has run: scanning is turned off for this device)." + last},
		{"no check: never offered", BasisVersion, banner, true, false, ScanOutside,
			scanHead + device + " No safe vulnerability check exists for this CVE." + last},
		{"not known: says less", BasisVersion, banner, false, false, "", scanHead + device + last},
		{"scan state not known", BasisVersion, banner, true, true, "",
			scanHead + device + " A safe vulnerability check exists for this CVE: run the check to confirm it." + last},
		{"typed by a person", BasisVersion, &KnownVersion{Software: "web server", Version: "2.4.1", Source: VersionByManual}, false, false, "",
			"Version match only: A person (entered on the Devices page) states web server 2.4.1, inside NVD's affected range." + device + last},
		{"stated over LLDP", BasisVersion, &KnownVersion{Software: "Junos", Version: "15.1R7.9", Source: VersionByStated}, false, false, "",
			"Version match only: The device's own statement on the network states Junos 15.1R7.9, inside NVD's affected range." + device + last},
		{"the device states it, the range does not settle it", BasisVersion, snmp, true, false, "",
			"Version match only: The device's own SNMP answer states edge firewall OS 7.2.13, inside NVD's affected range, but that range does not clearly cover this release (no end, or listed for another edition or release), so the version alone does not confirm it. No safe vulnerability check exists for this CVE." + last},
		{"the device has not answered SNMP for over a week", BasisVersion, staleSNMP, true, false, "",
			"Version match only: The device's own SNMP answer stated edge firewall OS 7.2.13, inside NVD's affected range, but the device has not answered SNMP since " + orgtime.CalendarDay(old) + ", so that version no longer confirms it. It is confirmed by itself once the device answers SNMP again: check that SNMP is on and reachable for it. No safe vulnerability check exists for this CVE." + last},
		{"product only", BasisProduct, nil, true, false, "",
			"Product match only: the device runs the product, but its version is not known, so it could not be compared with NVD's affected range." + device + " No safe vulnerability check exists for this CVE." + last},
	} {
		if got := WhySuspected(c.basis, c.known, c.checkKnown, c.has, c.reach, t0); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

// A person's confirm does not stop the matcher from closing the finding when the version proves it not affected.
func TestConfirmByPerson_StillAutoResolvesWhenTheSoftwareIsUpdated(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	vuln := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.1.2"}})
	e.advance(time.Hour)
	if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{vuln}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ConfirmByPerson(t.Context(), id, "checked", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	e.advance(time.Hour)
	if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.2"), []Vuln{vuln}); err != nil { // updated: outside the range
		t.Fatal(err)
	}
	r, _ := e.svc.Get(t.Context(), id)
	if r.Status != StatusNotRelevant || r.ResolvedBy != SystemUser || r.ResolutionReason != ReasonNotAffectedVersion {
		t.Fatalf("a person-confirmed finding was not resolved by proof: %+v", r.Finding)
	}
	// and when the version is inside the range again, it reopens as confirmed (the person's word stands)
	e.advance(time.Hour)
	if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{vuln}); err != nil {
		t.Fatal(err)
	}
	if r, _ = e.svc.Get(t.Context(), id); r.Status != StatusConfirmed || r.Basis != BasisPerson {
		t.Fatalf("after matching again: %+v", r.Finding)
	}
}

// Confirm then Undo is not a person's reopen decision: the finding still auto-resolves when the version is fixed.
func TestUnconfirmByPerson_DoesNotStopAutoResolve(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	vuln := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.1.2"}})
	e.advance(time.Hour)
	if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{vuln}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ConfirmByPerson(t.Context(), id, "checked", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UnconfirmByPerson(t.Context(), id, "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	e.advance(time.Hour)
	if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.2"), []Vuln{vuln}); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.svc.Get(t.Context(), id); r.Status != StatusNotRelevant || r.ResolutionReason != ReasonNotAffectedVersion {
		t.Fatalf("Undo stopped the matcher from closing the finding: %+v", r.Finding)
	}
}
