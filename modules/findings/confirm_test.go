package findings

import (
	"errors"
	"strings"
	"testing"
	"time"
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
	ev := e.pub.take()
	if len(ev) != 1 || ev[0].Payload != (StatusChangedEvent{FindingID: id, From: StatusSuspected, To: StatusConfirmed}) {
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

// The matcher never takes the confirmation back: a re-run with version evidence, an agent's row or no match at all leaves the finding confirmed.
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
	// the same device now runs a version outside the range: a suspected finding would close, this one stays
	if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.2"), []Vuln{vuln}); err != nil {
		t.Fatal(err)
	}
	r, _ := e.svc.Get(t.Context(), id)
	if r.Status != StatusConfirmed || r.Basis != BasisPerson {
		t.Fatalf("the matcher changed a person's confirmation: %+v", r)
	}
	for _, a := range e.auditActions() {
		if a == "findings.basis_raised" || a == "findings.auto_resolved" {
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
	if h := r.History[len(r.History)-1]; h.Action != "reopened" || h.User != "it@acme.example" || !strings.Contains(h.Note, "Confirmation undone by it@acme.example") {
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

// The sentence says, from real facts, why a finding is only suspected and what would confirm it.
func TestWhySuspected(t *testing.T) {
	t.Parallel()
	snmp := &KnownVersion{Software: "edge firewall OS", Version: "7.2.13", Source: VersionBySNMP}
	for _, c := range []struct {
		name            string
		basis           Basis
		known           *KnownVersion
		checkKnown, has bool
		reach           string
		want            string
	}{
		{"outside the ranges", BasisVersion, snmp, true, true, ScanOutside,
			"Version match only: The device's own SNMP answer states edge firewall OS 7.2.13, inside NVD's affected range. A vulnerability check can confirm it, but none has run: the device is outside the confirmed scan ranges. Or confirm it yourself."},
		{"scan off", BasisVersion, snmp, true, true, ScanOff,
			"Version match only: The device's own SNMP answer states edge firewall OS 7.2.13, inside NVD's affected range. A vulnerability check can confirm it, but none has run: network scanning is off for this device. Or confirm it yourself."},
		{"no check", BasisVersion, snmp, true, false, ScanOutside,
			"Version match only: The device's own SNMP answer states edge firewall OS 7.2.13, inside NVD's affected range. A vulnerability check would confirm it, but none exists for this CVE, so only a person can. Or confirm it yourself."},
		{"covered", BasisVersion, &KnownVersion{Software: "web server", Version: "2.4.1", Source: VersionByScan}, true, true, ScanCovered,
			"Version match only: A network scan (a guess from what a service answers) states web server 2.4.1, inside NVD's affected range. A vulnerability check can confirm it: a scan of this device runs it. Or confirm it yourself."},
		{"not known: says less", BasisVersion, snmp, false, false, "",
			"Version match only: The device's own SNMP answer states edge firewall OS 7.2.13, inside NVD's affected range. Or confirm it yourself."},
		{"scan state not known", BasisVersion, snmp, true, true, "",
			"Version match only: The device's own SNMP answer states edge firewall OS 7.2.13, inside NVD's affected range. A vulnerability check can confirm it. Or confirm it yourself."},
		{"typed by a person", BasisVersion, &KnownVersion{Software: "web server", Version: "2.4.1", Source: VersionByManual}, false, false, "",
			"Version match only: A person (entered on the Devices page) states web server 2.4.1, inside NVD's affected range. Or confirm it yourself."},
		{"product only", BasisProduct, nil, true, false, "",
			"Product match only: the device runs the product, but its version is not known, so it could not be compared with NVD's affected range. A vulnerability check would confirm it, but none exists for this CVE, so only a person can. Or confirm it yourself."},
	} {
		if got := WhySuspected(c.basis, c.known, c.checkKnown, c.has, c.reach); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}
