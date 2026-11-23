package findings

import (
	"testing"
	"time"
)

// Auto-resolve in the matcher: a proof is listed only for a CVE the device has a finding for, and only when every software
// of the product is proved outside (a second copy that needs a version proves nothing).
func TestMatchAsset_NotAffectedNeedsEverySoftwareProved(t *testing.T) {
	t.Parallel()
	v := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})
	have := map[string]bool{v.CVE: true}
	if r := MatchAsset(nas("6.2.0"), []Vuln{v}, have, t0); len(r.NotAffected) != 1 || r.NotAffected[0].CVE != v.CVE {
		t.Fatalf("one software outside: %+v", r)
	}
	if r := MatchAsset(nas("6.2.0"), []Vuln{v}, nil, t0); len(r.NotAffected) != 0 {
		t.Fatalf("no finding to close, yet listed: %+v", r)
	}
	a := nas("6.2.0")
	a.Software = append(a.Software, Software{ID: "s-2", Display: "Photo Station", Vendor: "QNAP", Product: "Photo Station", KevKeys: []string{"qnap|photo station"}})
	if r := MatchAsset(a, []Vuln{v}, have, t0); len(r.NotAffected) != 0 {
		t.Fatalf("a second copy without a version still needs deciding: %+v", r)
	}
}

// Auto-resolve and the confirmations that hold against it (the stored lifecycle, not the matcher alone).

// A finding a safe check confirmed stays open when only the data says its version is fixed (the ranges moved, the device did not):
// the check saw the flaw on that version. The same correction closes an unconfirmed finding.
func TestAutoResolve_AScanConfirmedFindingStaysOpenOnAFixedVersion(t *testing.T) {
	t.Parallel()
	for _, confirmed := range []bool{true, false} {
		e := newEnv(t)
		e.feeds.vulns = []Vuln{qnapRanged}
		if res, err := e.svc.UpsertFromMatch(t.Context(), e.scanDevice("6.1.1", "agent"), e.feeds.vulns); err != nil || len(res.Created) != 1 {
			t.Fatalf("%+v %v", res, err)
		}
		if confirmed {
			e.advance(time.Hour)
			if _, err := e.svc.ConfirmFromScan(t.Context(), "a-1", qnapRanged.CVE, scanEv("t1")); err != nil {
				t.Fatal(err)
			}
		}
		e.advance(time.Hour)
		fixedAt := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.1.1"}}) // 6.1.1 is now the fixed release
		e.feeds.vulns = []Vuln{fixedAt}
		if _, err := e.svc.UpsertFromMatch(t.Context(), e.scanDevice("6.1.1", "agent"), e.feeds.vulns); err != nil {
			t.Fatal(err)
		}
		f := e.only(t)
		switch {
		case confirmed && (f.State != StateOpen || f.Verified != VerifiedScan):
			t.Errorf("scan-confirmed on a version the data now calls fixed: %+v, want open and confirmed by the scan", f)
		case !confirmed && (f.State != StateHandled || f.Via != ViaDataCorrected):
			t.Errorf("unconfirmed on a version the data now calls fixed: %+v, want closed as data corrected", f)
		}
	}
}

// A person who confirmed a finding and later says its software is not installed closes it: the "not installed" mark is the person's
// word about the device, and it outranks their earlier confirmation. The finding is not relevant, under the marker's name.
func TestAutoResolve_NotInstalledClosesAPersonConfirmedFinding(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	sw := Software{ID: "s-1", Display: "App", Vendor: "Acme", Product: "App", Version: "1.0", Source: "nmap", SeenAt: t0}
	a := Asset{ID: "a-1", Name: "host-1", Software: []Software{sw}}
	e.matchPass(t, a, MatchResult{New: []Match{versionMatch(sw)}})
	id := e.only(t).ID
	if _, err := e.svc.Verify(t.Context(), id, "logged in, the affected build runs", "anna@example.com"); err != nil {
		t.Fatal(err)
	}
	if f := e.only(t); f.Verified != VerifiedPerson {
		t.Fatalf("after the confirmation: %+v", f)
	}
	e.advance(time.Hour)
	sw.MarkedBy = "ben@example.com"
	a.Software, a.NotInstalled = nil, []Software{sw}
	e.matchPass(t, a, MatchResult{})
	f := e.only(t)
	if f.State != StateHandled || f.Resolution != ResolutionNotRelevant || f.Via != ViaNotInstalled || f.ResolvedBy != "ben@example.com" {
		t.Fatalf("person-confirmed, then marked not installed: %+v, want not relevant via not installed by the marker", f)
	}
}

// A person who confirmed a finding keeps it open when the match can no longer decide the CVE (its platform is not known any more:
// the OS set on the device was cleared) and asks instead: the person's word outranks a question, as a safe check's proof does; only
// Undo takes it back. The same question closes an unconfirmed finding as data corrected.
func TestAutoResolve_APlatformQuestionLeavesAPersonConfirmedFindingOpen(t *testing.T) {
	t.Parallel()
	for _, confirmed := range []bool{true, false} {
		e := newEnv(t)
		sw := sshRow("9.0p1", "protocol 2.0", "nmap") // a scan's banner: suspected
		sw.SeenAt = t0
		alpine := Asset{ID: "a-1", Name: "gw-alpine", ManualOS: "Alpine Linux 3.15", Software: []Software{sw}} // a branch with no fix: NVD's range decides
		vulns := []Vuln{sshhole()}
		if res, err := e.svc.UpsertFromMatch(t.Context(), alpine, vulns); err != nil || len(res.Created) != 1 {
			t.Fatalf("%+v %v", res, err)
		}
		if confirmed {
			if _, err := e.svc.Verify(t.Context(), e.only(t).ID, "logged in, the affected build runs", "anna@example.com"); err != nil {
				t.Fatal(err)
			}
		}
		e.advance(time.Hour)
		unknown := alpine
		unknown.ManualOS = "" // nothing names the platform now: the CVE is asked, not matched
		if _, err := e.svc.UpsertFromMatch(t.Context(), unknown, vulns); err != nil {
			t.Fatal(err)
		}
		qs, err := e.svc.Questions(t.Context(), "a-1")
		if err != nil || len(qs) != 1 || qs[0].Kind != QuestionPlatform {
			t.Fatalf("questions %+v %v, want the platform question", qs, err)
		}
		f := e.only(t)
		switch {
		case confirmed && (f.State != StateOpen || f.Verified != VerifiedPerson || !f.Detected):
			t.Errorf("person-confirmed, then a platform question: %+v, want open, detected and confirmed by the person", f)
		case !confirmed && (f.State != StateHandled || f.Via != ViaDataCorrected):
			t.Errorf("unconfirmed, then a platform question: %+v, want closed as data corrected", f)
		}
	}
}
