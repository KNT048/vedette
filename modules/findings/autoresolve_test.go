package findings

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

// D-530: a suspected finding whose version the matcher proves outside every NVD range of its CVE is closed by Vedette
// (not_relevant, system, reason not_affected_version, history, audit findings.auto_resolved, status_changed), once;
// it reopens by itself when a later match says the device is affected again.
func TestContract_D530_ProvedNotAffectedClosesAndReopens(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := []Vuln{qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})}
	run := func(ver string) {
		t.Helper()
		e.advance(time.Minute)
		if _, err := e.svc.UpsertFromMatch(t.Context(), nas(ver), v); err != nil {
			t.Fatal(err)
		}
	}
	run("6.1.1") // inside: a version finding
	e.pub.take()
	run("6.2.0") // updated: proved outside
	r, err := loadByPair(t.Context(), e.db.Reader(), "a-1", "CVE-2022-27593")
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusNotRelevant || r.ResolvedBy != SystemUser || r.ResolutionReason != ReasonNotAffectedVersion ||
		!strings.HasPrefix(r.ResolutionNote, "Not affected: version 6.2.0 of Photo Station is outside every version range NVD lists for CVE-2022-27593.") {
		t.Fatalf("finding = %+v", r.Finding)
	}
	if ev := e.pub.take(); len(ev) != 1 || ev[0].Name != EventStatusChanged || ev[0].Payload.(StatusChangedEvent).To != StatusNotRelevant {
		t.Fatalf("events = %+v", ev)
	}
	run("6.2.0") // said once
	if n := e.count(`SELECT count(*) FROM fnd_finding_history WHERE action = 'not_relevant' AND user = 'system'`); n != 1 {
		t.Fatalf("history rows %d", n)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.auto_resolved'`); n != 1 {
		t.Fatalf("audit rows %d", n)
	}
	run("6.0.0") // a downgrade: affected again
	r, _ = loadByPair(t.Context(), e.db.Reader(), "a-1", "CVE-2022-27593")
	if r.Status != StatusSuspected || r.ResolvedBy != "" || r.ResolutionReason != "" || r.ResolutionNote != "" {
		t.Fatalf("not reopened: %+v", r.Finding)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding_history WHERE action = 'matches_again' AND note LIKE '%reopened%'`); n != 1 {
		t.Fatalf("matches_again rows %d", n)
	}
	if ev := e.pub.take(); len(ev) != 1 || ev[0].Payload.(StatusChangedEvent).To != StatusSuspected {
		t.Fatalf("events = %+v", ev)
	}
}

// D-530: only a positive proof closes. No NVD data, an unreadable version, no version, a person's own closing, a
// scan confirmation, and a No that rests only on the "Multiple Products" naming rule never close or reopen anything.
func TestContract_D530_OnlyAProofCloses(t *testing.T) {
	t.Parallel()
	ranged := []Vuln{qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})}
	open := func(t *testing.T, e *env) Record {
		t.Helper()
		r, err := loadByPair(t.Context(), e.db.Reader(), "a-1", "CVE-2022-27593")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for name, tc := range map[string]struct {
		ver   string
		vulns []Vuln
	}{
		"no NVD data":          {"6.2.0", []Vuln{qnapVuln()}},
		"unreadable version":   {"6.2(4)M3", ranged},
		"no version":           {"", ranged},
		"placeholder version":  {"0", ranged},
		"words without number": {"latest", ranged},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), ranged); err != nil {
				t.Fatal(err)
			}
			if _, err := e.svc.UpsertFromMatch(t.Context(), nas(tc.ver), tc.vulns); err != nil {
				t.Fatal(err)
			}
			if r := open(t, e); r.Status != StatusSuspected {
				t.Fatalf("closed without a proof: %+v", r.Finding)
			}
		})
	}
	t.Run("a person's not_relevant is not reopened by a match", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), ranged); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.SetStatus(t.Context(), open(t, e).ID, ActionNotRelevant, "lab device", "admin@example.test"); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), ranged); err != nil {
			t.Fatal(err)
		}
		if r := open(t, e); r.Status != StatusNotRelevant || r.ResolvedBy != "admin@example.test" {
			t.Fatalf("%+v", r.Finding)
		}
	})
	t.Run("a scan-confirmed finding is never closed by the version", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), ranged); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.ConfirmFromScan(t.Context(), "a-1", "CVE-2022-27593", Evidence{Template: "CVE-2022-27593", CheckedAt: t0}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.2.0"), ranged); err != nil {
			t.Fatal(err)
		}
		if r := open(t, e); r.Status != StatusConfirmed {
			t.Fatalf("%+v", r.Finding)
		}
	})
	t.Run("a scan reopens what Vedette closed", func(t *testing.T) {
		t.Parallel()
		f := Finding{Status: StatusSuspected, Basis: BasisVersion, Severity: SeverityHigh, Confidence: ConfVersion}
		f, _, ok := f.AutoResolve("Not affected", t0)
		if !ok {
			t.Fatal("not closed")
		}
		out, err := f.ConfirmFromScan(Evidence{Template: "x", CheckedAt: t0}, t0)
		if err != nil || out.Finding.Status != StatusConfirmed || out.Finding.ResolutionReason != "" || out.History[0].Action != "reopened" {
			t.Fatalf("%+v %v", out, err)
		}
	})
}

// D-530 in the matcher: a proof is listed only for a CVE the device has a finding for, and only when every software
// of the product is proved outside (a second copy that needs a version proves nothing).
func TestMatchAsset_D530_NotAffectedNeedsEverySoftwareProved(t *testing.T) {
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

// W3-3: a product-only finding graded higher before D-500 takes the product severity (medium) at the next match, once,
// with an audit line; review H2: product to version raises the severity and says so on the bus.
func TestUpsert_SeverityFollowsTheBasis(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{qnapVuln()}); err != nil {
		t.Fatal(err)
	}
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE fnd_finding SET severity = 'critical'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	for i, want := range []int{1, 0} {
		res, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{qnapVuln()})
		if err != nil || res.Regraded != want {
			t.Fatalf("round %d: %+v %v", i, res, err)
		}
	}
	r, _ := loadByPair(t.Context(), e.db.Reader(), "a-1", "CVE-2022-27593")
	if r.Severity != SeverityMedium || e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.regraded'`) != 1 {
		t.Fatalf("severity %s", r.Severity)
	}
	if ev := e.pub.take(); len(ev) != 0 {
		t.Fatalf("a re-grade down is not news: %+v", ev)
	}
	inside := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})
	inside.Ransomware = true
	if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{inside}); err != nil {
		t.Fatal(err)
	}
	r, _ = loadByPair(t.Context(), e.db.Reader(), "a-1", "CVE-2022-27593")
	if r.Basis != BasisVersion || r.Severity != SeverityCritical {
		t.Fatalf("after the ranges: %s %s", r.Basis, r.Severity)
	}
	if ev := e.pub.take(); len(ev) != 1 || ev[0].Name != EventStatusChanged || ev[0].Payload.(StatusChangedEvent).Severity != SeverityCritical {
		t.Fatalf("events %+v", ev)
	}
}
