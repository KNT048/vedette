package findings

import (
	"database/sql"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// seedNameOnly gives the device the open product findings the matcher made before D-602 for the matches it now drops (NameOnly):
// suspected, basis product, with the sentence they had. It returns their CVEs.
func seedNameOnly(t testing.TB, e *env, a Asset, vulns []Vuln) []string {
	t.Helper()
	res := MatchAsset(a, vulns, nil, *e.clock)
	var cves []string
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		for _, m := range res.NameOnly {
			m.Evidence.Summary = m.said
			f, h := NewFinding(m, *e.clock)
			r := Record{ID: store.NewID("f"), AssetID: a.ID, CVE: m.CVE, Finding: f, FirstSeen: *e.clock, LastSeen: *e.clock}
			if err := insertRecord(t.Context(), tx, r); err != nil {
				return err
			}
			if err := insertHistory(t.Context(), tx, r.ID, h); err != nil {
				return err
			}
			cves = append(cves, m.CVE)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return cves
}

// desktop55 is the N100's DESKTOP-55UKKFV (2026-11-17): Windows 11 Pro on Insider build 26300, which core/winrel does not list, as
// agent-intake's windowsRow writes it (no release CPE, the product names the build), with a Photo Station row whose version compares.
func desktop55() Asset {
	return Asset{ID: "a-desk", Name: "DESKTOP-55UKKFV", OS: "Microsoft Windows 11 Pro 10.0.26300.9974", Software: []Software{
		{ID: "s-win", Display: "Windows 11 Pro", Vendor: "microsoft", Product: "Windows (build 26300)", Version: "10.0.26300.9974", Source: "agent",
			KevKeys: []string{"microsoft|windows"}},
		{ID: "s-1", Display: "Photo Station", Vendor: "QNAP", Product: "Photo Station", Version: "6.1.1", Source: "agent", KevKeys: []string{"qnap|photo station"}},
	}}
}

// D-602: a Windows build newer than the release table cannot be placed among the releases NVD lists: every Windows KEV entry is "could
// not be checked" (not_comparable), never a finding, and the sentence says why in plain words. A version match on another row stays.
func TestMatchAsset_D602_UnknownWindowsBuildIsUnchecked(t *testing.T) {
	t.Parallel()
	inRange := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})
	vulns := []Vuln{cve0367, cve0210, cve62215, inRange}
	for i := range vulns {
		vulns[i].NVDAnswered = true
	}
	res := MatchAsset(desktop55(), vulns, nil, winNow)
	if len(res.New) != 1 || res.New[0].CVE != inRange.CVE || res.New[0].Basis != BasisVersion {
		t.Fatalf("findings: %+v", res.New)
	}
	var dropped []string
	for _, m := range res.NameOnly {
		dropped = append(dropped, m.CVE)
		if !strings.HasPrefix(m.Evidence.Summary, NameOnlyNote) ||
			!strings.Contains(m.Evidence.Summary, "Windows build 26300 is newer than Vedette's table of Windows releases, so Vedette cannot compare 10.0.26300.9974 with the builds NVD lists for "+m.CVE) ||
			!strings.Contains(m.Evidence.Summary, `now listed under "Could not be checked"`) || jsLen(m.Evidence.Summary) > MaxNote {
			t.Errorf("%s: %q", m.CVE, m.Evidence.Summary)
		}
	}
	slices.Sort(dropped)
	if want := []string{"CVE-2002-0367", "CVE-2004-0210", "CVE-2025-62215"}; !slices.Equal(dropped, want) {
		t.Fatalf("dropped %v, want %v", dropped, want)
	}
	if len(res.Unchecked) != 3 {
		t.Fatalf("unchecked %+v", res.Unchecked)
	}
	for _, u := range res.Unchecked {
		if u.SoftwareID != "s-win" || u.Reason != UncheckedNotComparable || u.Version != "10.0.26300.9974" {
			t.Errorf("unchecked %+v", u)
		}
	}
	// the same device on a build the table knows (26100, 24H2) is read as before: CVE-2025-62215 is a version finding
	known := desktop55()
	known.Software[0].Product, known.Software[0].Version = "Windows 11 24H2", "10.0.26100.6899"
	known.Software[0].CPE = "cpe:2.3:o:microsoft:windows_11_24h2:10.0.26100.6899:*:*:*:*:*:x64:*"
	if r := MatchAsset(known, []Vuln{cve62215}, nil, winNow); len(r.New) != 1 || r.New[0].Basis != BasisVersion {
		t.Fatalf("24H2: %+v", r)
	}
}

// D-602 on CISA's key: whatever made the product-only match (no NVD data, a version NVD's ranges cannot order, NVD naming other
// products), there is no finding; the CVE goes to the could-not-check list with #920's reason. A scannable CVE on a row the agent
// did not report stays a finding (the scan's target); on the agent's row it does not.
func TestMatchAsset_D602_CISAKeyUnknownIsUnchecked(t *testing.T) {
	t.Parallel()
	noData := qnapVuln()
	noData.NVDAnswered = true
	unordered := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "next"}})
	unordered.CVE = "CVE-2023-0002"
	other := qnapVuln(Affected{CPE: "cpe:2.3:a:qnap:qts:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "5.0"}})
	other.CVE = "CVE-2023-0003"
	res := MatchAsset(nas("6.1.1"), []Vuln{noData, unordered, other}, nil, t0)
	if len(res.New)+len(res.Existing) != 0 || len(res.NameOnly) != 3 {
		t.Fatalf("result %+v", res)
	}
	got := map[string]UncheckedReason{}
	for _, u := range res.Unchecked {
		got[u.CVE] = u.Reason
	}
	want := map[string]UncheckedReason{noData.CVE: UncheckedNoNVDData, unordered.CVE: UncheckedNotComparable, other.CVE: UncheckedNotNamed}
	if len(got) != len(want) {
		t.Fatalf("unchecked %v, want %v", got, want)
	}
	for c, r := range want {
		if got[c] != r {
			t.Errorf("%s: %s, want %s", c, got[c], r)
		}
	}
	scan := qnapScanned()
	if r := MatchAsset(nas("6.1.1"), []Vuln{scan}, nil, t0); len(r.New) != 1 || r.New[0].Basis != BasisProduct || len(r.NameOnly) != 0 {
		t.Fatalf("scannable on a scanned row: %+v", r)
	}
	agent := nas("6.1.1")
	agent.Software[0].Source = "agent"
	if r := MatchAsset(agent, []Vuln{scan}, nil, t0); len(r.New) != 0 || len(r.NameOnly) != 1 {
		t.Fatalf("scannable on the agent's row: %+v", r)
	}
	// "every version" (NVD) without a version and a version inside a range stay findings
	every := qnapVuln(Affected{CPE: qnapCPE})
	if r := MatchAsset(nas(""), []Vuln{every}, nil, t0); len(r.New) != 1 || r.New[0].Basis != BasisProduct || len(r.NameOnly) != 0 {
		t.Fatalf("every version, no version: %+v", r)
	}
	if r := MatchAsset(nas("6.1.1"), []Vuln{qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})}, nil, t0); len(r.New) != 1 || r.New[0].Basis != BasisVersion {
		t.Fatalf("version: %+v", r)
	}
}

// D-602, the rule change reaching findings made before it: on the next reconcile an open product finding without version evidence
// closes (not_relevant by the system, the reason in its note and history), with no notice (only a status_changed event notify does
// not send on) and its CVE then under "Could not be checked". A risk acceptance, a person's reopen and a version finding are never
// touched. A second pass changes nothing; a later match that compares a version reopens it.
func TestContract_D602_ReconcileClosesNameOnlyFindings(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	dev := desktop55()
	inRange := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})
	accepted, reopened := cve62215, cve0210
	e.feeds.vulns = []Vuln{cve0367, cve0210, cve62215, inRange}
	e.inv.match = map[string]Asset{dev.ID: dev}
	e.inv.assets = map[string]AssetView{dev.ID: {ID: dev.ID, IP: "192.168.18.60", Kind: "computer", Display: "Windows 11 Pro"}}
	seeded := seedNameOnly(t, e, dev, e.feeds.vulns)
	if len(seeded) != 3 {
		t.Fatalf("seeded %v", seeded)
	}
	if _, err := e.svc.UpsertFromMatch(t.Context(), Asset{ID: dev.ID, Name: dev.Name, Software: dev.Software[1:]}, []Vuln{inRange}); err != nil {
		t.Fatal(err)
	}
	load := func(cve string) Record {
		t.Helper()
		r, err := loadByPair(t.Context(), e.db.Reader(), dev.ID, cve)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if _, err := e.svc.setStatus(t.Context(), load(accepted.CVE).ID, ActionAcceptRisk, "until the next build", "kien@example.test", dayOf(*e.clock).AddDate(0, 0, 30)); err != nil {
		t.Fatal(err)
	}
	for _, a := range []Action{ActionNotRelevant, ActionReopen} {
		if _, err := e.svc.SetStatus(t.Context(), load(reopened.CVE).ID, a, "checked by hand", "kien@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	e.pub.take()
	e.advance(time.Hour)
	res, err := e.svc.Reconcile(t.Context())
	if err != nil || res.NameOnly != 1 || res.Created != 0 || res.Aged+res.Closed+res.Retired != 0 {
		t.Fatalf("reconcile %+v %v", res, err)
	}
	r := load(cve0367.CVE)
	if r.Status != StatusNotRelevant || r.ResolvedBy != SystemUser || r.ResolutionReason != ReasonNotAffectedVersion ||
		!strings.HasPrefix(r.ResolutionNote, NameOnlyNote+": Windows build 26300 is newer than Vedette's table of Windows releases") {
		t.Fatalf("not closed: %+v", r.Finding)
	}
	if last := r.History[len(r.History)-1]; last.User != SystemUser || last.Action != string(StatusNotRelevant) || last.Note != r.ResolutionNote {
		t.Fatalf("history %+v", last)
	}
	ev := e.pub.take()
	if len(ev) != 1 || ev[0].Name != EventStatusChanged || ev[0].Payload != (StatusChangedEvent{FindingID: r.ID, From: StatusSuspected, To: StatusNotRelevant, Reason: ReasonNotAffectedVersion}) {
		t.Fatalf("events %+v", ev)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.auto_resolved' AND detail LIKE '%D-602%'`); n != 1 {
		t.Fatalf("audit rows %d", n)
	}
	if a := load(accepted.CVE); a.Status != StatusRiskAccepted {
		t.Errorf("risk acceptance touched: %+v", a.Finding)
	}
	p := load(reopened.CVE)
	if p.Status != StatusSuspected || !strings.Contains(p.History[len(p.History)-1].Note, "Vedette now matches CVE-2004-0210 by the product name only (Windows build 26300 is newer") {
		t.Errorf("person's reopen: %+v %+v", p.Finding, p.History[len(p.History)-1])
	}
	if v := load(inRange.CVE); v.Status != StatusSuspected || v.Basis != BasisVersion {
		t.Errorf("version finding: %+v", v.Finding)
	}
	rows, err := e.svc.ListUnchecked(t.Context(), dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	var listed []string
	for _, u := range rows {
		listed = append(listed, u.CVE)
	}
	if !slices.Equal(listed, []string{cve0367.CVE}) { // the closed one; the accepted and the reopened ones are a person's
		t.Fatalf("unchecked %v", listed)
	}
	// a second pass changes nothing
	e.advance(time.Hour)
	if res, err := e.svc.Reconcile(t.Context()); err != nil || res.NameOnly != 0 {
		t.Fatalf("second pass %+v %v", res, err)
	}
	if ev := e.pub.take(); len(ev) != 0 || len(load(cve0367.CVE).History) != len(r.History) {
		t.Fatalf("second pass wrote: %+v", ev)
	}
	// the build becomes one the table knows and NVD's rows compare: the closed finding reopens on that evidence
	dev.Software[0].Product, dev.Software[0].Version = "Windows 11 24H2", "10.0.26100.1742"
	dev.Software[0].CPE = "cpe:2.3:o:microsoft:windows_11_24h2:10.0.26100.1742:*:*:*:*:*:x64:*"
	v := cve62215
	v.CVE = cve0367.CVE
	e.feeds.vulns = []Vuln{v}
	if _, err := e.svc.UpsertFromMatch(t.Context(), dev, e.feeds.vulns); err != nil {
		t.Fatal(err)
	}
	if r := load(cve0367.CVE); r.Status != StatusSuspected || r.Basis != BasisVersion ||
		!strings.Contains(r.History[len(r.History)-1].Note, "it had closed it because only the product name matched") {
		t.Fatalf("not reopened: %+v %+v", r.Finding, r.History[len(r.History)-1])
	}
}
