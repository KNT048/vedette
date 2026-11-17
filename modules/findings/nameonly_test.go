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
		for _, m := range slices.Concat(res.NameOnly, res.Aged) {
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
			!strings.Contains(m.Evidence.Summary, "Windows build 26300 is newer than Vedette's table of Windows releases (an Insider or preview build), so Vedette cannot compare 10.0.26300.9974 with the builds NVD lists for "+m.CVE) ||
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
// products), there is no finding; the CVE goes to the could-not-check list with #920's reason. A scannable CVE stays a finding on any
// row, the agent's too (the scan's target, review r1 H1 of #939).
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
	if r := MatchAsset(agent, []Vuln{scan}, nil, t0); len(r.New) != 1 || len(r.NameOnly) != 0 { // review r1 H1 of #939: on any row
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

// Review r1 of #939, M1 and M2: NVD's "every version" is version evidence for a row whose version Vedette cannot read too, and which
// row wins never decides whether the CVE is a finding (both orders).
func TestMatchAsset_D602_EveryVersionAndRowOrder(t *testing.T) {
	t.Parallel()
	every := qnapVuln(Affected{CPE: qnapCPE})
	for _, ver := range []string{"", "15.2(4)M3", "R7000-V1.0.11.100_10.2.100"} {
		if r := MatchAsset(nas(ver), []Vuln{every}, nil, t0); len(r.New) != 1 || len(r.NameOnly) != 0 || !r.New[0].every {
			t.Errorf("every version, version %q: %+v", ver, r)
		}
	}
	agent := Software{ID: "s-a", Display: "Photo Station", Vendor: "QNAP", Product: "Photo Station", Version: "R7000-V1.0.11.100_10.2.100", Source: "agent", KevKeys: []string{"qnap|photo station"}}
	bare := Software{ID: "s-b", Display: "Photo Station", Vendor: "QNAP", Product: "Photo Station", KevKeys: []string{"qnap|photo station"}}
	unordered := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "next"}})
	for name, rows := range map[string][]Software{"agent first": {agent, bare}, "bare first": {bare, agent}} {
		a := Asset{ID: "a", Name: "nas", Software: rows}
		if r := MatchAsset(a, []Vuln{every}, nil, t0); len(r.New) != 1 || len(r.NameOnly) != 0 {
			t.Errorf("%s, every version: %+v", name, r)
		}
		// neither row has version evidence: no finding whatever the order, and the agent's row is the one listed
		if r := MatchAsset(a, []Vuln{unordered}, nil, t0); len(r.New) != 0 || len(r.NameOnly) != 1 || r.NameOnly[0].SoftwareID != "s-a" {
			t.Errorf("%s, unordered range: %+v", name, r)
		}
	}
}

// Review r1 of #939, M3 and H2 (a): "add the version" only where a version would decide; otherwise, and before NVD has answered at
// all, the CVE is under "could not be checked" at once with the reason (no_nvd_data, no_nvd_versions).
func TestMatchAsset_D602_AddTheVersionOnlyWhereItDecides(t *testing.T) {
	t.Parallel()
	pending := qnapVuln() // NVD has not answered yet (NVDAnswered false)
	dash := qnapVuln(Affected{CPE: "cpe:2.3:a:qnap:photo_station:-:*:*:*:*:*:*:*"})
	dash.CVE = "CVE-2023-0004"
	ranged := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})
	ranged.CVE = "CVE-2023-0005"
	for _, ver := range []string{"", "6.1.1"} {
		r := MatchAsset(nas(ver), []Vuln{pending, dash, ranged}, nil, t0)
		got := uncByCVE(r.Unchecked)
		if got["s-1 "+pending.CVE].Reason != UncheckedNoNVDData || got["s-1 "+dash.CVE].Reason != UncheckedNoNVDVersions {
			t.Errorf("version %q: unchecked %+v", ver, r.Unchecked)
		}
		if ver == "" && (len(r.NeedVersion) != 1 || !slices.Equal(r.NeedVersion[0].CVEs, []string{ranged.CVE})) {
			t.Errorf("no version: need %+v", r.NeedVersion)
		}
	}
}

// Review r1 of #939, H2 (b): a device × exploited CVE that enters "could not be checked" for the first time is announced once, in one
// findings.unchecked.added event per device and write listing the CVEs; never again for that pair, and never for a CVE the device has
// a finding for (the old product findings closing into the list at the upgrade stay silent).
func TestContract_D602_NewUncheckedIsAnnouncedOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	dev := desktop55()
	e.inv.match = map[string]Asset{dev.ID: dev}
	old := []Vuln{cve0367}
	seedNameOnly(t, e, dev, old) // the upgrade: a product finding an earlier rule made
	e.pub.take()
	if _, err := e.svc.UpsertFromMatch(t.Context(), dev, old); err != nil {
		t.Fatal(err)
	}
	for _, ev := range e.pub.take() {
		if ev.Name == EventUncheckedAdded {
			t.Fatalf("the upgrade announced %+v", ev)
		}
	}
	added := []Vuln{cve0367, cve0210, cve4250}
	if _, err := e.svc.UpsertFromMatch(t.Context(), dev, added); err != nil {
		t.Fatal(err)
	}
	var got []UncheckedAddedEvent
	for _, ev := range e.pub.take() {
		if ev.Name == EventUncheckedAdded {
			got = append(got, ev.Payload.(UncheckedAddedEvent))
		}
	}
	if len(got) != 1 || got[0].AssetID != dev.ID || got[0].AssetName != dev.Name || len(got[0].CVEs) != 2 ||
		got[0].CVEs[0].CVE != cve0210.CVE || got[0].CVEs[1].CVE != cve4250.CVE || got[0].CVEs[0].Reason != UncheckedNotComparable || got[0].CVEs[0].Software != "Windows 11 Pro" {
		t.Fatalf("events %+v", got)
	}
	e.advance(time.Hour)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, ev := range e.pub.take() {
		if ev.Name == EventUncheckedAdded {
			t.Fatalf("announced twice: %+v", ev)
		}
	}
	if _, err := e.svc.OnAssetDeleted(t.Context(), dev.ID); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_unchecked_seen`); n != 0 {
		t.Fatalf("seen rows left after the delete: %d", n)
	}
}

// Review r2 H1 of #939: a version inside the range of every edition or track NVD pins for one of the row's products is version
// evidence, though the row does not say which edition it is: a version finding whose sentence names the pinned values. NVD's real rows
// (N100 copy, 2026-11-16). Firefox ESR against "-" stays as #906 decided (TestNA_ApplicationEditionAsMain).
func TestMatchAsset_D602_PinnedEditionStillDecides(t *testing.T) {
	t.Parallel()
	rows := func(cve, vendor, product string, aff ...[3]string) Vuln {
		v := Vuln{CVE: cve, Vendor: vendor, Product: product, NVDAnswered: true}
		for _, a := range aff {
			v.Affected = append(v.Affected, Affected{CPE: a[0], Range: VersionRange{StartIncl: a[1], EndExcl: a[2]}})
		}
		return v
	}
	acrobat := rows("CVE-2026-34621", "Adobe", "Acrobat and Reader",
		[3]string{"cpe:2.3:a:adobe:acrobat_dc:*:*:*:*:continuous:*:*:*", "", "26.001.21411"},
		[3]string{"cpe:2.3:a:adobe:acrobat_reader_dc:*:*:*:*:continuous:*:*:*", "", "26.001.21411"},
		[3]string{"cpe:2.3:a:adobe:acrobat:*:*:*:*:classic:*:*:*", "24.0.0", "24.001.30362"},
		[3]string{"cpe:2.3:a:adobe:acrobat:*:*:*:*:classic:*:*:*", "24.0.0", "24.001.30360"})
	gitlab := rows("CVE-2021-39935", "GitLab", "Community and Enterprise Editions",
		[3]string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*", "10.5.0", "14.3.6"},
		[3]string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:*", "10.5.0", "14.3.6"},
		[3]string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*", "14.4.0", "14.4.4"},
		[3]string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:*", "14.4.0", "14.4.4"},
		[3]string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*", "14.5.0", "14.5.2"},
		[3]string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:*", "14.5.0", "14.5.2"})
	row := func(display, vendor, product, ver, source string, v Vuln) Asset {
		return Asset{ID: "a", Name: "pc", Software: []Software{{ID: "s", Display: display, Vendor: vendor, Product: product, Version: ver, Source: source,
			KevKeys: []string{KevKey(v.Vendor, v.Product)}}}}
	}
	for _, tc := range []struct {
		name string
		a    Asset
		v    Vuln
		says string // "" = no finding
	}{
		{"Acrobat Reader DC 24.002.20759 (agent)", row("Adobe Acrobat Reader DC", "Adobe", "Acrobat and Reader", "24.002.20759", "agent", acrobat), acrobat, "for continuous only"},
		{"Acrobat Reader DC 26.001.21411 (fixed)", row("Adobe Acrobat Reader DC", "Adobe", "Acrobat and Reader", "26.001.21411", "agent", acrobat), acrobat, ""},
		{"GitLab 14.3.0 (nmap)", row("GitLab", "GitLab", "GitLab", "14.3.0", "nmap", gitlab), gitlab, "for community or enterprise only"},
		{"GitLab 14.3.6 (fixed)", row("GitLab", "GitLab", "GitLab", "14.3.6", "nmap", gitlab), gitlab, ""},
	} {
		r := MatchAsset(tc.a, []Vuln{tc.v}, nil, t0)
		if tc.says == "" {
			if len(r.New)+len(r.NameOnly) != 0 {
				t.Errorf("%s: %+v", tc.name, r)
			}
			continue
		}
		if len(r.New) != 1 || r.New[0].Basis != BasisVersion || !strings.Contains(r.New[0].Evidence.Summary, tc.says) || r.New[0].Evidence.Agent {
			t.Errorf("%s: %+v", tc.name, r)
		}
	}
	// one pinned edition whose ranges leave the version out (the attribute would decide): not evidence
	mixed := rows("CVE-2099-0101", "GitLab", "Community and Enterprise Editions",
		[3]string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*", "10.5.0", "14.3.6"},
		[3]string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:*", "10.5.0", "14.2.0"})
	if r := MatchAsset(row("GitLab", "GitLab", "GitLab", "14.3.0", "nmap", mixed), []Vuln{mixed}, nil, t0); len(r.New) != 0 || len(r.NameOnly) != 1 {
		t.Errorf("mixed editions: %+v", r)
	}
}

// Review r2 H2 of #939: an out-of-service Windows release (Windows 11 21H2) that NVD's list brackets with releases of its kind before
// and after it has the flaw (no update brings it the fix): a finding with that sentence, kept by the age rule. Listed only for newer
// releases (a feature it may not have), it stays "could not be checked".
func TestMatchAsset_D602_EndedWindowsBracketedIsAFinding(t *testing.T) {
	t.Parallel()
	pc := winPC(22000, false, "2538", "x64")
	clfs := nvdWindows("CVE-2025-29824", "2025-04-08", nvdRow{"windows_10_21h2", "*", "x64", "10.0.19044.5737"}, nvdRow{"windows_11_22h2", "*", "x64", "10.0.22621.5189"},
		nvdRow{"windows_11_24h2", "*", "x64", "10.0.26100.3775"}, nvdRow{"windows_server_2025", "*", "x64", "10.0.26100.3775"})
	clfs.Published = winDay("2025-04-08")
	w, m := oneMatch(t, pc, clfs, false, cve62215)
	wantMatch(t, "21H2 bracketed", w, m, "new", BasisProduct, SeverityMedium, "Microsoft no longer updates Windows 11 21H2", "Windows 10 21H2", "move to a serviced release")
	if !versionBacked(m) {
		t.Error("bracketed: no version evidence")
	}
	newer := nvdWindows("CVE-2099-0102", "2026-10-01", nvdRow{"windows_11_22h2", "*", "x64", "10.0.22621.5189"}, nvdRow{"windows_11_24h2", "*", "x64", "10.0.26100.3775"})
	if w, _ := oneMatch(t, pc, newer, false, cve62215); w != "nameonly" {
		t.Errorf("newer releases only: %s", w)
	}
	// a serviced release (23H2) is read by its own rows, as before
	if w, _ := oneMatch(t, winPC(22631, false, "5189", "x64"), clfs, false, cve62215); w != "none" {
		t.Errorf("23H2 at the fix: %s", w)
	}
}

// Review r2 M1 of #939: before NVD has answered for a CVE, its could-not-check row says Vedette is waiting for NVD's data (nvd_pending),
// not that NVD has none; once NVD answered with nothing, it says that.
func TestUnchecked_D602_WaitingForNVD(t *testing.T) {
	t.Parallel()
	pending := qnapVuln()
	answered := qnapVuln()
	answered.CVE, answered.NVDAnswered = "CVE-2023-0006", true
	r := MatchAsset(nas("6.1.1"), []Vuln{pending, answered}, nil, t0)
	got := uncByCVE(r.Unchecked)
	if u := got["s-1 "+pending.CVE]; u.Reason != UncheckedNoNVDData || !u.NVDPending {
		t.Errorf("pending: %+v", u)
	}
	if u := got["s-1 "+answered.CVE]; u.Reason != UncheckedNoNVDData || u.NVDPending {
		t.Errorf("answered: %+v", u)
	}
	for _, m := range r.NameOnly {
		want := map[string]string{pending.CVE: "Vedette is waiting for NVD's data for " + pending.CVE, answered.CVE: "NVD has not published which products " + answered.CVE}[m.CVE]
		if !strings.Contains(m.Evidence.Summary, want) {
			t.Errorf("%s: %q", m.CVE, m.Evidence.Summary)
		}
	}
	e := newEnv(t)
	if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{pending}); err != nil {
		t.Fatal(err)
	}
	rows, err := e.svc.ListUnchecked(t.Context(), "a-1")
	if err != nil || len(rows) != 1 || !rows[0].NVDPending {
		t.Fatalf("stored: %+v %v", rows, err)
	}
	items := UncheckedItems(rows, map[string]KevInfo{pending.CVE: {Name: "x", DateAdded: "2022-09-01"}}, nil)
	if len(items) != 1 || !items[0].CVEs[0].NVDPending {
		t.Fatalf("items: %+v", items)
	}
}
