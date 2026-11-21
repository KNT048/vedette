package findings

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// winlab01 is a test box's Windows Server 2025 VM: its osquery agent reports build 26100.1742 (the GA media, carrying
// September 2024's update) and Microsoft Edge (Chromium), the row CISA's "Microsoft | Edge" entries are keyed to.
func winlab01() Asset {
	a := winPC(26100, true, "1742", "x64")
	a.Name = "WINLAB01"
	a.Software = append(a.Software, Software{ID: "s-edge", Display: "Microsoft Edge", Vendor: "microsoft", Product: "edge", Version: "130.0.2849.80",
		Source: "agent", KevKeys: []string{"microsoft|edge"}})
	return a
}

// WIN-NOISE-2: WINLAB01 had 17 open "suspected, Vedette cannot compare version" findings. With NVD's real rows (testdata,
// as the feeds module stores them), the 11 that Microsoft fixed in or before September 2024 close as not affected, naming the build and
// the month; CVE-2024-43572 and CVE-2024-43573 (October 2024) stay and name the update that fixes them. CVE-2015-1671 (.NET, Lync,
// Silverlight, Live Meeting) and CVE-2021-43890 (App Installer) are CISA "Microsoft Windows" entries whose NVD list names only other
// products: the agent's build is compared with nothing, so they are no agent evidence and the age rule drops them (#904). The two
// Edge Legacy (EdgeHTML) entries on the Chromium Edge row close by the Edge Legacy rule.
func TestMatchAsset_WinLab01(t *testing.T) {
	vulns := loadGolden(t, "testdata/kev-nvd-winlab01-n55.json")
	have := map[string]bool{}
	for _, v := range vulns {
		have[v.CVE] = !strings.HasPrefix(v.CVE, "CVE-2024-49") // the two November/December 2024 entries only give Server 2025's own fix builds
	}
	res := MatchAsset(winlab01(), vulns, have, winDay("2026-11-15"))
	var closed []string
	for _, m := range res.NotAffected {
		closed = append(closed, m.CVE)
		if strings.HasPrefix(m.CVE, "CVE-2016-720") { // the Edge Legacy rule, TestMatchAsset_EdgeLegacy
			continue
		}
		for _, s := range []string{"build 26100.1742 of Windows Server 2025", "monthly update of September 2024", "Windows updates are cumulative"} {
			if !strings.Contains(m.Evidence.Summary, s) {
				t.Errorf("%s: %q does not say %q", m.CVE, m.Evidence.Summary, s)
			}
		}
	}
	slices.Sort(closed)
	want := []string{"CVE-2016-7200", "CVE-2016-7201", "CVE-2017-0143", "CVE-2017-0146", "CVE-2020-0601", "CVE-2021-40449", "CVE-2024-38014", "CVE-2024-38106", "CVE-2024-38107",
		"CVE-2024-38178", "CVE-2024-38193", "CVE-2024-38217", "CVE-2024-43461"}
	if !slices.Equal(closed, want) {
		t.Fatalf("closed %d %v, want %d %v", len(closed), closed, len(want), want)
	}
	stay := map[string]string{}
	for _, m := range res.Existing {
		stay[m.CVE] = m.Evidence.Summary
		if m.Basis != BasisProduct || !m.Evidence.AgentRow {
			t.Errorf("%s: %s agent_row=%v", m.CVE, m.Basis, m.Evidence.AgentRow)
		}
	}
	for _, c := range []string{"CVE-2024-43572", "CVE-2024-43573"} {
		for _, s := range []string{"Microsoft fixed " + c + " in its October 2024 update", "Windows 11 24H2, fixed in build 26100.2033", "carries the updates up to September 2024 only"} {
			if !strings.Contains(stay[c], s) {
				t.Errorf("%s: %q does not say %q", c, stay[c], s)
			}
		}
	}
	if len(stay) != 2 {
		t.Errorf("%d stay open, want 2: %v", len(stay), stay)
	}
	aged := map[string]string{}
	for _, m := range res.Aged {
		aged[m.CVE] = m.Evidence.Summary
	}
	for c, s := range map[string]string{"CVE-2015-1671": "NVD lists it for .net framework, live meeting, lync and 1 more, not Windows Server 2025, so no version could be compared. Vedette reopens this finding if NVD's data names this software or a scan finds it.",
		"CVE-2021-43890": "NVD lists it for app installer, not Windows Server 2025, so no version could be compared."} {
		if !strings.HasPrefix(aged[c], AgedNote) || !strings.Contains(aged[c], s) || len([]rune(aged[c])) > MaxNote {
			t.Errorf("%s: aged %q (%d runes), want it to say %q", c, aged[c], len([]rune(aged[c])), s)
		}
	}
	if len(aged) != 2 {
		t.Errorf("%d aged, want 2: %v", len(aged), aged)
	}
}

// #904: a recent CISA "Microsoft Windows" entry whose NVD list names only other products stays a product finding on the agent's row (the
// age rule does not apply yet) and says what NVD lists instead (the others-only sentence); its agent row stays (the page does not ask for the
// version), but it is no agent evidence: once the entry is 12 months old it ages out. A list naming the component Windows' update
// services (SMBv1) or any Windows release is the row's own and keeps its agent evidence.
func TestMatchAsset_904_WindowsEntryNVDListsOthersOnly(t *testing.T) {
	t.Parallel()
	appInstaller := Vuln{CVE: "CVE-2026-43890", Vendor: "Microsoft", Product: "Windows", Affected: []Affected{
		{CPE: "cpe:2.3:a:microsoft:app_installer:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "1.16"}}}}
	now := winDay("2026-11-15")
	recent := appInstaller
	recent.Published, recent.DateAdded = now.AddDate(0, -2, 0), now.AddDate(0, -2, 0)
	res := MatchAsset(winlab01(), []Vuln{recent}, nil, now)
	if len(res.New) != 0 || len(res.Aged) != 0 || len(res.NameOnly) != 1 { // Product name only, so no finding
		t.Fatalf("recent: %+v", res)
	}
	m := res.NameOnly[0]
	want := "CISA lists this flaw for Microsoft Windows, but NVD lists CVE-2026-43890 for app installer only, not Windows Server 2025; check the vendor advisory and close it if it does not apply."
	if m.Basis != BasisProduct || !m.Evidence.AgentRow || confirmedMatch(m) || !strings.Contains(m.said, want) ||
		!strings.Contains(m.Evidence.Summary, "NVD lists CVE-2026-43890 for app installer, names Vedette does not tie to Windows Server 2025") {
		t.Errorf("recent: basis %s agent_row %v confirmed %v %q %q", m.Basis, m.Evidence.AgentRow, confirmedMatch(m), m.said, m.Evidence.Summary)
	}
	if len(res.Unchecked) != 1 || res.Unchecked[0].Reason != UncheckedNotNamed {
		t.Errorf("recent: unchecked %+v", res.Unchecked)
	}
	old := appInstaller
	old.Published, old.DateAdded = now.AddDate(-3, 0, 0), now.AddDate(-3, 0, 0)
	if res := MatchAsset(winlab01(), []Vuln{old}, map[string]bool{old.CVE: true}, now); len(res.Aged) != 1 || len(res.Existing) != 0 {
		t.Errorf("old: %+v", res)
	}
	// the row's own: SMBv1 (winOSComponents) or another Windows release without a range Vedette reads keeps the agent evidence
	for _, cpe := range []string{"cpe:2.3:a:microsoft:server_message_block:1.0:*:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"} {
		own := old
		own.Affected = []Affected{{CPE: cpe}}
		res := MatchAsset(winlab01(), []Vuln{own}, nil, now)
		if len(res.Aged) != 1 || len(res.New)+len(res.NameOnly) != 0 || !res.Aged[0].Evidence.AgentRow || res.Aged[0].others != "" { // No agent-row exception
			t.Errorf("%s: %+v", cpe, res)
		}
	}
	// no NVD data yet: CISA's own naming of the product is all there is, and the agent row keeps it (TestContract_AgentRowNeverAges)
	none := old
	none.Affected = nil
	if res := MatchAsset(winlab01(), []Vuln{none}, nil, now); len(res.Aged) != 1 || len(res.New)+len(res.NameOnly) != 0 || confirmedMatch(res.Aged[0]) {
		t.Errorf("no NVD data: %+v", res)
	}
}

// The build-month rule never guesses the month: without NVD's published days the build's month is not known; a CVE Microsoft later extended (CVE-2013-3900,
// opt-in) is never closed by it; and once Microsoft numbers Server 2025 apart from Windows 11 24H2 (26100.32313 against 26100.7781 in
// February 2026), a 24H2-only fix build of a later month says nothing about the server's build.
func TestMatchAsset_NeverGuesses(t *testing.T) {
	vulns := loadGolden(t, "testdata/kev-nvd-winlab01-n55.json")
	undated := slices.Clone(vulns)
	for i := range undated {
		if undated[i].CVE == "CVE-2024-49039" {
			undated[i].Published = time.Time{} // one fix build of the server without its day: the walk would miss its month
		}
	}
	if res := MatchAsset(winlab01(), undated, map[string]bool{"CVE-2024-38106": true}, winDay("2026-11-15")); len(res.NotAffected) != 0 {
		t.Errorf("a month without its published day closed %s: %q", res.NotAffected[0].CVE, res.NotAffected[0].Evidence.Summary)
	}
	// review r2 #5: the August and September 2024 entries without their day put 26100.1742 in the placeholder month: never shown as the
	// build's month; CVE-2024-43572 says the month is not known and still names its fix
	undated = slices.Clone(vulns)
	for i := range undated {
		if strings.HasPrefix(undated[i].CVE, "CVE-2024-38") || undated[i].CVE == "CVE-2024-43461" {
			undated[i].Published = time.Time{}
		}
	}
	res := MatchAsset(winlab01(), undated, map[string]bool{"CVE-2024-43572": true, "CVE-2024-38106": true}, winDay("2026-11-15"))
	if len(res.NotAffected) != 0 {
		t.Errorf("placeholder month closed %s: %q", res.NotAffected[0].CVE, res.NotAffected[0].Evidence.Summary)
	}
	for _, m := range res.Existing {
		if m.CVE == "CVE-2024-43572" && (!strings.Contains(m.Evidence.Summary, "Vedette cannot tell which month's update it carries") || !strings.Contains(m.Evidence.Summary, "fixed in build 26100.2033") || strings.Contains(m.Evidence.Summary, "January 1")) {
			t.Errorf("CVE-2024-43572 with the month unknown: %q", m.Evidence.Summary)
		}
	}
	// CVE-2013-3900 with an old list naming only Windows 7 (winRevised): the month rule does not close it either
	old := nvdRaw("CVE-2013-3900", "2022-01-10", "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*")
	old.Published = winDay("2013-12-10")
	if w, m := oneMatch(t, winlab01(), old, true, vulns...); w != "nameonly" {
		t.Errorf("CVE-2013-3900: %s %q", w, m.Evidence.Summary)
	}
	// Server 2025 at 26100.32313 (February 2026's update). January and February 2026 give its own fix builds (NVD's real rows of
	// CVE-2026-20805 and CVE-2026-21510); a March 2026 entry fixed for 24H2 only, in 24H2's numbering (synthetic), must not move it.
	srv := winPC(26100, true, "32313", "x64")
	jan := nvdWindows("CVE-2026-20805", "2026-01-13", nvdRow{"windows_11_24h2", "*", "*", "10.0.26100.7623"}, nvdRow{"windows_server_2025", "*", "*", "10.0.26100.7623"})
	feb := nvdWindows("CVE-2026-21510", "2026-02-10", nvdRow{"windows_11_24h2", "*", "x64", "10.0.26100.7781"}, nvdRow{"windows_server_2025", "*", "*", "10.0.26100.32313"})
	mar := nvdWindows("CVE-2026-90001", "2026-03-10", nvdRow{"windows_11_24h2", "*", "*", "10.0.26100.8037"})
	apr := nvdWindows("CVE-2026-90002", "2026-04-14", nvdRow{"windows_11_24h2", "*", "*", "10.0.26100.8246"}, nvdRow{"windows_10_22h2", "*", "*", "10.0.19045.7184"})
	jan.Published, feb.Published, mar.Published, apr.Published = winDay("2026-01-13"), winDay("2026-02-10"), winDay("2026-03-10"), winDay("2026-04-14")
	if w, m := oneMatch(t, srv, mar, true, jan, feb, apr); w != "nameonly" {
		t.Errorf("March 2026 (24H2 only) on February's server build: %s %q", w, m.Evidence.Summary)
	}
	old.Published = winDay("2025-12-09")
	old.CVE = "CVE-2025-90003"
	w, m := oneMatch(t, srv, old, true, jan, feb, mar, apr)
	wantMatch(t, "December 2025 on February's server build", w, m, "notaffected", "", "", "monthly update of February 2026")
}

// dated is an NVD Windows entry with its published day (synthetic unless the comment names the CVE).
func dated(cve, published, added string, rows ...nvdRow) Vuln {
	v := nvdWindows(cve, added, rows...)
	v.Published = winDay(published)
	return v
}

// noRange keeps the older-releases proofs out of a case: a 24H2 row without a fix build is a release of the device's build, so the older
// flow says "not checked" and only the month rule could close it.
var noRange = nvdRow{"windows_11_24h2", "-", "*", ""}

// Review r1 #1 of #806 (reproduced): the build's month must not depend on which entries one match gets. Reconcile's recent write got
// only this week's entries; the earliest Server 2025 row there (October 2026) moved the cut-off for 24H2 rows, a March 2026 24H2-only
// fix counted for the server's February 2026 build 26100.32313, and the March entry closed. The cut-off is Server 2025's release month.
func TestMatchAsset_PartOfTheListNeverMovesTheMonth(t *testing.T) {
	srv := winPC(26100, true, "32313", "x64")
	a := dated("CVE-2026-90010", "2026-10-13", "2026-11-12", nvdRow{"windows_server_2025", "*", "*", "10.0.26100.33650"}, nvdRow{"windows_11_24h2", "*", "*", "10.0.26100.9711"})
	b := dated("CVE-2026-90011", "2026-03-10", "2026-11-12", nvdRow{"windows_11_24h2", "*", "*", "10.0.26100.8037"})
	if w, m := oneMatch(t, srv, b, true, a); w != "nameonly" {
		t.Errorf("March 2026 24H2-only entry on February's server build: %s %q", w, m.Evidence.Summary)
	}
}

// Review r1 #2 and #3 of #806: each margin of the month rule holds a case of its own.
func TestMatchAsset_Margins(t *testing.T) {
	vulns := loadGolden(t, "testdata/kev-nvd-winlab01-n55.json")
	srv := winlab01() // build 26100.1742: September 2024
	server2022 := func(end string) nvdRow { return nvdRow{"windows_server_2022", "*", "*", end} }
	for _, tc := range []struct {
		name string
		v    Vuln
	}{
		// published in the build's own month with no fix build of its numbering: it may be a flaw published before its fix
		{"same month, no fix build", dated("CVE-2024-90030", "2024-09-10", "2024-09-10", noRange, server2022("10.0.20348.2700"))},
		// an earlier month, but CISA listed it less than 90 days ago (Microsoft and NVD revisit a listed CVE)
		{"listed under 90 days ago", dated("CVE-2024-90031", "2024-08-13", "2026-10-01", noRange, server2022("10.0.20348.2655"))},
		// review r1 #4: a family row of every Windows release keeps an entry open, and so does a range of a release Vedette does not
		// know that ends above the device's build
		{"windows:* row", dated("CVE-2019-90032", "2019-01-08", "2022-03-03", nvdRow{"windows_7", "-", "*", ""}, nvdRow{"windows", "*", "*", ""})},
		{"windows_nt row", dated("CVE-2019-90033", "2019-01-08", "2022-03-03", nvdRow{"windows_7", "-", "*", ""}, nvdRow{"windows_nt", "-", "*", ""})},
		{"unknown release above the build", dated("CVE-2019-90034", "2019-01-08", "2022-03-03", nvdRow{"windows_7", "-", "*", ""}, nvdRow{"windows_server_2025_azure", "*", "*", "10.0.26100.9999"})},
	} {
		if w, m := oneMatch(t, srv, tc.v, true, vulns...); w != "nameonly" {
			t.Errorf("%s: %s %q", tc.name, w, m.Evidence.Summary)
		}
	}
	// an own-numbering fix build on a CVE without its published day: the walk would miss that month, so the month is not known. Here an
	// October 2024 entry fixed by December's build (26100.2605) has no day; without it the walk would reach November on 26100.2314
	srv = winPC(26100, true, "2314", "x64")
	undated := nvdWindows("CVE-2024-90035", "2024-10-08", nvdRow{"windows_11_24h2", "*", "*", "10.0.26100.2605"})
	oct := dated("CVE-2024-90036", "2024-10-08", "2024-10-08", noRange, server2022("10.0.20348.2762"))
	if w, m := oneMatch(t, srv, oct, true, append(slices.Clone(vulns), undated)...); w != "nameonly" {
		t.Errorf("undated fix build: %s %q", w, m.Evidence.Summary)
	}
	// review r1 #3: two months with the same bar (NVD's November and December 2025 both end at 26100.7392): the month stays at the first
	srv = winPC(26100, true, "7392", "x64")
	own := func(cve, day, end string) Vuln {
		return dated(cve, day, day, nvdRow{"windows_server_2025", "*", "*", end})
	}
	months := []Vuln{own("CVE-2025-90037", "2025-10-14", "10.0.26100.6899"), own("CVE-2025-90038", "2025-11-11", "10.0.26100.7392"), own("CVE-2025-90039", "2025-12-09", "10.0.26100.7392")}
	nov := dated("CVE-2025-90040", "2025-11-11", "2025-11-11", noRange, server2022("10.0.20348.4405"))
	if w, m := oneMatch(t, srv, nov, true, months...); w != "nameonly" {
		t.Errorf("equal bars: %s %q", w, m.Evidence.Summary)
	}
	// review r2 #1 and #2: after Microsoft numbered Server 2025 apart from 24H2, a 24H2 fix build says nothing against the server's
	// revision, and when it is above 24H2's builds of the device's months the fix came later. Server 2025 at 26100.32313 (February 2026;
	// NVD's real January and February 2026 rows of CVE-2026-20805 and CVE-2026-21510, 24H2's February build 26100.7781); entries fixed in
	// March 2026 (24H2 26100.8037), one published before its fix in February, one in January
	srv = winPC(26100, true, "32313", "x64")
	jan := dated("CVE-2026-20805", "2026-01-13", "2026-01-13", nvdRow{"windows_11_24h2", "*", "*", "10.0.26100.7623"}, nvdRow{"windows_server_2025", "*", "*", "10.0.26100.7623"})
	feb := dated("CVE-2026-21510", "2026-02-10", "2026-02-10", nvdRow{"windows_11_24h2", "*", "x64", "10.0.26100.7781"}, nvdRow{"windows_server_2025", "*", "*", "10.0.26100.32313"})
	for _, v := range []Vuln{
		dated("CVE-2026-90050", "2026-02-10", "2026-02-20", nvdRow{"windows_11_24h2", "*", "*", "10.0.26100.8037"}),
		dated("CVE-2026-90051", "2026-01-13", "2026-01-20", nvdRow{"windows_11_24h2", "*", "*", "10.0.26100.8037"}),
	} {
		if w, m := oneMatch(t, srv, v, true, jan, feb); w != "nameonly" {
			t.Errorf("%s, 24H2 fixed in March, on February's server build: %s %q", v.CVE, w, m.Evidence.Summary)
		}
	}
	// a row of another Microsoft product (Office) next to the Windows rows keeps the entry open: Windows' update does not service it
	office := dated("CVE-2019-90052", "2019-01-08", "2022-03-03", nvdRow{"windows_7", "-", "*", ""})
	office.Affected = append(office.Affected, Affected{CPE: "cpe:2.3:a:microsoft:office:2016:*:*:*:*:*:*:*"})
	if w, m := oneMatch(t, winlab01(), office, true, vulns...); w != "nameonly" {
		t.Errorf("Office row: %s %q", w, m.Evidence.Summary)
	}
}

// Review r2 #3 of #806: the month rule also runs when the device's own rows cannot tell (most closes outside Server 2025). Windows Server
// 2019 at 17763.6414 (October 2024, the fixture's own Server 2019 fix builds): NVD's real rows of CVE-2023-21823 (February 2023) give
// windows_server_2019 with no fix build and Windows 10 1809 < 17763.4010; it closes. With an own row that ends above the build it is the
// device's own range that decides: affected.
func TestMatchAsset_OwnRowsWithoutAFixBuild(t *testing.T) {
	vulns := loadGolden(t, "testdata/kev-nvd-winlab01-n55.json")
	srv := winPC(17763, true, "6414", "x64")
	v := dated("CVE-2023-21823", "2023-02-14", "2023-02-14", nvdRow{"windows_server_2019", "-", "*", ""}, nvdRow{"windows_10_1809", "*", "*", "10.0.17763.4010"})
	w, m := oneMatch(t, srv, v, true, vulns...)
	wantMatch(t, "own row without a fix build", w, m, "notaffected", "", "", "build 17763.6414 of Windows Server 2019 carries Microsoft's monthly update of October 2024")
	v.Affected[0] = Affected{CPE: "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.0.17763.9999"}}
	w, m = oneMatch(t, srv, v, true, vulns...)
	wantMatch(t, "own row above the build", w, m, "existing", BasisVersion, SeverityHigh)
}

// Reconcile's two writes (backlog, this week's entries) read the build's month from the whole list: a September 2024 entry fixed only by
// a later build (26100.2100, above the device's 26100.2000) stops the walk at August, so an October 2024 entry stays open on the recent
// write too, where that September entry is not.
func TestReconcile_BuildMonthFromTheWholeList(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	*e.clock = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	week := "2026-11-12"
	e.feeds.vulns = []Vuln{
		dated("CVE-2024-90020", "2024-08-13", "2024-08-13", nvdRow{"windows_11_24h2", "*", "*", "10.0.26100.1457"}),
		dated("CVE-2024-90021", "2024-09-10", "2024-09-10", nvdRow{"windows_11_24h2", "*", "*", "10.0.26100.2100"}), // fixed by a later build
		dated("CVE-2024-90022", "2024-11-12", week, nvdRow{"windows_server_2025", "*", "*", "10.0.26100.2314"}),
		dated("CVE-2024-90023", "2024-10-08", week, nvdRow{"windows_11_24h2", "*", "*", "10.0.26100.1900"}),
	}
	dev := winPC(26100, true, "2000", "x64")
	e.inv.match = map[string]Asset{dev.ID: dev}
	e.inv.assets = map[string]AssetView{dev.ID: {ID: dev.ID, IP: "—", Kind: "server", Display: dev.Name}}
	if _, err := e.svc.UpsertFromMatch(t.Context(), dev, e.feeds.vulns); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reconciler(&markPub{}, e.inv).Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Not proved either way, so no finding and no close: the entry is under "Could not be checked"
	if r, err := loadByPair(t.Context(), e.db.Reader(), dev.ID, "CVE-2024-90023"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("October 2024 entry on a build from August: %+v %v", r.Row, err)
	}
	rows, err := e.svc.ListUnchecked(t.Context(), dev.ID)
	if err != nil || !slices.ContainsFunc(rows, func(u UncheckedRow) bool { return u.CVE == "CVE-2024-90023" }) {
		t.Fatalf("October 2024 entry not under could not be checked: %+v %v", rows, err)
	}
}
