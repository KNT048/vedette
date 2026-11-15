package findings

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// winlab01 is the N100's Windows Server 2025 VM of customer walk 3 n55: its osquery agent reports build 26100.1742 (the GA media, carrying
// September 2024's update) and Microsoft Edge (Chromium), the row CISA's "Microsoft | Edge" entries are keyed to.
func winlab01() Asset {
	a := winPC(26100, true, "1742", "x64")
	a.Name = "WINLAB01"
	a.Software = append(a.Software, Software{ID: "s-edge", Display: "Microsoft Edge", Vendor: "microsoft", Product: "edge", Version: "130.0.2849.80",
		Source: "agent", KevKeys: []string{"microsoft|edge"}})
	return a
}

// WIN-NOISE-2 (D-618): WINLAB01 had 17 open "suspected, Vedette cannot compare version" findings. With NVD's real rows (testdata,
// as the feeds module stores them), the 11 that Microsoft fixed in or before September 2024 close as not affected, naming the build and
// the month; CVE-2024-43572 and CVE-2024-43573 (October 2024) stay and name the update that fixes them; CVE-2015-1671 (.NET, Lync,
// Silverlight), CVE-2021-43890 (App Installer) and the two Edge (EdgeHTML) entries on the Edge row stay.
func TestMatchAsset_D618_WinLab01(t *testing.T) {
	vulns := loadGolden(t, "testdata/kev-nvd-winlab01-n55.json")
	have := map[string]bool{}
	for _, v := range vulns {
		have[v.CVE] = !strings.HasPrefix(v.CVE, "CVE-2024-49") // the two November/December 2024 entries only give Server 2025's own fix builds
	}
	res := MatchAsset(winlab01(), vulns, have, winDay("2026-11-15"))
	var closed []string
	for _, m := range res.NotAffected {
		closed = append(closed, m.CVE)
		for _, s := range []string{"build 26100.1742 of Windows Server 2025", "monthly update of September 2024", "Windows updates are cumulative"} {
			if !strings.Contains(m.Evidence.Summary, s) {
				t.Errorf("%s: %q does not say %q", m.CVE, m.Evidence.Summary, s)
			}
		}
	}
	slices.Sort(closed)
	want := []string{"CVE-2017-0143", "CVE-2017-0146", "CVE-2020-0601", "CVE-2021-40449", "CVE-2024-38014", "CVE-2024-38106", "CVE-2024-38107",
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
	for _, c := range []string{"CVE-2015-1671", "CVE-2021-43890", "CVE-2016-7200", "CVE-2016-7201"} {
		if _, ok := stay[c]; !ok {
			t.Errorf("%s does not stay open", c)
		}
	}
	if len(stay) != 6 {
		t.Errorf("%d stay open, want 6: %v", len(stay), stay)
	}
}

// D-618 never guesses the month: without NVD's published days the build's month is not known; a CVE Microsoft later extended (CVE-2013-3900,
// opt-in) is never closed by it; and once Microsoft numbers Server 2025 apart from Windows 11 24H2 (26100.32313 against 26100.7781 in
// February 2026), a 24H2-only fix build of a later month says nothing about the server's build.
func TestMatchAsset_D618_NeverGuesses(t *testing.T) {
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
	// CVE-2013-3900 with an old list naming only Windows 7 (D-610 winRevised): the month rule does not close it either
	old := nvdRaw("CVE-2013-3900", "2022-01-10", "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*")
	old.Published = winDay("2013-12-10")
	if w, m := oneMatch(t, winlab01(), old, true, vulns...); w != "existing" {
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
	if w, m := oneMatch(t, srv, mar, true, jan, feb, apr); w != "existing" {
		t.Errorf("March 2026 (24H2 only) on February's server build: %s %q", w, m.Evidence.Summary)
	}
	old.Published = winDay("2025-12-09")
	old.CVE = "CVE-2025-90003"
	w, m := oneMatch(t, srv, old, true, jan, feb, mar, apr)
	wantMatch(t, "December 2025 on February's server build", w, m, "notaffected", "", "", "monthly update of February 2026")
}
