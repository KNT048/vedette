package findings

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/winrel"
)

// NVD's Windows rows of four CISA KEV entries, as NVD gives them (2026-11-14; vulnerable rows only, product, target_hw and
// versionEndExcluding). They are data in the test: no test reads NVD.
type nvdRow struct{ product, version, target, end string }

func nvdWindows(cve, added string, rows ...nvdRow) Vuln {
	v := Vuln{CVE: cve, Vendor: "Microsoft", Product: "Windows", DateAdded: winDay(added)}
	for _, r := range rows {
		v.Affected = append(v.Affected, Affected{CPE: "cpe:2.3:o:microsoft:" + r.product + ":" + r.version + ":*:*:*:*:*:" + r.target + ":*", Range: VersionRange{EndExcl: r.end}})
	}
	return v
}

func winDay(s string) time.Time {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return t
}

var (
	// CVE-2025-62215, kernel race condition (November 2025): names 25H2 and Server 2022 23H2, not Windows 11 22H2 (out of service).
	cve62215 = nvdWindows("CVE-2025-62215", "2025-11-12",
		nvdRow{"windows_10_1809", "*", "x64", "10.0.17763.8027"}, nvdRow{"windows_10_1809", "*", "x86", "10.0.17763.8027"},
		nvdRow{"windows_10_21h2", "*", "*", "10.0.19044.6575"}, nvdRow{"windows_10_22h2", "*", "*", "10.0.19045.6575"},
		nvdRow{"windows_11_23h2", "*", "*", "10.0.22631.6199"}, nvdRow{"windows_11_24h2", "*", "*", "10.0.26100.7092"},
		nvdRow{"windows_11_25h2", "*", "*", "10.0.26200.7092"}, nvdRow{"windows_server_2019", "*", "*", "10.0.17763.8027"},
		nvdRow{"windows_server_2022", "*", "*", "10.0.20348.4346"}, nvdRow{"windows_server_2022_23h2", "*", "*", "10.0.25398.1965"},
		nvdRow{"windows_server_2025", "*", "*", "10.0.26100.7092"})
	// CVE-2025-29824, CLFS (April 2025): per target rows.
	cve29824 = nvdWindows("CVE-2025-29824", "2025-04-08",
		nvdRow{"windows_10_1809", "*", "x64", "10.0.17763.7136"}, nvdRow{"windows_10_22h2", "*", "x64", "10.0.19045.5737"},
		nvdRow{"windows_11_22h2", "*", "arm64", "10.0.22621.5189"}, nvdRow{"windows_11_22h2", "*", "x64", "10.0.22621.5189"},
		nvdRow{"windows_11_23h2", "*", "arm64", "10.0.22631.5189"}, nvdRow{"windows_11_23h2", "*", "x64", "10.0.22631.5189"},
		nvdRow{"windows_11_24h2", "*", "arm64", "10.0.26100.3775"}, nvdRow{"windows_11_24h2", "*", "x64", "10.0.26100.3775"},
		nvdRow{"windows_server_2008", "-", "x86", ""}, nvdRow{"windows_server_2012", "r2", "*", ""},
		nvdRow{"windows_server_2022", "*", "*", "10.0.20348.3453"}, nvdRow{"windows_server_2022_23h2", "*", "*", "10.0.25398.1551"},
		nvdRow{"windows_server_2025", "*", "x64", "10.0.26100.3775"})
	// CVE-2025-33073, SMB client (June 2025, listed October 2025): names 24H2, not 25H2, which shipped after the fix.
	cve33073 = nvdWindows("CVE-2025-33073", "2025-10-20",
		nvdRow{"windows_10_1809", "*", "x64", "10.0.17763.7434"}, nvdRow{"windows_10_22h2", "*", "*", "10.0.19045.5965"},
		nvdRow{"windows_11_23h2", "*", "*", "10.0.22631.5472"}, nvdRow{"windows_11_24h2", "*", "*", "10.0.26100.4270"},
		nvdRow{"windows_server_2008", "-", "x64", ""}, nvdRow{"windows_server_2022", "*", "*", "10.0.20348.3745"},
		nvdRow{"windows_server_2025", "*", "*", "10.0.26100.4270"})
	// CVE-2023-36884, Windows Search (July 2023): NVD's windows_10_22h2 row ends at a 19044 build; nothing after Windows 11 22H2.
	cve36884 = nvdWindows("CVE-2023-36884", "2023-07-17",
		nvdRow{"windows_10_1809", "*", "x64", "10.0.17763.4737"}, nvdRow{"windows_10_21h2", "*", "*", "10.0.19044.3324"},
		nvdRow{"windows_10_22h2", "*", "*", "10.0.19044.3324"}, nvdRow{"windows_11_21h2", "*", "*", "10.0.22000.2295"},
		nvdRow{"windows_11_22h2", "*", "*", "10.0.22621.2134"}, nvdRow{"windows_server_2008", "-", "*", ""},
		nvdRow{"windows_server_2019", "*", "*", "10.0.17763.4737"}, nvdRow{"windows_server_2022", "*", "*", "10.0.20348.1903"})
)

// winPC is a device with the operating-system row agent-intake gives (D-546).
func winPC(build int, server bool, ubr, target string) Asset {
	r, ok := winrel.ByBuild(build, server)
	if !ok {
		panic("no release")
	}
	v := "10.0." + strconv.Itoa(build) + "." + ubr
	return Asset{ID: "a-pc", Name: "pc-01", OS: "Microsoft " + r.Display + " " + v, Software: []Software{{
		ID: "s-win", Display: r.Display, Vendor: "microsoft", Product: r.Display, Version: v, Source: "agent",
		CPE: "cpe:2.3:o:microsoft:" + r.Product + ":" + v + ":*:*:*:*:*:" + target + ":*", KevKeys: []string{"microsoft|windows"},
	}}}
}

var winNow = winDay("2026-11-14")

// oneMatch runs the matcher for one entry (all of list as the feed, for review H2's "named" guard) and returns where it landed.
func oneMatch(t *testing.T, a Asset, v Vuln, have bool, list ...Vuln) (where string, m Match) {
	t.Helper()
	res := MatchAsset(a, append([]Vuln{v}, list...), map[string]bool{v.CVE: have}, winNow)
	for _, x := range []struct {
		name string
		ms   []Match
	}{{"new", res.New}, {"existing", res.Existing}, {"notaffected", res.NotAffected}, {"unlisted", res.Unlisted}} {
		for _, m := range x.ms {
			if m.CVE == v.CVE {
				return x.name, m
			}
		}
	}
	return "none", Match{}
}

func wantMatch(t *testing.T, name string, where string, m Match, wantWhere string, basis Basis, sev Severity, says ...string) {
	t.Helper()
	if where != wantWhere || basis != "" && (m.Basis != basis || m.Severity != sev) {
		t.Errorf("%s: %s %s/%s %q", name, where, m.Basis, m.Severity, m.Evidence.Summary)
		return
	}
	for _, s := range says {
		if !strings.Contains(m.Evidence.Summary, s) {
			t.Errorf("%s: %q does not say %q", name, m.Evidence.Summary, s)
		}
	}
}

// D-546: the device's own release decides by its update revision, per target; a patched PC closes by proof.
func TestMatchAsset_D546_OwnReleaseByUpdateRevision(t *testing.T) {
	w, m := oneMatch(t, winPC(22631, false, "4460", "x64"), cve29824, false)
	wantMatch(t, "23H2 x64 unpatched", w, m, "new", BasisVersion, SeverityHigh, "before 10.0.22631.5189")
	w, m = oneMatch(t, winPC(22631, false, "5189", "x64"), cve29824, true)
	wantMatch(t, "23H2 x64 patched", w, m, "notaffected", "", "", "Not affected: version 10.0.22631.5189")
	// review M1: target not known (a Wazuh agent without arch): inside every target's range is affected, outside every one closes
	w, m = oneMatch(t, winPC(22631, false, "4460", "*"), cve29824, false)
	wantMatch(t, "23H2 any target unpatched", w, m, "new", BasisVersion, SeverityHigh)
	w, m = oneMatch(t, winPC(22631, false, "5189", "*"), cve29824, true)
	wantMatch(t, "23H2 any target patched", w, m, "notaffected", "", "")
	// the same build on a server: its own rows
	w, m = oneMatch(t, winPC(25398, true, "1500", "x64"), cve29824, false)
	wantMatch(t, "Server 2022 23H2", w, m, "new", BasisVersion, SeverityHigh, "before 10.0.25398.1551")
	if f := FixedInFor(winPC(22631, false, "4460", "x64"), cve29824); f == nil || f.Kind != "fixed" || f.Fixed != "10.0.22631.5189" {
		t.Errorf("fixed_in: %+v", f)
	}
}

// Review H1: a release Microsoft no longer services is missing from new entries. Its sibling's rows decide (22H2 is 23H2's code
// base); a release with no sibling listed and an older build than one the entry lists stays "not checked", with the reason.
func TestMatchAsset_D546_OutOfServiceRelease(t *testing.T) {
	w, m := oneMatch(t, winPC(22621, false, "6060", "x64"), cve62215, false) // 22H2's last update, October 2025
	wantMatch(t, "22H2 after its end", w, m, "new", BasisVersion, SeverityHigh, "before 10.0.22621.6199", "Windows 11 23H2")
	if f := FixedInFor(winPC(22621, false, "6060", "x64"), cve62215); f == nil || f.Fixed != "10.0.22621.6199" {
		t.Errorf("fixed_in of a sibling: %+v", f)
	}
	w, m = oneMatch(t, winPC(22000, false, "3260", "x64"), cve62215, true)
	wantMatch(t, "11 21H2", w, m, "existing", BasisProduct, SeverityMedium, "newer ones among them", "check that Windows 11 21H2 is still supported")
}

// Review H2: siblings on one build line are read with the device's revision; NVD names 25H2 and Server 2022 23H2 as the table does.
func TestMatchAsset_D546_SiblingRelease(t *testing.T) {
	w, m := oneMatch(t, winPC(26200, false, "6899", "x64"), cve33073, true)
	wantMatch(t, "25H2 on a 24H2-only entry", w, m, "notaffected", "", "", "Windows 11 24H2", "same monthly update")
	only25 := nvdWindows("CVE-2099-0001", "2026-10-01", nvdRow{"windows_11_25h2", "*", "*", "10.0.26200.7092"})
	w, m = oneMatch(t, winPC(26100, false, "6899", "x64"), only25, false)
	wantMatch(t, "24H2 on a 25H2-only entry", w, m, "new", BasisVersion, SeverityHigh, "before 10.0.26100.7092", "Windows 11 25H2")
	// a server is never a client's sibling, even on the same build
	only24 := nvdWindows("CVE-2099-0002", "2026-10-01", nvdRow{"windows_11_24h2", "*", "*", "10.0.26100.7092"})
	w, m = oneMatch(t, winPC(26100, true, "6899", "x64"), only24, false)
	wantMatch(t, "Server 2025 on a client-only entry", w, m, "new", BasisProduct, SeverityMedium, "has not checked")
	// NVD's row ends at a build of another release of the line (windows_10_22h2 < 10.0.19044.3324): read at that build
	w, m = oneMatch(t, winPC(19045, false, "3200", "x64"), cve36884, false)
	wantMatch(t, "10 22H2 unpatched", w, m, "new", BasisVersion, SeverityHigh, "before 10.0.19045.3324")
	w, m = oneMatch(t, winPC(19045, false, "3324", "x64"), cve36884, true)
	wantMatch(t, "10 22H2 patched", w, m, "notaffected", "", "")
}

// NVD's names in the real rows above are the table's: a wrong name would leave the device's own rows unread.
func TestWinrel_NamesAreNVDs(t *testing.T) {
	for _, v := range []Vuln{cve62215, cve29824, cve33073, cve36884} {
		for _, af := range v.Affected {
			c, err := ParseCPE(af.CPE)
			if err != nil {
				t.Fatal(err)
			}
			p, _ := windowsProduct(c)
			if l, ok := winListedOf(c); !ok || l.build == 0 && !l.old {
				t.Errorf("%s: %s is not known", v.CVE, p)
			}
		}
	}
	for _, b := range []struct {
		build  int
		server bool
		cve    Vuln
	}{{26200, false, cve62215}, {25398, true, cve62215}, {25398, true, cve29824}} {
		r, _ := winrel.ByBuild(b.build, b.server)
		if !winNamed([]Vuln{b.cve}, r.Product) {
			t.Errorf("%s does not name %s", b.cve.CVE, r.Product)
		}
	}
}

// Every release the entry lists is older than the device's: no finding and a close only with a proof (the release shipped at least
// 90 days after CISA listed the flaw, or NVD's list is a year old) and when NVD names the release at all (review H2); otherwise
// "not checked" with the reason. A finding left open by a feature update closes the same way (review M2).
func TestMatchAsset_D546_NewerThanEveryListedRelease(t *testing.T) {
	pc := winPC(26100, false, "7092", "x64") // upgraded from 23H2; NVD names 24H2 in cve62215
	w, m := oneMatch(t, pc, cve36884, true, cve62215)
	wantMatch(t, "shipped after the listing", w, m, "notaffected", "", "", "older than this device's Windows 11 24H2", "came out on 1 Oct 2024")
	if w, _ := oneMatch(t, pc, cve36884, false, cve62215); w != "none" {
		t.Errorf("a fresh device: %s", w)
	}
	w, m = oneMatch(t, pc, cve36884, true)
	wantMatch(t, "release NVD never named", w, m, "existing", BasisProduct, SeverityMedium, "has not named Windows 11 24H2")
	recent := cve36884
	recent.CVE, recent.DateAdded = "CVE-2023-36424", winDay("2026-04-13") // an old flaw CISA listed this year
	w, m = oneMatch(t, pc, recent, true, cve62215)
	wantMatch(t, "listed this year", w, m, "existing", BasisProduct, SeverityMedium, "less than a year old")
	old := recent
	old.DateAdded = winDay("2025-06-01") // settled: NVD's list stood a year
	w, m = oneMatch(t, pc, old, true, cve62215)
	wantMatch(t, "settled", w, m, "notaffected", "", "", "over a year")
	// VulnCheck lists flaws without waiting for a fix: its date proves nothing about the release
	vc := cve36884
	vc.Source, vc.DateAdded = SourceVulnCheck, winDay("2026-03-01")
	w, m = oneMatch(t, pc, vc, true, cve62215)
	wantMatch(t, "VulnCheck, recent", w, m, "existing", BasisProduct, SeverityMedium)
	// one row the table does not know: as before, not checked
	other := cve36884
	other.CVE = "CVE-2099-0003"
	other.Affected = append(slices.Clone(other.Affected), Affected{CPE: "cpe:2.3:a:microsoft:server_message_block:1.0:*:*:*:*:*:*:*"})
	w, m = oneMatch(t, pc, other, true, cve62215)
	wantMatch(t, "a non-Windows row", w, m, "existing", BasisProduct, SeverityMedium, "has not checked")
}

// Review L1: a target the release's rows do not list proves nothing; review L2: "-" rows stay not checked; family rows of every
// release are not checked.
func TestMatchAsset_D546_WhatProvesNothing(t *testing.T) {
	x64only := nvdWindows("CVE-2099-0004", "2025-04-08", nvdRow{"windows_11_23h2", "*", "x64", "10.0.22631.5189"})
	w, m := oneMatch(t, winPC(22631, false, "5189", "arm64"), x64only, true)
	wantMatch(t, "arm64 PC, x64 rows only", w, m, "existing", BasisProduct, SeverityMedium, "on x64 only")
	dash := Vuln{CVE: "CVE-2099-0005", Vendor: "Microsoft", Product: "Windows", Affected: []Affected{{CPE: "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*"}}}
	w, m = oneMatch(t, winPC(17763, true, "8027", "x64"), dash, true)
	wantMatch(t, "windows_server_2019:-", w, m, "existing", BasisProduct, SeverityMedium)
	family := Vuln{CVE: "CVE-2099-0006", Vendor: "Microsoft", Product: "Windows", Affected: []Affected{{CPE: "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"}}}
	w, m = oneMatch(t, winPC(22631, false, "5189", "x64"), family, false)
	wantMatch(t, "o:microsoft:windows", w, m, "new", BasisProduct, SeverityMedium)
	// a family row next to the release's own patched row: the own row's No is not a proof
	both := cve29824
	both.CVE = "CVE-2099-0007"
	both.Affected = append(slices.Clone(both.Affected), Affected{CPE: "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*"})
	if w, _ := oneMatch(t, winPC(22631, false, "5189", "x64"), both, true); w == "notaffected" {
		t.Error("windows_11:* next to a patched row closed the finding")
	}
}

// Review M4: a person's "Windows 11" row next to the agent's release row does not keep the finding open.
func TestMatchAsset_D546_ManualWindowsRowIsCovered(t *testing.T) {
	a := winPC(22631, false, "5189", "x64")
	a.Software = append(a.Software, Software{ID: "s-m", Display: "Windows 11", Vendor: "Microsoft", Product: "Windows 11", Version: "10.0.22631.5189", Source: "manual", KevKeys: []string{"microsoft|windows"}})
	w, _ := oneMatch(t, a, cve29824, true)
	if w != "notaffected" {
		t.Fatalf("agent row and a manual row: %s", w)
	}
	alone := Asset{ID: "a-m", Name: "m", Software: a.Software[1:]} // without the agent's row the manual one is matched as before
	if w, _ := oneMatch(t, alone, cve29824, true); w != "existing" {
		t.Fatalf("manual row alone: %s", w)
	}
}

// One monthly update closes every flaw the PC is affected by: the latest end.
func TestFixedInForAll_D546_Windows(t *testing.T) {
	g := FixedInForAll(winPC(22631, false, "4460", "x64"), []Vuln{cve29824, cve62215, cve36884})
	f := g[cve29824.CVE]
	if f == nil || f.Kind != "fixed" || f.Fixed != "10.0.22631.6199" || !f.Closed[cve62215.CVE] || f.Closed[cve36884.CVE] {
		t.Fatalf("group: %+v", f)
	}
}
