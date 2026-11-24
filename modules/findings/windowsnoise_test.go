package findings

import (
	"strings"
	"testing"
	"time"
)

// nvdRaw is a KEV "Microsoft | Windows" entry with NVD's rows as NVD writes them (no ranges).
func nvdRaw(cve, added string, cpes ...string) Vuln {
	v := Vuln{CVE: cve, Vendor: "Microsoft", Product: "Windows", DateAdded: winDay(added)}
	for _, c := range cpes {
		v.Affected = append(v.Affected, Affected{CPE: c})
	}
	return v
}

var (
	// NVD's rows of CVE-2002-0367 (smss.exe, published 2002-06-25; CISA KEV 2022-03-03), read from NVD on 2026-11-15.
	cve0367 = nvdRaw("CVE-2002-0367", "2022-03-03", "cpe:2.3:o:microsoft:windows_2000:-:*:*:*:*:*:*:*",
		"cpe:2.3:o:microsoft:windows_nt:4.0:*:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_nt:4.0:-:*:*:terminal_server:*:*:*")
	// NVD's rows of CVE-2004-0210 (read 2026-11-15).
	cve0210 = nvdRaw("CVE-2004-0210", "2022-03-03", "cpe:2.3:a:microsoft:interix:2.2:*:*:*:*:*:*:*",
		"cpe:2.3:o:microsoft:windows_2000:-:sp4:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_nt:4.0:sp6a:*:*:server:*:*:*")
	// CVE-2008-4250 (MS08-067), added to KEV in May 2026: NVD's list names only releases before Windows 10.
	cve4250 = nvdRaw("CVE-2008-4250", "2026-05-20", "cpe:2.3:o:microsoft:windows_2000:-:sp4:*:*:*:*:*:*",
		"cpe:2.3:o:microsoft:windows_server_2003:-:sp1:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_server_2008:-:*:*:*:*:*:x64:*",
		"cpe:2.3:o:microsoft:windows_vista:-:sp1:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_xp:-:sp2:*:*:*:*:*:*")
)

// A Windows Server 2025 VM whose agent gives its exact build (26100.1742, its GA media) had 140 open product findings of
// XP-era entries. An entry NVD lists only for releases before Windows 10, with a CVE id from before Windows 10, is ruled out with a proof
// and closes an open finding; the older-releases proof also holds at 26100.1742 now that it is Server 2025's first public build.
func TestMatchAsset_XPEraEntriesDoNotApply(t *testing.T) {
	srv := winPC(26100, true, "1742", "x64")
	w, m := oneMatch(t, srv, cve0367, true, cve62215)
	wantMatch(t, "CVE-2002-0367 open", w, m, "notaffected", "", "", "only for Windows releases before Windows 10 (Windows 2000, Windows NT 4.0 or older)", "dates from 2002", "Windows Server 2025 is not affected")
	if w, _ := oneMatch(t, srv, cve0367, false, cve62215); w != "none" {
		t.Errorf("CVE-2002-0367 on a fresh device: %s", w)
	}
	// CVE-2004-0210 (POSIX subsystem): NVD also lists Interix 2.2, another product at one version of that time
	w, m = oneMatch(t, srv, cve0210, true, cve62215)
	wantMatch(t, "CVE-2004-0210", w, m, "notaffected", "", "", "(Windows 2000, Windows NT 4.0 or older) and Interix 2.2", "dates from 2004")
	w, m = oneMatch(t, srv, cve4250, true, cve62215)
	wantMatch(t, "CVE-2008-4250 (KEV 2026)", w, m, "notaffected", "", "", "dates from 2008")
	// CVE-2019-0708 (BlueKeep) names only older releases and has stood in KEV since 2021: the older-releases proof at Server 2025's GA build.
	blue := nvdRaw("CVE-2019-0708", "2021-11-03", "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*",
		"cpe:2.3:o:microsoft:windows_xp:-:sp3:*:*:*:*:*:*")
	w, m = oneMatch(t, srv, blue, true, cve62215)
	wantMatch(t, "CVE-2019-0708", w, m, "notaffected", "", "", "only for Windows releases older than this device's Windows Server 2025")
	// a 2018 CVE CISA listed only this year, NVD naming only Windows 7: its list has stood since 2018 (the CVE's year)
	w, m = oneMatch(t, srv, nvdRaw("CVE-2018-3333", "2026-06-01", "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*"), true, cve62215)
	wantMatch(t, "2018 CVE listed this year", w, m, "notaffected", "", "", "the CVE dates from 2018, so NVD's list has stood for over a year")
}

// The old-list proof stays conservative: an entry without NVD data, one with a family row of every Windows release, one naming a release Vedette does
// not know, a recent listing of a CVE of Windows 10's time naming only older releases, and a device NVD never named keep their finding.
func TestMatchAsset_StaysWhenNVDCannotTell(t *testing.T) {
	srv := winPC(26100, true, "1742", "x64")
	for _, tc := range []struct {
		name string
		v    Vuln
	}{
		{"no NVD data", Vuln{CVE: "CVE-2003-0352", Vendor: "Microsoft", Product: "Windows", DateAdded: winDay("2022-03-03")}},
		{"family row", nvdRaw("CVE-2004-1111", "2022-03-03", "cpe:2.3:o:microsoft:windows_nt:4.0:*:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*")},
		{"another product at any version", nvdRaw("CVE-2004-2222", "2022-03-03", "cpe:2.3:o:microsoft:windows_nt:4.0:*:*:*:*:*:*:*", "cpe:2.3:a:microsoft:interix:*:*:*:*:*:*:*:*")},
		{"unknown release", nvdRaw("CVE-2006-2222", "2022-03-03", "cpe:2.3:o:microsoft:windows_xp:-:*:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_ce:5.0:*:*:*:*:*:*:*")},
		{"this year's CVE listed this year", nvdRaw("CVE-2026-3333", "2026-10-01", "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*")},
		{"last year's CVE listed this year", nvdRaw("CVE-2025-3333", "2026-10-01", "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*")},
	} {
		if w, m := oneMatch(t, srv, tc.v, true, cve62215); w != "nameonly" || m.Basis != BasisProduct { // Kept, not a finding
			t.Errorf("%s: %s %s %q", tc.name, w, m.Basis, m.Evidence.Summary)
		}
	}
	// review H2 guard: a list that never names the device's release proves nothing
	if w, _ := oneMatch(t, srv, cve0367, true); w != "nameonly" {
		t.Errorf("unnamed release: %s", w)
	}
}

// As the name-only rule reads it: a product-only match on a row the device's agent reported with its version is no finding any more,
// agent row or typed row alike: only the product name matched (NVD has no data yet), so the CVE is dropped (NameOnly) and the
// AgentRow flag still says the agent gave the version.
func TestMatchAsset_AgentRowProductMatchIsNameOnly(t *testing.T) {
	sw := func(source string) Asset {
		return Asset{ID: "a", Name: "srv01", Software: []Software{{ID: "s", Display: "Acme Server", Vendor: "acme", Product: "server", Version: "2016", Source: source, KevKeys: []string{"acme|server"}}}}
	}
	v := Vuln{CVE: "CVE-2026-11111", Vendor: "Acme", Product: "Server", DateAdded: winDay("2026-10-01"), NVDAnswered: true} // NVD has no data: product match
	for _, tc := range []struct {
		source string
		want   bool
	}{{"agent", true}, {"manual", false}} {
		res := MatchAsset(sw(tc.source), []Vuln{v}, map[string]bool{}, winNow)
		if len(res.New) != 0 || len(res.NameOnly) != 1 || res.NameOnly[0].Basis != BasisProduct || res.NameOnly[0].Evidence.AgentRow != tc.want {
			t.Fatalf("%s: new %+v name-only %+v", tc.source, res.New, res.NameOnly)
		}
		if s := res.NameOnly[0].Evidence.Summary; !strings.HasPrefix(s, NameOnlyNote) || !strings.Contains(s, "NVD has not published which products CVE-2026-11111 affects yet") {
			t.Errorf("%s: %q", tc.source, s)
		}
		if !strings.Contains(res.NameOnly[0].said, "lists no affected versions") {
			t.Errorf("%s: %q", tc.source, res.NameOnly[0].said)
		}
	}
}

// What the old-list proof must never close (#801).
func TestMatchAsset_OldWindowsListsThatNeverClose(t *testing.T) {
	srv := winPC(26100, true, "1742", "x64")
	pc24 := winPC(26100, false, "1742", "x64")
	stays := func(name string, a Asset, v Vuln) {
		t.Helper()
		if w, m := oneMatch(t, a, v, true, cve62215); w != "nameonly" || m.Basis != BasisProduct { // Kept, not a finding
			t.Errorf("%s: %s %s %q", name, w, m.Basis, m.Evidence.Summary)
		}
	}
	// #1: windows_nt at any version, or "-", is every NT release, NT 10.0 among them
	stays("windows_nt:*", srv, nvdRaw("CVE-2004-3333", "2022-03-03", "cpe:2.3:o:microsoft:windows_2000:-:*:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_nt:*:*:*:*:*:*:*:*"))
	stays("windows_nt:-", srv, nvdRaw("CVE-2004-3334", "2022-03-03", "cpe:2.3:o:microsoft:windows_nt:-:*:*:*:*:*:*:*"))
	// #2: CVE-2013-3900 (KEV since 2022, fix opt-in), which Microsoft extended to Windows 10 and later: with NVD's rows of 2026-10-07 (they
	// name 24H2 and Server 2025 with no range) and with an older list naming only releases before Windows 10 or only up to 23H2/2022
	var now3900 []string
	for _, p := range []string{"windows_10_1507:-", "windows_10_1809:-", "windows_10_22h2:-", "windows_11_23h2:-", "windows_11_24h2:-", "windows_7:-:sp1",
		"windows_8.1:-", "windows_server_2008:r2:sp1", "windows_server_2012:r2", "windows_server_2016:-", "windows_server_2019:-", "windows_server_2022:-",
		"windows_server_2022_23h2:-", "windows_server_2025:-"} {
		parts := strings.SplitN(p, ":", 3)
		upd := "*"
		if len(parts) == 3 {
			upd = parts[2]
		}
		now3900 = append(now3900, "cpe:2.3:o:microsoft:"+parts[0]+":"+parts[1]+":"+upd+":*:*:*:*:*:*")
	}
	cve3900 := nvdRaw("CVE-2013-3900", "2022-01-10", now3900...)
	stays("CVE-2013-3900 now, Server 2025", srv, cve3900)
	stays("CVE-2013-3900 now, 24H2", pc24, cve3900)
	stays("CVE-2013-3900 old list", srv, nvdRaw("CVE-2013-3900", "2022-01-10", "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:*:*"))
	stays("CVE-2013-3900 list up to 2022", srv, nvdRaw("CVE-2013-3900", "2022-01-10", "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*"))
	// #2: a pre-2015 entry CISA listed within 90 days: Microsoft and NVD may still be revisiting it
	stays("listed last month", srv, nvdRaw("CVE-2009-4444", "2026-10-20", "cpe:2.3:o:microsoft:windows_xp:-:sp3:*:*:*:*:*:*"))
	if _, m := oneMatch(t, srv, nvdRaw("CVE-2018-4444", "2026-10-20", "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*"), true, cve62215); !strings.Contains(m.Evidence.Summary, "less than 90 days ago") {
		t.Errorf("recent listing of an old CVE: %q", m.Evidence.Summary)
	}
	// #8: a pre-2015 entry that also lists 24H2 (Server 2025's build) stays; a still-shipping product at one version (IE 11) keeps it
	stays("also 24H2", srv, nvdRaw("CVE-2014-5555", "2022-03-03", "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_11_24h2:-:*:*:*:*:*:*"))
	stays("IE 11 row", srv, nvdRaw("CVE-2014-6666", "2022-03-03", "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*", "cpe:2.3:a:microsoft:internet_explorer:11:*:*:*:*:*:*:*"))
	// #3: a CVE of the year the release came out, fixed in a late update, whose list names older releases only, listed by CISA in 2026
	late := nvdRaw("CVE-2024-7777", "2026-03-01", "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:*:*")
	late.Affected[0].Range = VersionRange{EndExcl: "10.0.20348.2849"}
	late.Affected[1].Range = VersionRange{EndExcl: "10.0.22631.4460"}
	stays("CVE-2024 on Server 2025 GA", srv, late)
	// #8: the CVE-year proof on a build below the release's first public one (a 24H2 Copilot+ PC on 26100.712)
	if w, m := oneMatch(t, winPC(26100, false, "712", "arm64"), nvdRaw("CVE-2018-8888", "2026-10-01", "cpe:2.3:o:microsoft:windows_10_1809:-:*:*:*:*:*:*:*"), true, cve62215); w != "nameonly" || !strings.Contains(m.Evidence.Summary, "first public one") {
		t.Errorf("below the first public build: %s %q", w, m.Evidence.Summary)
	}
}

// Review r2 of #801: the CVE-year proof needs every listed release to be out by the CVE's year (a CVE-2010 list naming Server 2022 grew
// later); the Interix exception is Microsoft's application only; a missing, future or VulnCheck-recent listing date closes nothing.
func TestMatchAsset_CVEYearProofNeedsEveryListedRelease(t *testing.T) {
	srv := winPC(26100, true, "1742", "x64")
	stays := func(name string, v Vuln) {
		t.Helper()
		if w, m := oneMatch(t, srv, v, true, cve62215); w != "nameonly" || m.Basis != BasisProduct { // Kept, not a finding
			t.Errorf("%s: %s %s %q", name, w, m.Basis, m.Evidence.Summary)
		}
	}
	stays("CVE-2010 listing Server 2022", nvdRaw("CVE-2010-9999", "2026-05-01", "cpe:2.3:o:microsoft:windows_7:-:*:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*"))
	stays("another vendor's interix", nvdRaw("CVE-2004-7777", "2022-03-03", "cpe:2.3:o:microsoft:windows_2000:-:*:*:*:*:*:*:*", "cpe:2.3:a:acme:interix:2.2:*:*:*:*:*:*:*"))
	stays("interix as an OS row", nvdRaw("CVE-2004-7778", "2022-03-03", "cpe:2.3:o:microsoft:windows_2000:-:*:*:*:*:*:*:*", "cpe:2.3:o:microsoft:interix:2.2:*:*:*:*:*:*:*"))
	zero := nvdRaw("CVE-2008-7779", "2022-03-03", "cpe:2.3:o:microsoft:windows_xp:-:*:*:*:*:*:*:*")
	zero.DateAdded = time.Time{}
	stays("no listing date", zero)
	stays("listing date in the future", nvdRaw("CVE-2008-7780", "2027-01-01", "cpe:2.3:o:microsoft:windows_xp:-:*:*:*:*:*:*:*"))
	vc := nvdRaw("CVE-2008-7781", "2026-10-01", "cpe:2.3:o:microsoft:windows_xp:-:*:*:*:*:*:*:*")
	vc.Source = SourceVulnCheck
	stays("VulnCheck-only, listed last month", vc)
	vcOld := nvdRaw("CVE-2018-7782", "2026-03-01", "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*")
	vcOld.Source = SourceVulnCheck // its date is VulnCheck's; the CVE-year proof holds from it as from CISA's
	if w, _ := oneMatch(t, srv, vcOld, true, cve62215); w != "notaffected" {
		t.Errorf("VulnCheck-only, listed 8 months ago: %s", w)
	}
}
