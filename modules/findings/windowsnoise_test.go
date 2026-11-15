package findings

import (
	"strings"
	"testing"
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

// N52-1 (D-610): a Windows Server 2025 VM whose agent gives its exact build (26100.1742, its GA media) had 140 open product findings of
// XP-era entries. An entry NVD lists only for releases before Windows 10, with a CVE id from before Windows 10, is ruled out with a proof
// and closes an open finding; the D-546 (d) proof also holds at 26100.1742 now that it is Server 2025's first public build.
func TestMatchAsset_D610_XPEraEntriesDoNotApply(t *testing.T) {
	srv := winPC(26100, true, "1742", "x64")
	w, m := oneMatch(t, srv, cve0367, true, cve62215)
	wantMatch(t, "CVE-2002-0367 open", w, m, "notaffected", "", "", "only for Windows releases before Windows 10 (windows 2000, windows nt)", "dates from 2002", "Windows Server 2025 is not affected")
	if w, _ := oneMatch(t, srv, cve0367, false, cve62215); w != "none" {
		t.Errorf("CVE-2002-0367 on a fresh device: %s", w)
	}
	// CVE-2004-0210 (POSIX subsystem): NVD also lists Interix 2.2, another product at one version of that time
	w, m = oneMatch(t, srv, cve0210, true, cve62215)
	wantMatch(t, "CVE-2004-0210", w, m, "notaffected", "", "", "(windows 2000, windows nt) and interix 2.2", "dates from 2004")
	w, m = oneMatch(t, srv, cve4250, true, cve62215)
	wantMatch(t, "CVE-2008-4250 (KEV 2026)", w, m, "notaffected", "", "", "dates from 2008")
	// CVE-2019-0708 (BlueKeep) names only older releases and has stood in KEV since 2021: D-546 (d) at Server 2025's GA build.
	blue := nvdRaw("CVE-2019-0708", "2021-11-03", "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*",
		"cpe:2.3:o:microsoft:windows_xp:-:sp3:*:*:*:*:*:*")
	w, m = oneMatch(t, srv, blue, true, cve62215)
	wantMatch(t, "CVE-2019-0708", w, m, "notaffected", "", "", "only for Windows releases older than this device's Windows Server 2025")
	// a 2018 CVE CISA listed only this year, NVD naming only Windows 7: its list has stood since 2018 (the CVE's year, D-610)
	w, m = oneMatch(t, srv, nvdRaw("CVE-2018-3333", "2026-10-01", "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*"), true, cve62215)
	wantMatch(t, "2018 CVE listed this year", w, m, "notaffected", "", "", "the CVE dates from 2018, so NVD's list has stood for over a year")
}

// D-610 stays conservative: an entry without NVD data, one with a family row of every Windows release, one naming a release Vedette does
// not know, a recent listing of a CVE of Windows 10's time naming only older releases, and a device NVD never named keep their finding.
func TestMatchAsset_D610_StaysWhenNVDCannotTell(t *testing.T) {
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
		if w, m := oneMatch(t, srv, tc.v, true, cve62215); w != "existing" || m.Basis != BasisProduct {
			t.Errorf("%s: %s %s %q", tc.name, w, m.Basis, m.Evidence.Summary)
		}
	}
	// review H2 guard: a list that never names the device's release proves nothing
	if w, _ := oneMatch(t, srv, cve0367, true); w != "existing" {
		t.Errorf("unnamed release: %s", w)
	}
}

// N52-2: a product-only match on a row the device's agent reported with its version says so (evidence.agent_row), so the page does not
// ask to add the version; a typed row's does not.
func TestMatchAsset_N52_AgentRowProductMatch(t *testing.T) {
	sw := func(source string) Asset {
		return Asset{ID: "a", Name: "byn", Software: []Software{{ID: "s", Display: "Acme Server", Vendor: "acme", Product: "server", Version: "2016", Source: source, KevKeys: []string{"acme|server"}}}}
	}
	v := Vuln{CVE: "CVE-2026-11111", Vendor: "Acme", Product: "Server", DateAdded: winDay("2026-10-01")} // no NVD data: product match
	for _, tc := range []struct {
		source string
		want   bool
	}{{"agent", true}, {"manual", false}} {
		res := MatchAsset(sw(tc.source), []Vuln{v}, map[string]bool{}, winNow)
		if len(res.New) != 1 || res.New[0].Basis != BasisProduct || res.New[0].Evidence.AgentRow != tc.want || res.New[0].Evidence.Agent {
			t.Errorf("%s: %+v", tc.source, res.New)
		}
		if !strings.Contains(res.New[0].Evidence.Summary, "lists no affected versions") {
			t.Errorf("%s: %q", tc.source, res.New[0].Evidence.Summary)
		}
	}
}
