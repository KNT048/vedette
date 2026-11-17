package findings

import (
	"strings"
	"testing"
)

// #910: a KEV entry reaches a software row through NVD's CPE list when CISA's vendor|product names a component ("Chromium V8",
// "Win32k") or another product ("IGEL OS"). The entries below are the rows the N100's feeds store for them (2026-11-16 copy).

func chromeRow(ver string) Software {
	return Software{ID: "s-chrome", Display: "Google Chrome", Vendor: "Google", Product: "Chrome", Version: ver, Source: "agent",
		KevKeys: []string{"google|chrome"}}
}

func edgeRow(ver string) Software {
	return Software{ID: "s-edge", Display: "Microsoft Edge", Vendor: "Microsoft", Product: "Edge", Version: ver, Source: "agent",
		KevKeys: []string{"microsoft|edge"}}
}

// cve202687491 is CISA "Google | Chromium V8"; NVD lists google:chrome before 153.0.8010.36.
func cve202687491() Vuln {
	return Vuln{CVE: "CVE-2026-87491", Vendor: "Google", Product: "Chromium V8", DateAdded: winDay("2026-09-09"), Published: winDay("2026-09-09"),
		Affected: []Affected{{CPE: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "153.0.8010.36"}}}}
}

func onlyMatch(t *testing.T, name string, res MatchResult) Match {
	t.Helper()
	if len(res.New)+len(res.Existing) != 1 {
		t.Fatalf("%s: new %v existing %v, want one match", name, res.New, res.Existing)
	}
	return append(res.New, res.Existing...)[0]
}

func TestMatchAsset_910_ChromiumV8OnChrome(t *testing.T) {
	t.Parallel()
	v := cve202687491()
	a := Asset{ID: "a", Name: "pc", OS: "Microsoft Windows 11 Pro", Software: []Software{chromeRow("150.0.7871.4")}}
	m := onlyMatch(t, "Chrome 150", MatchAsset(a, []Vuln{v}, nil, t0))
	if m.SoftwareID != "s-chrome" || m.Basis != BasisVersion || !m.Evidence.Agent || !strings.Contains(m.Evidence.Summary, "153.0.8010.36") {
		t.Errorf("Chrome 150: %+v", m)
	}
	if f := FixedInFor(a, v); f == nil || f.Kind != "fixed" || f.Fixed != "153.0.8010.36" {
		t.Errorf("fixed_in: %+v", f)
	}
	if r := RowFixes(a, []Vuln{v})[v.CVE]; r == nil || r.Fixed != "153.0.8010.36" || r.Software != "Google Chrome" {
		t.Errorf("row fix: %+v", r)
	}
	if got := matchedOn(a, KevInfo{Vendor: v.Vendor, Product: v.Product}, &v); got != "Google Chrome" {
		t.Errorf("matchedOn = %q, want the Chrome row", got)
	}

	a.Software = []Software{chromeRow("153.0.8010.36")} // updated: the finding closes on NVD's range
	res := MatchAsset(a, []Vuln{v}, map[string]bool{v.CVE: true}, t0)
	if len(res.New)+len(res.Existing) != 0 || len(res.NotAffected) != 1 {
		t.Errorf("Chrome 153.0.8010.36: %+v", res)
	}

	// CISA never named Chrome: no version, or an NVD row of every version, is no finding and no "add the version" item.
	a.Software = []Software{chromeRow("")}
	if res := MatchAsset(a, []Vuln{v}, nil, t0); len(res.New) != 0 || len(res.NeedVersion) != 0 {
		t.Errorf("Chrome without a version: %+v", res)
	}
	every := v
	every.Affected = []Affected{{CPE: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"}}
	a.Software = []Software{chromeRow("150.0.7871.4")}
	if res := MatchAsset(a, []Vuln{every}, nil, t0); len(res.New) != 0 || len(res.NeedVersion) != 0 {
		t.Errorf("NVD lists every Chrome version: %+v", res)
	}
}

// CVE-2022-21882 is CISA "Microsoft | Win32k"; NVD lists each Windows release with the build that fixes it. Published in 2022, it stays
// because a build was compared (D-615).
func TestMatchAsset_910_Win32kOnWindowsRelease(t *testing.T) {
	t.Parallel()
	v := Vuln{CVE: "CVE-2022-21882", Vendor: "Microsoft", Product: "Win32k", DateAdded: winDay("2022-02-04"), Published: winDay("2022-01-11"),
		Affected: []Affected{
			{CPE: "cpe:2.3:o:microsoft:windows_11_21h2:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.0.22000.434"}},
			{CPE: "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.0.20348.469"}},
			{CPE: "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*"},
		}}
	a := winPC(20348, true, "350", "x64")
	m := onlyMatch(t, "Server 2022 build 20348.350", MatchAsset(a, []Vuln{v}, nil, t0))
	if m.SoftwareID != "s-win" || m.Basis != BasisVersion || !strings.Contains(m.Evidence.Summary, "20348.469") {
		t.Errorf("Server 2022: %+v", m)
	}
	if f := FixedInFor(a, v); f == nil || f.Fixed != "10.0.20348.469" {
		t.Errorf("fixed_in: %+v", f)
	}
	a = winPC(20348, true, "469", "x64")
	if res := MatchAsset(a, []Vuln{v}, map[string]bool{v.CVE: true}, t0); len(res.New)+len(res.Existing) != 0 || len(res.NotAffected) != 1 {
		t.Errorf("Server 2022 build 20348.469: %+v", res)
	}
}

// CVE-2025-47827 is CISA "IGEL | IGEL OS" (a Secure Boot bypass); NVD lists the Windows releases with the build that revokes it.
// WINLAB01 (Server 2025 26100.1742) is affected until 26100.6899; its Edge row is not.
func TestMatchAsset_910_IGELEntryOnWindowsServer2025(t *testing.T) {
	t.Parallel()
	v := Vuln{CVE: "CVE-2025-47827", Vendor: "IGEL", Product: "IGEL OS", DateAdded: winDay("2025-10-14"), Published: winDay("2025-06-05"),
		Affected: []Affected{
			{CPE: "cpe:2.3:o:igel:igel_os:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "11.01.100"}},
			{CPE: "cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.0.26100.6899"}},
			{CPE: "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*"},
			{CPE: "cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.0.26100.6899"}},
		}}
	a := winlab01()
	m := onlyMatch(t, "WINLAB01", MatchAsset(a, []Vuln{v}, nil, t0))
	if m.SoftwareID != "s-win" || m.Basis != BasisVersion || !m.Evidence.Agent || !strings.Contains(m.Evidence.Summary, "26100.6899") {
		t.Errorf("WINLAB01: %+v", m)
	}
	if f := FixedInFor(a, v); f == nil || f.Kind != "fixed" || f.Fixed != "10.0.26100.6899" {
		t.Errorf("fixed_in: %+v", f)
	}
	if r := RowFixes(a, []Vuln{v})[v.CVE]; r == nil || !r.Windows || r.Fixed != "10.0.26100.6899" {
		t.Errorf("row fix: %+v", r)
	}
}

// CVE-2024-36971 is CISA "Android | Kernel"; NVD lists upstream linux_kernel ranges (6.7 to 6.9.4, 5.16 to 6.1.94). A distribution's
// kernel keeps its upstream version while it backports fixes, so only the distribution's own word decides (D-516): no word, no
// finding; Ubuntu's "fixed in linux 6.8.0-44.44" on 6.8.0-31.31 is one.
func TestMatchAsset_910_AndroidKernelEntryOnDistributionKernels(t *testing.T) {
	t.Parallel()
	v := Vuln{CVE: "CVE-2024-36971", Vendor: "Android", Product: "Kernel", DateAdded: winDay("2024-08-07"), Published: winDay("2024-06-10"),
		Affected: []Affected{
			{CPE: "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*"},
			{CPE: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "5.16", EndExcl: "6.1.94"}},
			{CPE: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "6.7", EndExcl: "6.9.4"}},
		}}
	kernel := func(ver, pkg, src string, packaged bool) Software {
		return Software{ID: "s-kernel", Display: "Kernel", Vendor: "Linux", Product: "Kernel", Version: ver, Source: "agent", Packaged: packaged,
			PkgVersion: pkg, PkgSource: src, KevKeys: []string{"linux|kernel"}}
	}
	ubuntu := Asset{ID: "u", Name: "ubuntu", OS: "Ubuntu 24.04.1 LTS", AgentOS: "Ubuntu 24.04.1 LTS", Software: []Software{kernel("6.8.0", "6.8.0-31.31", "linux-signed", true)}}
	debian := Asset{ID: "d", Name: "debian", OS: "Debian GNU/Linux 12 (bookworm)", AgentOS: "Debian GNU/Linux 12 (bookworm)",
		Software: []Software{kernel("6.1.69", "6.1.69-1", "linux-signed-amd64", true)}}
	typed := Asset{ID: "t", Name: "typed", OS: "Ubuntu 24.04.1 LTS", Software: []Software{kernel("6.8.0", "", "", false)}}
	typed.Software[0].Source = "manual"
	for _, a := range []Asset{ubuntu, debian, typed} {
		if res := MatchAsset(a, []Vuln{v}, nil, t0); len(res.New) != 0 || len(res.NeedVersion) != 0 {
			t.Errorf("%s without the distribution's word: %+v", a.Name, res)
		}
	}
	v.Distro = []DistroFix{
		{Distro: "ubuntu", Release: "24.04", Package: "linux", Status: "fixed", Fixed: "6.8.0-44.44"},
		{Distro: "debian", Release: "12", Package: "linux", Status: "fixed", Fixed: "6.1.94-1"}, // another upstream release: no word on 6.1.69-1
	}
	m := onlyMatch(t, "Ubuntu 24.04 kernel", MatchAsset(ubuntu, []Vuln{v}, nil, t0))
	if m.Basis != BasisVersion || !strings.Contains(m.Evidence.Summary, "6.8.0-44.44") {
		t.Errorf("Ubuntu kernel: %+v", m)
	}
	if f := FixedInFor(ubuntu, v); f == nil || f.DistroFixed != "6.8.0-44.44" {
		t.Errorf("Ubuntu fixed_in: %+v", f)
	}
	if res := MatchAsset(debian, []Vuln{v}, nil, t0); len(res.New) != 0 {
		t.Errorf("Debian kernel: %+v", res)
	}
}

// CVE-2025-14174 (CISA "Google | Chromium"): NVD lists Chrome up to 143.0.7499.40 and Chromium Edge before 143.0.3650.80. A Chromium
// Edge row is microsoft:edge_chromium too; an EdgeHTML one is not. On a device with both browsers the finding is on the Chrome row and
// names Chrome's fix, not Edge's.
func TestMatchAsset_910_ChromiumEntryOnChromeAndEdge(t *testing.T) {
	t.Parallel()
	v := Vuln{CVE: "CVE-2025-14174", Vendor: "Google", Product: "Chromium", DateAdded: winDay("2025-12-12"), Published: winDay("2025-12-12"),
		Affected: []Affected{
			{CPE: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", Range: VersionRange{EndIncl: "143.0.7499.40"}},
			{CPE: "cpe:2.3:a:microsoft:edge_chromium:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "143.0.3650.80"}},
		}}
	both := Asset{ID: "a", Name: "pc", Software: []Software{chromeRow("120.0.6099.109"), edgeRow("120.0.2210.61")}}
	if m := onlyMatch(t, "Chrome and Edge", MatchAsset(both, []Vuln{v}, nil, t0)); m.SoftwareID != "s-chrome" {
		t.Errorf("Chrome and Edge: matched %s", m.SoftwareID)
	}
	if f := FixedInFor(both, v); f == nil || f.Kind != "up_to" || f.Fixed != "143.0.7499.40" {
		t.Errorf("fixed_in of the Chrome finding: %+v", f)
	}
	edge := Asset{ID: "b", Name: "pc", Software: []Software{edgeRow("120.0.2210.61")}}
	if m := onlyMatch(t, "Edge", MatchAsset(edge, []Vuln{v}, nil, t0)); m.SoftwareID != "s-edge" || m.Basis != BasisVersion {
		t.Errorf("Edge: %+v", m)
	}
	if f := FixedInFor(edge, v); f == nil || f.Fixed != "143.0.3650.80" {
		t.Errorf("Edge fixed_in: %+v", f)
	}
	edge.Software = []Software{edgeRow("44.19041.1266.0")} // EdgeHTML: Chromium Edge's range says nothing about it
	if res := MatchAsset(edge, []Vuln{v}, nil, t0); len(res.New) != 0 || len(res.NeedVersion) != 0 {
		t.Errorf("Edge Legacy: %+v", res)
	}
}
