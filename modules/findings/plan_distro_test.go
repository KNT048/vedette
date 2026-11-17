package findings

import (
	"slices"
	"testing"
)

// debRow is an agent's deb row of an Ubuntu or Debian device.
func debRow(id, display, src, ver string) Software {
	return Software{ID: id, Display: display, Version: ver, Source: "agent", Packaged: true, PkgVersion: ver, PkgSource: src}
}

// kernelRow is the Kernel row intake builds from the running kernel image (vendor Linux, product Kernel).
func kernelRow(id, src, ver string) Software {
	s := debRow(id, "Kernel", src, ver)
	s.Vendor, s.Product = "Linux", "Kernel"
	return s
}

// distroV is a tier CVE with the distributions' fixed rows (Feeds.TierDistro).
func distroV(cve, tier string, daysAgo int, epss float64, rows ...DistroFix) TierVuln {
	v := tierV(cve, tier, daysAgo, epss)
	v.Distro = rows
	return v
}

func noble(pkg, fixed string, pro bool) DistroFix {
	return DistroFix{Distro: "ubuntu", Release: "24.04", Package: pkg, Status: "fixed", Fixed: fixed, Pro: pro}
}

// An Ubuntu device's packages are compared with Ubuntu's own first fixed version for its release and source package: below it
// (and Ubuntu's own build) the CVE is listed with basis distro, one item per source package naming the highest fixed version, Pro-only
// fixes apart. Left out: a CVE Ubuntu's data does not name for that release, a package at or above the fix, a PPA build, an exploited
// CVE, one older than 12 months. A device of a release the feeds hold no row for is not compared.
func TestPlan_DistroPackages(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "a-u", Name: "web-u", OS: "Ubuntu 24.04 LTS", Software: []Software{
		debRow("s1", "libssl3", "openssl", "3.0.13-0ubuntu3.4"),
		debRow("s2", "openssl", "openssl", "3.0.13-0ubuntu3.4"),
		kernelRow("s3", "linux-signed", "6.8.0-45.45"),
		debRow("s4", "nginx", "nginx", "1.24.0-2ubuntu7.1~ppa1"), // a PPA build below Ubuntu's fix: not Ubuntu's word (review r1 #4a of #808)
		debRow("s5", "sudo", "sudo", "1.9.15p5-3ubuntu5.24.04.1"),
		debRow("s6", "zlib1g", "zlib", "1:1.3.dfsg-3.1ubuntu2.1"),
	}}
	if d, rel, pkgs := DevicePackages(a); d != "ubuntu" || rel != "24.04" || !slices.Equal(pkgs, []string{"linux", "nginx", "openssl", "sudo", "zlib"}) {
		t.Fatalf("DevicePackages %q %q %v", d, rel, pkgs)
	}
	dv := []TierVuln{
		distroV("CVE-2026-50001", "likely", 30, 0.4, noble("openssl", "3.0.13-0ubuntu3.5", false)),
		distroV("CVE-2026-50002", "recent", 40, 0.01, noble("openssl", "3.0.13-0ubuntu3.6", false)),
		distroV("CVE-2026-50003", "recent", 40, 0.01, DistroFix{Distro: "ubuntu", Release: "22.04", Package: "openssl", Status: "fixed", Fixed: "3.0.2-0ubuntu1.19"}),
		distroV("CVE-2026-50004", "recent", 50, 0.02, noble("linux", "6.8.0-50.51", false)),
		distroV("CVE-2026-50005", "likely", 20, 0.9, noble("openssl", "3.0.13-0ubuntu3.9", false)),   // exploited: a finding
		distroV("CVE-2025-50006", "recent", 400, 0.01, noble("openssl", "3.0.13-0ubuntu3.5", false)), // older than 12 months
		distroV("CVE-2026-50007", "recent", 40, 0.01, noble("nginx", "1.24.0-2ubuntu7.3", false)),    // a PPA build: not Ubuntu's word
		distroV("CVE-2026-50008", "recent", 40, 0.01, noble("sudo", "1.9.15p5-3ubuntu5.24.04.1", false)),
		distroV("CVE-2026-50009", "recent", 60, 0.01, noble("zlib", "1:1.3.dfsg-3.1ubuntu2.1+esm1", true)),
		distroV("CVE-2026-50010", "recent", 70, 0.005, noble("openssl", "3.0.13-0ubuntu3.5+esm1", true), noble("openssl", "3.0.13-0ubuntu3.5", false)),
	}
	x := newTierIndex(nil).withDistro(dv, map[string]bool{"ubuntu/24.04": true})
	items, compared := matchTiers(a, x, map[string]bool{"CVE-2026-50005": true}, t0)
	if !compared || len(items) != 3 {
		t.Fatalf("compared %v, items %+v", compared, items)
	}
	ssl, kernel, zlib := items[0], items[1], items[2]
	if ssl.Group != "a-u/s1" || ssl.Kind != "distro" || ssl.Software != "openssl" || ssl.Version != "3.0.13-0ubuntu3.4" || ssl.Fixed != "3.0.13-0ubuntu3.6" || ssl.Pro {
		t.Fatalf("openssl %+v", ssl)
	}
	if got := cvesOf(ssl); !slices.Equal(got, []string{"CVE-2026-50001/likely/distro", "CVE-2026-50002/recent/distro", "CVE-2026-50010/recent/distro"}) {
		t.Fatalf("openssl cves %v", got)
	}
	if kernel.Software != "linux" || kernel.Fixed != "6.8.0-50.51" || kernel.Version != "6.8.0-45.45" || len(kernel.CVEs) != 1 {
		t.Fatalf("kernel %+v", kernel)
	}
	if zlib.Group != "a-u/s6/pro" || !zlib.Pro || zlib.Fixed != "1:1.3.dfsg-3.1ubuntu2.1+esm1" || cvesOf(zlib)[0] != "CVE-2026-50009/recent/distro" {
		t.Fatalf("zlib %+v", zlib)
	}
	// a release the feeds hold no row for: not compared, nothing listed (drop when unsure)
	a.OS = "Ubuntu 22.04 LTS"
	if items, compared = matchTiers(a, x, nil, t0); compared || len(items) != 0 {
		t.Fatalf("22.04 not covered: compared %v, %+v", compared, items)
	}
}

// Distribution items through the job and the endpoint: the item says kind distro, the fixed version and pro, and the device counts as compared.
func TestPlan_DistroThroughTheEndpoint(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.inv.assets["a-u"] = AssetView{ID: "a-u", Hostname: ptr("web-u"), IP: "192.168.10.31", Kind: "server", Name: "web-u"}
	e.inv.match["a-u"] = Asset{ID: "a-u", Name: "web-u", OS: "Ubuntu 24.04 LTS", Software: []Software{debRow("s1", "libssl3", "openssl", "3.0.13-0ubuntu3.4")}}
	e.feeds.distro = []TierVuln{distroV("CVE-2026-50001", "likely", 30, 0.4, noble("openssl", "3.0.13-0ubuntu3.5", false))}
	e.feeds.covered = map[string]bool{"ubuntu/24.04": true}
	e.feeds.tier = TierStatus{EPSS: "ready", Recent: "ready", EPSSDate: t0, RecentSince: t0.AddDate(0, 0, -365)}
	e.feeds.stamp = "s1"
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	c, b := e.call("GET", "/findings/plan?asset=a-u", "viewer", "")
	items, _ := b["items"].([]any)
	if c != 200 || len(items) != 1 {
		t.Fatalf("%d %v", c, b)
	}
	it := items[0].(map[string]any)
	cve := it["cves"].([]any)[0].(map[string]any)
	if it["kind"] != "distro" || it["fixed"] != "3.0.13-0ubuntu3.5" || it["pro"] != false || it["software"] != "openssl" || cve["basis"] != "distro" || cve["tier"] != "likely" {
		t.Fatalf("item %v", it)
	}
	if v := e.svc.Plan(); v.Compared != 1 || v.Unchecked != 1 { // a-1 of the env has no row the plan compares
		t.Fatalf("plan %+v", v)
	}
}

// A long list opens on what matters: likely first by EPSS, then the recent ones by CVSS score (their EPSS is under 10 % and
// close together), then by EPSS, then newest.
func TestPlan_CVEOrderLikelyThenSeverity(t *testing.T) {
	t.Parallel()
	cs := []PlanCVE{
		{CVE: "CVE-2026-1", Tier: "recent", Score: ptr(5.0), EPSS: ptr(0.05), Published: "2026-10-01"},
		{CVE: "CVE-2026-2", Tier: "recent", Score: ptr(9.8), EPSS: ptr(0.001), Published: "2026-09-01"},
		{CVE: "CVE-2026-3", Tier: "likely", Score: ptr(5.0), EPSS: ptr(0.2), Published: "2026-08-01"},
		{CVE: "CVE-2026-4", Tier: "likely", Score: ptr(9.0), EPSS: ptr(0.6), Published: "2026-08-01"},
		{CVE: "CVE-2026-5", Tier: "recent", Score: nil, EPSS: ptr(0.09), Published: "2026-10-01"},
		{CVE: "CVE-2026-6", Tier: "recent", Score: ptr(5.0), EPSS: ptr(0.07), Published: "2026-10-01"},
	}
	sortPlanCVEs(cs)
	var got []string
	for _, c := range cs {
		got = append(got, c.CVE)
	}
	if want := []string{"CVE-2026-4", "CVE-2026-3", "CVE-2026-2", "CVE-2026-6", "CVE-2026-1", "CVE-2026-5"}; !slices.Equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}

// Review r1 #1 of #808: apt keeps the previous kernel's modules, headers and tools installed; only the running kernel's packages (the
// Kernel row's source and version) count, so a box that runs the fix gets no "Upgrade the linux package" item, and a box without a
// Kernel row compares no kernel package. A linux-* source that is no kernel (linux-firmware) is compared as any package.
func TestPlan_DistroKernelOnlyTheRunningOne(t *testing.T) {
	t.Parallel()
	dv := []TierVuln{
		distroV("CVE-2026-51001", "recent", 30, 0.01, noble("linux", "6.8.0-50.51", false)),
		distroV("CVE-2026-51002", "recent", 30, 0.01, noble("linux-firmware", "20240318.git3b128b60-0ubuntu2.5", false)),
	}
	x := newTierIndex(nil).withDistro(dv, map[string]bool{"ubuntu/24.04": true})
	a := Asset{ID: "a-k", OS: "Ubuntu 24.04 LTS", Software: []Software{
		kernelRow("s1", "linux-signed", "6.8.0-50.51"),
		debRow("s2", "linux-modules-6.8.0-45-generic", "linux", "6.8.0-45.45"),
		debRow("s3", "linux-headers-6.8.0-45", "linux", "6.8.0-45.45"),
		debRow("s4", "linux-firmware", "linux-firmware", "20240318.git3b128b60-0ubuntu2.3"),
	}}
	items, compared := matchTiers(a, x, nil, t0)
	if !compared || len(items) != 1 || items[0].Software != "linux-firmware" {
		t.Fatalf("running the fixed kernel: compared %v, %+v", compared, items)
	}
	if _, _, pkgs := DevicePackages(a); !slices.Equal(pkgs, []string{"linux", "linux-firmware"}) {
		t.Fatalf("packages %v", pkgs)
	}
	// running the old kernel: its image and modules of that version count, once, at that version
	a.Software[0] = kernelRow("s1", "linux-signed", "6.8.0-45.45")
	if items, _ = matchTiers(a, x, nil, t0); len(items) != 2 || items[0].Software != "linux" || items[0].Version != "6.8.0-45.45" || len(items[0].CVEs) != 1 {
		t.Fatalf("running the old kernel: %+v", items)
	}
	// no Kernel row: no kernel package is compared
	a.Software = a.Software[1:]
	if items, _ = matchTiers(a, x, nil, t0); len(items) != 1 || items[0].Software != "linux-firmware" {
		t.Fatalf("no Kernel row: %+v", items)
	}
}
