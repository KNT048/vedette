package findings

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// A distribution kernel is judged once per CVE, on its Kernel row (the running kernel): the headers, modules and tools of any
// installed kernel, an image that does not run, a metapackage and linux-libc-dev are parts of a kernel, never matched on their own;
// an installed image at or above the distribution's fix turns the fix into a restart.
func TestDistroKernelOnceOnTheRunningKernel(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	const osName = "Ubuntu 26.04.1 LTS"
	pkg := func(name, full, src string) Software {
		return Software{ID: "s-" + name, Display: name, Vendor: name, Product: name, Version: "7.0.0", Source: "agent", Packaged: true, PkgVersion: full, PkgSource: src}
	}
	kernel := Software{ID: "s-kernel", Display: "Kernel", Vendor: "Linux", Product: "Kernel", Version: "7.0.0", Source: "agent", Packaged: true,
		PkgVersion: "7.0.0-43.43", PkgSource: "linux-signed", KevKeys: []string{"linux|kernel"}}
	parts := []Software{
		pkg("linux-headers-7.0.0-43-generic", "7.0.0-43.43", "linux"), pkg("linux-modules-7.0.0-43-generic", "7.0.0-43.43", "linux"),
		pkg("linux-tools-7.0.0-43", "7.0.0-43.43", "linux"), pkg("linux-image-generic", "7.0.0.44.44", "linux-meta"),
		pkg("linux-libc-dev", "7.0.0-44.44", "linux"), pkg("linux-modules-7.0.0-44-generic", "7.0.0-44.44", "linux"),
	}
	newImage := pkg("linux-image-7.0.0-44-generic", "7.0.0-44.44", "linux-signed")
	firmware := pkg("linux-firmware", "20260319.git1a2b3c4d-0ubuntu1", "linux-firmware")
	v := Vuln{CVE: "CVE-2026-90001", Vendor: "Linux", Product: "Kernel", NVDAnswered: true,
		Distro: []DistroFix{{Distro: "ubuntu", Release: "26.04", Package: "linux", Status: "fixed", Fixed: "7.0.0-44.44"}}}
	device := func(sw ...Software) Asset {
		return Asset{ID: "a", Name: "boxanna", OS: osName, AgentOS: osName, Software: sw}
	}

	// the new kernel is installed and does not run yet: one finding, on the Kernel row, fixed by a restart
	a := device(append([]Software{kernel, newImage, firmware}, parts...)...)
	m := onlyMatch(t, "installed, not running", MatchAsset(a, []Vuln{v}, nil, now))
	if m.SoftwareID != kernel.ID || !strings.Contains(m.Evidence.Summary, "the fixed kernel 7.0.0-44.44 is already installed, so this device has the flaw until it restarts into it") {
		t.Fatalf("installed, not running: %+v", m)
	}
	if f := FixOf(a, kernel, v); f.Kind != FixRestart || f.Version != "7.0.0-44.44" {
		t.Fatalf("installed, not running: fix %+v", f)
	}
	if f := FixedInFor(a, v); f == nil || f.DistroFixed != "7.0.0-44.44" || f.RestartInto != "7.0.0-44.44" {
		t.Fatalf("installed, not running: fixed_in %+v", f)
	}
	if w := FixWords(Fix{Kind: FixRestart, Version: "7.0.0-44.44"}, "Kernel", ""); !strings.HasPrefix(w, "restart the device so it runs the installed Kernel 7.0.0-44.44") {
		t.Fatalf("fix words %q", w)
	}
	if d, rel, pkgs := DevicePackages(a); d != "ubuntu" || rel != "26.04" || !slices.Equal(pkgs, []string{"linux", "linux-firmware"}) {
		t.Fatalf("device packages %s %s %v", d, rel, pkgs)
	}

	// the fixed kernel is not installed: the fix is to install it
	if f := FixOf(device(append([]Software{kernel}, parts...)...), kernel, v); f.Kind != FixDistroUpdate || f.Version != "7.0.0-44.44" {
		t.Fatalf("not installed: fix %+v", f)
	}
	if f := FixedInFor(device(append([]Software{kernel}, parts...)...), v); f == nil || f.RestartInto != "" {
		t.Fatalf("not installed: fixed_in %+v", f)
	}
	// an image the distribution did not build (a PPA) is no fix
	ppa := pkg("linux-image-7.0.0-44-generic", "7.0.0-44.44~ppa1", "linux-signed")
	if f := FixOf(device(kernel, ppa), kernel, v); f.Kind != FixDistroUpdate {
		t.Fatalf("a PPA image: fix %+v", f)
	}
	// an installed kernel below the fix: an update, not a restart
	older := pkg("linux-image-7.0.0-44-generic", "7.0.0-43.50", "linux-signed")
	if f := FixOf(device(kernel, older), kernel, v); f.Kind != FixDistroUpdate {
		t.Fatalf("an installed kernel below the fix: fix %+v", f)
	}

	// after the restart: the Kernel row is the new image; the old kernel's packages give nothing
	running := kernel
	running.PkgVersion = "7.0.0-44.44"
	oldImage := pkg("linux-image-7.0.0-43-generic", "7.0.0-43.43", "linux-signed")
	if res := MatchAsset(device(append([]Software{running, oldImage}, parts...)...), []Vuln{v}, map[string]bool{v.CVE: true}, now); len(res.New)+len(res.Existing) != 0 || len(res.NotAffected) != 1 {
		t.Fatalf("after the restart: %+v", res)
	}

	// a container shares its host's kernel: linux-libc-dev alone is no finding
	if res := MatchAsset(device(pkg("linux-libc-dev", "7.0.0-43.43", "linux")), []Vuln{v}, nil, now); len(res.New) != 0 {
		t.Fatalf("linux-libc-dev alone: %+v", res)
	}

	// Alpine's kernel package is the kernel itself (no ABI-named packages): never left out
	alpine := Asset{ID: "al", Name: "alp", OS: "Alpine Linux 3.23", AgentOS: "Alpine Linux 3.23", Software: []Software{
		{ID: "s-lts", Display: "linux-lts", Vendor: "linux-lts", Product: "linux-lts", Version: "6.12.40", Source: "agent", Packaged: true, PkgVersion: "6.12.40-r0", PkgSource: "linux-lts"}}}
	if sws := deviceSoftware(alpine); len(sws) != 1 {
		t.Fatalf("Alpine: %+v", sws)
	}
}
