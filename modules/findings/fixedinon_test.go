package findings

import (
	"testing"
)

// A kernel CVE on no exploited list has no key that names its line, so the finding page reads its fix on the finding's own line: the
// distribution's fixed package and, with the fixed kernel installed and not running, the restart into it (the same answer as FixOf).
func TestFixedInOnReadsTheFindingsLineOfACatalogueCVE(t *testing.T) {
	t.Parallel()
	const osName = "Ubuntu 26.04.1 LTS"
	kernel := Software{ID: "s-kernel", Display: "Kernel", Vendor: "Linux", Product: "Kernel", Version: "7.0.0", Source: "agent", Packaged: true,
		PkgVersion: "7.0.0-43.43", PkgSource: "linux-signed", KevKeys: []string{"linux|kernel"}}
	image := Software{ID: "s-img", Display: "linux-image-7.0.0-44-generic", Vendor: "linux-image-7.0.0-44-generic", Product: "linux-image-7.0.0-44-generic",
		Version: "7.0.0", Source: "agent", Packaged: true, PkgVersion: "7.0.0-44.44", PkgSource: "linux-signed"}
	a := Asset{ID: "a", Name: "boxanna", OS: osName, AgentOS: osName, Software: []Software{kernel, image}}
	// a catalogue entry: no exploited list, so no vendor and product key; NVD's range and Ubuntu's word on its kernel package
	v := Vuln{CVE: "CVE-2026-90002", NVDAnswered: true,
		Affected: []Affected{{CPE: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "6.0", EndExcl: "7.0.1"}}},
		Distro:   []DistroFix{{Distro: "ubuntu", Release: "26.04", Package: "linux", Status: "fixed", Fixed: "7.0.0-44.44"}}}

	if f := FixOf(a, kernel, v); f.Kind != FixRestart || f.Version != "7.0.0-44.44" {
		t.Fatalf("stored fix %+v", f)
	}
	f := FixedInOn(a, kernel, v)
	if f == nil || f.Kind != "distro" || f.DistroFixed != "7.0.0-44.44" || f.RestartInto != "7.0.0-44.44" || f.Distro != "Ubuntu" {
		t.Fatalf("fixed_in %+v", f)
	}
}
