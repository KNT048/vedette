package findings

import (
	"strings"
	"testing"
	"time"
)

// D-516: on a packaged deb row the distribution's word on its own package decides before NVD's upstream ranges.
func TestDistroDecidesForAPackagedRow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	ssh := func(full, source string) Software {
		return Software{ID: "s-ssh", Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6p1", KevKeys: []string{"openbsd|openssh"},
			Source: source, Packaged: true, PkgVersion: full, PkgSource: "openssh"}
	}
	// NVD: every OpenSSH before 10.6p2 is affected, so the upstream 9.6p1 is inside the range
	v := Vuln{CVE: "CVE-2026-10001", Vendor: "OpenBSD", Product: "OpenSSH",
		Affected: []Affected{{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.6p2"}}},
		Distro: []DistroFix{
			{Distro: "ubuntu", Release: "24.04", Package: "openssh", Status: "fixed", Fixed: "1:9.6p1-3ubuntu13.5"},
			{Distro: "ubuntu", Release: "24.04", Package: "openssh", Status: "not_affected"}, // the fixed version wins
			{Distro: "ubuntu", Release: "20.04", Package: "openssh", Status: "fixed", Fixed: "1:8.2p1-4ubuntu0.13+esm3", Pro: true},
			{Distro: "ubuntu", Release: "26.04", Package: "openssh", Status: "not_affected"},
			{Distro: "debian", Release: "12", Package: "openssh", Status: "fixed", Fixed: "1:9.2p1-2+deb12u5"},
			{Distro: "ubuntu", Release: "24.04", Package: "openssh-ssh1", Status: "fixed", Fixed: "1:99"}, // another source package
		}}
	on := func(osName string, s Software, have bool) MatchResult {
		return MatchAsset(Asset{ID: "a", Name: "web-01", OS: osName, Software: []Software{s}}, []Vuln{v}, map[string]bool{v.CVE: have}, now)
	}

	// installed at or above the fixed version: no new finding; an open one is proved not affected (D-530 closes it)
	if r := on("Ubuntu 24.04.1 LTS", ssh("1:9.6p1-3ubuntu13.14", "agent"), false); len(r.New) != 0 {
		t.Fatalf("a patched package made a finding: %+v", r.New)
	}
	r := on("Ubuntu 24.04.1 LTS", ssh("1:9.6p1-3ubuntu13.5", "agent"), true)
	if len(r.New)+len(r.Existing) != 0 || len(r.NotAffected) != 1 ||
		r.NotAffected[0].Evidence.Summary != "Not affected: Ubuntu 24.04 fixed CVE-2026-10001 in openssh 1:9.6p1-3ubuntu13.5, and this device has 1:9.6p1-3ubuntu13.5 (Ubuntu security data). Vedette closed this by itself and reopens it if a later match says the device is affected." {
		t.Fatalf("patched, with a finding: %+v", r)
	}
	// the distribution says not affected
	r = on("Ubuntu 26.04 LTS", ssh("1:10.2p1-2ubuntu3.8", "agent"), true)
	if len(r.NotAffected) != 1 || !strings.Contains(r.NotAffected[0].Evidence.Summary, "Ubuntu says its openssh package of Ubuntu 26.04 is not affected by CVE-2026-10001") {
		t.Fatalf("not affected: %+v", r)
	}
	// installed below the fixed version: a version finding that names the distribution's fix
	r = on("Ubuntu 24.04.1 LTS", ssh("1:9.6p1-3ubuntu13.4", "agent"), false)
	if len(r.New) != 1 || r.New[0].Basis != BasisVersion || r.New[0].Severity != SeverityHigh ||
		r.New[0].Evidence.Summary != "web-01 runs OpenSSH 1:9.6p1-3ubuntu13.4 from Ubuntu 24.04's packages. Ubuntu fixed CVE-2026-10001 in openssh 1:9.6p1-3ubuntu13.5 (Ubuntu security data); no scan has confirmed it yet, so this is only suspected." {
		t.Fatalf("unpatched: %+v", r.New)
	}
	f := FixedInFor(Asset{ID: "a", Name: "web-01", OS: "Ubuntu 24.04.1 LTS", Software: []Software{ssh("1:9.6p1-3ubuntu13.4", "agent")}}, v)
	if f == nil || f.Kind != "distro" || f.Distro != "Ubuntu" || f.DistroPro || f.Fixed != "" || f.DistroFixed != "1:9.6p1-3ubuntu13.5" || f.DistroRelease != "24.04" || f.Version != "1:9.6p1-3ubuntu13.4" || f.Source != "Ubuntu security data" {
		t.Fatalf("fixed in: %+v", f)
	}
	// Debian: the release is the major number; the epoch counts
	if r := on("Debian GNU/Linux 12 (bookworm)", ssh("1:9.2p1-2+deb12u5", "agent"), true); len(r.NotAffected) != 1 || !strings.Contains(r.NotAffected[0].Evidence.Summary, "(Debian Security Tracker)") {
		t.Fatalf("Debian 12 patched: %+v", r)
	}
	if r := on("Debian 12", ssh("9.2p1-2+deb12u9", "agent"), false); len(r.New) != 1 || r.New[0].Basis != BasisVersion {
		t.Fatalf("Debian 12 without the epoch is below 1:9.2p1-2+deb12u5: %+v", r.New)
	}
	// a fix only Ubuntu Pro has: below it, the page says so
	if f := FixedInFor(Asset{ID: "a", Name: "web-01", OS: "Ubuntu 20.04.6 LTS", Software: []Software{ssh("1:8.2p1-4ubuntu0.13", "agent")}}, v); f == nil || !f.DistroPro {
		t.Fatalf("Pro fix: %+v", f)
	}
	// no word for the release, a row that is not the package database's, or no OS: NVD decides as before
	for name, c := range map[string]struct {
		os string
		s  Software
	}{
		"a release with no row":      {"Ubuntu 22.04.5 LTS", ssh("1:8.9p1-3ubuntu0.18", "agent")},
		"a row a person typed":       {"Ubuntu 24.04.1 LTS", ssh("1:9.6p1-3ubuntu13.14", "manual")},
		"a row with no full version": {"Ubuntu 24.04.1 LTS", ssh("", "agent")},
		"a device with no OS":        {"", ssh("1:9.6p1-3ubuntu13.14", "agent")},
	} {
		if r := on(c.os, c.s, false); len(r.New) != 1 || !strings.Contains(r.New[0].Evidence.Summary, "inside the range affected by") {
			t.Errorf("%s: %+v, want NVD's version finding", name, r.New)
		}
	}
}
