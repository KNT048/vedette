package findings

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// The class behind "Install Alpine Linux's security updates for OpenSSH: fixes 25 CVEs" on a package that is already current: every kind
// of row the plan compares (a distribution's package with and without that distribution's data, an application the agent reads, firmware
// the device states over SNMP, a version from a scan banner), on every distribution the feeds supply data for and one they do not. The
// old outcome of each case is written down (the logic before this change: Alpine and every RPM distribution "install the security
// updates, fixes N CVEs" from NVD's upstream ranges; Ubuntu and Debian only their fixed rows, nothing for a package their data does not
// name or another build); the test checks the outcome now and logs the counts by category (run with -v).
func TestPlan_TheWholeClass(t *testing.T) {
	t.Parallel()
	upstream := func(cve string) TierVuln { // NVD: OpenSSH before 10.3
		return tierV(cve, "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.3"}})
	}
	tier := []TierVuln{upstream("CVE-2026-90001"), upstream("CVE-2026-90002"), upstream("CVE-2026-90003"),
		tierV("CVE-2026-90010", "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "150.0"}}),
		tierV("CVE-2026-90020", "recent", 30, 0.01, Affected{CPE: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "7.2.0", EndExcl: "7.2.9"}})}
	alp := func(cve, branch, fixed string) TierVuln {
		return distroV(cve, "recent", 30, 0.01, alpineFix(branch, fixed))
	}
	ubu := func(cve, fixed string) TierVuln {
		return distroV(cve, "recent", 30, 0.01, noble("openssh", fixed, false))
	}
	ubuOpen := distroV("CVE-2026-90004", "recent", 30, 0.01, DistroFix{Distro: "ubuntu", Release: "24.04", Package: "openssh", Status: "open"})
	apk := sshAgentRow("10.2_p1-r1", "openssh")
	firefox := Software{ID: "s-ff", Display: "Mozilla Firefox", Vendor: "Mozilla", Product: "Firefox", Version: "140.0", Source: "agent"}
	forti := Software{ID: "s-fgt", Display: "FortiOS", Vendor: "Fortinet", Product: "FortiOS", Version: "7.2.5", Source: "snmp"}
	banner := Software{ID: "s-b", Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.2", Source: "nmap"}
	cases := []struct {
		category, name, os string
		row                Software
		distro             []TierVuln
		covered            string
		old, want          string // "" = no item; else kind/distro_data:CVE count ("distro/none:3")
	}{
		{"Alpine package, Alpine has the data", "current: every CVE fixed at or below the release", "Alpine Linux v3.23", apk,
			[]TierVuln{alp("CVE-2026-90001", "3.23", "10.2_p1-r1"), alp("CVE-2026-90002", "3.23", "10.2_p1-r0"), alp("CVE-2026-90003", "3.23", "0")}, "alpine/", "distro/:3", ""},
		{"Alpine package, Alpine has the data", "below Alpine's fix", "Alpine Linux v3.23", apk,
			[]TierVuln{alp("CVE-2026-90001", "3.23", "10.2_p1-r3"), alp("CVE-2026-90002", "3.23", "10.2_p1-r0"), alp("CVE-2026-90003", "3.23", "10.2_p1-r0")}, "alpine/", "distro/:3", "distro/fixed:1"},
		{"Alpine package, Alpine has the data", "no fix from Alpine yet", "Alpine Linux v3.23", apk,
			[]TierVuln{alp("CVE-2026-90001", "3.23", "10.2_p1-r1")}, "alpine/", "distro/:3", "distro/no_fix:2"},
		{"Alpine package, Alpine has the data", "OS names no branch", "Alpine Linux", apk,
			[]TierVuln{distroV("CVE-2026-90001", "recent", 30, 0.01, alpineFix("3.22", "10.0_p1-r11"), alpineFix("3.23", "10.2_p1-r1")),
				alp("CVE-2026-90002", "3.23", "10.2_p1-r1"), alp("CVE-2026-90003", "3.23", "10.2_p1-r1")}, "alpine/", "distro/:3", ""},
		{"Alpine package, no Alpine data", "feed off or package not named", "Alpine Linux v3.23", apk, nil, "", "distro/:3", "distro/none:3"},
		{"Ubuntu package, Ubuntu has the data", "below Ubuntu's fix", "Ubuntu 24.04 LTS", sshAgentRow("1:10.2p1-2ubuntu3.8", "openssh"),
			[]TierVuln{ubu("CVE-2026-90001", "1:10.2p1-2ubuntu3.9")}, "ubuntu/24.04", "distro/fixed:1", "distro/fixed:1"},
		{"Ubuntu package, Ubuntu has the data", "no fix from Ubuntu yet (open)", "Ubuntu 24.04 LTS", sshAgentRow("1:10.2p1-2ubuntu3.8", "openssh"),
			[]TierVuln{ubu("CVE-2026-90001", "1:10.2p1-2ubuntu3.8"), ubuOpen}, "ubuntu/24.04", "", "distro/no_fix:1"},
		{"Ubuntu package, no Ubuntu data", "package Ubuntu's data never names", "Ubuntu 24.04 LTS", sshAgentRow("1:10.2p1-2ubuntu3.8", "openssh"),
			[]TierVuln{distroV("CVE-2026-90009", "recent", 30, 0.01, noble("sudo", "1.9.15p5-3ubuntu5.24.04.1", false))}, "ubuntu/24.04", "", "distro/none:3"},
		{"RPM package (no data read yet)", "Rocky", "Rocky Linux 9.6", sshAgentRow("10.2p1-1.el9", "openssh"), nil, "", "distro/:3", "distro/none:3"},
		{"application read by the agent", "Firefox", "Windows 11", firefox, nil, "", "fixed/:1", "fixed/:1"},
		{"firmware stated over SNMP", "FortiOS", "FortiOS 7.2.5", forti, nil, "", "fixed/:1", "fixed/:1"},
		{"version from a scan banner", "nmap OpenSSH", "", banner, nil, "", "", ""},
	}
	type tally struct{ cases, wrongBefore int }
	by := map[string]*tally{}
	for _, c := range cases {
		a := Asset{ID: "dev", Name: "dev", OS: c.os, AgentOS: c.os, Software: []Software{c.row}}
		covered := map[string]bool{}
		if c.covered != "" {
			covered[c.covered] = true
		}
		x := newTierIndex(tier).withDistro(c.distro, covered)
		items, _ := matchTiers(a, x, nil, t0)
		got := ""
		if len(items) > 1 {
			t.Errorf("%s / %s: %d items %+v", c.category, c.name, len(items), items)
		}
		if len(items) == 1 {
			got = fmt.Sprintf("%s/%s:%d", items[0].Kind, items[0].DistroData, len(items[0].CVEs))
		}
		if got != c.want {
			t.Errorf("%s / %s: %q, want %q", c.category, c.name, got, c.want)
		}
		b := by[c.category]
		if b == nil {
			b = &tally{}
			by[c.category] = b
		}
		b.cases++
		if c.old != c.want {
			b.wrongBefore++
		}
	}
	var lines []string
	for _, k := range slices.Sorted(maps.Keys(by)) {
		lines = append(lines, fmt.Sprintf("%-38s cases %d: wrong before %d, right now %d", k, by[k].cases, by[k].wrongBefore, by[k].cases))
	}
	t.Log("plan items by category:\n" + strings.Join(lines, "\n"))
}
