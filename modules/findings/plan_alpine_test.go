package findings

import (
	"slices"
	"testing"
)

func alpineFix(branch, fixed string) DistroFix {
	const pkg = "openssh"
	if fixed == "0" {
		return DistroFix{Distro: DistroAlpine, Release: branch, Package: pkg, Status: "not_affected"}
	}
	return DistroFix{Distro: DistroAlpine, Release: branch, Package: pkg, Status: "fixed", Fixed: fixed}
}

// nvdSSH is a tier CVE NVD's upstream range puts OpenSSH 10.2p1 inside ("before 10.3").
func nvdSSH(cve string) TierVuln {
	return tierV(cve, "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.3"}})
}

// An Alpine firewall runs openssh-server 10.2_p1-r1, the newest release its branch has. Its packages are judged by Alpine's own fix
// data (secdb through OSV.dev), the way Trivy and Grype judge them, for every CVE NVD's upstream ranges put it inside:
//   - Alpine fixed it in 10.2_p1-r1 on 3.23, or says the package is not affected: no item (the 25 CVEs of the upstream range are gone);
//   - Alpine fixed it in a later release of the branch: one item naming Alpine's fixed release, never an upstream one;
//   - Alpine lists no fix for it (secdb lists fixed releases only): "no fix from Alpine Linux yet", not an update to install.
func TestPlan_AlpinePackagesByAlpinesData(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "fw", Name: "fw", AgentOS: "Alpine Linux v3.23", OS: "Alpine Linux v3.23", Software: []Software{sshAgentRow("10.2_p1-r1", "openssh")}}
	tier := []TierVuln{nvdSSH("CVE-2026-70001"), nvdSSH("CVE-2026-70002"), nvdSSH("CVE-2026-70003"), nvdSSH("CVE-2026-70004")}
	alpine := []TierVuln{
		distroV("CVE-2026-70001", "recent", 30, 0.01, alpineFix("3.23", "10.2_p1-r1"), alpineFix("3.22", "10.0_p1-r11")),
		distroV("CVE-2026-70002", "recent", 30, 0.01, alpineFix("3.23", "0")),
	}
	x := newTierIndex(tier).withDistro(alpine, map[string]bool{"alpine/": true})
	if d, rel, pkgs := DevicePackages(a); d != DistroAlpine || rel != "" || !slices.Equal(pkgs, []string{"openssh"}) {
		t.Fatalf("DevicePackages %q %q %v", d, rel, pkgs)
	}

	// 70001 fixed in the installed release, 70002 not affected; 70003 and 70004 Alpine has no fix for: the "no fix yet" item only
	items, compared := matchTiers(a, x, nil, t0)
	if !compared || len(items) != 1 {
		t.Fatalf("compared %v, items %+v", compared, items)
	}
	nf := items[0]
	if nf.Kind != "distro" || nf.DistroData != DistroDataNoFix || nf.Fixed != "" || nf.Distro != "Alpine Linux" || nf.Group != "fw/s-agent/nofix" ||
		!slices.Equal(cvesOf(nf), []string{"CVE-2026-70003/recent/distro", "CVE-2026-70004/recent/distro"}) {
		t.Fatalf("no fix item %+v", nf)
	}
	if s := updateSentence(planAction(nf)); s != "No fix from Alpine Linux yet for openssh (10.2_p1-r1)" {
		t.Fatalf("sentence %q", s)
	}

	// Alpine has fixed every one of them at or below the installed release: no item at all
	all := slices.Clone(alpine)
	all = append(all, distroV("CVE-2026-70003", "recent", 30, 0.01, alpineFix("3.23", "10.2_p1-r0")),
		distroV("CVE-2026-70004", "recent", 30, 0.01, alpineFix("3.23", "10.2_p1-r1")))
	x = newTierIndex(tier).withDistro(all, map[string]bool{"alpine/": true})
	if items, compared = matchTiers(a, x, nil, t0); !compared || len(items) != 0 {
		t.Fatalf("current package: compared %v, items %+v", compared, items)
	}

	// below Alpine's fix: an item naming Alpine's fixed release (the highest of the item)
	below := slices.Clone(all)
	below[3] = distroV("CVE-2026-70004", "recent", 30, 0.01, alpineFix("3.23", "10.2_p1-r3"))
	x = newTierIndex(tier).withDistro(below, map[string]bool{"alpine/": true})
	items, _ = matchTiers(a, x, nil, t0)
	if len(items) != 1 || items[0].DistroData != DistroDataFixed || items[0].Fixed != "10.2_p1-r3" || items[0].Version != "10.2_p1-r1" || items[0].Software != "openssh" ||
		!slices.Equal(cvesOf(items[0]), []string{"CVE-2026-70004/recent/distro"}) {
		t.Fatalf("below the fix: %+v", items)
	}
	if s := updateSentence(planAction(items[0])); s != "Upgrade the openssh package from 10.2_p1-r1 to 10.2_p1-r3 or later" {
		t.Fatalf("sentence %q", s)
	}

	// an OS that names no branch: the branch whose fixed release has the installed upstream version (3.23's), as the exploited path
	a.AgentOS, a.OS = "Alpine Linux", "Alpine Linux"
	x = newTierIndex(tier).withDistro(all, map[string]bool{"alpine/": true})
	if items, _ = matchTiers(a, x, nil, t0); len(items) != 0 {
		t.Fatalf("no branch named: %+v", items)
	}

	// no Alpine data for the package at all: the fallback, which says to check Alpine's updates and that NVD lists the CVEs
	x = newTierIndex(tier).withDistro(nil, map[string]bool{"alpine/": true})
	items, _ = matchTiers(a, x, nil, t0)
	if len(items) != 1 || items[0].DistroData != DistroDataNone || items[0].Fixed != "" || len(items[0].CVEs) != 4 {
		t.Fatalf("no data: %+v", items)
	}
	if s := updateSentence(planAction(items[0])); s != "Check Alpine Linux's security updates for OpenSSH" {
		t.Fatalf("fallback sentence %q", s)
	}

	// the feed is on but not loaded yet: nothing on a guess
	x = newTierIndex(tier).withKnown(nil, map[string]bool{DistroAlpine: true}).withDistro(nil, nil)
	if items, _ = matchTiers(a, x, nil, t0); len(items) != 0 {
		t.Fatalf("loading: %+v", items)
	}
}

// Ubuntu and Debian go through the same mechanism: an open entry (no fix from the distribution yet) is a "no fix yet" item, and a CVE
// their data does not list for the package is no item (their data lists every CVE they track).
func TestPlan_DistroNoFixYetIsOneMechanism(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "u", Name: "u", OS: "Ubuntu 24.04 LTS", Software: []Software{sshAgentRow("1:10.2p1-2ubuntu3.8", "openssh")}}
	open := DistroFix{Distro: "ubuntu", Release: "24.04", Package: "openssh", Status: "open"}
	x := newTierIndex([]TierVuln{nvdSSH("CVE-2026-70009")}).withDistro([]TierVuln{
		distroV("CVE-2026-70005", "recent", 30, 0.01, open),
		distroV("CVE-2026-70006", "recent", 30, 0.01, noble("openssh", "1:10.2p1-2ubuntu3.9", false)),
	}, map[string]bool{"ubuntu/24.04": true})
	items, _ := matchTiers(a, x, nil, t0)
	slices.SortFunc(items, func(p, q PlanItem) int { return len(p.DistroData) - len(q.DistroData) }) // fixed, then no_fix
	if len(items) != 2 || items[0].DistroData != DistroDataFixed || items[0].Fixed != "1:10.2p1-2ubuntu3.9" ||
		items[1].DistroData != DistroDataNoFix || items[1].Distro != "Ubuntu" || !slices.Equal(cvesOf(items[1]), []string{"CVE-2026-70005/recent/distro"}) {
		t.Fatalf("items %+v", items)
	}
}
