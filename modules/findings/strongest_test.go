package findings

import (
	"fmt"
	"strings"
	"testing"
)

// The class: one software on one device reported by several sources at once (a scan banner, a person's entry with or without the
// package release, an agent's package row of deb, rpm or apk, a Wazuh agent's row, the device's SNMP answer). Vendor and product
// may differ in case only ("openbsd" from nmap's CPE, "OpenBSD" from the agent's map), the CPE may be on one row only, and the banner
// may give a less precise form of the same release ("10.2" for the agent's 10.2p1 and Alpine's 10.2_p1-r1). Every surface must
// describe the software by its strongest row: the agent's, else a person's, else the device's SNMP answer, else the scan banner.
// Inventory decides that row (inventory INV-50) and its MatchInput gives findings only the effective row of each software; the
// cases stand in for it the same way (the device's Software is the strongest row alone), so the measure checks what findings does
// with inventory's answer on every surface, and that a distribution's package never gets an upstream upgrade.
//
// strongestCase is one combination of rows on one device.
type strongestCase struct {
	name   string
	a      Asset
	strong string // the id of the row every surface must describe the software by
	pkg    bool   // the strongest row is a distribution's package (packaged, or a person gave its package release)
	plans  bool   // the strongest row's version may give an upstream plan item (an upstream build a source the plan trusts gave)
}

// strongestRows of the measure: the OpenSSH rows a box holds for one device.
func sshBanner(version string) Software {
	return Software{ID: "s-nmap", Display: "OpenSSH " + version, Vendor: "openbsd", Product: "openssh", Version: version, Source: "nmap",
		CPE: "cpe:/a:openbsd:openssh:10.2", KevKeys: []string{"openbsd|openssh"}}
}

func sshManual(pkg string) Software {
	return Software{ID: "s-manual", Display: "OpenSSH 10.2", Vendor: "openbsd", Product: "openssh", Version: "10.2", Source: "manual",
		PkgVersion: pkg, KevKeys: []string{"openbsd|openssh"}}
}

func sshAgent(version, pkg string, packaged bool) Software {
	s := Software{ID: "s-agent", Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: version, Source: "agent",
		Packaged: packaged, KevKeys: []string{"openbsd|openssh"}}
	if packaged && pkg != "" {
		s.PkgVersion, s.PkgSource = pkg, "openssh"
	}
	return s
}

func sshSNMP() Software {
	return Software{ID: "s-snmp", Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.2", Source: "snmp",
		KevKeys: []string{"openbsd|openssh"}}
}

// strongestCases builds every combination for three devices: an Alpine router (apk), an Ubuntu host (deb, and Wazuh's deb row), a
// Rocky host (rpm); plus an agent row that is no package (built from source, so NVD's upstream range is its range).
func strongestCases() []strongestCase {
	type osCase struct {
		name, os                     string
		banner                       string
		agentVer, agentPkg, manualPk string
	}
	oses := []osCase{
		{"alpine", "Alpine Linux 3.23.0", "10.2", "10.2p1", "10.2_p1-r1", "10.2_p1-r1"},
		{"ubuntu", "Ubuntu 26.04 LTS", "10.2p1 Ubuntu 2ubuntu3.8", "10.2p1", "1:10.2p1-2ubuntu3.8", "1:10.2p1-2ubuntu3.8"},
		{"ubuntu-wazuh", "Ubuntu 26.04 LTS", "10.2p1 Ubuntu 2ubuntu3.8", "10.2p1", "", "1:10.2p1-2ubuntu3.8"}, // Wazuh gives no source package
		{"rocky", "Rocky Linux 9.6", "10.2", "10.2p1", "10.2p1-1.el9", "10.2p1-1.el9"},
	}
	var out []strongestCase
	for _, o := range oses {
		for _, banner := range []bool{false, true} {
			for _, manual := range []string{"", "plain", "pkg"} {
				for _, agent := range []string{"", "packaged", "upstream"} {
					for _, snmp := range []bool{false, true} {
						var rows, names []string
						var sws []Software
						a := Asset{ID: "dev", Name: o.name, OS: o.os}
						if banner {
							sws, names = append(sws, sshBanner(o.banner)), append(names, "banner")
						}
						if snmp {
							sws, names = append(sws, sshSNMP()), append(names, "snmp")
						}
						switch manual {
						case "plain":
							sws, names = append(sws, sshManual("")), append(names, "manual")
						case "pkg":
							sws, names = append(sws, sshManual(o.manualPk)), append(names, "manual+pkg")
						}
						switch agent {
						case "packaged":
							sws, names = append(sws, sshAgent(o.agentVer, o.agentPkg, true)), append(names, "agent")
							a.AgentOS = o.os
						case "upstream":
							sws, names = append(sws, sshAgent("10.2p1", "", false)), append(names, "agent-upstream")
							a.AgentOS = o.os
						}
						if len(sws) < 2 {
							continue // one row: nothing shadows anything
						}
						c := strongestCase{name: o.name + ": " + strings.Join(names, "+")}
						for _, s := range sws {
							rows = append(rows, s.ID)
						}
						switch {
						case agent != "":
							c.strong, c.pkg, c.plans = "s-agent", agent == "packaged", agent == "upstream"
						case manual != "":
							c.strong, c.pkg, c.plans = "s-manual", manual == "pkg", manual == "plain"
						case snmp:
							c.strong, c.plans = "s-snmp", true
						default:
							c.strong = rows[0]
						}
						var eff []Software // inventory's MatchInput: the other rows of the software are left out
						for _, s := range sws {
							if s.ID == c.strong {
								eff = append(eff, s)
							}
						}
						a.Software = eff
						c.a = a
						out = append(out, c)
					}
				}
			}
		}
	}
	return out
}

// strongestViolations runs every surface on one case and says where a surface described the software by another row than the
// strongest, or planned an upstream upgrade for a package.
func strongestViolations(c strongestCase) []string {
	var bad []string
	kev := Vuln{CVE: "CVE-2099-0101", Vendor: "OpenBSD", Product: "OpenSSH", Affected: []Affected{
		{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.6"}}}}
	vulns := []Vuln{kev, sshhole()}
	// exploited findings, Needs your input (add the version, could not be checked, questions)
	res := MatchAsset(c.a, vulns, nil, t0)
	for _, m := range append(append(res.New, res.Existing...), res.Asked...) {
		if m.SoftwareID != c.strong {
			bad = append(bad, fmt.Sprintf("finding %s on %s", m.CVE, m.SoftwareID))
		}
	}
	for _, n := range res.NeedVersion {
		if n.SoftwareID != c.strong {
			bad = append(bad, "add-the-version on "+n.SoftwareID)
		}
	}
	for _, u := range res.Unchecked {
		if u.SoftwareID != c.strong {
			bad = append(bad, fmt.Sprintf("could-not-be-checked %s on %s", u.CVE, u.SoftwareID))
		}
	}
	// To fix and the report: the update of the exploited finding
	for cve, f := range RowFixes(c.a, []Vuln{kev}) {
		if f.SoftwareID != c.strong {
			bad = append(bad, fmt.Sprintf("to-fix %s on %s", cve, f.SoftwareID))
		}
		if c.pkg && f.Kind != "distro" {
			bad = append(bad, fmt.Sprintf("to-fix %s says %s %s for a package", cve, f.Kind, f.Fixed))
		}
	}
	if f := FixedInFor(c.a, kev); f != nil && c.pkg && f.Kind != "distro" {
		bad = append(bad, fmt.Sprintf("finding-page says %s %s for a package", f.Kind, f.Fixed))
	}
	// Recommended updates (the plan)
	tier := tierV("CVE-2026-60001", "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.6"}})
	items, _ := planOf(c.a, []TierVuln{tier}, nil)
	for _, it := range items {
		if it.SoftwareID != c.strong {
			bad = append(bad, fmt.Sprintf("plan item on %s (%s to %s)", it.SoftwareID, it.Version, it.Fixed))
		} else if !c.plans {
			bad = append(bad, fmt.Sprintf("plan item %s to %s for a %s row", it.Version, it.Fixed, map[bool]string{true: "package", false: "banner"}[c.pkg]))
		}
	}
	if c.plans && len(items) != 1 {
		bad = append(bad, fmt.Sprintf("plan has %d items for an upstream build, want 1", len(items)))
	}
	return bad
}

// TestStrongestRow_EveryCombination is the measure of the class: run again after any change to how rows are chosen. It fails
// with every case and surface that describes the software by a weaker row.
func TestStrongestRow_EveryCombination(t *testing.T) {
	t.Parallel()
	cases := strongestCases()
	failed, total := 0, 0
	bySurface := map[string]int{}
	for _, c := range cases {
		total++
		bad := strongestViolations(c)
		if len(bad) == 0 {
			continue
		}
		failed++
		for _, b := range bad {
			bySurface[strings.SplitN(b, " ", 2)[0]]++
		}
		t.Errorf("%s: %s", c.name, strings.Join(bad, "; "))
	}
	t.Logf("%d of %d combinations describe the software by a weaker row or plan an upstream upgrade for a package; by surface %v", failed, total, bySurface)
}

// The rows of an Alpine router and an Ubuntu host as every source reported them (not through inventory's MatchInput, which would
// keep the agent's row alone): even then a person's package release (or an
// agent's package row) is a distribution's package, so the plan names no upstream "upgrade to 10.6" for it and the exploited
// finding's update is the distribution's. A person's entry with no package release keeps its upstream item.
func TestStrongestRow_EnteredPackageReleaseIsNoUpstreamUpgrade(t *testing.T) {
	t.Parallel()
	tier := tierV("CVE-2026-60001", "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.6"}})
	kev := Vuln{CVE: "CVE-2099-0101", Vendor: "OpenBSD", Product: "OpenSSH", Affected: []Affected{
		{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.6"}}}}
	router := Asset{ID: "router", Name: "router", OS: "Alpine Linux 3.23.0", AgentOS: "Alpine Linux 3.23.0",
		Software: []Software{sshBanner("10.2"), sshManual("10.2_p1-r1"), sshAgent("10.2p1", "10.2_p1-r1", true)}}
	host := Asset{ID: "host", Name: "host", OS: "Ubuntu 26.04 LTS", AgentOS: "Ubuntu 26.04 LTS",
		Software: []Software{sshBanner("10.2p1 Ubuntu 2ubuntu3.8"), sshAgent("10.2p1", "1:10.2p1-2ubuntu3.8", true)}}
	typed := Asset{ID: "typed", Name: "typed", OS: "Alpine Linux 3.23.0", Software: []Software{sshBanner("10.2"), sshManual("10.2_p1-r1")}}
	for _, a := range []Asset{router, host, typed} {
		if items, _ := planOf(a, []TierVuln{tier}, nil); len(items) != 0 {
			t.Errorf("%s: plan %+v, want no upstream upgrade for a package", a.Name, items)
		}
	}
	for _, a := range []Asset{router, typed} {
		for cve, f := range RowFixes(a, []Vuln{kev}) {
			if f.SoftwareID != "s-nmap" && f.Kind != "distro" {
				t.Errorf("%s: %s on %s is %s %s, want the distribution's updates", a.Name, cve, f.SoftwareID, f.Kind, f.Fixed)
			}
		}
	}
	plain := Asset{ID: "plain", Name: "plain", OS: "Alpine Linux 3.23.0", Software: []Software{sshManual("")}}
	if items, _ := planOf(plain, []TierVuln{tier}, nil); len(items) != 1 || items[0].Fixed != "10.6" || items[0].SoftwareID != "s-manual" {
		t.Errorf("a typed upstream version: %+v, want one upgrade to 10.6", items)
	}
}
