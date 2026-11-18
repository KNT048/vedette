package findings

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

// The class behind "an update shows as Not relevant": every way a version finding closes because a later reading is outside every range,
// for every reader (the device's agent, its SNMP answer, a scan banner, a person) and every kind of version (an application's version, a
// distribution's package release). Before the rule, every one of them closed not_relevant; now a move of the release read by the same
// reader (or by the device itself both times) is patched, and the rest stays not_relevant. Run with -v for the counts by category.
func TestFixedByUpdate_TheWholeClass(t *testing.T) {
	t.Parallel()
	app := func(src, ver string) Software {
		return Software{ID: "s-app", Display: "Acme Gateway", Vendor: "Acme", Product: "Gateway", Version: ver, Source: src, KevKeys: []string{"acme|gateway"}, SeenAt: t0}
	}
	appVuln := []Vuln{{CVE: "CVE-2026-80001", Vendor: "Acme", Product: "Gateway",
		Affected: []Affected{{CPE: "cpe:2.3:a:acme:gateway:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "7.0"}}}}}
	narrowed := []Vuln{{CVE: "CVE-2026-80001", Vendor: "Acme", Product: "Gateway",
		Affected: []Affected{{CPE: "cpe:2.3:a:acme:gateway:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "6.0"}}}}}
	deb := func(rel string) Software {
		return Software{ID: "s-ssh", Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6p1", Source: "agent", Packaged: true,
			PkgVersion: rel, PkgSource: "openssh", KevKeys: []string{"openbsd|openssh"}, SeenAt: t0}
	}
	debVuln := func(fixed string) []Vuln {
		return []Vuln{{CVE: "CVE-2026-80002", Vendor: "OpenBSD", Product: "OpenSSH",
			Affected: []Affected{{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "9.8"}}},
			Distro:   []DistroFix{{Distro: "ubuntu", Release: "24.04", Package: "openssh", Status: "fixed", Fixed: fixed}}}}
	}
	type step struct {
		os    string
		row   Software
		vulns []Vuln
	}
	cases := []struct {
		category, name string
		first, then    step
		want           Status // now; before the rule every case was not_relevant
	}{
		{"application read by the agent", "the agent reads a new version", step{"Windows 11", app("agent", "6.24"), appVuln}, step{"Windows 11", app("agent", "7.23.0"), appVuln}, StatusPatched},
		{"application read by the agent", "the same version, NVD's range corrected", step{"Windows 11", app("agent", "6.24"), appVuln}, step{"Windows 11", app("agent", "6.24"), narrowed}, StatusNotRelevant},
		{"firmware the device states over SNMP", "the device states a new version", step{"", app("snmp", "6.2"), appVuln}, step{"", app("snmp", "7.1"), appVuln}, StatusPatched},
		{"version read from a scan banner", "the banner shows a new version", step{"", app("nmap", "6.2"), appVuln}, step{"", app("nmap", "7.1"), appVuln}, StatusPatched},
		{"version read from a scan banner", "the agent replaces the banner's guess", step{"", app("nmap", "6.2"), appVuln}, step{"", app("agent", "7.1"), appVuln}, StatusNotRelevant},
		{"version a person gave", "a person corrects the version", step{"", app("agent", "6.2"), appVuln}, step{"", app("manual", "7.1"), appVuln}, StatusNotRelevant},
		{"version a person gave", "a person gives a new version twice", step{"", app("manual", "6.2"), appVuln}, step{"", app("manual", "7.1"), appVuln}, StatusNotRelevant},
		{"distribution package (Ubuntu's data)", "the agent reads the fixed release", step{"Ubuntu 24.04 LTS", deb("1:9.6p1-3ubuntu13.13"), debVuln("1:9.6p1-3ubuntu13.14")}, step{"Ubuntu 24.04 LTS", deb("1:9.6p1-3ubuntu13.14"), debVuln("1:9.6p1-3ubuntu13.14")}, StatusPatched},
		{"distribution package (Ubuntu's data)", "Ubuntu's data arrives for the same release", step{"Ubuntu 24.04 LTS", deb("1:9.6p1-3ubuntu13.14"), debVuln("1:9.6p1-3ubuntu13.15")}, step{"Ubuntu 24.04 LTS", deb("1:9.6p1-3ubuntu13.14"), debVuln("1:9.6p1-3ubuntu13.14")}, StatusNotRelevant},
	}
	moved := map[string][2]int{} // category -> {patched now, cases}
	for _, c := range cases {
		e := newEnv(t)
		run := func(s step) {
			e.advance(time.Hour)
			a := Asset{ID: "a-1", Name: "dev", OS: s.os, AgentOS: s.os, Software: []Software{s.row}}
			if _, err := e.svc.UpsertFromMatch(t.Context(), a, s.vulns); err != nil {
				t.Fatal(err)
			}
		}
		run(c.first)
		cve := c.first.vulns[0].CVE
		if r, err := loadByPair(t.Context(), e.db.Reader(), "a-1", cve); err != nil || !r.Status.Open() {
			t.Fatalf("%s: not matched first: %+v %v", c.name, r.Finding, err)
		}
		run(c.then)
		r, _ := loadByPair(t.Context(), e.db.Reader(), "a-1", cve)
		if r.Status != c.want {
			t.Errorf("%s / %s: %s (%s), want %s", c.category, c.name, r.Status, r.ResolutionNote, c.want)
		}
		m := moved[c.category]
		m[1]++
		if r.Status == StatusPatched {
			m[0]++
		}
		moved[c.category] = m
	}
	var lines []string
	for _, k := range slices.Sorted(maps.Keys(moved)) {
		lines = append(lines, fmt.Sprintf("%-40s cases %d: before patched 0, now patched %d", k, moved[k][1], moved[k][0]))
	}
	t.Log("closures after a later reading, by category:\n" + strings.Join(lines, "\n"))
}
