package findings

import (
	"strings"
	"testing"
	"time"
)

func TestPlatformLimits_DataIsValid(t *testing.T) {
	t.Parallel()
	if platformLimitErr != nil {
		t.Fatal(platformLimitErr)
	}
	if l, ok := platformLimits["CVE-2026-123158"]; !ok || len(l.Only) != 1 || l.Only[0] != "alpine" {
		t.Fatalf("CVE-2026-123158 = %+v, want only alpine", l)
	}
}

// sshhole is CVE-2026-123158 as the feeds give it: KEV OpenBSD|OpenSSH, NVD's range before 10.6 (kev-nvd-golden.json).
func sshhole() Vuln {
	return Vuln{CVE: "CVE-2026-123158", Vendor: "OpenBSD", Product: "OpenSSH", Affected: []Affected{
		{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.6"}},
	}}
}

func sshRow(version, banner, source string) Software {
	return Software{ID: "ssh", Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: version, Banner: banner, Source: source,
		CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", KevKeys: []string{"openbsd|openssh"}}
}

// KF-4 / N45-3: the GitLab server's "OpenSSH 9.6p1 Ubuntu 3ubuntu13.20" on the public IP is Ubuntu's glibc+PAM build: not listed,
// and the reason is there for the exposure page. Nothing about "run a scan".
func TestPlatform_UbuntuBannerRulesOutAlpineOnlyCVE(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "ext:203.0.113.4", Name: "203.0.113.4", Software: []Software{sshRow("9.6p1 Ubuntu 3ubuntu13.20", "Ubuntu Linux; protocol 2.0", "")}}
	res := MatchAsset(a, []Vuln{sshhole()}, nil, t0)
	if len(res.New) != 0 || len(res.OtherPlatform) != 1 {
		t.Fatalf("new %+v, other platform %+v; want none listed, one ruled out", res.New, res.OtherPlatform)
	}
	why := res.OtherPlatform[0].Evidence.Summary
	if !strings.Contains(why, "affects only OpenSSH built with musl libc and without PAM") || !strings.Contains(why, "9.6p1 Ubuntu 3ubuntu13.20") || strings.Contains(why, "scan") {
		t.Errorf("reason = %q", why)
	}
}

// A device whose OS (osquery) is Ubuntu: its open finding of the Alpine-only CVE closes by itself (D-530 path) with the reason.
func TestPlatform_DeviceOSClosesTheFinding(t *testing.T) {
	t.Parallel()
	sw := sshRow("9.6p1", "", "agent")
	sw.Packaged, sw.PkgVersion, sw.PkgSource = true, "1:9.6p1-3ubuntu13.20", "openssh"
	a := Asset{ID: "a", Name: "boxkien", OS: "Ubuntu 24.04.3 LTS", AgentOS: "Ubuntu 24.04.3 LTS", Software: []Software{sw}}
	res := MatchAsset(a, []Vuln{sshhole()}, map[string]bool{"CVE-2026-123158": true}, t0)
	if len(res.Existing) != 0 || len(res.NotAffected) != 1 {
		t.Fatalf("existing %+v, not affected %+v", res.Existing, res.NotAffected)
	}
	if n := res.NotAffected[0].Evidence.Summary; !strings.HasPrefix(n, "Not affected: CVE-2026-123158 affects only") || !strings.Contains(n, "this device runs Ubuntu 24.04.3 LTS") {
		t.Errorf("note = %q", n)
	}
}

// KF-5: the office firewall's "OpenSSH 10.2" says no platform: listed as suspected, with the condition and what to check. A Ubuntu
// host whose port a scan saw is no proof either (it may forward the port to an Alpine container).
func TestPlatform_UnknownPlatformKeepsTheFindingWithTheCondition(t *testing.T) {
	t.Parallel()
	for _, a := range []Asset{
		{ID: "fw", Name: "192.168.18.1", Software: []Software{sshRow("10.2", "protocol 2.0", "nmap")}},
		{ID: "host", Name: "docker1", OS: "Ubuntu 24.04.3 LTS", Software: []Software{sshRow("10.2", "", "nmap")}},
		{ID: "alp", Name: "alp1", OS: "Alpine Linux v3.23", AgentOS: "Alpine Linux v3.23", Software: []Software{sshRow("10.2", "", "agent")}},
	} {
		res := MatchAsset(a, []Vuln{sshhole()}, nil, t0)
		if len(res.New) != 1 || res.New[0].Basis != BasisVersion || len(res.OtherPlatform) != 0 {
			t.Fatalf("%s: new %+v, other %+v; want one suspected by version", a.Name, res.New, res.OtherPlatform)
		}
		s := res.New[0].Evidence.Summary
		if !strings.Contains(s, "It affects only OpenSSH built with musl libc and without PAM") || !strings.Contains(s, "check the openssh package version on that device") {
			t.Errorf("%s: summary = %q", a.Name, s)
		}
	}
}

// A CVE not on the list is untouched by a platform word.
func TestPlatform_OtherCVEsUnchanged(t *testing.T) {
	t.Parallel()
	v := sshhole()
	v.CVE = "CVE-2024-6387"
	res := MatchAsset(Asset{ID: "x", Name: "x", Software: []Software{sshRow("9.6p1 Ubuntu 3ubuntu13.20", "Ubuntu Linux; protocol 2.0", "")}}, []Vuln{v}, nil, t0)
	if len(res.New) != 1 || len(res.OtherPlatform) != 0 || strings.Contains(res.New[0].Evidence.Summary, "affects only") {
		t.Fatalf("result %+v", res)
	}
}

// Review r1 #1, #2, #11 (b, c): the device's OS is evidence only for its own inventory's rows: an agent row takes the OS, an SNMP
// row only the OS the device states itself; a row a person typed, a scan row and a row of unknown source never take it.
func TestPlatform_OSIsEvidenceOnlyForTheDevicesOwnRows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, source, os, stated, agent, snmp string
		out                                   bool
	}{
		{"agent row on a Ubuntu device", "agent", "Ubuntu 24.04.3 LTS", "", "Ubuntu 24.04.3 LTS", "", true},
		{"agent row, the folded OS is a guess the agent never reported (review r2 of #790)", "agent", "Ubuntu 24.04.3 LTS", "", "", "", false},
		{"agent row, a person's OS won but the agent reports Ubuntu", "agent", "Alpine Linux v3.23", "", "Ubuntu 24.04.3 LTS", "", true},
		{"scan row on a Junos switch that states its OS over SNMP (D-549, N47-1)", "nmap", "Juniper Junos", "JUNOS 15.1R7.9", "", "JUNOS 15.1R7.9", true},
		{"scan row, Junos only in an LLDP frame (forgeable with the device's MAC, review r1 #3)", "nmap", "", "JUNOS 15.1R7.9", "", "", false},
		{"scan row, Junos OS Evolved runs containers (review r1 #4)", "nmap", "", "JUNOS 21.4R1.12-EVO", "", "JUNOS 21.4R1.12-EVO", false},
		{"scan row, SNMP says Junos but an agent reports another OS", "nmap", "", "JUNOS 15.1R7.9", "Alpine Linux v3.23", "JUNOS 15.1R7.9", false},
		{"scan row on a device that states Ubuntu over SNMP (may forward to a container)", "nmap", "", "Ubuntu 22.04", "", "", false},
		{"manual row on a Ubuntu device (an Alpine container's sshd typed by hand)", "manual", "Ubuntu 24.04.3 LTS", "", "", "", false},
		{"scan row on a Ubuntu device", "nmap", "Ubuntu 24.04.3 LTS", "", "", "", false},
		{"row of unknown source", "", "Ubuntu 24.04.3 LTS", "", "", "", false},
		{"SNMP row, OS only a fingerprint or DHCP guess", "snmp", "Microsoft Windows", "", "", "", false},
		{"SNMP row, the device states its OS", "snmp", "", "Ubuntu 22.04", "", "", true},
	} {
		a := Asset{ID: "d", Name: "docker1", OS: tc.os, StatedOS: tc.stated, AgentOS: tc.agent, SNMPOS: tc.snmp, Software: []Software{sshRow("10.2", "", tc.source)}}
		res := MatchAsset(a, []Vuln{sshhole()}, nil, t0)
		if got := len(res.OtherPlatform) == 1 && len(res.New) == 0; got != tc.out {
			t.Errorf("%s: ruled out %v, want %v (new %+v)", tc.name, got, tc.out, res.New)
		}
	}
}

// Review r1 #11 (a): an agent-read Ubuntu OpenSSH (ruled out) beside a scan-seen OpenSSH with no platform (an Alpine container's
// port) keeps the open finding: neither closed nor reported as ruled out.
func TestPlatform_ContainerPortKeepsTheFinding(t *testing.T) {
	t.Parallel()
	host := sshRow("9.6p1", "", "agent")
	host.ID, host.Packaged, host.PkgVersion, host.PkgSource = "pkg", true, "1:9.6p1-3ubuntu13.20", "openssh"
	a := Asset{ID: "d", Name: "docker1", OS: "Ubuntu 24.04.3 LTS", AgentOS: "Ubuntu 24.04.3 LTS", Software: []Software{host, sshRow("10.2", "", "nmap")}}
	res := MatchAsset(a, []Vuln{sshhole()}, map[string]bool{"CVE-2026-123158": true}, t0)
	if len(res.Existing) != 1 || len(res.NotAffected) != 0 || len(res.OtherPlatform) != 0 {
		t.Fatalf("existing %+v, not affected %+v, other %+v", res.Existing, res.NotAffected, res.OtherPlatform)
	}
}

// Review r1 #3: a deb/rpm package is "not Alpine", never "not Debian": an entry limited to a deb/rpm family is not ruled out by
// the package format (an OS name Vedette does not know, "Linux Mint", names nothing).
func TestPlatform_PackageFormatOnlyRulesOutNonDebRPMEntries(t *testing.T) {
	t.Parallel()
	pkg := swInfo{ver: "9.6p1", packaged: true, pkgVer: "1:9.6p1-1", platformOS: "Linux Mint 22"}
	if _, out := ruledOut(platformLimit{Only: []string{"debian"}, Affects: "x"}, evidenceOf(pkg), "CVE-2099-0001"); out {
		t.Error("a Debian-only entry was ruled out by the device's deb package")
	}
	why, out := ruledOut(platformLimit{Only: []string{"alpine"}, Affects: "x"}, evidenceOf(pkg), "CVE-2099-0001")
	if !out || !strings.Contains(why, "deb or rpm package database") || strings.Contains(why, "the device's rpm") {
		t.Errorf("alpine-only entry: %q %v", why, out)
	}
}

// Review r1 #4: the word that rules a CVE out is always in the sentence shown: one past the shown text decides nothing.
func TestPlatform_RulingWordIsInTheReason(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 130) + " Ubuntu"
	res := MatchAsset(Asset{ID: "x", Name: "x", Software: []Software{sshRow("10.2", long, "scan")}}, []Vuln{sshhole()}, nil, t0)
	if len(res.OtherPlatform) != 0 || len(res.New) != 1 {
		t.Fatalf("a platform word past the shown text ruled it out: %+v", res)
	}
}

// Review r1 #7: the distribution's own word comes first: Ubuntu says its package is affected (fixed in a later revision), so the
// hand list does not close it.
func TestPlatform_DistributionWordBeatsTheHandList(t *testing.T) {
	t.Parallel()
	sw := sshRow("9.6p1", "", "agent")
	sw.Packaged, sw.PkgVersion, sw.PkgSource = true, "1:9.6p1-3ubuntu13.14", "openssh"
	v := sshhole()
	v.Distro = []DistroFix{{Distro: "ubuntu", Release: "24.04", Package: "openssh", Status: "fixed", Fixed: "1:9.6p1-3ubuntu13.20"}}
	res := MatchAsset(Asset{ID: "a", Name: "boxkien", OS: "Ubuntu 24.04.3 LTS", AgentOS: "Ubuntu 24.04.3 LTS", Software: []Software{sw}}, []Vuln{v}, nil, t0)
	if len(res.New) != 1 || len(res.OtherPlatform) != 0 {
		t.Fatalf("new %+v, other %+v; want the distribution's version finding", res.New, res.OtherPlatform)
	}
}

// Review r1 #11 (d), #6: through the service: a platform proof closes the open finding (audit says D-547, no version compared)
// and a later match on a platform it affects reopens it.
func TestContract_D547_PlatformClosesAndReopens(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	run := func(os string) {
		t.Helper()
		e.advance(time.Minute)
		a := Asset{ID: "a-1", Name: "fw1", OS: os, AgentOS: os, Software: []Software{sshRow("10.2", "", "agent")}}
		if _, err := e.svc.UpsertFromMatch(t.Context(), a, []Vuln{sshhole()}); err != nil {
			t.Fatal(err)
		}
	}
	load := func() Record {
		t.Helper()
		r, err := loadByPair(t.Context(), e.db.Reader(), "a-1", "CVE-2026-123158")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	run("") // platform unknown: suspected with the condition
	if r := load(); r.Status != StatusSuspected || !strings.Contains(r.Evidence.Summary, "It affects only OpenSSH built with musl") {
		t.Fatalf("created = %+v", r.Finding)
	}
	run("Ubuntu 24.04.3 LTS")
	if r := load(); r.Status != StatusNotRelevant || r.ResolvedBy != SystemUser || !strings.HasPrefix(r.ResolutionNote, "Not affected: CVE-2026-123158 affects only") {
		t.Fatalf("not closed by the platform: %+v", r.Finding)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.auto_resolved' AND detail LIKE '%D-547%no version was compared%'`); n != 1 {
		t.Fatalf("audit rows naming the platform proof: %d", n)
	}
	run("Alpine Linux v3.23")
	if r := load(); r.Status != StatusSuspected || r.ResolutionReason != "" {
		t.Fatalf("not reopened: %+v", r.Finding)
	}
}
