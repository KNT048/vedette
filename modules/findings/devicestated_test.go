package findings

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// A firewall that states FortiOS 7.2.13 over SNMP; NVD lists 6.4.0 up to before 7.4.10 as affected by one exploited CVE and up to
// before 7.4.7 by another, and names no 7.2 fix: the device really is affected.
const fortiCPE = "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"

func fortiVulns() []Vuln {
	recent := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return []Vuln{
		{CVE: "CVE-2025-61624", Vendor: "Fortinet", Product: "FortiOS", DateAdded: recent, Published: recent,
			Affected: []Affected{{CPE: fortiCPE, Range: VersionRange{StartIncl: "6.4.0", EndExcl: "7.4.10"}}}},
		{CVE: "CVE-2025-68686", Vendor: "Fortinet", Product: "FortiOS", DateAdded: recent, Published: recent,
			Affected: []Affected{{CPE: fortiCPE, Range: VersionRange{StartIncl: "6.4.0", EndExcl: "7.4.7"}}}},
	}
}

// fortiSNMP is the firewall as the matcher reads it when it answers Vedette's SNMP read with FortiOS 7.2.13.
func fortiSNMP() Asset {
	a := snmpDevice("a-1", "FortiOS 7.2.13")
	a.Name = "fw-edge"
	a.SNMPOSAt = t0 // it answered just now (SNMPFresh)
	return a
}

// fortiRow is the firewall with one FortiOS 7.2.13 row from source (nmap's banner, a person's entry) and no SNMP answer.
func fortiRow(source string) Asset {
	return Asset{ID: "a-1", Name: "fw-edge", Software: []Software{{ID: "s-fos", Display: "FortiOS", Vendor: "Fortinet", Product: "FortiOS",
		Version: "7.2.13", Source: source, KevKeys: []string{"fortinet|fortios"}}}}
}

func byCVE(ms []Match, cve string) (Match, bool) {
	i := slices.IndexFunc(ms, func(m Match) bool { return m.CVE == cve })
	if i < 0 {
		return Match{}, false
	}
	return ms[i], true
}

// The device's own agent reporting the version inside a range with an end confirms it too.
func TestMatchAsset_AgentStatedVersionConfirms(t *testing.T) {
	t.Parallel()
	a := nas("6.1.1")
	a.Software[0].Source = "agent"
	res := MatchAsset(a, []Vuln{qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.1.2"}})}, nil, t0)
	if len(res.New) != 1 || res.New[0].Evidence.Source != SourceAgent || !res.New[0].Evidence.Agent {
		t.Fatalf("matches %+v", res.New)
	}
}

// An SNMP answer older than SNMPFresh (or of unknown age) does not confirm: the device may run another version by now. A weekly scan
// window (an answer 7 days and a few hours ago) keeps it confirmed, so findings do not flip every week.
func TestMatchAsset_AnOldSNMPAnswerDoesNotConfirm(t *testing.T) {
	t.Parallel()
	for name, at := range map[string]time.Time{"sixteen days ago": t0.Add(-16 * 24 * time.Hour), "unknown": {}} {
		a := fortiSNMP()
		a.SNMPOSAt = at
		if m, ok := byCVE(MatchAsset(a, fortiVulns(), nil, t0).New, "CVE-2025-61624"); !ok || m.Basis != BasisVersion || m.Evidence.Source != "" {
			t.Errorf("%s: %+v", name, m)
		}
	}
	for name, at := range map[string]time.Time{"7 days and 5 hours ago": t0.Add(-7*24*time.Hour - 5*time.Hour), "14 days ago": t0.Add(-14 * 24 * time.Hour)} {
		a := fortiSNMP()
		a.SNMPOSAt = at
		if m, _ := byCVE(MatchAsset(a, fortiVulns(), nil, t0).New, "CVE-2025-61624"); m.Evidence.Source != SourceSNMP {
			t.Errorf("%s: %+v", name, m)
		}
	}
}

// The device's own SNMP answer puts the version inside a range with an end: the match carries source snmp and says why in plain words.
func TestMatchAsset_SNMPStatedVersionConfirms(t *testing.T) {
	t.Parallel()
	res := MatchAsset(fortiSNMP(), fortiVulns(), nil, t0)
	if len(res.New) != 2 {
		t.Fatalf("matches %+v", res.New)
	}
	m, _ := byCVE(res.New, "CVE-2025-61624")
	if m.Basis != BasisVersion || m.Evidence.Source != SourceSNMP {
		t.Fatalf("match %+v", m)
	}
	const want = "Confirmed: fw-edge reports Fortinet FortiOS 7.2.13 over SNMP; NVD lists 6.4.0 up to before 7.4.10 as affected by CVE-2025-61624."
	if m.Evidence.Summary != want {
		t.Fatalf("summary\n got %q\nwant %q", m.Evidence.Summary, want)
	}
	f, _ := NewFinding(m, t0)
	if f.Status != StatusConfirmed || !f.ByDevice() || f.Validate() != nil {
		t.Fatalf("finding %+v: %v", f, f.Validate())
	}
}

// Review H2: an agent's distribution package is confirmed only by the distribution's own fix, never by NVD's upstream range, which
// ignores backports: a packaged OpenSSH 8.7p1 on Rocky Linux 9.4 (no distribution data), or on Ubuntu 22.04 when the data has no
// 22.04 row, stays suspected. A row the agent reads that is not a distribution package still confirms by NVD's range.
func TestMatchAsset_APackageIsConfirmedOnlyByItsDistribution(t *testing.T) {
	t.Parallel()
	v := Vuln{CVE: "CVE-2026-90001", Vendor: "OpenBSD", Product: "OpenSSH",
		Affected: []Affected{{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "8.5p1", EndExcl: "9.8p1"}}},
		Distro:   []DistroFix{{Distro: "ubuntu", Release: "24.04", Package: "openssh", Status: "fixed", Fixed: "1:9.6p1-3ubuntu13.4"}}}
	ssh := func(ver, full string, packaged bool) Software {
		return Software{ID: "s-ssh", Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: ver, KevKeys: []string{"openbsd|openssh"},
			Source: "agent", Packaged: packaged, PkgVersion: full, PkgSource: "openssh"}
	}
	for name, a := range map[string]Asset{
		"Rocky Linux 9.4, rpm": {ID: "a", Name: "rocky", OS: "Rocky Linux 9.4 (Blue Onyx)", AgentOS: "Rocky Linux 9.4 (Blue Onyx)",
			Software: []Software{ssh("8.7p1", "", true)}},
		"Ubuntu 22.04, no 22.04 row": {ID: "a", Name: "jammy", OS: "Ubuntu 22.04.4 LTS", AgentOS: "Ubuntu 22.04.4 LTS",
			Software: []Software{ssh("8.9p1", "1:8.9p1-3ubuntu0.10", true)}},
		"a package version without the packaged flag": {ID: "a", Name: "jammy", OS: "Ubuntu 22.04.4 LTS", AgentOS: "Ubuntu 22.04.4 LTS",
			Software: []Software{ssh("8.9p1", "1:8.9p1-3ubuntu0.10", false)}},
	} {
		m, ok := byCVE(MatchAsset(a, []Vuln{v}, nil, t0).New, v.CVE)
		if !ok || m.Basis != BasisVersion || m.Evidence.Source != "" {
			t.Errorf("%s: %+v", name, m)
		}
		if f, _ := NewFinding(m, t0); f.Status != StatusSuspected {
			t.Errorf("%s: status %s", name, f.Status)
		}
	}
	// below the distribution's own fix: confirmed
	noble := Asset{ID: "a", Name: "noble", OS: "Ubuntu 24.04.1 LTS", AgentOS: "Ubuntu 24.04.1 LTS", Software: []Software{ssh("9.6p1", "1:9.6p1-3ubuntu13.3", true)}}
	if m, ok := byCVE(MatchAsset(noble, []Vuln{v}, nil, t0).New, v.CVE); !ok || m.Evidence.Source != SourceAgent {
		t.Errorf("below Ubuntu's fix: %+v", m)
	}
	// an application the agent reads directly with its upstream version: NVD's range decides and confirms
	app := Asset{ID: "a", Name: "win", OS: "Microsoft Windows 11 Pro", Software: []Software{ssh("9.6p1", "", false)}}
	if m, ok := byCVE(MatchAsset(app, []Vuln{v}, nil, t0).New, v.CVE); !ok || m.Evidence.Source != SourceAgent {
		t.Errorf("an app the agent reads: %+v", m)
	}
}

// What stays suspected: a version from a banner, one a person typed (also as a correction of the device's SNMP row), a range with
// no end, and a version the scheme cannot order (no finding at all, a could-not-check row).
func TestMatchAsset_OnlyTheDevicesOwnStatementConfirms(t *testing.T) {
	t.Parallel()
	corrected := fortiRow("manual")
	corrected.Software[0].ReportedSource = "snmp"
	for name, a := range map[string]Asset{
		"nmap banner":         fortiRow("nmap"),
		"scan":                fortiRow("scan"),
		"typed by a person":   fortiRow("manual"),
		"a person's override": corrected,
	} {
		res := MatchAsset(a, fortiVulns(), nil, t0)
		m, ok := byCVE(res.New, "CVE-2025-61624")
		if !ok || m.Basis != BasisVersion || m.Evidence.Source != "" || strings.HasPrefix(m.Evidence.Summary, "Confirmed") {
			t.Errorf("%s: %+v", name, m)
			continue
		}
		if f, _ := NewFinding(m, t0); f.Status != StatusSuspected {
			t.Errorf("%s: status %s", name, f.Status)
		}
	}
	open := fortiVulns()[:1]
	open[0].Affected = []Affected{{CPE: fortiCPE, Range: VersionRange{StartIncl: "6.4.0"}}} // no end: no fix to name past it
	if m, ok := byCVE(MatchAsset(fortiSNMP(), open, nil, t0).New, "CVE-2025-61624"); !ok || m.Evidence.Source != "" {
		t.Errorf("open-ended range: %+v", m)
	}
	res := MatchAsset(snmpDevice("ios", "Cisco IOS 15.2(4)M3"), loadGolden(t, "testdata/kev-nvd-snmp-os.json"), nil, t0)
	if len(res.New) != 0 || len(res.NotComparable) == 0 {
		t.Errorf("not comparable: %+v", res)
	}
}

// Review H1: while a person's OS correction stands, inventory writes the person's value into the SNMP reading too: that is no
// statement of the device, so it never confirms.
func TestMatchAsset_APersonsOSCorrectionNeverConfirms(t *testing.T) {
	t.Parallel()
	a := fortiSNMP()
	a.ManualOS, a.OSCorrection = "FortiOS 7.2.13", "it@acme.example set the OS to FortiOS 7.2.13 on 18 Nov 2026"
	m, ok := byCVE(MatchAsset(a, fortiVulns(), nil, t0).New, "CVE-2025-61624")
	if !ok || m.Basis != BasisVersion || m.Evidence.Source != "" || strings.HasPrefix(m.Evidence.Summary, "Confirmed") {
		t.Fatalf("a person's OS: %+v", m)
	}
	if f, _ := NewFinding(m, t0); f.Status != StatusSuspected {
		t.Fatalf("status %s", f.Status)
	}
}
