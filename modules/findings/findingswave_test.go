package findings

import (
	"strings"
	"testing"
)

// W-1 (TUNE-5b walk): the build a Windows server's own agent reports, inside NVD's range, is a detection: the evidence says
// what the agent reports and which build fixes it, never "only suspected". The same build read by a scan keeps the old words.
func TestMatchAsset_AgentBuildIsADetection(t *testing.T) {
	srv := winPC(26100, true, "1742", "x64")
	srv.Name = "WIN-LAB"
	_, m := oneMatch(t, srv, cve62215, false)
	s := m.Evidence.Summary
	if !m.Evidence.Agent || m.Basis != BasisVersion ||
		!strings.HasPrefix(s, "The agent on WIN-LAB reports Windows Server 2025 build 26100.1742. Microsoft fixed CVE-2025-62215 in build 26100.7092") ||
		strings.Contains(s, "suspected") {
		t.Fatalf("agent row: %+v", m)
	}
	scanned := winPC(26100, true, "1742", "x64")
	scanned.Software[0].Source = "nmap"
	_, m = oneMatch(t, scanned, cve62215, false)
	if m.Evidence.Agent || !strings.Contains(m.Evidence.Summary, "only suspected") {
		t.Fatalf("scan row: %+v", m)
	}
}

// What the CVE page asks. An agent's Ubuntu reading and a Junos switch's own statement rule the
// Alpine-only CVE out; a scan-seen OpenSSH with no platform, a guessed OS and a CVE not on the list do not.
func TestPlatformRuledOut(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    Asset
		cve  string
		want bool
	}{
		{"agent row, agent says Ubuntu", Asset{ID: "a", AgentOS: "Ubuntu 24.04.3 LTS", Software: []Software{sshRow("9.6p1", "", "agent")}}, "CVE-2026-123158", true},
		{"agent row, only a guessed OS", Asset{ID: "a", OS: "Ubuntu 24.04.3 LTS", Software: []Software{sshRow("9.6p1", "", "agent")}}, "CVE-2026-123158", false},
		{"Junos switch, scan-seen OpenSSH", Asset{ID: "sw", StatedOS: "Juniper Networks, Inc. ex4200-48t Ethernet Switch, kernel JUNOS 15.1R7.9", SNMPOS: "Juniper Networks, Inc. ex4200-48t Ethernet Switch, kernel JUNOS 15.1R7.9", Software: []Software{sshRow("7.5", "", "nmap")}}, "CVE-2026-123158", true},
		{"forged LLDP Junos on an Alpine box (review r1 #3)", Asset{ID: "sw", StatedOS: "JUNOS 15.1R7.9", Software: []Software{sshRow("10.2", "", "nmap")}}, "CVE-2026-123158", false},
		{"firewall that says nothing", Asset{ID: "fw", Software: []Software{sshRow("10.2", "protocol 2.0", "nmap")}}, "CVE-2026-123158", false},
		{"a CVE not on the list", Asset{ID: "a", AgentOS: "Ubuntu 24.04.3 LTS", Software: []Software{sshRow("9.6p1", "", "agent")}}, "CVE-2024-6387", false},
	} {
		if got := PlatformRuledOut(tc.a, tc.cve, "OpenBSD", "OpenSSH", alpineSSH(), t0); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Review r1 #5, #6, #7: no "Detected by the agent" while the platform condition is open or when NVD names no end; an ESU-only or a
// feature-update fix says so instead of "that monthly update".
func TestMatchAsset_AgentWordsOnlyWhenTheyHold(t *testing.T) {
	r := MatchAsset(Asset{ID: "a", Name: "fw1", Software: []Software{sshRow("10.2", "", "agent")}}, []Vuln{sshhole()}, nil, t0)
	if len(r.New) != 0 || len(r.Asked) != 1 { // No finding while the platform condition is open
		t.Fatalf("platform open: %+v", r)
	}
	m := MatchAsset(Asset{ID: "a", Name: "alp1", AgentOS: "Alpine Linux v3.23", Software: []Software{sshRow("10.2_p1-r0", "", "agent")}}, []Vuln{sshhole()}, nil, t0).New
	if len(m) != 1 || !m[0].Evidence.Agent {
		t.Fatalf("agent says Alpine: %+v", m)
	}
	all := Vuln{CVE: "CVE-2099-0004", Vendor: "QNAP", Product: "Photo Station", Affected: []Affected{{CPE: "cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "6.0"}}}}
	box := nas("6.1.1")
	box.Software[0].Source = "agent"
	if m = MatchAsset(box, []Vuln{all}, nil, t0).New; len(m) != 1 || m[0].Evidence.Agent {
		t.Fatalf("no end: %+v", m)
	}
	_, w := oneMatch(t, winPC(19045, false, "6456", "x64"), cve62215, false) // Windows 10 22H2 after its last free update
	if !w.Evidence.Agent || !strings.Contains(w.Evidence.Summary, "comes only with Extended Security Updates for Windows 10 22H2") || strings.Contains(w.Evidence.Summary, "monthly update") {
		t.Fatalf("esu: %q", w.Evidence.Summary)
	}
}

// Review r2 nit: an ended release read through a later sibling's rows says no update for it carries the fix (winFix feature_update).
func TestMatchAsset_FeatureUpdateSentence(t *testing.T) {
	_, m := oneMatch(t, winPC(22621, false, "6060", "x64"), cve62215, false) // Windows 11 22H2, out of service, NVD lists 23H2
	if !m.Evidence.Agent || !strings.Contains(m.Evidence.Summary, "but no update for this release carries it: this device has the flaw until it moves to Windows 11 23H2 or later") {
		t.Fatalf("%q", m.Evidence.Summary)
	}
}
