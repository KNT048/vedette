package findings

import "testing"

// The Juniper EX4200 switch .47 states "JUNOS 15.1R7.9" only over LLDP (no SNMP read of it), and a scan saw its
// OpenSSH. On a device whose MAC at its address IEEE assigned to Juniper Networks, the LLDP statement counts: the Alpine-only
// CVE-2026-123158 is ruled out (an open finding closes, the CVE page drops the device). An LLDP claim on any other card (forged with
// that device's MAC, review r1 #3 of #800), an SNMP answer naming another OS, Junos OS Evolved or an agent's other OS keep it.
func TestPlatform_LLDPJunosOnAJuniperCard(t *testing.T) {
	t.Parallel()
	const lldp = "JUNOS 15.1R7.9"
	for _, tc := range []struct {
		name, stated, snmp, agent, mac string
		out                            bool
	}{
		{"LLDP Junos, Juniper card (the switch .47)", lldp, "", "", "3c:8a:b0:9c:85:ff", true},
		{"LLDP Junos, another maker's card (a forged frame with an Alpine box's MAC)", lldp, "", "", "00:0c:29:12:34:56", false},
		{"LLDP Junos, Juniper Systems (another company)", lldp, "", "", "0c:05:35:00:00:01", false},
		{"LLDP Junos, no MAC at an address", lldp, "", "", "", false},
		{"LLDP Junos on a Juniper card, but SNMP answers Linux", lldp, "Linux 6.1.0", "", "3c:8a:b0:9c:85:ff", false},
		{"LLDP Junos OS Evolved on a Juniper card", "JUNOS 21.4R1.12-EVO", "", "", "3c:8a:b0:9c:85:ff", false},
		{"LLDP Junos on a Juniper card, an agent reports Alpine", lldp, "", "Alpine Linux v3.23", "3c:8a:b0:9c:85:ff", false},
	} {
		a := Asset{ID: "sw", Name: "192.168.142.47", OS: "Juniper EX2200 switch (JUNOS 12)", StatedOS: tc.stated, SNMPOS: tc.snmp, AgentOS: tc.agent, MAC: tc.mac,
			Software: []Software{sshRow("7.5", "", "nmap")}}
		res := MatchAsset(a, []Vuln{sshhole()}, map[string]bool{"CVE-2026-123158": true}, t0)
		got := len(res.NotAffected) == 1 && len(res.Existing) == 0
		if got != tc.out {
			t.Errorf("%s: closed %v, want %v (existing %+v)", tc.name, got, tc.out, res.Existing)
		}
		if got := PlatformRuledOut(a, "CVE-2026-123158", "OpenBSD", "OpenSSH", alpineSSH(), t0); got != tc.out {
			t.Errorf("%s: CVE page ruled out %v, want %v", tc.name, got, tc.out)
		}
	}
}
