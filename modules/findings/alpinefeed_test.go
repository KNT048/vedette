package findings

import "testing"

// D-605: only the device's own statement (agent, SNMP answer) or a person's OS says Alpine; a person's other OS wins; the folded OS (an
// nmap or DHCP guess) never does.
func TestStatesAlpine(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		a    Asset
		want bool
	}{
		{Asset{SNMPOS: "Alpine Linux"}, true}, // BN340 after #950: uname over SNMP
		{Asset{AgentOS: "Alpine Linux v3.23"}, true},
		{Asset{ManualOS: "Alpine Linux 3.23"}, true},
		{Asset{OS: "Alpine Linux"}, false}, // nmap's guess
		{Asset{ManualOS: "Ubuntu 24.04", SNMPOS: "Alpine Linux"}, false},
		{Asset{SNMPOS: "Linux bn340 6.12.1-0-lts"}, false},
	} {
		if got := StatesAlpine(tc.a); got != tc.want {
			t.Errorf("%+v: %v, want %v", tc.a, got, tc.want)
		}
	}
}
