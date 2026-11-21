package findings

import "testing"

// What a device of a distribution sees on the plan while that distribution's data is loaded, loaded with no row, or lacks its release:
// only a feed that has never completed a pull makes the device wait; after a pull, a package the data does not name, and a release it
// holds no row for, get the honest "Check <distro>'s security updates" item.
func TestPlan_DistroLoadedStatesAsTheCustomerSeesThem(t *testing.T) {
	t.Parallel()
	tier := []TierVuln{nvdSSH("CVE-2026-71001"), nvdSSH("CVE-2026-71002")}
	alpine := Asset{ID: "fw", Name: "fw", AgentOS: "Alpine Linux v3.23", OS: "Alpine Linux v3.23", Software: []Software{sshAgentRow("10.2_p1-r1", "openssh")}}
	ubuntu := Asset{ID: "u", Name: "u", OS: "Ubuntu 22.04 LTS", Software: []Software{sshAgentRow("1:8.9p1-3ubuntu0.10", "openssh")}}
	tier = append(tier, tierV("CVE-2026-71003", "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.3"}}))
	for name, tc := range map[string]struct {
		a        Asset
		loading  map[string]bool
		known    map[string]bool
		covered  map[string]bool
		distro   []TierVuln
		wantItem string // the sentence of the one item, "" for none
		compared bool
	}{
		"never pulled: the device waits, unchecked":                    {a: alpine, loading: map[string]bool{DistroAlpine: true}},
		"pull completed with zero rows: the fallback item, not a wait": {a: alpine, wantItem: "Check Alpine Linux's security updates for OpenSSH", compared: true},
		"the data names no such package: the fallback item": {a: alpine, known: map[string]bool{"alpine/curl": true}, covered: map[string]bool{"alpine/": true},
			wantItem: "Check Alpine Linux's security updates for OpenSSH", compared: true},
		"package known, no row for the device's release: the fallback item": {a: ubuntu, known: map[string]bool{"ubuntu/openssh": true},
			covered: map[string]bool{"ubuntu/24.04": true}, distro: []TierVuln{distroV("CVE-2026-71009", "recent", 30, 0.01, noble("openssh", "1:9.6p1-3ubuntu13.9", false))},
			wantItem: "Check Ubuntu's security updates for OpenSSH", compared: true},
		"package known, release still loading: the device waits": {a: ubuntu, loading: map[string]bool{"ubuntu": true}, known: map[string]bool{"ubuntu/openssh": true},
			covered: map[string]bool{"ubuntu/24.04": true}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			x := newTierIndex(tier).withKnown(tc.known, tc.loading).withDistro(tc.distro, tc.covered)
			items, compared := matchTiers(tc.a, x, nil, t0)
			if compared != tc.compared {
				t.Fatalf("compared %v, items %+v", compared, items)
			}
			if tc.wantItem == "" {
				if len(items) != 0 {
					t.Fatalf("items %+v", items)
				}
				return
			}
			if len(items) != 1 || items[0].DistroData != DistroDataNone {
				t.Fatalf("items %+v", items)
			}
			if s := updateSentence(planAction(items[0])); s != tc.wantItem {
				t.Fatalf("sentence %q, want %q", s, tc.wantItem)
			}
		})
	}
}
