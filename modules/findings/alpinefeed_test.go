package findings

import (
	"strings"
	"testing"
)

// Only the device's own statement (agent, SNMP answer) or a person's OS says Alpine; a person's other OS wins; the folded OS (an
// nmap or DHCP guess) never does.
func TestStatesAlpine(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		a    Asset
		want bool
	}{
		{Asset{SNMPOS: "Alpine Linux"}, true}, // uname read over SNMP
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

// gw-alpine's package release is read against the feed's rows, and only them. With Alpine's rows (alpine-osv) 10.2_p1-r1 on 3.23 is
// not affected; with the feed on but not loaded the question stays; with the feed off NVD's range decides (a finding), never a made-up
// list; a branch the feed has no row for (edge: OSV.dev lists none) is never closed either.
func TestPlatform_AlpineFeedRowsDecide(t *testing.T) {
	t.Parallel()
	bn340 := func(os, rel string) Asset {
		row := sshRow("10.2", "", "manual")
		row.PkgVersion, row.ReportedSource = rel, "nmap"
		return Asset{ID: "a-gw-alpine", Name: "gw-alpine", SNMPOS: "Alpine Linux", ManualOS: os, Software: []Software{row}}
	}
	have := map[string]bool{"CVE-2026-123158": true}
	if res := MatchAsset(bn340("Alpine Linux 3.23", "10.2_p1-r1"), []Vuln{sshhole()}, have, t0); len(res.NotAffected) != 1 ||
		!strings.Contains(res.NotAffected[0].Evidence.Summary, "Alpine Linux 3.23 fixed it in openssh-server 10.2_p1-r1") {
		t.Fatalf("with the feed's rows: %+v", res)
	}
	// alpine-osv on but not loaded (never filled, or every pull failed: feeds' DistroLoading) keeps the question,
	// even with the release a person gave; only with the feed off does NVD decide (a finding)
	loading := sshhole()
	loading.Distro, loading.DistroLoading = nil, map[string]bool{DistroAlpine: true}
	for _, rel := range []string{"10.2_p1-r1", ""} {
		res := MatchAsset(bn340("Alpine Linux 3.23", rel), []Vuln{loading}, have, t0)
		if len(res.New)+len(res.Existing)+len(res.NotAffected) != 0 || len(res.Asked) != 1 || len(res.Unchecked) != 1 || res.Unchecked[0].Reason != UncheckedPackageUnknown ||
			!strings.Contains(res.Asked[0].AskedWhy(), "Alpine Linux's fixed releases are not loaded yet") {
			t.Fatalf("feed on, not loaded, release %q: %+v", rel, res)
		}
	}
	off := sshhole()
	off.Distro = nil
	if res := MatchAsset(bn340("Alpine Linux 3.23", "10.2_p1-r1"), []Vuln{off}, have, t0); len(res.NotAffected) != 0 || len(res.New)+len(res.Existing) != 1 {
		t.Fatalf("feed off: %+v", res)
	}
	if res := MatchAsset(Asset{ID: "u", Name: "web", AgentOS: "Ubuntu 24.04", Software: []Software{sshRow("9.6p1", "", "agent")}}, []Vuln{loading}, have, t0); len(res.Asked) != 0 || len(res.NotAffected) != 1 {
		t.Fatalf("an Ubuntu device is not asked while Alpine's data loads: %+v", res)
	}
	below := MatchAsset(bn340("Alpine Linux 3.23", "10.2_p1-r0"), []Vuln{sshhole()}, nil, t0)
	if len(below.New) != 1 || !strings.Contains(below.New[0].Evidence.Summary, "Update openssh-server to 10.2_p1-r1 or later") {
		t.Fatalf("below the 3.23 fix: %+v", below)
	}
	if res := MatchAsset(bn340("Alpine Linux edge", "10.6_p2-r0"), []Vuln{sshhole()}, have, t0); len(res.NotAffected) != 0 {
		t.Fatalf("edge has no row in the feed, yet: %+v", res)
	}
}
