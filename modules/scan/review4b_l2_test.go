package scan

import (
	"slices"
	"testing"
)

// #189 review L2: a run that holds several CVEs probes each device only for the CVEs its own events listed it for. A
// device listed for CVE-A whose finding for CVE-B is mitigated (plan keeps mitigated findings, affected() does not
// count them) is not probed for CVE-B.
func TestReview4b_L2_ABacklogProbesOnlyTheEventsPairs(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.findings.mu.Lock()
	r.findings.list = append(r.findings.list,
		FindingRef{ID: "f-4", AssetID: "a-srv", CVE: "CVE-2023-46805", Status: "suspected"},
		FindingRef{ID: "f-5", AssetID: "a-web01", CVE: "CVE-2023-46805", Status: "mitigated"})
	r.findings.mu.Unlock()
	r.eng.reply = lines()
	backlogOf(t, r, "CVE-2024-3400", "CVE-2023-46805")
	r.tick()
	for _, j := range r.eng.sent() {
		want := map[string][]string{"192.168.10.12": {"http/cves/2024/CVE-2024-3400.yaml"}, "192.168.10.10": {"http/cves/2023/CVE-2023-46805.yaml"}}[j.Targets[0].Host]
		if !slices.Equal(j.Templates, want) {
			t.Fatalf("%s was probed for %v, want %v (the events listed it only for that)", j.Targets[0].Host, j.Templates, want)
		}
	}
	r.tick() // the run is over: the events are closed and listed
	if got := eventResults(r); !slices.Equal(got["CVE-2023-46805"].Devices, []string{"SRV-AD"}) {
		t.Fatalf("devices of CVE-2023-46805: %v", got["CVE-2023-46805"].Devices)
	}
}
