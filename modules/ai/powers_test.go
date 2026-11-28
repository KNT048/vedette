package ai

import (
	"slices"
	"testing"
)

// The table of what each job may do covers every job, says for each what an answer may change and where it may send, and gives a
// tool that sends its arguments out of the box (a connection) to one job only: Ask, where a person asks and an administrator allows
// each connection outside the network. Every tool of the box a row names exists.
func TestJobPowersCoverEveryJobAndGiveSendingToolsToAskOnly(t *testing.T) {
	known := []string{"device_updates", "events_around", "get_finding", "list_findings", "lookup_cve", "lookup_ioc", "search_assets"}
	for _, j := range Jobs() {
		p, ok := jobPowers[j]
		if !ok || p.writes == "" || p.egress == "" {
			t.Errorf("%s: no row, or a row that does not say what it writes and where it sends", j)
		}
		for _, c := range p.classes {
			if c != toolBox && c != toolConnLAN && c != toolConnOut {
				t.Errorf("%s: unknown tool class %q", j, c)
			}
			if (c == toolConnLAN || c == toolConnOut) && j != JobAskMyData {
				t.Errorf("%s may send to a connection", j)
			}
		}
		for _, n := range p.boxTools {
			if !slices.Contains(known, n) {
				t.Errorf("%s names a tool the box does not have: %s", j, n)
			}
		}
		if !j.CarriesInternalData() && len(p.classes) > 0 {
			t.Errorf("%s reads public text only and may not have tools", j)
		}
	}
	if jobPowers[JobLogInvestigate].permits(toolConnLAN, "conn_x__y") || !jobPowers[JobAskMyData].permits(toolBox, "search_assets") || jobPowers[JobAskMyData].permits(toolBox, "events_around") {
		t.Error("permits")
	}
}
