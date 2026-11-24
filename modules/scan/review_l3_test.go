package scan

import (
	"slices"
	"testing"
)

// A CVE a person dismissed (false positive, not relevant, patched) is not probed again.
func TestReview_L3_DismissedFindingsAreNotProbed(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.findings.list[1].Status = "false_positive" // f-2, CVE-2024-3400 on a-web01
	// what is left on WEB01 (CVE-2021-44228) has no template: nothing to check, no run
	_, err := r.svc.StartRun(r.ctx(), "it@acme.example", []string{"a-web01"})
	wantAPI(t, err, 400, "nothing_to_check")
	// with a CVE that has a template, the run probes it and still not the dismissed one
	r.giveCheck("a-web01")
	v := r.start("a-web01")
	r.wait()
	if jobs := r.eng.sent(); len(jobs) != 1 || slices.Contains(jobs[0].Templates, "http/cves/2024/CVE-2024-3400.yaml") || rowOf(r.run(v.ID), "a-web01", "no_template") == nil {
		t.Fatalf("jobs %+v rows %+v", jobs, r.run(v.ID).Results)
	}
}
