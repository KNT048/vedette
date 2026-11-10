package scan

import (
	"testing"
)

// L3: a CVE a person dismissed (false positive, not relevant, patched) is not probed again.
func TestReview_L3_DismissedFindingsAreNotProbed(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.findings.list[1].Status = "false_positive" // f-2, CVE-2024-3400 on a-web01
	v := r.start("a-web01")
	r.wait()
	if len(r.eng.sent()) != 0 || rowOf(r.run(v.ID), "a-web01", "no_template") == nil {
		t.Fatalf("jobs %+v rows %+v", r.eng.sent(), r.run(v.ID).Results)
	}
}
