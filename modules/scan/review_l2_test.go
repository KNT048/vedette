package scan

import (
	"slices"
	"strings"
	"testing"
)

// L2: the consent is audited in full: one row per picked device, and the start row counts and hashes the whole list.
func TestReview_L2_PicksAuditedInFull(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.start("a-nas02", "a-web01")
	r.wait()
	var start auditRow
	var picks []string
	for _, a := range r.audits() {
		switch a.Action {
		case "scan.start":
			start = a
		case "scan.pick":
			picks = append(picks, a.Target)
		}
	}
	if !strings.HasPrefix(start.Detail, "2 targets, 1 picked by hand, sha256 ") || !slices.Equal(picks, []string{"a-nas02"}) {
		t.Fatalf("start %+v, picks %v", start, picks)
	}
}
