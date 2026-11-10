package scan

import (
	"testing"

	"github.com/knt048/vedette/modules/scan/nucleiargv"
)

// M1: the pick is per device: only ids that were pick_only when the run started are picked; a device that becomes
// fragile during a "Select all" run is checked again without the pick and skipped.
func TestReview_M1_PickIsPerDevice(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.eng.onRun = func(j nucleiargv.Job) {
		if j.Targets[0].Host == "192.168.10.21" { // while the picked NAS is scanned, SRV-AD is marked fragile
			r.inv.setPolicy(func(id string, explicit bool) Decision {
				if id == "a-srv" && !explicit {
					return Decision{Reason: "fragile_passive_only"}
				}
				return samplePolicy(id, explicit)
			})
		}
	}
	v := r.start("a-nas02", "a-srv")
	r.wait()
	got := r.run(v.ID)
	if row := rowOf(got, "a-srv", "skipped"); row == nil || row.Note != "Fragile device: scanned only when you pick it in Scan now." {
		t.Fatalf("a-srv: %+v", got.Results)
	}
	if len(r.eng.sent()) != 1 {
		t.Fatalf("jobs: %+v", r.eng.sent())
	}
	if n := r.count(`SELECT count(*) FROM scan_run WHERE picked = '["a-nas02"]'`); n != 1 {
		t.Fatalf("picked ids stored: %d", n)
	}
}
