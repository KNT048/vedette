package scan

import (
	"testing"

	"github.com/knt048/vedette/modules/scan/nucleiargv"
)

// L1: the job is skipped when the inventory decided on another address than the one the scan would use. The device
// moves while the run is under way (it was pickable when the run started).
func TestReview_L1_AddressMustBeTheOneDecidedOn(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.eng.onRun = func(j nucleiargv.Job) {
		if j.Targets[0].Host == "192.168.10.21" { // while the NAS is scanned, WEB01's inventory row gets another address
			r.inv.setPolicy(func(id string, explicit bool) Decision {
				d := samplePolicy(id, explicit)
				if id == "a-web01" {
					d.IP = "192.168.10.99"
				}
				return d
			})
		}
	}
	v := r.start("a-nas02", "a-web01")
	r.wait()
	if row := rowOf(r.run(v.ID), "a-web01", "skipped"); row == nil || row.Note != "The device's address changed since the scan started; not scanned." || len(r.eng.sent()) != 1 {
		t.Fatalf("%+v %d", r.run(v.ID).Results, len(r.eng.sent()))
	}
}
