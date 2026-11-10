package scan

import (
	"testing"
)

// L1: the job is skipped when the inventory decided on another address than the one the scan would use.
func TestReview_L1_AddressMustBeTheOneDecidedOn(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.inv.setPolicy(func(id string, explicit bool) Decision {
		d := samplePolicy(id, explicit)
		if id == "a-web01" {
			d.IP = "192.168.10.99" // the device moved after the snapshot
		}
		return d
	})
	v := r.start("a-web01")
	r.wait()
	if row := rowOf(r.run(v.ID), "a-web01", "skipped"); row == nil || row.Note != "The device's address changed since the scan started; not scanned." || len(r.eng.sent()) != 0 {
		t.Fatalf("%+v %d", r.run(v.ID).Results, len(r.eng.sent()))
	}
}
