package scan

import (
	"slices"
	"testing"
)

// L6: a device deleted between the device list and its policy read leaves the list, it does not fail it.
func TestReview_L6_DeletedDeviceDoesNotFailTheList(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.inv.setPolicy(func(id string, explicit bool) Decision {
		if id == "a-far" {
			return Decision{Reason: ReasonGone}
		}
		return samplePolicy(id, explicit)
	})
	ts, err := r.svc.Targets(r.ctx())
	if err != nil || slices.ContainsFunc(ts, func(v TargetView) bool { return v.ID == "a-far" }) || len(ts) != len(sampleDevices())-1 {
		t.Fatalf("%v %+v", err, ts)
	}
}
