package scan

import "testing"

// Reach says, for one device, how the scan stands to it: covered, outside the confirmed ranges, off for the device, or not known.
func TestReach_PerDevice(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	for id, want := range map[string]Reach{
		"a-web01": ReachCovered,
		"a-far":   ReachOutside,
		"a-never": ReachOff,
		"a-unk":   ReachUnknown, // not approved: neither inside nor outside a range
		"a-gone":  ReachUnknown,
	} {
		got, err := r.svc.Reach(r.ctx(), id)
		if err != nil || got != want {
			t.Errorf("%s: reach %q (err %v), want %q", id, got, err, want)
		}
	}
}
