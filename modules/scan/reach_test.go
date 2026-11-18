package scan

import "testing"

// Reach reads the policy of the one device (never the device list) and names why the scan does not reach it.
func TestReach_PerDevice(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	for id, want := range map[string]Reach{
		"a-far":   ReachOutside,
		"a-never": ReachDeviceOff,
		"a-web01": ReachUnknown, // allowed: the page says nothing about the scan
	} {
		got, err := r.svc.Reach(r.ctx(), id)
		if err != nil || got != want {
			t.Errorf("%s: reach %q (err %v), want %q", id, got, err, want)
		}
	}
	r.inv.mu.Lock()
	single, batches := r.inv.single, r.inv.batches
	r.inv.mu.Unlock()
	if single != 3 || batches != 0 {
		t.Errorf("policy reads: single %d, batches %d; want 3 single reads and no list", single, batches)
	}
}
