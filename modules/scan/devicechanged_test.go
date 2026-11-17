package scan

import "testing"

// D-601 (review r1 M2): turning a device's network scan off while its vulnerability check runs stops that check at once (the probes on
// their way are closed as stopped, its row says why) and the run goes on with the next device; a change that still allows it, or one of
// another device, stops nothing.
func TestD601_ScanTurnedOffStopsThatDeviceOnly(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	started := r.eng.blockRuns()
	v := r.start("a-web01", "a-nas02")
	<-started
	if err := r.svc.DeviceChanged(r.ctx(), "a-nas02"); err != nil { // not the device being checked
		t.Fatal(err)
	}
	if err := r.svc.DeviceChanged(r.ctx(), "a-web01"); err != nil { // still allowed: nothing stops
		t.Fatal(err)
	}
	r.inv.mu.Lock()
	prev := r.inv.policy
	r.inv.mu.Unlock()
	r.inv.setPolicy(func(id string, explicit bool) Decision {
		if id == "a-web01" {
			return Decision{Reason: reasonNever} // its network scan was turned off on its page
		}
		return prev(id, explicit)
	})
	r.eng.mu.Lock()
	r.eng.blocked = false // the next device's job answers
	r.eng.mu.Unlock()
	if err := r.svc.DeviceChanged(r.ctx(), "a-web01"); err != nil {
		t.Fatal(err)
	}
	r.wait()
	got := r.run(v.ID)
	if got.Status != "done" {
		t.Fatalf("status %q, want done: only the device's part stops", got.Status)
	}
	var web, nas bool
	for _, row := range got.Results {
		switch row.TargetID {
		case "a-web01":
			web = web || row.Note == noteTurnedOff
		case "a-nas02":
			nas = nas || row.Note != noteSkipped
		}
	}
	if !web || !nas {
		t.Fatalf("rows %+v: a-web01 stopped with its note, a-nas02 still checked", got.Results)
	}
	if n := r.count(`SELECT count(*) FROM scan_probe WHERE result = 'stopped'`); n == 0 {
		t.Fatal("the probes on their way are not closed as stopped")
	}
}
