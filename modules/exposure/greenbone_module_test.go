package exposure

import "testing"

// FULL-2 (Trưởng), for Mlee (D-529): switching the External exposure module off stops an enabled Greenbone (Down, its data kept) and
// switching it on starts it again; a Greenbone that is off is left alone both ways. GreenboneAtStart is the box's start-up call.
func TestContract_INV25_TheModuleSwitchStopsAndStartsGreenbone(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.svc.ModuleSwitched(false) // off while Greenbone is off: nothing
	e.svc.ModuleSwitched(true)
	e.svc.gb().upWG.Wait()
	h.with(func(h *fakeGB) {
		if h.ups != 0 || h.downs != 0 {
			t.Fatalf("ups %d downs %d with Greenbone off", h.ups, h.downs)
		}
	})
	e.enable()
	e.svc.ModuleSwitched(false)
	e.svc.gb().upWG.Wait()
	h.with(func(h *fakeGB) {
		if h.ups != 1 || h.downs != 1 {
			t.Fatalf("after the module off: ups %d downs %d, want 1 and 1", h.ups, h.downs)
		}
	})
	if !e.svc.GreenboneEnabled(e.ctx()) {
		t.Fatal("the module switch turned the setting off")
	}
	e.svc.ModuleSwitched(true)
	e.svc.gb().upWG.Wait()
	e.svc.GreenboneAtStart(e.ctx()) // the box's start-up call: Up again (it is idempotent at the host)
	e.svc.gb().upWG.Wait()
	h.with(func(h *fakeGB) {
		if h.ups != 3 || h.downs != 1 {
			t.Fatalf("after the module on and a start-up: ups %d downs %d, want 3 and 1", h.ups, h.downs)
		}
	})
}
