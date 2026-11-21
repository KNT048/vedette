package scan

import (
	"errors"
	"fmt"
	"slices"
	"testing"
)

// newSharedEnv is an env whose inventory holds shared values that differ from the defaults.
func newSharedEnv(t *testing.T) (*env, *fakeInventory) {
	t.Helper()
	e := newEnv(t)
	e.inv.checks = Checks{Window: Window{Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "21:00", To: "06:00"}, Rate: 7, Exclusions: []string{"192.168.10.9"}}
	return e, e.inv
}

// INV-16 (#850): the window, the check rate and the exclusions are read from the inventory, not scan_setting; PUT /scans/config
// writes them there in its own transaction and settles the inventory's events with the outcome; the scan-only settings stay here, and
// scan_setting keeps no copy of them.
func TestContract_INV16_SharedWindowRateAndExclusions(t *testing.T) {
	t.Parallel()
	e, inv := newSharedEnv(t)
	cv, err := e.svc.Config(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if c := cv.Config; c.Window.From != "21:00" || c.Window.To != "06:00" || c.Rate != 7 || !slices.Equal(c.Exclusions, []string{"192.168.10.9"}) {
		t.Fatalf("config = %+v, want the inventory's values", c)
	}
	// the targets subtract the shared exclusions
	st, err := e.svc.settings(e.ctx(), e.db.Reader())
	if err != nil || st.Rate != 7 {
		t.Fatalf("settings = %+v, %v", st, err)
	}

	if e.count(`SELECT count(*) FROM pragma_table_info('scan_setting') WHERE name IN ('days', 'win_from', 'win_to', 'rate', 'exclusions')`) != 0 {
		t.Fatal("scan_setting still has a copy of the shared values")
	}

	// a save of the shared fields goes to the inventory, in the same transaction, and settles committed
	from, rate := "20:00", 9
	if _, err := e.svc.SaveConfig(e.ctx(), "admin@acme.example", Patch{From: &from, Rate: &rate, Exclusions: []string{"192.168.10.0/28"}}); err != nil {
		t.Fatal(err)
	}
	if len(inv.saved) != 1 || inv.saved[0].Window.From != "20:00" || inv.saved[0].Window.To != "06:00" || inv.saved[0].Rate != 9 ||
		!slices.Equal(inv.saved[0].Exclusions, []string{"192.168.10.0/28"}) || !slices.Equal(inv.settled, []bool{true}) {
		t.Fatalf("saved %+v, settled %v", inv.saved, inv.settled)
	}
	if cv, _ := e.svc.Config(e.ctx()); cv.Config.Rate != 9 || cv.Config.Window.From != "20:00" {
		t.Fatalf("read back %+v", cv.Config)
	}
	// a save of scan-only settings writes the shared values back as they were
	auto := false
	if _, err := e.svc.SaveConfig(e.ctx(), "admin@acme.example", Patch{AutoRescan: &auto}); err != nil {
		t.Fatal(err)
	}
	if len(inv.saved) != 2 || !slices.Equal(inv.saved[1].Exclusions, inv.saved[0].Exclusions) || inv.saved[1].Rate != 9 || inv.saved[1].Window.From != inv.saved[0].Window.From {
		t.Fatalf("a scan-only save changed the shared values: %+v", inv.saved) // it writes them back unchanged (review #857 M1)
	}

	// the inventory refuses: nothing is stored and its events are dropped
	inv.refuse = errors.New("refused")
	if _, err := e.svc.SaveConfig(e.ctx(), "admin@acme.example", Patch{Rate: &rate}); err == nil {
		t.Fatal("a refused shared save succeeded")
	}
	if inv.settled[len(inv.settled)-1] {
		t.Fatalf("settled %v after a failed save", inv.settled)
	}
}

// review #857 L7: a list over 200 that a merge left passes a save that does not grow it; growing it is refused.
func TestContract_INV16_ALongMergedListStillSaves(t *testing.T) {
	t.Parallel()
	e, inv := newSharedEnv(t)
	long := make([]string, 0, 210)
	for i := range 210 {
		long = append(long, fmt.Sprintf("10.0.%d.%d", i/250, i%250+1))
	}
	inv.checks.Exclusions = long
	auto := false
	if _, err := e.svc.SaveConfig(e.ctx(), "admin@acme.example", Patch{AutoRescan: &auto}); err != nil {
		t.Fatalf("a save that keeps the long list: %v", err)
	}
	if _, err := e.svc.SaveConfig(e.ctx(), "admin@acme.example", Patch{Exclusions: append(slices.Clone(long), "10.9.9.9")}); err == nil {
		t.Fatal("a list grown past 200 was saved")
	}
}
