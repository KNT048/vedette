package scan

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"testing"

	"github.com/knt048/vedette/core/audit"
)

// sharedInventory is fakeInventory with the one store of the shared window, check rate and exclusions (INV-16, #850).
type sharedInventory struct {
	*fakeInventory
	mu      sync.Mutex
	checks  Checks
	saved   []Checks
	settled []bool
	refuse  error
}

func (f *sharedInventory) Checks(context.Context) (Checks, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checks, nil
}

func (f *sharedInventory) SaveChecks(_ context.Context, tx *sql.Tx, _ string, c Checks) error {
	if tx == nil {
		return errors.New("no transaction")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse != nil {
		return f.refuse
	}
	f.saved = append(f.saved, c)
	f.checks = c
	return nil
}

func (f *sharedInventory) Settle(_ context.Context, _ *sql.Tx, committed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settled = append(f.settled, committed)
}

func newSharedEnv(t *testing.T) (*env, *sharedInventory) {
	t.Helper()
	e := &env{t: t, db: newDB(t), clock: &fakeClock{now: t0}, inv: &fakeInventory{scope: confirmedScope()}, engine: &fakeEngine{}}
	inv := &sharedInventory{fakeInventory: e.inv, checks: Checks{Window: Window{Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "21:00", To: "06:00"}, Rate: 7, Exclusions: []string{"192.168.10.9"}}}
	svc, err := NewService(Config{DB: e.db, Audit: audit.New(e.clock.Now), Inventory: inv, Engine: e.engine, Pack: testPack(t), Log: slog.New(slog.DiscardHandler), Clock: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e, inv
}

// INV-16 (#850): the window, the check rate and the exclusions are read from the inventory, not scan_setting; PUT /scans/config
// writes them there in its own transaction and settles the inventory's events with the outcome; the scan-only settings stay here.
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
	// scan_setting keeps a copy for a rollback to a version before #850
	if e.count(`SELECT rate FROM scan_setting`) != 9 {
		t.Fatal("scan_setting's copy was not written along")
	}

	// a save of scan-only settings does not touch the shared store
	auto := false
	if _, err := e.svc.SaveConfig(e.ctx(), "admin@acme.example", Patch{AutoRescan: &auto}); err != nil {
		t.Fatal(err)
	}
	if len(inv.saved) != 1 {
		t.Fatalf("a scan-only save wrote the shared store: %+v", inv.saved)
	}

	// the inventory refuses: nothing is stored and its events are dropped
	inv.refuse = errors.New("refused")
	if _, err := e.svc.SaveConfig(e.ctx(), "admin@acme.example", Patch{Rate: &rate}); err == nil {
		t.Fatal("a refused shared save succeeded")
	}
	if inv.settled[len(inv.settled)-1] {
		t.Fatalf("settled %v after a failed save", inv.settled)
	}

	// a window the schedule time is no longer inside (saved on Settings › Scanning) runs nothing scheduled
	inv.refuse = nil
	inv.checks.Window = Window{Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "01:00", To: "03:00"}
	if cv, _ := e.svc.Config(e.ctx()); cv.NextRun != nil || cv.ScheduleBlockedReason == nil {
		t.Fatalf("next run %v outside the shared window, blocked %v", cv.NextRun, cv.ScheduleBlockedReason)
	}
}
