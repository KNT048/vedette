package findings

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/knt048/vedette/core/jobs"
)

// D-144: the bus is best-effort, so findings catches up on its own. These tests drop the event (they never call the
// handler) and expect the periodic Reconcile to end in the state the event would have produced.

func TestContract_INV9_ReconcileCreatesTheFindingALostMatchEventLeft(t *testing.T) {
	t.Parallel()
	e := newEnv(t) // device a-1 matches, but inventory.match.changed was dropped: nothing called OnMatchChanged
	res, err := e.svc.Reconcile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if res.Devices != 1 || res.Created != 1 || res.Orphans != 0 {
		t.Fatalf("result = %+v", res)
	}
	if e.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'a-1' AND cve = 'CVE-2022-27593'`) != 1 {
		t.Fatal("the finding was not created")
	}
	if ev := e.pub.take(); len(ev) != 1 || ev[0].Name != EventCreated {
		t.Fatalf("events = %+v, want one %s", ev, EventCreated)
	}
}

func TestContract_INV9_ReconcileRemovesTheFindingsOfADeviceWhoseDeleteEventWasLost(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	e.inv.mu.Lock() // the device is deleted and inventory.asset.deleted is dropped
	delete(e.inv.assets, "a-1")
	delete(e.inv.match, "a-1")
	e.inv.mu.Unlock()
	res, err := e.svc.Reconcile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if res.Orphans != 1 || res.Devices != 0 {
		t.Fatalf("result = %+v", res)
	}
	if e.count(`SELECT count(*) FROM fnd_finding`) != 0 || e.count(`SELECT count(*) FROM fnd_finding_history`) != 0 {
		t.Fatal("the findings of the deleted device are still there")
	}
	if got := e.auditActions(); got[len(got)-1] != "findings.deleted_with_asset" {
		t.Fatalf("audit = %v", got)
	}
}

func TestContract_INV9_ReconcileTwiceChangesNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	other := Asset{ID: "a-2", Name: "nas02", Software: nas("").Software}
	e.inv.match["a-2"] = other
	e.inv.assets["a-2"] = AssetView{ID: "a-2", IP: "192.168.10.22", Kind: "nas", Display: "Photo Station"}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	counts := func() [4]int {
		return [4]int{e.count(`SELECT count(*) FROM fnd_finding`), e.count(`SELECT count(*) FROM fnd_finding_history`), e.count(`SELECT count(*) FROM core_audit`), len(e.pub.take())}
	}
	before := counts()
	res, err := e.svc.Reconcile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 0 || res.Orphans != 0 || res.Devices != 2 {
		t.Fatalf("second run = %+v", res)
	}
	after := counts()
	after[3] = len(e.pub.take())
	if before[0] != 2 || after[0] != before[0] || after[1] != before[1] || after[2] != before[2] || after[3] != 0 {
		t.Fatalf("findings, history, audit, events: before %v after %v; the second run must change none", before, after)
	}
}

func TestReconcileNeverReopensOrRecreatesWhatAPersonClosed(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	if _, err := e.svc.SetStatus(t.Context(), id, ActionPatched, "updated", "it@example.test"); err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	r, err := e.svc.Get(t.Context(), id)
	if err != nil || r.Status != StatusPatched || e.count(`SELECT count(*) FROM fnd_finding`) != 1 || len(e.pub.take()) != 0 {
		t.Fatalf("status %v err %v: a closed finding must stay closed and not be created again", r.Status, err)
	}
}

func TestReconcileRemovesNothingWhenTheDeviceListCannotBeRead(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	e.inv.mu.Lock()
	e.inv.idsErr = errors.New("inventory is busy")
	e.inv.mu.Unlock()
	if _, err := e.svc.Reconcile(t.Context()); err == nil {
		t.Fatal("a failed device list must be an error, not an empty list")
	}
	if e.count(`SELECT count(*) FROM fnd_finding`) != 1 {
		t.Fatal("a finding was removed on a failed read")
	}
}

func TestReconcileKeepsTheFindingsOfADeviceInventoryStillKnows(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	// a-2 is created after the device list was read: the list lacks it, Assets knows it
	other := Asset{ID: "a-2", Name: "nas02", Software: nas("").Software}
	if _, err := e.svc.UpsertFromMatch(t.Context(), other, e.feeds.vulns); err != nil {
		t.Fatal(err)
	}
	e.inv.mu.Lock()
	e.inv.assets["a-2"] = AssetView{ID: "a-2", IP: "192.168.10.22", Kind: "nas", Display: "Photo Station"}
	e.inv.mu.Unlock()
	res, err := e.svc.Reconcile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if res.Orphans != 0 || e.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'a-2'`) != 1 {
		t.Fatalf("result %+v: the finding of a device inventory still knows was removed", res)
	}
}

func TestReconcileStopsWhenItsContextIsCancelled(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := e.svc.Reconcile(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if e.count(`SELECT count(*) FROM fnd_finding`) != 0 {
		t.Fatal("it wrote after being cancelled")
	}
}

type testGate struct {
	mu sync.Mutex
	on bool
}

func (g *testGate) Enabled(string) bool { g.mu.Lock(); defer g.mu.Unlock(); return g.on }
func (g *testGate) set(v bool)          { g.mu.Lock(); g.on = v; g.mu.Unlock() }

func TestContract_INV9_ReconcileJobRunsOnlyWhileFindingsIsOn(t *testing.T) {
	jb := Jobs(nil)
	if len(jb) != 1 || jb[0].Module != "findings" || jb[0].Name != "reconcile" || jb[0].Every != time.Hour {
		t.Fatalf("jobs = %+v", jb)
	}
	synctest.Test(t, func(t *testing.T) {
		var runs atomic.Int32
		j := jb[0]
		j.Run = func(context.Context) error { runs.Add(1); return nil } // the schedule is what is tested here
		g := &testGate{}
		s := jobs.New(slog.New(slog.DiscardHandler), g, nil)
		if err := s.Add(j); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		go s.Run(ctx)
		synctest.Wait()
		if runs.Load() != 0 {
			t.Fatal("the job ran while the module was off")
		}
		g.set(true)
		s.ModuleChanged("findings", true)
		synctest.Wait()
		if runs.Load() != 1 {
			t.Fatalf("runs after the module came on = %d, want 1 (at once)", runs.Load())
		}
		time.Sleep(time.Hour)
		synctest.Wait()
		if runs.Load() != 2 {
			t.Fatalf("runs after an hour = %d, want 2", runs.Load())
		}
		g.set(false)
		s.ModuleChanged("findings", false)
		time.Sleep(3 * time.Hour)
		synctest.Wait()
		if runs.Load() != 2 {
			t.Fatalf("the job ran %d times, it must not run while the module is off", runs.Load())
		}
		cancel()
		synctest.Wait()
	})
}
