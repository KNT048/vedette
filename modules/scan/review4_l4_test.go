package scan

import (
	"testing"
	"time"
)

// L4: the slot is recorded in the transaction that inserts its run, so a failure between the two cannot give one slot
// a run and leave the slot open for a second one.
func TestReview4_L4_TheSlotAndItsRunCommitTogether(t *testing.T) {
	t.Parallel()
	r := schedEnv(t)
	r.exec(`CREATE TRIGGER test_no_slot BEFORE UPDATE OF sched_last ON scan_setting BEGIN SELECT RAISE(ABORT, 'test: the slot cannot be written'); END`)
	r.setNow(hm(tue17, 2, 30))
	err := r.svc.RunSchedule(r.ctx())
	r.wait()
	if n := r.scheduled(); err == nil || n != 0 {
		t.Fatalf("a run started although its slot could not be recorded: error %v, %d runs", err, n)
	}
}

// L4: a start refused because the engine is still busy (review M2 of S3) does not use up the slot; the run starts at
// a later tick while the window is open.
func TestReview4_L4_ARefusedStartKeepsTheSlot(t *testing.T) {
	t.Parallel()
	r := schedEnv(t)
	started := r.eng.blockRuns()
	release := make(chan struct{})
	r.eng.mu.Lock()
	r.eng.stubborn = release
	r.eng.mu.Unlock()
	v := r.start("a-web01")
	<-started
	if _, err := r.svc.StopRun(r.ctx(), "it@acme.example", v.ID); err != nil {
		t.Fatal(err)
	}
	r.wait()
	r.schedAt(hm(tue17, 2, 30)) // the engine is still busy: the start is refused
	if r.count(`SELECT count(*) FROM scan_setting WHERE sched_last IS NOT NULL`) != 0 {
		t.Fatal("the slot was used up by a start that was refused")
	}
	r.eng.mu.Lock()
	r.eng.stubborn, r.eng.blocked = nil, false
	r.eng.mu.Unlock()
	close(release)
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for r.svc.busy.Load() != 0 {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("the engine did not return")
		}
	}
	r.schedAt(hm(tue17, 2, 40))
	if n := r.scheduled(); n != 1 {
		t.Fatalf("%d scheduled runs after the engine returned, want 1", n)
	}
}

// L4: the rescan run and the event's link to it commit together: a failure leaves no run that the event does not
// know about (which the next pass would start again).
func TestReview4_L4_TheEventAndItsRunCommitTogether(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.exec(`CREATE TRIGGER test_no_link BEFORE UPDATE OF run_id ON scan_event BEGIN SELECT RAISE(ABORT, 'test: the event cannot be linked'); END`)
	if err := r.svc.OnNewKEV(r.ctx(), kev("CVE-2024-3400")); err != nil {
		t.Fatal(err)
	}
	r.advance(2 * time.Minute)
	_ = r.svc.RunRescans(r.ctx())
	r.wait()
	if n := r.count(`SELECT count(*) FROM scan_run`); n != 0 {
		t.Fatalf("%d rescan runs although the event could not be linked to one", n)
	}
}
