package scan

import (
	"testing"
	"time"
)

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
	if n := r.count(`SELECT count(*) FROM core_run`); n != 0 {
		t.Fatalf("%d rescan runs although the event could not be linked to one", n)
	}
}
