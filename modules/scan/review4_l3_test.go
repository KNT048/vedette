package scan

import (
	"testing"
	"time"
)

// L3: an event whose scanner never becomes ready does not wait for ever: after the same 7 days as an event whose
// template never came, it is dropped.
func TestReview4_L3_AnEventDoesNotWaitForEverForTheScanner(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.eng.setDown(errNoHeartbeat)
	if err := r.svc.OnNewKEV(r.ctx(), kev("CVE-2024-3400")); err != nil {
		t.Fatal(err)
	}
	r.advance(2 * time.Minute)
	r.tick()
	if r.count(`SELECT count(*) FROM scan_event WHERE result IS NULL`) != 1 {
		t.Fatal("the event did not wait for the scanner")
	}
	r.advance(8 * 24 * time.Hour)
	r.tick()
	if n := r.count(`SELECT count(*) FROM scan_event`); n != 0 {
		t.Fatalf("%d events still waiting for a scanner that never came", n)
	}
}
