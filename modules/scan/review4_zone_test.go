package scan

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// zoneEnv is schedEnv with an organization zone that can be unreadable (nil: the read failed, timed out, or the name
// is not a zone).
func zoneEnv(t *testing.T) (*runEnv, *atomic.Bool) {
	t.Helper()
	r := schedEnv(t)
	broken := &atomic.Bool{}
	cfg := r.svc.cfg
	cfg.Location = func(context.Context) *time.Location {
		if broken.Load() {
			return nil
		}
		return time.UTC
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.svc = svc
	return r, broken
}

// #164 review, after H1: when the organization zone cannot be read, the schedule fails closed. The tick is skipped
// (no run at what may be the wrong hour), next_run is not shown, and the slot runs once the zone is back while its
// window is open.
func TestReview4_ZoneUnknownSkipsTheSchedule(t *testing.T) {
	t.Parallel()
	r, broken := zoneEnv(t)
	broken.Store(true)
	r.schedAt(hm(tue17, 2, 30))
	if n := r.scheduled(); n != 0 {
		t.Fatalf("%d scheduled runs while the organization zone is unknown", n)
	}
	if got := r.nextRun(); got != "<nil>" {
		t.Errorf("next_run %s while the zone is unknown", got)
	}
	if r.count(`SELECT count(*) FROM scan_setting WHERE sched_last IS NOT NULL`) != 0 {
		t.Fatal("the slot was used up while the zone was unknown")
	}
	broken.Store(false)
	r.schedAt(hm(tue17, 2, 40))
	if n := r.scheduled(); n != 1 {
		t.Fatalf("%d scheduled runs once the zone is back, want 1", n)
	}
}

// The KEV rescan follows the same rule: no automated run starts while the zone is unknown; the event waits.
func TestReview4_ZoneUnknownHoldsTheKEVRescan(t *testing.T) {
	t.Parallel()
	r, broken := zoneEnv(t)
	broken.Store(true)
	if err := r.svc.OnNewKEV(r.ctx(), kev("CVE-2024-3400")); err != nil {
		t.Fatal(err)
	}
	r.advance(2 * time.Minute)
	r.tick()
	if n := r.count(`SELECT count(*) FROM scan_run`); n != 0 {
		t.Fatalf("%d rescan runs while the organization zone is unknown", n)
	}
	if r.count(`SELECT count(*) FROM scan_event WHERE result IS NULL AND run_id IS NULL`) != 1 {
		t.Fatal("the event did not wait for the zone")
	}
	broken.Store(false)
	r.tick()
	if n := r.count(`SELECT count(*) FROM scan_run WHERE trigger = 'new_kev'`); n != 1 {
		t.Fatalf("%d rescan runs once the zone is back, want 1", n)
	}
}
