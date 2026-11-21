package scan

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// zoneEnv is a run environment with an organization zone that can be unreadable (nil: the read failed, timed out, or the name
// is not a zone).
func zoneEnv(t *testing.T) (*runEnv, *atomic.Bool) {
	t.Helper()
	r := newRunEnv(t)
	broken := &atomic.Bool{}
	cfg := r.svc.cfg
	cfg.Location = func(context.Context) *time.Location {
		if broken.Load() {
			return nil
		}
		return time.UTC
	}
	svc, err := r.rebuild(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.svc = svc
	return r, broken
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
	if n := r.count(`SELECT count(*) FROM core_run`); n != 0 {
		t.Fatalf("%d rescan runs while the organization zone is unknown", n)
	}
	if r.count(`SELECT count(*) FROM scan_event WHERE result IS NULL AND run_id IS NULL`) != 1 {
		t.Fatal("the event did not wait for the zone")
	}
	broken.Store(false)
	r.tick()
	if n := r.count(`SELECT count(*) FROM core_run WHERE trigger = 'event'`); n != 1 {
		t.Fatalf("%d rescan runs once the zone is back, want 1", n)
	}
}

// A zone that stays unreadable for 7 days closes the event as expired_zone, visible in the rescan log.
func TestReview4_ZoneUnknownFor7DaysShowsTheEventAsExpired(t *testing.T) {
	t.Parallel()
	r, broken := zoneEnv(t)
	broken.Store(true)
	if err := r.svc.OnNewKEV(r.ctx(), kev("CVE-2024-3400")); err != nil {
		t.Fatal(err)
	}
	r.advance(8 * 24 * time.Hour)
	r.tick()
	if r.count(`SELECT count(*) FROM scan_event WHERE result = 'expired_zone'`) != 1 || r.count(`SELECT count(*) FROM core_run`) != 0 {
		t.Fatal("the event was not closed as expired_zone, or a run started")
	}
}
