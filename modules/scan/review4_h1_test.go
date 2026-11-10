package scan

import (
	"context"
	"testing"
	"time"
)

// #164 review H1: the window, the slot and next_run are read in the organization's time zone, never the process's.
// The cmd/vedette test TestScanReadsTheOrgTimeZone shows the wiring; this one shows the module uses the zone it is given.
func TestReview4_H1_TheScheduleIsInTheOrgZone(t *testing.T) {
	t.Parallel()
	r := schedEnv(t) // Monday to Friday, 22:00 to 05:00, daily at 02:00
	ict := time.FixedZone("ICT", 7*3600)
	cfg := r.svc.cfg
	cfg.Location = func(context.Context) *time.Location { return ict }
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.svc = svc
	r.schedAt(hm(tue17, -5, 30)) // Monday 19:30 UTC is Tuesday 02:30 in the office: Monday's window
	if n := r.scheduled(); n != 1 {
		t.Fatalf("Tuesday 02:30 in the office: %d runs, want 1", n)
	}
	r.schedAt(hm(tue17, 2, 30)) // Tuesday 02:30 UTC is 09:30 in the office: working hours
	if n := r.scheduled(); n != 1 {
		t.Fatalf("09:30 in the office: %d runs, want still 1", n)
	}
	r.setNow(hm(tue17, 12, 0)) // 19:00 in the office
	if got := r.nextRun(); got != "2026-11-17T19:00:00.000Z" {
		t.Errorf("next run %s, want Wednesday 02:00 in the office (19:00 UTC)", got)
	}
	// nil zone (or a nil answer): UTC, not the machine's zone
	cfg.Location = func(context.Context) *time.Location { return nil }
	if svc, err = NewService(cfg); err != nil || svc.loc(t.Context()) != time.UTC {
		t.Fatalf("a nil zone: %v %v", svc.loc(t.Context()), err)
	}
}
