package scan

import (
	"testing"
	"time"
)

// W3-6 (W2-4): a box whose schedule never ran shows, and runs, its first scheduled run in the next window of any window day, not on
// the weekly weekday. Customer walk: Friday 13 Nov 14:40 with the default weekly Sunday 23:00 and 22:00-05:00 every day showed
// "15 Nov 2026, 23:00"; tonight's window is allowed, so the first run is tonight. From the second run on the weekday counts again.
// The clock is the env's fake clock: no real time passes.
func TestSchedule_FirstRunIsTheNextWindowNotTheWeekday(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	p := Patch{Days: []int{1, 2, 3, 4, 5, 6, 7}, From: ptr("22:00"), To: ptr("05:00"), SchedEnabled: ptr(true), SchedFrequency: ptr("weekly"), SchedWeekday: ptr(7), SchedAt: ptr("23:00")}
	if _, err := r.svc.SaveConfig(r.ctx(), "admin@acme.example", p); err != nil {
		t.Fatal(err)
	}
	fri13 := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	r.setNow(hm(fri13, 14, 40))
	if got := r.nextRun(); got != "2026-11-13T23:00:00.000Z" {
		t.Fatalf("next run on Friday 14:40 of a box that never ran a schedule: %s, want tonight 23:00", got)
	}
	r.schedAt(hm(fri13, 14, 40)) // Thursday's slot has closed: it was never due, so it is not recorded and the first run stays tonight
	if r.count(`SELECT count(*) FROM scan_setting WHERE sched_last IS NOT NULL`) != 0 || r.count(`SELECT count(*) FROM core_audit WHERE action = 'scan.schedule.missed'`) != 0 {
		t.Fatalf("a slot before the first run was recorded: %v", r.audits())
	}
	r.schedAt(hm(fri13, 23, 0).Add(30 * time.Second))
	if n := r.scheduled(); n != 1 {
		t.Fatalf("Friday 23:00: %d scheduled runs, want the first one", n)
	}
	r.setNow(hm(fri13, 23, 30))
	if got := r.nextRun(); got != "2026-11-15T23:00:00.000Z" {
		t.Fatalf("next run after the first one: %s, want the weekly Sunday 23:00", got)
	}
	r.schedAt(hm(fri13.AddDate(0, 0, 1), 23, 0).Add(30 * time.Second)) // Saturday: not the weekday any more
	if n := r.scheduled(); n != 1 {
		t.Fatalf("Saturday 23:00: %d scheduled runs, want still 1", n)
	}
}

// The window still decides: a first run waits for the next window day, and outside the window days nothing is shown earlier.
func TestNextRun_FirstWaitsForAWindowDay(t *testing.T) {
	t.Parallel()
	c := Settings{Window: Window{Days: []int{1, 2, 3, 4, 5}, From: "22:00", To: "05:00"}, Schedule: Schedule{Enabled: true, Frequency: "weekly", Weekday: 3, At: "23:00"}}
	sat := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC) // Saturday: not a window day
	if got := c.NextRun(sat, time.UTC, true); got == nil || !got.Equal(time.Date(2026, 11, 16, 23, 0, 0, 0, time.UTC)) {
		t.Fatalf("first run from Saturday: %v, want Monday 23:00", got)
	}
	if got := c.NextRun(sat, time.UTC, false); got == nil || !got.Equal(time.Date(2026, 11, 18, 23, 0, 0, 0, time.UTC)) {
		t.Fatalf("a later run from Saturday: %v, want Wednesday 23:00", got)
	}
}
