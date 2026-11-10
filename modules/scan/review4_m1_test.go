package scan

import "testing"

// #164 review M1: a window that crosses midnight counts by its start day (the GUI's words), so a slot after midnight
// belongs to the window of the day before. With Monday to Friday, 22:00 to 05:00 and a daily 02:00 run: Monday 02:00 is
// Sunday's window (no run, and not 20 hours late at Monday 22:00), Tuesday 02:00 is Monday's, Saturday 02:00 is
// Friday's. next_run says the same.
func TestReview4_M1_ACrossMidnightWindowCountsByItsStartDay(t *testing.T) {
	t.Parallel()
	r := schedEnv(t)
	r.schedAt(hm(mon16, 2, 30))  // Sunday's window: Sunday is not a window day
	r.schedAt(hm(mon16, 22, 30)) // Monday's window is open, but its slot is Tuesday 02:00
	if n := r.scheduled(); n != 0 {
		t.Fatalf("Monday: %d scheduled runs, want 0 (Monday 02:00 belongs to Sunday's window)", n)
	}
	r.schedAt(hm(tue17, 2, 30))
	r.schedAt(hm(tue17, 3, 0)) // the same slot again
	if n := r.scheduled(); n != 1 {
		t.Fatalf("Tuesday 02:00 (Monday's window): %d runs, want 1", n)
	}
	r.schedAt(hm(fri20, 2, 30)) // Thursday's window
	r.schedAt(hm(sat21, 2, 30)) // Friday's window
	if n := r.scheduled(); n != 3 {
		t.Fatalf("Friday's window: %d runs in all, want 3", n)
	}
	r.setNow(hm(fri20, 12, 0))
	if got := r.nextRun(); got != "2026-11-21T02:00:00.000Z" {
		t.Errorf("next run on Friday noon: %s, want Saturday 02:00 (Friday's window)", got)
	}
	r.setNow(hm(sun22, 12, 0))
	if got := r.nextRun(); got != "2026-11-24T02:00:00.000Z" {
		t.Errorf("next run on Sunday noon: %s, want Tuesday 02:00 (Monday 02:00 is in Sunday's window)", got)
	}
}

// M1: a slot runs only while its own window is open. One that could not start in time (here the scanner was down) is
// recorded as missed when its window closes, not run late in the next window.
func TestReview4_M1_AMissedSlotIsNotRunLate(t *testing.T) {
	t.Parallel()
	r := schedEnv(t)
	r.eng.setDown(errNoHeartbeat)
	r.schedAt(hm(wed18, 2, 30)) // Tuesday's window, the scanner is down
	r.eng.setDown(nil)
	r.schedAt(hm(wed18, 6, 0))   // that window has closed
	r.schedAt(hm(wed18, 22, 30)) // Wednesday's window: its slot is Thursday 02:00
	if n := r.scheduled(); n != 0 {
		t.Fatalf("%d scheduled runs: the missed Wednesday 02:00 slot ran late", n)
	}
	if r.count(`SELECT count(*) FROM scan_setting WHERE sched_last = '2026-11-18T02:00:00.000Z'`) != 1 ||
		r.count(`SELECT count(*) FROM core_audit WHERE action = 'scan.schedule.missed'`) != 1 {
		t.Fatalf("the missed slot is not recorded: %v", r.audits())
	}
	r.schedAt(hm(thu19, 2, 30))
	if n := r.scheduled(); n != 1 {
		t.Fatalf("Thursday 02:00: %d runs, want 1", n)
	}
}
