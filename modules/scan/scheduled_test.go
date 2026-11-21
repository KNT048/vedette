package scan

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/schedule"
)

// schedEnv is a run environment with the box's schedule service on the test clock, the vulnerability checks registered on it, and
// the shared scan window of the inventory (every day 22:00 to 05:00) as its scan window.
func schedEnv(t *testing.T) (*runEnv, *schedule.Service) {
	t.Helper()
	r := newRunEnv(t)
	r.exec(`INSERT INTO core_org (id, name, timezone, install_id) VALUES (1, 'Acme', 'UTC', 'install-1') ON CONFLICT (id) DO UPDATE SET timezone = 'UTC'`) // the schedules and the window are read in the organization's zone
	sched, err := schedule.New(schedule.Config{DB: r.db, Clock: r.clock.Now, ScanWindow: func(ctx context.Context) (schedule.Window, error) {
		c, err := r.inv.Checks(ctx)
		return schedule.Window{Days: c.Window.Days, From: c.Window.From, To: c.Window.To}, err
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sched.Register(r.svc.ScheduleOwner()); err != nil {
		t.Fatal(err)
	}
	return r, sched
}

// save puts the checks on a daily rule at 23:00 in the scan window.
func save(t *testing.T, r *runEnv, sched *schedule.Service) {
	t.Helper()
	if _, err := sched.Save(r.ctx(), ScheduleKey, schedule.Setting{Enabled: true, Rule: schedule.DailyAt("23:00").InWindow()}, "admin@acme.example"); err != nil {
		t.Fatal(err)
	}
}

func (r *runEnv) scheduled() int {
	r.t.Helper()
	return r.count(`SELECT count(*) FROM core_run WHERE trigger = 'schedule'`)
}

func tick(t *testing.T, r *runEnv, sched *schedule.Service, at time.Time) {
	t.Helper()
	r.setNow(at)
	if _, err := sched.Tick(r.ctx()); err != nil {
		t.Fatal(err)
	}
	r.wait()
}

func skipReason(t *testing.T, r *runEnv, sched *schedule.Service) string {
	t.Helper()
	v, err := sched.Get(r.ctx(), ScheduleKey)
	if err != nil {
		t.Fatal(err)
	}
	if v.LastSkipReason == nil {
		return ""
	}
	return *v.LastSkipReason
}

// S-SCAN-4: a due check starts one run over the devices that may be scanned without a pick, inside the scan window, once per due
// time; the run says which schedule started it.
func TestScheduled_OneRunPerDueTimeOverTheDevicesThatNeedNoPick(t *testing.T) {
	t.Parallel()
	r, sched := schedEnv(t)
	save(t, r, sched) // 10:00 UTC today (t0): the next due time is tonight
	tick(t, r, sched, r.clock.Now())
	if n := r.count(`SELECT count(*) FROM core_run`); n != 0 {
		t.Fatalf("%d runs before the due time", n)
	}
	r.setNow(r.clock.Now().Add(13*time.Hour + 30*time.Second)) // 23:00:30
	tick(t, r, sched, r.clock.Now())
	runs, _ := r.svc.Runs(r.ctx())
	if len(runs) != 1 || runs[0].Trigger != "schedule" || runs[0].StartedBy != "system" || runs[0].Total != 2 {
		t.Fatalf("runs: %+v", runs) // a-web01 and a-srv: not the fragile NAS, the box, "never", unapproved or out of scope
	}
	if n := r.count(`SELECT count(*) FROM core_run WHERE schedule_id IS NOT NULL`); n != 1 {
		t.Fatalf("%d runs name their schedule", n)
	}
	tick(t, r, sched, r.clock.Now().Add(time.Minute))
	if n := r.count(`SELECT count(*) FROM core_run`); n != 1 {
		t.Fatalf("one due time started %d runs", n)
	}
}

// The run stops by itself when the window it was held for closes, and says why.
func TestScheduled_StopsWhenTheWindowEnds(t *testing.T) {
	t.Parallel()
	r, sched := schedEnv(t)
	r.inv.checks.Window.To = "23:01"
	save(t, r, sched)
	r.eng.blockRuns()
	tick(t, r, sched, r.clock.Now().Add(13*time.Hour+59*time.Second+800*time.Millisecond)) // 23:00:59.8: the window closes 200 ms later
	runs, _ := r.svc.Runs(r.ctx())
	if len(runs) != 1 || runs[0].Status != "auto_stopped" || *runs[0].StopReason != noteWindowEnded {
		t.Fatalf("%+v", runs)
	}
}

// The checks' window is always the scan window (the Safety tab's promise); the editor says so. A person's run once now has no end of
// its own.
func TestScheduled_TheWindowIsAlwaysTheScanWindow(t *testing.T) {
	t.Parallel()
	r, sched := schedEnv(t)
	_, err := sched.Save(r.ctx(), ScheduleKey, schedule.Setting{Enabled: true, Rule: schedule.DailyAt("12:00")}, "admin@acme.example")
	var re *schedule.RuleError
	if !errors.As(err, &re) || re.Field != "window" || !strings.Contains(re.Message, "only inside the scan window") {
		t.Fatalf("a rule without the scan window: %v", err)
	}
	v, err := sched.Get(r.ctx(), ScheduleKey)
	if err != nil || len(v.Limits.Windows) != 1 || v.Limits.Windows[0] != schedule.WindowGlobal || v.Limits.Reason == "" {
		t.Fatalf("limits %+v %v", v.Limits, err)
	}
	if _, err := sched.RunNow(r.ctx(), ScheduleKey, "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	r.wait()
	if n := r.count(`SELECT count(*) FROM core_run WHERE trigger = 'manual' AND requested_by = 'it@acme.example'`); n != 1 {
		t.Fatalf("run once now: %d manual runs", n)
	}
}

// A new box is checked in its first open scan window, not on the weekly default: the first due time is the window's next opening,
// and the editor's preview says so.
func TestScheduled_TheFirstCheckOfANewBoxIsTheNextOpenWindow(t *testing.T) {
	t.Parallel()
	r, sched := schedEnv(t)
	if err := sched.Start(r.ctx()); err != nil { // saves the default: Sunday 23:00 in the window
		t.Fatal(err)
	}
	t.Cleanup(sched.Close)
	v, err := sched.Get(r.ctx(), ScheduleKey)
	if err != nil || len(v.Upcoming) == 0 {
		t.Fatalf("%+v %v", v, err)
	}
	now := r.clock.Now() // Tuesday 10:00 UTC; the window opens at 22:00
	if want := time.Date(now.Year(), now.Month(), now.Day(), 22, 0, 0, 0, time.UTC); !v.Upcoming[0].Equal(want) {
		t.Fatalf("first start %v, want tonight's opening %v (not Sunday 23:00)", v.Upcoming[0], want)
	}
	if v.Upcoming[1].Weekday() != time.Sunday { // afterwards the weekly rule
		t.Fatalf("second start %v", v.Upcoming[1])
	}
	tick(t, r, sched, now.Add(12*time.Hour+time.Minute)) // 22:01: the window is open
	if r.scheduled() != 1 {
		t.Fatalf("%d scheduled runs in the first window", r.scheduled())
	}
}

// A refusal that passes (a check is running, the scanner is not ready) does not use up the due time: the check starts as soon as it
// can, in the same window.
func TestScheduled_ARefusalThatPassesHoldsTheDueTime(t *testing.T) {
	t.Parallel()
	r, sched := schedEnv(t)
	save(t, r, sched)
	due := r.clock.Now().Add(13*time.Hour + 30*time.Second)
	r.eng.setDown(errors.New("restarting"))
	tick(t, r, sched, due)
	if got := skipReason(t, r, sched); got != msgScannerDown || r.scheduled() != 0 {
		t.Fatalf("scanner down: %q, %d runs", got, r.scheduled())
	}
	r.eng.setDown(nil)
	tick(t, r, sched, due.Add(time.Minute))
	if r.scheduled() != 1 {
		t.Fatalf("the check did not start once it could: %d runs", r.scheduled())
	}
	v, _ := sched.Get(r.ctx(), ScheduleKey)
	if v.LastSkipReason != nil || v.LastDueAt == nil {
		t.Fatalf("%+v", v)
	}
}

// A due time that cannot start says why, and the next one starts as planned.
func TestScheduled_ASkippedDueTimeSaysWhy(t *testing.T) {
	t.Parallel()
	r, sched := schedEnv(t)
	save(t, r, sched)
	due := r.clock.Now().Add(13*time.Hour + 30*time.Second)

	r.inv.mu.Lock()
	r.inv.scope = Scope{}
	r.inv.mu.Unlock()
	tick(t, r, sched, due)
	if got := skipReason(t, r, sched); got != msgNoCommitment || r.scheduled() != 0 {
		t.Fatalf("no commitment: %q, %d runs", got, r.scheduled())
	}

	r.inv.mu.Lock()
	r.inv.scope = confirmedScope()
	r.inv.mu.Unlock()
	r.eng.setDown(errors.New("no scanner"))
	tick(t, r, sched, due.Add(24*time.Hour))
	if got := skipReason(t, r, sched); got != msgScannerDown || r.scheduled() != 0 {
		t.Fatalf("scanner down: %q, %d runs", got, r.scheduled())
	}

	r.eng.setDown(nil)
	r.inv.setPolicy(func(string, bool) Decision { return Decision{Reason: reasonNever} })
	tick(t, r, sched, due.Add(48*time.Hour))
	if got := skipReason(t, r, sched); !strings.Contains(got, "without someone picking") || r.scheduled() != 0 {
		t.Fatalf("nothing to check: %q, %d runs", got, r.scheduled())
	}

	r.inv.setPolicy(samplePolicy)
	tick(t, r, sched, due.Add(72*time.Hour))
	if r.scheduled() != 1 || skipReason(t, r, sched) != "" {
		t.Fatalf("the next due time did not start: %d runs, skip %q", r.scheduled(), skipReason(t, r, sched))
	}
}

// The organization's zone decides the window: a zone nobody can read holds the check, with the reason.
func TestScheduled_AZoneNobodyCanReadHoldsTheCheck(t *testing.T) {
	t.Parallel()
	r, sched := schedEnv(t)
	cfg := r.svc.cfg
	cfg.Location = func(context.Context) *time.Location { return nil }
	svc, err := r.rebuild(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.svc = svc
	// the owner of the new service takes the place of the old one
	sched2, err := schedule.New(schedule.Config{DB: r.db, Clock: r.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := sched2.Register(svc.ScheduleOwner()); err != nil {
		t.Fatal(err)
	}
	save(t, r, sched2)
	tick(t, r, sched2, r.clock.Now().Add(13*time.Hour+30*time.Second))
	if got := skipReason(t, r, sched2); !strings.Contains(got, "time zone") || r.scheduled() != 0 {
		t.Fatalf("%q, %d runs", got, r.scheduled())
	}
	_ = sched
}

// A check that a person's Scan now holds the lane for is not started a second time.
func TestScheduled_ARunningCheckSkipsTheDueTime(t *testing.T) {
	t.Parallel()
	r, sched := schedEnv(t)
	save(t, r, sched)
	started := r.eng.blockRuns()
	v := r.start("a-web01")
	<-started
	r.setNow(r.clock.Now().Add(13*time.Hour + 30*time.Second))
	if _, err := sched.Tick(r.ctx()); err != nil { // no wait: the person's run is still going
		t.Fatal(err)
	}
	got := skipReason(t, r, sched)
	if !strings.Contains(got, "already running") && !strings.Contains(got, "had not ended") {
		t.Fatalf("skip reason %q", got)
	}
	if _, err := r.svc.StopRun(r.ctx(), "it@acme.example", v.ID); err != nil {
		t.Fatal(err)
	}
	r.wait()
}
