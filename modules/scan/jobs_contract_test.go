package scan

import (
	"context"
	"database/sql"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/jobs"
)

func (r *runEnv) advance(d time.Duration) {
	r.clock.mu.Lock()
	r.clock.now = r.clock.now.Add(d)
	r.clock.mu.Unlock()
}

func (r *runEnv) tick() {
	r.t.Helper()
	if err := r.svc.RunRescans(r.ctx()); err != nil {
		r.t.Fatal(err)
	}
	r.wait()
}

func (r *runEnv) events() []EventView {
	r.t.Helper()
	evs, _, err := r.svc.Events(r.ctx())
	if err != nil {
		r.t.Fatal(err)
	}
	return evs
}

func kev(cve string) NewKEV {
	return NewKEV{CVE: cve, Vendor: "Palo Alto Networks", Product: "PAN-OS", HasTemplate: true}
}

// INV-9, PRE-4, POST-4: a new KEV entry with a template rescans exactly the devices with an open finding for it,
// with only that CVE's templates, within 60 minutes, outside the time window (D-126 (3)), and the log says how it went.
func TestContract_INV9_RescanAfterANewKEV(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t) // t0 is 10:00 UTC, outside the default 22:00-05:00 window
	r.eng.reply = lines("CVE-2024-3400")
	if err := r.svc.OnNewKEV(r.ctx(), kev("CVE-2024-3400")); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.OnNewKEV(r.ctx(), kev("CVE-2024-3400")); err != nil { // the same entry twice is one event
		t.Fatal(err)
	}
	r.tick() // too early: the inventory and findings match the new entry first
	if len(r.eng.sent()) != 0 || len(r.events()) != 0 {
		t.Fatal("rescanned before the findings settled, or listed a pending event")
	}
	r.advance(2 * time.Minute)
	r.tick()
	jobs := r.eng.sent()
	if len(jobs) != 1 || jobs[0].Targets[0].Host != "192.168.10.12" || !slices.Equal(jobs[0].Templates, []string{"http/cves/2024/CVE-2024-3400.yaml"}) {
		t.Fatalf("jobs: %+v", jobs) // a-web01 only, and not its other CVE
	}
	r.tick() // the run is over: the event is closed
	evs := r.events()
	if len(evs) != 1 || evs[0].Result != "matched" || evs[0].CVE != "CVE-2024-3400" || evs[0].Product != "Palo Alto Networks PAN-OS" ||
		!slices.Equal(evs[0].Devices, []string{"WEB01"}) || evs[0].LatencyMin == nil || *evs[0].LatencyMin > 60 || evs[0].RunID == nil {
		t.Fatalf("event: %+v", evs)
	}
	run := r.run(*evs[0].RunID)
	if run.Trigger != "new_kev" || run.TriggerNote == nil || *run.TriggerNote != "New KEV entry with a scan template: CVE-2024-3400" || run.StartedBy != "system" {
		t.Fatalf("run: %+v", run)
	}
	if !slices.ContainsFunc(r.inv.calls, func(c policyCall) bool { return c.id == "a-web01" && !c.explicit }) {
		t.Fatal("an automatic rescan must ask the policy without a pick")
	}
}

// INV-9: auto rescan off → skipped_off and no scan; no device that may be scanned without a pick → no_match (a fragile
// device is never touched by an automatic run, D-126 (2)); no template in the installed pack → it waits, then is dropped.
func TestContract_INV9_SkippedOffNoMatchAndPack(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	for _, c := range []string{"CVE-2022-27593", "CVE-2023-46805", "CVE-2021-44228"} {
		if err := r.svc.OnNewKEV(r.ctx(), kev(c)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.svc.OnNewKEV(r.ctx(), NewKEV{CVE: "CVE-2020-0001", HasTemplate: false}); err != nil {
		t.Fatal(err)
	}
	r.advance(2 * time.Minute)
	r.tick()
	got := map[string]string{}
	for _, e := range r.events() {
		got[e.CVE] = e.Result
	}
	// 27593 is only on the fragile NAS: a hand pick only (D-145 (7)); 46805 is on no device; 44228 has no template in
	// the pack: still waiting
	if len(got) != 2 || got["CVE-2022-27593"] != "pick_only" || got["CVE-2023-46805"] != "no_match" || len(r.eng.sent()) != 0 {
		t.Fatalf("events: %v, jobs %d", got, len(r.eng.sent()))
	}
	for _, e := range r.events() {
		if e.CVE == "CVE-2022-27593" && !slices.Equal(e.Devices, []string{"NAS-PHOTOS"}) {
			t.Fatalf("pick_only names the devices that need the pick: %v", e.Devices)
		}
	}
	if r.count(`SELECT count(*) FROM scan_event WHERE cve = 'CVE-2020-0001'`) != 0 || r.count(`SELECT count(*) FROM scan_event WHERE cve = 'CVE-2021-44228' AND result IS NULL`) != 1 {
		t.Fatal("an entry without a template was queued, or the one without a pack template was closed")
	}
	r.advance(8 * 24 * time.Hour)
	r.tick()
	if r.count(`SELECT count(*) FROM scan_event WHERE cve = 'CVE-2021-44228' AND result IS NULL`) != 0 {
		t.Fatal("an event whose template never came waits forever")
	}
	// D-261 (2): it stays in the rescan log, with the reason as its result
	var seen *EventView
	for _, e := range r.events() {
		if e.CVE == "CVE-2021-44228" {
			seen = &e
		}
	}
	if seen == nil || seen.Result != "expired_no_template" || len(seen.Devices) != 0 || seen.RunID != nil {
		t.Fatalf("a dropped event is not visible with its reason: %+v", seen)
	}
	if _, err := r.svc.SaveConfig(r.ctx(), "admin@acme.example", Patch{AutoRescan: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.OnNewKEV(r.ctx(), kev("CVE-2024-3400")); err != nil {
		t.Fatal(err)
	}
	r.advance(2 * time.Minute)
	r.tick()
	evs, auto, _ := r.svc.Events(r.ctx())
	if auto || evs[0].CVE != "CVE-2024-3400" || evs[0].Result != "skipped_off" || len(r.eng.sent()) != 0 {
		t.Fatalf("off: %v %+v", auto, evs)
	}
}

// INV-9: a rescan that finds a scan running waits for it, still inside the hour.
func TestContract_INV9_WaitsForTheRunningScan(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	started := r.eng.blockRuns()
	v := r.start("a-nas02")
	<-started
	if err := r.svc.OnNewKEV(r.ctx(), kev("CVE-2024-3400")); err != nil {
		t.Fatal(err)
	}
	r.advance(2 * time.Minute)
	if err := r.svc.RunRescans(r.ctx()); err != nil {
		t.Fatal(err)
	}
	if r.count(`SELECT count(*) FROM scan_event WHERE run_id IS NULL AND result IS NULL`) != 1 {
		t.Fatal("the rescan did not wait")
	}
	if _, err := r.svc.StopRun(r.ctx(), "it@acme.example", v.ID); err != nil {
		t.Fatal(err)
	}
	r.wait()
	r.eng.mu.Lock()
	r.eng.blocked, r.eng.reply = false, lines()
	r.eng.mu.Unlock()
	r.advance(time.Minute)
	r.tick()
	r.tick()
	if evs := r.events(); len(evs) != 1 || evs[0].Result != "clear" || *evs[0].LatencyMin != 3 {
		t.Fatalf("%+v", evs)
	}
}

// INV-9, D-145 (7): a rescan run stopped before every device was done is "stopped", never "clear" (which would hide
// the devices that were not checked).
func TestContract_INV9_AStoppedRescanSaysSo(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	started := r.eng.blockRuns()
	if err := r.svc.OnNewKEV(r.ctx(), kev("CVE-2024-3400")); err != nil {
		t.Fatal(err)
	}
	r.advance(2 * time.Minute)
	if err := r.svc.RunRescans(r.ctx()); err != nil {
		t.Fatal(err)
	}
	<-started
	var runID string
	if err := r.db.Reader().QueryRowContext(r.ctx(), `SELECT run_id FROM scan_event`).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.StopRun(r.ctx(), "it@acme.example", runID); err != nil {
		t.Fatal(err)
	}
	r.wait()
	r.tick()
	if evs := r.events(); len(evs) != 1 || evs[0].Result != "stopped" || evs[0].RunID == nil || *evs[0].RunID != runID {
		t.Fatalf("%+v", evs)
	}
}

// POST-3, S-SCAN-4: the scheduled run starts once per slot, only inside the window, only with devices that may be
// scanned without a pick, and stops when the window ends.
func TestContract_POST3_ScheduleInsideTheWindow(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	if _, err := r.svc.SaveConfig(r.ctx(), "admin@acme.example", Patch{SchedFrequency: ptr("daily")}); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.RunSchedule(r.ctx()); err != nil { // 10:00 UTC: yesterday's 23:00 slot, but the window is closed
		t.Fatal(err)
	}
	if r.count(`SELECT count(*) FROM scan_run`) != 0 {
		t.Fatal("a scheduled run outside the window")
	}
	r.advance(13*time.Hour + 30*time.Second) // 23:00:30, inside 22:00-05:00
	if err := r.svc.RunSchedule(r.ctx()); err != nil {
		t.Fatal(err)
	}
	r.wait()
	runs, _ := r.svc.Runs(r.ctx())
	if len(runs) != 1 || runs[0].Trigger != "schedule" || runs[0].StartedBy != "system" || runs[0].Total != 2 {
		t.Fatalf("runs: %+v", runs) // a-web01 and a-srv: not the fragile NAS, the box, "never", unapproved or out of scope
	}
	if err := r.svc.RunSchedule(r.ctx()); err != nil {
		t.Fatal(err)
	}
	if r.count(`SELECT count(*) FROM scan_run`) != 1 {
		t.Fatal("one slot started two runs")
	}
}

func TestSchedule_StopsWhenTheWindowEnds(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	if _, err := r.svc.SaveConfig(r.ctx(), "admin@acme.example", Patch{SchedFrequency: ptr("daily"), To: ptr("23:01")}); err != nil {
		t.Fatal(err)
	}
	r.advance(13*time.Hour + 59*time.Second + 800*time.Millisecond) // 23:00:59.8: the window closes 200 ms later
	r.eng.blockRuns()
	if err := r.svc.RunSchedule(r.ctx()); err != nil {
		t.Fatal(err)
	}
	r.wait()
	runs, _ := r.svc.Runs(r.ctx())
	if len(runs) != 1 || runs[0].Status != "stopped" || *runs[0].StopReason != noteWindowEnded {
		t.Fatalf("%+v", runs)
	}
}

func TestSchedule_Slots(t *testing.T) {
	t.Parallel()
	c := Settings{Window: Window{Days: []int{1, 2, 3, 4, 5}, From: "22:00", To: "05:00"}, Schedule: Schedule{Enabled: true, Frequency: "weekly", Weekday: 5, At: "23:00"}}
	mon := time.Date(2026, 11, 16, 1, 0, 0, 0, time.UTC) // Monday 01:00
	if s := c.lastSlot(mon, time.UTC, false); s == nil || !s.Equal(time.Date(2026, 11, 13, 23, 0, 0, 0, time.UTC)) {
		t.Fatalf("last weekly slot: %v", s)
	}
	// the Friday 23:00 slot belongs to Friday's window, which closes on Saturday 05:00
	if end, ok := c.slotWindowEnd(time.Date(2026, 11, 13, 23, 0, 0, 0, time.UTC)); !ok || !end.Equal(time.Date(2026, 11, 14, 5, 0, 0, 0, time.UTC)) {
		t.Fatalf("Friday's window: %v %v", end, ok)
	}
	// a 02:00 slot on Monday is in Sunday's window, and Sunday is not a window day
	early := c
	early.Schedule.At = "02:00"
	if _, ok := early.slotWindowEnd(time.Date(2026, 11, 16, 2, 0, 0, 0, time.UTC)); ok {
		t.Fatal("Monday 02:00 counted in a window although Sunday is not a window day")
	}
	day := Settings{Window: Window{Days: []int{2}, From: "09:00", To: "17:00"}, Schedule: Schedule{At: "16:00"}}
	if end, ok := day.slotWindowEnd(time.Date(2026, 11, 10, 16, 0, 0, 0, time.UTC)); !ok || end.Hour() != 17 || end.Day() != 10 {
		t.Fatal("same-day window")
	}
}

// INV-7: probe rows are kept 90 days, rescan events one year; the job deletes what is older.
func TestContract_INV7_Retention(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	err := r.db.Write(r.ctx(), func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO scan_probe (id, ts, ip, label, template, request, result) VALUES ('old', '2026-08-11T09:59:00.000Z', '1.1.1.1', 'x', 't', 'r', 'matched')`,
			`INSERT INTO scan_probe (id, ts, ip, label, template, request, result) VALUES ('kept', '2026-08-12T10:01:00.000Z', '1.1.1.1', 'x', 't', 'r', 'matched')`,
			`INSERT INTO scan_event (id, ts, cve, product, result) VALUES ('e-old', '2025-11-09T10:00:00.000Z', 'CVE-2020-0001', 'x', 'clear')`,
			`INSERT INTO scan_event (id, ts, cve, product, result) VALUES ('e-kept', '2025-11-11T10:00:00.000Z', 'CVE-2020-0002', 'x', 'clear')`,
		} {
			if _, err := tx.ExecContext(r.ctx(), q); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.svc.RunRetention(r.ctx()); err != nil {
		t.Fatal(err)
	}
	if r.count(`SELECT count(*) FROM scan_probe`) != 1 || r.count(`SELECT count(*) FROM scan_probe WHERE id = 'kept'`) != 1 ||
		r.count(`SELECT count(*) FROM scan_event`) != 1 || r.count(`SELECT count(*) FROM scan_event WHERE id = 'e-kept'`) != 1 {
		t.Fatal("retention")
	}
}

func TestJobs_AreTheModulesAndTick(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	for _, j := range Jobs(r.svc) {
		if j.Module != ModuleID || j.Every <= 0 || j.Every > time.Hour || j.Run == nil {
			t.Fatalf("%+v", j)
		}
	}
}

func TestHandlers_Events(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	if err := r.svc.OnNewKEV(r.ctx(), kev("CVE-2023-46805")); err != nil {
		t.Fatal(err)
	}
	r.advance(2 * time.Minute)
	r.tick()
	h := r.http()
	code, b := h.call("GET", "/scans/events", "viewer", "")
	items, _ := b["items"].([]any)
	if code != 200 || b["auto_rescan"] != true || len(items) != 1 || items[0].(map[string]any)["result"] != "no_match" {
		t.Fatalf("%d %v", code, b)
	}
}

type offGate struct{}

func (offGate) Enabled(string) bool { return false }

type doneRec struct{ ch chan jobs.Run }

func (d doneRec) Record(_ context.Context, r jobs.Run) error { d.ch <- r; return nil }

// D-160: the retention job is housekeeping: with the module off the scheduler still runs it and it deletes what is past
// the retention. The other two jobs of the module do not run.
func TestTheRetentionJobRunsWhileTheModuleIsOff(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	err := r.db.Write(r.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(r.ctx(), `INSERT INTO scan_probe (id, ts, ip, label, template, request, result) VALUES ('old', '2026-08-11T09:59:00.000Z', '1.1.1.1', 'x', 't', 'r', 'matched')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := doneRec{make(chan jobs.Run, 8)}
	sched := jobs.New(slog.New(slog.DiscardHandler), offGate{}, nil, jobs.WithRecorder(rec))
	for _, j := range Jobs(r.svc) {
		if err := sched.Add(j); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); sched.Run(ctx) }()
	select {
	case run := <-rec.ch:
		if run.Job != "retention" || run.Status != jobs.StatusOK {
			t.Fatalf("run = %+v", run)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no job ran while the module was off")
	}
	cancel()
	<-done
	if n := r.count(`SELECT count(*) FROM scan_probe`); n != 0 {
		t.Fatalf("%d expired probe rows left: the retention job did not run while the module was off", n)
	}
}
