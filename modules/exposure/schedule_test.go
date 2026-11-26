package exposure

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corerun "github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/schedule"
)

// scheduleEnv is an env whose service registers the targets' schedules on a schedule service of its own (no scan window).
func scheduleEnv(t *testing.T) (*env, *schedule.Service) {
	t.Helper()
	e := newEnv(t)
	sch, err := schedule.New(schedule.Config{DB: e.db, Clock: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	cfg := e.svc.cfg
	cfg.Schedules = sch
	e.useService(cfg)
	if err := sch.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sch.Close)
	return e, sch
}

// moveTo moves the env's clock to at (forward only).
func (e *env) moveTo(at time.Time) {
	if d := at.Sub(e.clock.Now()); d > 0 {
		e.advance(d)
	}
}

// runOf reads the trigger and the requester of run id.
func (e *env) runOf(id string) (trigger, by string) {
	e.t.Helper()
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT trigger, requested_by FROM core_run WHERE id = ?`, id).Scan(&trigger, &by); err != nil {
		e.t.Fatal(err)
	}
	return trigger, by
}

// Every target gets its schedule when it is added (weekly, inside the scan window, as the terms say) and loses it when it is deleted;
// a target stored without one gets it at start.
func TestSchedule_EveryTargetHasOne(t *testing.T) {
	t.Parallel()
	e, sch := scheduleEnv(t)
	d := e.addVerifiedDomain()
	v, err := sch.Get(e.ctx(), ScheduleKey(d.ID))
	if err != nil || !v.Saved || !v.Enabled || v.Rule.Freq != schedule.Weekly || v.Rule.Window != schedule.WindowGlobal || v.EditRole != "admin" ||
		v.Limits.MinEveryMinutes != MinScheduleMinutes || v.Limits.Reason == "" {
		t.Fatalf("the default schedule: %+v %v", v, err)
	}
	ip := e.detect(ipA)[0]
	if n := e.count(`SELECT count(*) FROM core_schedule WHERE owner_key = ?`, ScheduleKey(ip.ID)); n != 1 {
		t.Fatalf("the box's IP has no schedule: %d", n)
	}
	e.exec(`DELETE FROM core_schedule WHERE owner_key = ?`, ScheduleKey(ip.ID))
	if err := e.svc.EnsureSchedules(e.ctx()); err != nil {
		t.Fatal(err)
	}
	// the public IP detection's own schedule is also exposure's; only the targets' schedules count here
	if n := e.count(`SELECT count(*) FROM core_schedule WHERE owner_module = 'exposure' AND owner_key <> ?`, PublicIPScheduleKey); n != 2 {
		t.Fatalf("schedules after the start: %d", n)
	}
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", d.ID); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM core_schedule WHERE owner_key = ?`, ScheduleKey(d.ID)); n != 0 {
		t.Fatalf("a deleted target keeps its schedule: %d", n)
	}
	if _, err := sch.Get(e.ctx(), ScheduleKey(d.ID)); !errors.Is(err, schedule.ErrUnknownOwner) {
		t.Fatalf("the schedule of a deleted target: %v", err)
	}
}

// Set, preview, pause, run once and the due time through core/schedule: every 3 days at 02:30 on working days, the next three starts;
// an interval under the owner's limit refused with its reason; a pause holds the due time; Run once now queues a person's scan; a due
// scan needs the current testing terms (skipped with the reason without them) and runs as the box, never with the disruptive checks.
func TestSchedule_SetPreviewPauseRunOnce(t *testing.T) {
	t.Parallel()
	e, sch := scheduleEnv(t)
	d := e.addVerifiedDomain()
	if _, err := e.commit(d.ID); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{content: Content{Hosts: []HostRow{{Name: "acme.example", IP: ipA, IPs: []HostIP{{IP: ipA, Family: "ipv4", Class: ClassPublic}}}}}}
	e.svc.SetRunner(runner)
	key := ScheduleKey(d.ID)
	every3, at, from, to := 3*24*60, "02:30", "00:00", "00:00"
	rule := schedule.Rule{Freq: schedule.Interval, EveryMinutes: &every3, At: &at, Window: schedule.WindowCustom, WindowDays: []int{1, 2, 3, 4, 5}, WindowFrom: &from, WindowTo: &to}
	v, err := sch.Save(e.ctx(), key, schedule.Setting{Enabled: true, Rule: rule}, "admin@acme.example")
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := time.LoadLocation(v.Zone)
	if len(v.Upcoming) != 3 || v.Upcoming[0].In(loc).Format("15:04") != at {
		t.Fatalf("preview: %+v", v.Upcoming)
	}
	for _, u := range v.Upcoming {
		l := u.In(loc)
		if wd := l.Weekday(); wd == time.Saturday || wd == time.Sunday { // a time due on a weekend starts when the window opens on Monday
			t.Fatalf("a start outside Mon-Fri: %v (%v)", l, v.Upcoming)
		}
	}
	short := 60
	_, err = sch.Save(e.ctx(), key, schedule.Setting{Enabled: true, Rule: schedule.Every(short)}, "admin@acme.example")
	var re *schedule.RuleError
	if !errors.As(err, &re) || !strings.Contains(re.Message, "6 hours") {
		t.Fatalf("an hourly external scan: %v", err)
	}
	// paused: the due time passes and nothing starts
	daily := schedule.DailyAt("02:30")
	pause := e.clock.Now().Add(72 * time.Hour)
	if v, err = sch.Save(e.ctx(), key, schedule.Setting{Enabled: true, Rule: daily, PausedUntil: &pause}, "admin@acme.example"); err != nil {
		t.Fatal(err)
	}
	e.moveTo(e.clock.Now().Add(26 * time.Hour))
	if _, err := sch.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM exp_scan`); n != 0 {
		t.Fatalf("a paused schedule started %d scans", n)
	}
	// run once now: a person's scan, now, without the terms (the confirmation is enough for a person's press)
	runID, err := sch.RunNow(e.ctx(), key, "admin@acme.example")
	if err != nil || runID == "" {
		t.Fatalf("run once now: %q %v", runID, err)
	}
	e.waitScan(runID)
	if trig, by := e.runOf(runID); trig != "manual" || by != "admin@acme.example" || runner.calls != 1 {
		t.Fatalf("run once now: %s by %s, %d scans", trig, by, runner.calls)
	}
	if _, err := sch.RunNow(e.ctx(), key, "admin@acme.example"); err == nil || !strings.Contains(err.Error(), "less than 10 minutes") {
		t.Fatalf("run once again at once: %v", err)
	}
	// resumed; due without the terms: skipped, and the editor says why
	if v, err = sch.Save(e.ctx(), key, schedule.Setting{Enabled: true, Rule: daily}, "admin@acme.example"); err != nil {
		t.Fatal(err)
	}
	e.moveTo(*v.NextDueAt)
	if _, err := sch.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if v, err = sch.Get(e.ctx(), key); err != nil || v.LastSkipReason == nil || !strings.Contains(*v.LastSkipReason, "testing terms") {
		t.Fatalf("due without the terms: %+v %v", v, err)
	}
	// with the terms (the disruptive checks included): a scheduled scan by the box, deep, never disruptive
	e.acceptTerms(d.ID, true)
	e.moveTo(*v.NextDueAt)
	if _, err := sch.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if v, err = sch.Get(e.ctx(), key); err != nil || v.LastRunID == nil || v.LastSkipReason != nil {
		t.Fatalf("due with the terms: %+v %v", v, err)
	}
	e.waitScan(*v.LastRunID)
	if trig, by := e.runOf(*v.LastRunID); trig != "schedule" || by != corerun.System || runner.calls != 2 {
		t.Fatalf("the scheduled scan: %s by %s, %d scans", trig, by, runner.calls)
	}
	if m := runner.last.Mode; !m.Full || m.Disruptive {
		t.Fatalf("the scheduled scan's mode: %+v", m)
	}
	if m, err := e.svc.ModeNow(e.ctx(), SystemUser, d.ID); err != nil || m.Disruptive {
		t.Fatalf("the mode the box's scan reads before a deep step: %+v %v", m, err)
	}
	if m, err := e.svc.ModeNow(e.ctx(), "admin@acme.example", d.ID); err != nil || !m.Disruptive {
		t.Fatalf("a person's scan keeps the disruptive checks: %+v %v", m, err)
	}
	// switched off: the due time is skipped with the reason
	off := false
	if _, err := e.svc.EditNode(e.ctx(), "admin@acme.example", d.ID, NodeEdit{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	if v, err = sch.Get(e.ctx(), key); err != nil {
		t.Fatal(err)
	}
	e.moveTo(*v.NextDueAt)
	if _, err := sch.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if v, err = sch.Get(e.ctx(), key); err != nil || v.LastSkipReason == nil || !strings.Contains(*v.LastSkipReason, "switched off") {
		t.Fatalf("due while switched off: %+v %v", v, err)
	}
}

// gateRunner blocks the scan of one target until it is released, so another target's scan waits in the lane's queue.
type gateRunner struct {
	hold    string
	release chan struct{}
	scanned chan string
}

func (r *gateRunner) Scan(ctx context.Context, st ScanTarget) (Content, error) {
	r.scanned <- st.ID
	if st.ID == r.hold {
		select {
		case <-r.release:
		case <-ctx.Done():
		}
	}
	return Content{}, nil
}

// A scheduled scan queued at 02:30 behind another target's long scan, whose testing terms are withdrawn at 03:00, does not scan when it
// starts at 04:00: the run ends failed with the reason and the target is never sent anything.
func TestSchedule_AQueuedScanStopsWhenTheTermsAreWithdrawn(t *testing.T) {
	t.Parallel()
	e, sch := scheduleEnv(t)
	d := e.addVerifiedDomain()
	if _, err := e.commit(d.ID); err != nil {
		t.Fatal(err)
	}
	e.acceptTerms(d.ID, false)
	ip := e.detect(ipA)[0]
	if _, err := e.commit(ip.ID); err != nil {
		t.Fatal(err)
	}
	r := &gateRunner{hold: ip.ID, release: make(chan struct{}), scanned: make(chan string, 4)}
	e.svc.SetRunner(r)
	long, err := e.svc.StartScan(e.ctx(), Actor{Email: "admin@acme.example"}, ip.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := <-r.scanned; got != ip.ID {
		t.Fatalf("the long scan: %s", got)
	}
	key := ScheduleKey(d.ID)
	v, err := sch.Save(e.ctx(), key, schedule.Setting{Enabled: true, Rule: schedule.DailyAt("02:30")}, "admin@acme.example")
	if err != nil {
		t.Fatal(err)
	}
	e.moveTo(*v.NextDueAt)
	if _, err := sch.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if v, err = sch.Get(e.ctx(), key); err != nil || v.LastRunID == nil {
		t.Fatalf("the due scan was not queued: %+v %v", v, err)
	}
	queued := *v.LastRunID
	e.advance(30 * time.Minute)
	if _, err := e.svc.RevokeTerms(e.ctx(), "admin@acme.example", d.ID); err != nil {
		t.Fatal(err)
	}
	e.advance(time.Hour)
	close(r.release)
	e.waitScan(long.ID)
	e.waitScan(queued)
	var status, errText string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT status, coalesce(error, '') FROM core_run WHERE id = ?`, queued).Scan(&status, &errText); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(errText, "testing terms were withdrawn") {
		t.Fatalf("the queued scheduled scan: %s %q", status, errText)
	}
	select {
	case got := <-r.scanned:
		t.Fatalf("the target was scanned after its terms were withdrawn: %s", got)
	default:
	}
}

// A service built with Schedules owns both of the module's schedules: registering either owner again is refused as a duplicate.
func TestNewService_RegistersBothScheduleOwners(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for name, o := range map[string]schedule.Owner{
		"public IP detection": e.svc.PublicIPScheduleOwner(),
		"target scans":        {Module: ModuleID, Key: ScheduleOwner, PerSubject: true, Default: DefaultSchedule(), Start: e.svc.startScheduled},
	} {
		if err := e.sched.Register(o); err == nil || !strings.Contains(err.Error(), "registered twice") {
			t.Errorf("%s: the service did not register its owner: %v", name, err)
		}
	}
}
