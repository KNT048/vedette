package exposure

import (
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/server/servertest"
)

func (e *env) runJob() {
	e.t.Helper()
	if err := e.svc.RunAutoDetect(e.ctx()); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) settings() BoxIP {
	e.t.Helper()
	b, err := e.svc.Settings(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

func TestContract_INV11_AutoDetectSchedule(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.prober.set(ipA, ipB)

	// first start: no check yet, auto-detect is on by default, so the job checks at once (a full check)
	if b := e.settings(); !b.Auto || b.IntervalMin != 60 || b.LastRun != nil {
		t.Fatalf("defaults = %+v", b)
	}
	e.runJob()
	if got := e.ipValues(); !slices.Equal(got, []string{ipA, ipB}) || e.prober.count() != DeepRounds {
		t.Fatalf("first run: IPs %v, rounds %d", got, e.prober.count())
	}
	b := e.settings()
	if b.LastRun == nil || !b.LastRun.OK || b.LastRun.At != "2026-11-09T10:00:00.000Z" {
		t.Fatalf("last run = %+v", b.LastRun)
	}

	// then every 60 minutes (the job wakes every minute and may start half a tick early)
	for _, d := range []time.Duration{time.Minute, 30 * time.Minute, 59 * time.Minute} {
		e.clock.now = t0.Add(d)
		e.runJob()
		if e.prober.count() != DeepRounds {
			t.Fatalf("a check ran %s after the last one", d)
		}
	}
	e.clock.now = t0.Add(60*time.Minute - JobTick/2)
	e.runJob()
	if e.prober.count() != DeepRounds+LightRounds { // the full check was 59.5 minutes ago: this one is light
		t.Fatalf("no check when it was due: %d rounds", e.prober.count())
	}
	// it runs as the box itself and leaves one audit row per run
	var runs, adds, renews int
	for _, a := range e.audits() {
		switch {
		case a.Action == "exposure.auto_detect" && a.User == SystemUser:
			runs++
		case a.Action == "exposure.verify_ok" && a.User == SystemUser:
			adds++
		case a.Action == "exposure.verify_renew":
			renews++
		}
	}
	if runs != 2 || adds != 2 || renews != 0 {
		t.Fatalf("audit: %d runs, %d adds, %d renewals: %v", runs, adds, renews, e.audits())
	}
	if last := e.audits()[len(e.audits())-1]; !strings.HasPrefix(last.Detail, "seen: ") {
		t.Fatalf("last run row = %+v", last)
	}

	// a failing check is recorded and not retried before the next interval (the services are not hammered)
	e.prober.offline()
	e.clock.now = t0.Add(120 * time.Minute)
	e.runJob()
	if b := e.settings(); b.LastRun.OK || b.LastRun.At != "2026-11-09T12:00:00.000Z" {
		t.Fatalf("failed run = %+v", b.LastRun)
	}
	calls := e.prober.count()
	e.clock.now = t0.Add(150 * time.Minute)
	e.runJob()
	if e.prober.count() != calls {
		t.Fatal("a failed check was retried at once")
	}
	if got := e.ipValues(); !slices.Equal(got, []string{ipA, ipB}) {
		t.Fatalf("IPs after a failed check = %v", got)
	}
}

// Short intervals: each check asks the three services once; the full check with its many connections runs at most once an hour.
func TestContract_INV11_LightAndFullChecks(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.prober.set(ipA, ipB)
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", true, 1); err != nil {
		t.Fatal(err)
	}
	e.runJob() // first: full
	if e.prober.count() != DeepRounds || len(e.ipValues()) != 2 {
		t.Fatalf("first check: %d rounds, IPs %v", e.prober.count(), e.ipValues())
	}
	rounds := e.prober.count()
	for i := 1; i < 60; i++ { // 59 minutes of one-minute checks: light
		e.clock.now = t0.Add(time.Duration(i) * time.Minute)
		e.runJob()
		if got := e.prober.count() - rounds; got != LightRounds {
			t.Fatalf("minute %d: %d rounds", i, got)
		}
		rounds = e.prober.count()
	}
	e.clock.now = t0.Add(60 * time.Minute) // an hour after the full one: full again
	e.runJob()
	if got := e.prober.count() - rounds; got != DeepRounds {
		t.Fatalf("hourly full check: %d rounds", got)
	}
	// "Detect now" is always a full check
	rounds = e.prober.count()
	if _, err := e.svc.Detect(e.ctx(), "admin@acme.example", true); err != nil {
		t.Fatal(err)
	}
	if e.prober.count()-rounds != DeepRounds {
		t.Fatal("Detect now was not a full check")
	}
}

func TestContract_INV11_ManualModeAndSettings(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.prober.set(ipA)
	e.runJob()
	kept := e.ipValues()

	// manual mode: nothing runs by itself, the list is kept, "Detect now" still works
	b, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", false, 60)
	if err != nil || b.Auto {
		t.Fatalf("switch off: %+v %v", b, err)
	}
	e.prober.set(ipB)
	calls := e.prober.count()
	e.advance(5 * time.Hour)
	e.runJob()
	if e.prober.count() != calls || !slices.Equal(e.ipValues(), kept) {
		t.Fatalf("manual mode ran by itself: rounds %d -> %d, IPs %v", calls, e.prober.count(), e.ipValues())
	}
	if got := e.detect(ipB); len(got) != 1 || !slices.Equal(e.ipValues(), []string{ipA, ipB}) {
		t.Fatalf("Detect now: %v", got)
	}

	// the interval is 1 minute to 24 hours; a refusal changes nothing
	for _, n := range []int{0, -1, 1441, 1 << 20} {
		_, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", true, n)
		wantAPI(t, err, 400, "bad_interval")
	}
	if b := e.settings(); b.Auto || b.IntervalMin != 60 {
		t.Fatalf("a refused save changed the settings: %+v", b)
	}
	for _, n := range []int{1, 5, 10, 15, 30, 60, 360, 720, 1440} {
		if b, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", false, n); err != nil || b.IntervalMin != n {
			t.Fatalf("interval %d: %+v %v", n, b, err)
		}
	}
	var changes int
	for _, a := range e.audits() {
		if a.Action == "exposure.box_ip_settings" {
			changes++
		}
	}
	if changes != 10 {
		t.Fatalf("%d settings changes audited", changes)
	}

	// turning auto-detect on checks at once; but not again within 5 minutes (toggling is not a way to probe)
	e.advance(time.Hour)
	e.prober.set(ipC)
	calls = e.prober.count()
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", true, 60); err != nil {
		t.Fatal(err)
	}
	if e.prober.count() == calls || !slices.Contains(e.ipValues(), ipC) {
		t.Fatalf("turning on did not check: rounds %d -> %d, IPs %v", calls, e.prober.count(), e.ipValues())
	}
	calls = e.prober.count()
	for range 3 {
		_, _ = e.svc.SaveSettings(e.ctx(), "admin@acme.example", false, 60)
		if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", true, 60); err != nil {
			t.Fatal(err)
		}
	}
	if e.prober.count() != calls {
		t.Fatalf("toggling probed %d more rounds", e.prober.count()-calls)
	}
	// the person who turned it on is the one in the audit trail of that check
	if !slices.ContainsFunc(e.audits(), func(a auditRow) bool {
		return a.Action == "exposure.verify_ok" && a.Target == ipC && a.User == "admin@acme.example"
	}) {
		t.Fatal("the check started by the switch is not attributed to the admin")
	}
}

func TestContract_INV11_RemovedIPComesBack(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.prober.set(ipA, ipB)
	e.runJob()
	all, _ := e.svc.Targets(e.ctx())
	gone := all[1]
	if _, err := e.svc.Commit(e.ctx(), "admin@acme.example", gone.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", gone.ID); err != nil {
		t.Fatal(err)
	}
	// auto-detect on and the box still uses it: it is added again at the next check, as a new target with no commitment
	e.advance(time.Hour)
	e.runJob()
	back, err := e.svc.Targets(e.ctx())
	if err != nil || len(back) != 2 {
		t.Fatalf("targets = %+v %v", back, err)
	}
	var again TargetView
	for _, v := range back {
		if v.Value == gone.Value {
			again = v
		}
	}
	if again.ID == gone.ID || again.Commitment != nil || again.Scannable || str((*string)(again.BlockedReason)) != "no_commitment" {
		t.Fatalf("returned target = %+v", again)
	}
	// with auto-detect off it stays removed until somebody detects
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", false, 60); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", again.ID); err != nil {
		t.Fatal(err)
	}
	e.advance(24 * time.Hour)
	e.runJob()
	if slices.Contains(e.ipValues(), gone.Value) {
		t.Fatal("a removed IP came back with auto-detect off")
	}
}

func TestJobs_Registration(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	js := Jobs(e.svc)
	if len(js) != 1 || js[0].Module != "exposure" || js[0].Name != "auto-detect" || js[0].Every != JobTick || js[0].Run == nil {
		t.Fatalf("jobs = %+v", js)
	}
	sched := jobs.New(slog.New(slog.DiscardHandler), servertest.NewGate(), nil)
	if err := sched.Add(js[0]); err != nil {
		t.Fatal(err)
	}
}
