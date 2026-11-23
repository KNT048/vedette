package sensoractive_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/schedule"
	"github.com/knt048/vedette/core/sensorlink"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// The weekly scan of every port gives the lane up to a run queued in it even when the two start at the same moment: a run queued in a
// transaction that commits only after the weekly scan looked at the lane (and found it free) still makes it give way, instead of
// waiting behind it for up to an hour and a half.
func TestQueueAWeeklyScanStartingWhileARunIsQueuedStillGivesWay(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	_, p := newBlockingWeekly(t)
	e.withProber(p)
	release := sa.HoldRunLock(e.svc) // the weekly run starts, then waits before it looks at the lane
	var releaseOnce sync.Once
	defer releaseOnce.Do(release)
	tick := runTick(e)
	waitFor(t, "the weekly run to start", func() bool {
		return e.count(`SELECT count(*) FROM core_run WHERE kind = 'all_ports' AND status = 'running'`) == 1
	})
	weekly := e.str(`SELECT id FROM core_run WHERE kind = 'all_ports'`)
	looked := make(chan struct{})
	var once sync.Once
	e.inv.mu.Lock()
	e.inv.onPolicy = func(string) { once.Do(func() { close(looked) }) } // after its look at the lane, before nmap
	e.inv.mu.Unlock()
	var sweep string
	err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		var err error
		sweep, err = e.svc.ScheduleOwner().Start(e.ctx(), tx, schedule.Fire{OwnerKey: sa.ScheduleKey, Trigger: run.Schedule, By: run.System})
		if err != nil {
			return err
		}
		releaseOnce.Do(release)
		select {
		case <-looked: // the weekly run found the lane free: the sweep is not committed yet
			return nil
		case <-time.After(30 * time.Second):
			return errors.New("the weekly run never read its device's policy")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := waitRun(t, e, weekly, run.Done, run.Partial, run.Failed, run.Stopped); r.Status != run.Partial || !strings.Contains(r.Summary, "gave way") {
		t.Fatalf("the weekly run: %+v", r)
	}
	if err := <-tick; err != nil {
		t.Fatal(err)
	}
	if r := waitRun(t, e, sweep, run.Done, run.Partial, run.Failed, run.Stopped, run.Waiting); r.Status != run.Done {
		t.Fatalf("the sweep queued behind the weekly run: %+v", r)
	}
}

// "Scan the LAN now" pressed again while the person's sweep has given way to a check is the sweep going on: refused as busy, with no
// second consent and no second resume; the pass goes on by itself once the check is done.
func TestQueueScanTheLANNowAgainWhileThePassGaveWay(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow, func(e *env) {
		e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/25"} })
	})
	e.sweptBefore()
	firstBatch, check := make(chan struct{}), make(chan struct{})
	batchHeld, checkHeld := make(chan struct{}), make(chan struct{})
	var batchOnce, checkOnce sync.Once
	e.withProber(probeFunc(func(ctx context.Context, argv []string) (sa.Output, error) {
		var started, held chan struct{}
		switch {
		case slices.Contains(argv, "-sn") && targetsOf(argv)[0] == "192.168.10.1":
			batchOnce.Do(func() { started, held = firstBatch, batchHeld })
		case !slices.Contains(argv, "-sn") && slices.Contains(argv, "192.168.10.20"):
			checkOnce.Do(func() { started, held = check, checkHeld })
		}
		if started != nil {
			close(started)
			select {
			case <-held:
			case <-ctx.Done():
				return sa.Output{}, ctx.Err()
			}
		}
		return sa.Output{XML: emptyScan}, nil
	}))
	var mu sync.Mutex
	consents := 0
	record := func(*sql.Tx, sa.ManualRun) error {
		mu.Lock()
		defer mu.Unlock()
		consents++
		return nil
	}
	m, err := e.svc.StartManual(e.ctx(), "ann@example.com", nil, record)
	if err != nil {
		t.Fatal(err)
	}
	waitClosed(t, firstBatch, "the sweep's first batch")
	if _, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, record); err != nil {
		t.Fatal(err)
	}
	close(batchHeld)
	waitClosed(t, check, "the person's check") // the pass gave way to it
	if r := waitRun(t, e, m.ID, run.Waiting); r.Status != run.Waiting {
		t.Fatalf("the pass: %+v", r)
	}
	e.setBase(local(9, 12, 11)) // past the gap between two sweeps, within the person's hour
	_, err = e.svc.StartManual(e.ctx(), "ann@example.com", nil, record)
	if !errors.Is(err, sa.ErrSlotBusy) {
		t.Fatalf("Scan the LAN now again while the pass gave way: %v, want busy", err)
	}
	mu.Lock()
	n := consents
	mu.Unlock()
	if n != 2 {
		t.Fatalf("%d consents recorded, want 2 (the sweep and the check)", n)
	}
	if r, _ := e.svc.Runs().Read(e.ctx(), m.ID); r.Status != run.Waiting {
		t.Fatalf("the pass after the second press: %+v", r)
	}
	if n := e.count(`SELECT count(*) FROM core_run_log WHERE text LIKE 'Resumed by%'`); n != 0 {
		t.Fatalf("the pass was resumed by the second press (%d log lines)", n)
	}
	close(checkHeld)
	if r := waitRun(t, e, m.ID, run.Done, run.Partial, run.Failed, run.Stopped); r.Status != run.Done || r.Done != 126 {
		t.Fatalf("the pass after the check: %+v", r)
	}
}

// The text of a failed weekly scan says what happens next: the first failure is tried again in the next window, the second one in a
// row waits for the next week (it does not say "next window" then).
func TestAllPortsASecondFailureSaysItWaitsAWeek(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	xml := fixtureXML(t, "device.xml")
	e.withProber(probeFunc(func(_ context.Context, argv []string) (sa.Output, error) {
		if slices.Contains(argv, "-p-") {
			return sa.Output{XML: emptyScan}, nil // the device never answered on any port
		}
		return sa.Output{XML: xml}, nil
	}))
	failed := func(day int) run.Run {
		t.Helper()
		e.setBase(local(9+day, 2, 0))
		if day > 0 {
			if err := e.db.Write(e.ctx(), func(tx dbTx) error {
				_, err := tx.ExecContext(e.ctx(), doneRunSQL, fmt.Sprintf("run_sweep_d%d", day), sa.RunSweep, e.clock().UTC().Format("2006-01-02T15:04:05.000Z"), "")
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := e.svc.Tick(e.ctx()); err != nil {
			t.Fatal(err)
		}
		w := runsOfKind(e, sa.RunAllPorts)
		if len(w) != day+1 || w[0].Status != run.Failed {
			t.Fatalf("day %d: the weekly runs %+v", day, w)
		}
		return w[0]
	}
	if r := failed(0); !strings.HasSuffix(r.Summary, "It is tried again in the next window") {
		t.Fatalf("the first failure: %q", r.Summary)
	}
	r := failed(1)
	if strings.Contains(r.Summary, "next window") || !strings.HasSuffix(r.Summary, "so it is tried again next week") {
		t.Fatalf("the second failure in a row: %q", r.Summary)
	}
	if got := e.str(`SELECT outcome FROM sa_all_ports WHERE asset_id = 'a-web'`); got != "failed" {
		t.Fatalf("the device's weekly outcome: %q, want failed (next week)", got)
	}
}

// restartingWorker is a scan worker that has not reported yet (core or the scan container just restarted) until report is called.
type restartingWorker struct {
	mu       sync.Mutex
	reported bool
}

func (w *restartingWorker) report() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reported = true
}

func (w *restartingWorker) NmapHealth() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.reported {
		return "the scan worker has not reported since core started; active discovery runs once it does"
	}
	return ""
}

func (w *restartingWorker) WorkerAbsent() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.reported
}

func (w *restartingWorker) Probe(context.Context, []string) (sa.Output, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.reported {
		return sa.Output{}, sa.ErrWorkerUnavailable
	}
	return sa.Output{XML: emptyScan}, nil
}

// "Check this device now" pressed while the scan worker has not reported since a restart waits for the worker, as the window's checks
// do, instead of being refused: it is listed as queued, asking again answers it (one consent), and it runs once the worker reports.
// "Scan the LAN now" is still refused then, and so is a check while the worker reports that it cannot run nmap.
func TestQueueACheckAskedBeforeTheWorkerReportedWaitsForIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow)
	e.sweptBefore()
	w := &restartingWorker{}
	e.withProber(w)
	consents := 0
	record := func(*sql.Tx, sa.ManualRun) error { consents++; return nil }
	m, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, record)
	if err != nil {
		t.Fatalf("a check while the worker has not reported: %v", err)
	}
	r, err := e.svc.Runs().Read(e.ctx(), m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != run.Waiting || !strings.HasPrefix(r.Summary, "Waiting for the scan worker to be available") || !m.Queued {
		t.Fatalf("the check: %+v (queued %v)", r, m.Queued)
	}
	again, err := e.svc.StartManual(e.ctx(), "bob@example.com", []string{"a-web"}, record)
	if err != nil || again.ID != m.ID || consents != 1 {
		t.Fatalf("asked again: %+v, %v, %d consents; want run %s and one consent", again, err, consents, m.ID)
	}
	v, err := e.svc.Engine(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Persons) != 1 || v.Persons[0].ID != m.ID || !v.Persons[0].Queued {
		t.Fatalf("the person's runs listed: %+v", v.Persons)
	}
	if _, err := e.svc.StartManual(e.ctx(), "ann@example.com", nil, record); !errors.Is(err, sa.ErrUnavailable) {
		t.Fatalf("Scan the LAN now while the worker has not reported: %v, want unavailable", err)
	}
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.svc.Runs().Read(e.ctx(), m.ID); r.Status != run.Waiting {
		t.Fatalf("the check after a tick while the worker is away: %+v", r)
	}
	w.report()
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if r := waitRun(t, e, m.ID, run.Done, run.Failed, run.Partial, run.Stopped); r.Status != run.Done {
		t.Fatalf("the check once the worker reported: %+v", r)
	}
	// a worker that reports it cannot run nmap does not come back by itself: a check is refused
	e.withProber(&sickProber{msg: "nmap is not installed in the scan container"})
	if _, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-printer"}, record); !errors.Is(err, sa.ErrUnavailable) {
		t.Fatalf("a check while nmap is missing: %v, want unavailable", err)
	}
}

// The scan worker is absent until its first heartbeat and again once it has not reported for 90 seconds.
func TestDispatcherWorkerAbsent(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Date(2026, 11, 9, 2, 0, 0, 0, time.UTC)
	d := sa.NewDispatcher(sa.DispatcherOptions{Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }})
	if !d.WorkerAbsent() {
		t.Fatal("absent before its first heartbeat: false")
	}
	if _, err := d.ActiveHeartbeat(t.Context(), &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true, Version: "7.94SVN"}}); err != nil {
		t.Fatal(err)
	}
	if d.WorkerAbsent() {
		t.Fatal("absent right after a heartbeat")
	}
	mu.Lock()
	now = now.Add(91 * time.Second)
	mu.Unlock()
	if !d.WorkerAbsent() {
		t.Fatal("not absent 91 seconds after its last heartbeat")
	}
}

// "Scan the LAN now" and "Check this device now" on an idle scanner start at once: the answer does not say queued (the person sees
// "Scan started", not "Queued: it starts when the scanner is free") although the dispatcher may not have picked the run up yet.
func TestQueueARunOnAnIdleScannerIsNotQueued(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow)
	m, err := e.svc.StartManual(e.ctx(), "ann@example.com", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Queued {
		t.Errorf("Scan the LAN now on an idle scanner answers queued: %+v", m)
	}
	waitManual(t, e)
	m, err = e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Queued {
		t.Errorf("Check this device now on an idle scanner answers queued: %+v", m)
	}
	waitManual(t, e)
}
