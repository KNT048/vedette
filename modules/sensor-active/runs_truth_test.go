package sensoractive_test

import (
	"context"
	"database/sql"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/run"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// Run pages tell the truth on a real box: a person's check that something stopped says the one reason it stopped for, and goes on after
// a reason it can survive; queued checks add up in line; a check that waits for the scan worker starts when the worker reports and
// gives up in plain words when it never does.

// logOf is every line of run id's log, joined.
func logOf(t *testing.T, e *env, id string) string {
	t.Helper()
	d, err := e.svc.Runs().Get(e.ctx(), id)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range d.Log {
		lines = append(lines, l.Text)
	}
	return strings.Join(lines, " | ")
}

// A person asked to check a device, not an address. The device left the address while its check ran (a sweep found it elsewhere, or
// another device took the address): the check says so and checks the device again at its new address, instead of ending "stopped"
// with a guess of three reasons.
func TestTruthAPersonsCheckOfADeviceThatMovedIsCheckedAtItsNewAddress(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow)
	e.sweptBefore()
	moved := netip.MustParseAddr("192.168.10.21")
	var once sync.Once
	var mu sync.Mutex
	var probed [][]string
	e.withProber(probeFunc(func(ctx context.Context, argv []string) (sa.Output, error) {
		mu.Lock()
		probed = append(probed, targetsOf(argv))
		mu.Unlock()
		if slices.Contains(argv, "192.168.10.20") {
			once.Do(func() {
				e.inv.mu.Lock()
				e.inv.assets["a-web"] = moved
				e.inv.mu.Unlock()
				if err := e.svc.AssetChanged(context.WithoutCancel(ctx), "a-web"); err != nil {
					t.Error(err)
				}
			})
			<-ctx.Done() // the move stops the nmap on the old address
			return sa.Output{}, ctx.Err()
		}
		return sa.Output{XML: emptyScan}, nil
	}))
	m, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := waitRun(t, e, m.ID, run.Done, run.Partial, run.Failed, run.Stopped)
	log := logOf(t, e, m.ID)
	if r.Status != run.Done || !strings.Contains(log, "no longer at the address") || !strings.Contains(log, "checked again") {
		t.Fatalf("the check: %+v; log: %s", r, log)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.ContainsFunc(probed, func(ts []string) bool { return slices.Contains(ts, moved.String()) }) {
		t.Fatalf("probed %q: the new address was never checked", probed)
	}
}

// A person's check stopped because the device's own safety rules changed under it (set to never be scanned) says exactly that, not
// "the window closed, the scope changed or the module was turned off", and is not tried again.
func TestTruthAPersonsCheckStoppedByTheDevicesRulesSaysWhy(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow)
	e.sweptBefore()
	calls := 0
	var mu sync.Mutex
	e.withProber(probeFunc(func(ctx context.Context, _ []string) (sa.Output, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		e.inv.mu.Lock()
		e.inv.decision["a-web"] = sa.Decision{Reason: "regular_scan_never", Never: true}
		e.inv.mu.Unlock()
		if err := e.svc.AssetChanged(context.WithoutCancel(ctx), "a-web"); err != nil {
			t.Error(err)
		}
		<-ctx.Done()
		return sa.Output{}, ctx.Err()
	}))
	m, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := waitRun(t, e, m.ID, run.Done, run.Partial, run.Failed, run.Stopped)
	if r.Status != run.Failed || r.Summary != "Failed: The check stopped because the device was set to never be scanned" {
		t.Fatalf("the check: %+v", r)
	}
	if log := logOf(t, e, m.ID); strings.Contains(log, "window closed") || strings.Contains(log, "checked again") {
		t.Fatalf("log: %s", log)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("nmap ran %d times, want once", calls)
	}
}

// Device checks queued one behind the other add up: each holds the lane about as long as a check takes on this box (the middle of the
// recent checks), so the 2nd in line starts later than the 1st, and the running check says the same time left that the line adds up.
func TestTruthQueuedChecksAddUpInLine(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow, func(e *env) { e.inv.assets["a-third"] = netip.MustParseAddr("192.168.10.31") })
	e.sweptBefore()
	err := e.db.Write(e.ctx(), func(tx *sql.Tx) error { // five checks of 8 minutes each, a day ago
		for i := range 5 {
			from := e.clock().Add(-24*time.Hour + time.Duration(i)*time.Hour).UTC()
			_, err := tx.ExecContext(e.ctx(), `INSERT INTO core_run (id, module, kind, lane, title, trigger, requested_by, status, queued_at, started_at, ended_at, updated_at)
				VALUES (?1, 'sensor-active', 'device_check', 'nmap', 'Check', 'manual', 'ann@example.com', 'done', ?2, ?2, ?3, ?3)`,
				"old-"+string(rune('a'+i)), from.Format("2006-01-02T15:04:05.000Z"), from.Add(8*time.Minute).Format("2006-01-02T15:04:05.000Z"))
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	started, hold := make(chan struct{}), make(chan struct{})
	var once sync.Once
	e.withProber(probeFunc(func(ctx context.Context, argv []string) (sa.Output, error) {
		if slices.Contains(argv, "192.168.10.20") {
			once.Do(func() { close(started) })
			select {
			case <-hold:
			case <-ctx.Done():
				return sa.Output{}, ctx.Err()
			}
		}
		return sa.Output{XML: emptyScan}, nil
	}))
	defer close(hold)
	first, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	waitClosed(t, started, "the first check")
	a, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-printer"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-third"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	read := func(id string) run.Run {
		t.Helper()
		r, err := e.svc.Runs().Read(e.ctx(), id)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := read(first.ID); !strings.HasSuffix(r.Summary, "about 8 minutes left") {
		t.Fatalf("the running check: %q", r.Summary)
	}
	if r := read(a.ID); !strings.HasSuffix(r.Summary, "; it starts in about 8 minutes") {
		t.Fatalf("1st in line: %q", r.Summary)
	}
	if r := read(b.ID); !strings.HasSuffix(r.Summary, "(2nd in line); it starts in about 16 minutes") {
		t.Fatalf("2nd in line: %q", r.Summary)
	}
}

// reportingWorker is a scan worker that has not reported since a restart until report: it tells the module when it reports
// (OnReport), as the Dispatcher does at every heartbeat, and may say nmap is missing.
type reportingWorker struct {
	mu       sync.Mutex
	reported bool
	noNmap   bool
	hook     func()
}

func (w *reportingWorker) report(noNmap bool) {
	w.mu.Lock()
	w.reported, w.noNmap = true, noNmap
	hook := w.hook
	w.mu.Unlock()
	if hook != nil {
		hook()
	}
}

func (w *reportingWorker) OnReport(fn func()) { w.mu.Lock(); w.hook = fn; w.mu.Unlock() }

func (w *reportingWorker) NmapMissing() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.reported && w.noNmap
}

func (w *reportingWorker) WorkerAbsent() bool { w.mu.Lock(); defer w.mu.Unlock(); return !w.reported }

func (w *reportingWorker) NmapHealth() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case !w.reported:
		return "the scan worker has not reported since core started; active discovery runs once it does"
	case w.noNmap:
		return "nmap is not installed in the scan container; active discovery cannot run until the scan image is rebuilt"
	}
	return ""
}

func (w *reportingWorker) Probe(context.Context, []string) (sa.Output, error) {
	if w.NmapHealth() != "" {
		return sa.Output{}, sa.ErrWorkerUnavailable
	}
	return sa.Output{XML: emptyScan}, nil
}

// A person's check asked while the scan worker had not reported since a restart starts as soon as the worker reports, not at the next
// tick of the window's driver.
func TestTruthACheckWaitingForTheWorkerStartsWhenItReports(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow)
	e.sweptBefore()
	w := &reportingWorker{}
	e.withProber(w)
	m, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := waitRun(t, e, m.ID, run.Waiting); r.Status != run.Waiting {
		t.Fatalf("before the worker reported: %+v", r)
	}
	w.report(false) // no Tick
	if r := waitRun(t, e, m.ID, run.Done, run.Failed, run.Partial, run.Stopped); r.Status != run.Done {
		t.Fatalf("after the worker reported: %+v", r)
	}
}

// A person's check gives up in plain words when the worker never comes back (30 minutes), or comes back saying nmap is missing (at once).
func TestTruthACheckWaitingForTheWorkerGivesUp(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow, func(e *env) { e.inv.assets["a-third"] = netip.MustParseAddr("192.168.10.31") })
	e.sweptBefore()
	w := &reportingWorker{}
	e.withProber(w)
	gone, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.setBase(e.baseTime().Add(29 * time.Minute))
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if r := waitRun(t, e, gone.ID, run.Waiting); r.Status != run.Waiting {
		t.Fatalf("after 29 minutes: %+v", r)
	}
	e.setBase(e.baseTime().Add(2 * time.Minute))
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if r := waitRun(t, e, gone.ID, run.Failed, run.Done, run.Partial, run.Stopped); r.Status != run.Failed ||
		!strings.HasPrefix(r.Summary, "Failed: The scan worker did not report for 30 minutes") {
		t.Fatalf("after 31 minutes: %+v", r)
	}
	noNmap, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-third"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.report(true)
	if r := waitRun(t, e, noNmap.ID, run.Failed, run.Done, run.Partial, run.Stopped); r.Status != run.Failed ||
		!strings.Contains(r.Summary, "nmap is not installed") {
		t.Fatalf("the worker reports nmap missing: %+v", r)
	}
}
