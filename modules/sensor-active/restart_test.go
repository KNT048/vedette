package sensoractive_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/run"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// gateProber answers the first nmap job once open is closed and holds every later one until its context ends (a restart).
type gateProber struct {
	mu      sync.Mutex
	n       int
	open    chan struct{}
	started chan int
}

func newGate() *gateProber {
	return &gateProber{open: make(chan struct{}), started: make(chan int, 64)}
}

func (g *gateProber) Probe(ctx context.Context, _ []string) (sa.Output, error) {
	g.mu.Lock()
	g.n++
	n := g.n
	g.mu.Unlock()
	g.started <- n
	if n == 1 {
		select {
		case <-g.open:
			return sa.Output{XML: emptyScan}, nil
		case <-ctx.Done():
			return sa.Output{}, ctx.Err()
		}
	}
	<-ctx.Done()
	return sa.Output{}, ctx.Err()
}

func (g *gateProber) wait(t *testing.T, n int) {
	t.Helper()
	for got := range g.started {
		if got >= n {
			return
		}
	}
}

// A restart while a person's check runs and the person's sweep waits for it: after the restart neither fails nor sticks while the scan
// worker has not reported yet; both wait for it and go on when it reports.
func TestRestartPersonsRunsWaitForTheWorkerAndGoOn(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow, func(e *env) {
		e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/25"} })
	})
	e.sweptBefore()
	g := newGate()
	e.withProber(g)
	sw, err := e.svc.StartManual(e.ctx(), "ann@example.com", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	g.wait(t, 1) // the sweep's first batch is in nmap
	ck, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	close(g.open)
	g.wait(t, 2) // the sweep gave way after its batch; the check is in nmap
	if r := waitRun(t, e, sw.ID, run.Waiting); r.Done != 64 {
		t.Fatalf("the sweep before the restart: %+v", r)
	}
	w := &reportingWorker{}
	e.withProber(w) // core restarts; the scan worker has not reported yet
	if r := waitRun(t, e, ck.ID, run.Waiting, run.Failed, run.Done, run.Partial, run.Stopped); r.Status != run.Waiting {
		t.Fatalf("the person's check after the restart: %s (%s), want waiting for the scan worker | %s", r.Status, r.Summary, logOf(t, e, ck.ID))
	}
	if l := logOf(t, e, ck.ID); strings.Count(l, "Stopped") != 1 || !strings.Contains(l, "Stopped: Vedette restarted") {
		t.Fatalf("the check's log says the restart once, as the restart: %s", l)
	}
	w.report(false)
	sa.WaitBackground(e.svc)
	if r := waitRun(t, e, ck.ID, run.Done, run.Failed, run.Partial, run.Stopped); r.Status != run.Done {
		t.Fatalf("the check once the worker reported: %s (%s)", r.Status, r.Summary)
	}
	r := waitRun(t, e, sw.ID, run.Done, run.Failed, run.Partial, run.Stopped)
	if r.Status != run.Done || r.Done != 126 {
		t.Fatalf("the sweep once the worker reported: %s (%s) | %s", r.Status, r.Summary, logOf(t, e, sw.ID))
	}
	if l := logOf(t, e, sw.ID); strings.Contains(l, "Failed") {
		t.Fatalf("sweep log %s", l)
	}
}

// A person's sweep that a restart stopped mid-batch waits for the scan worker after it (outside the window, within the person's hour); a
// person's Resume while the worker is still away waits again with that reason instead of ending, and the worker's first report lets the
// pass go on from its cursor to its end.
func TestRestartAPersonsSweepGoesOnWhenTheWorkerReports(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow, func(e *env) {
		e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/25"} })
	})
	e.sweptBefore()
	g := newGate()
	e.withProber(g)
	sw, err := e.svc.StartManual(e.ctx(), "ann@example.com", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	g.wait(t, 1)
	w := &reportingWorker{}
	e.withProber(w)
	if r := waitRun(t, e, sw.ID, run.Waiting); r.WaitingFor == nil || *r.WaitingFor != "the scan worker to be available" {
		t.Fatalf("the sweep after the restart: %s", r.Summary)
	}
	// Devices and Settings › Scanning still show the person's sweep, with what it waits for
	v, err := e.svc.Engine(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Persons) != 1 || v.Persons[0].ID != sw.ID || !v.Persons[0].Queued || e.svc.Manual(e.ctx()) == nil {
		t.Fatalf("the person's runs listed after the restart: %+v", v.Persons)
	}
	if err := e.svc.Runs().Resume(e.ctx(), sw.ID, "ann@example.com"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the resumed sweep to wait again", func() bool {
		return strings.Count(logOf(t, e, sw.ID), "Waiting for the scan worker to be available") == 2
	})
	if r := waitRun(t, e, sw.ID, run.Waiting); r.Done != 0 {
		t.Fatalf("the sweep resumed while the worker is away: %+v", r)
	}
	if err := e.svc.Tick(e.ctx()); err != nil { // a tick while the worker is away leaves it waiting
		t.Fatal(err)
	}
	w.report(false) // no tick: the report wakes it
	r := waitRun(t, e, sw.ID, run.Done, run.Failed, run.Partial, run.Stopped)
	if r.Status != run.Done || r.Done != 126 {
		t.Fatalf("the sweep once the worker reported: %s (%s) | %s", r.Status, r.Summary, logOf(t, e, sw.ID))
	}
}

// settle waits up to d for run id to end and returns its state as stored then (still live or waiting when it did not end).
func settle(t *testing.T, e *env, id string, d time.Duration) run.Run {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		r, err := e.svc.Runs().Read(e.ctx(), id)
		if err != nil {
			t.Fatal(err)
		}
		if r.Status.Ended() || time.Now().After(deadline) {
			return r
		}
		<-time.After(20 * time.Millisecond)
	}
}

// The class of a restart: every shape a person's run can be in when core restarts (a check running, queued or waiting for the scan
// worker; a sweep running, waiting for the worker, or waiting for the check it gave way to), with the scan worker not reported yet
// after the restart. Counted: a run that fails, or ends without its work, before the worker reports, and a run that is not done once
// the worker reported (stuck, failed, or stopped with no reason). Every one must be zero.
func TestRestartEveryPersonsRunEndsTrue(t *testing.T) {
	t.Parallel()
	type shape struct {
		name  string
		build func(t *testing.T, e *env) []string // the person's runs, left as the old process had them
	}
	held := func(e *env) *gateProber { g := newGate(); e.withProber(g); return g }
	shapes := []shape{
		{"a check running", func(t *testing.T, e *env) []string {
			g := held(e)
			m, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			g.wait(t, 1)
			return []string{m.ID}
		}},
		{"a check queued behind another", func(t *testing.T, e *env) []string {
			g := held(e)
			a, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-printer"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			g.wait(t, 1)
			b, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			return []string{a.ID, b.ID}
		}},
		{"a check waiting for the worker", func(t *testing.T, e *env) []string {
			e.withProber(&reportingWorker{})
			m, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			waitRun(t, e, m.ID, run.Waiting)
			return []string{m.ID}
		}},
		{"a sweep running", func(t *testing.T, e *env) []string {
			g := held(e)
			m, err := e.svc.StartManual(e.ctx(), "ann@example.com", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			g.wait(t, 1)
			return []string{m.ID}
		}},
		{"a sweep waiting for the worker", func(t *testing.T, e *env) []string {
			g := held(e)
			m, err := e.svc.StartManual(e.ctx(), "ann@example.com", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			g.wait(t, 1)
			e.withProber(&reportingWorker{}) // a first restart: it waits for the worker
			waitRun(t, e, m.ID, run.Waiting)
			return []string{m.ID}
		}},
		{"a sweep that gave way to a running check", func(t *testing.T, e *env) []string {
			g := held(e)
			sw, err := e.svc.StartManual(e.ctx(), "ann@example.com", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			g.wait(t, 1)
			ck, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			close(g.open)
			g.wait(t, 2)
			waitRun(t, e, sw.ID, run.Waiting)
			return []string{sw.ID, ck.ID}
		}},
	}
	wrong := 0
	for _, sh := range shapes {
		e := newEnv(t, fakeOpts{}, outsideWindow, func(e *env) {
			e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/25"} })
		})
		e.sweptBefore()
		ids := sh.build(t, e)
		w := &reportingWorker{}
		e.withProber(w) // core restarts; the scan worker has not reported yet
		for _, id := range ids {
			if r := settle(t, e, id, 300*time.Millisecond); r.Status.Ended() {
				wrong++
				t.Logf("%s: before the worker reported, run %s ended %s (%s)", sh.name, id, r.Status, r.Summary)
			}
		}
		w.report(false)
		for _, id := range ids {
			if r := settle(t, e, id, 5*time.Second); r.Status != run.Done {
				wrong++
				t.Logf("%s: once the worker reported, run %s is %s (%s)", sh.name, id, r.Status, r.Summary)
			}
		}
	}
	t.Logf("person's runs a restart left untrue: %d", wrong)
	if wrong != 0 {
		t.Fatalf("%d of the person's runs a restart touched did not end true", wrong)
	}
}
