package sensoractive_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// #830: the worker's progress report of a running job reaches the Tracker the probe's context carried, checked and nothing else;
// the Dispatcher keeps none of it.
func TestProgressReachesTheSinkOfTheProbe(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	ctx, cancel := probeCtx(t, time.Hour)
	defer cancel()
	tr := progress.NewTracker(r.clk.Now)
	ch := probe(progress.WithSink(ctx, tr), r.d, argvOf(t, nmapargv.Extra, 100, "192.168.10.20"))
	j := r.poll(t, "", 5*time.Second).Jobs[0]
	if err := r.worker.PostProgress(t.Context(), j.ID, &sensorlink.JobProgress{Phase: "services", Percent: 40, RemainingS: 120}); err != nil {
		t.Fatal(err)
	}
	v := tr.View()
	if v == nil || v.Phase != progress.PhaseServices || *v.Percent != 40 || v.ETA == nil || *v.ETA != "2026-11-10T08:02:00.000Z" || v.Message == nil || *v.Message != "Second pass: administration and alternative ports" {
		t.Fatalf("view = %+v", v)
	}
	if err := r.worker.PostResult(t.Context(), j.ID, okResult("<nmaprun/>")); err != nil {
		t.Fatal(err)
	}
	await(t, ch)
	// the job is over: a late report is unknown and changes nothing
	err := r.worker.PostProgress(t.Context(), j.ID, &sensorlink.JobProgress{Phase: "ports", Percent: 1})
	var e *sensorlink.Error
	if !errors.As(err, &e) || e.Code != sensorlink.CodeUnknownJob {
		t.Fatalf("late report: %v", err)
	}
	if tr.View().Phase != progress.PhaseServices {
		t.Fatal("a late report reached the Tracker")
	}
}

// A probe without a Sink (discovery, the weekly all-ports run) takes reports and drops them.
func TestProgressWithoutASinkIsDropped(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	ch := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	j := r.poll(t, "", 5*time.Second).Jobs[0]
	if err := r.worker.PostProgress(t.Context(), j.ID, &sensorlink.JobProgress{Phase: "discovery", Percent: 3}); err != nil {
		t.Fatal(err)
	}
	if err := r.worker.PostResult(t.Context(), j.ID, okResult("<nmaprun/>")); err != nil {
		t.Fatal(err)
	}
	await(t, ch)
}

// sinkFunc is a progress.Sink of a function.
type sinkFunc func(progress.Update)

func (f sinkFunc) Report(u progress.Update) { f(u) }

// Review r1 #1: a report never reaches the Sink after the job's result has been taken, however the two race.
func TestNoProgressAfterTheResult(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	var ended, late atomic.Bool
	sink := sinkFunc(func(progress.Update) {
		if ended.Load() {
			late.Store(true)
		}
	})
	ctx, cancel := probeCtx(t, time.Hour) // the job's timeout: the reporter's clock (at most 1500 s) never reaches it
	defer cancel()
	ch := probe(progress.WithSink(ctx, sink), r.d, argvOf(t, nmapargv.Normal, 100, "192.168.10.20"))
	j := r.poll(t, "", 5*time.Second).Jobs[0]
	var wg sync.WaitGroup
	stop, posting := make(chan struct{}), make(chan struct{})
	wg.Add(1)
	go func() { // a worker that keeps reporting while its result goes in (the Dispatcher's clock moves, so none is throttled)
		defer wg.Done()
		<-posting
		// Review r1 #4: it reports until the result is in, a few hundred times at most, polling with the job named at every step so
		// the moving clock never makes the job lost (a poll naming it is the worker being alive; 90 s without one is not).
		for range 300 {
			select {
			case <-stop:
				return
			default:
			}
			r.clk.Advance(5 * time.Second)
			_, _ = r.d.Jobs(t.Context(), 0, []string{j.ID})
			_ = r.d.JobProgress(t.Context(), j.ID, &sensorlink.JobProgress{Phase: "ports", Percent: 50})
		}
	}()
	close(posting) // the reports start as the result is sent
	if err := r.worker.PostResult(t.Context(), j.ID, okResult("<nmaprun/>")); err != nil {
		t.Fatal(err)
	}
	await(t, ch)
	ended.Store(true)
	for range 50 { // the reporter goes on after the result: none of its reports may land
		r.clk.Advance(5 * time.Second)
		_ = r.d.JobProgress(t.Context(), j.ID, &sensorlink.JobProgress{Phase: "ports", Percent: 99})
	}
	close(stop)
	wg.Wait()
	if late.Load() {
		t.Fatal("a progress report reached the Sink after the result")
	}
}

// Review r1 #2: core takes at most one report per job every ProgressEvery (a second of slack), whatever the worker sends.
func TestProgressIsThrottledPerJob(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	tr := progress.NewTracker(r.clk.Now)
	ch := probe(progress.WithSink(t.Context(), tr), r.d, argvOf(t, nmapargv.Normal, 100, "192.168.10.20"))
	j := r.poll(t, "", 5*time.Second).Jobs[0]
	post := func(pct float64) {
		t.Helper()
		if err := r.worker.PostProgress(t.Context(), j.ID, &sensorlink.JobProgress{Phase: "ports", Percent: pct}); err != nil {
			t.Fatal(err)
		}
	}
	post(10)
	post(20) // same instant: dropped
	r.clk.Advance(3 * time.Second)
	post(30) // 3 s later: dropped
	if p := *tr.View().Percent; p != 10 {
		t.Fatalf("percent = %v, want the first report only", p)
	}
	r.clk.Advance(time.Second + time.Millisecond) // 4 s after the first: inside the slack, taken
	post(40)
	if p := *tr.View().Percent; p != 40 {
		t.Fatalf("percent = %v, want the report after the gap", p)
	}
	if err := r.worker.PostResult(t.Context(), j.ID, okResult("<nmaprun/>")); err != nil {
		t.Fatal(err)
	}
	await(t, ch)
}

// #830: the first report of a job opens a new pass of its phase, so a second nmap run of a device starts from its own 0 even where
// the run before it ended in the same phase a little further on (the Tracker keeps the bar from going back within one pass).
func TestEachJobOpensAPass(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	ctx, cancel := probeCtx(t, time.Hour)
	defer cancel()
	tr := progress.NewTracker(r.clk.Now)
	ctx = progress.WithSink(ctx, tr)
	for i, pct := range []float64{30, 15} {
		ch := probe(ctx, r.d, argvOf(t, nmapargv.Normal, 100, "192.168.10.20"))
		j := r.poll(t, "", 5*time.Second).Jobs[0]
		r.clk.Advance(time.Minute)
		if err := r.worker.PostProgress(t.Context(), j.ID, &sensorlink.JobProgress{Phase: "ports", Percent: pct}); err != nil {
			t.Fatal(err)
		}
		v := tr.View()
		if *v.Percent != pct || v.PhaseStartedAt != v.UpdatedAt {
			t.Fatalf("run %d: percent %v, phase from %s at %s; want %v, a pass of its own", i, *v.Percent, v.PhaseStartedAt, v.UpdatedAt, pct)
		}
		if err := r.worker.PostResult(t.Context(), j.ID, okResult("<nmaprun/>")); err != nil {
			t.Fatal(err)
		}
		await(t, ch)
	}
}
