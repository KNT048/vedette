package sensoractive_test

import (
	"errors"
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
