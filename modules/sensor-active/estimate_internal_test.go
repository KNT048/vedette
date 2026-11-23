package sensoractive

import (
	"context"
	"testing"
	"time"

	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/core/run"
)

// A running device run says how far the worker's nmap is and how long it has left, from the worker's last report; nothing before
// the first report, and nothing once the run has ended (the report is dropped with the run).
func TestTheWorkersReportIsTheEstimateOfARunningDeviceRun(t *testing.T) {
	t.Parallel()
	s := &Service{}
	r := run.Run{ID: "run-1", Status: run.Running}
	if got := s.workerEstimate(t.Context(), r); got != "" {
		t.Fatalf("before any report: %q", got)
	}
	s.runSink("run-1").Report(progress.Update{Phase: progress.PhasePorts, Percent: 41.7, Remaining: 9*time.Minute + 10*time.Second, NewPass: true})
	if got := s.workerEstimate(t.Context(), r); got != "finding open ports, 41%; about 10 minutes left" {
		t.Fatalf("after a report: %q", got)
	}
	s.runSink("run-1").Report(progress.Update{Phase: progress.PhaseServices, Percent: -1, Remaining: 20 * time.Second})
	if got := s.workerEstimate(t.Context(), r); got != "reading service versions; less than a minute left" {
		t.Fatalf("no percent, under a minute: %q", got)
	}
	if got := s.workerEstimate(t.Context(), run.Run{ID: "run-1", Status: run.Done}); got != "" {
		t.Fatalf("an ended run: %q", got)
	}
	s.dropProgress("run-1")
	if _, ok := s.lastProgress("run-1"); ok {
		t.Fatal("the report outlived its run")
	}
}

// The line of a device check only moves forward. nmap restarts its percent at every phase and the check makes two nmap runs, so the
// raw reports of one check read 8% → 84% → 28% → 20%; the line names the pass and the phase each percent belongs to, and a report that
// would move it back (a lower percent of the same phase, an earlier phase) is not shown.
func TestTheLineOfADeviceCheckOnlyMovesForward(t *testing.T) {
	t.Parallel()
	s := &Service{}
	r := run.Run{ID: "run-1", Status: run.Running}
	first := withPass(progress.WithSink(context.Background(), s.runSink("run-1")), 1, 2)
	second := withPass(progress.WithSink(context.Background(), s.runSink("run-1")), 2, 2)
	steps := []struct {
		ctx  context.Context
		u    progress.Update
		want string
	}{
		{first, progress.Update{Phase: progress.PhasePorts, Percent: 8, NewPass: true}, "pass 1 of 2: finding open ports, 8%"},
		{first, progress.Update{Phase: progress.PhaseServices, Percent: 84}, "pass 1 of 2: reading service versions, 84%"},
		{first, progress.Update{Phase: progress.PhasePorts, Percent: 90}, "pass 1 of 2: reading service versions, 84%"},    // an earlier phase
		{first, progress.Update{Phase: progress.PhaseServices, Percent: 60}, "pass 1 of 2: reading service versions, 84%"}, // lower, same phase
		{second, progress.Update{Phase: progress.PhasePorts, Percent: 28, NewPass: true}, "pass 2 of 2: finding open ports, 28%"},
		{second, progress.Update{Phase: progress.PhasePorts, Percent: 20}, "pass 2 of 2: finding open ports, 28%"},
		{second, progress.Update{Phase: progress.PhaseScripts, Percent: 5}, "pass 2 of 2: running service checks, 5%"},
	}
	for i, st := range steps {
		progress.Report(st.ctx, st.u)
		p, _ := s.lastProgress(r.ID)
		if got := progressLine(p); got != st.want {
			t.Fatalf("report %d (%+v): %q, want %q", i+1, st.u, got, st.want)
		}
	}
}
