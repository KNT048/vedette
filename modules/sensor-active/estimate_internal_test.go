package sensoractive

import (
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
	s.runSink("run-1").Report(progress.Update{Percent: 41.7, Remaining: 9*time.Minute + 10*time.Second})
	if got := s.workerEstimate(t.Context(), r); got != "41% of this pass; about 10 minutes left" {
		t.Fatalf("after a report: %q", got)
	}
	s.runSink("run-1").Report(progress.Update{Percent: -1, Remaining: 20 * time.Second})
	if got := s.workerEstimate(t.Context(), r); got != "less than a minute left" {
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
