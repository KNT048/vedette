package scan

import (
	"context"
	"testing"
	"time"

	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/modules/scan/nucleiout"
)

// progressEngine reports through the Sink of its context, as the scan worker's reports do through the Dispatcher (#830), and holds
// the job until the test releases it.
type progressEngine struct {
	*runEngine
	reached, release chan struct{}
}

func (p progressEngine) Run(ctx context.Context, job Job) (nucleiout.Outcome, error) {
	progress.Report(ctx, progress.Update{Phase: progress.PhaseVulns, Percent: -1, Done: 3, Total: 8, Unit: progress.UnitChecks})
	close(p.reached)
	<-p.release
	return p.runEngine.Run(ctx, job)
}

// #830: a running scan shows how far its device is; the progress lives with the run and is gone when it ends.
func TestRunShowsTheProgressOfItsDevice(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	pe := progressEngine{runEngine: r.eng, reached: make(chan struct{}), release: make(chan struct{})}
	r.svc.cfg.Engine = pe
	v := r.start("a-nas02")
	select {
	case <-pe.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the engine was not reached")
	}
	got := r.run(v.ID).Progress
	if got == nil || got.Phase != progress.PhaseVulns || got.Done == nil || *got.Done != 3 || *got.Total != 8 || *got.Unit != progress.UnitChecks || *got.Percent != 37.5 {
		t.Fatalf("progress = %+v", got)
	}
	// the list carries it too, and it goes through the API types
	h := NewScanHandlers(r.svc)
	list, err := h.ScanGetScansRuns(r.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := list.Items[0].Progress.Get(); !ok || p.Phase != "vulns" || p.Done.Or(0) != 3 {
		t.Fatalf("API progress = %+v", list.Items[0].Progress)
	}
	close(pe.release)
	r.wait()
	if end := r.run(v.ID); end.Status != "done" || end.Progress != nil {
		t.Fatalf("after the run: status %s, progress %+v", end.Status, end.Progress)
	}
	list, err = h.ScanGetScansRuns(r.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if !list.Items[0].Progress.IsNull() {
		t.Fatalf("API progress after the run = %+v", list.Items[0].Progress)
	}
}
