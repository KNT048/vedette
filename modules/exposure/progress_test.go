package exposure

import (
	"context"
	"time"
	"testing"

	"github.com/knt048/vedette/core/progress"
)

// reportRunner reports through the Sink of the run's context, as the scan worker's nmap does through the Dispatcher (#830).
type reportRunner struct{ waitRunner }

func (r *reportRunner) Scan(ctx context.Context, t ScanTarget) (Content, error) {
	progress.Report(ctx, progress.Update{Phase: progress.PhaseServices, Percent: 25})
	return r.waitRunner.Scan(ctx, t)
}

// #830: the run shows how far its step is while it runs, and nothing once it has ended.
func TestScanRun_ShowsTheProgressOfItsStep(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := &reportRunner{waitRunner{fakeRunner: fakeRunner{content: sampleContent()}, in: make(chan struct{}), hold: make(chan struct{})}}
	e.svc.SetRunner(r)
	v := scanReady(t, e)
	if _, err := e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, ""); err != nil {
		t.Fatal(err)
	}
	<-r.in
	cur := e.svc.CurrentScan()
	if cur == nil || cur.Progress == nil || cur.Progress.Phase != progress.PhaseServices || *cur.Progress.Percent != 25 {
		t.Fatalf("current = %+v", cur)
	}
	got, ok := e.svc.StopScan(e.ctx(), "operator@acme.example")
	if !ok || got.Progress != nil {
		t.Fatalf("stopped = %+v", got)
	}
	if cur := e.svc.CurrentScan(); cur.Progress != nil {
		t.Fatalf("progress after the end = %+v", cur.Progress)
	}
}

func TestReportOpenVASIsItsPercent(t *testing.T) {
	t.Parallel()
	tr := progress.NewTracker(nil)
	reportOpenVAS(progress.WithSink(t.Context(), tr), 37)
	if v := tr.View(); v.Phase != progress.PhaseOpenVAS || *v.Percent != 37 {
		t.Fatalf("view = %+v", v)
	}
	ctx, cancel := context.WithTimeout(progress.WithSink(t.Context(), tr), time.Hour)
	defer cancel()
	d, _ := ctx.Deadline()
	reportOpenVAS(ctx, 50)
	if v := tr.View(); v.EndsBy == nil || *v.EndsBy != d.Add(gbStopBudget).UTC().Format("2006-01-02T15:04:05.000Z") {
		t.Fatalf("ends_by = %v", v.EndsBy)
	}
}
