package main

import (
	"context"
	"testing"

	"github.com/knt048/vedette/content/nucleipack"
	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	"github.com/knt048/vedette/modules/scan/pack"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// #830 FAIL 2: the exposure deep scan hands its templates to nuclei as many runs of at most 200, one after another; each run's own
// count went to the run's Tracker as it was, and the page read 85 % → 39 % → 82.5 % → 70 %. The template step now counts all its
// runs as one pass: the fake runner reports what the Dispatcher would (0, half, all of its own templates), and the step's percent
// never falls, its total never grows, and it ends with every template sent counted.

// reportingRun makes the fake's runner report like the Dispatcher does for a nuclei job, into the Sink of the context it is given.
func reportingRun(f *templatesFake) func(ctx context.Context, r sensoractive.NucleiRequest) (nucleiout.Outcome, error) {
	run := f.scanner().run
	return func(ctx context.Context, r sensoractive.NucleiRequest) (nucleiout.Outcome, error) {
		n := int64(len(r.Templates))
		for _, d := range []int64{0, n / 2, n} {
			progress.Report(ctx, progress.Update{Phase: progress.PhaseVulns, Percent: -1, Done: d, Total: n, Unit: progress.UnitChecks})
		}
		return run(ctx, r)
	}
}

// watchTracker is a Sink that checks every View of tr after each report reaches it.
type watchTracker struct {
	t      *testing.T
	tr     *progress.Tracker
	last   float64
	total  int64
	shown  int
	passes int
}

func (w *watchTracker) Report(u progress.Update) {
	w.t.Helper()
	if u.NewPass {
		w.passes++
	}
	w.tr.Report(u)
	v := w.tr.View()
	w.shown++
	if v.Phase != progress.PhaseVulns {
		w.t.Fatalf("phase %s", v.Phase)
	}
	p := 0.0
	if v.Percent != nil {
		p = *v.Percent
	}
	if p < w.last {
		w.t.Fatalf("the step's percent went back from %v to %v", w.last, p)
	}
	if v.Total != nil {
		if w.total > 0 && *v.Total > w.total {
			w.t.Fatalf("the step's total grew from %d to %d", w.total, *v.Total)
		}
		w.total = *v.Total
	}
	w.last = p
}

func TestExposureFullCountsAllItsRunsAsOne(t *testing.T) {
	t.Parallel()
	f := &templatesFake{gateOK: true, answer: func(r sensoractive.NucleiRequest) nucleiout.Outcome {
		var o nucleiout.Outcome
		for _, id := range r.Templates {
			o.Results = append(o.Results, nucleiout.Result{Template: id, Target: "8.8.8.8:18443", Matched: id == "nginx-version", MatcherName: "nginx"})
		}
		return o
	}}
	a := f.scanner()
	a.run = reportingRun(f)
	a.mode = (&modes{list: []exposure.ScanMode{{Full: true}}}).now
	w := &watchTracker{t: t, tr: progress.NewTracker(nil)}
	got, err := a.ScanTemplates(progress.WithSink(t.Context(), w), fullTarget(false), ownPublicIP, []exposure.TemplateJob{fullJobOf("CVE-2018-13379")})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.reqs) < 5 {
		t.Fatalf("%d runs: the test needs a step of many runs", len(f.reqs))
	}
	v := w.tr.View()
	if *v.Done != int64(len(got.Sent)) || *v.Total != int64(len(got.Sent)) || *v.Percent != 100 || w.passes != 1 {
		t.Fatalf("end of the step: %d of %d (%v %%) in %d passes, want all %d templates sent, one pass", *v.Done, *v.Total, *v.Percent, w.passes, len(got.Sent))
	}
}

func TestExposureBaselineCountsAllItsRunsAsOne(t *testing.T) {
	t.Parallel()
	f := &templatesFake{gateOK: true, answer: func(sensoractive.NucleiRequest) nucleiout.Outcome { return nucleiout.Outcome{} }}
	a := f.scanner()
	a.run = reportingRun(f)
	w := &watchTracker{t: t, tr: progress.NewTracker(nil)}
	second := ownJob("CVE-2019-19781")
	second.Port = 18444
	got, err := a.ScanTemplates(progress.WithSink(t.Context(), w), exposure.ScanTarget{ID: "t-1", User: "u-admin"}, ownPublicIP,
		[]exposure.TemplateJob{ownJob("CVE-2018-13379"), second})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.reqs) != 2 {
		t.Fatalf("%d runs, want one a port", len(f.reqs))
	}
	if v := w.tr.View(); *v.Done != int64(len(got.Sent)) || *v.Total != int64(len(got.Sent)) || w.passes != 1 {
		t.Fatalf("end of the step: %d of %d in %d passes, want %d, one pass", *v.Done, *v.Total, w.passes, len(got.Sent))
	}
}

// Review r1 #2: a web port's starting total is the plan it can reach, not the cap: every template its technologies templates could
// bring in (all of them matching), never less than what a real outcome chooses, and below exposure.FullTemplatesPerPort with the
// committed pack (it was the cap: 4000 for a port that sends about 2200).
func TestPortBoundIsTheReachablePlan(t *testing.T) {
	t.Parallel()
	ix, err := nucleipack.Index()
	if err != nil {
		t.Fatal(err)
	}
	products := pack.ProductTags(ix.Templates)
	p := fullPorts(ownPublicIP, []exposure.TemplateJob{fullJobOf("CVE-2018-13379")}, nil)[0]
	bound := portBound(ix, products, p, false)
	tech := 0
	every := map[string][]string{}
	for _, tp := range ix.Templates {
		if tp.Tech() && tp.RunsAt(true, false) {
			tech++
			every[tp.ID] = nil
		}
	}
	for name, found := range map[string]map[string][]string{"nothing matched": nil, "nginx": {"nginx-version": {"nginx"}}, "every technologies template": every} {
		plan, _ := webPlan(ix, p, foundTags(ix, products, found, p), false, exposure.FullTemplatesPerPort-tech)
		if n := int64(tech + len(plan)); n > bound {
			t.Errorf("%s: %d templates sent, over the bound %d", name, n, bound)
		}
	}
	if bound >= exposure.FullTemplatesPerPort {
		t.Errorf("bound %d is the cap %d", bound, exposure.FullTemplatesPerPort)
	}
}
