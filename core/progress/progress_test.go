package progress

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *clock               { return &clock{t: time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)} }
func val[T any](p *T) (T, bool) {
	var z T
	if p == nil {
		return z, false
	}
	return *p, true
}

func TestNothingBeforeTheFirstReport(t *testing.T) {
	if v := NewTracker(nil).View(); v != nil {
		t.Fatalf("view = %+v, want nil", v)
	}
}

func TestPhaseOnly(t *testing.T) {
	c := newClock()
	tr := NewTracker(c.now)
	c.add(3 * time.Second)
	tr.Report(Phase(PhaseVulns, "checking"))
	v := tr.View()
	if v.Phase != PhaseVulns || v.Percent != nil || v.Done != nil || v.Total != nil || v.Unit != nil || v.ETA != nil || *v.Message != "checking" {
		t.Fatalf("view = %+v", v)
	}
	if v.StartedAt != "2026-11-16T08:00:00.000Z" || v.PhaseStartedAt != "2026-11-16T08:00:03.000Z" || v.UpdatedAt != v.PhaseStartedAt {
		t.Fatalf("times = %s %s %s", v.StartedAt, v.PhaseStartedAt, v.UpdatedAt)
	}
}

func TestToolEstimateWins(t *testing.T) {
	c := newClock()
	tr := NewTracker(c.now)
	tr.Report(Update{Phase: PhasePorts, Percent: 12.345, Remaining: 90 * time.Second})
	v := tr.View()
	if p, _ := val(v.Percent); p != 12.3 {
		t.Fatalf("percent = %v", p)
	}
	if e, _ := val(v.ETA); e != "2026-11-16T08:01:30.000Z" {
		t.Fatalf("eta = %v", e)
	}
}

func TestPaceEstimateAfterTenSeconds(t *testing.T) {
	c := newClock()
	tr := NewTracker(c.now)
	tr.Report(Update{Phase: PhaseVulns, Percent: -1, Done: 0, Total: 100, Unit: UnitChecks})
	c.add(5 * time.Second)
	tr.Report(Update{Phase: PhaseVulns, Done: 5, Total: 100, Unit: UnitChecks})
	if v := tr.View(); v.ETA != nil {
		t.Fatalf("eta before 10 s = %v", *v.ETA)
	}
	c.add(15 * time.Second) // 20 s for 20 checks: 80 left take 80 s
	tr.Report(Update{Phase: PhaseVulns, Done: 20, Total: 100, Unit: UnitChecks})
	v := tr.View()
	if e, _ := val(v.ETA); e != "2026-11-16T08:01:40.000Z" {
		t.Fatalf("eta = %v", e)
	}
	if p, _ := val(v.Percent); p != 20 {
		t.Fatalf("percent = %v", p)
	}
	if d, _ := val(v.Done); d != 20 {
		t.Fatalf("done = %v", d)
	}
	// percent without a count: elapsed * (100 - p) / p
	c2 := newClock()
	tr2 := NewTracker(c2.now)
	tr2.Report(Update{Phase: PhaseServices, Percent: 0})
	c2.add(20 * time.Second)
	tr2.Report(Update{Phase: PhaseServices, Percent: 25})
	if e, _ := val(tr2.View().ETA); e != "2026-11-16T08:01:20.000Z" {
		t.Fatalf("eta from percent = %v", e)
	}
}

func TestANewPassOfAPhaseRestartsIt(t *testing.T) {
	c := newClock()
	tr := NewTracker(c.now)
	tr.Report(Update{Phase: PhasePorts, Percent: 90})
	c.add(time.Minute)
	tr.Report(Update{Phase: PhasePorts, Percent: 5})
	if v := tr.View(); v.PhaseStartedAt != "2026-11-16T08:01:00.000Z" {
		t.Fatalf("phase start = %s", v.PhaseStartedAt)
	}
	c.add(time.Second)
	tr.Report(Update{Phase: PhasePorts, Percent: 4}) // a small step back is the same pass
	if v := tr.View(); v.PhaseStartedAt != "2026-11-16T08:01:00.000Z" {
		t.Fatalf("phase start moved on a small step back: %s", v.PhaseStartedAt)
	}
}

// What a worker or a device may have shaped never reaches a View out of range.
func TestBadReportsAreDroppedOrCut(t *testing.T) {
	c := newClock()
	tr := NewTracker(c.now)
	tr.Report(Update{Phase: "rm -rf", Percent: 50})
	if tr.View() != nil {
		t.Fatal("an unknown phase was kept")
	}
	for _, u := range []Update{
		{Phase: PhasePorts, Percent: math.NaN()},
		{Phase: PhasePorts, Percent: math.Inf(1)},
		{Phase: PhasePorts, Percent: -5},
		{Phase: PhasePorts, Percent: -1, Done: 5, Total: 0, Unit: UnitChecks},
		{Phase: PhasePorts, Percent: -1, Done: -1, Total: 10, Unit: UnitChecks},
		{Phase: PhasePorts, Percent: -1, Done: 1, Total: MaxCount + 1, Unit: UnitChecks},
		{Phase: PhasePorts, Percent: -1, Done: 1, Total: 10, Unit: "bytes"},
		{Phase: PhasePorts, Percent: -1, Remaining: -time.Second},
		{Phase: PhasePorts, Percent: -1, Remaining: MaxRemaining + time.Second},
	} {
		tr.Report(u)
		v := tr.View()
		if v.Percent != nil || v.Done != nil || v.Total != nil || v.Unit != nil || v.ETA != nil {
			t.Fatalf("%+v kept something: %+v", u, v)
		}
	}
	tr.Report(Update{Phase: PhasePorts, Percent: 250})
	if p, _ := val(tr.View().Percent); p != 100 {
		t.Fatalf("percent over 100 = %v", p)
	}
	tr.Report(Update{Phase: PhaseVulns, Done: 12, Total: 10, Unit: UnitChecks})
	if d, _ := val(tr.View().Done); d != 10 {
		t.Fatalf("done over total = %v", d)
	}
	tr.Report(Update{Phase: PhaseVulns, Percent: -1, Message: "a\x00b\u202e\nc" + strings.Repeat("x", 500)})
	m, _ := val(tr.View().Message)
	if strings.ContainsAny(m, "\x00\u202e\n") || len([]rune(m)) != MaxMessage {
		t.Fatalf("message = %q", m)
	}
}

func TestReportFindsTheSinkOfTheContext(t *testing.T) {
	Report(context.Background(), Phase(PhasePorts, "")) // no sink: nothing happens
	tr := NewTracker(nil)
	ctx := WithSink(context.Background(), tr)
	Report(ctx, Phase(PhasePorts, ""))
	if v := tr.View(); v == nil || v.Phase != PhasePorts {
		t.Fatalf("view = %+v", v)
	}
	if SinkFrom(context.Background()) != nil {
		t.Fatal("a sink from nowhere")
	}
}

// Review r1 #7: a pace that would put the end centuries away is capped at MaxRemaining, never an overflowed time.
func TestPaceEstimateIsCapped(t *testing.T) {
	c := newClock()
	tr := NewTracker(c.now)
	tr.Report(Update{Phase: PhaseVulns, Done: 0, Total: MaxCount, Unit: UnitChecks})
	c.add(time.Hour)
	tr.Report(Update{Phase: PhaseVulns, Done: MaxCount / 50, Total: MaxCount, Unit: UnitChecks}) // 2 %: 49 h more at this pace
	if e, _ := val(tr.View().ETA); e != "2026-11-18T09:00:00.000Z" {
		t.Fatalf("eta = %v, want now + MaxRemaining", e)
	}
	c.add(1000 * time.Hour)
	tr.Report(Update{Phase: PhaseServices, Percent: 0})
	c.add(1000000 * time.Hour)
	tr.Report(Update{Phase: PhaseServices, Percent: 1})
	want := c.t.Add(MaxRemaining).UTC().Format("2006-01-02T15:04:05.000Z")
	if e, _ := val(tr.View().ETA); e != want {
		t.Fatalf("eta = %v, want %s", e, want)
	}
}

// #830 FAIL 2: within a pass the bar never goes back. A lower percent keeps what was shown; only a new pass (another phase, a
// report that says so, a tool's own percent falling far) starts lower.
func TestNeverBackwardsWithinAPass(t *testing.T) {
	c := newClock()
	tr := NewTracker(c.now)
	tr.Report(Update{Phase: PhaseVulns, Percent: -1, Done: 170, Total: 200, Unit: UnitChecks})
	c.add(5 * time.Second)
	tr.Report(Update{Phase: PhaseVulns, Percent: -1, Done: 78, Total: 200, Unit: UnitChecks}) // what the N100 showed
	v := tr.View()
	if d, _ := val(v.Done); d != 170 || *v.Percent != 85 || v.PhaseStartedAt != "2026-11-16T08:00:00.000Z" {
		t.Fatalf("after a lower count: done %v percent %v phase start %s, want 170, 85, the same pass", d, *v.Percent, v.PhaseStartedAt)
	}
	tr.Report(Update{Phase: PhaseServices, Percent: 90, Remaining: time.Minute, Message: "first"})
	c.add(5 * time.Second)
	tr.Report(Update{Phase: PhaseServices, Percent: 80, Remaining: 20 * time.Minute, Message: "second"})
	v = tr.View()
	if p, _ := val(v.Percent); p != 90 || *v.ETA != "2026-11-16T08:01:05.000Z" || *v.Message != "first" || v.UpdatedAt != "2026-11-16T08:00:10.000Z" {
		t.Fatalf("held: percent %v eta %v message %v updated %s; want 90 with its own estimate and note, updated now", p, *v.ETA, *v.Message, v.UpdatedAt)
	}
	tr.Report(Update{Phase: PhaseVulns, Percent: -1, Done: 0, Total: 10, Unit: UnitChecks, NewPass: true})
	if d, _ := val(tr.View().Done); d != 0 {
		t.Fatalf("a new pass kept the old count: %v", d)
	}
}

// #830 FAIL 2: the jobs of a Series add up, whatever each reports of its own, and the count of the pass only grows. The reports
// come as the N100's exposure deep scan sent them: one 200-template job after another, each from 0, with a late report of a job
// that already ended.
func TestSeriesAddsItsJobsUp(t *testing.T) {
	c := newClock()
	tr := NewTracker(c.now)
	ctx := WithSink(context.Background(), tr)
	s := NewSeries(ctx, PhaseVulns, 800) // an upper bound
	var seen []float64
	look := func() {
		t.Helper()
		v := tr.View()
		p, _ := val(v.Percent)
		if n := len(seen); n > 0 && p < seen[n-1] {
			t.Fatalf("percent went back: %v after %v", p, seen)
		}
		if n, _ := val(v.Total); n != 800 && n != 600 {
			t.Fatalf("total = %d", n)
		}
		seen = append(seen, p)
	}
	look()
	for job, counts := range [][]int64{{0, 85, 170}, {0, 78, 165}, {0, 140}} {
		jctx, end := s.Job(ctx)
		for _, d := range counts {
			c.add(5 * time.Second)
			Report(jctx, Update{Phase: PhaseVulns, Percent: -1, Done: d, Total: 200, Unit: UnitChecks})
			look()
		}
		end(200)
		look()
		Report(jctx, Update{Phase: PhaseVulns, Percent: -1, Done: 10, Total: 200, Unit: UnitChecks}) // late: dropped
		look()
		if job == 0 {
			s.Plan(600) // the owner knows better now: the pass shrinks, the bar jumps forward
			look()
		}
	}
	v := tr.View()
	if d, _ := val(v.Done); d != 600 || *v.Percent != 100 || v.PhaseStartedAt != "2026-11-16T08:00:00.000Z" {
		t.Fatalf("end: done %v percent %v start %s, want 600, 100, one pass", d, *v.Percent, v.PhaseStartedAt)
	}
	if want := []float64{0, 0, 10.6, 21.3, 25, 25, 33.3, 33.3, 46.3, 60.8, 66.7, 66.7, 66.7, 90, 100, 100}; fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("percents = %v, want %v", seen, want)
	}
}

// The estimate of the end of a Series is the pace of the whole pass.
func TestSeriesEstimateFollowsThePass(t *testing.T) {
	c := newClock()
	tr := NewTracker(c.now)
	ctx := WithSink(context.Background(), tr)
	s := NewSeries(ctx, PhaseVulns, 400)
	jctx, end := s.Job(ctx)
	c.add(10 * time.Second)
	Report(jctx, Update{Phase: PhaseVulns, Percent: -1, Done: 100, Total: 200, Unit: UnitChecks})
	c.add(10 * time.Second)
	end(200) // 200 of 400 in 20 s: 200 left take 20 s
	if e, _ := val(tr.View().ETA); e != "2026-11-16T08:00:40.000Z" {
		t.Fatalf("eta = %v", e)
	}
	jctx, _ = s.Job(ctx)
	c.add(10 * time.Second)
	Report(jctx, Update{Phase: PhaseVulns, Percent: -1, Done: 100, Total: 200, Unit: UnitChecks}) // 300 in 30 s: 100 left take 10 s
	if e, _ := val(tr.View().ETA); e != "2026-11-16T08:00:40.000Z" {
		t.Fatalf("eta = %v", e)
	}
}

// Reports of a Series from many goroutines (the worker's two readers, the owner) never take the bar back; run with -race.
func TestSeriesIsMonotonicUnderConcurrentReports(t *testing.T) {
	tr := NewTracker(nil)
	ctx := WithSink(context.Background(), tr)
	s := NewSeries(ctx, PhaseVulns, 4*100)
	stop := make(chan struct{})
	var last float64
	watched := make(chan error, 1)
	go func() {
		defer close(watched)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if v := tr.View(); v != nil && v.Percent != nil {
				if *v.Percent < last {
					watched <- fmt.Errorf("percent went back from %v to %v", last, *v.Percent)
					return
				}
				last = *v.Percent
			}
		}
	}()
	for range 4 {
		jctx, end := s.Job(ctx)
		var wg sync.WaitGroup
		for g := range 3 {
			wg.Go(func() {
				for d := int64(g); d <= 100; d += 3 {
					Report(jctx, Update{Phase: PhaseVulns, Percent: -1, Done: d, Total: 100, Unit: UnitChecks})
				}
			})
		}
		wg.Wait()
		end(100)
	}
	close(stop)
	if err := <-watched; err != nil {
		t.Fatal(err)
	}
	if d, _ := val(tr.View().Done); d != 400 {
		t.Fatalf("done = %d, want 400", d)
	}
}
