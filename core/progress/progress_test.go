package progress

import (
	"context"
	"math"
	"strings"
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
	tr.Report(Update{Phase: PhaseVulns, Percent: -1, Message: "a\x00b‮\nc" + strings.Repeat("x", 500)})
	m, _ := val(tr.View().Message)
	if strings.ContainsAny(m, "\x00‮\n") || len([]rune(m)) != MaxMessage {
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
