package run_test

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/run"
)

// A run whose first turn only finds it must wait (the scan worker had not reported) has not started: no started time, no "Started"
// line, its step not started. Its next turn that really works is its start. A run that began before keeps its start when a later turn
// waits.
func TestARunThatWaitsBeforeAnyWorkIsNotStarted(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	g := newGated()
	p := b.process(nil, g.kind("sensor-active", "device_check", "nmap", true))
	p.start(t)
	s := spec("sensor-active", "device_check", "Check of printer")
	s.Steps = []run.StepPlan{{Name: "printer", Total: 1}}
	id := create(t, p, s)
	x := g.waitStarted(t)
	if err := x.StartStep(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	g.release <- run.Result{Status: run.Waiting, WaitingFor: "the scan worker to be available", NotBegun: true}
	p.waitEnded(t, id)
	d := b.get(p, id)
	if d.Status != run.Waiting || d.StartedAt != nil || d.Steps[0].StartedAt != nil {
		t.Fatalf("after a first turn that only waited: status %s, started %v, step started %v", d.Status, d.StartedAt, d.Steps[0].StartedAt)
	}
	if l := b.logText(p, id); strings.Contains(l, "Started") || !strings.Contains(l, "Waiting for the scan worker to be available") {
		t.Fatalf("log: %s", l)
	}
	b.clock.Advance(20 * time.Minute)
	if err := p.Resume(t.Context(), id, run.System); err != nil {
		t.Fatal(err)
	}
	x = g.waitStarted(t)
	if x.Resumed {
		t.Fatal("a run that never began is not a resumed one")
	}
	d = b.get(p, id)
	if d.StartedAt == nil || *d.StartedAt != "2026-03-02T10:20:00.000Z" || d.RunningSince == nil || *d.RunningSince != *d.StartedAt {
		t.Fatalf("the turn that works starts it: started %v, running since %v", d.StartedAt, d.RunningSince)
	}
	// this turn works, then waits for the window; a later turn that waits before any work keeps the start of a run that began
	g.release <- run.Result{Status: run.Waiting, WaitingFor: "the scan window (opens 23:00)"}
	p.waitEnded(t, id)
	if err := p.Resume(t.Context(), id, run.System); err != nil {
		t.Fatal(err)
	}
	if x = g.waitStarted(t); !x.Resumed {
		t.Fatal("a run that began is resumed")
	}
	g.release <- run.Result{Status: run.Waiting, WaitingFor: "the scan worker to be available", NotBegun: true}
	p.waitEnded(t, id)
	if d = b.get(p, id); d.StartedAt == nil || *d.StartedAt != "2026-03-02T10:20:00.000Z" {
		t.Fatalf("a run that began keeps its start: %v", d.StartedAt)
	}
}

// RunningSince is the start of a running run's current turn: after a restart and a resume it is the new turn, not the first start.
func TestRunningSinceIsTheCurrentTurn(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	g := newGated()
	k := g.kind("sensor-active", "device_check", "nmap", true)
	p := b.process(nil, k)
	p.start(t)
	s := spec("sensor-active", "device_check", "Check of printer")
	s.Steps = []run.StepPlan{{Name: "printer", Total: 1}}
	id := create(t, p, s)
	g.waitStarted(t)
	p.Close() // Vedette stops: the run is left running and the next start recovers it
	b.clock.Advance(25 * time.Minute)
	p2 := b.process(nil, k)
	p2.start(t)
	g.waitStarted(t)
	d := b.get(p2, id)
	if d.StartedAt == nil || *d.StartedAt != "2026-03-02T10:00:00.000Z" || d.RunningSince == nil || *d.RunningSince != "2026-03-02T10:25:00.000Z" {
		t.Fatalf("started %v, running since %v", d.StartedAt, d.RunningSince)
	}
	g.release <- run.Result{}
	p2.waitEnded(t, id)
	if d = b.get(p2, id); d.RunningSince != nil {
		t.Fatalf("an ended run has no current turn: %v", *d.RunningSince)
	}
}

// Asked is a person's latest ask of a run and the first turn after it: the queue time of a run a person started, or a person's resume
// of any run (a run the box queued, too); nothing for a run nobody asked for. It is read from the database, so a new process reads it.
func TestAskedIsThePersonsLatestAskAndTheTurnAfterIt(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	g := newGated()
	k := g.kind("sensor-active", "lan_sweep", "nmap", true)
	p := b.process(nil, k)
	p.start(t)
	s := run.Spec{Module: "sensor-active", Kind: "lan_sweep", Title: "LAN sweep", Trigger: run.Schedule, RequestedBy: run.System,
		WaitingFor: "the scan window (opens 23:00)"}
	id := create(t, p, s)
	r, _ := p.Read(t.Context(), id)
	if asked, began, err := p.Asked(t.Context(), r); err != nil || !asked.IsZero() || !began.IsZero() {
		t.Fatalf("a run nobody asked for: %v %v %v", asked, began, err)
	}
	b.clock.Advance(time.Hour)
	if err := p.Resume(t.Context(), id, "ann@example.com"); err != nil {
		t.Fatal(err)
	}
	g.waitStarted(t)
	p.Close()
	b.clock.Advance(10 * time.Minute)
	p2 := b.process(nil, k)
	p2.start(t)
	g.waitStarted(t)
	r, _ = p2.Read(t.Context(), id)
	asked, began, err := p2.Asked(t.Context(), r)
	want := time.Date(2026, 3, 2, 11, 0, 0, 0, time.UTC)
	if err != nil || !asked.Equal(want) || !began.Equal(want) {
		t.Fatalf("after a person's resume and a restart: asked %v, began %v (%v), want both %v", asked, began, err, want)
	}

	m := create(t, p2, spec("sensor-active", "lan_sweep", "LAN sweep again")) // a person's own run: its queue time is the ask
	r, _ = p2.Read(t.Context(), m)
	if asked, began, err := p2.Asked(t.Context(), r); err != nil || !asked.Equal(want.Add(10*time.Minute)) || !began.IsZero() {
		t.Fatalf("a person's queued run: asked %v, began %v (%v)", asked, began, err)
	}
}
