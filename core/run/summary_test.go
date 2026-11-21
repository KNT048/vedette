package run_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/run"
)

// Every run reads as one line of words made by the box: what a queued run waits for (with the run that holds its lane), what a
// waiting one waits for and how far it got with the kind's unit and estimate, why a stopped one stopped.
func TestTheSummaryOfARunAndTheRunAQueuedOneWaitsFor(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	g := newGated()
	sweep := g.kind("sensor-active", "lan_sweep", "nmap", true)
	sweep.Unit = "addresses"
	sweep.Estimate = func(context.Context, run.Run) string { return "about 9 more windows at 50 packets/s" }
	p := b.process(nil, sweep, g.kind("sensor-active", "device_check", "nmap", false))
	p.start(t)
	s := spec("sensor-active", "lan_sweep", "LAN sweep of 10.20.0.0/16")
	s.Steps = []run.StepPlan{{Name: "10.20.0.0/16", Total: 65534}}
	first := create(t, p, s)
	x := g.waitStarted(t)
	if err := x.Progress(t.Context(), 1, 6272, 65534); err != nil {
		t.Fatal(err)
	}
	check := create(t, p, spec("sensor-active", "device_check", "Check of printer"))
	r := b.get(p, check)
	if r.BlockedBy == nil || r.BlockedBy.ID != first || r.Summary != "Queued behind “LAN sweep of 10.20.0.0/16”; it starts when that run ends" {
		t.Fatalf("queued: %+v", r.Run)
	}
	if r := b.get(p, first); r.Summary != "6,272 of 65,534 addresses; about 9 more windows at 50 packets/s" || r.BlockedBy != nil {
		t.Fatalf("running: %q", r.Summary)
	}
	g.release <- run.Result{Status: run.Waiting, WaitingFor: "the scan window (opens Mon 23:00)"}
	p.waitEnded(t, first)
	if r := b.get(p, first); r.Summary != "Waiting for the scan window (opens Mon 23:00); 6,272 of 65,534 addresses; about 9 more windows at 50 packets/s" {
		t.Fatalf("waiting: %q", r.Summary)
	}
	g.waitStarted(t) // the check had the lane once the sweep waited
	if err := p.Stop(t.Context(), check, "ann@example.com", ""); err != nil {
		t.Fatal(err)
	}
	p.waitEnded(t, check)
	if r := b.get(p, check); r.Summary != "Stopped by ann@example.com" {
		t.Fatalf("stopped: %q", r.Summary)
	}
}

// A run made waiting holds no place in its lane's queue until it is resumed; the context of a kind's Run names its run; a subject
// gone or moved inside the caller's transaction stops or moves its runs.
func TestARunMadeWaitingTheRunInTheContextAndTheSubjectRules(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	var seen string
	p := b.process(nil, run.Kind{Module: "sensor-active", Name: "device_check", Lane: "nmap", Run: func(ctx context.Context, _ *run.Exec) (run.Result, error) {
		seen = run.IDFrom(ctx)
		return run.Result{}, nil
	}})
	p.start(t)
	s := spec("sensor-active", "device_check", "Check of printer")
	s.Subject = &run.Subject{Kind: "device", ID: "a-1", Label: "printer"}
	s.WaitingFor = "the scan window (opens 23:00)"
	id := create(t, p, s)
	if r := b.get(p, id); r.Status != run.Waiting || r.StartedAt != nil || !strings.HasPrefix(r.Summary, "Waiting for the scan window") {
		t.Fatalf("made waiting: %+v", r.Run)
	}
	if err := p.Resume(t.Context(), id, run.System); err != nil {
		t.Fatal(err)
	}
	p.waitEnded(t, id)
	if seen != id {
		t.Fatalf("the Run's context named %q, want %q", seen, id)
	}
	other := create(t, p, s) // waiting again for the same device
	if err := b.db.Write(t.Context(), func(tx *sql.Tx) error {
		if err := p.SubjectMovedTx(t.Context(), tx, "sensor-active", "device", "a-1", "a-2"); err != nil {
			return err
		}
		return p.SubjectGoneTx(t.Context(), tx, "sensor-active", "device", "a-2", "The device was deleted")
	}); err != nil {
		t.Fatal(err)
	}
	if r := b.get(p, id); r.Subject.ID != "a-2" || r.Status != run.Done {
		t.Fatalf("the ended run after a merge: %+v", r.Run)
	}
	if r := b.get(p, other); r.Status != run.Stopped || r.StopReason == nil || *r.StopReason != "The device was deleted" {
		t.Fatalf("the waiting run of a deleted device: %+v", r.Run)
	}
	b.invariantsHold()
}
