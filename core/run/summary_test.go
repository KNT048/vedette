package run_test

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

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
	// the run in its way says how long it has left: the queued one starts roughly then
	if r.BlockedBy == nil || r.BlockedBy.ID != first ||
		r.Summary != "Queued behind “LAN sweep of 10.20.0.0/16”, which has about 9 more windows at 50 packets/s; it starts when that run ends" {
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

// What a waiting run waits for can change while it waits (the window opened while the scan worker is not ready yet): Rewait says
// the new reason on the run and in its log, leaves a run that waits for it already as it is, and never touches a run that is not
// waiting.
func TestRewaitChangesOnlyWhatAWaitingRunWaitsFor(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	g := newGated()
	p := b.process(nil, g.kind("sensor-active", "device_check", "nmap", true))
	p.start(t)
	s := spec("sensor-active", "device_check", "Check of printer")
	s.WaitingFor = "its turn in the scan window"
	waiting := create(t, p, s)
	queued := create(t, p, spec("sensor-active", "device_check", "Check of router"))
	g.waitStarted(t)
	if err := p.Rewait(t.Context(), "the scan worker to be available", waiting, queued, "run_missing"); err != nil {
		t.Fatal(err)
	}
	if err := p.Rewait(t.Context(), "the scan worker to be available", waiting); err != nil { // the same reason again: nothing new
		t.Fatal(err)
	}
	r := b.get(p, waiting)
	if r.Status != run.Waiting || r.Summary != "Waiting for the scan worker to be available" {
		t.Fatalf("the waiting run: %+v", r.Run)
	}
	if got := strings.Count(b.logText(p, waiting), "Waiting for the scan worker to be available"); got != 1 {
		t.Fatalf("the log says the new reason %d times, want once:\n%s", got, b.logText(p, waiting))
	}
	if r := b.get(p, queued); r.Status != run.Running || r.WaitingFor != nil {
		t.Fatalf("a run that was not waiting changed: %+v", r.Run)
	}
	if err := p.Rewait(t.Context(), "", waiting); err == nil {
		t.Fatal("an empty reason was accepted")
	}
	g.release <- run.Result{}
	p.waitEnded(t, queued)
	b.invariantsHold()
}

// A queued run says its place in line and when it starts, adding up the run in its way and every run queued before it as far as
// their kinds can tell (Kind.Hold): not only the run that holds the lane now. A run that waits for its module to be turned on is not
// ahead of it (the dispatcher passes it by).
func TestAQueuedRunSaysItsPlaceInLineAndWhenItStarts(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	g := newGated()
	holds := map[string]time.Duration{"LAN sweep of 10.20.0.0/16": 10 * time.Minute, "Check of printer": 5 * time.Minute, "Check of router": 0}
	hold := func(_ context.Context, r run.Run) (time.Duration, bool) {
		d, ok := holds[r.Title]
		return d, ok
	}
	sweep := g.kind("sensor-active", "lan_sweep", "nmap", true)
	sweep.Hold = hold
	check := g.kind("sensor-active", "device_check", "nmap", false)
	check.Hold = hold
	other := g.kind("scan", "vuln_identify", "nmap", false)
	gt := &gate{}
	p := b.process(gt, sweep, check, other)
	p.start(t)
	create(t, p, spec("sensor-active", "lan_sweep", "LAN sweep of 10.20.0.0/16"))
	g.waitStarted(t)
	gt.setScan(false)
	b.clock.Advance(time.Second)
	create(t, p, spec("scan", "vuln_identify", "Identification for the vulnerability checks")) // its module is off: never ahead
	b.clock.Advance(time.Second)
	first := create(t, p, spec("sensor-active", "device_check", "Check of printer"))
	b.clock.Advance(time.Second)
	second := create(t, p, spec("sensor-active", "device_check", "Check of NAS")) // its kind cannot tell how long it takes
	b.clock.Advance(time.Second)
	third := create(t, p, spec("sensor-active", "device_check", "Check of router"))
	b.clock.Advance(time.Second)
	fourth := create(t, p, spec("sensor-active", "device_check", "Check of camera"))
	for id, want := range map[string]string{
		first:  "Queued behind “LAN sweep of 10.20.0.0/16”; it starts in about 10 minutes",
		second: "Queued behind “LAN sweep of 10.20.0.0/16” and 1 run queued before it (2nd in line); it starts in about 15 minutes",
		third:  "Queued behind “LAN sweep of 10.20.0.0/16” and 2 runs queued before it (3rd in line); it starts in more than 15 minutes",
		fourth: "Queued behind “LAN sweep of 10.20.0.0/16” and 3 runs queued before it (4th in line); it starts in more than 15 minutes",
	} {
		if r := b.get(p, id); r.Summary != want {
			t.Errorf("%s: %q, want %q", r.Title, r.Summary, want)
		}
	}
	// the list reads the same lines
	runs, _, err := p.List(t.Context(), run.Filter{Kind: "device_check"})
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 4 || !strings.Contains(runs[0].Summary, "(4th in line)") {
		t.Fatalf("the list: %+v", runs)
	}
	g.release <- run.Result{}
	x := g.waitStarted(t)
	if x.ID() != first {
		t.Fatalf("started %s, want the first queued check %s", x.ID(), first)
	}
	if r := b.get(p, third); r.Summary != "Queued behind “Check of printer” and 1 run queued before it (2nd in line); it starts in more than 5 minutes" {
		t.Errorf("after the sweep: %q", r.Summary)
	}
	for _, id := range []string{first, second, third, fourth} {
		if id != first {
			g.waitStarted(t)
		}
		g.release <- run.Result{}
		p.waitEnded(t, id)
	}
	b.invariantsHold()
}

// The words of a long line: the place in line past the teens, a wait in hours, and a holder that lets the lane go at once.
func TestTheWordsOfALongLine(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	g := newGated()
	k := g.kind("sensor-active", "device_check", "nmap", false)
	k.Hold = func(_ context.Context, r run.Run) (time.Duration, bool) {
		if r.Status == run.Running {
			return 0, true // it gives the lane up at once
		}
		return 2 * time.Hour, true
	}
	p := b.process(nil, k)
	p.start(t)
	create(t, p, spec("sensor-active", "device_check", "Check of printer"))
	g.waitStarted(t)
	ids := make([]string, 22)
	for i := range ids {
		b.clock.Advance(time.Second)
		ids[i] = create(t, p, spec("sensor-active", "device_check", fmt.Sprintf("Check %d", i+1)))
	}
	for i, want := range map[int]string{
		0:  "Queued behind “Check of printer”; it starts in about a minute",
		1:  "Queued behind “Check of printer” and 1 run queued before it (2nd in line); it starts in about 2 hours",
		10: "Queued behind “Check of printer” and 10 runs queued before it (11th in line); it starts in about 20 hours",
		21: "Queued behind “Check of printer” and 21 runs queued before it (22nd in line); it starts in about 42 hours",
	} {
		if r := b.get(p, ids[i]); r.Summary != want {
			t.Errorf("%s: %q, want %q", r.Title, r.Summary, want)
		}
	}
}
