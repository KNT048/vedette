package run_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/run"
)

// The Runs tab lists runs by the time they started, the time its Started column shows: a run queued early that started late is listed
// where it started, and a run that has not started yet is listed by the time it was queued.
func TestTheRunsAreListedByWhenTheyStarted(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	p := b.process(nil, run.Kind{Module: "scan", Name: "quiet", Lane: "quiet", Run: func(context.Context, *run.Exec) (run.Result, error) { return run.Result{}, nil }})
	insert := func(id, queued, started string) {
		t.Helper()
		err := b.db.Write(t.Context(), func(tx *sql.Tx) error {
			_, err := tx.ExecContext(t.Context(), `INSERT INTO core_run (id, module, kind, lane, title, trigger, requested_by, status, queued_at, started_at, ended_at, updated_at)
				VALUES (?1, 'scan', 'quiet', 'quiet', ?1, 'manual', 'ann@example.com', CASE WHEN ?3 IS NULL THEN 'waiting' ELSE 'done' END, ?2, ?3, ?3, ?2)`,
				id, queued, sql.NullString{String: started, Valid: started != ""})
			if err != nil {
				return err
			}
			if started == "" {
				_, err = tx.ExecContext(t.Context(), `UPDATE core_run SET waiting_for = 'the scan window' WHERE id = ?`, id)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	insert("check-queued-early", "2026-11-23T20:30:00.000Z", "2026-11-24T00:05:00.000Z") // waited for the window, started last
	insert("sweep", "2026-11-24T00:00:00.000Z", "2026-11-24T00:01:00.000Z")
	insert("check", "2026-11-24T00:02:00.000Z", "2026-11-24T00:02:30.000Z")
	insert("waiting", "2026-11-24T00:03:00.000Z", "") // not started: listed by when it was queued
	runs, _, err := p.List(t.Context(), run.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range runs {
		got = append(got, r.ID)
	}
	if strings.Join(got, " ") != "check-queued-early waiting check sweep" {
		t.Fatalf("listed %q, want check-queued-early waiting check sweep", got)
	}
}

// A waiting run says what it waits for and how far it got, never a time left: nothing moves while it waits.
func TestAWaitingRunSaysWhatItWaitsForNotATimeLeft(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	g := newGated()
	sweep := g.kind("sensor-active", "lan_sweep", "nmap", true)
	sweep.Unit = "addresses"
	sweep.Estimate = func(context.Context, run.Run) string { return "less than a minute left" }
	p := b.process(nil, sweep)
	p.start(t)
	s := spec("sensor-active", "lan_sweep", "LAN sweep of 192.0.2.0/24")
	s.Steps = []run.StepPlan{{Name: "192.0.2.0/24", Total: 268}}
	id := create(t, p, s)
	x := g.waitStarted(t)
	if err := x.Progress(t.Context(), 1, 254, 268); err != nil {
		t.Fatal(err)
	}
	g.release <- run.Result{Status: run.Waiting, WaitingFor: "the scan worker to be available"}
	p.waitEnded(t, id)
	if r := b.get(p, id); r.Summary != "Waiting for the scan worker to be available; 254 of 268 addresses" {
		t.Fatalf("waiting: %q", r.Summary)
	}
}

// A long wait in hours rounds to the nearest hour: 3 hours and 10 minutes ahead is "about 3 hours", not 4.
func TestAWaitInHoursRoundsToTheNearestHour(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		hold time.Duration
		want string
	}{
		{3*time.Hour + 10*time.Minute, "about 3 hours"},
		{2*time.Hour + 40*time.Minute, "about 3 hours"},
		{61*time.Minute + 20*time.Second, "about 62 minutes"}, // minutes still round up: a wait is never shorter than it says
	} {
		b := newBox(t)
		g := newGated()
		holder := g.kind("sensor-active", "lan_sweep", "nmap", true)
		holder.Hold = func(context.Context, run.Run) (time.Duration, bool) { return c.hold, true }
		p := b.process(nil, holder, g.kind("sensor-active", "device_check", "nmap", false))
		p.start(t)
		create(t, p, spec("sensor-active", "lan_sweep", "LAN sweep of 192.0.2.0/24"))
		g.waitStarted(t)
		id := create(t, p, spec("sensor-active", "device_check", "Check of printer"))
		if r := b.get(p, id); !strings.HasSuffix(r.Summary, "; it starts in "+c.want) {
			t.Errorf("hold %s: %q, want it to end in %q", c.hold, r.Summary, c.want)
		}
		g.release <- run.Result{}
	}
}

// A waiting run whose cause never comes back gives up: it ends failed with the words of why, its steps with it, and the invariants
// hold. Only a waiting run can give up.
func TestAWaitingRunGivesUpWithWords(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	g := newGated()
	p := b.process(nil, g.kind("sensor-active", "device_check", "nmap", false))
	p.start(t)
	s := spec("sensor-active", "device_check", "Check of printer")
	s.Steps = []run.StepPlan{{Name: "printer", Total: 1}}
	s.WaitingFor = "the scan worker to be available"
	id := create(t, p, s)
	const why = "The scan worker did not report for 30 minutes, so the check did not run"
	if err := p.GiveUp(t.Context(), id, why); err != nil {
		t.Fatal(err)
	}
	r := b.get(p, id)
	if r.Status != run.Failed || r.Summary != "Failed: "+why || r.EndedAt == nil || r.Steps[0].Status != run.Failed {
		t.Fatalf("gave up: %+v", r)
	}
	if !strings.HasSuffix(b.logText(p, id), "Failed: "+why) {
		t.Fatalf("log: %s", b.logText(p, id))
	}
	if err := p.GiveUp(t.Context(), id, why); !errors.Is(err, run.ErrNotLive) {
		t.Fatalf("giving up an ended run: %v", err)
	}
	b.invariantsHold()
}

// The box resuming a run writes "Queued again", and the start writes "Resumed": the log does not say "Resumed" twice for one resume.
func TestTheBoxResumingARunSaysResumedOnce(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	g := newGated()
	p := b.process(nil, g.kind("sensor-active", "device_check", "nmap", true))
	p.start(t)
	s := spec("sensor-active", "device_check", "Check of printer")
	s.WaitingFor = "its turn in the scan window"
	id := create(t, p, s)
	if err := p.Resume(t.Context(), id, run.System); err != nil {
		t.Fatal(err)
	}
	g.waitStarted(t)
	g.release <- run.Result{}
	p.waitEnded(t, id)
	if got := b.logText(p, id); strings.Count(got, "Resumed") > 1 || !strings.Contains(got, "Queued again") {
		t.Fatalf("log: %s", got)
	}
}
