package sensoractive_test

import (
	"database/sql"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/store"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// waitingPass creates a LAN pass over the env's ranges that waits for the scan window, as the window's pass or an old person's pass
// leaves it: trigger and by say who started it, ago how long ago it was queued and started (0: it never started).
func waitingPass(t *testing.T, e *env, trigger run.Trigger, by string, ago time.Duration) string {
	t.Helper()
	st, err := e.inv.Settings(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	ranges := st.LANRanges
	var steps []run.StepPlan
	for _, r := range ranges {
		steps = append(steps, run.StepPlan{Name: r, Total: rangeHosts(t, r)})
	}
	id, err := e.svc.Runs().Create(e.ctx(), run.Spec{Module: sa.ModuleID, Kind: sa.RunSweep, Title: "LAN sweep of " + strings.Join(ranges, ", "),
		Trigger: trigger, RequestedBy: by, Subject: &run.Subject{Kind: "scope", ID: "lan", Label: strings.Join(ranges, ", ")}, Steps: steps,
		WaitingFor: "the scan window (opens 10 Nov 2026, 01:00)"})
	if err != nil {
		t.Fatal(err)
	}
	if ago > 0 {
		at := store.FormatTS(e.clock().Add(-ago))
		if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
			_, err := tx.ExecContext(e.ctx(), `UPDATE core_run SET queued_at = ?, started_at = ? WHERE id = ?`, at, at, id)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

// rangeHosts is the addresses a sweep walks in an IPv4 CIDR: all but the network and broadcast address.
func rangeHosts(t *testing.T, cidr string) int {
	t.Helper()
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return 1<<(32-p.Bits()) - 2
}

// The class: a person's ask of a LAN pass ("Scan the LAN now" on a pass that waits, or the run page's Start now) must make the pass go
// now, outside the scan window, and keep going after Vedette restarts, for the person's hour. Each case below is one way a person asks;
// the count of cases where the pass waited for the window instead is the number in the pull request (before the fix 4 of 4: the ask
// lived only in memory, or was not seen at all for Start now).
func TestCountAPersonsAskOfAPassHoldsNowAndAfterARestart(t *testing.T) {
	t.Parallel()
	type ask struct {
		name    string
		ranges  string
		rate    int
		trigger run.Trigger
		by      string
		ago     time.Duration
		scanNow bool // Scan the LAN now, else Start now on the run page
		restart bool // Vedette restarts while the pass sweeps its first batch
	}
	cases := []ask{
		{name: "Start now on the window's waiting pass", ranges: "192.168.10.0/26", rate: 100, trigger: run.Schedule, by: run.System},
		{name: "Start now on the window's waiting pass, then a restart", ranges: "192.168.10.0/26", rate: 100, trigger: run.Schedule, by: run.System, restart: true},
		{name: "Start now on a person's pass whose hour is over", ranges: "192.168.10.0/26", rate: 100, trigger: run.Manual, by: "ann@example.com", ago: 4 * time.Hour},
		{name: "Scan the LAN now on a long waiting pass, then a restart", ranges: "192.168.0.0/20", rate: 1, trigger: run.Manual, by: "ann@example.com", ago: 4 * time.Hour, scanNow: true, restart: true},
	}
	waited := 0
	for _, c := range cases {
		e := newEnv(t, fakeOpts{}, outsideWindow, func(e *env) {
			e.inv.set(func(s *sa.Settings) { s.LANRanges, s.Rate = []string{c.ranges}, c.rate })
		})
		e.sweptBefore()
		id := waitingPass(t, e, c.trigger, c.by, c.ago)
		g := newGate()
		if c.restart {
			e.withProber(g)
		}
		if c.scanNow {
			m, err := e.svc.StartManual(e.ctx(), "bob@example.com", nil, nil)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if m.ID != id {
				t.Fatalf("%s: a pass of many windows goes on, it is not replaced (%s, want %s)", c.name, m.ID, id)
			}
		} else if err := e.svc.Runs().Resume(e.ctx(), id, "bob@example.com"); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if c.restart {
			select {
			case <-g.started: // the first batch is in nmap
			case <-time.After(10 * time.Second): // the pass never sent a batch: it waits (counted below)
			}
			e.withProber(e.prober()) // Vedette restarts mid-batch with a scan worker that reports
		}
		r := waitRun(t, e, id, run.Done, run.Waiting, run.Failed, run.Partial, run.Stopped)
		if r.Status != run.Done {
			waited++
			t.Errorf("%s: %s (%s) | %s", c.name, r.Status, r.Summary, logOf(t, e, id))
		}
	}
	t.Logf("a person's ask that left the pass waiting for the window: %d of %d", waited, len(cases))
}

// Scan the LAN now on a waiting pass of a scope one person's hour sweeps whole starts a fresh pass (the LAN as it is now), and the old
// one ends saying why; it is never a second pass going at once.
func TestScanTheLANNowReplacesAShortWaitingPass(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow)
	e.sweptBefore()
	old := waitingPass(t, e, run.Manual, "ann@example.com", 4*time.Hour)
	m, err := e.svc.StartManual(e.ctx(), "bob@example.com", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID == old {
		t.Fatal("the 4-hour-old pass was reused")
	}
	if r := waitRun(t, e, m.ID, run.Done, run.Waiting, run.Failed, run.Partial, run.Stopped); r.Status != run.Done {
		t.Fatalf("the fresh pass: %s (%s)", r.Status, r.Summary)
	}
	if r := waitRun(t, e, old, run.Stopped); !strings.Contains(r.Summary, "new sweep") {
		t.Fatalf("the old pass says why it ended: %q", r.Summary)
	}
}

// A pass a person asked for that waits for the scan worker past the person's hour reads, outside the window, that it waits for the
// window (its log says so), instead of "Waiting for the scan worker" for hours with nothing in its log.
func TestAPassLeftWaitingForTheWorkerSaysItWaitsForTheWindow(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow)
	e.sweptBefore()
	id := waitingPass(t, e, run.Manual, "ann@example.com", 4*time.Hour)
	if err := e.svc.Runs().Rewait(e.ctx(), "the scan worker to be available", id); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	r := waitRun(t, e, id, run.Waiting)
	if r.WaitingFor == nil || !strings.HasPrefix(*r.WaitingFor, "the scan window") || !strings.Contains(logOf(t, e, id), "Waiting for the scan window") {
		t.Fatalf("%s | %s", r.Summary, logOf(t, e, id))
	}
}

// A person's check queued behind another when Vedette restarts, and dispatched while the scan worker has not reported yet, waits for
// it without having started: its Started time is when it really began, after the worker reported, not the restart.
func TestACheckThatOnlyWaitedForTheWorkerHasNotStarted(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow)
	e.sweptBefore()
	g := newGate()
	e.withProber(g)
	first, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	g.wait(t, 1)
	second, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-printer"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := &reportingWorker{}
	e.withProber(w) // Vedette restarts; the scan worker has not reported yet
	r := waitRun(t, e, second.ID, run.Waiting)
	waitRun(t, e, first.ID, run.Waiting)
	if r.StartedAt != nil || strings.Contains(logOf(t, e, second.ID), "Started") {
		t.Fatalf("a check that only waited for the worker: started %v | %s", *r.StartedAt, logOf(t, e, second.ID))
	}
	if r, _ := e.svc.Runs().Read(e.ctx(), first.ID); r.StartedAt == nil {
		t.Fatal("the check that ran before the restart keeps its start")
	}
	w.report(false)
	sa.WaitBackground(e.svc)
	if r := waitRun(t, e, second.ID, run.Done, run.Failed, run.Partial, run.Stopped); r.StartedAt == nil || r.Status != run.Done {
		t.Fatalf("the check once the worker reported: %s, started %v", r.Status, r.StartedAt)
	}
}
