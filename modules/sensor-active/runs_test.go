package sensoractive_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/run"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

var emptyScan = []byte(`<?xml version="1.0" encoding="UTF-8"?><nmaprun scanner="nmap" args="nmap" version="7.95" xmloutputversion="1.05"></nmaprun>`)

// heldProber answers every nmap job at once with an empty scan, except the call numbers in hold (1-based), which wait until release
// is closed or their context ends (a restart, a stop).
type heldProber struct {
	mu      sync.Mutex
	argv    [][]string
	hold    map[int]bool
	started chan int
	release chan struct{}
}

func newHeld(hold ...int) *heldProber {
	h := &heldProber{hold: map[int]bool{}, started: make(chan int, 16), release: make(chan struct{})}
	for _, n := range hold {
		h.hold[n] = true
	}
	return h
}

func (h *heldProber) Probe(ctx context.Context, argv []string) (sa.Output, error) {
	h.mu.Lock()
	h.argv = append(h.argv, slices.Clone(argv))
	n := len(h.argv)
	h.mu.Unlock()
	h.started <- n
	if h.hold[n] {
		select {
		case <-h.release:
		case <-ctx.Done():
			return sa.Output{}, ctx.Err()
		}
	}
	return sa.Output{XML: emptyScan}, nil
}

func (h *heldProber) calls() [][]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.argv)
}

func (h *heldProber) wait(t *testing.T, n int) {
	t.Helper()
	for {
		select {
		case got := <-h.started:
			if got >= n {
				return
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("nmap call %d never came", n)
		}
	}
}

func sweepRuns(e *env) []run.Run {
	e.t.Helper()
	runs, _, err := e.svc.Runs().List(e.ctx(), run.Filter{Module: sa.ModuleID, Kind: sa.RunSweep})
	if err != nil {
		e.t.Fatal(err)
	}
	return runs
}

// A restart in the middle of a pass loses nothing: core/run records the run stopped by the restart and queues it again, and it goes
// on from its cursor (the done count of its step) in the same run.
func TestRunsARestartMidSweepGoesOnFromTheCursor(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, func(e *env) {
		e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/25"} }) // 126 addresses: batches of 64 and 62
	})
	held := newHeld(2)
	e.withProber(held)
	errc := make(chan error, 1)
	go func() { _, err := e.svc.DiscoverRanges(context.WithoutCancel(e.ctx())); errc <- err }()
	held.wait(t, 2) // the first batch is recorded; the second one is in nmap
	before := sweepRuns(e)
	if len(before) != 1 || before[0].Done != 64 {
		t.Fatalf("before the restart: %+v", before)
	}
	again := newHeld()
	e.withProber(again) // the process stops and a new one starts
	<-errc
	waitFor(t, "the pass to end after the restart", func() bool {
		r := sweepRuns(e)
		return len(r) == 1 && r[0].Status == run.Done
	})
	after := sweepRuns(e)
	if len(after) != 1 || after[0].ID != before[0].ID || after[0].Done != 126 || after[0].Total != 126 {
		t.Fatalf("after the restart: %+v, want the same run done with 126 of 126 addresses", after)
	}
	calls := again.calls()
	if len(calls) != 1 || targetsOf(calls[0])[0] != "192.168.10.65" {
		t.Fatalf("after the restart nmap ran %q, want the second batch only, from the cursor", calls)
	}
	d, err := e.svc.Runs().Get(e.ctx(), after[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	var log []string
	for _, l := range d.Log {
		log = append(log, l.Text)
	}
	if !slices.Contains(log, "Stopped: "+run.RestartReason) || !slices.Contains(log, "Queued again to continue after the restart") {
		t.Fatalf("log %q: the restart is not said", log)
	}
}

// A /16 a person typed is one run across windows: the window closes, the pass waits with its cursor and true progress, and the next
// window goes on with the same run.
func TestRunsAWideRangeIsOneRunAcrossWindows(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, func(e *env) {
		e.setBase(local(9, 4, 59).Add(50 * time.Second)) // 10 s to the end of the window
		e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"10.20.0.0/16"}; s.Rate = 1000 })
		e.inv.assets["a-far"] = netip.MustParseAddr("10.20.7.9") // a device seen before: its /24 is swept first
	})
	e.inv.mu.Lock()
	e.inv.addrs = map[netip.Addr]string{netip.MustParseAddr("10.20.7.9"): "a-far"}
	e.inv.mu.Unlock()
	held := newHeld(3)
	e.withProber(held)
	_, err := e.svc.DiscoverRanges(e.ctx()) // the third batch is cut by the window's end
	if !errors.Is(err, sa.ErrStopped) {
		t.Fatalf("first window: %v", err)
	}
	runs := sweepRuns(e)
	if len(runs) != 1 || runs[0].Status != run.Waiting || runs[0].Total != 65534 || runs[0].Done != 128 {
		t.Fatalf("after the first window: %+v, want one waiting run, 128 of 65,534 addresses", runs)
	}
	if !strings.HasPrefix(runs[0].Summary, "Waiting for the scan window (opens ") || !strings.Contains(runs[0].Summary, "128 of 65,534 addresses") {
		t.Fatalf("summary %q", runs[0].Summary)
	}
	if first := targetsOf(held.calls()[0])[0]; !strings.HasPrefix(first, "10.20.7.") {
		t.Fatalf("the pass began at %s, want the /24 where a device was seen", first)
	}
	// the next window: the same run goes on from its cursor
	e.setClock(local(10, 4, 59).Add(50*time.Second))
	held2 := newHeld(2)
	e.withProber(held2)
	if _, err := e.svc.DiscoverRanges(e.ctx()); !errors.Is(err, sa.ErrStopped) {
		t.Fatalf("second window: %v", err)
	}
	runs = sweepRuns(e)
	if len(runs) != 1 || runs[0].Done != 128+64 {
		t.Fatalf("after the second window: %+v, want the same run, 192 addresses done", runs)
	}
}

// A person's check while a pass runs is a queued run that says it waits for the pass; the pass gives way to it after its batch, and
// the window goes on with the pass from its cursor afterwards.
func TestRunsAPersonsCheckDuringASweepIsQueuedBehindIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, func(e *env) {
		e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/25"} })
	})
	e.sweptBefore()
	held := newHeld(1)
	e.withProber(held)
	errc := make(chan error, 1)
	go func() { _, err := e.svc.DiscoverRanges(e.ctx()); errc <- err }()
	held.wait(t, 1)
	m, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.svc.Runs().Read(e.ctx(), m.ID)
	if err != nil {
		t.Fatal(err)
	}
	sweep := sweepRuns(e)[0]
	if r.Status != run.Queued || r.BlockedBy == nil || r.BlockedBy.ID != sweep.ID ||
		r.Summary != "Queued behind “LAN sweep of 192.168.10.0/25”; it starts when that run ends" {
		t.Fatalf("the person's check: %+v", r)
	}
	close(held.release)
	if err := <-errc; !errors.Is(err, sa.ErrStopped) { // the pass waits: it gave way
		t.Fatalf("the pass: %v", err)
	}
	waitManual(t, e)
	if r, _ := e.svc.Runs().Read(e.ctx(), m.ID); r.Status != run.Done {
		t.Fatalf("the person's check ended %s", r.Status)
	}
	if s := sweepRuns(e)[0]; s.Status != run.Waiting || !strings.Contains(s.Summary, "Check of") {
		t.Fatalf("the pass while the check ran: %+v", s)
	}
	if err := e.svc.Tick(e.ctx()); err != nil { // the window's driver goes on with the pass
		t.Fatal(err)
	}
	if s := sweepRuns(e)[0]; s.Status != run.Done || s.Done != 126 {
		t.Fatalf("the pass after the check: %+v", s)
	}
	var sweeps []string
	for _, c := range held.calls() {
		if slices.Contains(c, "-sn") {
			sweeps = append(sweeps, targetsOf(c)[0])
		}
	}
	if !slices.Equal(sweeps, []string{"192.168.10.1", "192.168.10.65"}) {
		t.Fatalf("sweep batches %q: want the first batch, then the pass from its cursor", sweeps)
	}
	if c := held.calls()[1]; !slices.Contains(c, "192.168.10.20") {
		t.Fatalf("the second nmap job was %q, want the person's check", c)
	}
}

// Count test of the class "LAN scan work kept outside core/run": the kinds of work the module does that are not runs of core/run,
// and the module's tables that held a job, a queue or a cursor of its own. Before: 5 kinds (sweep, device check, SNMP read, scan of
// every port, service scan for exposure) and 6 tables (sa_job, sa_queue, sa_sweep, sa_first_pass, sa_snmp, sa_snmp_answer); after: 0
// and 0.
func TestRunsEveryLANScanIsARun(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	var notRuns []string
	for _, k := range []string{sa.RunSweep, sa.RunCheck, sa.RunSNMP, sa.RunAllPorts, sa.RunService} {
		if _, err := e.svc.Runs().Create(e.ctx(), run.Spec{Module: sa.ModuleID, Kind: k, Title: "probe of the kind", Trigger: run.Manual,
			RequestedBy: "test", WaitingFor: "nothing"}); errors.Is(err, run.ErrUnknownKind) {
			notRuns = append(notRuns, k)
		}
	}
	var tables []string
	for _, tb := range []string{"sa_job", "sa_queue", "sa_sweep", "sa_first_pass", "sa_snmp", "sa_snmp_answer"} {
		if e.count(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = '`+tb+`'`) > 0 {
			tables = append(tables, tb)
		}
	}
	t.Logf("kinds of LAN work not on core/run: %d %v; tables of their own: %d %v", len(notRuns), notRuns, len(tables), tables)
	if len(notRuns) != 0 || len(tables) != 0 {
		t.Fatalf("LAN scan work outside core/run: kinds %v, tables %v", notRuns, tables)
	}
}
