package sensoractive_test

import (
	"context"
	"errors"
	"fmt"
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
	h := &heldProber{hold: map[int]bool{}, started: make(chan int, 4096), release: make(chan struct{})}
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
	e.withProber(again)                                              // the process stops and a new one starts
	if err := <-errc; err != nil && !errors.Is(err, sa.ErrStopped) { // the caller of the old process hears how its run went
		t.Fatal(err)
	}
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
		e.setBase(local(9, 4, 59).Add(50 * time.Second))
		e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"10.20.0.0/16"}; s.Rate = 1000 })
		e.inv.assets["a-far"] = netip.MustParseAddr("10.20.7.9") // a device seen before: its /24 is swept first
	})
	e.inv.mu.Lock()
	e.inv.addrs = map[netip.Addr]string{netip.MustParseAddr("10.20.7.9"): "a-far"}
	e.inv.mu.Unlock()
	held := newHeld(3)
	e.withProber(held)
	e.setClock(local(9, 4, 59).Add(56 * time.Second)) // 4 s to the end of the window
	_, err := e.svc.DiscoverRanges(e.ctx())           // the third batch is cut by the window's end
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
	held2 := newHeld(2)
	e.withProber(held2)
	e.setClock(local(10, 4, 59).Add(56 * time.Second))
	if _, err := e.svc.DiscoverRanges(e.ctx()); !errors.Is(err, sa.ErrStopped) {
		t.Fatalf("second window: %v", err)
	}
	runs = sweepRuns(e)
	if len(runs) != 1 || runs[0].Done != 128+64 {
		t.Fatalf("after the second window: %+v, want the same run, 192 addresses done", runs)
	}
}

// A person's check while a pass runs is a queued run that says it waits for the pass; the pass gives way to it after its batch and
// goes on from its cursor as soon as the check is done.
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
		r.Summary != "Queued behind “LAN sweep of 192.168.10.0/25”; it starts in about a minute" { // the pass gives way after its batch
		t.Fatalf("the person's check: %+v", r)
	}
	close(held.release)
	if err := <-errc; err != nil { // the pass gave way to the check, then went on from its cursor to its end
		t.Fatalf("the pass: %v", err)
	}
	waitManual(t, e)
	if r, _ := e.svc.Runs().Read(e.ctx(), m.ID); r.Status != run.Done {
		t.Fatalf("the person's check ended %s", r.Status)
	}
	if s := sweepRuns(e)[0]; s.Status != run.Done || s.Done != 126 || s.ID != sweep.ID {
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

// A person's sweep outside the window that gives way to a Scan now identification goes on as soon as the identification is done,
// within the person's hour: no driver of the window is needed.
func TestRunsAPersonsSweepGoesOnAfterTheWorkItGaveWayTo(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow, func(e *env) {
		e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/25"} })
	})
	e.sweptBefore()
	held := newHeld(1)
	e.withProber(held)
	m, err := e.svc.StartManual(e.ctx(), "ann@example.com", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	held.wait(t, 1)
	done := make(chan error, 1)
	go func() { _, err := e.svc.IdentifyDevice(e.ctx(), "a-web"); done <- err }()
	waitFor(t, "the identification to queue", func() bool {
		return e.count(`SELECT count(*) FROM core_run WHERE kind = 'device_check' AND status = 'queued'`) == 1
	})
	close(held.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the person's pass to end", func() bool {
		r, err := e.svc.Runs().Read(e.ctx(), m.ID)
		return err == nil && r.Status == run.Done
	})
	if r, _ := e.svc.Runs().Read(e.ctx(), m.ID); r.Done != 126 {
		t.Fatalf("the person's pass: %+v", r)
	}
}

// "Scan the LAN now" on a pass that waits for the window goes on with that pass from its cursor, under the person's hour: one run,
// its cursor kept.
func TestRunsScanTheLANNowGoesOnWithTheWaitingPass(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, func(e *env) {
		e.setBase(local(9, 4, 59).Add(50 * time.Second))
		e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/25"} })
	})
	held := newHeld(2)
	e.withProber(held)
	e.setClock(local(9, 4, 59).Add(56 * time.Second)) // 4 s to the end of the window
	if _, err := e.svc.DiscoverRanges(e.ctx()); !errors.Is(err, sa.ErrStopped) {
		t.Fatalf("the window's pass: %v", err)
	}
	before := sweepRuns(e)
	if len(before) != 1 || before[0].Status != run.Waiting || before[0].Done != 64 {
		t.Fatalf("the pass after the window: %+v", before)
	}
	e.setClock(local(9, 12, 0)) // noon: no window, the gap since the last sweep is over
	again := newHeld()
	e.withProber(again)
	m, err := e.svc.StartManual(e.ctx(), "ann@example.com", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != before[0].ID {
		t.Fatalf("Scan the LAN now made run %s, want the waiting pass %s", m.ID, before[0].ID)
	}
	waitManual(t, e)
	after := sweepRuns(e)
	if len(after) != 1 || after[0].Status != run.Done || after[0].Done != 126 {
		t.Fatalf("after Scan the LAN now: %+v, want the same pass done", after)
	}
	if calls := again.calls(); len(calls) != 1 || targetsOf(calls[0])[0] != "192.168.10.65" {
		t.Fatalf("nmap ran %q, want the rest of the pass only", calls)
	}
}

// A range added to the scope while a pass goes on is swept in that pass.
func TestRunsARangeAddedMidPassIsSweptInIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, func(e *env) {
		e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/26"} })
	})
	held := newHeld(1)
	e.withProber(held)
	errc := make(chan error, 1)
	go func() { _, err := e.svc.DiscoverRanges(e.ctx()); errc <- err }()
	held.wait(t, 1)
	e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/26", "192.168.10.128/26"} })
	close(held.release)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	runs := sweepRuns(e)
	if len(runs) != 1 || runs[0].Status != run.Done || runs[0].Done != 124 || runs[0].Total != 124 {
		t.Fatalf("the pass: %+v, want both ranges (62 + 62 addresses) in one run", runs)
	}
}

// sweepHeld answers every nmap job at once, except the first sweep batch, which waits until release is closed.
type sweepHeld struct {
	*heldProber
	once sync.Once
}

func (h *sweepHeld) Probe(ctx context.Context, argv []string) (sa.Output, error) {
	if slices.Contains(argv, "-sn") {
		hold := false
		h.once.Do(func() { hold = true })
		if hold {
			h.mu.Lock()
			h.argv = append(h.argv, slices.Clone(argv))
			h.mu.Unlock()
			h.started <- 0
			select {
			case <-h.release:
			case <-ctx.Done():
				return sa.Output{}, ctx.Err()
			}
			return sa.Output{XML: emptyScan}, nil
		}
	}
	return h.heldProber.Probe(ctx, argv)
}

// In the window, a device that waits for its check while the pass runs takes its turn between two batches: the window's driver
// does not hold it until the pass ends, which may take the whole window.
func TestRunsTheQueueTakesTurnsWithThePass(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, func(e *env) {
		e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/25"} })
	})
	held := &sweepHeld{heldProber: newHeld()}
	e.withProber(held)
	if _, err := comesDue(e); err != nil { // the sweep's schedule queues the pass
		t.Fatal(err)
	}
	tick := make(chan error, 1)
	go func() { tick <- e.svc.Tick(e.ctx()) }()
	<-held.started // the pass's first batch is in nmap (the devices no check reached went first)
	for len(held.started) > 0 {
		<-held.started
	}
	e.inv.mu.Lock()
	e.inv.assets["a-new"] = netip.MustParseAddr("192.168.10.40")
	e.inv.mu.Unlock()
	if err := e.svc.Enqueue(e.ctx(), "a-new", "discovered"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the queued device to take its turn while the pass still runs", func() bool {
		return e.count(`SELECT count(*) FROM core_run WHERE kind = 'device_check' AND subject_id = 'a-new' AND status = 'queued'`) == 1
	})
	close(held.release)
	if err := <-tick; err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM core_run WHERE kind = 'device_check' AND subject_id = 'a-new' AND status = 'done'`); n != 1 {
		t.Fatalf("the device's check: %d done", n)
	}
	if s := sweepRuns(e)[0]; s.Status != run.Done || s.Done != 126 {
		t.Fatalf("the pass: %+v", s)
	}
	var order []string
	for _, c := range held.calls() {
		switch {
		case slices.Contains(c, "-sn"):
			order = append(order, "sweep "+targetsOf(c)[0])
		case slices.Contains(c, "192.168.10.40"):
			order = append(order, "check")
		}
	}
	if i, j := slices.Index(order, "check"), slices.Index(order, "sweep 192.168.10.65"); i < 0 || j < 0 || i > j {
		t.Fatalf("order %q: want the check between the two batches", order)
	}
}

// In the next window a pass that waits goes on before the devices beyond the first checks' cap: a device takes its turn only after
// a batch of the pass, so the pass is never held behind the whole queue.
func TestRunsAWaitingPassGoesOnBeforeTheRestOfTheQueue(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, func(e *env) {
		e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/25"} })
	})
	held := newHeld(2)
	e.withProber(held)
	e.setClock(local(9, 4, 59).Add(56 * time.Second)) // the window's end cuts the second batch
	if _, err := e.svc.DiscoverRanges(e.ctx()); !errors.Is(err, sa.ErrStopped) {
		t.Fatalf("the first window: %v", err)
	}
	if s := sweepRuns(e); len(s) != 1 || s[0].Done != 64 || s[0].Status != run.Waiting {
		t.Fatalf("the pass after the first window: %+v", s)
	}
	var late []string // the addresses of the devices beyond the cap of first checks
	for i := range 30 {
		id, ip := fmt.Sprintf("a-q%d", i), netip.AddrFrom4([4]byte{192, 168, 10, byte(90 + i)})
		e.inv.mu.Lock()
		e.inv.assets[id] = ip
		e.inv.mu.Unlock()
		if err := e.svc.Enqueue(e.ctx(), id, "discovered"); err != nil {
			t.Fatal(err)
		}
		if i >= 25 {
			late = append(late, ip.String())
		}
	}
	calls := newHeld()
	e.withProber(calls)
	e.setClock(local(10, 2, 0)) // the next window
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	pass, firstLate := -1, -1
	for i, c := range calls.calls() {
		switch {
		case slices.Contains(c, "-sn") && pass < 0:
			pass = i
		case firstLate < 0 && slices.ContainsFunc(late, func(ip string) bool { return slices.Contains(c, ip) }):
			firstLate = i
		}
	}
	if pass < 0 || firstLate < 0 || pass > firstLate {
		t.Fatalf("the pass's batch was nmap job %d, the first check beyond the cap job %d: want the pass first", pass, firstLate)
	}
	if s := sweepRuns(e); s[0].Status != run.Done || s[0].Done != 126 {
		t.Fatalf("the pass: %+v", s[0])
	}
}

// The scan worker gone in the middle of a window with devices waiting: the driver does not resume them over and over; the pass and
// the checks wait, and the next tick tries again.
func TestRunsNoBusyLoopWhileTheWorkerIsGone(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, func(e *env) {
		e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/25"} })
	})
	var mu sync.Mutex
	n := 0
	e.withProber(probeFunc(func(_ context.Context, argv []string) (sa.Output, error) {
		mu.Lock()
		defer mu.Unlock()
		n++
		if slices.Contains(argv, "-sn") && n == 1 {
			return sa.Output{XML: emptyScan}, nil
		}
		return sa.Output{}, sa.ErrWorkerUnavailable // the worker goes away after the pass's first batch
	}))
	for i := range 3 {
		id := fmt.Sprintf("a-w%d", i)
		e.inv.mu.Lock()
		e.inv.assets[id] = netip.AddrFrom4([4]byte{192, 168, 10, byte(100 + i)})
		e.inv.mu.Unlock()
	}
	if _, err := comesDue(e); err != nil { // the sweep's schedule queues the pass
		t.Fatal(err)
	}
	start := time.Now()
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 30*time.Second {
		t.Fatalf("the tick took %v", took)
	}
	if resumes := e.count(`SELECT count(*) FROM core_run_log l JOIN core_run r ON r.id = l.run_id WHERE r.kind = 'device_check' AND l.text = 'Resumed'`); resumes > 10 {
		t.Fatalf("%d resumes of the waiting checks while the worker was gone", resumes)
	}
	if s := sweepRuns(e); len(s) != 1 || s[0].Status != run.Waiting {
		t.Fatalf("the pass: %+v", s)
	}
}
