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
	"github.com/knt048/vedette/core/sensorlink"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// A person can always ask: a check or a sweep that meets a busy scanner is a queued run that says what it waits for, and run pages
// tell the truth (what a run counted, why nothing was counted, what a waiting run really waits for).

func runsOfKind(e *env, kind string) []run.Run {
	e.t.Helper()
	runs, _, err := e.svc.Runs().List(e.ctx(), run.Filter{Module: sa.ModuleID, Kind: kind})
	if err != nil {
		e.t.Fatal(err)
	}
	return runs
}

// waitRun waits until run id is in one of the states, and returns it.
func waitRun(t *testing.T, e *env, id string, states ...run.Status) run.Run {
	t.Helper()
	give := time.After(30 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		r, err := e.svc.Runs().Read(e.ctx(), id)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(states, r.Status) {
			return r
		}
		select {
		case <-give:
			t.Fatalf("run %s stayed %s (%s), want %v", id, r.Status, r.Summary, states)
		case <-tick.C:
		}
	}
}

// A person's "Check this device now" during the weekly scan of every port makes that scan give the lane up at once (it stays due),
// instead of waiting behind it for up to an hour and a half.
func TestQueueAPersonsCheckDuringTheWeeklyScanGoesFirst(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	b, p := newBlockingWeekly(t)
	e.withProber(p)
	tick := runTick(e)
	waitClosed(t, b.started, "the weekly run")
	m, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-b.ended:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("the weekly run ended with %v, want stopped", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the weekly run kept the lane while a person's check waited")
	}
	if err := <-tick; err != nil {
		t.Fatal(err)
	}
	if r := waitRun(t, e, m.ID, run.Done, run.Failed, run.Partial, run.Stopped); r.Status != run.Done {
		t.Fatalf("the person's check: %+v", r)
	}
	w := runsOfKind(e, sa.RunAllPorts)
	if len(w) != 1 || w[0].Status != run.Partial || !strings.Contains(w[0].Summary, "gave way to other work") {
		t.Fatalf("the weekly run: %+v", w)
	}
}

// Several checks a person asks for while the scanner is busy are each queued (none refused): another device, a LAN sweep behind
// them; the same device asked again gets the run it already has, never a second one. Every one of them is listed.
func TestQueueEveryPersonsAskIsQueuedAndOneDeviceOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow)
	held := newHeld(1)
	e.withProber(held)
	first, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	held.wait(t, 1)
	second, err := e.svc.StartManual(e.ctx(), "bob@example.com", []string{"a-printer"}, nil)
	if err != nil {
		t.Fatalf("a check of another device while the scanner is busy: %v", err)
	}
	again, err := e.svc.StartManual(e.ctx(), "bob@example.com", []string{"a-web"}, nil)
	if err != nil || again.ID != first.ID {
		t.Fatalf("the same device asked again: %+v, %v; want its run %s", again, err, first.ID)
	}
	sweep, err := e.svc.StartManual(e.ctx(), "ann@example.com", nil, nil)
	if err != nil {
		t.Fatalf("Scan the LAN now while checks are queued: %v", err)
	}
	r, err := e.svc.Runs().Read(e.ctx(), second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != run.Queued || r.BlockedBy == nil || r.BlockedBy.ID != first.ID || !strings.HasPrefix(r.Summary, "Queued behind “Check of ") {
		t.Fatalf("the second check: %+v", r)
	}
	if n := e.count(`SELECT count(*) FROM core_run WHERE kind = 'device_check' AND subject_id = 'a-web'`); n != 1 {
		t.Fatalf("%d checks of the same device, want 1", n)
	}
	v, err := e.svc.Engine(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	var listed []string
	for _, m := range v.Persons {
		listed = append(listed, m.ID)
	}
	if !slices.Equal(listed, []string{first.ID, second.ID, sweep.ID}) {
		t.Fatalf("the person's runs listed: %v, want %v", listed, []string{first.ID, second.ID, sweep.ID})
	}
	close(held.release)
	waitManual(t, e)
	for _, id := range []string{first.ID, second.ID, sweep.ID} {
		if r, _ := e.svc.Runs().Read(e.ctx(), id); r.Status != run.Done {
			t.Fatalf("run %s ended %s: %s", id, r.Status, r.Summary)
		}
	}
}

// The weekly scan of every port counts its device when it ran, says how long it has left while it runs (a person's check queued
// behind it says it too), and fails with the reason when the device did not answer at all, instead of "Done: 0 of 1 devices".
func TestAllPortsRunCountsItsDeviceAndSaysHowLongItHasLeft(t *testing.T) {
	t.Parallel()
	t.Run("running", func(t *testing.T) {
		t.Parallel()
		e := allPortsEnv(t)
		b, p := newBlockingWeekly(t)
		e.withProber(p)
		tick := runTick(e)
		waitClosed(t, b.started, "the weekly run")
		w := runsOfKind(e, sa.RunAllPorts)
		if len(w) != 1 || !strings.HasSuffix(w[0].Summary, "minutes left at 100 packets/s") {
			t.Fatalf("the weekly run while it runs: %+v", w)
		}
		e.svc.Stop() // the module turned off ends it
		<-b.ended
		if err := <-tick; err != nil {
			t.Fatal(err)
		}
	})
	t.Run("answered", func(t *testing.T) {
		t.Parallel()
		e := allPortsEnv(t)
		if err := e.svc.Tick(e.ctx()); err != nil {
			t.Fatal(err)
		}
		w := runsOfKind(e, sa.RunAllPorts)
		if len(w) == 0 || w[len(w)-1].Status != run.Done || w[len(w)-1].Summary != "Done: 1 of 1 devices" {
			t.Fatalf("the weekly runs: %+v", w)
		}
	})
	t.Run("no answer", func(t *testing.T) {
		t.Parallel()
		e := allPortsEnv(t)
		xml := fixtureXML(t, "device.xml")
		e.withProber(probeFunc(func(_ context.Context, argv []string) (sa.Output, error) {
			if slices.Contains(argv, "-p-") {
				return sa.Output{XML: emptyScan}, nil // nmap ran its whole time and no port of the device replied
			}
			return sa.Output{XML: xml}, nil
		}))
		if err := e.svc.Tick(e.ctx()); err != nil {
			t.Fatal(err)
		}
		w := runsOfKind(e, sa.RunAllPorts)
		if len(w) == 0 {
			t.Fatal("no weekly run")
		}
		last := w[0]
		if last.Status != run.Failed || !strings.Contains(last.Summary, "No answer from the device on any port") {
			t.Fatalf("the weekly run of a device that never answered: %+v", last)
		}
		if n := e.count(`SELECT count(*) FROM sa_all_ports WHERE outcome = 'retry'`); n != 1 {
			t.Fatalf("%d devices held for one more try, want 1 (a first failure is tried again in the next window)", n)
		}
	})
}

// sickProber is a scan worker that has not reported yet (a core that just restarted): nmap is not available.
type sickProber struct {
	mu  sync.Mutex
	msg string
}

func (p *sickProber) NmapHealth() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.msg
}

func (p *sickProber) heal() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.msg = ""
}

func (p *sickProber) Probe(context.Context, []string) (sa.Output, error) {
	return sa.Output{}, sa.ErrWorkerUnavailable
}

// A device check waiting inside the window says what it really waits for: the scan worker when it is not ready (after a restart,
// before it reports), its turn when it is, the next window once the window closed.
func TestWaitingChecksSayWhatTheyReallyWaitFor(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	e.sweptBefore()
	sick := &sickProber{msg: "the scan worker has not reported since core started; active discovery runs once it does"}
	e.withProber(sick)
	if err := e.svc.Enqueue(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	reason := func() string {
		return e.str(`SELECT coalesce(waiting_for, status) FROM core_run WHERE kind = 'device_check' AND subject_id = 'a-web'`)
	}
	if got := reason(); got != "the scan worker to be available" {
		t.Fatalf("queued inside the window while the worker is not ready: waiting for %q", got)
	}
	// a check queued while the worker was fine, and the worker then went away: the window's tick says so
	if err := e.svc.Runs().Rewait(e.ctx(), "its turn in the scan window", e.str(`SELECT id FROM core_run WHERE kind = 'device_check'`)); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Tick(e.ctx()); !errors.Is(err, sa.ErrUnavailable) {
		t.Fatalf("tick: %v", err)
	}
	if got := reason(); got != "the scan worker to be available" {
		t.Fatalf("after the tick: waiting for %q", got)
	}
	// outside the window it waits for the next one, whatever the worker
	e.setBase(local(9, 12, 0))
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := reason(); !strings.HasPrefix(got, "the scan window (opens ") {
		t.Fatalf("outside the window: waiting for %q", got)
	}
}

// lostProber loses the scan worker under every device scan, as an update of Vedette does when it restarts the scan container.
func lostProber() sa.Prober {
	return probeFunc(func(_ context.Context, argv []string) (sa.Output, error) {
		if slices.Contains(argv, "-sn") {
			return sa.Output{XML: emptyScan}, nil
		}
		return sa.Output{}, sa.ErrWorkerLost
	})
}

// A check the scan worker dropped (it restarted under it) never reads as a Go error: the window's check waits for the worker and is
// tried again; a person's check fails with words that say what happened.
func TestAWorkerLostUnderACheckIsSaidInWords(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	e.sweptBefore()
	e.withProber(lostProber())
	if err := e.svc.Enqueue(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	w := runsOfKind(e, sa.RunCheck)
	if len(w) != 1 || w[0].Status != run.Waiting || strings.Contains(w[0].Summary, "sensoractive") || !strings.Contains(w[0].Summary, "scan worker") {
		t.Fatalf("the window's check after the worker was lost: %+v", w)
	}
	m, err := e.svc.StartManual(e.ctx(), "ann@example.com", []string{"a-printer"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := waitRun(t, e, m.ID, run.Done, run.Failed, run.Partial, run.Stopped)
	if r.Status != run.Failed || strings.Contains(r.Summary, "sensoractive") || !strings.Contains(r.Summary, "scan worker stopped") {
		t.Fatalf("the person's check after the worker was lost: %+v", r)
	}
}

// SNMP: an update of a device that does not change whether it may be read (a sensor learned its name, a check recorded its ports)
// does not stop its read; a read that got no answer fails with the reason; one that got an answer counts its device.
func TestSNMPAReadEndsWithWhatTheDeviceAnswered(t *testing.T) {
	t.Parallel()
	t.Run("an unrelated change of the device", func(t *testing.T) {
		t.Parallel()
		started, goOn := make(chan struct{}), make(chan struct{})
		r := &fakeReader{answer: func(ctx context.Context, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
			close(started)
			select {
			case <-goOn:
				return juniperAnswers(j), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}}
		w := newSNMPWorld(t, r)
		w.set("a-sw", v2c("community-1"))
		go func() {
			<-started
			if err := w.svc.AssetChanged(context.Background(), "a-sw"); err != nil { // nothing that matters to SNMP changed
				t.Error(err)
			}
			close(goOn)
		}()
		res, err := w.svc.CheckSNMP(t.Context(), "a", "a-sw")
		if err != nil || !res.OK {
			t.Fatalf("the read: %+v, %v", res, err)
		}
		if got := snmpRunSummary(t, w); got != "Done: 1 of 1 devices" {
			t.Fatalf("the read's run: %q", got)
		}
	})
	t.Run("no answer", func(t *testing.T) {
		t.Parallel()
		r := &fakeReader{answer: func(_ context.Context, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
			return []sensorlink.SNMPAnswer{{Target: j.Targets[0].IP, Status: sensorlink.SNMPStatusNoAnswer}}, nil
		}}
		w := newSNMPWorld(t, r)
		w.set("a-sw", v2c("community-1"))
		if _, err := w.svc.CheckSNMP(t.Context(), "a", "a-sw"); err != nil {
			t.Fatal(err)
		}
		if got := snmpRunSummary(t, w); !strings.HasPrefix(got, "Failed: No answer from 192.168.10.20 on UDP port 161") {
			t.Fatalf("the read's run: %q", got)
		}
	})
	t.Run("the window's round, one of two answered", func(t *testing.T) {
		t.Parallel()
		r := &fakeReader{answer: func(_ context.Context, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
			out := juniperAnswers(j)
			for i := range out {
				if out[i].Target != "192.168.10.20" {
					out[i] = sensorlink.SNMPAnswer{Target: out[i].Target, Status: sensorlink.SNMPStatusNoAnswer}
				}
			}
			return out, nil
		}}
		w := newSNMPWorld(t, r)
		w.inv.mu.Lock()
		w.inv.assets["a-rt"] = netip.MustParseAddr("192.168.10.22")
		w.inv.addrs[netip.MustParseAddr("192.168.10.22")] = "a-rt"
		w.inv.approved["a-rt"] = true
		w.inv.mu.Unlock()
		w.set("a-sw", v2c("community-1"))
		w.set("a-rt", v2c("community-1"))
		if err := w.svc.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := snmpRunSummary(t, w); got != "Partly done: No answer over SNMP from device a-rt (192.168.10.22); 1 of 2 devices" {
			t.Fatalf("the round's run: %q", got)
		}
	})
}

// snmpRunSummary is the summary of the newest SNMP read.
func snmpRunSummary(t *testing.T, w *snmpWorld) string {
	t.Helper()
	runs, _, err := w.svc.Runs().List(t.Context(), run.Filter{Module: sa.ModuleID, Kind: sa.RunSNMP})
	if err != nil || len(runs) == 0 {
		t.Fatalf("no SNMP read: %v", err)
	}
	return runs[0].Summary
}
