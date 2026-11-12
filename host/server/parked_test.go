package server_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

// Tests of the framework support for runs parked across the host's own restart (D-316, plan
// docs/plans/2026-11-12-host-self-update.md slice 1). The commands here exist only in this file:
// production registers none of them yet (host.self_update comes in slice 2).

// parkArgs drives test.self_park, which behaves as host.self_update will: it parks first, and the
// first side effect outside its state ("dispatch") happens later, in the settle goroutine it starts
// from OnParked.
type parkArgs struct {
	Wait     bool   `json:"wait"`     // block before parking until the run's context ends (a SIGTERM before parking)
	Late     bool   `json:"late"`     // with Wait: return Parked anyway once the context ended
	Dispatch string `json:"dispatch"` // "": no settle goroutine; "ok": dispatch, then settle succeeded when finish closes; "fail": the dispatch fails
}

// parkFx holds the parking test commands and what they observed. srv is set once the server exists.
type parkFx struct {
	srv        atomic.Pointer[server.Server]
	started    chan string // run id, when test.self_park starts
	onParked   atomic.Int64
	dispatches atomic.Int64                 // first side effects of the settle goroutine
	observe    atomic.Pointer[func(string)] // called by the settle goroutine just before its side effect
	finish     chan struct{}                // the work outside the process is done: settle succeeded
	stop       chan struct{}                // closed at cleanup: settle goroutines still waiting end
	settled    chan error                   // what the settle goroutine's SettleParked returned
	after      chan api.Status
	own        []server.Command // the parking commands of this file
	cmds       []server.Command // own plus the base fixture's
}

func newParkFx(t testing.TB) *parkFx {
	t.Helper()
	base := newFixture(t)
	x := &parkFx{
		started: make(chan string, 8), finish: make(chan struct{}), stop: make(chan struct{}),
		settled: make(chan error, 8), after: make(chan api.Status, 16),
	}
	t.Cleanup(func() { close(x.stop) })
	parkAt := func(d time.Duration) func(context.Context, *server.RunContext, struct{}) (any, error) {
		return func(_ context.Context, rc *server.RunContext, _ struct{}) (any, error) {
			rc.AfterFinish(func(_ context.Context, st api.Status) { x.after <- st })
			rc.OnParked(func() { x.onParked.Add(1) })
			if d == 0 {
				return server.Parked{}, nil
			}
			return server.Parked{Deadline: time.Now().Add(d)}, nil
		}
	}
	x.own = []server.Command{
		server.Define(server.Spec[parkArgs]{
			Name: "test.self_park", Write: true, Parks: true, Timeout: 5 * time.Second,
			Run: func(ctx context.Context, rc *server.RunContext, a parkArgs) (any, error) {
				x.started <- rc.RunID
				if a.Wait {
					<-ctx.Done()
					if !a.Late {
						return nil, ctx.Err()
					}
				}
				rc.AfterFinish(func(_ context.Context, st api.Status) { x.after <- st })
				rc.OnParked(func() { x.onParked.Add(1) })
				if a.Dispatch != "" {
					id, fail := rc.RunID, a.Dispatch == "fail"
					rc.OnParked(func() { go x.settleLoop(id, fail) })
				}
				return server.Parked{Deadline: time.Now().Add(2 * time.Hour), Result: map[string]string{"phase": "staged"}}, nil
			},
		}),
		server.Define(server.Spec[struct{}]{Name: "test.park_zero", Write: true, Parks: true, Timeout: 5 * time.Second, Run: parkAt(0)}),
		server.Define(server.Spec[struct{}]{Name: "test.park_past", Write: true, Parks: true, Timeout: 5 * time.Second, Run: parkAt(-time.Second)}),
		server.Define(server.Spec[struct{}]{Name: "test.park_far", Write: true, Parks: true, Timeout: 5 * time.Second, Run: parkAt(4 * time.Hour)}),
		server.Define(server.Spec[struct{}]{Name: "test.park_undeclared", Write: true, Timeout: 5 * time.Second, Run: parkAt(time.Hour)}),
		server.Define(server.Spec[struct{}]{
			Name: "test.park_with_error", Write: true, Parks: true, Timeout: 5 * time.Second,
			Run: func(_ context.Context, rc *server.RunContext, _ struct{}) (any, error) {
				rc.OnParked(func() { x.onParked.Add(1) })
				return &server.Parked{Deadline: time.Now().Add(time.Hour)}, errors.New("changed my mind")
			},
		}),
	}
	x.cmds = append(base.cmds, x.own...)
	return x
}

// settleLoop stands for the settle goroutine of host.self_update: its first round dispatches (the
// first side effect outside the state dir), and it ends the run with SettleParked.
func (x *parkFx) settleLoop(runID string, fail bool) {
	if obs := x.observe.Load(); obs != nil {
		(*obs)(runID)
	}
	x.dispatches.Add(1)
	srv := x.srv.Load()
	if fail {
		x.settled <- srv.SettleParked(runID, api.StatusFailed, nil, &api.RunError{Code: "dispatch_failed", Message: "The work could not be handed over."})
		return
	}
	select {
	case <-x.finish:
		x.settled <- srv.SettleParked(runID, api.StatusSucceeded, map[string]string{"phase": "installed"}, nil)
	case <-x.stop:
	}
}

func startPark(t testing.TB, mutate ...func(*server.Options)) (*servertest.Harness, *parkFx) {
	t.Helper()
	x := newParkFx(t)
	h := prepareAwait(t, x.cmds, mutate...)
	x.srv.Store(h.Server)
	h.Serve(t)
	return h, x
}

// restartPark is the next host process on the same state, socket path aside; it does not listen yet.
func restartPark(t testing.TB, h *servertest.Harness, resume func(api.Run) bool) (*servertest.Harness, *parkFx) {
	t.Helper()
	x := newParkFx(t)
	h2 := prepareAwait(t, x.cmds, func(o *server.Options) {
		o.StateDir, o.AuditPath, o.SocketPath = h.StateDir, h.AuditPath, h.Socket+"2"
		o.Resume = resume
	})
	x.srv.Store(h2.Server)
	return h2, x
}

// sigterm is what the SIGTERM handler of cmd/vedette-host does: Shutdown.
func sigterm(t testing.TB, h *servertest.Harness) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), hangBound)
	defer cancel()
	if err := h.Server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

// recv waits for one value from ch, at most hangBound.
func recv[T any](t testing.TB, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(hangBound):
		t.Fatalf("after %v: %s", hangBound, what)
	}
	var zero T
	return zero
}

// parkRun starts test.self_park and waits until the run is parked.
func parkRun(t testing.TB, h *servertest.Harness, a parkArgs, id string) api.Run {
	t.Helper()
	r := run(t, h.Client, "test.self_park", a, id)
	var got api.Run
	waitFor(t, "run "+r.RunID+" to park", func() bool {
		got, _ = h.Client.GetRun(context.Background(), r.RunID)
		return got.ParkedDeadline != nil || got.Status.Terminal()
	})
	if got.Status != api.StatusRunning || got.ParkedDeadline == nil {
		t.Fatalf("run did not park: %+v", got)
	}
	return got
}

func TestParked_SIGTERMWhileParkedKeepsTheRunRunningAndTheLockHeld(t *testing.T) {
	t.Parallel()
	h, x := startPark(t)
	parked := parkRun(t, h, parkArgs{}, rid1)
	if string(parked.Result) != `{"phase":"staged"}` {
		t.Fatalf("parked run = %+v", parked)
	}
	waitFor(t, "OnParked to run", func() bool { return x.onParked.Load() == 1 })
	_, err := h.Client.Run(context.Background(), "test.echo", echoArgs{Name: "x"}, rid2, "admin")
	if ce := clientErr(t, err, http.StatusConflict, api.CodeBusy); ce.RunID != parked.RunID {
		t.Fatalf("busy names %q", ce.RunID)
	}
	if got := strings.Join(auditFor(t, h, parked.RunID), ","); got != "accepted,parked" {
		t.Fatalf("audit while parked: %s", got)
	}
	// Read the events so far (state running, the parked log line) to know the numbering.
	ctx, cancel := context.WithTimeout(context.Background(), hangBound)
	defer cancel()
	s := h.Client.Events(ctx, parked.RunID, 0)
	var seen []api.Event
	for len(seen) < 2 {
		ev, err := s.Next()
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, ev)
	}
	s.Close()
	if seen[1].Kind != api.KindLog || !strings.Contains(seen[1].Line, "parked") {
		t.Fatalf("events = %+v", seen)
	}

	sigterm(t, h)

	var asked []api.Run
	var socketAtResume atomic.Bool
	h2, _ := restartPark(t, h, func(r api.Run) bool {
		asked = append(asked, r)
		_, err := os.Lstat(h.Socket + "2")
		socketAtResume.Store(err == nil)
		return true
	})
	if len(asked) != 1 || asked[0].RunID != parked.RunID || asked[0].Status != api.StatusRunning || asked[0].ParkedDeadline == nil || socketAtResume.Load() {
		t.Fatalf("Resume was asked %+v (socket present %v)", asked, socketAtResume.Load())
	}
	if !h2.Server.WriteActive() || h2.Server.AwaitingConfirm() {
		t.Fatal("the resumed parked run must hold the lock before Listen, and is not awaiting")
	}
	h2.Serve(t)
	got, err := h2.Client.GetRun(context.Background(), parked.RunID)
	if err != nil || got.Status != api.StatusRunning || got.ParkedDeadline == nil || !got.ParkedDeadline.Equal(*parked.ParkedDeadline) {
		t.Fatalf("after the restart: %+v %v", got, err)
	}
	_, err = h2.Client.Run(context.Background(), "test.echo", echoArgs{Name: "x"}, rid3, "admin")
	if ce := clientErr(t, err, http.StatusConflict, api.CodeBusy); ce.RunID != parked.RunID {
		t.Fatalf("busy after the restart names %q", ce.RunID)
	}
	// The events go on where they left off (Last-Event-ID) and end at the final state.
	ctx2, cancel2 := context.WithTimeout(context.Background(), hangBound)
	defer cancel2()
	s2 := h2.Client.Events(ctx2, parked.RunID, seen[len(seen)-1].Seq)
	defer s2.Close()
	evCh := make(chan api.Event, 8)
	go func() {
		defer close(evCh)
		for {
			ev, err := s2.Next()
			if err != nil {
				return
			}
			evCh <- ev
		}
	}()
	// The resumed settle goroutine ends the run (here the test stands in for it).
	if err := h2.Server.SettleParked(parked.RunID, api.StatusSucceeded, map[string]string{"phase": "installed"}, nil); err != nil {
		t.Fatal(err)
	}
	var last api.Event
	for ev := range evCh {
		if ev.Seq <= seen[len(seen)-1].Seq {
			t.Fatalf("event %d repeated after the restart", ev.Seq)
		}
		last = ev
	}
	if last.Kind != api.KindState || last.Status != api.StatusSucceeded {
		t.Fatalf("last event = %+v", last)
	}
	fin, _ := h2.Client.GetRun(context.Background(), parked.RunID)
	if fin.Status != api.StatusSucceeded || fin.ParkedDeadline != nil || fin.FinishedAt == nil || string(fin.Result) != `{"phase":"installed"}` {
		t.Fatalf("final run = %+v", fin)
	}
	if got := strings.Join(auditFor(t, h2, parked.RunID), ","); got != "accepted,parked,ok" {
		t.Fatalf("audit of the run across the restart: %s", got)
	}
	if h2.Server.WriteActive() {
		t.Fatal("lock still held after SettleParked")
	}
	run(t, h2.Client, "test.echo", echoArgs{Name: "x"}, uuid(1))
}

func TestParked_SIGTERMBeforeParkingFailsTheRunShuttingDownAndReleasesTheLock(t *testing.T) {
	t.Parallel()
	for name, a := range map[string]parkArgs{
		"the command obeys its context":     {Wait: true, Dispatch: "ok"},
		"the command returns Parked anyway": {Wait: true, Late: true, Dispatch: "ok"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h, x := startPark(t)
			r := run(t, h.Client, "test.self_park", a, rid1)
			recv(t, x.started, "the command to start")
			sigterm(t, h)
			var asked atomic.Int64
			h2, _ := restartPark(t, h, func(api.Run) bool { asked.Add(1); return true })
			if h2.Server.WriteActive() || asked.Load() != 0 {
				t.Fatalf("lock %v, Resume asked %d times: a run that never parked holds nothing", h2.Server.WriteActive(), asked.Load())
			}
			h2.Serve(t)
			got, err := h2.Client.GetRun(context.Background(), r.RunID)
			if err != nil || got.Status != api.StatusFailed || got.Error == nil || got.Error.Code != api.CodeShuttingDown || got.ParkedDeadline != nil {
				t.Fatalf("run = %+v %v", got, err)
			}
			if lines := strings.Join(auditFor(t, h2, r.RunID), ","); lines != "accepted,failed" {
				t.Fatalf("audit = %s", lines)
			}
			// Nothing was started for it: no OnParked, no dispatch.
			if x.onParked.Load() != 0 || x.dispatches.Load() != 0 {
				t.Fatalf("OnParked %d, dispatches %d", x.onParked.Load(), x.dispatches.Load())
			}
			run(t, h2.Client, "test.echo", echoArgs{Name: "x"}, rid2)
		})
	}
}

func TestParked_SettleEndsTheRunOnceAndARacingSecondGetsNotParked(t *testing.T) {
	t.Parallel()
	h, x := startPark(t)
	parked := parkRun(t, h, parkArgs{}, rid1)
	// A bad status, an unknown run and the awaiting Settle change nothing.
	for _, st := range []api.Status{api.StatusRunning, api.StatusAwaitingConfirm, api.StatusRefused, api.StatusFailed, "bogus"} {
		if err := h.Server.SettleParked(parked.RunID, st, nil, nil); err == nil || errors.Is(err, server.ErrNotParked) {
			t.Errorf("SettleParked(%q) = %v", st, err)
		}
	}
	if err := h.Server.SettleParked("rn_ffffffffffffffff", api.StatusSucceeded, nil, nil); !errors.Is(err, server.ErrNotParked) {
		t.Fatalf("unknown run: %v", err)
	}
	if err := h.Server.Settle(parked.RunID, api.StatusSucceeded, nil); !errors.Is(err, server.ErrNotAwaiting) {
		t.Fatalf("Settle of a parked run = %v", err)
	}
	if got, _ := h.Client.GetRun(context.Background(), parked.RunID); got.Status != api.StatusRunning || got.ParkedDeadline == nil || !h.Server.WriteActive() {
		t.Fatalf("a refused settle changed the run: %+v", got)
	}
	var wins, notParked, other atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 50 {
		wg.Go(func() {
			<-start
			st, rerr := api.StatusSucceeded, (*api.RunError)(nil)
			if i%2 == 1 {
				st, rerr = api.StatusFailed, &api.RunError{Code: "self_update_interrupted", Message: "Interrupted."}
			}
			switch err := h.Server.SettleParked(parked.RunID, st, nil, rerr); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, server.ErrNotParked):
				notParked.Add(1)
			default:
				other.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || notParked.Load() != 49 || other.Load() != 0 {
		t.Fatalf("wins %d, not parked %d, other errors %d", wins.Load(), notParked.Load(), other.Load())
	}
	fin := finish(t, h.Client, parked.RunID)
	if (fin.Status != api.StatusSucceeded && fin.Status != api.StatusFailed) || fin.ParkedDeadline != nil || string(fin.Result) != `{"phase":"staged"}` {
		t.Fatalf("final run = %+v (a nil result keeps the parked one)", fin)
	}
	lines := auditFor(t, h, parked.RunID)
	if len(lines) != 3 || lines[0] != "accepted" || lines[1] != "parked" {
		t.Fatalf("audit = %v", lines)
	}
	if err := h.Server.SettleParked(parked.RunID, api.StatusSucceeded, nil, nil); !errors.Is(err, server.ErrNotParked) {
		t.Fatalf("a late SettleParked = %v", err)
	}
	if got, _ := h.Client.GetRun(context.Background(), parked.RunID); got.Status != fin.Status || !got.FinishedAt.Equal(*fin.FinishedAt) {
		t.Fatalf("a late SettleParked changed the run: %+v", got)
	}
	if h.Server.WriteActive() {
		t.Fatal("lock still held")
	}
	// Shutdown waits for the AfterFinish callbacks: exactly one ran.
	sigterm(t, h)
	if n := len(x.after); n != 1 {
		t.Fatalf("AfterFinish ran %d times", n)
	}
}

func TestParked_APanickingResumeCountsAsNo(t *testing.T) {
	t.Parallel()
	for name, resume := range map[string]func(api.Run) bool{
		"nil":    nil,
		"false":  func(api.Run) bool { return false },
		"panics": func(api.Run) bool { panic("boom") },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h, _ := startPark(t)
			parked := parkRun(t, h, parkArgs{}, rid1)
			sigterm(t, h)
			h2, _ := restartPark(t, h, resume)
			if h2.Server.WriteActive() {
				t.Fatal("a parked run that was not resumed must not hold the lock")
			}
			h2.Serve(t)
			got, err := h2.Client.GetRun(context.Background(), parked.RunID)
			if err != nil || got.Status != api.StatusFailed || got.Error == nil || got.Error.Code != api.CodeHostRestarted || got.ParkedDeadline != nil {
				t.Fatalf("run = %+v %v", got, err)
			}
			if lines := strings.Join(auditFor(t, h2, parked.RunID), ","); lines != "accepted,parked,failed" {
				t.Fatalf("audit = %s", lines)
			}
			run(t, h2.Client, "test.echo", echoArgs{Name: "x"}, rid2)
			if err := h2.Server.SettleParked(parked.RunID, api.StatusSucceeded, nil, nil); !errors.Is(err, server.ErrNotParked) {
				t.Fatalf("SettleParked = %v", err)
			}
		})
	}
}

func TestParked_SettleAfterShutdownBeganIsRefusedAndChangesNothing(t *testing.T) {
	t.Parallel()
	h, _ := startPark(t)
	parked := parkRun(t, h, parkArgs{}, rid1)
	sigterm(t, h)
	if err := h.Server.SettleParked(parked.RunID, api.StatusSucceeded, nil, nil); !errors.Is(err, server.ErrShuttingDown) {
		t.Fatalf("SettleParked after Shutdown = %v", err)
	}
	h2, _ := restartPark(t, h, func(api.Run) bool { return true })
	h2.Serve(t)
	got, err := h2.Client.GetRun(context.Background(), parked.RunID)
	if err != nil || got.Status != api.StatusRunning || got.ParkedDeadline == nil || got.FinishedAt != nil {
		t.Fatalf("run = %+v %v", got, err)
	}
	if lines := strings.Join(auditFor(t, h2, parked.RunID), ","); lines != "accepted,parked" {
		t.Fatalf("audit = %s", lines)
	}
}

func TestParked_SettleRacingShutdownLeavesAConsistentRun(t *testing.T) {
	t.Parallel()
	for i := range 8 {
		h, _ := startPark(t)
		parked := parkRun(t, h, parkArgs{}, uuid(100+i))
		var settleErr error
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Go(func() {
			<-start
			settleErr = h.Server.SettleParked(parked.RunID, api.StatusSucceeded, nil, nil)
		})
		wg.Go(func() {
			<-start
			sigterm(t, h)
		})
		close(start)
		wg.Wait()
		h2, _ := restartPark(t, h, func(api.Run) bool { return true })
		h2.Serve(t)
		got, err := h2.Client.GetRun(context.Background(), parked.RunID)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Join(auditFor(t, h2, parked.RunID), ",")
		switch {
		case settleErr == nil:
			// SettleParked got in first: the run is final on disk, with its line, before Shutdown closed the audit log.
			if got.Status != api.StatusSucceeded || lines != "accepted,parked,ok" || h2.Server.WriteActive() {
				t.Fatalf("iteration %d: settled, but run %+v lines %s", i, got, lines)
			}
		case errors.Is(settleErr, server.ErrShuttingDown):
			// Shutdown won: nothing changed, and the next start resumes the run with its lock.
			if got.Status != api.StatusRunning || lines != "accepted,parked" || !h2.Server.WriteActive() {
				t.Fatalf("iteration %d: refused, but run %+v lines %s", i, got, lines)
			}
		default:
			t.Fatalf("iteration %d: SettleParked = %v", i, settleErr)
		}
		if err := h2.Server.AuditError(); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
}

func TestParked_AnInvalidParkedFailsCommandFailedAndReleasesTheLock(t *testing.T) {
	t.Parallel()
	h, x := startPark(t)
	for i, name := range []string{"test.park_zero", "test.park_past", "test.park_far", "test.park_undeclared", "test.park_with_error"} {
		r := run(t, h.Client, name, nil, uuid(i+1))
		fin := finish(t, h.Client, r.RunID)
		if fin.Status != api.StatusFailed || fin.Error == nil || fin.Error.Code != api.CodeCommandFailed || fin.ParkedDeadline != nil {
			t.Fatalf("%s: %+v", name, fin)
		}
		if h.Server.WriteActive() {
			t.Fatalf("%s left the lock held", name)
		}
		if lines := strings.Join(auditFor(t, h, r.RunID), ","); lines != "accepted,failed" {
			t.Fatalf("%s: audit = %s", name, lines)
		}
	}
	if x.onParked.Load() != 0 {
		t.Fatalf("OnParked ran %d times for runs that were not parked", x.onParked.Load())
	}
	run(t, h.Client, "test.echo", echoArgs{Name: "x"}, rid1)
}

func TestParked_TheFirstSideEffectHappensAfterTheRunIsParked(t *testing.T) {
	t.Parallel()
	h, x := startPark(t)
	c := h.NewClient(t)
	type seen struct {
		run   api.Run
		audit []string
	}
	atDispatch := make(chan seen, 1)
	obs := func(runID string) { // on the settle goroutine: no t.Fatal here
		r, _ := c.GetRun(context.Background(), runID)
		var lines []string
		if page, err := c.Audit(context.Background(), 0, 500); err == nil {
			for _, a := range page.Records {
				if a.RunID != nil && *a.RunID == runID {
					lines = append(lines, a.Result)
				}
			}
		}
		atDispatch <- seen{r, lines}
	}
	x.observe.Store(&obs)
	r := run(t, h.Client, "test.self_park", parkArgs{Dispatch: "ok"}, rid1)
	got := recv(t, atDispatch, "the first side effect")
	if got.run.Status != api.StatusRunning || got.run.ParkedDeadline == nil || !slices.Equal(got.audit, []string{"accepted", "parked"}) {
		t.Fatalf("at the first side effect the run is %+v with audit %v: it must already be parked", got.run, got.audit)
	}
	close(x.finish) // the work outside the process ends
	if err := recv(t, x.settled, "the settle goroutine to settle"); err != nil {
		t.Fatal(err)
	}
	fin := finish(t, h.Client, r.RunID)
	if fin.Status != api.StatusSucceeded || string(fin.Result) != `{"phase":"installed"}` || x.dispatches.Load() != 1 {
		t.Fatalf("run = %+v, dispatches %d", fin, x.dispatches.Load())
	}
}

func TestParked_ADispatchFailureSettlesFailedAndReleasesTheLock(t *testing.T) {
	t.Parallel()
	h, x := startPark(t)
	r := run(t, h.Client, "test.self_park", parkArgs{Dispatch: "fail"}, rid1)
	if err := recv(t, x.settled, "the settle goroutine to settle"); err != nil {
		t.Fatal(err)
	}
	fin := finish(t, h.Client, r.RunID)
	if fin.Status != api.StatusFailed || fin.Error == nil || fin.Error.Code != "dispatch_failed" || fin.ParkedDeadline != nil {
		t.Fatalf("run = %+v", fin)
	}
	if lines := strings.Join(auditFor(t, h, r.RunID), ","); lines != "accepted,parked,failed" {
		t.Fatalf("audit = %s", lines)
	}
	if h.Server.WriteActive() {
		t.Fatal("lock still held")
	}
	run(t, h.Client, "test.echo", echoArgs{Name: "x"}, rid2)
}

func TestParked_WhileParkedAWhileAwaitingCommandFindsNothingToConfirm(t *testing.T) {
	t.Parallel()
	x := newAwaitFx(t)
	px := newParkFx(t)
	h := prepareAwait(t, append(x.cmds, px.own...))
	x.srv.Store(h.Server)
	px.srv.Store(h.Server)
	h.Serve(t)
	parked := parkRun(t, h, parkArgs{}, rid1)
	_, err := h.Client.Run(context.Background(), "test.confirm", runIDArgs{RunID: parked.RunID}, rid2, "admin")
	_ = clientErr(t, err, http.StatusPreconditionFailed, api.CodeNotAwaitingConfirm)
	_, err = h.Client.Run(context.Background(), "test.park", nil, rid3, "admin")
	if ce := clientErr(t, err, http.StatusConflict, api.CodeBusy); ce.RunID != parked.RunID {
		t.Fatalf("busy names %q", ce.RunID)
	}
}

func TestParked_OnlyOneRunHoldingTheLockIsResumed(t *testing.T) {
	t.Parallel()
	// Two parked run files can only come from a damaged state directory; the lock allows one.
	h, _ := startPark(t)
	a := parkRun(t, h, parkArgs{}, rid1)
	sigterm(t, h)
	src, err := os.ReadFile(h.StateDir + "/runs/" + a.RunID + ".json")
	if err != nil {
		t.Fatal(err)
	}
	second := "rn_00000000000000aa"
	if err := os.WriteFile(h.StateDir+"/runs/"+second+".json", []byte(strings.ReplaceAll(string(src), a.RunID, second)), 0o600); err != nil { //nolint:gosec // a path inside the test's own temp dir
		t.Fatal(err)
	}
	var calls atomic.Int64
	h2, _ := restartPark(t, h, func(api.Run) bool { calls.Add(1); return true })
	h2.Serve(t)
	var parkedRuns, failed int
	runs, _ := h2.Client.ListRuns(context.Background(), 50)
	for _, r := range runs {
		switch {
		case r.Status == api.StatusRunning && r.ParkedDeadline != nil:
			parkedRuns++
		case r.Status == api.StatusFailed && r.Error != nil && r.Error.Code == api.CodeHostRestarted:
			failed++
		}
	}
	if parkedRuns != 1 || failed != 1 || calls.Load() != 1 {
		t.Fatalf("parked %d failed %d Resume calls %d", parkedRuns, failed, calls.Load())
	}
}

func TestParked_RegistryRulesForParks(t *testing.T) {
	t.Parallel()
	ok := func(context.Context, *server.RunContext, runIDArgs) (any, error) { return nil, nil }
	bad := map[string]server.Command{
		"parks on a read command":  server.Define(server.Spec[runIDArgs]{Name: "t.a", Parks: true, Timeout: time.Second, Run: ok}),
		"parks and awaits":         server.Define(server.Spec[runIDArgs]{Name: "t.b", Write: true, Parks: true, Awaits: true, Timeout: time.Second, Run: ok}),
		"parks and while-awaiting": server.Define(server.Spec[runIDArgs]{Name: "t.c", Write: true, Parks: true, WhileAwaiting: true, Timeout: time.Second, Run: ok}),
	}
	for name, c := range bad {
		if _, err := server.NewRegistry(c); err == nil {
			t.Errorf("%s: NewRegistry accepted it", name)
		}
	}
	if _, err := server.NewRegistry(server.Define(server.Spec[runIDArgs]{Name: "t.d", Write: true, Parks: true, Timeout: time.Second, Run: ok})); err != nil {
		t.Fatal(err)
	}
}
