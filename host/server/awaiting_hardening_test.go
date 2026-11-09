package server_test

// Tests that came out of the independent security review of slice 3-1 (D-100): the lock handover,
// Awaits validation, events saved while waiting, resume hardening, Claim/Finish, OnParked and the
// RevertAt bounds.

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

// reviewFx adds the review's own commands to the awaiting fixture.
type reviewFx struct {
	*awaitFx
	release     chan struct{} // releases rv.block and rv.confirm_then_work
	blocking    chan struct{} // rv.block is running
	settled     chan error    // rv.confirm_then_work called Settle (its result)
	rc          atomic.Pointer[server.RunContext]
	revertIn    atomic.Int64 // rv.park_in parks with RevertAt = now + this
	armed       chan error   // rv.park_arm: the result of the Settle it fires from OnParked
	parkedCalls atomic.Int64
	all         []server.Command // the awaiting fixture's commands plus the review's
}

func startReview(t *testing.T, mutate ...func(*server.Options)) (*servertest.Harness, *reviewFx) {
	t.Helper()
	x := &reviewFx{awaitFx: newAwaitFx(t), release: make(chan struct{}), blocking: make(chan struct{}, 4), settled: make(chan error, 4), armed: make(chan error, 1)}
	t.Cleanup(func() {
		select {
		case <-x.release:
		default:
			close(x.release)
		}
	})
	cmds := append([]server.Command{}, x.cmds...)
	cmds = append(cmds,
		// An ordinary write that runs until released.
		server.Define(server.Spec[struct{}]{
			Name: "rv.block", Write: true, Timeout: 10 * time.Second,
			Run: func(ctx context.Context, _ *server.RunContext, _ struct{}) (any, error) {
				x.blocking <- struct{}{}
				select {
				case <-x.release:
					return nil, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			},
		}),
		// A READ command (no write lock) that returns Awaiting: refused by the framework.
		server.Define(server.Spec[struct{}]{
			Name: "rv.read_park", Write: false, Timeout: 5 * time.Second,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
				return server.Awaiting{RevertAt: time.Now().Add(time.Minute)}, nil
			},
		}),
		// A WhileAwaiting command that itself returns Awaiting: refused by the framework.
		server.Define(server.Spec[runIDArgs]{
			Name: "rv.confirm_park", Write: true, WhileAwaiting: true, Timeout: 5 * time.Second, Validate: validRunID,
			Run: func(context.Context, *server.RunContext, runIDArgs) (any, error) {
				return server.Awaiting{RevertAt: time.Now().Add(time.Minute)}, nil
			},
		}),
		// The shape of net.confirm per D-100 (2): settle, then finish its own work (remove the
		// /run copy, pending.json, write the result) before returning.
		server.Define(server.Spec[runIDArgs]{
			Name: "rv.confirm_then_work", Write: true, WhileAwaiting: true, Timeout: 10 * time.Second, Validate: validRunID,
			Run: func(ctx context.Context, _ *server.RunContext, a runIDArgs) (any, error) {
				x.settled <- x.srv.Load().Settle(a.RunID, api.StatusSucceeded, nil) //nolint:contextcheck // Settle takes no context
				select {
				case <-x.release:
					return nil, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			},
		}),
		// Parks with a RevertAt chosen by the test, counting OnParked calls.
		server.Define(server.Spec[struct{}]{
			Name: "rv.park_in", Write: true, Awaits: true, Timeout: 5 * time.Second,
			Run: func(_ context.Context, rc *server.RunContext, _ struct{}) (any, error) {
				rc.OnParked(func() { x.parkedCalls.Add(1) })
				return server.Awaiting{RevertAt: time.Now().Add(time.Duration(x.revertIn.Load()))}, nil
			},
		}),
		// Arms its "timer" in OnParked and fires it at once: the run must already be awaiting.
		server.Define(server.Spec[struct{}]{
			Name: "rv.park_arm", Write: true, Awaits: true, Timeout: 5 * time.Second,
			Run: func(_ context.Context, rc *server.RunContext, _ struct{}) (any, error) {
				rc.OnParked(func() { //nolint:contextcheck // Settle takes no context: it must finish even when the caller's is cancelled
					go func() {
						x.armed <- x.srv.Load().Settle(rc.RunID, api.StatusReverted, &api.RunError{Code: "not_confirmed", Message: "Early."})
					}()
				})
				return server.Awaiting{RevertAt: time.Now().Add(time.Minute)}, nil
			},
		}),
		// Returns Awaiting without being declared Awaits.
		server.Define(server.Spec[struct{}]{
			Name: "rv.undeclared_park", Write: true, Timeout: 5 * time.Second,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
				return server.Awaiting{RevertAt: time.Now().Add(time.Minute)}, nil
			},
		}),
		// A command that keeps its RunContext and logs while the run waits (a timer reporting
		// "reverting in N s", or the revert itself reporting progress).
		server.Define(server.Spec[struct{}]{
			Name: "rv.park_keep_rc", Write: true, Awaits: true, Timeout: 5 * time.Second,
			Run: func(_ context.Context, rc *server.RunContext, _ struct{}) (any, error) {
				x.rc.Store(rc)
				return server.Awaiting{RevertAt: time.Now().Add(2 * time.Minute)}, nil
			},
		}),
	)
	x.all = cmds
	h := prepareAwait(t, cmds, mutate...)
	x.srv.Store(h.Server)
	h.Serve(t)
	return h, x
}

func TestAwaiting_LockStaysHeldWhenTheTimerSettlesWhileAConfirmStillRuns(t *testing.T) {
	t.Parallel()
	h, x := startReview(t)
	parked := park(t, h, rid1)
	held := run(t, h.Client, "test.hold", runIDArgs{RunID: parked.RunID}, uuid(1))
	<-x.holding
	// The revert timer fires while the confirm command is still running.
	if err := h.Server.Settle(parked.RunID, api.StatusReverted, &api.RunError{Code: "not_confirmed", Message: "Not confirmed in time."}); err != nil {
		t.Fatal(err)
	}
	if !h.Server.WriteActive() {
		t.Errorf("WriteActive() = false while the write command %s is still running", held.RunID)
	}
	r, err := h.Client.Run(context.Background(), "rv.block", nil, uuid(2), "admin")
	if err == nil {
		select {
		case <-x.blocking:
			t.Errorf("write %s started while write %s (WhileAwaiting) was still running: two writes at once", r.RunID, held.RunID)
		case <-time.After(5 * time.Second):
			t.Errorf("write %s was accepted (not busy) while %s was still running", r.RunID, held.RunID)
		}
	} else if !client.IsCode(err, api.CodeBusy) {
		t.Errorf("want 409 busy, got %v", err)
	}
	close(x.hold)
	finish(t, h.Client, held.RunID)
}

// Same defect, the path net.confirm will take (D-100 (2)): it calls Settle and then still has
// work to do before Run returns; from Settle on, another write may run beside it.
func TestAwaiting_LockStaysHeldWhenAConfirmSettledItselfAndStillHasWork(t *testing.T) {
	t.Parallel()
	h, x := startReview(t)
	parked := park(t, h, rid1)
	cf := run(t, h.Client, "rv.confirm_then_work", runIDArgs{RunID: parked.RunID}, uuid(1))
	if err := <-x.settled; err != nil {
		t.Fatal(err)
	}
	r, err := h.Client.Run(context.Background(), "test.echo", echoArgs{Name: "x"}, uuid(2), "admin")
	if err == nil {
		t.Errorf("write %s accepted while %s (net.confirm) was still running after its Settle", r.RunID, cf.RunID)
	} else if !client.IsCode(err, api.CodeBusy) {
		t.Errorf("want 409 busy, got %v", err)
	}
	close(x.release)
	finish(t, h.Client, cf.RunID)
}

func TestAwaiting_AwaitingFromAReadCommandIsInvalid(t *testing.T) {
	t.Parallel()
	h, x := startReview(t)
	blk := run(t, h.Client, "rv.block", nil, uuid(1))
	<-x.blocking
	rp := run(t, h.Client, "rv.read_park", nil, uuid(2))
	deadline := time.Now().Add(5 * time.Second)
	for !h.Server.AwaitingConfirm() && time.Now().Before(deadline) {
		if r, _ := h.Client.GetRun(context.Background(), rp.RunID); r.Status.Terminal() {
			break
		}
		<-time.After(5 * time.Millisecond)
	}
	if !h.Server.AwaitingConfirm() {
		got, _ := h.Client.GetRun(context.Background(), rp.RunID)
		if got.Status != api.StatusFailed || got.Error == nil || got.Error.Code != api.CodeCommandFailed {
			t.Errorf("the read command's run = %+v, want failed command_failed", got)
		}
		close(x.release)
		return
	}
	t.Errorf("a read command (%s) parked as the awaiting run without holding the write lock", rp.RunID)
	hr, err := h.Client.Run(context.Background(), "test.hold", runIDArgs{RunID: rp.RunID}, uuid(3), "admin")
	if err == nil {
		select {
		case <-x.holding:
			t.Errorf("WhileAwaiting write %s ran while write %s held the lock: two writes at once", hr.RunID, blk.RunID)
		case <-time.After(2 * time.Second):
		}
	}
	close(x.hold)
	close(x.release)
	_ = h.Server.Settle(rp.RunID, api.StatusSucceeded, nil)
}

func TestAwaiting_AwaitingFromAWhileAwaitingCommandIsInvalidAndDoesNotOrphanTheWaitingRun(t *testing.T) {
	t.Parallel()
	h, _ := startReview(t)
	parked := park(t, h, rid1)
	cp := run(t, h.Client, "rv.confirm_park", runIDArgs{RunID: parked.RunID}, uuid(1))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r, _ := h.Client.GetRun(context.Background(), cp.RunID); r.Status != api.StatusRunning && r.Status != api.StatusQueued {
			break
		}
		<-time.After(5 * time.Millisecond)
	}
	if got, _ := h.Client.GetRun(context.Background(), cp.RunID); got.Status != api.StatusFailed || got.Error == nil || got.Error.Code != api.CodeCommandFailed {
		t.Errorf("the WhileAwaiting command's run = %+v, want failed command_failed", got)
	}
	if err := h.Server.Settle(parked.RunID, api.StatusReverted, &api.RunError{Code: "not_confirmed", Message: "Timer."}); err != nil {
		t.Errorf("the original awaiting run can no longer be settled: %v", err)
		_ = h.Server.Settle(cp.RunID, api.StatusSucceeded, nil) // settle whatever is "waiting" now
	}
	if h.Server.WriteActive() {
		t.Errorf("the write lock is still held after every run was settled (orphaned by %s)", cp.RunID)
	}
	if got, _ := h.Client.GetRun(context.Background(), parked.RunID); got.Status == api.StatusAwaitingConfirm {
		t.Errorf("run %s is stuck in awaiting_confirm", parked.RunID)
	}
}

func TestAwaiting_ResumedStreamContinuesAfterEventsLoggedWhileWaiting(t *testing.T) {
	t.Parallel()
	h, x := startReview(t, func(o *server.Options) { o.Resume = func(api.Run) bool { return true } })
	r := run(t, h.Client, "rv.park_keep_rc", nil, rid1)
	waitStatus(t, h.Client, r.RunID, api.StatusAwaitingConfirm)
	x.rc.Load().Log("reverting in 120 s unless confirmed")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := h.Client.Events(ctx, r.RunID, 0)
	var lastSeen api.Event
	for lastSeen.Kind != api.KindLog {
		ev, err := s.Next()
		if err != nil {
			t.Fatal(err)
		}
		lastSeen = ev
	}
	s.Close()
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	if err := h.Server.Shutdown(sctx); err != nil {
		t.Fatal(err)
	}
	h2 := prepareAwait(t, x.all, func(o *server.Options) {
		o.StateDir, o.AuditPath, o.SocketPath = h.StateDir, h.AuditPath, h.Socket+"2"
		o.Resume = func(api.Run) bool { return true }
	})
	h2.Serve(t)
	if err := h2.Server.Settle(r.RunID, api.StatusSucceeded, nil); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	s2 := h2.Client.Events(ctx2, r.RunID, lastSeen.Seq)
	defer s2.Close()
	var final bool
	for {
		ev, err := s2.Next()
		if err != nil {
			break
		}
		if ev.Kind == api.KindState && ev.Status == api.StatusSucceeded {
			final = true
		}
	}
	if !final {
		all := finishEvents(t, h2.Client, r.RunID)
		t.Errorf("a client resuming after seq %d never sees the final state; events after restart: %s", lastSeen.Seq, all)
	}
}

func finishEvents(t *testing.T, c *client.Client, runID string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := c.Events(ctx, runID, 0)
	defer s.Close()
	var b strings.Builder
	for {
		ev, err := s.Next()
		if err != nil {
			return b.String()
		}
		b.WriteString(jsonOf(map[string]any{"seq": ev.Seq, "kind": ev.Kind, "status": ev.Status, "line": ev.Line}))
	}
}

func TestAwaiting_ResumedRunWithWriteFalseStillReleasesTheLockAtSettle(t *testing.T) {
	t.Parallel()
	x := newAwaitFx(t)
	h := prepareAwait(t, x.cmds)
	x.srv.Store(h.Server)
	h.Serve(t)
	parked := park(t, h, rid1)
	if err := h.Server.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := h.StateDir + "/runs/" + parked.RunID + ".json"
	b, err := os.ReadFile(path) //nolint:gosec // the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(b), `"write":true`, `"write":false`, 1)
	if edited == string(b) {
		t.Fatal("run file has no write flag to edit")
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil { //nolint:gosec // the test's own temp dir
		t.Fatal(err)
	}
	h2 := prepareAwait(t, x.cmds, func(o *server.Options) {
		o.StateDir, o.AuditPath, o.SocketPath = h.StateDir, h.AuditPath, h.Socket+"2"
		o.Resume = func(api.Run) bool { return true }
	})
	h2.Serve(t)
	if err := h2.Server.Settle(parked.RunID, api.StatusSucceeded, nil); err != nil {
		t.Fatal(err)
	}
	if h2.Server.WriteActive() {
		t.Error("the write lock is still held after the resumed run settled")
	}
	if _, err := h2.Client.Run(context.Background(), "test.echo", echoArgs{Name: "x"}, rid2, "admin"); err != nil {
		var ce *client.Error
		if errors.As(err, &ce) && ce.Status == http.StatusConflict {
			t.Errorf("writes are refused for good: %v", err)
		}
	}
}

// ---- Claim and Finish: decide the race first, then work, then finish ----

func TestAwaiting_ClaimDecidesTheRaceBeforeAnyEffectRuns(t *testing.T) {
	t.Parallel()
	h, x := startAwait(t)
	parked := park(t, h, rid1)
	// The timer wins: it claims the run and starts its revert work.
	c, err := h.Server.Claim(parked.RunID)
	if err != nil {
		t.Fatal(err)
	}
	// A confirm that arrives during the revert work is refused by the framework and runs nothing.
	_, err = h.Client.Run(context.Background(), "test.confirm", runIDArgs{RunID: parked.RunID}, rid2, "admin")
	_ = clientErr(t, err, http.StatusPreconditionFailed, api.CodeNotAwaitingConfirm)
	if x.confirms.Load() != 0 {
		t.Fatal("a confirm ran after the timer had claimed the run")
	}
	// A second claim and a Settle lose too; the run is still not final.
	if _, err := h.Server.Claim(parked.RunID); !errors.Is(err, server.ErrNotAwaiting) {
		t.Fatalf("second Claim = %v", err)
	}
	if err := h.Server.Settle(parked.RunID, api.StatusSucceeded, nil); !errors.Is(err, server.ErrNotAwaiting) {
		t.Fatalf("Settle after Claim = %v", err)
	}
	if got, _ := h.Client.GetRun(context.Background(), parked.RunID); got.Status != api.StatusAwaitingConfirm {
		t.Fatalf("run = %+v before Finish", got)
	}
	// The write lock is kept while the winner works: an ordinary write is busy, not pending_confirm.
	_, err = h.Client.Run(context.Background(), "test.echo", echoArgs{Name: "x"}, rid3, "admin")
	if ce := clientErr(t, err, http.StatusConflict, api.CodeBusy); ce.RunID != parked.RunID {
		t.Fatalf("busy run_id %q", ce.RunID)
	}
	if !h.Server.WriteActive() || h.Server.AwaitingConfirm() {
		t.Fatalf("WriteActive %v AwaitingConfirm %v", h.Server.WriteActive(), h.Server.AwaitingConfirm())
	}
	// A bad status does not close the claim; the real one does, once.
	if err := c.Finish(api.StatusReverted, nil); err == nil {
		t.Fatal("Finish accepted reverted without an error")
	}
	if err := c.Finish(api.StatusReverted, &api.RunError{Code: "not_confirmed", Message: "Timer."}); err != nil {
		t.Fatal(err)
	}
	if err := c.Finish(api.StatusSucceeded, nil); !errors.Is(err, server.ErrNotAwaiting) {
		t.Fatalf("second Finish = %v", err)
	}
	if fin := finish(t, h.Client, parked.RunID); fin.Status != api.StatusReverted || fin.Error.Code != "not_confirmed" {
		t.Fatalf("run = %+v", fin)
	}
	if h.Server.WriteActive() {
		t.Fatal("lock still held after Finish")
	}
	if got := strings.Join(auditFor(t, h, parked.RunID), ","); got != "accepted,awaiting_confirm,reverted" {
		t.Fatalf("audit = %s", got)
	}
}

func TestAwaiting_ClaimAfterShutdownIsRefusedAndTheRunStaysAwaiting(t *testing.T) {
	t.Parallel()
	h, _ := startAwait(t)
	parked := park(t, h, rid1)
	if err := h.Server.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Server.Claim(parked.RunID); !errors.Is(err, server.ErrShuttingDown) {
		t.Fatalf("Claim after Shutdown = %v", err)
	}
	if !h.Server.AwaitingConfirm() {
		t.Fatal("a refused Claim changed the state")
	}
}

// ---- Awaits and the validation of Awaiting ----

func TestAwaiting_RegistryRulesForAwaitsAndWhileAwaiting(t *testing.T) {
	t.Parallel()
	ok := func(context.Context, *server.RunContext, runIDArgs) (any, error) { return nil, nil }
	type noRunID struct {
		Name string `json:"name"`
	}
	type wrongType struct {
		RunID int `json:"run_id"`
	}
	bad := map[string]server.Command{
		"awaits and while-awaiting": server.Define(server.Spec[runIDArgs]{Name: "t.a", Write: true, Awaits: true, WhileAwaiting: true, Timeout: time.Second, Run: ok}),
		"awaits on a read command":  server.Define(server.Spec[runIDArgs]{Name: "t.b", Awaits: true, Timeout: time.Second, Run: ok}),
		"while-awaiting, no run_id": server.Define(server.Spec[noRunID]{Name: "t.c", Write: true, WhileAwaiting: true, Timeout: time.Second, Run: func(context.Context, *server.RunContext, noRunID) (any, error) { return nil, nil }}),
		"run_id of the wrong type":  server.Define(server.Spec[wrongType]{Name: "t.d", Write: true, WhileAwaiting: true, Timeout: time.Second, Run: func(context.Context, *server.RunContext, wrongType) (any, error) { return nil, nil }}),
		"while-awaiting, no args":   server.Define(server.Spec[struct{}]{Name: "t.e", Write: true, WhileAwaiting: true, Timeout: time.Second, Run: func(context.Context, *server.RunContext, struct{}) (any, error) { return nil, nil }}),
	}
	for name, c := range bad {
		if _, err := server.NewRegistry(c); err == nil {
			t.Errorf("%s: NewRegistry accepted it", name)
		}
	}
	good := []server.Command{
		server.Define(server.Spec[runIDArgs]{Name: "t.f", Write: true, WhileAwaiting: true, Timeout: time.Second, Run: ok}),
		server.Define(server.Spec[struct{}]{Name: "t.g", Write: true, Awaits: true, Timeout: time.Second, Run: func(context.Context, *server.RunContext, struct{}) (any, error) { return nil, nil }}),
	}
	if _, err := server.NewRegistry(good...); err != nil {
		t.Fatal(err)
	}
}

func TestAwaiting_AwaitingFromACommandThatIsNotDeclaredAwaitsFails(t *testing.T) {
	t.Parallel()
	hr, _ := startReview(t)
	r := run(t, hr.Client, "rv.undeclared_park", nil, rid1)
	fin := finish(t, hr.Client, r.RunID)
	if fin.Status != api.StatusFailed || fin.Error == nil || fin.Error.Code != api.CodeCommandFailed || fin.RevertAt != nil {
		t.Fatalf("run = %+v", fin)
	}
	if hr.Server.AwaitingConfirm() || hr.Server.WriteActive() {
		t.Fatal("an undeclared Awaiting left state behind")
	}
}

// ---- RevertAt bounds, OnParked, resume clamp ----

func TestAwaiting_RevertAtMustBeInTheFutureAndWithinTheConfirmWindow(t *testing.T) {
	t.Parallel()
	h, x := startReview(t)
	for name, c := range map[string]struct {
		in   time.Duration
		want api.Status
	}{
		"in the past":       {-time.Second, api.StatusFailed},
		"now":               {0, api.StatusFailed},
		"one hour":          {time.Hour, api.StatusFailed},
		"just over 660 s":   {661 * time.Second, api.StatusFailed},
		"inside the window": {600 * time.Second, api.StatusAwaitingConfirm},
	} {
		x.revertIn.Store(int64(c.in))
		r := run(t, h.Client, "rv.park_in", nil, uuid(int(c.in/time.Second)+5000))
		var got api.Run
		if c.want == api.StatusAwaitingConfirm {
			got = waitStatus(t, h.Client, r.RunID, c.want)
			if err := h.Server.Settle(r.RunID, api.StatusSucceeded, nil); err != nil {
				t.Fatal(err)
			}
		} else {
			got = finish(t, h.Client, r.RunID)
		}
		if got.Status != c.want {
			t.Errorf("%s: status %s, want %s", name, got.Status, c.want)
		}
		if c.want == api.StatusFailed && (got.Error == nil || got.Error.Code != api.CodeCommandFailed || h.Server.WriteActive()) {
			t.Errorf("%s: %+v, lock %v", name, got.Error, h.Server.WriteActive())
		}
	}
}

func TestAwaiting_OnParkedRunsAfterTheRunIsParkedSoAnEarlyTimerCanSettle(t *testing.T) {
	t.Parallel()
	h, x := startReview(t)
	r := run(t, h.Client, "rv.park_arm", nil, rid1)
	// The "timer" fires at once from OnParked: the run must already be awaiting.
	if err := <-x.armed; err != nil {
		t.Fatalf("an early Settle from OnParked = %v", err)
	}
	if fin := finish(t, h.Client, r.RunID); fin.Status != api.StatusReverted {
		t.Fatalf("run = %+v", fin)
	}
	// OnParked is not called for a run that failed to park.
	x.parkedCalls.Store(0)
	x.revertIn.Store(int64(-time.Second))
	bad := run(t, h.Client, "rv.park_in", nil, rid2)
	finish(t, h.Client, bad.RunID)
	if x.parkedCalls.Load() != 0 {
		t.Fatal("OnParked ran for a run that was not parked")
	}
}

func TestAwaiting_ResumeClampsAStoredRevertAtBeyondTheWindow(t *testing.T) {
	t.Parallel()
	x := newAwaitFx(t)
	h := prepareAwait(t, x.cmds)
	x.srv.Store(h.Server)
	h.Serve(t)
	parked := park(t, h, rid1)
	if err := h.Server.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := h.StateDir + "/runs/" + parked.RunID + ".json"
	b, err := os.ReadFile(path) //nolint:gosec // the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	far := parked.StartedAt.Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)
	edited := strings.Replace(string(b), `"revert_at":"`+parked.RevertAt.UTC().Format(time.RFC3339Nano)+`"`, `"revert_at":"`+far+`"`, 1)
	if edited == string(b) {
		t.Fatalf("no revert_at to edit in %s", b)
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil { //nolint:gosec // the test's own temp dir
		t.Fatal(err)
	}
	var seen api.Run
	h2 := prepareAwait(t, x.cmds, func(o *server.Options) {
		o.StateDir, o.AuditPath, o.SocketPath = h.StateDir, h.AuditPath, h.Socket+"2"
		o.Resume = func(r api.Run) bool { seen = r; return true }
	})
	h2.Serve(t)
	limit := parked.StartedAt.Add(660 * time.Second)
	got, err := h2.Client.GetRun(context.Background(), parked.RunID)
	if err != nil || got.RevertAt == nil || got.RevertAt.After(limit) || got.RevertAt.Before(limit.Add(-time.Second)) {
		t.Fatalf("revert_at after resume = %v (limit %v) %v", got.RevertAt, limit, err)
	}
	_ = seen
}
