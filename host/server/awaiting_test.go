package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

// Tests of the framework support for runs that wait for confirmation (D-100, WP-07b part 3,
// slice 3-1). The commands here exist only in this file: production registers none of them.

type runIDArgs struct {
	RunID string `json:"run_id"`
}

type padArgs struct {
	Pad string `json:"pad"`
}

// awaitFx holds the test commands and what they observed. srv is set once the server exists.
type awaitFx struct {
	srv      atomic.Pointer[server.Server]
	parks    atomic.Int64
	confirms atomic.Int64
	after    chan api.Status
	hold     chan struct{} // test.hold blocks until it is closed
	holding  chan struct{}
	cmds     []server.Command
}

func validRunID(a *runIDArgs) error {
	if len(a.RunID) != 19 || !strings.HasPrefix(a.RunID, "rn_") {
		return server.Invalid("run_id", "must be a run id")
	}
	return nil
}

func newAwaitFx(t testing.TB) *awaitFx {
	t.Helper()
	base := newFixture(t)
	x := &awaitFx{after: make(chan api.Status, 8), hold: make(chan struct{}), holding: make(chan struct{}, 4)}
	t.Cleanup(func() {
		select {
		case <-x.hold:
		default:
			close(x.hold)
		}
	})
	settle := func(status api.Status, rerr *api.RunError) func(context.Context, *server.RunContext, runIDArgs) (any, error) {
		return func(_ context.Context, _ *server.RunContext, a runIDArgs) (any, error) {
			x.confirms.Add(1)
			err := x.srv.Load().Settle(a.RunID, status, rerr) //nolint:contextcheck // Settle takes no context: it must finish even when the caller's is cancelled
			if errors.Is(err, server.ErrNotAwaiting) {
				return nil, server.Refuse(http.StatusPreconditionFailed, api.CodeNotAwaitingConfirm, "Nothing is waiting.")
			}
			if err != nil {
				return nil, err
			}
			return map[string]bool{"settled": true}, nil
		}
	}
	x.cmds = append(base.cmds,
		server.Define(server.Spec[struct{}]{
			Name: "test.park", Write: true, Awaits: true, Timeout: 5 * time.Second,
			Run: func(_ context.Context, rc *server.RunContext, _ struct{}) (any, error) {
				x.parks.Add(1)
				rc.AfterFinish(func(_ context.Context, st api.Status) { x.after <- st })
				return server.Awaiting{RevertAt: time.Now().Add(2 * time.Minute), Result: map[string]int{"window_s": 120}}, nil
			},
		}),
		server.Define(server.Spec[struct{}]{
			Name: "test.park_nodeadline", Write: true, Awaits: true, Timeout: 5 * time.Second,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) { return server.Awaiting{}, nil },
		}),
		server.Define(server.Spec[struct{}]{
			Name: "test.park_error", Write: true, Awaits: true, Timeout: 5 * time.Second,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
				return &server.Awaiting{RevertAt: time.Now().Add(time.Minute)}, errors.New("changed my mind")
			},
		}),
		server.Define(server.Spec[runIDArgs]{
			Name: "test.confirm", Write: true, WhileAwaiting: true, Timeout: 5 * time.Second, Validate: validRunID,
			Run: settle(api.StatusSucceeded, nil),
		}),
		server.Define(server.Spec[runIDArgs]{
			Name: "test.revert", Write: true, WhileAwaiting: true, Timeout: 5 * time.Second, Validate: validRunID,
			Run: settle(api.StatusReverted, &api.RunError{Code: "cancelled", Message: "Cancelled."}),
		}),
		server.Define(server.Spec[runIDArgs]{
			Name: "test.hold", Write: true, WhileAwaiting: true, Timeout: 5 * time.Second, Validate: validRunID,
			Run: func(ctx context.Context, _ *server.RunContext, _ runIDArgs) (any, error) {
				x.holding <- struct{}{}
				select {
				case <-x.hold:
					return nil, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			},
		}),
		server.Define(server.Spec[padArgs]{
			Name: "test.big", Write: true, Timeout: 5 * time.Second, MaxBody: 1 << 20,
			Run: func(context.Context, *server.RunContext, padArgs) (any, error) { return nil, nil },
		}),
		server.Define(server.Spec[padArgs]{
			Name: "test.small", Write: true, Timeout: 5 * time.Second,
			Run: func(context.Context, *server.RunContext, padArgs) (any, error) { return nil, nil },
		}),
	)
	return x
}

// prepareAwait is servertest.Prepare on the real clock: the test commands compute RevertAt from
// time.Now(), and the server checks it against its own clock and the start of the run.
func prepareAwait(t testing.TB, cmds []server.Command, mutate ...func(*server.Options)) *servertest.Harness {
	t.Helper()
	return servertest.Prepare(t, cmds, append([]func(*server.Options){func(o *server.Options) { o.Now = time.Now }}, mutate...)...)
}

func startAwait(t testing.TB) (*servertest.Harness, *awaitFx) {
	t.Helper()
	x := newAwaitFx(t)
	h := prepareAwait(t, x.cmds)
	x.srv.Store(h.Server)
	h.Serve(t)
	return h, x
}

// waitStatus reads the run until it has the status.
func waitStatus(t testing.TB, c *client.Client, runID string, want api.Status) api.Run {
	t.Helper()
	var r api.Run
	var err error
	waitFor(t, "run "+runID+" to be "+string(want), func() bool {
		r, err = c.GetRun(context.Background(), runID)
		return err == nil && r.Status == want
	})
	return r
}

// park starts test.park and waits until the run awaits confirmation.
func park(t testing.TB, h *servertest.Harness, id string) api.Run {
	t.Helper()
	r := run(t, h.Client, "test.park", nil, id)
	return waitStatus(t, h.Client, r.RunID, api.StatusAwaitingConfirm)
}

func clientErr(t testing.TB, err error, status int, code string) *client.Error {
	t.Helper()
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Status != status || ce.Code != code {
		t.Fatalf("want %d %s, got %v", status, code, err)
	}
	return ce
}

func auditFor(t testing.TB, h *servertest.Harness, runID string) (results []string) {
	t.Helper()
	for _, a := range auditLines(t, h) {
		if a.RunID != nil && *a.RunID == runID {
			results = append(results, a.Result)
		}
	}
	return results
}

func TestAwaiting_HoldsTheWriteLockAndAnswersPendingConfirm(t *testing.T) {
	t.Parallel()
	h, x := startAwait(t)
	parked := park(t, h, rid1)
	if parked.RevertAt == nil || !parked.RevertAt.After(time.Now()) || parked.FinishedAt != nil || string(parked.Result) != `{"window_s":120}` {
		t.Fatalf("awaiting run = %+v", parked)
	}
	if !h.Server.WriteActive() || !h.Server.AwaitingConfirm() {
		t.Fatal("the awaiting run must hold the lock")
	}
	// Another write: 409 pending_confirm, with the run id of the waiting run; no run starts.
	ran := x.parks.Load()
	_, err := h.Client.Run(context.Background(), "test.echo", echoArgs{Name: "x"}, rid2, "admin")
	if ce := clientErr(t, err, http.StatusConflict, api.CodePendingConfirm); ce.RunID != parked.RunID {
		t.Fatalf("pending_confirm run_id = %q, want %q", ce.RunID, parked.RunID)
	}
	if _, err := h.Client.Run(context.Background(), "test.park", nil, rid3, "admin"); err == nil || !client.IsCode(err, api.CodePendingConfirm) || x.parks.Load() != ran {
		t.Fatalf("a second park: %v (parks %d)", err, x.parks.Load())
	}
	// The refusal is recorded as a refused run (spec 4: every command leaves a line).
	if l := lastAudit(t, h); l.Result != "refused" || l.Code == nil || *l.Code != api.CodePendingConfirm {
		t.Fatalf("last audit = %+v", l)
	}
	// Reads are not locked: a read command, the run, the list, the events and the info.
	if r, err := h.Client.Run(context.Background(), "test.read", nil, uuid(1), "admin"); err != nil {
		t.Fatalf("read command while awaiting: %v %+v", err, r)
	}
	if got, err := h.Client.GetRun(context.Background(), parked.RunID); err != nil || got.Status != api.StatusAwaitingConfirm {
		t.Fatalf("GetRun: %+v %v", got, err)
	}
	if runs, err := h.Client.ListRuns(context.Background(), 10); err != nil || len(runs) == 0 {
		t.Fatalf("ListRuns: %v %v", runs, err)
	}
	if _, err := h.Client.Info(context.Background()); err != nil {
		t.Fatalf("info: %v", err)
	}
	// Only the matching confirm ends it, and then the lock is free again.
	cf := run(t, h.Client, "test.confirm", runIDArgs{RunID: parked.RunID}, uuid(2))
	if fin := finish(t, h.Client, cf.RunID); fin.Status != api.StatusSucceeded {
		t.Fatalf("confirm run = %+v", fin)
	}
	done := finish(t, h.Client, parked.RunID)
	if done.Status != api.StatusSucceeded || done.RevertAt != nil || done.FinishedAt == nil || string(done.Result) != `{"window_s":120}` {
		t.Fatalf("settled run = %+v", done)
	}
	if h.Server.WriteActive() || h.Server.AwaitingConfirm() {
		t.Fatal("the lock must be free after settle")
	}
	run(t, h.Client, "test.echo", echoArgs{Name: "after"}, uuid(3))
	select {
	case st := <-x.after:
		if st != api.StatusSucceeded {
			t.Fatalf("AfterFinish saw %s", st)
		}
	case <-time.After(hangBound):
		t.Fatal("AfterFinish of the awaiting run never ran")
	}
}

func TestAwaiting_AuditHasThreeLinesAcceptedAwaitingFinal(t *testing.T) {
	t.Parallel()
	h, _ := startAwait(t)
	parked := park(t, h, rid1)
	if got := auditFor(t, h, parked.RunID); strings.Join(got, ",") != "accepted,awaiting_confirm" {
		t.Fatalf("while waiting: %v", got)
	}
	if err := h.Server.Settle(parked.RunID, api.StatusReverted, &api.RunError{Code: "not_confirmed", Message: "Not confirmed in time."}); err != nil {
		t.Fatal(err)
	}
	if got := auditFor(t, h, parked.RunID); strings.Join(got, ",") != "accepted,awaiting_confirm,reverted" {
		t.Fatalf("after settle: %v", got)
	}
	last := lastAudit(t, h)
	if last.Code == nil || *last.Code != "not_confirmed" {
		t.Fatalf("final line = %+v", last)
	}
	fin := finish(t, h.Client, parked.RunID)
	if fin.Status != api.StatusReverted || fin.Error == nil || fin.Error.Code != "not_confirmed" {
		t.Fatalf("run = %+v", fin)
	}
	// The event stream shows running, awaiting_confirm, reverted in order.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := h.Client.Events(ctx, parked.RunID, 0)
	defer s.Close()
	var states []api.Status
	for {
		ev, err := s.Next()
		if err != nil {
			break
		}
		if ev.Kind == api.KindState {
			states = append(states, ev.Status)
		}
	}
	if fmt.Sprint(states) != "[running awaiting_confirm reverted]" {
		t.Fatalf("states = %v", states)
	}
	// The chain still verifies end to end (no line was lost or doubled).
	if err := h.Server.AuditError(); err != nil {
		t.Fatal(err)
	}
}

func TestAwaiting_WhileAwaitingGetsThroughOnlyForTheMatchingRun(t *testing.T) {
	t.Parallel()
	h, x := startAwait(t)
	// Nothing awaits: refused by the framework, the command never runs.
	_, err := h.Client.Run(context.Background(), "test.confirm", runIDArgs{RunID: "rn_0123456789abcdef"}, rid1, "admin")
	_ = clientErr(t, err, http.StatusPreconditionFailed, api.CodeNotAwaitingConfirm)
	if x.confirms.Load() != 0 {
		t.Fatal("a confirm ran with nothing waiting")
	}
	parked := park(t, h, rid2)
	// A wrong run id (well formed, and another run's id) is refused the same way and the real one keeps waiting.
	other := run(t, h.Client, "test.read", nil, uuid(5))
	for i, id := range []string{"rn_0123456789abcdef", other.RunID} {
		_, err = h.Client.Run(context.Background(), "test.revert", runIDArgs{RunID: id}, uuid(10+i), "admin")
		_ = clientErr(t, err, http.StatusPreconditionFailed, api.CodeNotAwaitingConfirm)
	}
	// A malformed id is a plain invalid_args.
	_, err = h.Client.Run(context.Background(), "test.confirm", runIDArgs{RunID: "x"}, uuid(20), "admin")
	_ = clientErr(t, err, http.StatusBadRequest, api.CodeInvalidArgs)
	if x.confirms.Load() != 0 || !h.Server.AwaitingConfirm() {
		t.Fatalf("confirms %d, awaiting %v", x.confirms.Load(), h.Server.AwaitingConfirm())
	}
	// The matching one works; afterwards the same id is refused (the run settled).
	cf := run(t, h.Client, "test.revert", runIDArgs{RunID: parked.RunID}, uuid(30))
	finish(t, h.Client, cf.RunID)
	if r := finish(t, h.Client, parked.RunID); r.Status != api.StatusReverted || r.Error.Code != "cancelled" {
		t.Fatalf("run = %+v", r)
	}
	_, err = h.Client.Run(context.Background(), "test.confirm", runIDArgs{RunID: parked.RunID}, uuid(31), "admin")
	_ = clientErr(t, err, http.StatusPreconditionFailed, api.CodeNotAwaitingConfirm)
	if x.confirms.Load() != 1 {
		t.Fatalf("settle commands ran %d times, want 1", x.confirms.Load())
	}
}

func TestAwaiting_OneWhileAwaitingCommandAtATime(t *testing.T) {
	t.Parallel()
	h, x := startAwait(t)
	parked := park(t, h, rid1)
	first := run(t, h.Client, "test.hold", runIDArgs{RunID: parked.RunID}, uuid(1))
	<-x.holding
	_, err := h.Client.Run(context.Background(), "test.confirm", runIDArgs{RunID: parked.RunID}, uuid(2), "admin")
	if ce := clientErr(t, err, http.StatusConflict, api.CodeBusy); ce.RunID != first.RunID {
		t.Fatalf("busy run_id = %q, want %q", ce.RunID, first.RunID)
	}
	// The write lock itself is still answered with pending_confirm for an ordinary write.
	_, err = h.Client.Run(context.Background(), "test.echo", echoArgs{Name: "x"}, uuid(3), "admin")
	_ = clientErr(t, err, http.StatusConflict, api.CodePendingConfirm)
	close(x.hold)
	finish(t, h.Client, first.RunID)
	// The held command did not settle; the run still awaits and the slot is free again.
	if !h.Server.AwaitingConfirm() {
		t.Fatal("run no longer awaiting")
	}
	cf := run(t, h.Client, "test.confirm", runIDArgs{RunID: parked.RunID}, uuid(4))
	if fin := finish(t, h.Client, cf.RunID); fin.Status != api.StatusSucceeded {
		t.Fatalf("%+v", fin)
	}
}

func TestAwaiting_SettleWorksExactlyOnceUnderConcurrency(t *testing.T) {
	t.Parallel()
	h, x := startAwait(t)
	parked := park(t, h, rid1)
	var wins, notAwaiting, other atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	settle := func(st api.Status, rerr *api.RunError) {
		defer wg.Done()
		<-start
		switch err := h.Server.Settle(parked.RunID, st, rerr); {
		case err == nil:
			wins.Add(1)
		case errors.Is(err, server.ErrNotAwaiting):
			notAwaiting.Add(1)
		default:
			other.Add(1)
		}
	}
	for i := range 50 { // the confirm side and the timer side, 25 each
		wg.Add(1)
		if i%2 == 0 {
			go settle(api.StatusSucceeded, nil)
		} else {
			go settle(api.StatusReverted, &api.RunError{Code: "not_confirmed", Message: "Timer."})
		}
	}
	// A confirm command over the socket joins the race.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		if r, err := h.Client.Run(context.Background(), "test.confirm", runIDArgs{RunID: parked.RunID}, uuid(1), "admin"); err == nil {
			finish(t, h.Client, r.RunID)
		}
	}()
	close(start)
	wg.Wait()
	if wins.Load() > 1 || other.Load() != 0 {
		t.Fatalf("wins %d, not awaiting %d, other errors %d", wins.Load(), notAwaiting.Load(), other.Load())
	}
	fin := finish(t, h.Client, parked.RunID)
	finals := 0
	for _, r := range auditFor(t, h, parked.RunID) {
		if r != "accepted" && r != "awaiting_confirm" {
			finals++
		}
	}
	if finals != 1 {
		t.Fatalf("%d final audit lines for the run: %v", finals, auditFor(t, h, parked.RunID))
	}
	// Whichever side won is what the run says; the loser changed nothing.
	if fin.Status != api.StatusSucceeded && fin.Status != api.StatusReverted {
		t.Fatalf("run = %+v", fin)
	}
	if err := h.Server.Settle(parked.RunID, api.StatusSucceeded, nil); !errors.Is(err, server.ErrNotAwaiting) {
		t.Fatalf("a late Settle = %v", err)
	}
	if got, _ := h.Client.GetRun(context.Background(), parked.RunID); got.Status != fin.Status {
		t.Fatalf("a late Settle changed the run: %+v", got)
	}
	select {
	case <-x.after:
	case <-time.After(hangBound):
		t.Fatal("no AfterFinish")
	}
	select {
	case st := <-x.after:
		t.Fatalf("AfterFinish ran twice (%s)", st)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestAwaiting_SettleRejectsBadStatusWithoutConsumingTheRun(t *testing.T) {
	t.Parallel()
	h, _ := startAwait(t)
	parked := park(t, h, rid1)
	for _, c := range []struct {
		st   api.Status
		rerr *api.RunError
	}{
		{api.StatusRunning, nil}, {api.StatusAwaitingConfirm, nil}, {api.StatusRefused, &api.RunError{Code: "x"}},
		{api.StatusFailed, nil}, {api.StatusReverted, nil}, {"bogus", nil},
	} {
		if err := h.Server.Settle(parked.RunID, c.st, c.rerr); err == nil || errors.Is(err, server.ErrNotAwaiting) {
			t.Errorf("Settle(%q, %v) = %v", c.st, c.rerr, err)
		}
	}
	if !h.Server.AwaitingConfirm() {
		t.Fatal("a bad Settle consumed the run")
	}
	if err := h.Server.Settle("rn_ffffffffffffffff", api.StatusSucceeded, nil); !errors.Is(err, server.ErrNotAwaiting) {
		t.Fatalf("unknown run: %v", err)
	}
}

func TestAwaiting_SettleRacingShutdownLeavesAConsistentRun(t *testing.T) {
	t.Parallel()
	for i := range 12 {
		x := newAwaitFx(t)
		h := prepareAwait(t, x.cmds, func(o *server.Options) {
			o.Resume = func(api.Run) bool { return true }
		})
		x.srv.Store(h.Server)
		h.Serve(t)
		parked := park(t, h, uuid(100+i))
		var settleErr error
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			settleErr = h.Server.Settle(parked.RunID, api.StatusSucceeded, nil)
		}()
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := h.Server.Shutdown(ctx); err != nil {
				t.Errorf("shutdown: %v", err)
			}
		}()
		close(start)
		wg.Wait()
		switch {
		case settleErr == nil:
			// Settle got in first: the run is final on disk, with its line, before Shutdown closed the audit log.
		case errors.Is(settleErr, server.ErrShuttingDown):
			// Shutdown won: nothing changed. A restart that resumes finds the run still awaiting.
		default:
			t.Fatalf("Settle = %v", settleErr)
		}
		h2 := prepareAwait(t, x.cmds, func(o *server.Options) {
			o.StateDir, o.AuditPath, o.SocketPath = h.StateDir, h.AuditPath, h.Socket+"2"
			o.Resume = func(api.Run) bool { return true }
		})
		h2.Serve(t)
		got, err := h2.Client.GetRun(context.Background(), parked.RunID)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Join(auditFor(t, h2, parked.RunID), ",")
		if settleErr == nil && (got.Status != api.StatusSucceeded || lines != "accepted,awaiting_confirm,ok") {
			t.Fatalf("iteration %d: settled, but run %+v lines %s", i, got, lines)
		}
		if settleErr != nil && (got.Status != api.StatusAwaitingConfirm || lines != "accepted,awaiting_confirm") {
			t.Fatalf("iteration %d: refused, but run %+v lines %s", i, got, lines)
		}
		if err := h2.Server.AuditError(); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
}

func TestAwaiting_SettleAfterShutdownIsRefused(t *testing.T) {
	t.Parallel()
	h, _ := startAwait(t)
	parked := park(t, h, rid1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.Server.Settle(parked.RunID, api.StatusSucceeded, nil); !errors.Is(err, server.ErrShuttingDown) {
		t.Fatalf("Settle after Shutdown = %v", err)
	}
}

func TestAwaiting_RunSurvivesARestartWhenResumeSaysSo(t *testing.T) {
	t.Parallel()
	x := newAwaitFx(t)
	h := prepareAwait(t, x.cmds)
	x.srv.Store(h.Server)
	h.Serve(t)
	parked := park(t, h, rid1)
	// Stream the events before the restart to know the numbering.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	if err := h.Server.Shutdown(sctx); err != nil {
		t.Fatal(err)
	}

	var asked []api.Run
	var socketAtResume atomic.Bool
	x2 := newAwaitFx(t)
	h2 := prepareAwait(t, x2.cmds, func(o *server.Options) {
		o.StateDir, o.AuditPath, o.SocketPath = h.StateDir, h.AuditPath, h.Socket+"2"
		o.Resume = func(r api.Run) bool {
			asked = append(asked, r)
			_, err := os.Lstat(o.SocketPath)
			socketAtResume.Store(err == nil)
			return true
		}
	})
	x2.srv.Store(h2.Server)
	// Recovery is finished before Listen: nothing listens yet, and the state is already settled.
	if _, err := os.Lstat(h2.Socket); err == nil {
		t.Fatal("the socket exists before Listen")
	}
	if len(asked) != 1 || asked[0].RunID != parked.RunID || asked[0].RevertAt == nil || asked[0].Status != api.StatusAwaitingConfirm || socketAtResume.Load() {
		t.Fatalf("Resume was asked %+v (socket present %v)", asked, socketAtResume.Load())
	}
	if !h2.Server.AwaitingConfirm() || !h2.Server.WriteActive() {
		t.Fatal("the resumed run must hold the lock before Listen")
	}
	h2.Serve(t)

	got, err := h2.Client.GetRun(context.Background(), parked.RunID)
	if err != nil || got.Status != api.StatusAwaitingConfirm || got.RevertAt == nil || !got.RevertAt.Equal(*parked.RevertAt) {
		t.Fatalf("after restart: %+v %v", got, err)
	}
	// The lock is held, with the same run id, and the WhileAwaiting rules apply as before.
	_, err = h2.Client.Run(context.Background(), "test.echo", echoArgs{Name: "x"}, rid2, "admin")
	if ce := clientErr(t, err, http.StatusConflict, api.CodePendingConfirm); ce.RunID != parked.RunID {
		t.Fatalf("run_id %q", ce.RunID)
	}
	_, err = h2.Client.Run(context.Background(), "test.confirm", runIDArgs{RunID: "rn_0123456789abcdef"}, rid3, "admin")
	_ = clientErr(t, err, http.StatusPreconditionFailed, api.CodeNotAwaitingConfirm)
	// The events continue where they left off and end at the final state.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	s2 := h2.Client.Events(ctx2, parked.RunID, seen[len(seen)-1].Seq)
	defer s2.Close()
	evCh := make(chan api.Event, 8)
	go func() {
		for {
			ev, err := s2.Next()
			if err != nil {
				close(evCh)
				return
			}
			evCh <- ev
		}
	}()
	// The caller re-arms its timer and settles: here by a confirm command, as the GUI would.
	cf, err := h2.Client.Run(context.Background(), "test.confirm", runIDArgs{RunID: parked.RunID}, uuid(7), "admin")
	if err != nil {
		t.Fatal(err)
	}
	finish(t, h2.Client, cf.RunID)
	var last api.Event
	for ev := range evCh {
		if ev.Seq <= seen[len(seen)-1].Seq {
			t.Fatalf("event %d repeated after resume", ev.Seq)
		}
		last = ev
	}
	if last.Kind != api.KindState || last.Status != api.StatusSucceeded {
		t.Fatalf("last event = %+v", last)
	}
	fin, _ := h2.Client.GetRun(context.Background(), parked.RunID)
	if fin.Status != api.StatusSucceeded || fin.RevertAt != nil || string(fin.Result) != `{"window_s":120}` {
		t.Fatalf("final run = %+v", fin)
	}
	if got := strings.Join(auditFor(t, h2, parked.RunID), ","); got != "accepted,awaiting_confirm,ok" {
		t.Fatalf("audit of the run across the restart: %s", got)
	}
	if h2.Server.WriteActive() {
		t.Fatal("lock still held")
	}
}

func TestAwaiting_RunIsFailedHostRestartedWithoutResume(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*server.Options){
		"nil":      func(*server.Options) {},
		"false":    func(o *server.Options) { o.Resume = func(api.Run) bool { return false } },
		"panics":   func(o *server.Options) { o.Resume = func(api.Run) bool { panic("boom") } },
		"unwanted": func(o *server.Options) { o.Resume = func(r api.Run) bool { return r.Command != "test.park" } },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			x := newAwaitFx(t)
			h := prepareAwait(t, x.cmds)
			x.srv.Store(h.Server)
			h.Serve(t)
			parked := park(t, h, rid1)
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := h.Server.Shutdown(sctx); err != nil {
				t.Fatal(err)
			}
			h2 := prepareAwait(t, x.cmds, func(o *server.Options) {
				o.StateDir, o.AuditPath, o.SocketPath = h.StateDir, h.AuditPath, h.Socket+"2"
				setup(o)
			})
			if h2.Server.AwaitingConfirm() || h2.Server.WriteActive() {
				t.Fatal("a run that was not resumed must not hold the lock")
			}
			h2.Serve(t)
			got, err := h2.Client.GetRun(context.Background(), parked.RunID)
			if err != nil || got.Status != api.StatusFailed || got.Error == nil || got.Error.Code != api.CodeHostRestarted || got.RevertAt != nil {
				t.Fatalf("run = %+v %v", got, err)
			}
			if lines := strings.Join(auditFor(t, h2, parked.RunID), ","); lines != "accepted,awaiting_confirm,failed" {
				t.Fatalf("audit = %s", lines)
			}
			// The lock is free: a write works, and Settle has nothing to settle.
			run(t, h2.Client, "test.echo", echoArgs{Name: "x"}, rid2)
			if err := h2.Server.Settle(parked.RunID, api.StatusSucceeded, nil); !errors.Is(err, server.ErrNotAwaiting) {
				t.Fatalf("Settle = %v", err)
			}
		})
	}
}

func TestAwaiting_OnlyTheFirstAwaitingRunIsResumed(t *testing.T) {
	t.Parallel()
	// Two awaiting run files can only come from a damaged state directory; the lock allows one.
	x := newAwaitFx(t)
	h := prepareAwait(t, x.cmds)
	x.srv.Store(h.Server)
	h.Serve(t)
	a := park(t, h, rid1)
	if err := h.Server.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Copy the run file under a second id.
	src, err := os.ReadFile(h.StateDir + "/runs/" + a.RunID + ".json")
	if err != nil {
		t.Fatal(err)
	}
	second := "rn_00000000000000aa"
	copyOf := strings.ReplaceAll(string(src), a.RunID, second)
	if err := os.WriteFile(h.StateDir+"/runs/"+second+".json", []byte(copyOf), 0o600); err != nil { //nolint:gosec // a path inside the test's own temp dir
		t.Fatal(err)
	}
	var calls atomic.Int64
	h2 := prepareAwait(t, x.cmds, func(o *server.Options) {
		o.StateDir, o.AuditPath, o.SocketPath = h.StateDir, h.AuditPath, h.Socket+"2"
		o.Resume = func(api.Run) bool { calls.Add(1); return true }
	})
	h2.Serve(t)
	var awaiting, failed int
	runs, _ := h2.Client.ListRuns(context.Background(), 50)
	for _, r := range runs {
		switch {
		case r.Status == api.StatusAwaitingConfirm:
			awaiting++
		case r.Status == api.StatusFailed && r.Error != nil && r.Error.Code == api.CodeHostRestarted:
			failed++
		}
	}
	if awaiting != 1 || failed != 1 || calls.Load() != 1 {
		t.Fatalf("awaiting %d failed %d Resume calls %d", awaiting, failed, calls.Load())
	}
}

func TestAwaiting_IdempotentReplayOfConfirm(t *testing.T) {
	t.Parallel()
	h, x := startAwait(t)
	parked := park(t, h, rid1)
	args := runIDArgs{RunID: parked.RunID}
	first, err := h.Client.Run(context.Background(), "test.confirm", args, rid2, "admin")
	if err != nil {
		t.Fatal(err)
	}
	finish(t, h.Client, first.RunID)
	// The same request id, the same args: the same run, no second execution, no second settle.
	again, err := h.Client.Run(context.Background(), "test.confirm", args, rid2, "admin")
	if err != nil || again.RunID != first.RunID || again.Status != api.StatusSucceeded {
		t.Fatalf("replay = %+v %v", again, err)
	}
	if x.confirms.Load() != 1 {
		t.Fatalf("confirm ran %d times", x.confirms.Load())
	}
	// Another run id under the same request id is not a replay.
	_, err = h.Client.Run(context.Background(), "test.confirm", runIDArgs{RunID: "rn_0123456789abcdef"}, rid2, "admin")
	_ = clientErr(t, err, http.StatusUnprocessableEntity, api.CodeRequestIDReuse)
	finals := 0
	for _, r := range auditFor(t, h, parked.RunID) {
		if r == "ok" {
			finals++
		}
	}
	if finals != 1 {
		t.Fatalf("final lines: %v", auditFor(t, h, parked.RunID))
	}
	// A replay that arrives while the run still waits (the first call was lost) also returns the run.
	h2, x2 := startAwait(t)
	p2 := park(t, h2, rid1)
	hold := run(t, h2.Client, "test.hold", runIDArgs{RunID: p2.RunID}, rid3)
	<-x2.holding
	r2, err := h2.Client.Run(context.Background(), "test.hold", runIDArgs{RunID: p2.RunID}, rid3, "admin")
	if err != nil || r2.RunID != hold.RunID {
		t.Fatalf("replay of an in-flight confirm = %+v %v", r2, err)
	}
	close(x2.hold)
}

func TestAwaiting_InvalidAwaitingFailsTheRunAndFreesTheLock(t *testing.T) {
	t.Parallel()
	h, _ := startAwait(t)
	for i, name := range []string{"test.park_nodeadline", "test.park_error"} {
		r := run(t, h.Client, name, nil, uuid(i+1))
		fin := finish(t, h.Client, r.RunID)
		if fin.Status != api.StatusFailed || fin.Error == nil || fin.Error.Code != api.CodeCommandFailed || fin.RevertAt != nil {
			t.Fatalf("%s: %+v", name, fin)
		}
		if h.Server.AwaitingConfirm() || h.Server.WriteActive() {
			t.Fatalf("%s left the lock held", name)
		}
	}
}

func TestAwaiting_MaxBodyIsPerCommand(t *testing.T) {
	t.Parallel()
	h, _ := startAwait(t)
	body := func(n int) string { return `{"args":{"pad":"` + strings.Repeat("a", n) + `"}}` }
	// 600 KiB: over the default of 512 KiB, under the 1 MiB of test.big.
	st, _ := post(t, h, "test.small", goodHeaders(rid1), body(600<<10))
	if st != http.StatusBadRequest {
		t.Fatalf("default limit: %d", st)
	}
	_, eb := post(t, h, "test.small", goodHeaders(rid1), body(600<<10))
	if len(eb.Error.Details) != 1 || !strings.Contains(eb.Error.Details[0].Reason, "512 KiB") {
		t.Fatalf("details = %+v", eb.Error.Details)
	}
	if st, eb = post(t, h, "test.big", goodHeaders(rid2), body(600<<10)); st != http.StatusAccepted && st != http.StatusOK {
		t.Fatalf("a 600 KiB body for test.big: %d %+v", st, eb)
	}
	if st, eb = post(t, h, "test.big", goodHeaders(rid3), body(1<<20+10)); st != http.StatusBadRequest || len(eb.Error.Details) != 1 || !strings.Contains(eb.Error.Details[0].Reason, "1024 KiB") {
		t.Fatalf("over the per-command limit: %d %+v", st, eb)
	}
	// Registry rules.
	for _, bad := range []server.Command{
		server.Define(server.Spec[padArgs]{Name: "test.huge", Write: true, Timeout: time.Second, MaxBody: 5 << 20, Run: func(context.Context, *server.RunContext, padArgs) (any, error) { return nil, nil }}),
		server.Define(server.Spec[padArgs]{Name: "test.neg", Write: true, Timeout: time.Second, MaxBody: -1, Run: func(context.Context, *server.RunContext, padArgs) (any, error) { return nil, nil }}),
		server.Define(server.Spec[runIDArgs]{Name: "test.readawait", Timeout: time.Second, WhileAwaiting: true, Run: func(context.Context, *server.RunContext, runIDArgs) (any, error) { return nil, nil }}),
	} {
		if _, err := server.NewRegistry(bad); err == nil {
			t.Errorf("NewRegistry accepted %s", bad.Name())
		}
	}
}

func TestAwaiting_NetAndContainersReadersAnswerOnlyWhenWired(t *testing.T) {
	t.Parallel()
	h := servertest.Start(t, nil)
	for _, p := range []string{"/v1/state/net", "/v1/state/containers"} {
		st, b := raw(t, h, http.MethodGet, p, goodHeaders(rid1), "")
		var eb api.ErrorBody
		_ = json.Unmarshal(b, &eb)
		if st != http.StatusNotFound || eb.Error.Code != api.CodeUnknownCommand {
			t.Errorf("%s without a reader: %d %s", p, st, b)
		}
	}
	h2 := servertest.Start(t, nil, func(o *server.Options) {
		o.Readers = server.Readers{
			Net:        func(context.Context) (any, error) { return map[string]string{"k": "net"}, nil },
			Containers: func(context.Context) (any, error) { return map[string]string{"k": "ctr"}, nil },
		}
	})
	for p, want := range map[string]string{"/v1/state/net": `"k":"net"`, "/v1/state/containers": `"k":"ctr"`} {
		if st, b := raw(t, h2, http.MethodGet, p, goodHeaders(rid1), ""); st != 200 || !strings.Contains(string(b), want) {
			t.Errorf("%s: %d %s", p, st, b)
		}
	}
	if st, _ := raw(t, h2, http.MethodPost, "/v1/state/net", goodHeaders(rid1), "{}"); st != http.StatusNotFound {
		t.Errorf("POST /v1/state/net: %d", st)
	}
}
