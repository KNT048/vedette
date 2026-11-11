package server_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

func TestBusyWhileAWriteRuns(t *testing.T) {
	t.Parallel()
	h, f := start(t)
	first := run(t, h.Client, "test.slow", nil, rid1)
	<-f.started
	_, err := h.Client.Run(context.Background(), "test.echo", echoArgs{Name: "x"}, rid2, "admin")
	var e *client.Error
	if !errors.As(err, &e) || e.Status != http.StatusConflict || e.Code != api.CodeBusy || e.RunID != first.RunID {
		t.Fatalf("err = %v (%+v)", err, e)
	}
	if f.ran.Load() != 1 {
		t.Fatalf("the busy request ran: %d", f.ran.Load())
	}
	// The refusal is itself a run and an audit line; the first run is untouched.
	list, _ := h.Client.ListRuns(context.Background(), 10)
	var refused int
	for _, r := range list {
		if r.Status == api.StatusRefused && r.Error.Code == api.CodeBusy {
			refused++
		}
	}
	if refused != 1 || len(list) != 2 {
		t.Fatalf("list = %+v", list)
	}
	close(f.release)
	done := finish(t, h.Client, first.RunID)
	if done.Status != api.StatusSucceeded {
		t.Fatalf("first = %+v", done)
	}
	// Lock free: the same request id that was refused can run now (a refusal is not remembered).
	r := run(t, h.Client, "test.echo", echoArgs{Name: "x"}, rid2)
	finish(t, h.Client, r.RunID)
}

func TestIdempotentReplay(t *testing.T) {
	t.Parallel()
	h, f := start(t)
	args := echoArgs{Name: "same", Count: 1}
	first := run(t, h.Client, "test.echo", args, rid1)
	finish(t, h.Client, first.RunID)

	again, err := h.Client.Run(context.Background(), "test.echo", args, rid1, "someone-else")
	if err != nil {
		t.Fatal(err)
	}
	if again.RunID != first.RunID || again.Status != api.StatusSucceeded {
		t.Fatalf("replay = %+v, first = %+v", again, first)
	}
	if f.ran.Load() != 1 {
		t.Fatalf("ran %d times", f.ran.Load())
	}
	// Raw: a replay answers 200, a new run 202.
	st, _ := post(t, h, "test.echo", goodHeaders(rid1), jsonOf(map[string]any{"args": args}))
	if st != http.StatusOK {
		t.Fatalf("replay status %d", st)
	}

	// Same id, different args or different command: 422 request_id_reuse.
	for name, c := range map[string]struct {
		command string
		args    any
	}{
		"other args":    {"test.echo", echoArgs{Name: "different"}},
		"other command": {"test.read", nil},
		"extra field":   {"test.echo", echoArgs{Name: "same", Count: 2}},
	} {
		_, err := h.Client.Run(context.Background(), c.command, c.args, rid1, "admin")
		var e *client.Error
		if !errors.As(err, &e) || e.Status != http.StatusUnprocessableEntity || e.Code != api.CodeRequestIDReuse {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if f.ran.Load() != 1 {
		t.Fatalf("ran %d times", f.ran.Load())
	}
}

func TestIdempotencySurvivesRestart(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h := servertest.Start(t, f.cmds)
	args := echoArgs{Name: "durable"}
	first := run(t, h.Client, "test.echo", args, rid1)
	finish(t, h.Client, first.RunID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	// A second server over the same state and audit files.
	h2 := servertest.Prepare(t, f.cmds, func(o *server.Options) {
		o.StateDir, o.AuditPath = h.StateDir, h.AuditPath
		o.SocketPath = h.Socket + "2"
	})
	h2.Serve(t)
	again, err := h2.Client.Run(context.Background(), "test.echo", args, rid1, "admin")
	if err != nil || again.RunID != first.RunID {
		t.Fatalf("replay after restart = %+v, %v", again, err)
	}
	if f.ran.Load() != 1 {
		t.Fatalf("ran %d times", f.ran.Load())
	}
	if _, err := h2.Client.Run(context.Background(), "test.echo", echoArgs{Name: "other"}, rid1, "admin"); !client.IsCode(err, api.CodeRequestIDReuse) {
		t.Fatalf("reuse after restart: %v", err)
	}
	got, err := h2.Client.GetRun(context.Background(), first.RunID)
	if err != nil || got.Status != api.StatusSucceeded || string(got.Result) != `{"name":"durable"}` {
		t.Fatalf("run after restart = %+v, %v", got, err)
	}
	// Events of a finished run are served from disk after the restart.
	s := h2.Client.Events(context.Background(), first.RunID, 0)
	defer s.Close()
	var last api.Event
	for {
		ev, err := s.Next()
		if err != nil {
			break
		}
		last = ev
	}
	if last.Status != api.StatusSucceeded {
		t.Fatalf("last event = %+v", last)
	}
}

func TestTimeoutFailsRunAndReleasesLock(t *testing.T) {
	t.Parallel()
	h, f := start(t)
	r := run(t, h.Client, "test.timeout", nil, rid1)
	done := finish(t, h.Client, r.RunID)
	if done.Status != api.StatusFailed || done.Error.Code != api.CodeTimeout {
		t.Fatalf("done = %+v", done)
	}
	a := lastAudit(t, h)
	if a.Result != "failed" || *a.Code != api.CodeTimeout {
		t.Fatalf("audit = %+v", a)
	}
	next := run(t, h.Client, "test.echo", echoArgs{Name: "after"}, rid2)
	finish(t, h.Client, next.RunID)
	_ = f
}

func TestRateLimits(t *testing.T) {
	t.Parallel()
	zero := func(o *server.Options) { o.RequestsPerMinute, o.WritesPerMinute = 0, 0 }
	t.Run("requests per minute", func(t *testing.T) {
		t.Parallel()
		h, _ := start(t, zero)
		for i := range 60 {
			if _, err := h.Client.Info(context.Background()); err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
		}
		_, err := h.Client.Info(context.Background())
		var e *client.Error
		if !errors.As(err, &e) || e.Status != http.StatusTooManyRequests || e.Code != api.CodeRateLimited || e.RetryAfterS < 1 || e.RetryAfterS > 60 {
			t.Fatalf("err = %v (%+v)", err, e)
		}
		h.Clock.Advance(61 * time.Second)
		if _, err := h.Client.Info(context.Background()); err != nil {
			t.Fatalf("after a minute: %v", err)
		}
		// The 429 was audited (throttled to one line).
		var seen bool
		for _, a := range auditLines(t, h) {
			seen = seen || (a.Code != nil && *a.Code == api.CodeRateLimited && a.Result == "refused")
		}
		if !seen {
			t.Fatal("rate limit not audited")
		}
	})
	t.Run("writes per minute", func(t *testing.T) {
		t.Parallel()
		h, _ := start(t, zero)
		for i := range 10 {
			r := run(t, h.Client, "test.echo", echoArgs{Name: "x"}, uuid(i))
			finish(t, h.Client, r.RunID)
		}
		_, err := h.Client.Run(context.Background(), "test.echo", echoArgs{Name: "x"}, uuid(99), "admin")
		var e *client.Error
		if !errors.As(err, &e) || e.Code != api.CodeRateLimited || e.RetryAfterS < 1 {
			t.Fatalf("err = %v", err)
		}
		// Reads are not write-limited.
		if _, err := h.Client.Run(context.Background(), "test.read", nil, uuid(98), "admin"); err != nil {
			t.Fatalf("read command: %v", err)
		}
		h.Clock.Advance(61 * time.Second)
		r := run(t, h.Client, "test.echo", echoArgs{Name: "x"}, uuid(97))
		finish(t, h.Client, r.RunID)
	})
}

func TestRateLimitAuditIsThrottled(t *testing.T) {
	t.Parallel()
	h, _ := start(t, func(o *server.Options) { o.RequestsPerMinute = 1 })
	if _, err := h.Client.Info(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 50 {
		_, _ = h.Client.Info(context.Background())
	}
	var n int
	h.Clock.Advance(2 * time.Minute)
	for _, a := range auditLines(t, h) {
		if a.Code != nil && *a.Code == api.CodeRateLimited {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d rate_limited audit lines for a burst of 50, want 1", n)
	}
}

func TestShutdownRefusesNewAndCancelsRunning(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h := servertest.Start(t, f.cmds)
	r := run(t, h.Client, "test.slow", nil, rid1)
	<-f.started
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { done <- h.Server.Shutdown(ctx) }()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// The run ended failed host_shutting_down and is on disk with its audit line.
	h2 := servertest.Prepare(t, f.cmds, func(o *server.Options) {
		o.StateDir, o.AuditPath, o.SocketPath = h.StateDir, h.AuditPath, h.Socket+"2"
	})
	h2.Serve(t)
	got, err := h2.Client.GetRun(context.Background(), r.RunID)
	if err != nil || got.Status != api.StatusFailed || got.Error.Code != api.CodeShuttingDown {
		t.Fatalf("run = %+v, %v", got, err)
	}
	var found bool
	for _, a := range auditLines(t, h2) {
		found = found || (a.RunID != nil && *a.RunID == r.RunID && a.Code != nil && *a.Code == api.CodeShuttingDown)
	}
	if !found {
		t.Fatal("no audit line for the cancelled run")
	}
}

func TestShuttingDownAnswers503(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h := servertest.Start(t, f.cmds)
	r := run(t, h.Client, "test.hang", nil, rid1) // holds Shutdown for its kill grace
	_ = r
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.Server.Shutdown(ctx)
	}()
	deadline := time.After(5 * time.Second)
	for {
		st, b := raw(t, h, http.MethodGet, "/v1/info", goodHeaders(rid1), "")
		if st == http.StatusServiceUnavailable && strings.Contains(string(b), api.CodeShuttingDown) {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("never saw 503 (last %d %s)", st, b)
		case <-time.After(5 * time.Millisecond):
		}
	}
	close(f.release)
}

// A client that reads a terminal status and at once sends the next write must not get 409 busy
// for the run it just saw end: the run becomes readable and the lock free as one step.
func TestATerminalRunReadMeansTheWriteLockIsFree(t *testing.T) {
	t.Parallel()
	cmd := server.Define(server.Spec[struct{}]{
		Name: "test.fails_fast", Write: true, Timeout: 5 * time.Second,
		Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
			return nil, errors.New("no")
		},
	})
	h := servertest.Start(t, []server.Command{cmd})
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012x", i+1)
		r := run(t, h.Client, "test.fails_fast", nil, id)
		for {
			got, err := h.Client.GetRun(context.Background(), r.RunID)
			if err == nil && got.Status == api.StatusFailed {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if h.Server.WriteActive() {
			t.Fatalf("round %d: the run reads failed but the write lock is still held", i)
		}
	}
}
