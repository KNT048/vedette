package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

// The 660 s bound of RevertAt is elapsed + (RevertAt - now), the elapsed time measured on the
// monotonic clock from the start of the run (review of slice 3-4, H-1 (a)): the time a command
// spends before it parks counts, and a step of the wall clock during the run does not.
func TestAwaiting_TheBoundCountsTheTimeTheRunAlreadyTook(t *testing.T) {
	t.Parallel()
	slow := func(name string, window time.Duration) server.Command {
		return server.Define(server.Spec[struct{}]{
			Name: name, Write: true, Awaits: true, Timeout: 5 * time.Second,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
				<-time.After(150 * time.Millisecond)
				return server.Awaiting{RevertAt: time.Now().Add(window)}, nil
			},
		})
	}
	// edge_ok fits as long as the run took less than 30 s (hangBound); edge_over is over only because the 150 ms the
	// command spent count. Neither depends on the speed of the machine (D-373).
	h := prepareAwait(t, []server.Command{slow("test.edge_ok", 660*time.Second-hangBound), slow("test.edge_over", 660*time.Second-100*time.Millisecond)})
	h.Serve(t)
	ok := run(t, h.Client, "test.edge_ok", nil, rid1)
	waitStatus(t, h.Client, ok.RunID, api.StatusAwaitingConfirm)
	if err := h.Server.Settle(ok.RunID, api.StatusSucceeded, nil); err != nil {
		t.Fatal(err)
	}
	// 659.9 s from "now" is more than 660 s from the start: the park is refused and the run fails.
	over := run(t, h.Client, "test.edge_over", nil, rid2)
	r := waitStatus(t, h.Client, over.RunID, api.StatusFailed)
	if r.Error == nil || r.Error.Code != api.CodeCommandFailed {
		t.Fatalf("run %+v", r)
	}
	if h.Server.AwaitingConfirm() || h.Server.WriteActive() {
		t.Fatal("a refused park left the lock held")
	}
}

// With a clock that has no monotonic reading (the tests' fake) the elapsed time is the wall time.
func TestAwaiting_AWallClockStepDuringTheRunRefusesAWindowThatNoLongerFits(t *testing.T) {
	t.Parallel()
	clock := servertest.NewClock(time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC))
	cmd := server.Define(server.Spec[struct{}]{
		Name: "test.stepped", Write: true, Awaits: true, Timeout: 5 * time.Second,
		Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
			clock.Advance(15 * time.Minute)
			return server.Awaiting{RevertAt: clock.Now().Add(time.Minute)}, nil
		},
	})
	h := servertest.Start(t, []server.Command{cmd}, func(o *server.Options) { o.Now = clock.Now })
	r := run(t, h.Client, "test.stepped", nil, rid1)
	if f := waitStatus(t, h.Client, r.RunID, api.StatusFailed); f.Error == nil || f.Error.Code != api.CodeCommandFailed {
		t.Fatalf("run %+v", f)
	}
}
