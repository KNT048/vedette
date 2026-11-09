package ops_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
	"github.com/knt048/vedette/host/server"
)

// awaitNotifier is the server as Ops sees it, with the awaiting flag under the test's control.
type awaitNotifier struct{ awaiting atomic.Bool }

func (*awaitNotifier) Note(string, string, map[string]any) error { return nil }
func (*awaitNotifier) WriteActive() bool                         { return false }
func (n *awaitNotifier) AwaitingConfirm() bool                   { return n.awaiting.Load() }
func (*awaitNotifier) Claim(string) (*server.Claimed, error)     { return nil, server.ErrNotAwaiting }

// Deps.NetPending defaults to the server's answer: os.reboot refuses with net_pending_confirm
// while a run awaits confirmation (spec 16, D-100).
func TestNetPendingFollowsTheServersAwaitingRun(t *testing.T) {
	t.Parallel()
	clock := func() time.Time { return time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC) }
	m := opstest.NewMachine(t)
	o := m.Ops(clock)
	if o.NetPending() {
		t.Fatal("pending before Start: there is no server to ask")
	}
	n := &awaitNotifier{}
	o.Start(context.Background(), n)
	t.Cleanup(o.Close)
	if o.NetPending() {
		t.Fatal("pending with no awaiting run")
	}
	n.awaiting.Store(true)
	if !o.NetPending() {
		t.Fatal("not pending while a run awaits")
	}
	n.awaiting.Store(false)
	if o.NetPending() {
		t.Fatal("still pending after the run settled")
	}
	// A test seam replaces the answer.
	forced := m.Ops(clock, func(_ *ops.Config, d *ops.Deps) { d.NetPending = func() bool { return true } })
	forced.Start(context.Background(), n)
	t.Cleanup(forced.Close)
	if !forced.NetPending() {
		t.Fatal("Deps.NetPending was ignored")
	}
}
