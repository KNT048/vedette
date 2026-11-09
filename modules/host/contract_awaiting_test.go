package host_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

// INV-16 (framework half, slice 3-1): a run awaiting confirmation holds the write lock of the real
// system commands too. The parking command exists only in this test; production registers none.
func TestContract_INV16_AwaitingRunBlocksSystemWrites(t *testing.T) {
	t.Parallel()
	m := opstest.NewMachine(t)
	clock := servertest.NewClock(time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC))
	timers := &fakeTimers{}
	o := m.Ops(clock.Now, func(_ *ops.Config, d *ops.Deps) {
		d.AfterFunc = timers.after
		d.FreeBytes = func(string) (uint64, error) { return 100 << 30, nil }
	})
	parkCmd := server.Define(server.Spec[struct{}]{
		Name: "test.park", Write: true, Awaits: true, Timeout: 5 * time.Second,
		Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
			return server.Awaiting{RevertAt: clock.Now().Add(2 * time.Minute)}, nil
		},
	})
	h := servertest.Start(t, append(o.Commands(), parkCmd), func(so *server.Options) {
		so.StateDir, so.Readers, so.Now, so.WriteGate = m.State, o.Readers(), clock.Now, o.WriteGate
	})
	o.Start(context.Background(), h.Server) // the server is the Notifier: NetPending now asks it
	t.Cleanup(o.Close)

	parked, err := h.Client.Run(context.Background(), "test.park", nil, "11111111-1111-4111-8111-111111111111", "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		got, _ := h.Client.GetRun(context.Background(), parked.RunID)
		if got.Status == api.StatusAwaitingConfirm {
			break
		}
		if i > 1000 {
			t.Fatalf("never awaiting: %+v", got)
		}
		<-time.After(5 * time.Millisecond)
	}
	at := clock.Now().Add(time.Hour).Format(time.RFC3339)
	for i, args := range []api.OSRebootArgs{{When: "now"}, {When: "at", At: at}} {
		_, err := h.Client.OSReboot(context.Background(), args, fmt.Sprintf("22222222-2222-4222-8222-%012d", i), "admin@example.com")
		var ce *client.Error
		if !errors.As(err, &ce) || ce.Status != http.StatusConflict || ce.Code != api.CodePendingConfirm || ce.RunID != parked.RunID {
			t.Fatalf("os.reboot while awaiting: %v", err)
		}
	}
	if _, err := h.Client.OSCheck(context.Background(), "33333333-3333-4333-8333-333333333333", "admin@example.com"); !client.IsCode(err, api.CodePendingConfirm) {
		t.Errorf("os.check while awaiting: %v", err)
	}
	if _, err := h.Client.OSAutoSecuritySet(context.Background(), true, "33333333-3333-4333-8333-333333333334", "admin@example.com"); !client.IsCode(err, api.CodePendingConfirm) {
		t.Errorf("os.auto_security.set while awaiting: %v", err)
	}
	// Reads of the system state stay open.
	if _, err := h.Client.StateBackups(context.Background()); err != nil {
		t.Fatalf("a read while awaiting: %v", err)
	}
	if err := h.Server.Settle(parked.RunID, api.StatusSucceeded, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Client.OSReboot(context.Background(), api.OSRebootArgs{When: "at", At: at}, "44444444-4444-4444-8444-444444444444", "admin@example.com"); err != nil {
		t.Fatalf("os.reboot after the run settled: %v", err)
	}
}
