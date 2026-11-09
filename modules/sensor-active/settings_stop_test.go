package sensoractive_test

import (
	"context"
	"net/netip"
	"testing"

	sa "github.com/knt048/vedette/modules/sensor-active"
)

// ctxInv answers InScope like the real inventory does: a read under a cancelled context fails with ctx.Err().
type ctxInv struct{ *hookInv }

func (c ctxInv) InScope(ctx context.Context, ip netip.Addr) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return c.hookInv.InScope(ctx, ip)
}

// SettingsChanged cancels a device run that is still in its pre-checks (nothing is sent).
// The next storage read of ScanDevice then fails with context.Canceled; that must come back as ErrStopped, not as
// a failure, or drain would count an attempt (to the back; dropped at 3). The rule: a stop for a settings change
// is not an attempt.
func TestSettingsStopDuringPreChecksIsNotAnAttempt(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	h := &hookInv{fakeInv: e.inv}
	svc := buildWith(t, e, ctxInv{h})
	h.onAsset = func() {
		e.inv.set(func(s *sa.Settings) { s.Enabled = false })
		if err := svc.SettingsChanged(e.ctx()); err != nil {
			t.Error(err)
		}
	}
	if err := svc.Enqueue(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	markSweepDone(t, e, "saj-sweep-review2")
	if err := svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if calls := e.nm.calls(t); len(calls) != 0 {
		t.Fatalf("nmap ran: %q", calls)
	}
	if got := e.count(`SELECT attempts FROM sa_queue WHERE asset_id = 'a-web'`); got != 0 {
		t.Errorf("a run stopped by a settings change before nmap started counted as an attempt: attempts = %d", got)
	}
}
