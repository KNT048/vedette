package sensoractive_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	sa "github.com/knt048/vedette/modules/sensor-active"
)

// hookInv wraps the fake inventory to run a hook in the middle of the service's own checks. The hook stands in
// for an inventory.settings.changed event that the bus delivers (synchronously, from the request that saved the
// settings) after the service has looked at the settings and before nmap starts.
type hookInv struct {
	*fakeInv
	onAsset     func()
	onInScope   func(ip netip.Addr)
	onProtected func()
	policy      func(id string) (sa.Decision, bool)
}

func (h *hookInv) Asset(ctx context.Context, id string) (sa.Asset, error) {
	a, err := h.fakeInv.Asset(ctx, id)
	if f := h.onAsset; f != nil {
		h.onAsset = nil
		f()
	}
	return a, err
}

func (h *hookInv) InScope(ctx context.Context, ip netip.Addr) (bool, error) {
	in, err := h.fakeInv.InScope(ctx, ip)
	if f := h.onInScope; f != nil {
		f(ip)
	}
	return in, err
}

func (h *hookInv) ProtectedIPs(ctx context.Context) ([]netip.Addr, error) {
	out, err := h.fakeInv.ProtectedIPs(ctx)
	if f := h.onProtected; f != nil {
		h.onProtected = nil
		f()
	}
	return out, err
}

func (h *hookInv) ScanPolicy(ctx context.Context, id string) (sa.Decision, error) {
	if h.policy != nil {
		if d, ok := h.policy(id); ok {
			return d, nil
		}
	}
	return h.fakeInv.ScanPolicy(ctx, id)
}

func buildWith(t *testing.T, e *env, inv sa.Inventory) *sa.Service {
	t.Helper()
	svc, err := sa.New(sa.Config{DB: e.db, Inventory: inv, Observe: e.sink, Software: e.sink, Events: e.ev, NmapPath: e.nm.path, Prober: e.prober(), Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// INV-2, PRE-3: the person turns active scanning off ("stop now") while a device scan is between its checks and
// the start of nmap. The run is registered before its checks, SettingsChanged reaches it, and nmap never starts.
func TestContract_INV2_ScanningTurnedOffDuringTheChecksSendsNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	h := &hookInv{fakeInv: e.inv}
	svc := buildWith(t, e, h)
	h.onAsset = func() {
		e.inv.set(func(s *sa.Settings) { s.Enabled = false })
		if err := svc.SettingsChanged(e.ctx()); err != nil {
			t.Error(err)
		}
	}
	err := svc.ScanDevice(e.ctx(), "a-web", "discovered")
	if calls := e.nm.calls(t); len(calls) != 0 {
		t.Fatalf("scanning was turned off and SettingsChanged delivered before nmap started, yet nmap ran: %q (ScanDevice err = %v)", calls, err)
	}
	if !errors.Is(err, sa.ErrStopped) {
		t.Fatalf("err = %v, want ErrStopped", err)
	}
	if got := e.str(`SELECT status FROM sa_job`); got != "stopped" {
		t.Fatalf("job status = %q", got)
	}
}

// INV-1: an exclusion saved after the device's address passed InScope but before nmap started. The address is
// published before it is checked, so SettingsChanged sees it, and the run re-reads the scope before nmap.
func TestContract_INV1_ExclusionSavedAfterTheScopeCheckSendsNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	h := &hookInv{fakeInv: e.inv}
	svc := buildWith(t, e, h)
	h.onInScope = func(ip netip.Addr) {
		if ip != netip.MustParseAddr("192.168.10.20") {
			return
		}
		h.onInScope = nil
		e.inv.set(func(s *sa.Settings) { s.Exclusions = []string{"192.168.10.20"} })
		if err := svc.SettingsChanged(e.ctx()); err != nil {
			t.Error(err)
		}
	}
	err := svc.ScanDevice(e.ctx(), "a-web", "discovered")
	for _, c := range e.nm.calls(t) {
		if slices.Contains(c, "192.168.10.20") {
			t.Fatalf("192.168.10.20 was excluded (and SettingsChanged delivered) before nmap started, yet it was scanned: %q (err = %v)", c, err)
		}
	}
	if !errors.Is(err, sa.ErrStopped) {
		t.Fatalf("err = %v, want ErrStopped", err)
	}
}

// INV-1 on the sweep: an exclusion saved after the batch was built and before nmap started, with or without the
// event: probe reads the settings again for every address of the batch.
func TestContract_INV1_SweepExclusionSavedBetweenCheckAndExecSendsNothing(t *testing.T) {
	t.Parallel()
	victim := netip.MustParseAddr("192.168.10.20")
	for name, deliver := range map[string]bool{"event delivered": true, "event not delivered yet": false} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, fakeOpts{})
			h := &hookInv{fakeInv: e.inv}
			svc := buildWith(t, e, h)
			h.onProtected = func() { // inside the batch's own checks
				e.inv.set(func(s *sa.Settings) { s.Exclusions = []string{victim.String()} })
				if deliver {
					if err := svc.SettingsChanged(e.ctx()); err != nil {
						t.Error(err)
					}
				}
			}
			_, err := svc.DiscoverRanges(e.ctx())
			for _, c := range e.nm.calls(t) {
				if slices.Contains(targetsOf(c), victim.String()) {
					t.Fatalf("%s was excluded before nmap started, yet it is in the sweep argv (DiscoverRanges err = %v)", victim, err)
				}
			}
			if !errors.Is(err, sa.ErrStopped) {
				t.Fatalf("err = %v, want ErrStopped", err)
			}
		})
	}
}

// INV-4 / L4: lowering the rate stops the running job (it restarts at the new rate at the next tick); raising it
// does not.
func TestContract_INV4_LoweringTheRateStopsTheRunningJob(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		rate    int
		stopped bool
	}{"lowered": {20, true}, "raised": {500, false}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, fakeOpts{slowFrom: 1})
			done := make(chan error, 1)
			go func() { _, err := e.svc.DiscoverRanges(e.ctx()); done <- err }()
			waitFor(t, "the fake nmap to start", func() bool { return len(e.nm.calls(t)) > 0 })
			e.inv.set(func(s *sa.Settings) { s.Rate = c.rate })
			if err := e.svc.SettingsChanged(e.ctx()); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if !c.stopped {
					t.Fatalf("the run ended (%v) although the rate went up", err)
				}
				if !errors.Is(err, sa.ErrStopped) {
					t.Fatalf("err = %v, want ErrStopped", err)
				}
			case <-time.After(3 * time.Second):
				if c.stopped {
					t.Fatal("the run was not stopped by the lower rate")
				}
			}
		})
	}
}
