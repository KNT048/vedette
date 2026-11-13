package honeypot_test

// S-HP-1: the state of a trap or a Trap IP is what the host did, not what the switch says; a host that keeps refusing an
// address is not asked every minute.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/honeypot"
)

// Before the first Apply a switched-on trap is "starting", not "off" and not "failed"; after it, "listening".
func TestTrapsAreStartingUntilTheHostHasAnswered(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	d := e.addTrapIP("NAS-OLD", "192.168.10.241", honeypot.NAS, honeypot.HTTP, honeypot.SMB)
	if d.State != honeypot.StateStarting {
		t.Fatalf("trap IP before Apply: %s", d.State)
	}
	if got := overviewTraps(t, e)[2]; got.State != honeypot.StateStarting {
		t.Fatalf("ssh before Apply: %s", got.State)
	}
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := overviewTraps(t, e)[2]; got.State != honeypot.StateListening {
		t.Fatalf("ssh after Apply: %s", got.State)
	}
	if got := e.trapIP(d.ID); got.State != honeypot.StateListening || got.Reason != nil {
		t.Fatalf("trap IP after Apply: %+v", got)
	}
}

// A Trap IP whose host start failed is "failed" with the host's reason, whatever its switch says; so is a Trap IP the host
// could not set up while another one listens. Switching one Trap IP off leaves the others listening (each has its own services).
func TestTrapIPStateComesFromTheHost(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	e.host.failAdd = map[netip.Addr]error{addr("192.168.10.241"): fmt.Errorf("decoy_failed: %w %w", honeypot.ErrRefused, honeypot.ErrHostFailed)}
	nas := e.addTrapIP("NAS-OLD", "192.168.10.241", honeypot.NAS, honeypot.HTTP, honeypot.SMB)
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if d := e.trapIP(nas.ID); d.State != honeypot.StateFailed || d.Reason == nil || !strings.Contains(*d.Reason, "decoy_failed") {
		t.Fatalf("%+v", d)
	}
	if got := overviewTraps(t, e)[2]; got.State != honeypot.StateListening {
		t.Fatalf("the other Trap IP goes on: %s", got.State)
	}
	// the container does not start at all
	e.host.mu.Lock()
	e.host.failAdd = nil
	e.host.failStart = errStart
	e.host.mu.Unlock()
	e.svc.Kick()
	_ = e.svc.Apply(e.ctx())
	if d := e.trapIP(nas.ID); d.State != honeypot.StateFailed || d.Reason == nil || !strings.Contains(*d.Reason, "did not start") {
		t.Fatalf("%+v", d)
	}
	// the first Trap IP off: the NAS keeps listening on its own services
	e.host.mu.Lock()
	e.host.failStart = nil
	e.host.mu.Unlock()
	if err := e.enable(e.main, false); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if d := e.trapIP(nas.ID); d.State != honeypot.StateListening || d.Reason != nil {
		t.Fatalf("%+v", d)
	}
	if d := e.trapIP(e.main); d.State != honeypot.StateOff || d.Enabled {
		t.Fatalf("%+v", d)
	}
}

// Turning the last trap off shows "stopping" until the Apply that removes the address has run.
func TestTurningOffShowsStoppingUntilTheHostConfirms(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if err := e.setServices(e.main, honeypot.SMB); err != nil {
		t.Fatal(err)
	}
	if got := overviewTraps(t, e)[2]; got.State != honeypot.StateStopping {
		t.Fatalf("ssh turned off, not applied: %s", got.State)
	}
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := overviewTraps(t, e)[2]; got.State != honeypot.StateOff {
		t.Fatalf("ssh after Apply: %s", got.State)
	}
}

// Spare IPs are "unused" only once the inventory has seen a device in the network.
func TestSpareIPsSayWhenNothingWasChecked(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r, _ := e.svc.TrapIPs(e.ctx())
	if !r.SpareChecked || len(r.SpareIPs) == 0 {
		t.Fatalf("devices are known: %+v", r)
	}
	e.inv.mu.Lock()
	e.inv.devices = []honeypot.Device{{ID: "a-box", IP: addr("192.168.10.2"), Name: "vedette-hq", IsBox: true}}
	e.inv.mu.Unlock()
	r, _ = e.svc.TrapIPs(e.ctx())
	if r.SpareChecked || len(r.SpareIPs) == 0 {
		t.Fatalf("only the box is known: %+v", r)
	}
}

// refuseCounting refuses one address and counts how often the host was asked for it.
type refuseCounting struct {
	*fakeHost
	bad netip.Addr
	n   *int
	mu  *sync.Mutex
}

func (h refuseCounting) AddDecoyIP(ctx context.Context, ip netip.Addr, spec honeypot.DecoySpec) error {
	if ip == h.bad {
		h.mu.Lock()
		*h.n++
		h.mu.Unlock()
		return fmt.Errorf("decoy_failed: %w %w", honeypot.ErrRefused, honeypot.ErrHostFailed)
	}
	return h.fakeHost.AddDecoyIP(ctx, ip, spec)
}

// An address the host keeps refusing is asked for three times, then every ten minutes, and again when the configuration changes.
func TestRefusedAddressBacksOff(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	var n int
	e.cfg.Host = refuseCounting{fakeHost: e.host, bad: addr("192.168.10.241"), n: &n, mu: &sync.Mutex{}}
	svc, err := honeypot.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	e.setup()
	nas := e.addTrapIP("NAS-OLD", "192.168.10.241", honeypot.NAS, honeypot.HTTP, honeypot.SMB)
	apply := func() {
		t.Helper()
		if err := e.svc.Apply(e.ctx()); err != nil {
			t.Fatal(err)
		}
	}
	for range 5 {
		apply()
		e.now = e.now.Add(time.Minute)
	}
	if n != 3 {
		t.Fatalf("asked %d times in 5 minutes, want 3", n)
	}
	if d := e.trapIP(nas.ID); d.State != honeypot.StateFailed || d.Reason == nil {
		t.Fatalf("a backed-off address keeps its reason: %+v", d)
	}
	e.now = e.now.Add(10 * time.Minute)
	apply()
	if n != 4 {
		t.Fatalf("asked %d times after the back-off, want 4", n)
	}
	e.addTrapIP("PRN-OLD", "192.168.10.242", honeypot.Printer, honeypot.HTTP)
	apply()
	if n != 5 {
		t.Fatalf("asked %d times after a configuration change, want 5", n)
	}
}

// linkHost is a host that knows how it holds the addresses: their MACs, links and parent card.
type linkHost struct{ *fakeHost }

func (h linkHost) DecoyLinks(context.Context) map[netip.Addr]honeypot.DecoyLink {
	return map[netip.Addr]honeypot.DecoyLink{
		addr("192.168.10.240"): {MAC: "06:b7:36:4f:54:67", Link: "vdhc0a80af0", Parent: "eno1"},
		addr("192.168.10.241"): {MAC: "f8:bc:12:4f:54:68", Link: "vdhc0a80af1", Parent: "eno1"},
	}
}

func TestDecoyMACsComeFromTheHost(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.cfg.Host = linkHost{e.host}
	svc, err := honeypot.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	e.setup()
	nas := e.addTrapIP("NAS-OLD", "192.168.10.241", honeypot.NAS, honeypot.HTTP, honeypot.SMB)
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	a, b := e.trapIP(e.main), e.trapIP(nas.ID)
	if a.MAC == nil || *a.MAC != "06:b7:36:4f:54:67" || a.MACVendor != nil || b.MAC == nil || *b.MAC != "f8:bc:12:4f:54:68" {
		t.Fatalf("%v %v %v", a.MAC, a.MACVendor, b.MAC)
	}
}

// blockStatus holds the host's Status once block is set, and says so on entered.
type blockStatus struct {
	*fakeHost
	block   *atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (h blockStatus) Status(ctx context.Context) (honeypot.HostStatus, error) {
	if h.block.Load() {
		h.entered <- struct{}{}
		select {
		case <-h.release:
		case <-ctx.Done():
		}
	}
	return h.fakeHost.Status(ctx)
}

// A module switched off and on again runs a new Run: until its first Apply has answered the traps are "starting", not the
// "failed" of the run before.
func TestSwitchingTheModuleOnShowsStarting(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(e *env) { e.host = newHost(false) })
	bh := blockStatus{fakeHost: e.host, block: &atomic.Bool{}, entered: make(chan struct{}, 1), release: make(chan struct{})}
	e.cfg.Host = bh
	svc, err := honeypot.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	e.setup()
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := overviewTraps(t, e)[2]; got.State != honeypot.StateFailed {
		t.Fatalf("before: %s", got.State)
	}
	bh.block.Store(true)
	ctx, cancel := context.WithCancel(e.ctx())
	done := make(chan error, 1)
	go func() { done <- e.svc.Run(ctx) }()
	<-bh.entered // the first Apply of the new run is waiting for the host
	if got := overviewTraps(t, e)[2]; got.State != honeypot.StateStarting {
		t.Fatalf("while the first Apply waits: %s", got.State)
	}
	close(bh.release)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// A Trap IP is switched on at the moment it is deleted: the switch-on is refused where it writes, nothing is left on (INV-6).
type clearDuringRead struct {
	*fakeInv
	done atomic.Bool
	do   func()
}

func (c *clearDuringRead) Devices(ctx context.Context) ([]honeypot.Device, error) {
	d, err := c.fakeInv.Devices(ctx)
	if c.done.CompareAndSwap(false, true) {
		c.do()
	}
	return d, err
}

func TestTrapIPCannotBeSwitchedOnAfterItWasDeleted(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	if err := e.enable(e.main, false); err != nil {
		t.Fatal(err)
	}
	hook := &clearDuringRead{fakeInv: e.inv}
	e.cfg.Inventory = hook
	svc, err := honeypot.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	hook.do = func() {
		if err := svc.DeleteTrapIP(e.ctx(), "a", e.main); err != nil {
			t.Error(err)
		}
	}
	// SetTrapIPEnabled reads the world (with the Trap IP), the Trap IP is deleted, then it writes: refused where it writes.
	if _, err := svc.SetTrapIPEnabled(e.ctx(), "a", e.main, true); apiCode(t, err) != "not_found" {
		t.Fatalf("%v", err)
	}
	if n := e.count(`SELECT count(*) FROM hp_trap_ips`); n != 0 {
		t.Fatalf("%d trap IPs left", n)
	}
}

// With the first Trap IP clashing with a device the other Trap IPs still listen (each address stands alone, D-466); a Trap
// IP just switched off is "stopping" until the Apply that removes its address.
func TestTrapIPStateWhenAnotherIsUnusableAndWhenOneGoesOff(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	nas := e.addTrapIP("NAS-OLD", "192.168.10.241", honeypot.NAS, honeypot.HTTP, honeypot.SMB)
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if err := e.enable(nas.ID, false); err != nil {
		t.Fatal(err)
	}
	if d := e.trapIP(nas.ID); d.State != honeypot.StateStopping {
		t.Fatalf("just off: %+v", d)
	}
	if err := e.enable(nas.ID, true); err != nil {
		t.Fatal(err)
	}
	e.inv.mu.Lock()
	e.inv.devices = append(e.inv.devices, dev("a-new", "192.168.10.240", "NEW-PC", "pc"))
	e.inv.mu.Unlock()
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if d := e.trapIP(e.main); d.State != honeypot.StateConflict || d.Reason == nil || !strings.Contains(*d.Reason, "device") {
		t.Fatalf("%+v", d)
	}
	if d := e.trapIP(nas.ID); d.State != honeypot.StateListening {
		t.Fatalf("%+v", d)
	}
}

// The reason on the screen is the host adapter's plain sentence, not the wrapped error text.
type plainRefusal struct{}

func (plainRefusal) Error() string      { return "the host could not do it (decoy_failed)" }
func (plainRefusal) UserReason() string { return "the host could not do it" }
func (plainRefusal) Is(t error) bool    { return t == honeypot.ErrRefused || t == honeypot.ErrHostFailed }

func TestRefusalReasonIsThePlainSentence(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	e.host.failAdd = map[netip.Addr]error{addr("192.168.10.241"): fmt.Errorf("honeypot: decoy address 192.168.10.241: %w", plainRefusal{})}
	nas := e.addTrapIP("NAS-OLD", "192.168.10.241", honeypot.NAS, honeypot.HTTP, honeypot.SMB)
	_ = e.svc.Apply(e.ctx())
	if d := e.trapIP(nas.ID); d.Reason == nil || *d.Reason != "the host could not do it" {
		t.Fatalf("%+v", d)
	}
}

// An inventory event only hints at an Apply: during an Apply that keeps failing it must not turn "failed" into "starting".
func TestInventoryEventsDoNotMakeAFailingTrapStarting(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	e.host.failStart = errStart
	_ = e.svc.Apply(e.ctx())
	bus := &fakeBus{}
	e.svc.Subscribe(bus)
	for _, h := range bus.fns {
		if err := h(e.ctx(), events.Event{Name: "inventory.asset.updated"}); err != nil {
			t.Fatal(err)
		}
	}
	if got := overviewTraps(t, e)[2]; got.State != honeypot.StateFailed {
		t.Fatalf("after an inventory event: %s", got.State)
	}
}

// After the module was switched off, a switch-on shows "starting" until the first Apply answers, never the "module is off" failure.
func TestTrapsAreStartingAfterTheModuleWasOff(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Disable(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := overviewTraps(t, e)[2]; got.State != honeypot.StateStarting {
		t.Fatalf("after Disable: %s", got.State)
	}
}

// "listening" needs the host to hold the address (#475): a Trap IP the host holds listens even when the host refused or
// could not set up another one (the container runs for it), and a Trap IP whose outcome is unknown is "failed" with a plain
// reason, not "listening" because the container runs for the other one.
func TestListeningNeedsTheHostToHoldTheAddress(t *testing.T) {
	t.Parallel()
	sec, extra := addr("192.168.10.240"), addr("192.168.10.241")
	for name, refusal := range map[string]error{
		"refused as an address": fmt.Errorf("ip_in_use: %w", honeypot.ErrRefused),
		"host failure":          fmt.Errorf("decoy_failed: %w %w", honeypot.ErrRefused, honeypot.ErrHostFailed),
	} {
		e := newEnv(t)
		e.setup()
		e.host.failAdd = map[netip.Addr]error{sec: refusal}
		nas := e.addTrapIP("NAS-OLD", extra.String(), honeypot.NAS, honeypot.HTTP, honeypot.SMB)
		_ = e.svc.Apply(e.ctx())
		if !e.host.isRunning() {
			t.Fatalf("%s: the container does not run for the other Trap IP", name)
		}
		if d := e.trapIP(nas.ID); d.State != honeypot.StateListening || d.Reason != nil {
			t.Fatalf("%s: the Trap IP the host holds: %+v", name, d)
		}
		o, err := e.svc.Overview(e.ctx())
		if err != nil {
			t.Fatal(err)
		}
		main := e.trapIP(e.main)
		if got := o.Traps[2]; got.State == honeypot.StateListening || main.State == honeypot.StateListening || main.Reason == nil ||
			!strings.Contains(*main.Reason, strings.SplitN(refusal.Error(), ":", 2)[0]) {
			t.Fatalf("%s: a trap on a refused Trap IP: %s, %+v", name, got.State, main)
		}

		// The next Applies: no answer for the first Trap IP (twice: once on the record it is still not confirmed); the
		// other one the host took before stays up.
		e.host.mu.Lock()
		e.host.failAdd = map[netip.Addr]error{sec: errors.New("the host is busy")}
		e.host.mu.Unlock()
		for i := range 2 {
			_ = e.svc.Apply(e.ctx())
			o, err := e.svc.Overview(e.ctx())
			if err != nil {
				t.Fatal(err)
			}
			main := e.trapIP(e.main)
			if got := o.Traps[2]; got.State != honeypot.StateFailed || main.Reason == nil || !strings.Contains(*main.Reason, "not confirmed") {
				t.Fatalf("%s, unknown outcome %d: %s, %+v", name, i+1, got.State, main)
			}
			if d := e.trapIP(nas.ID); d.State != honeypot.StateListening {
				t.Fatalf("%s, unknown outcome %d: the other Trap IP: %+v", name, i+1, d)
			}
		}
	}
}

// After a restart of core nothing is confirmed until the host answers: the "applied" record is not the host's word.
func TestListeningAfterARestartWaitsForTheHost(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	again, err := honeypot.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.host.mu.Lock()
	e.host.failAdd = map[netip.Addr]error{addr("192.168.10.240"): errors.New("the host is busy")}
	e.host.mu.Unlock()
	_ = again.Apply(e.ctx())
	r, err := again.TrapIPs(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if d := r.Items[0]; d.State != honeypot.StateFailed || d.Reason == nil || !strings.Contains(*d.Reason, "not confirmed") || overviewTrapsOf(t, e, again)[2].State != honeypot.StateFailed {
		t.Fatalf("after a restart, no answer: %+v", d)
	}
	e.host.mu.Lock()
	e.host.failAdd = nil
	e.host.mu.Unlock()
	_ = again.Apply(e.ctx())
	if got := overviewTrapsOf(t, e, again)[2]; got.State != honeypot.StateListening {
		t.Fatalf("after the host answered: %s", got.State)
	}
}

func overviewTrapsOf(t *testing.T, e *env, svc *honeypot.Service) []honeypot.Trap {
	t.Helper()
	o, err := svc.Overview(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	return o.Traps
}
