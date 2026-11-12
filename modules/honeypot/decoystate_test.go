package honeypot_test

// S-HP-1: the state of a trap or a decoy is what the host did, not what the switch says; the decoy IP can be removed; a
// host that keeps refusing an address is not asked every minute.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/honeypot"
)

// Before the first Apply a switched-on trap is "starting", not "off" and not "failed"; after it, "listening".
func TestTrapsAreStartingUntilTheHostHasAnswered(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	d, err := e.svc.AddDecoy(e.ctx(), "a", honeypot.DecoyInput{Personality: honeypot.NAS, Name: "NAS-OLD", IP: "192.168.10.241"})
	if err != nil {
		t.Fatal(err)
	}
	if d.State != honeypot.StateStarting {
		t.Fatalf("decoy before Apply: %s", d.State)
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
	r, _ := e.svc.Decoys(e.ctx())
	if r.Items[0].State != honeypot.StateListening || r.Items[0].Reason != nil {
		t.Fatalf("decoy after Apply: %+v", r.Items[0])
	}
}

// A decoy whose host start failed is "failed" with the host's reason, whatever its switch says; so is a decoy the host
// could not set up while the main decoy listens. A decoy is not listening while no trap is on.
func TestDecoyStateComesFromTheHost(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	e.host.failAdd = map[netip.Addr]error{addr("192.168.10.241"): fmt.Errorf("decoy_failed: %w %w", honeypot.ErrRefused, honeypot.ErrHostFailed)}
	if _, err := e.svc.AddDecoy(e.ctx(), "a", honeypot.DecoyInput{Personality: honeypot.NAS, Name: "NAS-OLD", IP: "192.168.10.241"}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	r, _ := e.svc.Decoys(e.ctx())
	if d := r.Items[0]; d.State != honeypot.StateFailed || d.Reason == nil || !strings.Contains(*d.Reason, "decoy_failed") {
		t.Fatalf("%+v", d)
	}
	if got := overviewTraps(t, e)[2]; got.State != honeypot.StateListening {
		t.Fatalf("the main decoy goes on: %s", got.State)
	}
	// the container does not start at all
	e.host.mu.Lock()
	e.host.failAdd = nil
	e.host.failStart = errStart
	e.host.mu.Unlock()
	e.svc.Kick()
	_ = e.svc.Apply(e.ctx())
	r, _ = e.svc.Decoys(e.ctx())
	if d := r.Items[0]; d.State != honeypot.StateFailed || d.Reason == nil || !strings.Contains(*d.Reason, "did not start") {
		t.Fatalf("%+v", d)
	}
	// all traps off: an enabled decoy listens nowhere, and says why
	e.host.mu.Lock()
	e.host.failStart = nil
	e.host.mu.Unlock()
	for _, s := range []honeypot.ServiceName{honeypot.SSH, honeypot.SMB} {
		if _, err := e.svc.SetTrap(e.ctx(), "a", s, false); err != nil {
			t.Fatal(err)
		}
	}
	_ = e.svc.Apply(e.ctx())
	r, _ = e.svc.Decoys(e.ctx())
	if d := r.Items[0]; d.State != honeypot.StateOff || d.Reason == nil || !d.Enabled {
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
	if _, err := e.svc.SetTrap(e.ctx(), "a", honeypot.SSH, false); err != nil {
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

// The decoy IP can be removed, only while every trap is off; the host then loses the address.
func TestClearingTheSecondaryIP(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if _, err := e.svc.SetConfig(e.ctx(), "a", "", "FILESRV-OLD"); apiCode(t, err) != "bad_ip" {
		t.Fatalf("nothing to clear: %v", err)
	}
	e.setup()
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetConfig(e.ctx(), "a", " ", "FILESRV-OLD"); apiCode(t, err) != "traps_on" {
		t.Fatalf("traps on: %v", err)
	}
	for _, s := range []honeypot.ServiceName{honeypot.SSH, honeypot.SMB} {
		if _, err := e.svc.SetTrap(e.ctx(), "a", s, false); err != nil {
			t.Fatal(err)
		}
	}
	o, err := e.svc.SetConfig(e.ctx(), "a", "", "FILESRV-OLD")
	if err != nil || o.SecondaryIP != nil || o.Hostname != "FILESRV-OLD" {
		t.Fatalf("%+v %v", o, err)
	}
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if len(e.host.ips) != 0 || e.host.isRunning() {
		t.Fatalf("host ips %v running %v", e.host.ips, e.host.isRunning())
	}
	if _, err := e.svc.SetTrap(e.ctx(), "a", honeypot.SSH, true); apiCode(t, err) != "no_secondary_ip" {
		t.Fatalf("a trap needs an IP again: %v", err)
	}
	if e.count(`SELECT count(*) FROM core_audit WHERE action = 'honeypot.config' AND detail LIKE 'decoy IP removed%'`) != 1 {
		t.Fatal("the removal is not in the audit log")
	}
}

// Spare IPs are "unused" only once the inventory has seen a device in the network.
func TestSpareIPsSayWhenNothingWasChecked(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r, _ := e.svc.Decoys(e.ctx())
	if !r.SpareChecked || len(r.SpareIPs) == 0 {
		t.Fatalf("devices are known: %+v", r)
	}
	e.inv.mu.Lock()
	e.inv.devices = []honeypot.Device{{ID: "a-box", IP: addr("192.168.10.2"), Name: "vedette-hq", IsBox: true}}
	e.inv.mu.Unlock()
	r, _ = e.svc.Decoys(e.ctx())
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

func (h refuseCounting) AddDecoyIP(ctx context.Context, ip netip.Addr) error {
	if ip == h.bad {
		h.mu.Lock()
		*h.n++
		h.mu.Unlock()
		return fmt.Errorf("decoy_failed: %w %w", honeypot.ErrRefused, honeypot.ErrHostFailed)
	}
	return h.fakeHost.AddDecoyIP(ctx, ip)
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
	if _, err := e.svc.AddDecoy(e.ctx(), "a", honeypot.DecoyInput{Personality: honeypot.NAS, Name: "NAS-OLD", IP: "192.168.10.241"}); err != nil {
		t.Fatal(err)
	}
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
	r, _ := e.svc.Decoys(e.ctx())
	if d := r.Items[0]; d.State != honeypot.StateFailed || d.Reason == nil {
		t.Fatalf("a backed-off address keeps its reason: %+v", d)
	}
	e.now = e.now.Add(10 * time.Minute)
	apply()
	if n != 4 {
		t.Fatalf("asked %d times after the back-off, want 4", n)
	}
	if _, err := e.svc.AddDecoy(e.ctx(), "a", honeypot.DecoyInput{Personality: honeypot.Printer, Name: "PRN-OLD", IP: "192.168.10.242"}); err != nil {
		t.Fatal(err)
	}
	apply()
	if n != 5 {
		t.Fatalf("asked %d times after a configuration change, want 5", n)
	}
}

// macHost is a host that knows the MAC of the addresses it holds.
type macHost struct{ *fakeHost }

func (h macHost) DecoyMACs(context.Context) map[netip.Addr]string {
	return map[netip.Addr]string{addr("192.168.10.240"): "06:b7:36:4f:54:67", addr("192.168.10.241"): "06:b7:36:4f:54:68"}
}

func TestDecoyMACsComeFromTheHost(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.cfg.Host = macHost{e.host}
	svc, err := honeypot.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	e.setup()
	if _, err := e.svc.AddDecoy(e.ctx(), "a", honeypot.DecoyInput{Personality: honeypot.NAS, Name: "NAS-OLD", IP: "192.168.10.241"}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	o, _ := e.svc.Overview(e.ctx())
	r, _ := e.svc.Decoys(e.ctx())
	if o.SecondaryMAC == nil || *o.SecondaryMAC != "06:b7:36:4f:54:67" || r.Items[0].MAC == nil || *r.Items[0].MAC != "06:b7:36:4f:54:68" {
		t.Fatalf("%v %+v", o.SecondaryMAC, r.Items[0].MAC)
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
	<-done
}

// A trap is switched on at the moment the decoy IP is removed: the trap must not end up on with no IP (INV-6).
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

func TestTrapCannotBeSwitchedOnAfterTheIPWasRemoved(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if _, err := e.svc.SetConfig(e.ctx(), "a", "192.168.10.240", "FILESRV-OLD"); err != nil {
		t.Fatal(err)
	}
	hook := &clearDuringRead{fakeInv: e.inv}
	e.cfg.Inventory = hook
	svc, err := honeypot.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	hook.do = func() {
		if _, err := svc.SetConfig(e.ctx(), "a", "", "FILESRV-OLD"); err != nil {
			t.Error(err)
		}
	}
	// SetTrap reads the world (with the IP), the IP is removed, then SetTrap writes: refused where it writes.
	if _, err := svc.SetTrap(e.ctx(), "a", honeypot.SSH, true); apiCode(t, err) != "no_secondary_ip" {
		t.Fatalf("%v", err)
	}
	if n := e.count(`SELECT count(*) FROM hp_trap WHERE enabled = 1`); n != 0 {
		t.Fatalf("%d traps on with no IP", n)
	}
}

// With the decoy IP clashing, extra decoys say so instead of "no trap is on"; with the last trap just turned off they
// are "stopping" as the trap rows are.
func TestDecoyStateWhenTheMainIPIsUnusableAndWhenTheLastTrapGoesOff(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	if _, err := e.svc.AddDecoy(e.ctx(), "a", honeypot.DecoyInput{Personality: honeypot.NAS, Name: "NAS-OLD", IP: "192.168.10.241"}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	for _, s := range []honeypot.ServiceName{honeypot.SSH, honeypot.SMB} {
		if _, err := e.svc.SetTrap(e.ctx(), "a", s, false); err != nil {
			t.Fatal(err)
		}
	}
	r, _ := e.svc.Decoys(e.ctx())
	if r.Items[0].State != honeypot.StateStopping {
		t.Fatalf("last trap just off: %+v", r.Items[0])
	}
	for _, s := range []honeypot.ServiceName{honeypot.SSH} {
		if _, err := e.svc.SetTrap(e.ctx(), "a", s, true); err != nil {
			t.Fatal(err)
		}
	}
	e.inv.mu.Lock()
	e.inv.devices = append(e.inv.devices, dev("a-new", "192.168.10.240", "NEW-PC", "pc"))
	e.inv.mu.Unlock()
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	r, _ = e.svc.Decoys(e.ctx())
	if d := r.Items[0]; d.State != honeypot.StateConflict || d.Reason == nil || !strings.Contains(*d.Reason, "no trap listens") {
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
	if _, err := e.svc.AddDecoy(e.ctx(), "a", honeypot.DecoyInput{Personality: honeypot.NAS, Name: "NAS-OLD", IP: "192.168.10.241"}); err != nil {
		t.Fatal(err)
	}
	_ = e.svc.Apply(e.ctx())
	r, _ := e.svc.Decoys(e.ctx())
	if d := r.Items[0]; d.Reason == nil || *d.Reason != "the host could not do it" {
		t.Fatalf("%+v", d)
	}
}
