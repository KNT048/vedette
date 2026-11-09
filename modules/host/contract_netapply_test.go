package host_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

// net.apply, net.confirm, net.revert and the NTP sources (WP-07b part 3, slice 3-4; spec 6.5, D-100,
// D-101, D-106; host CONTRACT INV-16, INV-18, NET-1..NET-5). The machine is the fake of opstest: a
// temp root, fake netplan and chronyc, a fake ARP prober, and a fake network whose addresses follow
// whichever netplan file is the effective one (the overlay in /run, else /etc).

const (
	etcNetplan = "etc/netplan/90-vedette.yaml"
	runNetplan = "run/netplan/90-vedette.yaml"
	sourcesRel = "etc/chrony/sources.d/vedette.sources"
	boot2      = "99999999-8888-4777-8666-555555555555"
)

type fakeProber struct {
	mu        sync.Mutex
	conflict  bool
	probeErr  error
	gwErr     error
	gwErrFor  map[string]error // by source address; wins over gwErr
	probed    []string
	gwChecked []string
}

func (p *fakeProber) Probe(_ context.Context, iface string, ip netip.Addr) (ops.ProbeResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probed = append(p.probed, iface+" "+ip.String())
	return ops.ProbeResult{Conflict: p.conflict, MAC: "aa:bb:cc:dd:ee:ff"}, p.probeErr
}

func (p *fakeProber) GatewayCheck(_ context.Context, iface string, src, gw netip.Addr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gwChecked = append(p.gwChecked, iface+" "+src.String()+" "+gw.String())
	if err, ok := p.gwErrFor[src.String()]; ok {
		return err
	}
	return p.gwErr
}

func (p *fakeProber) set(f func(*fakeProber)) {
	p.mu.Lock()
	f(p)
	p.mu.Unlock()
}

func (p *fakeProber) probes() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.probed...)
}

// netBox is the fake network: eth0 always holds 192.168.1.50/24 (the address the installer gave),
// plus every address of the effective netplan file (DHCP: 192.168.1.77/24); eth1 is a second card.
type netBox struct {
	m      interface{ ReadRoot(string) (string, error) }
	noAddr atomic.Bool // the new address never shows up
}

var addrRE = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+/\d+`)

func (b *netBox) interfaces() ([]ops.HostIface, error) {
	text, err := b.m.ReadRoot(runNetplan)
	if err != nil {
		text, _ = b.m.ReadRoot(etcNetplan)
	}
	addrs := []netip.Prefix{netip.MustParsePrefix("192.168.1.50/24")}
	if !b.noAddr.Load() {
		for _, a := range addrRE.FindAllString(text, -1) {
			addrs = append(addrs, netip.MustParsePrefix(a))
		}
		if strings.Contains(text, "dhcp4: true") {
			addrs = append(addrs, netip.MustParsePrefix("192.168.1.77/24"))
		}
	}
	return []ops.HostIface{
		{Name: "lo", Loopback: true, Addrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
		{Name: "eth0", MAC: "02:00:00:00:00:01", Addrs: addrs},
		{Name: "eth1", MAC: "02:00:00:00:00:02"},
	}, nil
}

type netEnv struct {
	*sysEnv
	box   *netBox
	probe *fakeProber
}

func netMut(box *netBox, probe *fakeProber) mut {
	return func(_ *ops.Config, d *ops.Deps) {
		d.Interfaces, d.Probe = box.interfaces, probe
		d.NetPoll, d.NetWait, d.NetRetryGap = time.Millisecond, 30*time.Millisecond, time.Millisecond
	}
}

func startNet(t *testing.T) *netEnv {
	t.Helper()
	box, probe := &netBox{}, &fakeProber{}
	e := startSys(t, netMut(box, probe))
	box.m = e.m
	physicalCards(e.m)
	e.m.RuleText("chronyc", "-N", "^,*,203.0.113.7,2,6,377,12,0.0,0.0,0.0\n^,+,ntp1.example.com,2,6,377,12,0.0,0.0,0.0\n", 0, "", "")
	e.o.Start(context.Background(), e.h.Server)
	t.Cleanup(e.o.Close)
	return &netEnv{sysEnv: e, box: box, probe: probe}
}

func staticArgs(addr, gw string, mutate ...func(*api.NetApplyArgs)) api.NetApplyArgs {
	a := api.NetApplyArgs{
		Mgmt:            api.NetApplyMgmt{Iface: "eth0", Mode: api.NetModeStatic, Address: addr, Gateway: gw, DNS: []string{"1.1.1.1"}},
		ConfirmTimeoutS: 60,
	}
	for _, f := range mutate {
		f(&a)
	}
	return a
}

func span(name string) func(*api.NetApplyArgs) {
	return func(a *api.NetApplyArgs) { a.SPAN = api.NetApplySPAN{Iface: &name} }
}

func (n *netEnv) start(t *testing.T, args any, command string) api.Run {
	t.Helper()
	run, err := n.h.Client.Run(context.Background(), command, args, n.id(), "admin@example.com")
	if err != nil {
		t.Fatalf("%s: %v", command, err)
	}
	return run
}

// waitStatus polls until the run has the status (the stream of an awaiting run does not end).
func waitStatus(t *testing.T, h *servertest.Harness, id string, want api.Status) api.Run {
	t.Helper()
	var last api.Run
	eventually(t, fmt.Sprintf("run %s to be %s (last %s)", id, want, last.Status), func() bool {
		r, err := h.Client.GetRun(context.Background(), id)
		last = r
		return err == nil && r.Status == want
	})
	return last
}

// apply sends net.apply and waits for the run to wait for confirmation.
func (n *netEnv) apply(t *testing.T, args api.NetApplyArgs) api.Run {
	t.Helper()
	r := n.start(t, args, "net.apply")
	return waitStatus(t, n.h, r.RunID, api.StatusAwaitingConfirm)
}

// applyFinal sends net.apply and waits for its final status.
func (n *netEnv) applyFinal(t *testing.T, args api.NetApplyArgs, status api.Status, code string) api.Run {
	t.Helper()
	return n.final(t, "net.apply", args, status, code)
}

// establish makes 10.0.0.5/24 the confirmed configuration (the old state of the next change).
func (n *netEnv) establish(t *testing.T) {
	t.Helper()
	run := n.apply(t, staticArgs("10.0.0.5/24", "10.0.0.1"))
	n.ok(t, "net.confirm", api.NetRunArgs{RunID: run.RunID})
	waitStatus(t, n.h, run.RunID, api.StatusSucceeded)
	n.probe.set(func(p *fakeProber) { p.probed, p.gwChecked = nil, nil })
}

func (n *netEnv) file(rel string) (string, bool) {
	s, err := n.m.ReadRoot(rel)
	return s, err == nil
}

func (n *netEnv) gone(t *testing.T, rel string) {
	t.Helper()
	if _, ok := n.file(rel); ok {
		t.Errorf("/%s exists", rel)
	}
}

func (n *netEnv) pendingPath() string { return filepath.Join(n.m.State, "net", "pending.json") }

func (n *netEnv) applies() int { return len(n.m.Calls("netplan")) }

func (n *netEnv) state(t *testing.T) api.NetState {
	t.Helper()
	st, err := n.h.Client.StateNet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// activeTimer waits for the revert timer: the command arms it right after the run is parked, so the
// run can be seen waiting a moment before.
func (n *netEnv) activeTimer(t *testing.T) *fakeTimer {
	t.Helper()
	eventually(t, "the revert timer", func() bool { return len(n.timers.active()) == 1 })
	return n.timers.active()[0]
}

// restart stops the host without settling anything (a crash or a restart) and starts a new one on
// the same state directory and audit file. The new Ops has its own fake timers.
func (n *netEnv) restart(t *testing.T) (*servertest.Harness, *fakeTimers) {
	t.Helper()
	n.o.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := n.h.Server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	timers := &fakeTimers{}
	o2 := n.m.Ops(n.clock.Now, func(c *ops.Config, d *ops.Deps) {
		netMut(n.box, n.probe)(c, d)
		d.AfterFunc = timers.after
		d.FreeBytes = func(string) (uint64, error) { return 100 << 30, nil }
	})
	h2 := servertest.Start(t, o2.Commands(), func(so *server.Options) {
		so.StateDir, so.AuditPath, so.Readers, so.Now, so.WriteGate, so.Resume = n.m.State, n.h.AuditPath, o2.Readers(), n.clock.Now, o2.WriteGate, o2.Resume
	})
	o2.Start(context.Background(), h2.Server)
	t.Cleanup(o2.Close)
	return h2, timers
}

// --- the confirm window ---------------------------------------------------------------------------

func TestContract_NetApply_ManagementChangeWaitsThenConfirmWritesEtc(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	run := n.apply(t, staticArgs("10.0.0.5/24", "10.0.0.1"))
	if run.RevertAt == nil || !run.RevertAt.Equal(n.clock.Now().Add(60*time.Second)) {
		t.Fatalf("revert_at = %v", run.RevertAt)
	}
	// Spec 6.5 step 3: the new file is only the overlay; the saved configuration is untouched.
	overlay, ok := n.file(runNetplan)
	if !ok || !strings.Contains(overlay, "10.0.0.5/24") {
		t.Fatalf("overlay = %q", overlay)
	}
	n.gone(t, etcNetplan)
	pend, err := os.ReadFile(n.pendingPath())
	if err != nil || !strings.Contains(string(pend), run.RunID) || !strings.Contains(string(pend), `"boot_id":"11111111-2222-4333-8444-555555555555"`) {
		t.Fatalf("pending.json = %q %v", pend, err)
	}
	if st, err := os.Stat(n.pendingPath()); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("pending.json mode: %v %v", st, err)
	}
	if got := n.probe.probes(); len(got) != 1 || got[0] != "eth0 10.0.0.5" {
		t.Fatalf("ARP probes %v", got)
	}
	if calls := n.m.Calls("netplan"); len(calls) != 1 || len(calls[0]) != 1 || calls[0][0] != "apply" {
		t.Fatalf("netplan calls %v", calls)
	}
	assertEnvClean(t, n.m.Envs("netplan"))
	// The state endpoint tells what waits.
	st := n.state(t)
	if st.Pending == nil || st.Pending.RunID != run.RunID || !st.Pending.RevertAt.Equal(*run.RevertAt) {
		t.Fatalf("state/net pending = %+v", st.Pending)
	}
	if st.Config.Mgmt == nil || st.Config.Mgmt.Address != "10.0.0.5/24" {
		t.Fatalf("state/net config = %+v", st.Config)
	}
	if res := result[api.NetApplyResult](t, run); !res.Changed || !res.Confirm {
		t.Fatalf("result %+v", res)
	}
	// The write lock is held: every other write is 409 pending_confirm with the run id.
	ce := n.refusedWith(t, "os.check", nil, http.StatusConflict, api.CodePendingConfirm)
	if ce.RunID != run.RunID {
		t.Fatalf("pending_confirm run %q", ce.RunID)
	}
	// os.reboot gets the 409 too (INV-16; the framework answers before the command's own net_pending_confirm).
	_ = n.refusedWith(t, "os.reboot", api.OSRebootArgs{When: "now"}, http.StatusConflict, api.CodePendingConfirm)

	n.ok(t, "net.confirm", api.NetRunArgs{RunID: run.RunID})
	done := waitStatus(t, n.h, run.RunID, api.StatusSucceeded)
	if done.Error != nil {
		t.Fatalf("final run %+v", done)
	}
	if etc, ok := n.file(etcNetplan); !ok || etc != overlay {
		t.Fatalf("/etc after confirm = %q", etc)
	}
	if st, err := os.Stat(filepath.Join(n.m.Root, etcNetplan)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("netplan file mode: %v %v", st, err)
	}
	n.gone(t, runNetplan)
	if _, err := os.Lstat(n.pendingPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending.json after confirm: %v", err)
	}
	if n.applies() != 1 {
		t.Fatalf("confirm ran netplan apply (%d calls): the running configuration does not change", n.applies())
	}
	if len(n.timers.active()) != 0 {
		t.Fatal("the revert timer is still armed after confirm")
	}
	if st := n.state(t); st.Pending != nil {
		t.Fatalf("pending after confirm: %+v", st.Pending)
	}
	n.ok(t, "os.reboot.cancel", nil) // the lock is free again
}

func TestContract_NetApply_TheTimerRevertsTheChange(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	etcBefore, _ := n.file(etcNetplan)
	tm := n.activeTimer(t)
	if tm.d != 60*time.Second {
		t.Fatalf("timer of %s, want 60s", tm.d)
	}
	applies := n.applies()
	tm.fire()
	done := waitStatus(t, n.h, run.RunID, api.StatusReverted)
	if done.Error == nil || done.Error.Code != api.CodeNotConfirmed {
		t.Fatalf("run %+v", done)
	}
	n.gone(t, runNetplan)
	if etc, _ := n.file(etcNetplan); etc != etcBefore || !strings.Contains(etc, "10.0.0.5/24") {
		t.Fatalf("the saved configuration changed: %q", etc)
	}
	if _, err := os.Lstat(n.pendingPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending.json after the revert: %v", err)
	}
	if n.applies() != applies+1 {
		t.Fatalf("netplan apply ran %d times for the revert", n.applies()-applies)
	}
	// The old configuration was checked: its address and gateway.
	if gw := n.probe.gwChecked; len(gw) == 0 || !strings.HasSuffix(gw[len(gw)-1], "10.0.0.1") || !strings.Contains(gw[len(gw)-1], "10.0.0.5") {
		t.Fatalf("gateway checks %v", gw)
	}
	// The lock is free: a new change can start.
	n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
}

func TestContract_NetRevert_CancelsAtOnce(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	n.ok(t, "net.revert", api.NetRunArgs{RunID: run.RunID})
	done := waitStatus(t, n.h, run.RunID, api.StatusReverted)
	if done.Error == nil || done.Error.Code != api.CodeCancelled {
		t.Fatalf("run %+v", done)
	}
	n.gone(t, runNetplan)
	if len(n.timers.active()) != 0 {
		t.Fatal("the timer is armed after a cancel")
	}
	if st := n.state(t); st.Pending != nil || st.Config.Mgmt == nil || st.Config.Mgmt.Address != "10.0.0.5/24" {
		t.Fatalf("state/net %+v %+v", st.Pending, st.Config.Mgmt)
	}
}

func TestContract_NetApply_ARebootInsideTheWindowIsRevertedByReboot(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	// The box reboots: /run is empty, the boot id is new, the old file on disk is what runs.
	if err := os.Remove(filepath.Join(n.m.Root, runNetplan)); err != nil {
		t.Fatal(err)
	}
	n.m.SetBootID(boot2)
	applies := n.applies()
	h2, timers2 := n.restart(t)
	done := waitStatus(t, h2, run.RunID, api.StatusReverted)
	if done.Error == nil || done.Error.Code != api.CodeRevertedByReboot {
		t.Fatalf("run %+v", done)
	}
	if _, err := os.Lstat(n.pendingPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending.json after a reboot: %v", err)
	}
	if len(timers2.active()) != 0 {
		t.Fatal("a timer was armed for a run that was already reverted")
	}
	if n.applies() != applies {
		t.Fatal("netplan apply ran at start-up after a reboot: the boot already applied the old file")
	}
	if st, err := h2.Client.StateNet(context.Background()); err != nil || st.Pending != nil || st.Config.Mgmt.Address != "10.0.0.5/24" {
		t.Fatalf("state/net %+v %v", st, err)
	}
	// Nothing holds the lock any more.
	if _, err := h2.Client.Run(context.Background(), "net.apply", staticArgs("10.0.0.9/24", "10.0.0.1"), n.id(), "admin@example.com"); err != nil {
		t.Fatalf("the lock is still held: %v", err)
	}
}

func TestContract_NetApply_AHostCrashBeforeRevertAtRearmsTheTimer(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	n.clock.Advance(20 * time.Second)
	h2, timers2 := n.restart(t)
	waitStatus(t, h2, run.RunID, api.StatusAwaitingConfirm)
	tm := func() *fakeTimer {
		act := timers2.active()
		if len(act) != 1 {
			t.Fatalf("%d timers after the restart", len(act))
		}
		return act[0]
	}()
	if tm.d != 40*time.Second {
		t.Fatalf("re-armed timer of %s, want the 40 s that are left", tm.d)
	}
	// The overlay is still there and the lock is held.
	if _, ok := n.file(runNetplan); !ok {
		t.Fatal("the overlay is gone")
	}
	_, err := h2.Client.Run(context.Background(), "os.check", nil, n.id(), "x")
	if !client.IsCode(err, api.CodePendingConfirm) {
		t.Fatalf("a write after the restart: %v", err)
	}
	// The re-armed timer reverts it.
	tm.fire()
	done := waitStatus(t, h2, run.RunID, api.StatusReverted)
	if done.Error == nil || done.Error.Code != api.CodeNotConfirmed {
		t.Fatalf("run %+v", done)
	}
	n.gone(t, runNetplan)
}

func TestContract_NetApply_AHostCrashBeforeRevertAtStillAllowsConfirm(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	h2, timers2 := n.restart(t)
	waitStatus(t, h2, run.RunID, api.StatusAwaitingConfirm)
	r, err := h2.Client.Run(context.Background(), "net.confirm", api.NetRunArgs{RunID: run.RunID}, n.id(), "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if r = waitDone(t, h2.Client, r.RunID); r.Status != api.StatusSucceeded {
		t.Fatalf("confirm after restart: %+v", r)
	}
	waitStatus(t, h2, run.RunID, api.StatusSucceeded)
	if etc, ok := n.file(etcNetplan); !ok || !strings.Contains(etc, "10.0.0.9/24") {
		t.Fatalf("/etc = %q", etc)
	}
	n.gone(t, runNetplan)
	if len(timers2.active()) != 0 {
		t.Fatal("a timer outlived the confirm")
	}
}

func TestContract_NetApply_AHostCrashAfterRevertAtRevertsAtStart(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	n.clock.Advance(61 * time.Second)
	applies := n.applies()
	h2, timers2 := n.restart(t)
	done := waitStatus(t, h2, run.RunID, api.StatusReverted)
	if done.Error == nil || done.Error.Code != api.CodeNotConfirmed {
		t.Fatalf("run %+v", done)
	}
	n.gone(t, runNetplan)
	if n.applies() != applies+1 || len(timers2.active()) != 0 {
		t.Fatalf("applies +%d, timers %d", n.applies()-applies, len(timers2.active()))
	}
	if _, err := os.Lstat(n.pendingPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending.json: %v", err)
	}
}

func TestContract_NetApply_AFailedConnectivityCheckRevertsAtOnce(t *testing.T) {
	t.Parallel()
	t.Run("the gateway is silent", func(t *testing.T) {
		t.Parallel()
		n := startNet(t)
		n.establish(t)
		// Only the new address gets no answer; the old one (checked again after the revert) does.
		n.probe.set(func(p *fakeProber) { p.gwErrFor = map[string]error{"10.0.0.9": ops.ErrGatewaySilent} })
		applies := n.applies()
		n.applyFinal(t, staticArgs("10.0.0.9/24", "10.0.0.1"), api.StatusReverted, api.CodeConnectivityCheckFail)
		n.gone(t, runNetplan)
		if _, err := os.Lstat(n.pendingPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("pending.json: %v", err)
		}
		if n.applies() != applies+2 {
			t.Fatalf("netplan apply ran %d times, want the apply and the revert", n.applies()-applies)
		}
		if etc, _ := n.file(etcNetplan); !strings.Contains(etc, "10.0.0.5/24") {
			t.Fatalf("the saved configuration: %q", etc)
		}
		if len(n.timers.active()) != 0 {
			t.Fatal("a timer for a run that never waited")
		}
	})
	t.Run("the address never appears", func(t *testing.T) {
		t.Parallel()
		n := startNet(t)
		n.box.noAddr.Store(true)
		n.applyFinal(t, staticArgs("10.0.0.9/24", "10.0.0.1"), api.StatusReverted, api.CodeConnectivityCheckFail)
		n.gone(t, runNetplan)
		n.gone(t, etcNetplan)
		if len(n.probe.gwChecked) != 0 {
			t.Fatalf("the gateway was asked although the address never appeared: %v", n.probe.gwChecked)
		}
	})
	t.Run("netplan apply fails", func(t *testing.T) {
		t.Parallel()
		n := startNet(t)
		n.m.Rule("netplan", "apply", "", 1, "", "")
		n.applyFinal(t, staticArgs("10.0.0.9/24", "10.0.0.1"), api.StatusFailed, api.CodeRevertFailed) // the revert's apply fails too
		n.gone(t, runNetplan)
		n.gone(t, etcNetplan)
	})
}

func TestContract_NetApply_ARevertThatCannotApplyFailsAndKeepsTheOldFileOnDisk(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	n.m.Rule("netplan", "apply", "", 1, "", "") // from now on netplan apply fails
	n.ok2(t, "net.revert", run.RunID, http.StatusOK)
	done := waitStatus(t, n.h, run.RunID, api.StatusFailed)
	if done.Error == nil || done.Error.Code != api.CodeRevertFailed {
		t.Fatalf("run %+v", done)
	}
	if etc, _ := n.file(etcNetplan); !strings.Contains(etc, "10.0.0.5/24") {
		t.Fatalf("the saved configuration: %q", etc)
	}
	n.gone(t, runNetplan)
	// The note stays: the next start retries (the box has not been restored yet).
	if _, err := os.Lstat(n.pendingPath()); err != nil {
		t.Fatalf("pending.json was removed although netplan never applied the old file: %v", err)
	}
}

// ok2 runs net.confirm or net.revert and expects the command's own run to end failed (the revert
// it triggers failed) while the call itself was accepted.
func (n *netEnv) ok2(t *testing.T, command, runID string, _ int) {
	t.Helper()
	r, err := n.call(t, command, api.NetRunArgs{RunID: runID})
	if err != nil || r.Status != api.StatusFailed || r.Error == nil || r.Error.Code != api.CodeRevertFailed {
		t.Fatalf("%s: %+v %v", command, r, err)
	}
}

// --- refusals ---------------------------------------------------------------------------------------

func TestContract_NetApply_AnAddressInUseIsRefusedAndNothingIsWritten(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.probe.set(func(p *fakeProber) { p.conflict = true })
	r := n.applyFinal(t, staticArgs("10.0.0.9/24", "10.0.0.1"), api.StatusRefused, api.CodeAddressConflict)
	if !strings.Contains(r.Error.Message, "aa:bb:cc:dd:ee:ff") {
		t.Errorf("the refusal does not name the other device: %q", r.Error.Message)
	}
	n.gone(t, runNetplan)
	n.gone(t, etcNetplan)
	n.gone(t, sourcesRel)
	if _, err := os.Lstat(n.pendingPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending.json: %v", err)
	}
	if got := n.m.AllCalls(); len(got) != 0 {
		t.Fatalf("a program ran: %v", got)
	}
	// Nothing waits: the lock is free.
	n.probe.set(func(p *fakeProber) { p.conflict = false })
	n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
}

func TestContract_NetApply_AFailedProbeFailsTheRunAndChangesNothing(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.probe.set(func(p *fakeProber) { p.probeErr = errors.New("no packet socket") })
	n.applyFinal(t, staticArgs("10.0.0.9/24", "10.0.0.1"), api.StatusFailed, api.CodeARPProbeFailed)
	n.gone(t, runNetplan)
	if got := n.m.AllCalls(); len(got) != 0 {
		t.Fatalf("a program ran: %v", got)
	}
}

func TestContract_NetApply_CheckRefusals(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.refused(t, "net.apply", staticArgs("10.0.0.9/24", "10.0.1.1"), http.StatusPreconditionFailed, api.CodeGatewayOutsideSubnet)
	n.refused(t, "net.apply", staticArgs("10.0.0.9/24", "10.0.0.1", span("eth0")), http.StatusPreconditionFailed, api.CodeSameIface)
	n.refused(t, "net.apply", staticArgs("10.0.0.9/24", "10.0.0.1", span("eth7")), http.StatusPreconditionFailed, api.CodeIfaceUnknown)
	n.refused(t, "net.apply", staticArgs("10.0.0.9/24", "10.0.0.1", func(a *api.NetApplyArgs) { a.Mgmt.Iface = "eth9" }), http.StatusPreconditionFailed, api.CodeIfaceUnknown)
	n.refused(t, "net.apply", staticArgs("10.0.0.9/24", "10.0.0.1", func(a *api.NetApplyArgs) { a.Mgmt.Iface = "lo" }), http.StatusPreconditionFailed, api.CodeIfaceUnknown)
	if got := n.m.AllCalls(); len(got) != 0 || len(n.probe.probes()) != 0 {
		t.Fatalf("something ran: %v %v", got, n.probe.probes())
	}
	n.gone(t, runNetplan)
	// A netplan file that is not the host's (here in /etc/netplan) makes the backend unsupported (D-99).
	n.m.WriteRoot("etc/netplan/50-cloud-init.yaml", "network:\n  version: 2\n")
	n.refused(t, "net.apply", staticArgs("10.0.0.9/24", "10.0.0.1"), http.StatusPreconditionFailed, api.CodeNetBackendUnsupported)
	n.m.RemoveRoot("etc/netplan/50-cloud-init.yaml")
	n.m.RemoveRoot("usr/sbin/netplan")
	n.refused(t, "net.apply", staticArgs("10.0.0.9/24", "10.0.0.1"), http.StatusPreconditionFailed, api.CodeNetBackendUnsupported)
	if got := n.m.AllCalls(); len(got) != 0 {
		t.Fatalf("a program ran: %v", got)
	}
}

func TestContract_NetApply_InvalidArgsNeverReachTheSystem(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	s := func(m func(*api.NetApplyArgs)) api.NetApplyArgs { return staticArgs("10.0.0.9/24", "10.0.0.1", m) }
	cases := map[string]api.NetApplyArgs{
		"dhcp with an address":      s(func(a *api.NetApplyArgs) { a.Mgmt.Mode = api.NetModeDHCP }),
		"static without address":    s(func(a *api.NetApplyArgs) { a.Mgmt.Address = "" }),
		"a network address":         staticArgs("10.0.0.0/24", "10.0.0.1"),
		"a broadcast address":       staticArgs("10.0.0.255/24", "10.0.0.1"),
		"a bad prefix":              staticArgs("10.0.0.9/31", "10.0.0.1"),
		"a name for an address":     staticArgs("host.example/24", "10.0.0.1"),
		"a gateway that is the box": staticArgs("10.0.0.9/24", "10.0.0.9"),
		"a loopback dns":            s(func(a *api.NetApplyArgs) { a.Mgmt.DNS = []string{"127.0.0.1"} }),
		"four dns":                  s(func(a *api.NetApplyArgs) { a.Mgmt.DNS = []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"} }),
		"a bad mode":                s(func(a *api.NetApplyArgs) { a.Mgmt.Mode = "static\nx: y" }),
		"an iface with a space":     s(func(a *api.NetApplyArgs) { a.Mgmt.Iface = "eth0 x" }),
		"an iface with a newline":   s(func(a *api.NetApplyArgs) { a.Mgmt.Iface = "eth0\nx: y" }),
		"an empty span":             s(func(a *api.NetApplyArgs) { e := ""; a.SPAN.Iface = &e }),
		"a timeout of 29":           s(func(a *api.NetApplyArgs) { a.ConfirmTimeoutS = 29 }),
		"a timeout of 601":          s(func(a *api.NetApplyArgs) { a.ConfirmTimeoutS = 601 }),
		"a negative timeout":        s(func(a *api.NetApplyArgs) { a.ConfirmTimeoutS = -1 }),
		"five ntp servers": s(func(a *api.NetApplyArgs) {
			a.NTP = []string{"a.example", "b.example", "c.example", "d.example", "e.example"}
		}),
		"no mgmt": {},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) { n.refused(t, "net.apply", args, http.StatusBadRequest, api.CodeInvalidArgs) })
	}
	if got := n.m.AllCalls(); len(got) != 0 {
		t.Fatalf("a program ran: %v", got)
	}
	// net.confirm and net.revert take a run id and nothing else.
	for _, id := range []string{"", "rn_x", "rn_0123456789abcdeg", "../etc", "rn_0123456789abcdef0"} {
		n.refused(t, "net.confirm", api.NetRunArgs{RunID: id}, http.StatusBadRequest, api.CodeInvalidArgs)
		n.refused(t, "net.revert", api.NetRunArgs{RunID: id}, http.StatusBadRequest, api.CodeInvalidArgs)
	}
}

// --- changes that need no confirmation ---------------------------------------------------------------

func TestContract_NetApply_DNSSPANAndNTPOnlyChangesApplyAtOnce(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	applies := n.applies()

	r := n.applyFinal(t, staticArgs("10.0.0.5/24", "10.0.0.1", func(a *api.NetApplyArgs) { a.Mgmt.DNS = []string{"9.9.9.9"} }), api.StatusSucceeded, "")
	if res := result[api.NetApplyResult](t, r); !res.Changed || res.Confirm {
		t.Fatalf("dns-only result %+v", res)
	}
	if etc, _ := n.file(etcNetplan); !strings.Contains(etc, "9.9.9.9") || strings.Contains(etc, "1.1.1.1") {
		t.Fatalf("/etc after a DNS change: %q", etc)
	}
	n.gone(t, runNetplan)
	if _, err := os.Lstat(n.pendingPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a pending note for a DNS change")
	}
	if n.applies() != applies+1 || len(n.probe.probes()) != 0 || len(n.timers.active()) != 0 {
		t.Fatalf("applies +%d probes %v timers %d", n.applies()-applies, n.probe.probes(), len(n.timers.active()))
	}

	dns9 := func(a *api.NetApplyArgs) { a.Mgmt.DNS = []string{"9.9.9.9"} }
	n.applyFinal(t, staticArgs("10.0.0.5/24", "10.0.0.1", dns9, span("eth1")), api.StatusSucceeded, "")
	if etc, _ := n.file(etcNetplan); !strings.Contains(etc, "eth1:") || !strings.Contains(etc, "link-local: []") {
		t.Fatalf("/etc after a SPAN change: %q", etc)
	}
	if st := n.state(t); st.Config.SPAN == nil || *st.Config.SPAN != "eth1" {
		t.Fatalf("state/net span %v", st.Config.SPAN)
	}
	applies = n.applies()

	// NTP only: chrony, not netplan.
	n.m.RuleText("chronyc", "-N", "^,*,ntp1.example.com,2,6,377,12,0.0,0.0,0.0\n", 0, "", "")
	n.applyFinal(t, staticArgs("10.0.0.5/24", "10.0.0.1", dns9, span("eth1"), func(a *api.NetApplyArgs) { a.NTP = []string{"ntp1.example.com"} }), api.StatusSucceeded, "")
	if n.applies() != applies {
		t.Fatal("an NTP-only change ran netplan")
	}
	if src, _ := n.file(sourcesRel); !strings.Contains(src, "server ntp1.example.com iburst\n") || strings.Contains(src, "pool") {
		t.Fatalf("vedette.sources: %q", src)
	}
	if st := n.state(t); len(st.Config.NTP) != 1 || st.Config.NTP[0] != "ntp1.example.com" {
		t.Fatalf("state/net ntp %v", st.Config.NTP)
	}
	// None of them waited for confirmation or left the lock held.
	n.ok(t, "os.reboot.cancel", nil)
}

func TestContract_NetApply_TheSameStateIsANoOp(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	etc, _ := n.file(etcNetplan)
	all := len(n.m.AllCalls())
	r := n.applyFinal(t, staticArgs("10.0.0.5/24", "10.0.0.1"), api.StatusSucceeded, "")
	if res := result[api.NetApplyResult](t, r); res.Changed || res.Confirm {
		t.Fatalf("result %+v", res)
	}
	if got, _ := n.file(etcNetplan); got != etc {
		t.Fatal("the file changed")
	}
	if len(n.m.AllCalls()) != all || len(n.probe.probes()) != 0 || len(n.timers.active()) != 0 {
		t.Fatalf("a no-op did something: %v %v", n.m.AllCalls()[all:], n.probe.probes())
	}
	n.gone(t, runNetplan)
}

func TestContract_NetApply_DHCPAndAFirstConfigurationNeedConfirmation(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	run := n.apply(t, api.NetApplyArgs{Mgmt: api.NetApplyMgmt{Iface: "eth0", Mode: api.NetModeDHCP}, ConfirmTimeoutS: 30})
	if len(n.probe.probes()) != 0 {
		t.Fatalf("a DHCP change was probed: %v", n.probe.probes())
	}
	if run.RevertAt == nil || !run.RevertAt.Equal(n.clock.Now().Add(30*time.Second)) {
		t.Fatalf("revert_at %v", run.RevertAt)
	}
	ov, _ := n.file(runNetplan)
	if !strings.Contains(ov, "dhcp4: true") {
		t.Fatalf("overlay %q", ov)
	}
	n.ok(t, "net.confirm", api.NetRunArgs{RunID: run.RunID})
	// Back to a static address is a management change again.
	n.apply(t, staticArgs("10.0.0.5/24", ""))
}

func TestContract_NetApply_TheDefaultWindowIs120Seconds(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	run := n.apply(t, staticArgs("10.0.0.5/24", "10.0.0.1", func(a *api.NetApplyArgs) { a.ConfirmTimeoutS = 0 }))
	if run.RevertAt == nil || !run.RevertAt.Equal(n.clock.Now().Add(120*time.Second)) {
		t.Fatalf("revert_at %v", run.RevertAt)
	}
}

func TestContract_NetApply_AFailingDNSChangePutsTheOldFileBack(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	etc, _ := n.file(etcNetplan)
	n.probe.set(func(p *fakeProber) { p.gwErr = ops.ErrGatewaySilent })
	n.applyFinal(t, staticArgs("10.0.0.5/24", "10.0.0.1", func(a *api.NetApplyArgs) { a.Mgmt.DNS = []string{"9.9.9.9"} }), api.StatusReverted, api.CodeConnectivityCheckFail)
	if got, _ := n.file(etcNetplan); got != etc {
		t.Fatalf("the old file was not put back: %q", got)
	}
}

// --- confirm racing the timer ---------------------------------------------------------------------

func TestContract_NetConfirm_AWrongRunIDIsRefused(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	// Nothing waits.
	n.refused(t, "net.confirm", api.NetRunArgs{RunID: "rn_0123456789abcdef"}, http.StatusPreconditionFailed, api.CodeNotAwaitingConfirm)
	n.refused(t, "net.revert", api.NetRunArgs{RunID: "rn_0123456789abcdef"}, http.StatusPreconditionFailed, api.CodeNotAwaitingConfirm)
	run := n.apply(t, staticArgs("10.0.0.5/24", "10.0.0.1"))
	applies := n.applies()
	n.refused(t, "net.confirm", api.NetRunArgs{RunID: "rn_0123456789abcdef"}, http.StatusPreconditionFailed, api.CodeNotAwaitingConfirm)
	n.refused(t, "net.revert", api.NetRunArgs{RunID: "rn_0123456789abcdef"}, http.StatusPreconditionFailed, api.CodeNotAwaitingConfirm)
	// The run is untouched.
	if r, _ := n.h.Client.GetRun(context.Background(), run.RunID); r.Status != api.StatusAwaitingConfirm || n.applies() != applies {
		t.Fatalf("a wrong id changed something: %+v", r)
	}
	if _, ok := n.file(runNetplan); !ok {
		t.Fatal("the overlay was removed")
	}
	// A settled run id is refused as well.
	n.ok(t, "net.confirm", api.NetRunArgs{RunID: run.RunID})
	waitStatus(t, n.h, run.RunID, api.StatusSucceeded)
	n.refused(t, "net.confirm", api.NetRunArgs{RunID: run.RunID}, http.StatusPreconditionFailed, api.CodeNotAwaitingConfirm)
}

func TestContract_NetConfirm_AfterTheTimerFiredIsRefusedAndChangesNothing(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	n.activeTimer(t).fire()
	waitStatus(t, n.h, run.RunID, api.StatusReverted)
	etc, _ := n.file(etcNetplan)
	n.refused(t, "net.confirm", api.NetRunArgs{RunID: run.RunID}, http.StatusPreconditionFailed, api.CodeNotAwaitingConfirm)
	if got, _ := n.file(etcNetplan); got != etc || strings.Contains(got, "10.0.0.9") {
		t.Fatalf("a late confirm wrote /etc: %q", got)
	}
}

func TestContract_NetConfirm_ATimerThatFiresAfterAConfirmDoesNothing(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	tm := n.activeTimer(t)
	n.ok(t, "net.confirm", api.NetRunArgs{RunID: run.RunID})
	applies := n.applies()
	tm.fire() // a stale timer (the race lost): Claim fails, nothing runs
	if n.applies() != applies {
		t.Fatal("the stale timer ran netplan apply")
	}
	if r := waitStatus(t, n.h, run.RunID, api.StatusSucceeded); r.Error != nil {
		t.Fatalf("run %+v", r)
	}
	if etc, _ := n.file(etcNetplan); !strings.Contains(etc, "10.0.0.9/24") {
		t.Fatalf("/etc %q", etc)
	}
}

// Exactly one of a confirm and the timer wins, whatever the order; the loser changes nothing.
func TestContract_NetConfirm_RacingTheTimerExactlyOneWins(t *testing.T) {
	t.Parallel()
	for i := range 12 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			n := startNet(t)
			run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
			tm := n.activeTimer(t)
			var wg sync.WaitGroup
			var confirmErr error
			var confirmRun api.Run
			wg.Add(2)
			go func() { defer wg.Done(); tm.fire() }()
			go func() {
				defer wg.Done()
				confirmRun, confirmErr = n.call(t, "net.confirm", api.NetRunArgs{RunID: run.RunID})
			}()
			wg.Wait()
			final := waitStatus2(t, n.h, run.RunID)
			etc, hasEtc := n.file(etcNetplan)
			switch final.Status {
			case api.StatusSucceeded:
				if confirmErr != nil || confirmRun.Status != api.StatusSucceeded || !hasEtc || !strings.Contains(etc, "10.0.0.9") {
					t.Fatalf("confirm won but: %v %+v etc=%v", confirmErr, confirmRun, hasEtc)
				}
				if n.applies() != 1 {
					t.Fatalf("the timer ran a revert although the confirm won (%d applies)", n.applies())
				}
			case api.StatusReverted:
				var ce *client.Error
				if !errors.As(confirmErr, &ce) && confirmRun.Status == api.StatusSucceeded {
					t.Fatalf("both won: confirm %+v", confirmRun)
				}
				if hasEtc {
					t.Fatalf("the timer won but /etc was written: %q", etc)
				}
				if n.applies() != 2 {
					t.Fatalf("the revert ran %d applies", n.applies())
				}
			default:
				t.Fatalf("final %+v", final)
			}
			n.gone(t, runNetplan)
			if _, err := os.Lstat(n.pendingPath()); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("pending.json: %v", err)
			}
		})
	}
}

func waitStatus2(t *testing.T, h *servertest.Harness, id string) api.Run {
	t.Helper()
	var last api.Run
	eventually(t, "the run to end", func() bool {
		r, err := h.Client.GetRun(context.Background(), id)
		last = r
		return err == nil && r.Status.Terminal()
	})
	return last
}

// --- a note or an overlay that cannot be trusted ---------------------------------------------------

func TestContract_NetConfirm_ATamperedNoteIsNeverTrustedToKeepAConfiguration(t *testing.T) {
	t.Parallel()
	good := func(n *netEnv) string {
		b, err := os.ReadFile(n.pendingPath())
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	tamper := map[string]func(t *testing.T, n *netEnv, run api.Run){
		"a symlink": func(t *testing.T, n *netEnv, _ api.Run) {
			target := filepath.Join(filepath.Dir(n.m.Root), "elsewhere.json")
			if err := os.WriteFile(target, []byte(good(n)), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(n.pendingPath()); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, n.pendingPath()); err != nil {
				t.Fatal(err)
			}
		},
		"an unknown field": func(t *testing.T, n *netEnv, _ api.Run) {
			s := strings.Replace(good(n), `}`, `,"keep":true}`, 1)
			if err := os.WriteFile(n.pendingPath(), []byte(s), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"another run id": func(t *testing.T, n *netEnv, run api.Run) {
			s := strings.Replace(good(n), run.RunID, "rn_0000000000000000", 1)
			if err := os.WriteFile(n.pendingPath(), []byte(s), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"garbage": func(t *testing.T, n *netEnv, _ api.Run) {
			if err := os.WriteFile(n.pendingPath(), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"world readable": func(t *testing.T, n *netEnv, _ api.Run) {
			if err := os.Chmod(n.pendingPath(), 0o644); err != nil { //nolint:gosec // the test makes the note too open on purpose
				t.Fatal(err)
			}
		},
		"a directory": func(t *testing.T, n *netEnv, _ api.Run) {
			if err := os.Remove(n.pendingPath()); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(n.pendingPath(), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"a changed new_sha": func(t *testing.T, n *netEnv, _ api.Run) {
			s := good(n)
			s = regexp.MustCompile(`"new_sha":"[0-9a-f]{64}"`).ReplaceAllString(s, `"new_sha":"`+strings.Repeat("ab", 32)+`"`)
			if err := os.WriteFile(n.pendingPath(), []byte(s), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, f := range tamper {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			n := startNet(t)
			n.establish(t)
			run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
			f(t, n, run)
			etc, _ := n.file(etcNetplan)
			r, err := n.call(t, "net.confirm", api.NetRunArgs{RunID: run.RunID})
			if err != nil || r.Status != api.StatusFailed || r.Error == nil || r.Error.Code != api.CodePendingInvalid {
				t.Fatalf("confirm with %s: %+v %v", name, r, err)
			}
			done := waitStatus(t, n.h, run.RunID, api.StatusReverted)
			if done.Error == nil || done.Error.Code != api.CodePendingInvalid {
				t.Fatalf("run %+v", done)
			}
			if got, _ := n.file(etcNetplan); got != etc {
				t.Fatalf("a configuration was kept on a note that cannot be trusted: %q", got)
			}
			n.gone(t, runNetplan)
		})
	}
}

func TestContract_NetConfirm_ASwappedOverlayIsNotKept(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	// Another valid file at the overlay's name: its hash is not the one recorded.
	if err := os.WriteFile(filepath.Join(n.m.Root, runNetplan), []byte("network:\n  version: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := n.call(t, "net.confirm", api.NetRunArgs{RunID: run.RunID})
	if err != nil || r.Status != api.StatusFailed || r.Error.Code != api.CodePendingInvalid {
		t.Fatalf("confirm: %+v %v", r, err)
	}
	n.gone(t, etcNetplan)
	n.gone(t, runNetplan)
	waitStatus(t, n.h, run.RunID, api.StatusReverted)
}

func TestContract_NetApply_ASymlinkedNoteAtStartIsRevertedNotTrusted(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	target := filepath.Join(filepath.Dir(n.m.Root), "elsewhere.json")
	b, _ := os.ReadFile(n.pendingPath())
	if err := os.WriteFile(target, b, 0o600); err != nil { //nolint:gosec // a file of the test's own temp area
		t.Fatal(err)
	}
	_ = os.Remove(n.pendingPath())
	if err := os.Symlink(target, n.pendingPath()); err != nil {
		t.Fatal(err)
	}
	h2, timers2 := n.restart(t)
	done := waitStatus(t, h2, run.RunID, api.StatusReverted)
	if done.Error == nil || done.Error.Code != api.CodePendingInvalid {
		t.Fatalf("run %+v", done)
	}
	n.gone(t, runNetplan)
	if len(timers2.active()) != 0 {
		t.Fatal("a timer was armed on a note that cannot be trusted")
	}
	if _, err := os.Lstat(n.pendingPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the link is still there: %v", err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != string(b) { //nolint:gosec // as above
		t.Fatal("the file the link pointed to was touched")
	}
}

// A symlink at the overlay's name is removed as a link; what it points to is not touched.
func TestContract_NetRevert_NeverFollowsALinkAtTheOverlay(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	target := filepath.Join(filepath.Dir(n.m.Root), "precious")
	if err := os.WriteFile(target, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	ov := filepath.Join(n.m.Root, runNetplan)
	_ = os.Remove(ov)
	if err := os.Symlink(target, ov); err != nil {
		t.Fatal(err)
	}
	n.ok(t, "net.revert", api.NetRunArgs{RunID: run.RunID})
	waitStatus(t, n.h, run.RunID, api.StatusReverted)
	if _, err := os.Lstat(ov); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the link survived: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep me" { //nolint:gosec // as above
		t.Fatalf("the link's target was changed: %q", b)
	}
}

// A symlink in place of /etc/netplan is not written through (the directory is refused).
func TestContract_NetApply_ALinkedNetplanDirectoryIsRefusedNotFollowed(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	run := n.apply(t, staticArgs("10.0.0.9/24", "10.0.0.1"))
	outside := filepath.Join(filepath.Dir(n.m.Root), "outside")
	if err := os.Mkdir(outside, 0o755); err != nil { //nolint:gosec // a directory of the test's own temp area
		t.Fatal(err)
	}
	dir := filepath.Join(n.m.Root, "etc/netplan")
	_ = os.RemoveAll(dir)
	if err := os.Symlink(outside, dir); err != nil {
		t.Fatal(err)
	}
	r, err := n.call(t, "net.confirm", api.NetRunArgs{RunID: run.RunID})
	if err != nil || r.Status != api.StatusFailed {
		t.Fatalf("confirm: %+v %v", r, err)
	}
	if es, _ := os.ReadDir(outside); len(es) != 0 {
		t.Fatalf("the host wrote through the link: %v", es)
	}
}

func TestContract_NetApply_AnOverlayWithoutARunIsRevertedAtStart(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t)
	// A crash while the change was starting: the note and the overlay exist, no run waits.
	n.m.WriteRoot(runNetplan, "network:\n  version: 2\n")
	applies := n.applies()
	h2, _ := n.restart(t)
	recs := audit(t, h2)
	if last := recs[len(recs)-1]; last.Actor != "system" || last.Code == nil || *last.Code != "reverted_at_start" {
		t.Fatalf("the revert at start was not audited: %+v", last)
	}
	n.gone(t, runNetplan)
	if n.applies() != applies+1 {
		t.Fatalf("start-up ran netplan apply %d times", n.applies()-applies)
	}
}

// --- NTP ------------------------------------------------------------------------------------------------

func TestContract_NTP_FileContentAndEffectCheck(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.establish(t) // writes the default sources
	n.m.RuleText("chronyc", "-N", "^,*,203.0.113.7,2,6,377,12,0.0,0.0,0.0\n", 0, "", "")
	src, _ := n.file(sourcesRel)
	if src != "# Written by vedette-host. Do not edit: the host rewrites this file.\npool pool.ntp.org iburst\n" {
		t.Fatalf("default sources: %q", src)
	}
	if st, err := os.Stat(filepath.Join(n.m.Root, sourcesRel)); err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("sources mode: %v %v", st, err)
	}
	if st := n.state(t); st.Config.NTP == nil || len(st.Config.NTP) != 0 {
		t.Fatalf("default ntp in state/net: %#v", st.Config.NTP)
	}
	calls := n.m.Calls("chronyc")
	if len(calls) < 2 || strings.Join(calls[0], " ") != "reload sources" || strings.Join(calls[1], " ") != "-N -c sources" {
		t.Fatalf("chronyc calls %v", calls)
	}
	assertEnvClean(t, n.m.Envs("chronyc"))

	// Four servers, an address among them.
	n.m.ClearRules("chronyc")
	n.m.RuleText("chronyc", "-N", "^,*,203.0.113.7,2,6,377,12,0,0,0\n^,+,ntp.example.org,2,6,377,12,0,0,0\n^,-,time-a.example.net,2,6,377,12,0,0,0\n=,?,ntp_4.example,2,6,377,12,0,0,0\n", 0, "", "")
	servers := []string{"203.0.113.7", "ntp.example.org", "time-a.example.net", "ntp_4.example"}
	n.applyFinal(t, staticArgs("10.0.0.5/24", "10.0.0.1", func(a *api.NetApplyArgs) { a.NTP = servers }), api.StatusSucceeded, "")
	src, _ = n.file(sourcesRel)
	want := "# Written by vedette-host. Do not edit: the host rewrites this file.\n"
	for _, s := range servers {
		want += "server " + s + " iburst\n"
	}
	if src != want {
		t.Fatalf("sources %q", src)
	}
	if st := n.state(t); strings.Join(st.Config.NTP, ",") != strings.Join(servers, ",") {
		t.Fatalf("state/net ntp %v", st.Config.NTP)
	}
	// The same servers again: nothing to do (no reload).
	reloads := len(n.m.Calls("chronyc"))
	n.applyFinal(t, staticArgs("10.0.0.5/24", "10.0.0.1", func(a *api.NetApplyArgs) { a.NTP = servers }), api.StatusSucceeded, "")
	if len(n.m.Calls("chronyc")) != reloads {
		t.Fatal("an unchanged NTP list reloaded chrony")
	}
	// Back to the default pool.
	n.m.ClearRules("chronyc")
	n.m.RuleText("chronyc", "-N", "^,*,203.0.113.7,2,6,377,12,0,0,0\n", 0, "", "")
	n.applyFinal(t, staticArgs("10.0.0.5/24", "10.0.0.1"), api.StatusSucceeded, "")
	if src, _ = n.file(sourcesRel); !strings.Contains(src, "pool pool.ntp.org iburst\n") || strings.Contains(src, "server ") {
		t.Fatalf("sources after the default: %q", src)
	}
}

func TestContract_NTP_InjectionAndBadNamesAreRefusedBeforeAnythingIsWritten(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	bad := []string{
		"a.example\nserver evil.example iburst", "a.example iburst\nbindcmdaddress 0.0.0.0", "evil.example\r\nallow 0.0.0.0/0",
		"a b", "a\tb", "-x", ".x", "x;id", "x$(id)", "`id`", "a/b", "http://a.example", "a.example:123", "[::1]", "::1", "2001:db8::1",
		"1.2.3.999", "999.1.1.1", "01.2.3.4", "1.2.3", "0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255", "169.254.1.1",
		"", " ", "é.example", "a.example\x00", strings.Repeat("a", 65), "1234", "1.2.3.4/24", "pool pool.ntp.org", "a.example,b.example",
	}
	for i, s := range bad {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			n.refused(t, "net.apply", staticArgs("10.0.0.5/24", "10.0.0.1", func(a *api.NetApplyArgs) { a.NTP = []string{s} }), http.StatusBadRequest, api.CodeInvalidArgs)
		})
	}
	n.refused(t, "net.apply", staticArgs("10.0.0.5/24", "10.0.0.1", func(a *api.NetApplyArgs) { a.NTP = []string{"a.example", "A.EXAMPLE"} }), http.StatusBadRequest, api.CodeInvalidArgs)
	n.gone(t, sourcesRel)
	if got := n.m.AllCalls(); len(got) != 0 {
		t.Fatalf("a program ran: %v", got)
	}
}

func TestContract_NTP_AnEffectCheckThatFailsPutsTheOldFileBack(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.m.RuleText("chronyc", "-N", "^,*,203.0.113.7,2,6,377,12,0,0,0\n", 0, "", "")
	n.establish(t)
	before, _ := n.file(sourcesRel)
	// chrony never lists the new server (a name that does not resolve): the old file is put back.
	n.applyFinal(t, staticArgs("10.0.0.5/24", "10.0.0.1", func(a *api.NetApplyArgs) { a.NTP = []string{"nope.example"} }), api.StatusFailed, api.CodeNTPNotApplied)
	if after, _ := n.file(sourcesRel); after != before {
		t.Fatalf("the old sources were not put back: %q", after)
	}
	calls := n.m.Calls("chronyc")
	if last := strings.Join(calls[len(calls)-1], " "); last != "reload sources" {
		t.Fatalf("chrony was not told to reload the old file: %v", calls)
	}
	// With no old file there is nothing to put back: the file is removed again.
	n2 := startNet(t)
	n2.applyFinal(t, staticArgs("10.0.0.5/24", "10.0.0.1", func(a *api.NetApplyArgs) { a.NTP = []string{"nope.example"} }), api.StatusFailed, api.CodeNTPNotApplied)
	n2.gone(t, sourcesRel)
	n2.gone(t, runNetplan) // NTP comes before the network: nothing of it was touched
	n2.gone(t, etcNetplan)
	if _, err := os.Lstat(n2.pendingPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending.json: %v", err)
	}
}

func TestContract_NTP_AFailingReloadIsNotApplied(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	n.m.Rule("chronyc", "reload", "", 1, "", "")
	n.applyFinal(t, staticArgs("10.0.0.5/24", "10.0.0.1"), api.StatusFailed, api.CodeNTPNotApplied)
	n.gone(t, sourcesRel)
}

func TestContract_NTP_ALinkAtTheSourcesNameIsNeverFollowed(t *testing.T) {
	t.Parallel()
	n := startNet(t)
	target := filepath.Join(filepath.Dir(n.m.Root), "precious")
	if err := os.WriteFile(target, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(n.m.Root, "etc/chrony/sources.d")
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // a directory of the test's own temp root
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "vedette.sources")); err != nil {
		t.Fatal(err)
	}
	// The link is not a plain file: the host refuses to rewrite through it.
	n.applyFinal(t, staticArgs("10.0.0.5/24", "10.0.0.1"), api.StatusFailed, api.CodeNTPNotApplied)
	if b, _ := os.ReadFile(target); string(b) != "keep me" { //nolint:gosec // as above
		t.Fatalf("the link's target was changed: %q", b)
	}
	if got := n.m.Calls("chronyc"); len(got) != 0 {
		t.Fatalf("chrony ran: %v", got)
	}
}

// physicalCards gives eth0 and eth1 a hardware parent in the fake /sys, as a real card has.
func physicalCards(m interface{ WriteRoot(string, string) }) {
	m.WriteRoot("sys/class/net/eth0/device", "")
	m.WriteRoot("sys/class/net/eth1/device", "")
}
