package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
	hostserver "github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

// The honeypot over the real vedette-host (D-161, WP-30 slice 8a): the real host server and the real client on a unix
// socket, a fake machine under them (opstest), the module and the adapter as cmd/vedette wires them. Nothing here runs
// a container or touches a network card.

// hpProber says nothing else answers on the LAN.
type hpProber struct{}

func (hpProber) Probe(context.Context, string, netip.Addr) (ops.ProbeResult, error) {
	return ops.ProbeResult{}, nil
}
func (hpProber) GatewayCheck(context.Context, string, netip.Addr, netip.Addr) error { return nil }

// hpHost is a host on a box 192.168.10.250/24 behind 192.168.10.1, with the honeypot unit installed (unless noUnit).
type hpHost struct {
	m *opstest.Machine
	h *servertest.Harness
}

func startHPHost(t *testing.T, noUnit bool) *hpHost {
	t.Helper()
	m := opstest.NewMachine(t)
	clock := servertest.NewClock(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC))
	m.StatefulContainers()
	if !noUnit {
		m.InstallUnit(api.ServiceHoneypot, opstest.Digest('a'), true)
	}
	m.WriteRoot("sys/class/net/eth0/device", "")
	m.WriteRoot("proc/net/route", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t010AA8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")
	m.RuleText("chronyc", "-N", "^,*,203.0.113.7,2,6,377,12,0.0,0.0,0.0\n", 0, "", "")
	o := m.Ops(clock.Now, func(_ *ops.Config, d *ops.Deps) {
		d.FreeBytes = func(string) (uint64, error) { return 100 << 30, nil }
		d.AfterFunc = func(time.Duration, func()) func() bool { return func() bool { return true } }
		d.Sleep = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
		d.Interfaces = func() ([]ops.HostIface, error) {
			return []ops.HostIface{{Name: "eth0", MAC: "02:00:00:00:00:01", Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.10.250/24")}}}, nil
		}
		d.Probe = hpProber{}
		d.NetPoll, d.NetWait, d.NetRetryGap = time.Millisecond, 30*time.Millisecond, time.Millisecond
	})
	h := servertest.Start(t, o.Commands(), func(op *hostserver.Options) {
		op.StateDir, op.Readers, op.Now, op.WriteGate, op.Resume = m.State, o.Readers(), clock.Now, o.WriteGate, o.Resume
	})
	o.Start(context.Background(), h.Server)
	t.Cleanup(o.Close)
	return &hpHost{m: m, h: h}
}

// adapter is the real adapter on this host's socket.
func (e *hpHost) adapter() *honeypotHost {
	return &honeypotHost{api: e.h.Client, log: testLogger(), poll: time.Millisecond, busyFor: 5 * time.Second, runFor: 30 * time.Second}
}

func (e *hpHost) decoyLinks() []string { return e.m.IPLinks("ns") }

func (e *hpHost) unitState(t *testing.T) string {
	t.Helper()
	st, err := e.h.Client.StateContainers(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range st.Services {
		if s.Service == api.ServiceHoneypot {
			return s.UnitState
		}
	}
	t.Fatal("no honeypot in the state of the containers")
	return ""
}

func (e *hpHost) systemctl(verb string) int {
	n := 0
	for _, c := range e.m.Calls("systemctl") {
		if len(c) > 0 && c[0] == verb {
			n++
		}
	}
	return n
}

func (e *hpHost) decoysFile() string {
	b, _ := os.ReadFile(filepath.Join(e.m.State, "hp", "decoys.json"))
	return string(b)
}

// Every one of the five calls is idempotent against the real host: a second add of a decoy, a second remove, the removal
// of an address that was never added, a start of a container that runs and a stop of one that is stopped all succeed.
func TestHoneypotHostCallsAreIdempotent(t *testing.T) {
	t.Setenv("TZ", "UTC")
	e := startHPHost(t, false)
	a := e.adapter()
	ctx := t.Context()
	ip := netip.MustParseAddr("192.168.10.240")
	for range 2 {
		if err := a.AddDecoyIP(ctx, ip); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	if got := e.decoyLinks(); len(got) != 1 {
		t.Fatalf("links after two adds: %v", got)
	}
	for range 2 {
		if err := a.RemoveDecoyIP(ctx, ip); err != nil {
			t.Fatalf("remove: %v", err)
		}
	}
	if err := a.RemoveDecoyIP(ctx, netip.MustParseAddr("192.168.10.241")); err != nil {
		t.Fatalf("remove of an address that was never a decoy: %v", err)
	}
	if got := e.decoyLinks(); len(got) != 0 {
		t.Fatalf("links after the removals: %v", got)
	}
	for range 2 {
		if err := a.StartContainer(ctx, false); err != nil {
			t.Fatalf("start: %v", err)
		}
	}
	if n := e.systemctl("restart"); n != 1 {
		t.Fatalf("the second start restarted the container again (%d restarts)", n)
	}
	if err := a.StartContainer(ctx, true); err != nil || e.systemctl("restart") != 2 {
		t.Fatalf("a start with restart left the container as it was: %v (%d restarts)", err, e.systemctl("restart"))
	}
	if st, err := a.Status(ctx); err != nil || !st.Available || !st.Running {
		t.Fatalf("status after start: %+v %v", st, err)
	}
	for range 2 {
		if err := a.StopContainer(ctx); err != nil {
			t.Fatalf("stop: %v", err)
		}
	}
	if st, err := a.Status(ctx); err != nil || !st.Available || st.Running || e.unitState(t) != api.UnitInactive {
		t.Fatalf("status after stop: %+v %v (%s)", st, err, e.unitState(t))
	}
	if u, _ := e.m.Unit(api.ServiceHoneypot); strings.Contains(u, "[Install]") {
		t.Fatalf("the stop was not persisted (the unit still has [Install]):\n%s", u)
	}
}

// Enable a trap: the decoy address is on the fake machine and the container runs; switching off stops the container and
// removes the address, and EnsureOff says done only when both happened (a stop that fails keeps the module "turning off").
func TestHoneypotOverTheRealHostEnableAndSwitchOff(t *testing.T) {
	e := startHPHost(t, false)
	s := newStackWith(t, func(d *deps) {
		d.HoneypotDir, d.HostSocket = t.TempDir(), e.h.Socket
		d.DataDir, d.KeyPath = t.TempDir(), filepath.Join(t.TempDir(), "vedette.key")
	})
	s.saveScope(t)
	s.setModule("honeypot", true)
	if code, b := s.do("PUT", "/honeypot/config", "admin", `{"secondary_ip":"192.168.10.240","hostname":"FILESRV-OLD"}`); code != 200 {
		t.Fatalf("%d %v", code, b)
	}
	if code, b := s.do("PATCH", "/honeypot/traps/ssh", "admin", `{"enabled":true}`); code != 200 {
		t.Fatalf("%d %v", code, b)
	}
	if err := s.d.Honeypot.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := e.decoyLinks(); len(got) != 1 || got[0] != "vdhc0a80af0" {
		t.Fatalf("decoy links on the host: %v", got)
	}
	if !strings.Contains(e.decoysFile(), "192.168.10.240") {
		t.Fatalf("the host did not record the decoy: %s", e.decoysFile())
	}
	if e.unitState(t) != api.UnitActive {
		t.Fatalf("the container is %s", e.unitState(t))
	}
	if ok, why := s.d.Honeypot.HostStatus(); !ok || why != "" {
		t.Fatalf("host status %v %q", ok, why)
	}
	_, o := s.do("GET", "/honeypot", "viewer", "")
	if ssh := field(t, o, "traps").([]any)[2].(map[string]any); ssh["state"] != "listening" {
		t.Fatalf("ssh trap: %v", ssh)
	}
	// The files were written, so the first start restarted; an Apply with nothing new asks the host for no write at all;
	// a changed configuration restarts the container once so it reads it.
	if n := e.systemctl("restart"); n != 1 {
		t.Fatalf("%d restarts after the first Apply", n)
	}
	ipCalls := len(e.m.Calls(ops.BinIP))
	if err := s.d.Honeypot.Apply(t.Context()); err != nil || e.systemctl("restart") != 1 {
		t.Fatalf("second Apply: %v (%d restarts)", err, e.systemctl("restart"))
	}
	if n := len(e.m.Calls(ops.BinIP)); n != ipCalls {
		t.Fatalf("the second Apply asked the host to add an address it already holds (%d ip calls, was %d)", n, ipCalls)
	}
	if code, b := s.do("PATCH", "/honeypot/traps/http", "admin", `{"enabled":true}`); code != 200 {
		t.Fatalf("%d %v", code, b)
	}
	if err := s.d.Honeypot.Apply(t.Context()); err != nil || e.systemctl("restart") != 2 {
		t.Fatalf("Apply after a change: %v (%d restarts)", err, e.systemctl("restart"))
	}

	// Switching off: the host refuses to stop the container once, so the teardown is not done.
	s.setModule("honeypot", false)
	e.m.Rule("systemctl", "stop vedette-honeypot", "", 1, "stopfail", "")
	e.m.Mark("stopfail", true)
	teardown := honeypotEnsureOff(*s.d)
	if err := teardown(t.Context()); err == nil {
		t.Fatal("EnsureOff said done while the container is still running")
	}
	if e.unitState(t) != api.UnitActive {
		t.Fatalf("the container is %s", e.unitState(t))
	}
	if ok, why := s.d.Honeypot.HostStatus(); ok || !strings.Contains(why, "turning off") {
		t.Fatalf("host status while the teardown is pending: %v %q", ok, why)
	}
	e.m.Mark("stopfail", false)
	if err := teardown(t.Context()); err != nil {
		t.Fatalf("EnsureOff: %v", err)
	}
	if e.unitState(t) != api.UnitInactive || len(e.decoyLinks()) != 0 || strings.Contains(e.decoysFile(), "192.168.10.240") {
		t.Fatalf("after the switch-off: container %s, links %v, decoys %s", e.unitState(t), e.decoyLinks(), e.decoysFile())
	}
	if err := teardown(t.Context()); err != nil { // a repeat is a no-op
		t.Fatalf("second EnsureOff: %v", err)
	}
}

// A socket that is not there is a machine that is not an appliance; a socket nothing listens on is a host that is down.
// Neither lets a trap say it listens, and neither is an error of the run loop.
func TestHoneypotHostDownOrAbsentNothingListens(t *testing.T) {
	t.Parallel()
	stale := filepath.Join(shortTemp(t), "stale.sock")
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()
	for name, c := range map[string]struct{ sock, reason string }{
		"no socket file":      {filepath.Join(shortTemp(t), "absent.sock"), "not an appliance"},
		"nothing listens":     {stale, "not answering"},
		"no socket (no host)": {"", "not an appliance"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newStackWith(t, func(d *deps) {
				d.HoneypotDir, d.HostSocket = t.TempDir(), c.sock
				d.DataDir, d.KeyPath = t.TempDir(), filepath.Join(t.TempDir(), "vedette.key")
			})
			s.saveScope(t)
			s.setModule("honeypot", true)
			if code, b := s.do("PUT", "/honeypot/config", "admin", `{"secondary_ip":"192.168.10.240","hostname":"FILESRV-OLD"}`); code != 200 {
				t.Fatalf("%d %v", code, b)
			}
			if code, b := s.do("PATCH", "/honeypot/traps/ssh", "admin", `{"enabled":true}`); code != 200 {
				t.Fatalf("%d %v", code, b)
			}
			if err := s.d.Honeypot.Apply(t.Context()); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if ok, why := s.d.Honeypot.HostStatus(); ok || !strings.Contains(why, c.reason) {
				t.Fatalf("host status %v %q, want a reason with %q", ok, why, c.reason)
			}
			_, o := s.do("GET", "/honeypot", "viewer", "")
			if ssh := field(t, o, "traps").([]any)[2].(map[string]any); ssh["state"] != "off" {
				t.Fatalf("a trap claims %v with no host", ssh["state"])
			}
			if c.sock != "" { // a down host is not "done" for the teardown only when something was handed over; nothing was
				s.setModule("honeypot", false)
				if err := honeypotEnsureOff(*s.d)(t.Context()); err != nil {
					t.Fatalf("EnsureOff with nothing handed over: %v", err)
				}
			}
		})
	}
}

// shortTemp is a directory with a short path: a unix socket path may be at most about 100 bytes.
func shortTemp(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "hp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func TestHoneypotHostContainerNotInstalled(t *testing.T) {
	e := startHPHost(t, true)
	st, err := e.adapter().Status(t.Context())
	if err != nil || st.Available || st.Running || !strings.Contains(st.Reason, "not installed") {
		t.Fatalf("status %+v %v", st, err)
	}
	if err := e.adapter().StartContainer(t.Context(), false); err == nil || !strings.Contains(err.Error(), api.CodeUnitUnsafe) {
		t.Fatalf("start: %v", err)
	}
}

// What the host refuses comes back as a plain sentence with the code, not the host's text.
func TestHoneypotHostRefusalsArePlain(t *testing.T) {
	e := startHPHost(t, false)
	err := e.adapter().AddDecoyIP(t.Context(), netip.MustParseAddr("10.9.9.9"))
	if err == nil || !strings.Contains(err.Error(), "outside the network") || !strings.Contains(err.Error(), api.CodeIPNotInMgmtSubnet) {
		t.Fatalf("outside the subnet: %v", err)
	}
	if err := e.adapter().AddDecoyIP(t.Context(), netip.MustParseAddr("192.168.10.1")); err == nil || !strings.Contains(err.Error(), api.CodeIPIsGateway) {
		t.Fatalf("the gateway: %v", err)
	}
	if got := e.decoyLinks(); len(got) != 0 {
		t.Fatalf("a refused address left links: %v", got)
	}
}

// busyAPI makes the host busy (409 busy with a run id, then rate_limited) for the first calls of Run.
type busyAPI struct {
	hostAPI
	mu    sync.Mutex
	busy  int
	rate  int
	ids   []string
	calls int
}

func (b *busyAPI) Run(ctx context.Context, command string, args any, requestID, actor string) (api.Run, error) {
	b.mu.Lock()
	b.calls++
	b.ids = append(b.ids, requestID)
	switch {
	case b.busy != 0:
		if b.busy > 0 {
			b.busy--
		}
		b.mu.Unlock()
		return api.Run{}, &hostclient.Error{Status: http.StatusConflict, Code: api.CodeBusy, Message: "Another write command is already running."}
	case b.rate > 0:
		b.rate--
		b.mu.Unlock()
		return api.Run{}, &hostclient.Error{Status: http.StatusTooManyRequests, Code: api.CodeRateLimited, Message: "slow down", RetryAfterS: 1}
	}
	b.mu.Unlock()
	if actor != "system" {
		return api.Run{}, errors.New("the actor of a module call is not the system")
	}
	return b.hostAPI.Run(ctx, command, args, requestID, actor)
}

// A busy host is waited for under one request id and the call then goes through; a host that stays busy past the bound
// makes the call fail with a plain error and changes nothing, and the next call (the next loop) succeeds.
func TestHoneypotHostBusyIsRetried(t *testing.T) {
	e := startHPHost(t, false)
	ip := netip.MustParseAddr("192.168.10.240")

	b := &busyAPI{hostAPI: e.h.Client, busy: 3}
	a := &honeypotHost{api: b, log: testLogger(), poll: time.Millisecond, busyFor: 5 * time.Second, runFor: 30 * time.Second}
	if err := a.AddDecoyIP(t.Context(), ip); err != nil {
		t.Fatalf("add through a busy host: %v", err)
	}
	if b.calls != 4 || len(slices.Compact(slices.Clone(b.ids))) != 1 {
		t.Fatalf("%d calls with ids %v: want 4 calls, one request id", b.calls, b.ids)
	}
	if got := e.decoyLinks(); len(got) != 1 {
		t.Fatalf("links: %v", got)
	}
	if err := a.RemoveDecoyIP(t.Context(), ip); err != nil {
		t.Fatal(err)
	}

	b = &busyAPI{hostAPI: e.h.Client, busy: -1} // busy for good
	a = &honeypotHost{api: b, log: testLogger(), poll: time.Millisecond, busyFor: 30 * time.Millisecond, runFor: 30 * time.Second}
	start := time.Now()
	err := a.AddDecoyIP(t.Context(), ip)
	if !errors.Is(err, errHostBusy) || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("a host that stays busy: %v", err)
	}
	if time.Since(start) > 2*time.Second || len(e.decoyLinks()) != 0 {
		t.Fatalf("it took %v, links %v", time.Since(start), e.decoyLinks())
	}
	b.mu.Lock()
	b.busy = 0
	b.mu.Unlock()
	if err := a.AddDecoyIP(t.Context(), ip); err != nil || len(e.decoyLinks()) != 1 {
		t.Fatalf("the next call: %v, links %v", err, e.decoyLinks())
	}

	// A host that rate-limits (10 writes a minute) is waited for its Retry-After, inside the same bound.
	b = &busyAPI{hostAPI: e.h.Client, rate: 1}
	a = &honeypotHost{api: b, log: testLogger(), poll: time.Millisecond, busyFor: 10 * time.Second, runFor: 30 * time.Second}
	if err := a.RemoveDecoyIP(t.Context(), ip); err != nil || b.calls != 2 || len(e.decoyLinks()) != 0 {
		t.Fatalf("rate limited: %v after %d calls, links %v", err, b.calls, e.decoyLinks())
	}
}

// A run that does not end within runFor gives up with a plain error (the host goes on; the next call finds it busy and
// waits for it), and a cancelled context is the caller's error, not a refusal.
func TestHoneypotHostSlowRunAndCancel(t *testing.T) {
	e := startHPHost(t, false)
	a := &honeypotHost{api: e.h.Client, log: testLogger(), poll: time.Millisecond, busyFor: time.Second, runFor: time.Nanosecond}
	if err := a.AddDecoyIP(t.Context(), netip.MustParseAddr("192.168.10.240")); err != nil && !errors.Is(err, errHostTooLong) {
		t.Fatalf("slow run: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := e.adapter().StartContainer(ctx, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}

func testLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
