package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
	hostserver "github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
	"github.com/knt048/vedette/modules/honeypot"
)

// The honeypot over the real vedette-host (D-161, WP-30 slice 8a): the real host server and the real client on a unix
// socket, a fake machine under them (opstest), the module and the adapter as cmd/vedette wires them. Nothing here runs
// a container or touches a network card.

// hpProber says nothing else answers on the LAN, after delay (the real ARP probe takes about 4 s).
type hpProber struct{ delay time.Duration }

func (p hpProber) Probe(ctx context.Context, _ string, _ netip.Addr) (ops.ProbeResult, error) {
	select {
	case <-time.After(p.delay):
	case <-ctx.Done():
	}
	return ops.ProbeResult{}, nil
}
func (hpProber) GatewayCheck(context.Context, string, netip.Addr, netip.Addr) error { return nil }

// hpHost is a host on a box 192.168.10.250/24 behind 192.168.10.1, with the honeypot unit installed (unless noUnit).
type hpHost struct {
	m *opstest.Machine
	h *servertest.Harness
}

func startHPHost(t *testing.T, noUnit bool) *hpHost { return startHPHostWith(t, noUnit, false, 0) }

// startHPHostWith can give the host its real limits (60 requests and 10 writes a minute for all of core, on a clock that
// never advances, so nothing is ever forgiven) and a slow ARP probe.
func startHPHostWith(t *testing.T, noUnit, realLimits bool, probeDelay time.Duration) *hpHost {
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
		d.Probe = hpProber{delay: probeDelay}
		d.NetPoll, d.NetWait, d.NetRetryGap = time.Millisecond, 30*time.Millisecond, time.Millisecond
	})
	h := servertest.Start(t, o.Commands(), func(op *hostserver.Options) {
		op.StateDir, op.Readers, op.Now, op.WriteGate, op.Resume = m.State, o.Readers(), clock.Now, o.WriteGate, o.Resume
		if realLimits {
			op.RequestsPerMinute, op.WritesPerMinute = 60, 10
		}
	})
	o.Start(context.Background(), h.Server)
	t.Cleanup(o.Close)
	return &hpHost{m: m, h: h}
}

// adapter is the real adapter on this host's socket.
func (e *hpHost) adapter() *honeypotHost {
	return &honeypotHost{api: e.h.Client, log: testLogger(), poll: time.Second, runFor: 30 * time.Second}
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

// waitIdle waits until no write command holds the host's write lock: the runs core started and then stopped following
// (their answers were lost) have ended at the host. A run ends and frees the lock in one step (host/server finish), so
// the next write after this is never refused busy because of them. The bound only catches a host that hangs.
func (e *hpHost) waitIdle(t *testing.T) {
	t.Helper()
	eventually(t, "the host's write lock is free", func() bool { return !e.h.Server.WriteActive() })
}

func (e *hpHost) decoysFile() string {
	b, _ := os.ReadFile(filepath.Join(e.m.State, "hp", "decoys.json"))
	return string(b)
}

// Every one of the five calls is idempotent against the real host: a second add of a decoy, a second remove, the removal
// of an address that was never added, a start of a container that runs and a stop of one that is stopped all succeed.
func TestHoneypotHostCallsAreIdempotent(t *testing.T) {
	t.Parallel()
	e := startHPHost(t, false)
	a := e.adapter()
	ctx := t.Context()
	ip := netip.MustParseAddr("192.168.10.240")
	for range 2 {
		if err := a.AddDecoyIP(ctx, ip, honeypot.DecoySpec{}); err != nil {
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
	t.Parallel()
	e := startHPHost(t, false)
	s := newStackWith(t, func(d *deps) {
		d.HoneypotDir, d.HostSocket = t.TempDir(), e.h.Socket
		d.DataDir, d.KeyPath = t.TempDir(), filepath.Join(t.TempDir(), "vedette.key")
	})
	s.saveScope(t)
	s.setModule("honeypot", true)
	tip := s.addTrapIP(t, `{"name":"FILESRV-OLD","ip":"192.168.10.240","preset":"custom","vendor":null,"services":["ssh"]}`)
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
	// The files were written, so the first start restarted; an Apply with nothing new asks the host to add no address and to start nothing;
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
	if code, b := s.do("PUT", "/honeypot/trap-ips/"+tip, "admin", `{"name":"FILESRV-OLD","ip":"192.168.10.240","preset":"custom","vendor":null,"services":["ssh","http"]}`); code != 200 {
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
			s.addTrapIP(t, `{"name":"FILESRV-OLD","ip":"192.168.10.240","preset":"custom","vendor":null,"services":["ssh"]}`)
			if err := s.d.Honeypot.Apply(t.Context()); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if ok, why := s.d.Honeypot.HostStatus(); ok || !strings.Contains(why, c.reason) {
				t.Fatalf("host status %v %q, want a reason with %q", ok, why, c.reason)
			}
			_, o := s.do("GET", "/honeypot", "viewer", "")
			if ssh := field(t, o, "traps").([]any)[2].(map[string]any); ssh["state"] != "failed" {
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
	t.Parallel()
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
	t.Parallel()
	e := startHPHost(t, false)
	err := e.adapter().AddDecoyIP(t.Context(), netip.MustParseAddr("10.9.9.9"), honeypot.DecoySpec{})
	if err == nil || !strings.Contains(err.Error(), "outside the network") || !strings.Contains(err.Error(), api.CodeIPNotInMgmtSubnet) {
		t.Fatalf("outside the subnet: %v", err)
	}
	if err := e.adapter().AddDecoyIP(t.Context(), netip.MustParseAddr("192.168.10.1"), honeypot.DecoySpec{}); err == nil || !strings.Contains(err.Error(), api.CodeIPIsGateway) || errors.Is(err, honeypot.ErrHostFailed) {
		t.Fatalf("the gateway: %v", err)
	}
	// The host failing to build the decoy is a refusal (it holds nothing) but not about the address (#475).
	e.m.Rule(ops.BinIP, "link add link", "", 2, "", "")
	if err := e.adapter().AddDecoyIP(t.Context(), netip.MustParseAddr("192.168.10.240"), honeypot.DecoySpec{}); !errors.Is(err, honeypot.ErrRefused) || !errors.Is(err, honeypot.ErrHostFailed) || !strings.Contains(err.Error(), api.CodeDecoyFailed) {
		t.Fatalf("a failed build: %v", err)
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

// A busy or rate-limiting host is not waited for and not spun on: one Run call, errHostBusy at once, no refusal, no
// change; the next call (the next Apply) goes through.
func TestHoneypotHostBusyIsNotSpunOn(t *testing.T) {
	t.Parallel()
	e := startHPHost(t, false)
	ip := netip.MustParseAddr("192.168.10.240")
	for name, mk := range map[string]func() *busyAPI{
		"busy":         func() *busyAPI { return &busyAPI{hostAPI: e.h.Client, busy: 1} },
		"rate limited": func() *busyAPI { return &busyAPI{hostAPI: e.h.Client, rate: 1} },
	} {
		b := mk()
		a := &honeypotHost{api: b, log: testLogger(), poll: time.Second, runFor: 30 * time.Second}
		start := time.Now()
		err := a.AddDecoyIP(t.Context(), ip, honeypot.DecoySpec{})
		if !errors.Is(err, errHostBusy) || errors.Is(err, honeypot.ErrRefused) || b.calls != 1 || time.Since(start) > time.Second || len(e.decoyLinks()) != 0 {
			t.Fatalf("%s: %v after %d calls in %v, links %v", name, err, b.calls, time.Since(start), e.decoyLinks())
		}
		if err := a.AddDecoyIP(t.Context(), ip, honeypot.DecoySpec{}); err != nil || len(e.decoyLinks()) != 1 {
			t.Fatalf("%s: the next call: %v, links %v", name, err, e.decoyLinks())
		}
		if err := a.RemoveDecoyIP(t.Context(), ip); err != nil || len(e.decoyLinks()) != 0 {
			t.Fatalf("%s: remove: %v", name, err)
		}
	}
}

// With the host's real limits (60 requests and 10 writes a minute for all of core, the clock never advances) and a slow
// ARP probe, adding several addresses, starting the container and the steady state of many Applies stay inside them:
// a run is followed over its event stream, not polled, and addresses and container state are read once.
func TestHoneypotHostStaysInsideTheHostLimits(t *testing.T) {
	t.Parallel()
	e := startHPHostWith(t, false, true, time.Second)
	a := e.adapter()
	ctx := t.Context()
	for i := range 4 {
		if err := a.AddDecoyIP(ctx, netip.MustParseAddr(fmt.Sprintf("192.168.10.%d", 240+i)), honeypot.DecoySpec{}); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	if err := a.StartContainer(ctx, true); err != nil {
		t.Fatalf("start: %v", err)
	}
	for i := range 12 { // twelve Applies in steady state: a status read, every address already held, the container running
		if st, err := a.Status(ctx); err != nil || !st.Running {
			t.Fatalf("apply %d status: %+v %v", i, st, err)
		}
		for j := range 4 {
			if err := a.AddDecoyIP(ctx, netip.MustParseAddr(fmt.Sprintf("192.168.10.%d", 240+j)), honeypot.DecoySpec{}); err != nil {
				t.Fatalf("apply %d add: %v", i, err)
			}
		}
		if err := a.StartContainer(ctx, false); err != nil {
			t.Fatalf("apply %d start: %v", i, err)
		}
	}
	if got := len(e.decoyLinks()); got != 4 {
		t.Fatalf("%d links", got)
	}
	// What is left of the minute is still there for the rest of core (an OS check, net.confirm).
	for range 10 {
		if _, err := e.h.Client.StateContainers(ctx); err != nil {
			t.Fatalf("the adapter used up the host's requests: %v", err)
		}
	}
}

// A run that does not end within runFor is an unknown outcome, not a refusal; a cancelled context is the caller's error.
func TestHoneypotHostSlowRunAndCancel(t *testing.T) {
	t.Parallel()
	e := startHPHostWith(t, false, false, 300*time.Millisecond) // the add is still running when the answer comes
	a := &honeypotHost{api: e.h.Client, log: testLogger(), poll: time.Millisecond, runFor: time.Nanosecond}
	err := a.AddDecoyIP(t.Context(), netip.MustParseAddr("192.168.10.240"), honeypot.DecoySpec{})
	if !errors.Is(err, errHostTooLong) || errors.Is(err, honeypot.ErrRefused) {
		t.Fatalf("slow run: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := e.adapter().StartContainer(ctx, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}

func testLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// breakingProxy forwards to the host's socket; while broken is set every read of a run (its stored state, its events)
// answers 500, as a host that dies or a rate limit that bites after it accepted a command.
func breakingProxy(t *testing.T, target string, broken *atomic.Bool) string {
	t.Helper()
	sock := filepath.Join(shortTemp(t), "p.sock")
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL = &url.URL{Scheme: "http", Host: "host", Path: r.In.URL.Path, RawQuery: r.In.URL.RawQuery}
		},
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", target)
		}},
		FlushInterval: -1,
	}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if broken.Load() && strings.HasPrefix(r.URL.Path, "/v1/runs/") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		rp.ServeHTTP(w, r)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// H2 (SYS-5): the host accepted the add, then the follow-up reads failed: the outcome is unknown, not a refusal. The module
// keeps the address on record and shows no conflict, so switching off still removes it and no decoy is left on the host.
func TestHoneypotUnknownOutcomeIsNotForgottenByTheTeardown(t *testing.T) {
	t.Parallel()
	e := startHPHost(t, false)
	var broken atomic.Bool
	s := newStackWith(t, func(d *deps) {
		d.HoneypotDir, d.HostSocket = t.TempDir(), breakingProxy(t, e.h.Socket, &broken)
		d.DataDir, d.KeyPath = t.TempDir(), filepath.Join(t.TempDir(), "vedette.key")
	})
	s.saveScope(t)
	s.setModule("honeypot", true)
	s.addTrapIP(t, `{"name":"FILESRV-OLD","ip":"192.168.10.240","preset":"custom","vendor":null,"services":["ssh"]}`)
	broken.Store(true)
	if err := s.d.Honeypot.Apply(t.Context()); err == nil || errors.Is(err, honeypot.ErrRefused) {
		t.Fatalf("Apply with a host whose answers are lost: %v", err)
	}
	// The add goes on at the host after core stopped following it: wait for it to end (its link appears before it ends).
	e.waitIdle(t)
	if got := e.decoyLinks(); len(got) != 1 {
		t.Fatalf("the host did take the address, links: %v", got)
	}
	_, o := s.do("GET", "/honeypot", "viewer", "")
	if ssh := field(t, o, "traps").([]any)[2].(map[string]any); ssh["state"] == "conflict" || ssh["state"] == "listening" {
		t.Fatalf("an unknown outcome shows as %v", ssh["state"])
	}
	s.setModule("honeypot", false)
	teardown := honeypotEnsureOff(*s.d)
	if err := teardown(t.Context()); err == nil {
		t.Fatal("the teardown said done while it could not read what the host did")
	}
	// The failed teardown's own stop or remove may still run at the host, as the add did: once it ended, nothing holds the
	// write lock and the next teardown is not refused busy.
	e.waitIdle(t)
	broken.Store(false)
	if err := teardown(t.Context()); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if got := e.decoyLinks(); len(got) != 0 || strings.Contains(e.decoysFile(), "192.168.10.240") {
		t.Fatalf("a decoy is left on the host after the teardown: links %v, %s", got, e.decoysFile())
	}
}

// cutOffAPI lets the real host run every command, then reports each run as cut off (failed host_restarted): the host did
// the work, its answer was lost in a restart.
type cutOffAPI struct{ hostAPI }

func (c cutOffAPI) GetRun(ctx context.Context, runID string) (api.Run, error) {
	run, err := c.hostAPI.GetRun(ctx, runID)
	if err != nil {
		return run, err
	}
	run.Status, run.Error = api.StatusFailed, &api.RunError{Code: api.CodeHostRestarted, Message: "vedette-host restarted during this run"}
	return run, nil
}

// A run cut off by a host restart (or a timeout, a failure of the host itself) may have done its work: it is an unknown
// outcome, never a refusal, so the module keeps the address on record and the teardown removes the decoy the host made.
func TestHoneypotHostCutOffRunIsUnknown(t *testing.T) {
	t.Parallel()
	e := startHPHost(t, false)
	ip := netip.MustParseAddr("192.168.10.241")
	a := &honeypotHost{api: cutOffAPI{e.h.Client}, log: testLogger(), poll: time.Second, runFor: 30 * time.Second}
	err := a.AddDecoyIP(t.Context(), ip, honeypot.DecoySpec{})
	if err == nil || errors.Is(err, honeypot.ErrRefused) || errors.Is(err, errHostBusy) {
		t.Fatalf("cut-off add: %v, want an unknown outcome", err)
	}
	if got := e.decoyLinks(); len(got) != 1 {
		t.Fatalf("the host did the add: links %v", got)
	}
	if err := e.adapter().RemoveDecoyIP(t.Context(), ip); err != nil || len(e.decoyLinks()) != 0 {
		t.Fatalf("remove: %v, links %v", err, e.decoyLinks())
	}
}

// A module on with no trap (or every address refused) asks for the stop at every Apply: after the first persisted stop,
// with the container seen not running, the next stops cost no write; a start in between makes the next stop real again.
func TestHoneypotHostStopIsNotRepeated(t *testing.T) {
	t.Parallel()
	e := startHPHostWith(t, false, true, 0)
	a := e.adapter()
	ctx := t.Context()
	if err := a.StopContainer(ctx); err != nil {
		t.Fatal(err)
	}
	stops := e.systemctl("stop")
	for i := range 20 { // twenty Applies with no trap: a status read and a stop each, inside 60 requests and 10 writes
		if st, err := a.Status(ctx); err != nil || st.Running {
			t.Fatalf("apply %d status: %+v %v", i, st, err)
		}
		if err := a.StopContainer(ctx); err != nil {
			t.Fatalf("apply %d stop: %v", i, err)
		}
	}
	if got := e.systemctl("stop"); got != stops {
		t.Fatalf("systemctl stop ran %d more times in steady state", got-stops)
	}
	if err := a.StartContainer(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Status(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.StopContainer(ctx); err != nil || e.systemctl("stop") != stops+1 || e.unitState(t) == api.UnitActive {
		t.Fatalf("stop after a start: %v, stops %d, unit %s", err, e.systemctl("stop")-stops, e.unitState(t))
	}
}

// oldHost is a vedette-host from before D-466: its command list has no decoy_ip.set_ports.
type oldHost struct{ hostAPI }

func (o oldHost) Info(ctx context.Context) (api.Info, error) {
	info, err := o.hostAPI.Info(ctx)
	info.Commands = slices.DeleteFunc(info.Commands, func(c string) bool { return c == api.CmdDecoySetPorts })
	return info, err
}

func (e *hpHost) heldDecoy(t *testing.T, ip string) (api.NetDecoy, bool) {
	t.Helper()
	ns, err := e.h.Client.StateNet(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ns.Decoys {
		if d.IP == ip {
			return d, true
		}
	}
	return api.NetDecoy{}, false
}

// D-466, W1-14: the adapter hands the host each Trap IP's own ports and its vendor's MAC prefix, and later changes only what
// differs: new ports go by decoy_ip.set_ports (the link stays), a new prefix by remove + add, the same spec costs no write.
func TestHoneypotHostSendsEachTrapIPItsPortsAndPrefix(t *testing.T) {
	t.Parallel()
	e := startHPHost(t, false)
	a := e.adapter()
	ctx := t.Context()
	ip := netip.MustParseAddr("192.168.10.240")
	fileServer := honeypot.DecoySpec{OUI: "f8bc12", Ports: []honeypot.Port{{Proto: "tcp", Port: 3389}, {Proto: "tcp", Port: 445}}}
	if !a.KeepsPorts(ctx) {
		t.Fatal("the host lists decoy_ip.set_ports, but the adapter says it cannot keep ports")
	}
	if err := a.AddDecoyIP(ctx, ip, fileServer); err != nil {
		t.Fatal(err)
	}
	d, ok := e.heldDecoy(t, ip.String())
	if !ok || d.Ports == nil || fmt.Sprint(*d.Ports) != "[{tcp 445} {tcp 3389}]" || !strings.HasPrefix(d.MAC, "f8:bc:12:") {
		t.Fatalf("the host holds %+v (ports %v)", d, d.Ports)
	}
	mac := d.MAC
	writes := len(e.m.Calls(ops.BinIP))
	if err := a.AddDecoyIP(ctx, ip, fileServer); err != nil || len(e.m.Calls(ops.BinIP)) != writes {
		t.Fatalf("the same spec again: %v (%d ip calls, was %d)", err, len(e.m.Calls(ops.BinIP)), writes)
	}
	ssh := honeypot.DecoySpec{OUI: "f8bc12", Ports: []honeypot.Port{{Proto: "tcp", Port: 22}}}
	a.forgetDecoys()
	if err := a.AddDecoyIP(ctx, ip, ssh); err != nil {
		t.Fatal(err)
	}
	if d, _ := e.heldDecoy(t, ip.String()); d.Ports == nil || fmt.Sprint(*d.Ports) != "[{tcp 22}]" || d.MAC != mac {
		t.Fatalf("after new ports the host holds %+v (ports %v), MAC was %s", d, d.Ports, mac)
	}
	a.forgetDecoys()
	if err := a.AddDecoyIP(ctx, ip, honeypot.DecoySpec{Ports: ssh.Ports}); err != nil {
		t.Fatal(err)
	}
	d, _ = e.heldDecoy(t, ip.String())
	if b, err := strconv.ParseUint(d.MAC[:2], 16, 8); err != nil || b&0x02 == 0 || d.Ports == nil || len(*d.Ports) != 1 {
		t.Fatalf("no vendor: the host holds %+v, not a locally administered MAC with the ports", d)
	}
	if gw := a.Gateway(ctx); gw != netip.MustParseAddr("192.168.10.1") {
		t.Fatalf("gateway %v", gw)
	}
	links := a.DecoyLinks(ctx)
	if l := links[ip]; l.Link != "vdhc0a80af0" || l.MAC != d.MAC {
		t.Fatalf("links %+v", links)
	}
}

// An older vedette-host (no decoy_ip.set_ports in /v1/info) never gets ports, which it would refuse: its addresses answer
// every service, and the module is told so (KeepsPorts false).
func TestHoneypotHostSendsNoPortsToAnOlderHost(t *testing.T) {
	t.Parallel()
	e := startHPHost(t, false)
	a := &honeypotHost{api: oldHost{e.h.Client}, log: testLogger(), poll: time.Second, runFor: 30 * time.Second}
	ip := netip.MustParseAddr("192.168.10.241")
	if a.KeepsPorts(t.Context()) {
		t.Fatal("an older host was taken to keep ports")
	}
	if err := a.AddDecoyIP(t.Context(), ip, honeypot.DecoySpec{Ports: []honeypot.Port{{Proto: "tcp", Port: 445}}}); err != nil {
		t.Fatal(err)
	}
	if d, ok := e.heldDecoy(t, ip.String()); !ok || d.Ports != nil {
		t.Fatalf("an older host was sent ports: %+v", d)
	}
}

// noInfoHost is a host whose GET /v1/info fails (not answering it yet).
type noInfoHost struct{ hostAPI }

func (noInfoHost) Info(context.Context) (api.Info, error) {
	return api.Info{}, errors.New("info: no answer")
}

// B2 review: while the host's command list was never read, a Trap IP is not added without its ports (it would answer
// every running service until the next Apply): the outcome is unknown, not a refusal, and nothing is asked of the host.
func TestHoneypotHostAddsNothingWhileItsCommandListIsUnknown(t *testing.T) {
	t.Parallel()
	e := startHPHost(t, false)
	a := &honeypotHost{api: noInfoHost{e.h.Client}, log: testLogger(), poll: time.Second, runFor: 30 * time.Second}
	err := a.AddDecoyIP(t.Context(), netip.MustParseAddr("192.168.10.242"), honeypot.DecoySpec{Ports: []honeypot.Port{{Proto: "tcp", Port: 22}}})
	if err == nil || errors.Is(err, honeypot.ErrRefused) || !errors.Is(err, errNoCommandList) {
		t.Fatalf("add with no command list: %v", err)
	}
	if links := e.decoyLinks(); len(links) != 0 {
		t.Fatalf("the host was asked to add the address: %v", links)
	}
}

// B2 lab (Ubuntu 26.04): the passive sensor sees each Trap IP answer ARP with its own macvlan MAC. Over the real host, those frames
// never become devices, a frame of a Trap IP the host does not list yet is no device either, and every Trap IP listens (no
// conflict with itself). A foreign MAC on a held Trap IP address is still a device.
func TestHoneypotTrapIPFramesAreNeverDevices(t *testing.T) {
	t.Parallel()
	e := startHPHost(t, false)
	s := newStackWith(t, func(d *deps) {
		d.HoneypotDir, d.HostSocket = t.TempDir(), e.h.Socket
		d.DataDir, d.KeyPath = t.TempDir(), filepath.Join(t.TempDir(), "vedette.key")
	})
	s.saveScope(t)
	s.setModule("honeypot", true)
	s.addTrapIP(t, `{"name":"FILESRV-OLD","ip":"192.168.10.240","preset":"file_server","vendor":"dell","services":["smb","rdp"]}`)
	s.addTrapIP(t, `{"name":"NAS-ARCHIVE","ip":"192.168.10.241","preset":"nas","vendor":"synology","services":["http","smb"]}`)
	s.addTrapIP(t, `{"name":"BUILD-SRV-02","ip":"192.168.10.242","preset":"linux","vendor":"vmware","services":["ssh"]}`)
	if err := s.d.Honeypot.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	ns, err := e.h.Client.StateNet(t.Context())
	if err != nil || len(ns.Decoys) != 3 {
		t.Fatalf("state/net decoys %+v %v", ns.Decoys, err)
	}
	devices := func() int {
		l, err := s.d.Inventory.AllDevices(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return len(l)
	}
	before := devices()
	frame := func(ip, mac string) {
		t.Helper()
		obs := []observe.Observation{{AssetHint: observe.AssetHint{IP: netip.MustParseAddr(ip), MAC: mac}, Field: observe.MAC, Value: mac, Source: observe.Passive, Confidence: 0.9}}
		if err := s.d.Inventory.Record(t.Context(), obs); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range ns.Decoys {
		frame(d.IP, d.MAC)
	}
	// A fourth Trap IP the honeypot handed over (on the record) but the host does not list yet: its link coming up.
	if err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE hp_config SET value = '["192.168.10.240","192.168.10.241","192.168.10.242","192.168.10.243"]' WHERE key = 'applied'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	frame("192.168.10.243", "00:50:56:12:34:56")
	if n := devices(); n != before {
		t.Fatalf("the Trap IPs' own frames made %d device(s)", n-before)
	}
	if err := s.d.Honeypot.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, b := s.do("GET", "/honeypot/trap-ips", "viewer", "")
	for _, it := range field(t, b, "items").([]any) {
		if m := it.(map[string]any); m["state"] != "listening" || m["device_id"] != nil {
			t.Fatalf("a Trap IP is not listening: %v", m)
		}
	}
	frame("192.168.10.240", "aa:bb:cc:00:02:40") // another machine took a held Trap IP address
	if n := devices(); n != before+1 {
		t.Fatalf("a foreign machine on a Trap IP address: %d new devices", n-before)
	}
}
