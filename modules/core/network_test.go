package core_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
	hostserver "github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
	"github.com/knt048/vedette/modules/core"
)

// The Box network routes (S-CORE-8, D-56, D-99, D-100, D-106) through the real stack (server.New, sessions,
// SQLite) and a real host/client talking to an in-process vedette-host that runs the real net.* commands of
// host/ops on the fake machine of opstest: a temporary root, fake netplan and chronyc, a fake ARP prober and a
// fake network whose addresses follow whichever netplan file is the effective one. Timers are held back and fired
// by the test. Nothing touches the real system.

type netAPI struct {
	server.Fallback
	*core.ModuleHandlers
	*core.APIHandlers
	*core.NetworkHandlers
}

type nwTimer struct {
	d       time.Duration
	f       func()
	stopped bool
}

type nwTimers struct {
	mu sync.Mutex
	ts []*nwTimer
}

func (t *nwTimers) after(d time.Duration, f func()) func() bool {
	tm := &nwTimer{d: d, f: f}
	t.mu.Lock()
	t.ts = append(t.ts, tm)
	t.mu.Unlock()
	return func() bool {
		t.mu.Lock()
		defer t.mu.Unlock()
		was := !tm.stopped
		tm.stopped = true
		return was
	}
}

// fireLast runs the newest timer that is still live, except the hourly sweep: the revert timer of the change that waits.
func (t *nwTimers) fireLast() {
	t.mu.Lock()
	var f func()
	for _, tm := range t.ts {
		if !tm.stopped && tm.d != time.Hour {
			f = tm.f
		}
	}
	t.mu.Unlock()
	f()
}

type nwProber struct {
	mu       sync.Mutex
	conflict bool
	gwErr    error
	probed   []string
}

func (p *nwProber) Probe(_ context.Context, iface string, ip netip.Addr) (ops.ProbeResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probed = append(p.probed, iface+" "+ip.String())
	return ops.ProbeResult{Conflict: p.conflict, MAC: "aa:bb:cc:dd:ee:ff"}, nil
}

func (p *nwProber) GatewayCheck(context.Context, string, netip.Addr, netip.Addr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gwErr
}

func (p *nwProber) set(f func(*nwProber)) { p.mu.Lock(); f(p); p.mu.Unlock() }
func (p *nwProber) probes() int           { p.mu.Lock(); defer p.mu.Unlock(); return len(p.probed) }

// nwBox is the fake network: eth0 holds 192.168.1.50/24 (the address the installer gave) plus every address of
// the effective netplan file (DHCP: 192.168.1.77/24); eth1 is a second card; eth2 is not a card at all (no
// hardware parent) and only has an IPv6 link-local address.
type nwBox struct {
	m        *opstest.Machine
	spanAddr atomic.Bool // eth1 holds an address
}

var nwAddrRE = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+/\d+`)

func (b *nwBox) interfaces() ([]ops.HostIface, error) {
	text, err := b.m.ReadRoot("run/netplan/90-vedette.yaml")
	if err != nil {
		text, _ = b.m.ReadRoot("etc/netplan/90-vedette.yaml")
	}
	addrs := []netip.Prefix{netip.MustParsePrefix("192.168.1.50/24")}
	for _, a := range nwAddrRE.FindAllString(text, -1) {
		addrs = append(addrs, netip.MustParsePrefix(a))
	}
	if strings.Contains(text, "dhcp4: true") {
		addrs = append(addrs, netip.MustParsePrefix("192.168.1.77/24"))
	}
	var span []netip.Prefix
	if b.spanAddr.Load() {
		span = []netip.Prefix{netip.MustParsePrefix("10.9.9.9/24")}
	}
	return []ops.HostIface{
		{Name: "lo", Loopback: true, Addrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
		{Name: "eth0", MAC: "02:00:00:00:00:01", Addrs: addrs},
		{Name: "eth1", MAC: "02:00:00:00:00:02", Addrs: span},
		{Name: "eth2", MAC: "02:00:00:00:00:03", Addrs: []netip.Prefix{netip.MustParsePrefix("fe80::1/64")}},
		{Name: "veth1234", MAC: "02:00:00:00:00:04", Addrs: []netip.Prefix{netip.MustParsePrefix("10.88.0.1/16")}},
	}, nil
}

// nwCard lays out one sysfs card under the machine's root the way the kernel does.
func nwCard(t *testing.T, root, name string, physical bool) {
	t.Helper()
	dev := filepath.Join(root, "sys/devices/pci0000:00/net", name)
	for _, d := range []string{filepath.Join(dev, "statistics"), filepath.Join(root, "sys/class/net")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range map[string]string{"statistics/rx_packets": "0", "statistics/tx_packets": "0", "operstate": "up", "speed": "1000", "flags": "0x1003"} {
		if err := os.WriteFile(filepath.Join(dev, k), []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if physical {
		if err := os.Symlink("../..", filepath.Join(dev, "device")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../../devices/pci0000:00/net/"+name, filepath.Join(root, "sys/class/net", name)); err != nil {
		t.Fatal(err)
	}
}

// nwSensor is the passive sensor of the tests.
type nwSensor struct {
	mu      sync.Mutex
	measure core.SpanMeasure
	err     error
	setErr  error // SetSpanPort fails
	ports   []string
}

func (s *nwSensor) SpanStats(context.Context) (core.SpanMeasure, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.measure, s.err
}

func (s *nwSensor) SetSpanPort(_ context.Context, _, iface string, span bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setErr != nil {
		return s.setErr
	}
	s.ports = append(s.ports, fmt.Sprintf("%s/%t", iface, span))
	return nil
}

type netEnv struct {
	*world
	m       *opstest.Machine
	hh      *servertest.Harness
	o       *ops.Ops
	clock   *servertest.Clock
	timers  *nwTimers
	probe   *nwProber
	box     *nwBox
	nh      *core.NetworkHandlers
	sensor  *nwSensor
	changed atomic.Int32
	fault   *faultHost
	opts    netOpts
	afters  []func() // what the handlers asked to run later (the look after the window)
	afterD  []time.Duration
	afterMu sync.Mutex
	taken   atomic.Value // netip.Addr the inventory has
	admin   *client
	oper    *client
	viewer  *client
}

type netOpts struct {
	noHost, noSensor bool
	absentSocket     bool // the host is a client of a socket file that does not exist (a container-only install)
}

// faultHost is the real host with faults a test switches on: the state it reports, the errors it answers, and
// a gate that holds the read of state/net.
type faultHost struct {
	core.NetHost
	stateCalls  atomic.Int32
	hidePending atomic.Bool  // state/net says nothing waits although the run does
	stateErr    atomic.Value // error
	confirmErr  atomic.Value // error
	getRunErr   atomic.Value // error
	gate        chan struct{}
	onState     func() // runs inside the read of state/net
}

type errBox struct{ err error }

func (f *faultHost) StateNet(ctx context.Context) (api.NetState, error) {
	f.stateCalls.Add(1)
	if f.gate != nil {
		<-f.gate
	}
	if f.onState != nil {
		f.onState()
	}
	if e, _ := f.stateErr.Load().(errBox); e.err != nil {
		return api.NetState{}, e.err
	}
	st, err := f.NetHost.StateNet(ctx)
	if f.hidePending.Load() {
		st.Pending = nil
	}
	return st, err
}

func (f *faultHost) NetConfirm(ctx context.Context, runID, requestID, actor string) (api.Run, error) {
	if e, _ := f.confirmErr.Load().(errBox); e.err != nil {
		return api.Run{}, e.err
	}
	return f.NetHost.NetConfirm(ctx, runID, requestID, actor)
}

func (f *faultHost) GetRun(ctx context.Context, id string) (api.Run, error) {
	if e, _ := f.getRunErr.Load().(errBox); e.err != nil {
		return api.Run{}, e.err
	}
	return f.NetHost.GetRun(ctx, id)
}

func newNetEnv(t *testing.T, o netOpts) *netEnv {
	t.Helper()
	e := &netEnv{world: newWorld(t), m: opstest.NewMachine(t), timers: &nwTimers{}, probe: &nwProber{}, sensor: &nwSensor{measure: core.SpanMeasure{Verdict: "ok", PPS: 100, OtherMACs: 3, LastPacket: time.Date(2026, 11, 9, 11, 59, 59, 0, time.UTC)}}}
	e.clock = servertest.NewClock(time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC))
	e.box = &nwBox{m: e.m}
	for _, c := range []struct {
		n string
		p bool
	}{{"eth0", true}, {"eth1", true}, {"eth2", false}} {
		nwCard(t, e.m.Root, c.n, c.p)
	}
	e.m.WriteRoot("proc/net/route", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")
	e.m.RuleText("chronyc", "-N", "^,*,203.0.113.7,2,6,377,12,0.0,0.0,0.0\n^,+,ntp1.example.com,2,6,377,12,0.0,0.0,0.0\n", 0, "", "")
	e.o = e.m.Ops(e.clock.Now, func(_ *ops.Config, d *ops.Deps) {
		d.AfterFunc = e.timers.after
		d.FreeBytes = func(string) (uint64, error) { return 100 << 30, nil }
		d.Interfaces, d.Probe = e.box.interfaces, e.probe
		d.NetPoll, d.NetWait, d.NetRetryGap = time.Millisecond, 30*time.Millisecond, time.Millisecond
	})
	e.hh = servertest.Start(t, e.o.Commands(), func(op *hostserver.Options) {
		op.StateDir, op.Readers, op.Now, op.WriteGate, op.Resume = e.m.State, e.o.Readers(), e.clock.Now, e.o.WriteGate, e.o.Resume
	})
	e.o.Start(context.Background(), e.hh.Server)
	t.Cleanup(e.o.Close)
	e.nh = e.newHandlers(t, o)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("log of the box:\n%s", e.logs.String())
		}
	})
	e.admin, _ = e.signIn("admin@acme.example", "admin")
	e.oper, _ = e.signIn("operator@acme.example", "operator")
	e.viewer, _ = e.signIn("viewer@acme.example", "viewer")
	return e
}

// newHandlers builds the handlers on this world's database and mounts them on the HTTP stack; a second call is a
// restart of core (same database, same host, nothing in memory).
func (e *netEnv) newHandlers(t *testing.T, o netOpts) *core.NetworkHandlers {
	t.Helper()
	cfg := core.NetworkConfig{
		DB: e.env.DB, Auth: e.env.Svc, Audit: e.env.Audit, Log: e.logger(), Clock: e.clock.Now,
		AddressesChanged: func() { e.changed.Add(1) },
		AddressInUse: func(_ context.Context, ip netip.Addr) (bool, error) {
			a, _ := e.taken.Load().(netip.Addr)
			return a == ip, nil
		},
	}
	e.opts = o
	switch {
	case o.noHost:
	case o.absentSocket:
		cfg.Host = hostclient.New(filepath.Join(t.TempDir(), "absent.sock"))
	default:
		e.fault = &faultHost{NetHost: e.hh.NewClient(t)}
		cfg.Host = e.fault
	}
	cfg.AfterFunc = func(d time.Duration, f func()) {
		e.afterMu.Lock()
		e.afters, e.afterD = append(e.afters, f), append(e.afterD, d)
		e.afterMu.Unlock()
	}
	if !o.noSensor {
		cfg.Sensor = e.sensor
	}
	h, err := core.NewNetworkHandlers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	api, err := server.New(server.Config{
		API:  netAPI{Fallback: server.Fallback{Log: e.logger()}, ModuleHandlers: core.NewModuleHandlers(e.env.DB, e.reg), APIHandlers: e.h, NetworkHandlers: h},
		Auth: e.env.Svc.Sessions, Modules: e.reg, Log: e.logger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.api = api
	return h
}

func (w *world) logger() *slog.Logger { return slog.New(slog.NewTextHandler(w.logs, nil)) }

// hostPendingGone asks the host itself (not core, whose page would settle the change and spoil the next step).
func (e *netEnv) hostPendingGone() bool {
	st, err := e.hh.Client.StateNet(e.t.Context())
	return err == nil && st.Pending == nil
}

func (e *netEnv) actions() []string {
	rows, err := e.env.DB.Reader().QueryContext(e.t.Context(), "SELECT action FROM core_audit ORDER BY seq")
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			e.t.Fatal(err)
		}
		if strings.HasPrefix(a, "network.") {
			out = append(out, a)
		}
	}
	return out
}

func nwBody(extra map[string]any) map[string]any {
	b := map[string]any{"mode": "static", "address": "192.168.1.60", "prefix": 24, "gateway": "192.168.1.1", "dns": []any{"1.1.1.1"}}
	for k, v := range extra {
		if v == nil {
			delete(b, k)
		} else {
			b[k] = v
		}
	}
	return b
}

// configured makes the host write its first configuration: a static address through the whole confirm flow.
func (e *netEnv) configured() {
	e.t.Helper()
	wantOK(e.t, e.admin.put("/core/network/management", nwBody(map[string]any{"confirm": true})), 200)
	wantOK(e.t, e.admin.post("/core/network/management/confirm", nil), 200)
}

func spanBody(extra map[string]any) map[string]any {
	b := map[string]any{
		"enabled": true, "interface": "eth1", "extract": map[string]any{"dns": true, "tls_sni": true, "http_host": false, "flows": true},
		"filters": []any{map[string]any{"type": "cidr", "value": "10.0.5.0/24"}}, "cpu_percent": 25, "memory_mb": 512,
	}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func jstr(r reply, path ...string) string { return r.str(path...) }

func jval(r reply, path ...string) any { return getVal(r, path...) }

// ---- the page ----

func TestNetworkPageShowsTheCardsOfTheHostAndNotTheVirtualLinks(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	r := e.viewer.get("/core/network")
	wantOK(t, r, 200)
	ifs := getArr(r, "interfaces")
	if len(ifs) != 3 { // eth0, eth1, eth2; veth1234 is no card
		t.Fatalf("interfaces = %v", ifs)
	}
	first := ifs[0].(map[string]any)
	if first["name"] != "eth0" || first["role"] != "management" || first["link"] != true || first["speed"] != "1 Gb/s" || first["address"] != "192.168.1.50/24" {
		t.Errorf("eth0 = %v", first)
	}
	if e.viewer.get("/core/network").str("default_ntp") != "pool.ntp.org" {
		t.Error("default_ntp")
	}
	if got := jstr(r, "management", "mode"); got != "static" || jstr(r, "management", "address") != "192.168.1.50" || jstr(r, "management", "gateway") != "192.168.1.1" {
		t.Errorf("management of a box the host has not configured: %v", r.JSON["management"])
	}
	if jval(r, "pending") != nil || jstr(r, "ntp", "mode") != "default" || jstr(r, "span_status", "verdict") != "off" {
		t.Errorf("pending, ntp or status: %v", r.JSON)
	}
	if jval(r, "span", "extract", "dns") != true || jval(r, "span", "cpu_percent") != float64(25) {
		t.Errorf("span defaults: %v", r.JSON["span"])
	}
}

// ---- roles ----

func TestNetworkRolesAreEnforced(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	for _, c := range []*client{e.viewer, e.oper, e.admin} {
		wantOK(t, c.get("/core/network"), 200)
		wantOK(t, c.get("/core/network/span/status"), 200)
	}
	writes := []struct {
		m, p string
		b    any
	}{
		{"PUT", "/core/network/interfaces", map[string]any{"roles": map[string]any{"eth0": "management", "eth1": "unused", "eth2": "unused"}}},
		{"PUT", "/core/network/management", nwBody(nil)},
		{"POST", "/core/network/management/confirm", nil},
		{"POST", "/core/network/management/revert", nil},
		{"PUT", "/core/network/span", spanBody(nil)},
		{"PUT", "/core/network/ntp", map[string]any{"mode": "default", "servers": []any{}}},
	}
	for _, w := range writes {
		for _, c := range []*client{e.viewer, e.oper} {
			if r := c.request(w.m, w.p, w.b); r.Code != 403 {
				t.Errorf("%s %s as a lower role = %d", w.m, w.p, r.Code)
			}
		}
	}
	if len(e.actions()) != 0 {
		t.Errorf("refused calls left audit rows: %v", e.actions())
	}
}

// ---- management ----

func TestNetworkManagementChangeWaitsForConfirmThenIsKept(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	// Without confirm: the question, nothing sent to the host.
	r := e.admin.put("/core/network/management", nwBody(nil))
	wantStatus(t, r, 409, "confirm_required")
	if ip := jstr(r, "error", "new_ip"); ip != "192.168.1.60" {
		t.Errorf("new_ip = %q", ip)
	}
	if !strings.Contains(jstr(r, "error", "message"), "Open https://192.168.1.60:8443 within 5 minutes and confirm, or the box returns to the old settings. You will need to sign in again at the new address.") {
		t.Errorf("message = %q", jstr(r, "error", "message"))
	}
	if e.probe.probes() != 0 || len(e.actions()) != 0 {
		t.Errorf("a question must change nothing: probes %d, audit %v", e.probe.probes(), e.actions())
	}
	// With confirm: applied, waiting, with the time and the address it replaces.
	r = e.admin.put("/core/network/management", nwBody(map[string]any{"confirm": true}))
	wantOK(t, r, 200)
	if jstr(r, "management", "address") != "192.168.1.60" || jstr(r, "pending", "previous_address") != "192.168.1.50" {
		t.Fatalf("after apply: %v", r.JSON)
	}
	if jval(r, "pending", "reboot_at") != nil {
		t.Errorf("reboot_at = %v", jval(r, "pending", "reboot_at"))
	}
	exp, err := time.Parse(time.RFC3339, jstr(r, "pending", "expires_at"))
	if err != nil || exp.Sub(e.clock.Now()) < 290*time.Second || exp.Sub(e.clock.Now()) > 310*time.Second {
		t.Errorf("expires_at = %v (%v)", jstr(r, "pending", "expires_at"), err)
	}
	if e.changed.Load() == 0 {
		t.Error("the box's addresses changed: the cache of them must be dropped")
	}
	if e.probe.probes() != 1 {
		t.Errorf("the new address must be probed once, got %d", e.probe.probes())
	}
	// Another change, a cancel from nobody else, while it waits: refused.
	wantStatus(t, e.admin.put("/core/network/management", nwBody(map[string]any{"address": "192.168.1.61", "confirm": true})), 409, "change_pending")
	wantStatus(t, e.admin.put("/core/network/ntp", map[string]any{"mode": "custom", "servers": []any{"ntp.example.com"}}), 409, "change_pending")
	// Core restarted in the middle of the window: the page still shows the countdown and the old address.
	e.nh = e.newHandlers(t, netOpts{})
	r = e.admin.get("/core/network")
	wantOK(t, r, 200)
	if jstr(r, "pending", "previous_address") != "192.168.1.50" || jstr(r, "pending", "expires_at") == "" {
		t.Errorf("after a restart: %v", r.JSON["pending"])
	}
	// Confirm: kept.
	changedBefore := e.changed.Load()
	r = e.admin.post("/core/network/management/confirm", nil)
	wantOK(t, r, 200)
	if jval(r, "pending") != nil || jstr(r, "management", "address") != "192.168.1.60" {
		t.Errorf("after confirm: %v", r.JSON)
	}
	if e.changed.Load() <= changedBefore {
		t.Error("a confirm must drop the cache of the box's addresses")
	}
	wantStatus(t, e.admin.post("/core/network/management/confirm", nil), 409, "nothing_pending")
	wantStatus(t, e.admin.post("/core/network/management/revert", nil), 409, "nothing_pending")
	if got := e.actions(); !slices.Contains(got, "network.management") || !slices.Contains(got, "network.management_confirmed") {
		t.Errorf("audit = %v", got)
	}
	if strings.Count(strings.Join(e.actions(), " "), "network.management_confirmed") != 1 {
		t.Errorf("one confirm, one row: %v", e.actions())
	}
}

func TestNetworkRevertAndTheTimerGoBackToTheOldSettings(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	e.configured() // .60 saved
	change := nwBody(map[string]any{"address": "192.168.1.70", "confirm": true})
	// The person cancels.
	wantOK(t, e.admin.put("/core/network/management", change), 200)
	r := e.admin.post("/core/network/management/revert", nil)
	wantOK(t, r, 200)
	if jval(r, "pending") != nil || jstr(r, "management", "address") != "192.168.1.60" {
		t.Errorf("after cancel: %v", r.JSON)
	}
	wantStatus(t, e.admin.post("/core/network/management/revert", nil), 409, "nothing_pending")
	// Nobody confirms: the host's timer fires. The page shows the old address, and the audit log says so once.
	wantOK(t, e.admin.put("/core/network/management", change), 200)
	e.timers.fireLast()
	eventuallyOS(t, "the host to go back", func() bool {
		e.clock.Advance(7 * time.Second) // the page reads the host at most every 6 seconds
		return jval(e.admin.get("/core/network"), "pending") == nil
	})
	for range 2 {
		r = e.admin.get("/core/network")
		wantOK(t, r, 200)
		if jval(r, "pending") != nil || jstr(r, "management", "address") != "192.168.1.60" {
			t.Fatalf("after the timer: %v", r.JSON)
		}
	}
	if n := strings.Count(strings.Join(e.actions(), " "), "network.management_reverted"); n != 2 { // the cancel and the timer
		t.Errorf("audit = %v", e.actions())
	}
	// Too late to confirm: the sentence says the time ran out.
	wantOK(t, e.admin.put("/core/network/management", change), 200)
	e.timers.fireLast()
	eventuallyOS(t, "the host to go back", func() bool { return e.hostPendingGone() })
	r = e.admin.post("/core/network/management/confirm", nil)
	wantStatus(t, r, 409, "nothing_pending")
	if !strings.Contains(jstr(r, "error", "message"), "The time to confirm ran out and the box went back to the old settings.") {
		t.Errorf("message = %q", jstr(r, "error", "message"))
	}
}

func TestNetworkDNSOnlyAndNTPOnlyChangesApplyAtOnce(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	e.configured()
	r := e.admin.put("/core/network/management", nwBody(map[string]any{"dns": []any{"9.9.9.9", "1.1.1.1"}}))
	wantOK(t, r, 200)
	if jval(r, "pending") != nil || fmt.Sprint(jval(r, "management", "dns")) != "[9.9.9.9 1.1.1.1]" {
		t.Errorf("DNS only: %v", r.JSON)
	}
	// The same settings again: nothing happens, nothing is audited.
	n := len(e.actions())
	wantOK(t, e.admin.put("/core/network/management", nwBody(map[string]any{"dns": []any{"9.9.9.9", "1.1.1.1"}})), 200)
	if len(e.actions()) != n {
		t.Errorf("a no-op was audited: %v", e.actions())
	}
	r = e.admin.put("/core/network/ntp", map[string]any{"mode": "custom", "servers": []any{"NTP1.Example.com", "203.0.113.7"}})
	wantOK(t, r, 200)
	if jval(r, "pending") != nil || jstr(r, "ntp", "mode") != "custom" || fmt.Sprint(jval(r, "ntp", "servers")) != "[ntp1.example.com 203.0.113.7]" {
		t.Errorf("NTP: %v", r.JSON)
	}
	r = e.admin.put("/core/network/ntp", map[string]any{"mode": "default", "servers": []any{}})
	wantOK(t, r, 200)
	if jstr(r, "ntp", "mode") != "default" || len(getArr(r, "ntp", "servers")) != 0 {
		t.Errorf("NTP default: %v", r.JSON["ntp"])
	}
	got := strings.Join(e.actions(), " ")
	for _, a := range []string{"network.dns", "network.ntp"} {
		if !strings.Contains(got, a) {
			t.Errorf("audit %q missing in %v", a, e.actions())
		}
	}
}

func TestNetworkManagementToDHCPAsksWithoutAnAddress(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	e.configured()
	r := e.admin.put("/core/network/management", map[string]any{"mode": "dhcp"})
	wantStatus(t, r, 409, "confirm_required")
	if v, ok := r.JSON["error"].(map[string]any)["new_ip"]; !ok || v != nil {
		t.Errorf("new_ip must be present and null with DHCP: %v", r.JSON["error"])
	}
	r = e.admin.put("/core/network/management", map[string]any{"mode": "dhcp", "confirm": true})
	wantOK(t, r, 200)
	if jstr(r, "management", "mode") != "dhcp" || jstr(r, "management", "address") == "" || jval(r, "pending") == nil {
		t.Errorf("DHCP applied: %v", r.JSON)
	}
	wantOK(t, e.admin.post("/core/network/management/confirm", nil), 200)
}

func TestNetworkManagementInputChecks(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	put := func(b map[string]any) reply { return e.admin.put("/core/network/management", b) }
	wantStatus(t, put(map[string]any{"mode": "dhcp", "address": "192.168.1.9"}), 400, "dhcp_no_static")
	wantStatus(t, put(map[string]any{"mode": "dhcp", "dns": []any{"1.1.1.1"}}), 400, "dhcp_no_static")
	for _, bad := range []map[string]any{
		{"address": "300.1.1.1"}, {"address": "192.168.1.0"}, {"address": "192.168.1.255"}, {"address": "127.0.0.2"}, {"prefix": 31}, {"prefix": 7},
		{"gateway": "192.168.1.60"}, {"gateway": nil}, {"dns": []any{}}, {"dns": []any{"a.b"}}, {"dns": []any{"1.1.1.1", "1.1.1.1"}}, {"dns": []any{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"}},
	} {
		if r := put(nwBody(bad)); r.Code != 400 || r.code() != "invalid_static" {
			t.Errorf("%v = %d %q", bad, r.Code, r.code())
		}
	}
	r := put(nwBody(map[string]any{"gateway": "10.9.9.9"}))
	wantStatus(t, r, 400, "gateway_outside_subnet")
	if jstr(r, "error", "message") != "The gateway must be inside the address range you entered." {
		t.Errorf("message = %q", jstr(r, "error", "message"))
	}
	e.taken.Store(netip.MustParseAddr("192.168.1.99"))
	wantStatus(t, put(nwBody(map[string]any{"address": "192.168.1.99"})), 409, "ip_in_use") // an inventory device
	// Nothing above reached the host or the audit log.
	if e.probe.probes() != 0 || len(e.actions()) != 0 {
		t.Errorf("probes %d, audit %v", e.probe.probes(), e.actions())
	}
}

func TestNetworkHostRefusalsAreMapped(t *testing.T) {
	t.Parallel()
	t.Run("another device answers for the address", func(t *testing.T) {
		e := newNetEnv(t, netOpts{})
		e.probe.set(func(p *nwProber) { p.conflict = true })
		r := e.admin.put("/core/network/management", nwBody(map[string]any{"confirm": true}))
		wantStatus(t, r, 409, "address_conflict")
		if jstr(r, "error", "message") != "Another device already uses this address." {
			t.Errorf("message = %q", jstr(r, "error", "message"))
		}
		if jval(e.admin.get("/core/network"), "pending") != nil {
			t.Error("a refused change must not wait")
		}
		if got := e.actions(); !slices.Equal(got, []string{"network.management", "network.management_failed"}) {
			t.Errorf("audit = %v", got)
		}
	})
	t.Run("the box does not reach the network at the new address", func(t *testing.T) {
		e := newNetEnv(t, netOpts{})
		e.probe.set(func(p *nwProber) { p.gwErr = fmt.Errorf("no answer") })
		wantStatus(t, e.admin.put("/core/network/management", nwBody(map[string]any{"confirm": true})), 409, "connectivity_check_failed")
		r := e.admin.get("/core/network")
		if jval(r, "pending") != nil || jstr(r, "management", "address") != "192.168.1.50" {
			t.Errorf("after the host went back by itself: %v", r.JSON)
		}
	})
	t.Run("the network files are not the installer's", func(t *testing.T) {
		e := newNetEnv(t, netOpts{})
		e.m.WriteRoot("etc/netplan/50-cloud-init.yaml", "network: {version: 2}\n")
		r := e.admin.put("/core/network/management", nwBody(map[string]any{"confirm": true}))
		wantStatus(t, r, 409, "net_backend_unsupported")
		if !strings.Contains(jstr(r, "error", "message"), "network files were not set up by the Vedette installer") {
			t.Errorf("message = %q", jstr(r, "error", "message"))
		}
	})
}

// ---- SPAN ----

func TestNetworkSpanSettingsAreChecked(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	e.configured()
	put := func(extra map[string]any) reply { return e.admin.put("/core/network/span", spanBody(extra)) }
	wantStatus(t, put(map[string]any{"interface": "eth0"}), 409, "span_on_management")
	wantStatus(t, put(map[string]any{"interface": "wlan9"}), 400, "bad_interface")
	wantStatus(t, put(map[string]any{"interface": nil}), 400, "no_interface")
	wantStatus(t, put(map[string]any{"extract": map[string]any{"dns": false, "tls_sni": false, "http_host": false, "flows": false}}), 400, "nothing_selected")
	for _, f := range []map[string]any{
		{"type": "cidr", "value": "10.0.5.0"}, {"type": "cidr", "value": "10.0.0.0/7"}, {"type": "cidr", "value": ""}, {"type": "host", "value": "bad host!"},
		{"type": "host", "value": "1.2.3"}, {"type": "port", "value": "0"}, {"type": "port", "value": "65536"}, {"type": "port", "value": "http"},
	} {
		if r := put(map[string]any{"filters": []any{f}}); r.Code != 400 || r.code() != "bad_filter" {
			t.Errorf("filter %v = %d %q", f, r.Code, r.code())
		}
	}
	wantStatus(t, put(map[string]any{"filters": []any{map[string]any{"type": "port", "value": "53"}, map[string]any{"type": "port", "value": "53"}}}), 400, "bad_filter")
	// The limits are bounded by the schema itself (5 to 50, 128 to 2048): the server refuses the rest before a handler runs.
	for _, b := range []map[string]any{{"cpu_percent": 80}, {"cpu_percent": 4}, {"memory_mb": 64}, {"memory_mb": 4096}} {
		if r := put(b); r.Code != 400 {
			t.Errorf("limits %v = %d %q", b, r.Code, r.code())
		}
	}
	// Nothing above changed anything.
	if r := e.admin.get("/core/network"); jstr(r, "span", "interface") != "" || jval(r, "span", "enabled") != false {
		t.Errorf("span after refusals: %v", r.JSON["span"])
	}
}

func TestNetworkSpanPortIsSetThroughTheHostAndTheSettingsStayInCore(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	e.configured()
	r := e.admin.put("/core/network/span", spanBody(map[string]any{"filters": []any{
		map[string]any{"type": "cidr", "value": "10.0.5.7/24"}, map[string]any{"type": "host", "value": "Backup.LAN"}, map[string]any{"type": "port", "value": "053"},
	}}))
	wantOK(t, r, 200)
	if jval(r, "pending") != nil {
		t.Errorf("a SPAN change has no countdown: %v", r.JSON["pending"])
	}
	if jstr(r, "span", "interface") != "eth1" || jval(r, "span", "enabled") != true {
		t.Fatalf("span = %v", r.JSON["span"])
	}
	if got := fmt.Sprint(jval(r, "span", "filters")); got != "[map[type:cidr value:10.0.5.0/24] map[type:host value:backup.lan] map[type:port value:53]]" {
		t.Errorf("filters are stored in their normal form: %s", got)
	}
	for _, i := range getArr(r, "interfaces") {
		m := i.(map[string]any)
		if (m["name"] == "eth1") != (m["role"] == "span") {
			t.Errorf("roles: %v", getArr(r, "interfaces"))
		}
	}
	if e.sensor.ports[len(e.sensor.ports)-1] != "eth1/true" {
		t.Errorf("the sensor was told %v", e.sensor.ports)
	}
	// The host knows the port; the rest is core's, and survives a restart.
	e.nh = e.newHandlers(t, netOpts{})
	r = e.admin.get("/core/network")
	if jstr(r, "span", "interface") != "eth1" || jval(r, "span", "cpu_percent") != float64(25) || jval(r, "span", "extract", "http_host") != false {
		t.Errorf("after a restart: %v", r.JSON["span"])
	}
	sp, err := e.nh.SpanSettings(t.Context())
	if err != nil || len(sp.Filters) != 3 || sp.Extract.HTTPHost {
		t.Errorf("SpanSettings (what the sensor reads) = %+v, %v", sp, err)
	}
	// Turn it off: the port stays the SPAN port, the capture stops.
	r = e.admin.put("/core/network/span", spanBody(map[string]any{"enabled": false}))
	wantOK(t, r, 200)
	if jval(r, "span", "enabled") != false || jstr(r, "span", "interface") != "eth1" || e.sensor.ports[len(e.sensor.ports)-1] != "/false" {
		t.Errorf("off: %v, sensor %v", r.JSON["span"], e.sensor.ports)
	}
	if !slices.Contains(e.actions(), "network.span") {
		t.Errorf("audit = %v", e.actions())
	}
}

func TestNetworkSpanPortRefusalsOfTheHost(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	e.configured()
	e.box.spanAddr.Store(true)
	wantStatus(t, e.admin.put("/core/network/span", spanBody(nil)), 409, "span_has_address")
	e.box.spanAddr.Store(false)
	wantStatus(t, e.admin.put("/core/network/span", spanBody(map[string]any{"interface": "eth2"})), 409, "span_not_physical")
	if jstr(e.admin.get("/core/network"), "span", "interface") != "" {
		t.Error("a refused port must not be set")
	}
}

func TestNetworkSpanNeedsTheManagementAddressSavedFirst(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	wantStatus(t, e.admin.put("/core/network/span", spanBody(nil)), 409, "management_not_set")
	wantStatus(t, e.admin.put("/core/network/ntp", map[string]any{"mode": "custom", "servers": []any{"ntp.example.com"}}), 409, "management_not_set")
	// Turning SPAN off when none is set needs no host call.
	wantOK(t, e.admin.put("/core/network/span", spanBody(map[string]any{"enabled": false, "interface": nil})), 200)
}

func TestNetworkInterfaceRoles(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	e.configured()
	roles := func(a, b, c string) map[string]any {
		return map[string]any{"roles": map[string]any{"eth0": a, "eth1": b, "eth2": c}}
	}
	put := func(b map[string]any) reply { return e.admin.put("/core/network/interfaces", b) }
	wantStatus(t, put(roles("management", "management", "unused")), 409, "management_count")
	wantStatus(t, put(roles("unused", "span", "unused")), 409, "management_count")
	wantStatus(t, put(roles("unused", "management", "unused")), 409, "management_fixed")
	wantStatus(t, put(roles("management", "span", "span")), 409, "span_count")
	wantStatus(t, put(map[string]any{"roles": map[string]any{"eth0": "management", "eth1": "span"}}), 400, "invalid_roles")
	wantStatus(t, put(map[string]any{"roles": map[string]any{"eth0": "management", "eth1": "span", "wlan0": "unused"}}), 400, "invalid_roles")
	r := put(roles("management", "span", "unused"))
	wantOK(t, r, 200)
	if jstr(r, "span", "interface") != "eth1" || jval(r, "span", "enabled") != false {
		t.Errorf("a port chosen by role: %v", r.JSON["span"])
	}
	wantOK(t, e.admin.put("/core/network/span", spanBody(nil)), 200)
	r = put(roles("management", "unused", "unused"))
	wantOK(t, r, 200)
	if jstr(r, "span", "interface") != "" || jval(r, "span", "enabled") != false {
		t.Errorf("a port set to unused turns SPAN off: %v", r.JSON["span"])
	}
	if !slices.Contains(e.actions(), "network.interfaces") {
		t.Errorf("audit = %v", e.actions())
	}
}

func TestNetworkSpanStatus(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{noSensor: true})
	e.configured()
	rx := filepath.Join(e.m.Root, "sys/devices/pci0000:00/net/eth1/statistics/rx_packets")
	status := func() reply { r := e.viewer.get("/core/network/span/status"); wantOK(t, r, 200); return r }
	if status().str("verdict") != "off" {
		t.Error("off before a SPAN port is chosen")
	}
	wantOK(t, e.admin.put("/core/network/span", spanBody(nil)), 200)
	// Without a sensor the host's counters speak: the first look has nothing to compare, then packets per second.
	if v := status().str("verdict"); v != "no_traffic" {
		t.Errorf("first look = %s", v)
	}
	e.clock.Advance(7 * time.Second)
	if err := os.WriteFile(rx, []byte("1000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := status()
	if r.str("verdict") != "ok" || jval(r, "packets_per_s") != float64(143) || r.str("interface") != "eth1" {
		t.Errorf("counters rising: %v", r.JSON)
	}
	if jval(r, "last_packet_at") != nil {
		t.Errorf("the host cannot tell when the last packet came: last_packet_at = %v", jval(r, "last_packet_at"))
	}
	// One sample per reading of the host: looking again inside the cache gives the same number, not a reset.
	if again := status(); jval(again, "packets_per_s") != float64(143) || again.str("verdict") != "ok" {
		t.Errorf("a second look at the same reading: %v", again.JSON)
	}
	e.clock.Advance(7 * time.Second)
	if v := status().str("verdict"); v != "no_traffic" {
		t.Errorf("counters flat = %s", v)
	}
	if err := os.WriteFile(filepath.Join(e.m.Root, "sys/devices/pci0000:00/net/eth1/operstate"), []byte("down\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(7 * time.Second) // the page reads the host at most every 6 seconds
	if v := status().str("verdict"); v != "no_link" {
		t.Errorf("cable out = %s", v)
	}
}

func TestNetworkSpanStatusUsesTheSensorWhenItMeasures(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	e.configured()
	wantOK(t, e.admin.put("/core/network/span", spanBody(nil)), 200)
	r := e.viewer.get("/core/network/span/status")
	wantOK(t, r, 200)
	if r.str("verdict") != "ok" || jval(r, "packets_per_s") != float64(100) || jval(r, "other_macs") != float64(3) || r.str("last_packet_at") != "2026-11-09T11:59:59Z" {
		t.Errorf("sensor numbers: %v", r.JSON)
	}
	e.sensor.mu.Lock()
	e.sensor.measure = core.SpanMeasure{Verdict: "own_only", PPS: 2}
	e.sensor.mu.Unlock()
	if v := e.viewer.get("/core/network/span/status").str("verdict"); v != "own_only" {
		t.Errorf("own_only = %s", v)
	}
	e.sensor.mu.Lock()
	e.sensor.err = core.ErrNoSensor
	e.sensor.mu.Unlock()
	if v := e.viewer.get("/core/network/span/status").str("verdict"); v != "no_traffic" { // the module is off: the host's counters (flat)
		t.Errorf("no sensor = %s", v)
	}
	if e.viewer.get("/core/network").str("span_status", "verdict") == "" {
		t.Error("the page carries span_status too")
	}
}

// ---- no host, and the host's words ----

func TestNetworkWithoutAHostIsNotAnApplianceAndNeverA500(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{noHost: true})
	calls := []struct {
		m, p string
		b    any
	}{
		{"GET", "/core/network", nil}, {"GET", "/core/network/span/status", nil},
		{"PUT", "/core/network/management", nwBody(map[string]any{"confirm": true})}, {"POST", "/core/network/management/confirm", nil},
		{"POST", "/core/network/management/revert", nil}, {"PUT", "/core/network/span", spanBody(nil)},
		{"PUT", "/core/network/ntp", map[string]any{"mode": "default", "servers": []any{}}},
		{"PUT", "/core/network/interfaces", map[string]any{"roles": map[string]any{"eth0": "management"}}},
	}
	for _, c := range calls {
		r := e.admin.request(c.m, c.p, c.b)
		wantStatus(t, r, 409, "not_appliance")
		if !strings.Contains(jstr(r, "error", "message"), "change the box's network") {
			t.Errorf("%s %s message = %q", c.m, c.p, jstr(r, "error", "message"))
		}
	}
	if len(e.actions()) != 0 {
		t.Errorf("nothing was attempted, nothing is audited: %v", e.actions())
	}
	if cards, ok, err := e.nh.Cards(t.Context()); ok || err != nil || cards != nil {
		t.Errorf("Cards without a host = %v %v %v", cards, ok, err)
	}
}

func TestNetworkCardsForTheSensor(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	cards, ok, err := e.nh.Cards(t.Context())
	if err != nil || !ok || len(cards) != 3 {
		t.Fatalf("cards = %+v %v %v", cards, ok, err)
	}
	for _, c := range cards {
		if c.Name == "eth2" && len(c.Addresses) != 0 {
			t.Errorf("link-local addresses do not count: %v", c.Addresses)
		}
	}
}

func TestNetworkErrorTableOfTheHostCodes(t *testing.T) {
	t.Parallel()
	want := map[string][2]any{
		api.CodeAddressConflict:       {409, "address_conflict"},
		api.CodeGatewayOutsideSubnet:  {400, "gateway_outside_subnet"},
		api.CodeSameIface:             {409, "span_on_management"},
		api.CodeIfaceUnknown:          {400, "bad_interface"},
		api.CodeSPANHasAddress:        {409, "span_has_address"},
		api.CodeSPANNotPhysical:       {409, "span_not_physical"},
		api.CodeNetBackendUnsupported: {409, "net_backend_unsupported"},
		api.CodeNotAwaitingConfirm:    {409, "nothing_pending"},
		api.CodeNotConfirmed:          {409, "nothing_pending"},
		api.CodeConnectivityCheckFail: {409, "connectivity_check_failed"},
		api.CodeRevertedByReboot:      {409, "reverted_by_reboot"},
		api.CodeRevertFailed:          {502, "revert_failed"},
		api.CodeNetplanApplyFailed:    {502, "netplan_apply_failed"},
		api.CodeNTPNotApplied:         {502, "ntp_not_applied"},
		api.CodeARPProbeFailed:        {502, "arp_probe_failed"},
		api.CodePendingInvalid:        {502, "pending_invalid"},
		api.CodeConfirmFailed:         {502, "confirm_failed"},
		api.CodePendingConfirm:        {409, "pending_confirm"},
		api.CodeNetPendingConfirm:     {409, "pending_confirm"},
		api.CodeInvalidArgs:           {400, "invalid"},
		api.CodeBootIDUnreadable:      {502, "host_error"}, // not for the person: the details are in the log
		"last_mgmt_removed":           {502, "host_error"},
	}
	for host, w := range want {
		e := core.MapHostCodeForTest(host)
		if e.Status != w[0] || e.Code != w[1] || e.Message == "" {
			t.Errorf("host %q -> %d %q %q, want %v", host, e.Status, e.Code, e.Message, w)
		}
	}
}

// ---- the contract: the shape of every answer is the shape of api/openapi.json ----

func TestNetworkAnswersHaveTheShapeOfTheOpenAPIContract(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	raw, err := os.ReadFile("../../api/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	schemaOf := func(method, path string) map[string]any {
		op := doc["paths"].(map[string]any)[path].(map[string]any)[method].(map[string]any)
		return op["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	}
	check := func(what string, schema map[string]any, v any) {
		t.Helper()
		var walk func(path string, s map[string]any, v any)
		walk = func(path string, s map[string]any, v any) {
			if alts, ok := s["anyOf"].([]any); ok {
				for _, a := range alts {
					if m := a.(map[string]any); m["type"] != "null" {
						if v != nil {
							walk(path, m, v)
						}
					}
				}
				return
			}
			switch x := v.(type) {
			case map[string]any:
				props, _ := s["properties"].(map[string]any)
				for k := range x {
					if _, ok := props[k]; !ok {
						t.Errorf("%s: %s.%s is not in the contract", what, path, k)
					}
				}
				for _, k := range asStrings(s["required"]) {
					if _, ok := x[k]; !ok {
						t.Errorf("%s: %s.%s is required by the contract and missing", what, path, k)
					}
				}
				for k, sub := range props {
					if y, ok := x[k]; ok && y != nil {
						walk(path+"."+k, sub.(map[string]any), y)
					}
				}
			case []any:
				if items, ok := s["items"].(map[string]any); ok {
					for i, y := range x {
						walk(fmt.Sprintf("%s[%d]", path, i), items, y)
					}
				}
			case nil:
				if tp := s["type"]; tp != nil && fmt.Sprint(tp) != "[string null]" && fmt.Sprint(tp) != "[integer null]" && !slices.Contains(asStrings(tp), "null") {
					t.Errorf("%s: %s is null but the contract does not allow null", what, path)
				}
			}
		}
		walk("$", schema, v)
	}
	e.configured()
	wantOK(t, e.admin.put("/core/network/span", spanBody(nil)), 200)
	wantOK(t, e.admin.put("/core/network/management", nwBody(map[string]any{"address": "192.168.1.61", "confirm": true})), 200) // pending present
	check("GET /core/network", schemaOf("get", "/core/network"), e.viewer.get("/core/network").JSON)
	check("GET span/status", schemaOf("get", "/core/network/span/status"), e.viewer.get("/core/network/span/status").JSON)
	r := e.admin.post("/core/network/management/revert", nil)
	check("POST revert", schemaOf("post", "/core/network/management/revert"), r.JSON)
	r = e.admin.put("/core/network/ntp", map[string]any{"mode": "custom", "servers": []any{"ntp1.example.com"}})
	wantOK(t, r, 200)
	check("PUT ntp", schemaOf("put", "/core/network/ntp"), r.JSON)
}

func asStrings(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, s := range x {
			out = append(out, fmt.Sprint(s))
		}
		return out
	case string:
		return []string{x}
	}
	return nil
}

func TestNetworkPendingIsRebuiltFromTheHostWhenCoresRecordIsLost(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	wantOK(t, e.admin.put("/core/network/management", nwBody(map[string]any{"confirm": true})), 200)
	err := e.env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DELETE FROM core_setting WHERE key = 'core_network_pending'`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	e.nh = e.newHandlers(t, netOpts{})
	r := e.admin.get("/core/network")
	wantOK(t, r, 200)
	if jval(r, "pending") == nil || jval(r, "pending", "previous_address") != nil || jstr(r, "pending", "expires_at") == "" {
		t.Errorf("the host still waits; only the old address is unknown: %v", r.JSON["pending"])
	}
	// The buttons still work: the run id comes from the host.
	wantOK(t, e.admin.post("/core/network/management/confirm", nil), 200)
}

func TestNetworkARevertThatCannotBeAppliedShowsTheRestart(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	e.configured()
	wantOK(t, e.admin.put("/core/network/management", nwBody(map[string]any{"address": "192.168.1.70", "confirm": true})), 200)
	e.m.Rule("netplan", "apply", "", 1, "", "") // from now on the operating system refuses to apply anything
	e.timers.fireLast()
	eventuallyOS(t, "the host to schedule its restart", func() bool {
		st, err := e.hh.Client.StateNet(t.Context())
		return err == nil && st.Pending != nil && st.Pending.RebootAt != nil
	})
	e.clock.Advance(7 * time.Second)
	r := e.admin.get("/core/network")
	wantOK(t, r, 200)
	if jstr(r, "pending", "reboot_at") == "" || jstr(r, "pending", "previous_address") != "192.168.1.60" {
		t.Errorf("the page must say the box restarts: %v", r.JSON["pending"])
	}
	r = e.admin.post("/core/network/management/confirm", nil)
	wantStatus(t, r, 409, "nothing_pending")
	if !strings.Contains(jstr(r, "error", "message"), "restarts in a moment") {
		t.Errorf("message = %q", jstr(r, "error", "message"))
	}
	wantStatus(t, e.admin.put("/core/network/management", nwBody(map[string]any{"address": "192.168.1.71", "confirm": true})), 409, "change_pending")
}

// ---- the review of acc33e0 ----

// M2: the host allows 60 requests a minute for all of core. Readers that arrive together share one read, and a
// read is kept longer than the 5 s poll of the page.
func TestNetworkConcurrentReadsMakeOneHostCall(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	e.fault.gate = make(chan struct{})
	base := e.fault.stateCalls.Load()
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.nh.CoreGetCoreNetwork(t.Context()); err != nil {
				t.Error(err)
			}
		}()
	}
	eventuallyOS(t, "a reader to reach the host", func() bool { return e.fault.stateCalls.Load() > base })
	<-time.After(100 * time.Millisecond) // the other nine are queued behind it
	close(e.fault.gate)
	wg.Wait()
	if n := e.fault.stateCalls.Load() - base; n != 1 {
		t.Fatalf("ten readers made %d calls to the host", n)
	}
	e.clock.Advance(5 * time.Second) // the poll of span/status
	wantOK(t, e.viewer.get("/core/network/span/status"), 200)
	if n := e.fault.stateCalls.Load() - base; n != 1 {
		t.Errorf("the next poll inside the cache read the host again: %d calls", n)
	}
	e.clock.Advance(2 * time.Second)
	wantOK(t, e.viewer.get("/core/network/span/status"), 200)
	if n := e.fault.stateCalls.Load() - base; n != 2 {
		t.Errorf("after the cache ran out: %d calls", n)
	}
}

// M3: a confirm that the host did not take (429, or "nothing is waiting" from a race) does not end core's record.
// The page keeps the old address, and when the change later goes back it is audited once.
func TestNetworkAFailedConfirmKeepsTheRecordUntilTheRunEnds(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"rate limited":                   {&hostclient.Error{Status: 429, Code: api.CodeRateLimited, Message: "slow down", RetryAfterS: 5}, 429, "rate_limited"},
		"the host says nothing waits":    {&hostclient.Error{Status: 412, Code: api.CodeNotAwaitingConfirm, Message: "no"}, 409, "nothing_pending"},
		"a bad request of the transport": {&hostclient.Error{Status: 400, Code: api.CodeInvalidArgs, Message: "bad"}, 400, "invalid"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newNetEnv(t, netOpts{})
			wantOK(t, e.admin.put("/core/network/management", nwBody(map[string]any{"confirm": true})), 200)
			e.fault.confirmErr.Store(errBox{tc.err})
			wantStatus(t, e.admin.post("/core/network/management/confirm", nil), tc.status, tc.code)
			r := e.admin.get("/core/network")
			if jstr(r, "pending", "previous_address") != "192.168.1.50" {
				t.Fatalf("the record was dropped: %v", r.JSON["pending"])
			}
			e.fault.confirmErr.Store(errBox{})
			e.timers.fireLast()
			eventuallyOS(t, "the host to go back", func() bool { return e.hostPendingGone() })
			e.clock.Advance(7 * time.Second)
			wantOK(t, e.admin.get("/core/network"), 200)
			wantOK(t, e.admin.get("/core/network"), 200)
			want := []string{"network.management", "network.management_confirmed", "network.management_confirmed_failed", "network.management_reverted"}
			if got := e.actions(); !slices.Equal(got, want) {
				t.Errorf("audit = %v, want %v", got, want)
			}
		})
	}
}

// L2: only an ended run settles the record. A host that cannot be asked, or a run that is still going (a confirm
// in progress), writes nothing and is tried again; the revert is written once, when the run has ended.
func TestNetworkSettleWaitsForTheRunToEnd(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	wantOK(t, e.admin.put("/core/network/management", nwBody(map[string]any{"confirm": true})), 200)
	read := func() reply {
		e.clock.Advance(7 * time.Second)
		r := e.admin.get("/core/network")
		wantOK(t, r, 200)
		return r
	}
	e.fault.hidePending.Store(true) // the host has let go of the lock; the run itself is still awaiting
	read()
	e.fault.getRunErr.Store(errBox{&hostclient.Error{Status: 503, Code: api.CodeShuttingDown, Message: "restarting"}})
	read()
	e.fault.getRunErr.Store(errBox{})
	read()
	if got := e.actions(); !slices.Equal(got, []string{"network.management"}) {
		t.Fatalf("nothing ended, nothing may be written: %v", got)
	}
	// The record is still there: with the lock back, the page shows the old address again.
	e.fault.hidePending.Store(false)
	if r := read(); jstr(r, "pending", "previous_address") != "192.168.1.50" {
		t.Fatalf("record lost: %v", r.JSON["pending"])
	}
	e.timers.fireLast()
	eventuallyOS(t, "the host to go back", func() bool { return e.hostPendingGone() })
	read()
	read()
	if n := strings.Count(strings.Join(e.actions(), " "), "network.management_reverted"); n != 1 {
		t.Errorf("one revert, one row: %v", e.actions())
	}
}

// M1: the passive sensor reads its cards through Cards. No socket file: the operating system's interfaces (ok
// false); a host that does not answer: the last good list, or ok false before there is one; never an error.
func TestNetworkCardsSurviveAMissingOrFailingHost(t *testing.T) {
	t.Parallel()
	t.Run("socket file absent", func(t *testing.T) {
		e := newNetEnv(t, netOpts{absentSocket: true})
		cards, ok, err := e.nh.Cards(t.Context())
		if ok || err != nil || cards != nil {
			t.Fatalf("Cards = %v %v %v", cards, ok, err)
		}
	})
	t.Run("host hiccup", func(t *testing.T) {
		e := newNetEnv(t, netOpts{})
		cards, ok, err := e.nh.Cards(t.Context())
		if err != nil || !ok || len(cards) != 3 {
			t.Fatalf("first = %v %v %v", cards, ok, err)
		}
		e.fault.stateErr.Store(errBox{&hostclient.Error{Status: 503, Code: api.CodeShuttingDown, Message: "restarting"}})
		e.clock.Advance(7 * time.Second)
		cards, ok, err = e.nh.Cards(t.Context())
		if err != nil || !ok || len(cards) != 3 {
			t.Fatalf("while the host hiccups = %v %v %v", cards, ok, err)
		}
		e.fault.stateErr.Store(errBox{&hostclient.Error{Status: 429, Code: api.CodeRateLimited, Message: "slow down"}})
		e.nh = e.newHandlers(t, netOpts{}) // a restart of core while the host is busy: nothing known yet
		e.fault.stateErr.Store(errBox{&hostclient.Error{Status: 429, Code: api.CodeRateLimited, Message: "slow down"}})
		cards, ok, err = e.nh.Cards(t.Context())
		if err != nil || ok || cards != nil {
			t.Fatalf("before any good answer = %v %v %v", cards, ok, err)
		}
	})
}

// L3: a box with no configuration of the host's and no default route. One card with an address is the management
// card; several are not told apart, and the message never has an empty card name.
func TestNetworkManagementCardWithoutAConfigurationOrARoute(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	e.m.RemoveRoot("proc/net/route")
	e.clock.Advance(7 * time.Second)
	r := e.admin.get("/core/network")
	wantOK(t, r, 200)
	if first := getArr(r, "interfaces")[0].(map[string]any); first["name"] != "eth0" || first["role"] != "management" {
		t.Errorf("the only card with an address is the management card: %v", getArr(r, "interfaces"))
	}
	e.box.spanAddr.Store(true) // now two cards have an address
	e.clock.Advance(7 * time.Second)
	for _, c := range []struct {
		m, p string
		b    any
	}{
		{"PUT", "/core/network/management", nwBody(map[string]any{"confirm": true})},
		{"PUT", "/core/network/interfaces", map[string]any{"roles": map[string]any{"eth0": "management", "eth1": "span", "eth2": "unused"}}},
	} {
		r := e.admin.request(c.m, c.p, c.b)
		wantStatus(t, r, 409, "management_not_set")
		msg := jstr(r, "error", "message")
		if !strings.Contains(msg, "cannot tell which network card is the management card") || strings.HasPrefix(msg, " ") || strings.Contains(msg, "  ") {
			t.Errorf("%s message = %q", c.p, msg)
		}
	}
	if len(e.actions()) != 0 {
		t.Errorf("nothing was attempted: %v", e.actions())
	}
}

// L4: when the sensor cannot be told, the save says so (verdict sensor_unreachable), every look tries again, and a
// sensor that says it is off is never shown as "ok" from the host's counters.
func TestNetworkSensorThatCannotBeToldIsReported(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	e.configured()
	e.sensor.mu.Lock()
	e.sensor.setErr = fmt.Errorf("the sensor is gone")
	e.sensor.mu.Unlock()
	r := e.admin.put("/core/network/span", spanBody(nil))
	wantOK(t, r, 200)
	if jstr(r, "span_status", "verdict") != "sensor_unreachable" {
		t.Fatalf("the save must say it: %v", r.JSON["span_status"])
	}
	e.clock.Advance(7 * time.Second)
	if v := e.viewer.get("/core/network/span/status").str("verdict"); v != "sensor_unreachable" {
		t.Errorf("still unreachable = %s", v)
	}
	e.sensor.mu.Lock()
	e.sensor.setErr = nil
	e.sensor.mu.Unlock()
	if v := e.viewer.get("/core/network/span/status").str("verdict"); v != "ok" { // the next look tells the sensor, then shows what it measures
		t.Errorf("after the sensor came back = %s", v)
	}
	if last := e.sensor.ports[len(e.sensor.ports)-1]; last != "eth1/true" {
		t.Errorf("the sensor was told %v", e.sensor.ports)
	}
	e.sensor.mu.Lock()
	e.sensor.measure = core.SpanMeasure{Verdict: "off"}
	e.sensor.mu.Unlock()
	rx := filepath.Join(e.m.Root, "sys/devices/pci0000:00/net/eth1/statistics/rx_packets")
	if err := os.WriteFile(rx, []byte("5000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(7 * time.Second)
	if v := e.viewer.get("/core/network/span/status").str("verdict"); v == "ok" {
		t.Errorf("the sensor says it is off but the page says %s", v)
	}
}

// L5: 5 seconds after the window would run out the box's addresses are read again and the revert is settled and
// audited, with nobody on the page.
func TestNetworkLooksAgainAfterTheWindow(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	wantOK(t, e.admin.put("/core/network/management", nwBody(map[string]any{"confirm": true})), 200)
	e.afterMu.Lock()
	n := len(e.afters)
	d := e.afterD[n-1]
	look := e.afters[n-1]
	e.afterMu.Unlock()
	if d < 304*time.Second || d > 306*time.Second {
		t.Fatalf("the look is scheduled in %v, want the window plus 5 s", d)
	}
	e.timers.fireLast()
	eventuallyOS(t, "the host to go back", func() bool { return e.hostPendingGone() })
	before := e.changed.Load()
	look()
	if e.changed.Load() <= before {
		t.Error("the addresses were not refreshed")
	}
	if got := e.actions(); !slices.Equal(got, []string{"network.management", "network.management_reverted"}) {
		t.Errorf("the revert was not settled by the look: %v", got)
	}
}

// L8: an NTP save that changes nothing is audited, as the mock does.
func TestNetworkNTPSaveWithNoChangeIsAudited(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	e.configured()
	n := len(e.actions())
	wantOK(t, e.admin.put("/core/network/ntp", map[string]any{"mode": "default", "servers": []any{}}), 200)
	got := e.actions()
	if len(got) != n+1 || got[len(got)-1] != "network.ntp" {
		t.Errorf("audit = %v", got)
	}
}

// L1: core's rules are the host's (host/ops unicast4, hostInSubnet, IsGlobalUnicast), so a person gets the sentence of
// the form and not a refusal of the host.
func TestNetworkRulesMatchTheHosts(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	put := func(b map[string]any) reply { return e.admin.put("/core/network/management", b) }
	for name, tc := range map[string]struct {
		b    map[string]any
		code string
	}{
		"address link-local":       {nwBody(map[string]any{"address": "169.254.5.5", "gateway": "169.254.5.1"}), "invalid_static"},
		"address 0/8":              {nwBody(map[string]any{"address": "0.1.2.3", "prefix": 8, "gateway": "0.1.2.1"}), "invalid_static"},
		"gateway is the network":   {nwBody(map[string]any{"gateway": "192.168.1.0"}), "gateway_not_host"},
		"gateway is the broadcast": {nwBody(map[string]any{"gateway": "192.168.1.255"}), "gateway_not_host"},
		"dns link-local":           {nwBody(map[string]any{"dns": []any{"169.254.1.1"}}), "invalid_static"},
		"dns broadcast":            {nwBody(map[string]any{"dns": []any{"255.255.255.255"}}), "invalid_static"},
		"dns loopback":             {nwBody(map[string]any{"dns": []any{"127.0.0.1"}}), "invalid_static"},
		"dns unspecified":          {nwBody(map[string]any{"dns": []any{"0.0.0.0"}}), "invalid_static"},
	} {
		if r := put(tc.b); r.Code != 400 || r.code() != tc.code {
			t.Errorf("%s = %d %q (%s), want 400 %s", name, r.Code, r.code(), r.Raw, tc.code)
		}
	}
	// A private DNS server is fine, and so is a gateway that is a plain host.
	wantStatus(t, put(nwBody(map[string]any{"dns": []any{"10.1.1.1"}})), 409, "confirm_required")
	e.configured()
	for _, ip := range []string{"127.0.0.1", "0.1.2.3", "169.254.0.1", "224.0.0.1", "255.255.255.255", "1.2.3"} {
		wantStatus(t, e.admin.put("/core/network/ntp", map[string]any{"mode": "custom", "servers": []any{ip}}), 400, "bad_ntp")
	}
	wantOK(t, e.admin.put("/core/network/ntp", map[string]any{"mode": "custom", "servers": []any{"203.0.113.7"}}), 200)
}

// Two administrators saving at once: the changes go one after the other, so the second finds the first waiting.
func TestNetworkConcurrentWritesAreSerialised(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	other, _ := e.signIn("admin2@acme.example", "admin")
	var wg sync.WaitGroup
	got := make([]reply, 2)
	for i, c := range []*client{e.admin, other} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i] = c.put("/core/network/management", nwBody(map[string]any{"address": fmt.Sprintf("192.168.1.%d", 60+i), "confirm": true}))
		}()
	}
	wg.Wait()
	ok, pending := 0, 0
	for _, r := range got {
		switch {
		case r.Code == 200:
			ok++
		case r.Code == 409 && r.code() == "change_pending":
			pending++
		}
	}
	if ok != 1 || pending != 1 {
		t.Fatalf("one change goes through, the other finds it waiting: %d %s / %d %s", got[0].Code, got[0].Raw, got[1].Code, got[1].Raw)
	}
	if n := e.probe.probes(); n != 1 {
		t.Errorf("only the winner is probed: %d", n)
	}
}

// INV-7 on the network routes: an administrator demoted while the request is being served is refused at the audit
// write, before any call to the host.
func TestNetworkDemotedAdminIsRefusedBeforeTheHostIsCalled(t *testing.T) {
	t.Parallel()
	e := newNetEnv(t, netOpts{})
	second, _ := e.signIn("second@acme.example", "admin")
	var once sync.Once
	e.fault.onState = func() {
		once.Do(func() {
			err := e.env.DB.Write(context.Background(), func(tx *sql.Tx) error {
				_, err := tx.ExecContext(context.Background(), "UPDATE core_user SET role = 'viewer' WHERE email = 'second@acme.example'")
				return err
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
	r := second.put("/core/network/management", nwBody(map[string]any{"confirm": true}))
	if r.Code != 403 {
		t.Fatalf("demoted admin = %d %s", r.Code, r.Raw)
	}
	if e.probe.probes() != 0 || len(e.actions()) != 0 {
		t.Errorf("the host was called or a row written: probes %d, audit %v", e.probe.probes(), e.actions())
	}
	if jval(e.admin.get("/core/network"), "pending") != nil {
		t.Error("the refused change must not wait")
	}
}
