package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/inventory"
)

// The wiring of the Box network page (S-CORE-8): what cmd/vedette hands the handlers and what the handlers hand
// back (the sensor's cards, the box's addresses, the inventory). The behaviour of the routes is tested in
// modules/core (network_test.go) against the real host commands; here the host is a tiny fake on a unix socket.

// fakeHost answers GET /v1/state/net and GET /v1/runs/{id} on a unix socket.
type fakeHost struct {
	sock    string
	state   atomic.Value // api.NetState
	runs    atomic.Int32
	failing atomic.Bool // state/net answers 503
}

func startFakeHost(t *testing.T, st api.NetState) *fakeHost {
	t.Helper()
	dir, err := os.MkdirTemp("", "vh") // short: a unix socket path may be at most about 100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &fakeHost{sock: filepath.Join(dir, "h.sock")}
	f.state.Store(st)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/state/net", func(w http.ResponseWriter, _ *http.Request) {
		if f.failing.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(api.ErrorBody{Error: api.ErrorInfo{Code: api.CodeShuttingDown, Message: "restarting"}})
			return
		}
		_ = json.NewEncoder(w).Encode(f.state.Load())
	})
	mux.HandleFunc("GET /v1/runs/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.runs.Add(1)
		now := time.Now().UTC()
		_ = json.NewEncoder(w).Encode(api.Run{RunID: r.PathValue("id"), Command: api.CmdNetApply, Status: api.StatusReverted, StartedAt: now, FinishedAt: &now, Error: &api.RunError{Code: api.CodeNotConfirmed, Message: "not confirmed"}})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

func boxState() api.NetState {
	return api.NetState{Interfaces: []api.NetInterface{
		{Name: "eth0", MAC: "02:00:00:00:00:01", State: "up", Role: api.NetRoleManagement, Addresses: []string{"192.168.10.250/24", "fe80::1/64", "fd00::5/64"}},
		{Name: "eth1", MAC: "02:00:00:00:00:02", State: "up", Role: api.NetRoleSPAN, Addresses: []string{"fe80::2/64"}},
		{Name: "veth9", MAC: "02:00:00:00:00:09", State: "up", Addresses: []string{"10.88.0.1/16"}},
	}}
}

// The cards the passive sensor sees come from the host: IPv4 only, no link-local, no virtual links.
func TestWiringSensorCardsComeFromTheHost(t *testing.T) {
	t.Parallel()
	f := startFakeHost(t, boxState())
	var skew atomic.Int64 // the clock of the stack: the box reads the host at most every 6 seconds
	s := newStackWith(t, func(d *deps) {
		d.HostSocket, d.DataDir, d.KeyPath = f.sock, t.TempDir(), filepath.Join(t.TempDir(), "vedette.key")
		d.Clock = func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
	})
	nh := netHost{box: s.d.Network}
	got, err := nh.Interfaces(t.Context())
	if err != nil || len(got) != 2 || got[0].Name != "eth0" || got[1].Name != "eth1" {
		t.Fatalf("cards = %+v, %v", got, err)
	}
	if len(got[0].Addresses) != 1 || got[0].Addresses[0].Addr() != netip.MustParseAddr("192.168.10.250") || len(got[1].Addresses) != 0 || !got[0].Link {
		t.Errorf("addresses = %+v", got)
	}
	// The host hiccups: the last list, no error (the capture loop must not go into back-off for it).
	f.failing.Store(true)
	skew.Store(int64(10 * time.Second))
	again, err := nh.Interfaces(t.Context())
	if err != nil || len(again) != 2 {
		t.Fatalf("while the host hiccups = %+v, %v", again, err)
	}
}

// D-380 (#471): with no role set (a fresh install) the sensor's default card is the card of the default route, never the
// box's own bridge vedette0; a host that hiccups gives the last answer; without a host there is no answer (ok=false).
func TestWiringSensorDefaultCardIsTheDefaultRouteCard(t *testing.T) {
	t.Parallel()
	fresh := api.NetState{Interfaces: []api.NetInterface{
		{Name: "enp2s0", MAC: "02:00:00:00:00:01", State: "up", Addresses: []string{"192.168.18.141/24"}},
		{Name: "vedette0", MAC: "02:00:00:00:00:02", State: "up", Addresses: []string{"172.30.7.1/24"}},
		{Name: "wlp3s0", MAC: "02:00:00:00:00:03", State: "up", Addresses: []string{"192.168.18.142/24"}},
	}, DefaultRoute: &api.NetRoute{Iface: "enp2s0", Gateway: "192.168.18.1"}}
	f := startFakeHost(t, fresh)
	var skew atomic.Int64
	s := newStackWith(t, func(d *deps) {
		d.HostSocket, d.DataDir, d.KeyPath = f.sock, t.TempDir(), filepath.Join(t.TempDir(), "vedette.key")
		d.Clock = func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
	})
	nh := netHost{box: s.d.Network}
	if name, ok := nh.ManagementCard(t.Context()); name != "enp2s0" || !ok {
		t.Fatalf("default card = %q %v, want enp2s0", name, ok)
	}
	f.failing.Store(true)
	skew.Store(int64(10 * time.Second))
	if name, ok := nh.ManagementCard(t.Context()); name != "enp2s0" || !ok {
		t.Errorf("while the host hiccups = %q %v, want the last answer", name, ok)
	}
	f.failing.Store(false)
	noWifiAddr := slices.Clone(fresh.Interfaces)
	noWifiAddr[2].Addresses = nil
	for i, c := range []struct {
		name  string
		ifs   []api.NetInterface
		route string
		want  string
	}{
		{"a default route on the bridge, two cards with an address: not clear", fresh.Interfaces, "vedette0", ""},
		{"a default route on a VPN link, one card with an address", noWifiAddr, "wg0", "enp2s0"},
	} {
		f.state.Store(api.NetState{Interfaces: c.ifs, DefaultRoute: &api.NetRoute{Iface: c.route, Gateway: "10.9.0.1"}})
		skew.Store(int64(time.Duration(20+10*i) * time.Second))
		if name, ok := nh.ManagementCard(t.Context()); name != c.want || !ok {
			t.Errorf("%s = %q %v, want %q", c.name, name, ok, c.want)
		}
	}
	if name, ok := (netHost{box: newStackWith(t, func(*deps) {}).d.Network}).ManagementCard(t.Context()); name != "" || ok {
		t.Errorf("without a host = %q %v", name, ok)
	}
}

// M1 (D-385): a container-only install (no socket configured) never takes the core container's own interfaces for the
// box's cards: Interfaces gives none and no error (the cards come from the sensor's heartbeat), and SpanOptions has its
// defaults before the first save.
func TestWiringWithoutAHostCoreDoesNotReadItsOwnInterfaces(t *testing.T) {
	t.Parallel()
	s := newStackWith(t, func(*deps) {})
	if got, err := (netHost{box: s.d.Network}).Interfaces(t.Context()); err != nil || len(got) != 0 {
		t.Fatalf("Interfaces = %v %v, want no cards and no error", got, err)
	}
	x, filters, err := netHost{box: s.d.Network}.SpanOptions(t.Context())
	if err != nil || !x.DNS || !x.Flows || len(filters) != 0 {
		t.Errorf("options = %+v %v %v", x, filters, err)
	}
}

// M1 (D-263, D-385): HostCards says "no host" (ok=false, no error) only when core runs without a host socket. A configured
// host that gives no list (socket absent, or failing with nothing cached) is an error, so the sensor's heartbeat never
// decides on an appliance; Interfaces fails the same way (no fallback to the core container's own cards).
func TestWiringHostCardsFailClosedWhenAConfiguredHostGivesNoList(t *testing.T) {
	t.Parallel()
	t.Run("no socket configured", func(t *testing.T) {
		t.Parallel()
		s := newStackWith(t, func(*deps) {})
		cards, ok, err := netHost{box: s.d.Network}.HostCards(t.Context())
		if ok || err != nil || cards != nil {
			t.Fatalf("HostCards = %v %v %v, want no host and no error", cards, ok, err)
		}
	})
	t.Run("socket path set but absent", func(t *testing.T) {
		t.Parallel()
		s := newStackWith(t, func(d *deps) {
			d.HostSocket, d.DataDir, d.KeyPath = filepath.Join(t.TempDir(), "absent.sock"), t.TempDir(), filepath.Join(t.TempDir(), "vedette.key")
		})
		nh := netHost{box: s.d.Network}
		if _, ok, err := nh.HostCards(t.Context()); ok || err == nil {
			t.Fatalf("HostCards ok=%v err=%v, want an error", ok, err)
		}
		if _, err := nh.Interfaces(t.Context()); err == nil {
			t.Fatal("Interfaces fell back to the core container's own cards")
		}
	})
	t.Run("host failing with nothing cached", func(t *testing.T) {
		t.Parallel()
		f := startFakeHost(t, boxState())
		f.failing.Store(true) // answers an error from the first look: nothing is cached
		s := newStackWith(t, func(d *deps) {
			d.HostSocket, d.DataDir, d.KeyPath = f.sock, t.TempDir(), filepath.Join(t.TempDir(), "vedette.key")
		})
		nh := netHost{box: s.d.Network}
		if _, ok, err := nh.HostCards(t.Context()); ok || err == nil {
			t.Fatalf("HostCards ok=%v err=%v, want an error", ok, err)
		}
		if _, err := nh.Interfaces(t.Context()); err == nil {
			t.Fatal("Interfaces fell back to the core container's own cards")
		}
	})
}

// The module being off means nothing is measured; a missing service too. Both are ErrNoSensor, which the page
// answers from the host's counters.
func TestWiringSpanSensorIsAbsentWhileTheModuleIsOff(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	set := func(on bool) {
		t.Helper()
		var change modreg.Change
		err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
			var err error
			switch {
			case on && !s.d.Reg.Enabled("sensor-passive"):
				change, err = s.d.Reg.Enable(ctx, tx, "admin@acme.example", "sensor-passive", true)
			case !on && s.d.Reg.Enabled("sensor-passive"):
				change, err = s.d.Reg.Disable(ctx, tx, "admin@acme.example", "sensor-passive")
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		s.d.Reg.Publish(change) // a zero Change publishes nothing
	}
	sensor := &spanSensor{reg: s.d.Reg, svc: s.d.SensorPassive}
	set(false)
	if _, err := sensor.SpanStats(ctx); !errors.Is(err, core.ErrNoSensor) {
		t.Fatalf("module off: %v", err)
	}
	set(true)
	if _, err := sensor.SpanStats(ctx); errors.Is(err, core.ErrNoSensor) {
		t.Fatalf("module on: %v", err)
	}
	var none spanSensor
	if _, err := none.SpanStats(ctx); !errors.Is(err, core.ErrNoSensor) {
		t.Errorf("no service: %v", err)
	}
	if err := none.SetSpanPort(ctx, "a@b.c", "eth1", true); !errors.Is(err, core.ErrNoSensor) {
		t.Errorf("no service, set: %v", err)
	}
}

// M1 of the SP-4 review: the SPAN card is chosen against the cards the host reports, with the module off and before any
// heartbeat, and the choice is what the capture is told once it runs.
func TestWiringSpanPortCanBeChosenWithTheModuleOff(t *testing.T) {
	t.Parallel()
	f := startFakeHost(t, boxState())
	s := newStackWith(t, func(d *deps) {
		d.HostSocket, d.DataDir, d.KeyPath = f.sock, t.TempDir(), filepath.Join(t.TempDir(), "vedette.key")
	})
	ctx := t.Context()
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		change, err := s.d.Reg.Disable(ctx, tx, "admin@acme.example", "sensor-passive")
		s.d.Reg.Publish(change)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	sensor := &spanSensor{reg: s.d.Reg, svc: s.d.SensorPassive}
	if err := sensor.SetSpanPort(ctx, "admin@acme.example", "eth1", true); err != nil {
		t.Fatalf("a card of the host with the module off: %v", err)
	}
	if err := sensor.SetSpanPort(ctx, "admin@acme.example", "eth9", true); err == nil {
		t.Error("a card the host does not have was accepted")
	}
	if rep, err := s.d.SensorPassive.Config(ctx, 0, ""); err != nil || rep.Config.Interface != "eth1" || !rep.Config.Span {
		t.Errorf("config %+v %v", rep, err)
	}
}

// D-393 (M3): a container-only box (no host) with two cards that have an address gives no default card (D-380); through the
// real route the admin chooses one of them without SPAN, the sensor is told that card, GET says it is a choice (chosen), and
// null brings the default rule back.
func TestWiringContainerOnlyAdminChoosesAnAddressedCard(t *testing.T) {
	t.Parallel()
	s := newStackWith(t, func(*deps) {})
	ctx := t.Context()
	beat := &sensorlink.PassiveHeartbeat{Version: "1.0.0", Drops: map[string]int64{}, Interfaces: []sensorlink.HeartbeatIface{
		{Name: "enp2s0", MAC: "02:00:00:00:00:01", Link: true, IPv4: []string{"192.168.18.141/24"}},
		{Name: "eno1", MAC: "02:00:00:00:00:02", Link: true, IPv4: []string{"10.0.0.5/24"}},
	}}
	if _, err := s.d.SensorPassive.PassiveHeartbeat(ctx, beat); err != nil {
		t.Fatal(err)
	}
	sensor := func(m map[string]any) map[string]any {
		t.Helper()
		if l, ok := m["sensors"].([]any); ok && len(l) == 1 {
			m, _ = l[0].(map[string]any)
		}
		return m
	}
	if code, m := s.do("GET", "/inventory/sensors", "admin", ""); code != 200 || sensor(m)["interface"] != nil || sensor(m)["chosen"] != false {
		t.Fatalf("two cards, nothing chosen: %d %v", code, m)
	}
	if code, m := s.do("PATCH", "/inventory/sensors/sn-local", "admin", `{"interface":"eno1","span":false}`); code != 200 || m["interface"] != "eno1" || m["span"] != false || m["chosen"] != true {
		t.Fatalf("choose eno1: %d %v", code, m)
	}
	if rep, err := s.d.SensorPassive.Config(ctx, 0, ""); err != nil || rep.Config.Interface != "eno1" || rep.Config.Span {
		t.Errorf("the sensor is told %+v %v", rep, err)
	}
	if code, m := s.do("PATCH", "/inventory/sensors/sn-local", "admin", `{"interface":null,"span":false}`); code != 200 || m["interface"] != nil || m["chosen"] != false {
		t.Errorf("back to the default: %d %v", code, m)
	}
}

// ip_in_use looks at the inventory (the box itself excluded) and at the honeypot's decoys.
func TestWiringAddressInUse(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	if _, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Name: "fw", IP: "192.168.30.1"}); err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]bool{"192.168.30.1": true, "192.168.30.2": false} {
		got, err := addressInUse(ctx, s.d.Inventory, s.d.Honeypot, netip.MustParseAddr(ip))
		if err != nil || got != want {
			t.Errorf("%s = %v, %v, want %v", ip, got, err, want)
		}
	}
	if got, err := inventoryHasAddress(ctx, nil, netip.MustParseAddr("192.168.30.1")); got || err != nil {
		t.Errorf("no inventory = %v %v", got, err)
	}
	if got, err := addressInUse(ctx, s.d.Inventory, nil, netip.MustParseAddr("192.168.30.1")); !got || err != nil {
		t.Errorf("honeypot not built yet = %v %v", got, err)
	}
}

// AddressesChanged is d.HostNet.Invalidate: when the page settles a change that went back, the shared cache of the
// box's addresses (conn, the sweep, the honeypot) asks the host again at once.
func TestWiringAddressesChangedReachesTheHostNetCache(t *testing.T) {
	t.Parallel()
	f := startFakeHost(t, boxState())
	var fetches atomic.Int32
	cache := newHostNetCache(func(context.Context) ([]netip.Prefix, error) {
		fetches.Add(1)
		return []netip.Prefix{netip.MustParsePrefix("192.168.10.250/32")}, nil
	}, time.Now)
	s := newStackWith(t, func(d *deps) {
		d.HostSocket, d.HostNet, d.DataDir, d.KeyPath = f.sock, cache, t.TempDir(), filepath.Join(t.TempDir(), "vedette.key")
	})
	ctx := t.Context()
	cache.Get(ctx)
	cache.Get(ctx)
	if fetches.Load() != 1 {
		t.Fatalf("a fresh answer is served from memory: %d", fetches.Load())
	}
	// A change that waited and is no longer waiting at the host: the record is core's, the host has no pending.
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO core_setting (key, value, updated_at, updated_by) VALUES ('core_network_pending', '{"run_id":"rn_0123456789abcdef","previous_address":"192.168.10.9"}', '2026-11-10T08:00:00.000Z', 'test')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, body := s.do("GET", "/core/network", "viewer", ""); code != 200 {
		t.Fatalf("GET /core/network = %d %v", code, body)
	}
	cache.Get(ctx)
	if fetches.Load() != 2 {
		t.Fatalf("the settled change must drop the cache of the box's addresses: %d fetches", fetches.Load())
	}
	var rows int
	if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT count(*) FROM core_audit WHERE action = 'network.management_reverted'`).Scan(&rows); err != nil || rows != 1 {
		t.Errorf("revert rows = %d, %v", rows, err)
	}
	if code, _ := s.do("GET", "/core/network", "viewer", ""); code != 200 || strings.Contains("", "x") {
		t.Fatal("second read")
	}
	if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT count(*) FROM core_audit WHERE action = 'network.management_reverted'`).Scan(&rows); err != nil || rows != 1 {
		t.Errorf("settled twice: %d rows, %v", rows, err)
	}
}
