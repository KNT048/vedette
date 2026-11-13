package inventory_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// The addresses the box answers on besides its own device (the decoys of the honeypot, Config.BoxOwnedIPs) are the box: an
// observation of one of them (the ARP replies the trap gives itself) never creates or updates a device, it is counted,
// and a sweep must not probe the address (WP-14 review, honeypot CONTRACT open question 2).
func TestBoxOwnedAddressIsNoDevice(t *testing.T) {
	t.Parallel()
	owned := netip.MustParseAddr("192.168.10.240")
	e := newEnv(t, func(c *inventory.Config) {
		c.BoxOwnedIPs = func(context.Context) []netip.Addr { return []netip.Addr{owned} }
	})
	ctx := e.ctx()
	mac := func(ip netip.Addr, m string) []observe.Observation {
		h := observe.AssetHint{IP: ip, MAC: m}
		return []observe.Observation{
			{AssetHint: h, Field: observe.MAC, Value: m, Source: observe.Passive, Confidence: 0.9},
			{AssetHint: h, Field: observe.Kind, Value: "server", Source: observe.Passive, Confidence: 0.7},
		}
	}
	devices := func() int { return e.count(`SELECT count(*) FROM inv_asset`) }
	if err := e.svc.Record(ctx, mac(owned, "02:00:00:00:02:40")); err != nil {
		t.Fatal(err)
	}
	if n := devices(); n != 0 || e.svc.BoxOwnedSkipped() != 2 {
		t.Fatalf("%d devices, %d skipped: the trap's own address became a device", n, e.svc.BoxOwnedSkipped())
	}
	if len(e.ev.named(inventory.EventAssetDiscovered)) != 0 {
		t.Fatal("a discovery was announced")
	}
	// A batch with both: only the box-owned observations are dropped.
	batch := append(mac(owned, "02:00:00:00:02:40"), mac(netip.MustParseAddr("192.168.10.50"), "aa:bb:cc:00:00:50")...)
	if err := e.svc.Record(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if n := devices(); n != 1 {
		t.Fatalf("%d devices, want the one at .50", n)
	}
	// Software reported for the address (an agent on the decoy cannot exist) creates nothing either.
	err := e.svc.ReplaceSoftware(ctx, observe.AssetHint{IP: owned}, observe.Agent, []observe.Software{{Display: "Apache 2.4", Vendor: "Apache", Product: "http_server", Version: "2.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if n := devices(); n != 1 {
		t.Fatalf("%d devices after software for a box-owned address", n)
	}
	prot, err := e.svc.ProtectedIPs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range prot {
		found = found || a == owned
	}
	if !found {
		t.Fatalf("ProtectedIPs %v lacks the box-owned address", prot)
	}
}

// Without a provider nothing changes.
func TestNoBoxOwnedProviderChangesNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	h := observe.AssetHint{IP: netip.MustParseAddr("192.168.10.240"), MAC: "02:00:00:00:02:40"}
	if err := e.svc.Record(e.ctx(), []observe.Observation{{AssetHint: h, Field: observe.MAC, Value: "02:00:00:00:02:40", Source: observe.Passive, Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM inv_asset`); n != 1 || e.svc.BoxOwnedSkipped() != 0 {
		t.Fatalf("%d devices, %d skipped", n, e.svc.BoxOwnedSkipped())
	}
}

// WP-31 M7: a device that sits on a decoy's address (a DHCP lease or a static address an intruder chose) is a device. Only what
// carries no MAC, or one of the box's own MACs (its cards and the decoys' macvlan links, Config.BoxOwnedMACs), is the box; while
// the box's MACs are unknown, everything at the address is dropped as before.
func TestContract_INV17_AForeignMACOnADecoyAddressIsADevice(t *testing.T) {
	t.Parallel()
	owned := netip.MustParseAddr("192.168.10.240")
	known, freshAsks, macs := true, 0, []string{"02:00:00:00:02:40", "52:54:00:aa:bb:cc"}
	e := newEnv(t, func(c *inventory.Config) {
		c.BoxOwnedIPs = func(context.Context) []netip.Addr { return []netip.Addr{owned} }
		c.BoxOwnedMACs = func(_ context.Context, fresh bool) ([]string, error) {
			if !known {
				return nil, context.DeadlineExceeded
			}
			if fresh {
				freshAsks++
				return append([]string{"02:00:00:00:02:41"}, macs...), nil // a decoy added a moment ago
			}
			return macs, nil
		}
	})
	ctx := e.ctx()
	at := func(m string, f observe.Field, v string) []observe.Observation {
		return []observe.Observation{{AssetHint: observe.AssetHint{IP: owned, MAC: m}, Field: f, Value: v, Source: observe.Passive, Confidence: 0.9}}
	}
	devices := func() int { return e.count(`SELECT count(*) FROM inv_asset`) }
	for _, b := range [][]observe.Observation{
		at("02:00:00:00:02:40", observe.MAC, "02:00:00:00:02:40"), // the decoy itself
		at("52:54:00:AA:BB:CC", observe.MAC, "52:54:00:AA:BB:CC"), // the box's card, any case
		at("", observe.Hostname, "trap"),                          // no MAC: cannot tell, so the box
	} {
		if err := e.svc.Record(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	if n := devices(); n != 0 || freshAsks != 0 {
		t.Fatalf("%d devices from the box's own frames, %d fresh asks", n, freshAsks)
	}
	// A decoy added a moment ago: its MAC is not in the cached answer, so the host is asked again before it counts as a device.
	if err := e.svc.Record(ctx, at("02:00:00:00:02:41", observe.MAC, "02:00:00:00:02:41")); err != nil {
		t.Fatal(err)
	}
	if n := devices(); n != 0 || freshAsks != 1 {
		t.Fatalf("%d devices, %d fresh asks: a new decoy's own frame became a device", n, freshAsks)
	}
	known = false
	if err := e.svc.Record(ctx, at("aa:bb:cc:00:02:40", observe.MAC, "aa:bb:cc:00:02:40")); err != nil {
		t.Fatal(err)
	}
	if n := devices(); n != 0 {
		t.Fatalf("%d devices while the box's MACs are unknown", n)
	}
	known = true
	if err := e.svc.Record(ctx, at("aa:bb:cc:00:02:40", observe.MAC, "aa:bb:cc:00:02:40")); err != nil {
		t.Fatal(err)
	}
	if n := devices(); n != 1 || len(e.ev.named(inventory.EventAssetDiscovered)) != 1 {
		t.Fatalf("%d devices, %d discoveries: a foreign machine on a decoy address stayed invisible", n, len(e.ev.named(inventory.EventAssetDiscovered)))
	}
	if n := e.count(`SELECT count(*) FROM inv_asset WHERE ip = ?`, owned.String()); n != 1 {
		t.Fatal("the device does not hold the decoy's address")
	}
}

// B2 lab (Ubuntu 26.04): a Trap IP added a second ago answers ARP with its new macvlan MAC before the host lists it; that frame
// became a device, and the device then held the Trap IP in conflict. With Config.BoxDecoyMACs a foreign MAC at a box-owned address
// is a device only where the host holds a decoy with another MAC; where it holds none yet, the frame is the box's own link.
func TestContract_INV17_ADecoyComingUpIsNoDevice(t *testing.T) {
	t.Parallel()
	coming, held := netip.MustParseAddr("192.168.10.242"), netip.MustParseAddr("192.168.10.240")
	e := newEnv(t, func(c *inventory.Config) {
		c.BoxOwnedIPs = func(context.Context) []netip.Addr { return []netip.Addr{coming, held} }
		c.BoxOwnedMACs = func(context.Context, bool) ([]string, error) {
			return []string{"f8:bc:12:00:02:40", "52:54:00:aa:bb:cc"}, nil
		}
		c.BoxDecoyMACs = func(context.Context, bool) (map[netip.Addr]string, error) {
			return map[netip.Addr]string{held: "f8:bc:12:00:02:40"}, nil // the host does not list .242 yet
		}
	})
	at := func(ip netip.Addr, m string) []observe.Observation {
		return []observe.Observation{{AssetHint: observe.AssetHint{IP: ip, MAC: m}, Field: observe.MAC, Value: m, Source: observe.Passive, Confidence: 0.9}}
	}
	if err := e.svc.Record(e.ctx(), at(coming, "00:50:56:aa:02:42")); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM inv_asset`); n != 0 {
		t.Fatalf("the Trap IP coming up became %d device(s)", n)
	}
	// Where the host holds a decoy with another MAC, a foreign MAC is still another machine on the address (WP-31 M7).
	if err := e.svc.Record(e.ctx(), at(held, "aa:bb:cc:00:02:40")); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM inv_asset WHERE ip = ?`, held.String()); n != 1 {
		t.Fatalf("a foreign machine on a held decoy address: %d devices", n)
	}
}
