package main

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// DevicesOfKind reads inventory without the 2000 row cap of the device list (newest first): with 2000 newer devices the oldest one, the
// gateway, must still be a never-touch device. A cap here dropped it silently, with no error to make the fail-closed path trigger.
// The inventory is filled through the real observation path, so this test is slow on purpose (about 2000 rows).
func TestResponseDirectoryKeepsTheOldestGatewayPastTheListCap(t *testing.T) {
	s := newStack(t)
	ctx := t.Context()
	fg := s.addFortiGate()
	dir := responseDirectory{inv: s.d.Inventory, fnd: s.d.Findings}
	has := func() bool {
		l, err := dir.DevicesOfKind(ctx, "router", "firewall")
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range l {
			if d.ID == fg {
				return true
			}
		}
		return false
	}
	if !has() {
		t.Fatal("the FortiGate is not a router/firewall to begin with")
	}
	wait := time.NewTimer(10 * time.Millisecond) // every device below is strictly newer than the gateway: the list cap cuts the oldest first
	select {
	case <-wait.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var batch []observe.Observation
	for i := range 2000 {
		ip := netip.AddrFrom4([4]byte{10, 20, byte(i / 250), byte(i%250 + 1)})
		mac := fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256)
		batch = append(batch, observe.Observation{AssetHint: observe.AssetHint{IP: ip, MAC: mac}, Field: observe.MAC, Value: mac, Source: observe.Passive, Confidence: 0.9})
		if len(batch) == 200 {
			if err := s.d.Inventory.Record(ctx, batch); err != nil {
				t.Fatal(err)
			}
			batch = nil
		}
	}
	capped, err := s.d.Inventory.Devices(ctx) // the premise: the capped list no longer holds the gateway
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(capped.Items, func(d inventory.Device) bool { return d.ID == fg }) {
		t.Fatal("the premise is gone: the capped device list still holds the gateway, so this test proves nothing")
	}
	if !has() {
		t.Errorf("with 2000 newer devices the firewall %s is no longer returned by DevicesOfKind, so it is not never-touch", fg)
	}
}

// D-177 (M5): one passive frame (an SSDP NOTIFY or an LLDP frame that says "router") must not put an intruder's device on the never-touch
// list; a router whose kind came from nmap does, and so does an approved one.
func TestResponseDirectoryIgnoresARouterOnlyAPassiveFrameClaimed(t *testing.T) {
	s := newStack(t)
	ctx := t.Context()
	dir := responseDirectory{inv: s.d.Inventory, fnd: s.d.Findings}
	rec := func(ip, mac string, src observe.Source) {
		a := netip.MustParseAddr(ip)
		h := observe.AssetHint{IP: a, MAC: mac}
		if err := s.d.Inventory.Record(ctx, []observe.Observation{
			{AssetHint: h, Field: observe.MAC, Value: mac, Source: src, Confidence: 0.9},
			{AssetHint: h, Field: observe.Kind, Value: "router", Source: src, Confidence: 0.9},
		}); err != nil {
			t.Fatal(err)
		}
	}
	rec("10.7.0.66", "02:00:00:00:66:66", observe.Passive) // the intruder's InternetGatewayDevice announcement
	rec("10.7.0.1", "02:00:00:00:00:01", observe.Nmap)
	ips := func() []string {
		l, err := dir.DevicesOfKind(ctx, "router", "firewall")
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, d := range l {
			out = append(out, d.IP)
		}
		return out
	}
	if got := ips(); slices.Contains(got, "10.7.0.66") || !slices.Contains(got, "10.7.0.1") {
		t.Fatalf("gateways %v: want the nmap router and not the passive one", got)
	}
	l, err := s.d.Inventory.DevicesOfKind(ctx, []string{"router"})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range l {
		if d.IP == "10.7.0.66" {
			if err := s.d.Inventory.Approve(ctx, "emily@acme.example", d.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got := ips(); !slices.Contains(got, "10.7.0.66") {
		t.Fatalf("gateways %v: an approved router is missing", got)
	}
}
