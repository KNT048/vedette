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
