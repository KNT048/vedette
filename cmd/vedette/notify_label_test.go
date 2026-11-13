package main

import (
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
)

// Walk 4: new devices seen only by the passive sensor opened "A new unknown device appeared: switch". The label is the
// IP, else the MAC, with the vendor; a host name stays as it is.
func TestDeviceLabelOfANewDevice(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	const sw, cam = "aa:bb:cc:00:00:11", "aa:bb:cc:00:00:12"
	if err := s.d.Inventory.Record(ctx, []observe.Observation{
		{AssetHint: observe.AssetHint{MAC: sw}, Field: observe.Kind, Value: "switch", Source: observe.Passive, Confidence: 0.6},
		{AssetHint: observe.AssetHint{MAC: sw}, Field: observe.Vendor, Value: "Juniper Networks", Source: observe.Passive, Confidence: 0.4},
		{AssetHint: observe.AssetHint{MAC: cam, IP: netip.MustParseAddr("192.168.18.254")}, Field: observe.MAC, Value: cam, Source: observe.Passive, Confidence: 0.9},
	}); err != nil {
		t.Fatal(err)
	}
	l, err := s.d.Inventory.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{sw: sw + " (Juniper Networks)", cam: "192.168.18.254"}
	for _, d := range l.Items {
		if d.MAC == nil || want[*d.MAC] == "" {
			continue
		}
		if got, ok, err := (notifyDevices{s.d.Inventory}).DeviceLabel(ctx, d.ID); err != nil || !ok || got != want[*d.MAC] {
			t.Errorf("%s: label %q %v %v, want %q", *d.MAC, got, ok, err, want[*d.MAC])
		}
		delete(want, *d.MAC)
	}
	if len(want) != 0 {
		t.Errorf("devices not listed: %v", want)
	}
}
