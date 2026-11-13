package main

import (
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/notify"
)

// Walk 4 and D-552 (W8-2): a new-device incident names the device as the Devices page does (inventory's one naming rule: here the
// vendor, else the IP), with its address (the IP, else the MAC) beside it, never the bare kind "switch".
func TestDeviceStateOfANewDevice(t *testing.T) {
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
	want := map[string]notify.DeviceState{sw: {Name: "Juniper Networks", Address: sw}, cam: {Name: "192.168.18.254", Address: "192.168.18.254"}}
	ids := map[string]string{}
	for _, d := range l.Items {
		if d.MAC != nil && want[*d.MAC].Name != "" {
			ids[*d.MAC] = d.ID
		}
	}
	dir := notifyDevices{s.d.Inventory}
	all, err := dir.DeviceStates(ctx, []string{ids[sw], ids[cam], "no-such-device"}) // the job's batch read
	if err != nil || len(all) != 2 {
		t.Fatalf("batch = %+v, %v", all, err)
	}
	for mac, w := range want {
		one, err := dir.DeviceStates(ctx, []string{ids[mac]}) // the event's read of one device
		if err != nil || one[ids[mac]] != w || all[ids[mac]] != w {
			t.Errorf("%s: one %+v, batch %+v, %v; want %+v", mac, one[ids[mac]], all[ids[mac]], err, w)
		}
	}
	if one, err := dir.DeviceStates(ctx, []string{"no-such-device"}); len(one) != 0 || err != nil {
		t.Errorf("a device the inventory does not have: %+v %v", one, err)
	}
}
