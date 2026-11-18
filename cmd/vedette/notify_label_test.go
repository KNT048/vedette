package main

import (
	"context"
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/logs"
	"github.com/knt048/vedette/modules/notify"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// A new-device incident names the device as the Devices page does (inventory's one naming rule: here the
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

// DeviceRefs puts the kind in Display when a device has no software, so a declared device (named after its first
// product) whose Display equals its kind is not named from the ref: DeviceStates asks inventory.Names, as the Devices page names it.
func TestRefNameOfADeclaredDeviceWhoseProductIsItsKind(t *testing.T) {
	t.Parallel()
	if _, sure := refName(inventory.DeviceRef{Origin: "manual", Kind: "firewall", Display: "firewall", IP: "192.168.30.1"}); sure {
		t.Error("a declared device whose Display is its kind was named from the ref")
	}
	if n, sure := refName(inventory.DeviceRef{Origin: "discovered", Kind: "switch", Display: "switch", Vendor: "Juniper Networks", IP: "—"}); !sure || n != "Juniper Networks" {
		t.Errorf("discovered device = %q, %v", n, sure)
	}
}

// A vulnerability notice and a log incident name the device as the Devices page does: a PC with no host name is
// "Hon Hai Precision Ind. Co.,Ltd.", not its bare IP; the notice adds the address, like the new-device incident.
func TestFindingAndLogIncidentsUseTheDevicesName(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	const pc, ip = "aa:bb:cc:00:00:21", "192.168.18.181"
	if err := s.d.Inventory.Record(ctx, []observe.Observation{
		{AssetHint: observe.AssetHint{MAC: pc, IP: netip.MustParseAddr(ip)}, Field: observe.Vendor, Value: "Hon Hai Precision Ind. Co.,Ltd.", Source: observe.Passive, Confidence: 0.4},
	}); err != nil {
		t.Fatal(err)
	}
	l, err := s.d.Inventory.Devices(ctx)
	if err != nil || len(l.Items) != 1 {
		t.Fatalf("devices %+v %v", l, err)
	}
	id, want := l.Items[0].ID, "Hon Hai Precision Ind. Co.,Ltd. ("+ip+")"
	if name, ok, err := (notifyDevices{s.d.Inventory}).DeviceName(ctx, id); err != nil || !ok || name != want {
		t.Errorf("notice name %q %v %v, want %q", name, ok, err, want)
	}
	got, err := logsInventory{inv: s.d.Inventory}.DevicesAt(ctx, []string{ip, "192.168.18.9"})
	if err != nil || len(got) != 1 || len(got[ip]) != 1 || got[ip][0].ID != id || got[ip][0].Name != "Hon Hai Precision Ind. Co.,Ltd." || got[ip][0].Via != logs.ViaListedIP {
		t.Errorf("log device %+v %v, want %s and the Devices name", got, err, id)
	}
	// The address the device's SNMP is read from is the device too, and says so; the same device at its listed IP is not said twice.
	// An address two devices have returns both.
	other := "192.168.18.182"
	if err := s.d.Inventory.Record(ctx, []observe.Observation{
		{AssetHint: observe.AssetHint{MAC: "aa:bb:cc:00:00:22", IP: netip.MustParseAddr(other)}, Field: observe.Vendor, Value: "Acme", Source: observe.Passive, Confidence: 0.4},
	}); err != nil {
		t.Fatal(err)
	}
	l, err = s.d.Inventory.Devices(ctx)
	if err != nil || len(l.Items) != 2 {
		t.Fatalf("devices %+v %v", l, err)
	}
	otherID := l.Items[0].ID
	if otherID == id {
		otherID = l.Items[1].ID
	}
	mgmt := netip.MustParseAddr("10.9.9.1")
	snmp := func(context.Context) ([]sensoractive.SNMPDevice, error) {
		return []sensoractive.SNMPDevice{
			{DeviceID: id, ReadFrom: mgmt},
			{DeviceID: otherID, ReadFrom: mgmt},
			{DeviceID: id, ReadFrom: netip.MustParseAddr(ip)},
			{DeviceID: "gone", ReadFrom: netip.MustParseAddr("10.9.9.2")},
		}, nil
	}
	got, err = logsInventory{inv: s.d.Inventory, snmp: snmp}.DevicesAt(ctx, []string{ip, "10.9.9.1", "10.9.9.2"})
	if err != nil || len(got) != 2 || len(got[ip]) != 1 || got[ip][0].Via != logs.ViaListedIP {
		t.Fatalf("by address %+v %v, want the listed IP once and no device for a deleted one", got, err)
	}
	if m := got["10.9.9.1"]; len(m) != 2 || m[0].Via != logs.ViaSNMPRead || m[1].Via != logs.ViaSNMPRead || m[0].ID == m[1].ID {
		t.Errorf("read address %+v, want both devices, via snmp_read", m)
	}
}
