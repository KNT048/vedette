package logs

import (
	"testing"
)

func withInv(e *env, inv fakeInv) { e.svc.cfg.Inventory = inv }

// A firewall is listed at 192.168.10.1 and its SNMP is read from its management address 192.168.20.1: a source declared at the
// management address is that firewall, said with the address that matched.
func TestSourceMatchesADeviceByItsSNMPReadAddress(t *testing.T) {
	e := newEnv(t)
	withInv(e, fakeInv{at: map[string][]DeviceMatch{"192.168.20.1": {{Device: Device{ID: "a-fw", Name: "Edge firewall"}, Via: ViaSNMPRead}}}})
	s := e.add("FW-MGMT", "192.168.20.1")
	if s.AssetID == nil || *s.AssetID != "a-fw" || *s.AssetName != "Edge firewall" {
		t.Fatalf("device = %v %v, want a-fw Edge firewall", s.AssetID, s.AssetName)
	}
	if s.AssetVia == nil || *s.AssetVia != ViaSNMPRead || len(s.AssetMatches) != 0 {
		t.Errorf("via = %v matches = %v, want snmp_read and none", s.AssetVia, s.AssetMatches)
	}
}

// The listed IP says nothing about how it matched.
func TestSourceAtTheListedIPHasNoVia(t *testing.T) {
	e := newEnv(t)
	s := e.add("FW-HQ", "192.168.10.1")
	if s.AssetID == nil || s.AssetVia != nil {
		t.Errorf("device = %v via = %v, want a device and no via", s.AssetID, s.AssetVia)
	}
}

// An address two devices have names both and neither alone: the customer picks.
func TestSourceAtAnAddressOfTwoDevicesNamesBoth(t *testing.T) {
	e := newEnv(t)
	withInv(e, fakeInv{
		byIP: map[string]Device{"192.168.10.9": {ID: "a-1", Name: "Core switch"}},
		at:   map[string][]DeviceMatch{"192.168.10.9": {{Device: Device{ID: "a-2", Name: "Edge firewall"}, Via: ViaSNMPRead}}},
	})
	s := e.add("SW", "192.168.10.9")
	if s.AssetID != nil || s.AssetName != nil {
		t.Fatalf("picked %v %v, want no single device", s.AssetID, s.AssetName)
	}
	if len(s.AssetMatches) != 2 || s.AssetMatches[0].ID != "a-1" || s.AssetMatches[0].Via != nil || s.AssetMatches[1].ID != "a-2" || *s.AssetMatches[1].Via != ViaSNMPRead {
		t.Errorf("matches = %+v, want a-1 (listed) and a-2 (snmp_read)", s.AssetMatches)
	}
}

// No device at the address: nothing is named and the list is empty, not null.
func TestSourceWithNoDeviceHasNoMatches(t *testing.T) {
	e := newEnv(t)
	s := e.add("Unknown", "192.168.10.77")
	if s.AssetID != nil || s.AssetMatches == nil || len(s.AssetMatches) != 0 {
		t.Errorf("device = %v matches = %#v, want none and an empty list", s.AssetID, s.AssetMatches)
	}
}

// A bad connection names its device by any address too, but never guesses between two.
func TestBadConnectionNamesNoDeviceWhenTwoHaveTheAddress(t *testing.T) {
	e := newEnv(t)
	withInv(e, fakeInv{
		byIP: map[string]Device{"192.168.10.9": {ID: "a-1", Name: "Core switch"}, "192.168.10.5": {ID: "a-3", Name: "Reception PC"}},
		at: map[string][]DeviceMatch{
			"192.168.10.9": {{Device: Device{ID: "a-2", Name: "Edge firewall"}, Via: ViaSNMPRead}},
			"192.168.20.1": {{Device: Device{ID: "a-4", Name: "Branch router"}, Via: ViaSNMPRead}},
		},
	})
	got := e.svc.assetsFor(t.Context(), []string{"192.168.10.9", "192.168.10.5", "192.168.20.1"})
	if _, ok := got["192.168.10.9"]; ok {
		t.Errorf("named a device for an address two have: %+v", got)
	}
	if got["192.168.10.5"].ID != "a-3" || got["192.168.20.1"].ID != "a-4" {
		t.Errorf("devices = %+v, want a-3 by listed IP and a-4 by its read address", got)
	}
}

// An incident about a sender names the device at its read address, and both devices when two have the address.
func TestIncidentNamesEveryDeviceAtTheAddress(t *testing.T) {
	e := newEnv(t)
	withInv(e, fakeInv{
		byIP: map[string]Device{"192.168.10.9": {ID: "a-1", Name: "Core switch"}},
		at:   map[string][]DeviceMatch{"192.168.10.9": {{Device: Device{ID: "a-2", Name: "Edge firewall"}, Via: ViaSNMPRead}}},
	})
	got := e.svc.devicesOf(t.Context(), sourceRow{SenderIP: "192.168.10.9"})
	if len(got) != 2 || got[0].ID != "a-1" || got[1].ID != "a-2" {
		t.Errorf("devices = %+v, want a-1 and a-2", got)
	}
}
