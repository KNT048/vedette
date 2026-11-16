package inventory_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// #829 (J2): the address is an attribute of a device, never its identity.

const (
	xenMAC = "00:16:3e:5a:01:01" // burned in (Xensource OUI): the N100 C1 walk
	router = "3c:22:fb:00:00:fe" // another device the discovery sweep finds, so the sweep is known to run
)

// sweep is what sensor-active's discovery sweep sends for one host it found on the segment (results.go sweepObservations).
func sweep(mac, ip string) []observe.Observation {
	h := observe.AssetHint{MAC: mac, IP: netip.MustParseAddr(ip)}
	return []observe.Observation{{AssetHint: h, Field: observe.MAC, Value: mac, Source: observe.Nmap, Confidence: 0.9}}
}

// arp is what the passive sensor sends for one ARP sighting of a new MAC, in its order: the card's maker (the OUI table, a MAC-only
// hint) is queued before the ARP that pairs the MAC with its address (sensor-passive capture/engine.go add, queueVendor).
func arp(mac, ip string) []observe.Observation {
	return []observe.Observation{
		{AssetHint: observe.AssetHint{MAC: mac}, Field: observe.Vendor, Value: "Xensource", Source: observe.Passive, Confidence: 0.5},
		{AssetHint: observe.AssetHint{MAC: mac, IP: netip.MustParseAddr(ip)}, Field: observe.MAC, Value: mac, Source: observe.Passive, Confidence: 0.9},
	}
}

func (e *env) device(id string) inventory.Device {
	e.t.Helper()
	d, err := e.svc.Device(e.ctx(), id)
	if err != nil {
		e.t.Fatalf("device %s: %v", id, err)
	}
	return d
}

// C1 (the N100 walk on n70): a device added by hand with its address only binds the MAC first seen at that address, whatever the order
// of the sensor's batch, and then follows that MAC to its new address: one device, its id, approval, notes and software kept, no
// "new device". The bind is audited (inventory.bind_mac).
func TestContract_829_AHandAddedDeviceFollowsItsMAC(t *testing.T) {
	e := newEnv(t)
	id := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.18.201", Name: "nas"})
	notes := "rack 2"
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", id, inventory.Patch{Notes: &notes}); err != nil {
		t.Fatal(err)
	}
	e.ev.reset()
	e.tick(8 * time.Second)
	e.record(arp(xenMAC, "192.168.18.201")...)
	d := e.only()
	if d.ID != id || d.MAC == nil || *d.MAC != xenMAC || d.IP != "192.168.18.201" {
		t.Fatalf("after the first ARP: id %s mac %v ip %s; want %s bound to %s at .201", d.ID, d.MAC, d.IP, id, xenMAC)
	}
	if !has(e.auditActions(), "inventory.bind_mac") {
		t.Errorf("no inventory.bind_mac audit row: %v", e.auditActions())
	}
	e.tick(time.Hour)
	e.record(dhcp(xenMAC, "192.168.18.202", "")...)
	d = e.only()
	if d.ID != id || d.IP != "192.168.18.202" || !d.Approved || d.Origin != "manual" || d.Notes == nil || *d.Notes != notes || len(e.device(id).Software) != 1 {
		t.Errorf("after the move: id %s ip %s approved %v origin %s notes %v software %d; want %s at .202, approved, manual, notes and software kept",
			d.ID, d.IP, d.Approved, d.Origin, d.Notes, len(e.device(id).Software), id)
	}
	if got := e.ev.named(inventory.EventAssetDiscovered); len(got) != 0 {
		t.Errorf("a new device was announced: %v", got)
	}
}

// C2: a discovered device a person approved keeps its id, approval and notes when DHCP moves it.
func TestContract_829_AnApprovedDeviceMoves(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(burnt1, "192.168.18.20", "nas")...)
	id := e.idOf("192.168.18.20")
	if err := e.svc.Approve(e.ctx(), "kien", id); err != nil {
		t.Fatal(err)
	}
	notes := "kien's NAS"
	if err := e.svc.PatchDevice(e.ctx(), "kien", id, inventory.Patch{Notes: &notes}); err != nil {
		t.Fatal(err)
	}
	e.ev.reset()
	e.tick(time.Hour)
	e.record(dhcp(burnt1, "192.168.18.30", "")...)
	d := e.only()
	if d.ID != id || d.IP != "192.168.18.30" || !d.Approved || d.Notes == nil || *d.Notes != notes {
		t.Errorf("after the move: %+v", d.AssetCore)
	}
	if len(e.ev.named(inventory.EventAssetDiscovered)) != 0 {
		t.Error("a new device was announced")
	}
}

// C4 / rule 4: an address DHCP gave to another machine (another MAC) is a new device, announced, which takes the address; the old one,
// hand-added and bound or discovered and approved, keeps its approval and notes and is left without an address until it is seen again.
func TestContract_829_AReusedAddressIsANewDevice(t *testing.T) {
	for _, handAdded := range []bool{true, false} {
		e := newEnv(t)
		var id string
		if handAdded {
			id = e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.18.201"})
			e.record(arp(xenMAC, "192.168.18.201")...)
		} else {
			e.record(arp(xenMAC, "192.168.18.201")...)
			id = e.idOf("192.168.18.201")
			if err := e.svc.Approve(e.ctx(), "kien", id); err != nil {
				t.Fatal(err)
			}
		}
		e.ev.reset()
		e.tick(time.Hour)
		e.record(dhcp(burnt2, "192.168.18.201", "")...)
		if e.devices() != 2 || len(e.ev.named(inventory.EventAssetDiscovered)) != 1 {
			t.Fatalf("hand-added %v: %d devices, %d announced; want 2 and 1", handAdded, e.devices(), len(e.ev.named(inventory.EventAssetDiscovered)))
		}
		if newcomer := e.idOf("192.168.18.201"); newcomer == id || e.device(newcomer).Approved {
			t.Errorf("hand-added %v: the newcomer %s holds the address approved=%v", handAdded, newcomer, e.device(newcomer).Approved)
		}
		if d := e.device(id); !d.Approved || d.IP != "—" || d.MAC == nil || *d.MAC != xenMAC {
			t.Errorf("hand-added %v: the old device: approved %v ip %s mac %v; want approved, no address, %s", handAdded, d.Approved, d.IP, d.MAC, xenMAC)
		}
		// It comes back elsewhere: its own device again.
		e.tick(time.Hour)
		e.record(dhcp(xenMAC, "192.168.18.210", "")...)
		if d := e.device(id); d.IP != "192.168.18.210" || e.devices() != 2 {
			t.Errorf("hand-added %v: back at %s, %d devices", handAdded, d.IP, e.devices())
		}
	}
}

// C5 / gap 2: a report by address only (a version scan, an SNMP read, a software list) reaches the device at that address only while a
// sighting tied the two within ipTrust (3 days), or while the discovery sweep did not run in that time (the passive sensor sees
// broadcasts only: a quiet server is not a stale one; review r1 M2 of #872); past it the report is dropped, never written onto a device that may have left. A device known by its
// address only (a routed subnet) is still found by it. An address-only device past ipTrust does not adopt a MAC
// seen at its address: that MAC is a new device.
func TestContract_829_AnAddressOnlyReportNeedsARecentSighting(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(burnt1, "192.168.18.20", "")...)
	id := e.idOf("192.168.18.20")
	e.tick(71 * time.Hour)
	e.record(byAddress("192.168.18.20", "fresh-name")...)
	if d := e.only(); d.ID != id || d.Hostname == nil || *d.Hostname != "fresh-name" {
		t.Fatalf("within 3 days: id %s name %v", d.ID, d.Hostname)
	}
	e.tick(2 * time.Hour) // 73 h since the MAC was last seen at .20
	e.record(byAddress("192.168.18.20", "quiet-name")...)
	e.record(dhcp(router, "192.168.18.1", "")...) // the passive sensor runs, but sees broadcasts only: a quiet server's silence is no news
	if d := e.device(id); *d.Hostname != "quiet-name" {
		t.Fatalf("no discovery sweep in 3 days: the report must still reach the device, name %v", *d.Hostname)
	}
	e.record(sweep(router, "192.168.18.1")...) // the sweep runs and did not find the device at .20: its silence is news
	e.record(byAddress("192.168.18.20", "stale-name")...)
	if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: netip.MustParseAddr("192.168.18.20")}, observe.Nmap,
		[]observe.Software{{Display: "OpenSSH 9.6", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6", Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	if d := e.device(id); *d.Hostname != "quiet-name" || len(d.Software) != 0 {
		t.Errorf("past 3 days: name %v software %d; want the address-only reports dropped", *d.Hostname, len(e.device(id).Software))
	}
	// The MAC seen there again confirms the address: reports by address reach the device again.
	e.tick(time.Minute) // a newer name than quiet-name (same source and confidence: the newer wins)
	e.record(dhcp(burnt1, "192.168.18.20", "")...)
	e.record(byAddress("192.168.18.20", "stale-name")...)
	if d := e.device(id); *d.Hostname != "stale-name" {
		t.Errorf("after the MAC was seen again: name %v", *d.Hostname)
	}

	// Known by its address only (no MAC ever): found by it at any age.
	e.record(byAddress("10.20.0.5", "router-b")...)
	routed := e.idOf("10.20.0.5")
	e.tick(30 * 24 * time.Hour)
	e.record(byAddress("10.20.0.5", "router-b2")...)
	if d := e.device(routed); d.Hostname == nil || *d.Hostname != "router-b2" {
		t.Errorf("an address-only device: name %v", d.Hostname)
	}
	// ... but past 3 days with no sighting it adopts no MAC: the MAC is a new device, which takes the address.
	e.tick(73 * time.Hour)
	e.record(dhcp(burnt2, "10.20.0.5", "")...)
	if n := e.idOf("10.20.0.5"); n == routed || e.device(routed).MAC != nil {
		t.Errorf("a stale address-only device adopted the MAC (holder %s, old %s)", n, routed)
	}
}

// Gap 2: within ipTrust an address-only device adopts the MAC seen at its address (the same device, first time its MAC is known).
func TestContract_829_ARecentAddressOnlyDeviceAdoptsItsMAC(t *testing.T) {
	e := newEnv(t)
	e.record(byAddress("192.168.18.40", "printer")...)
	id := e.idOf("192.168.18.40")
	e.tick(time.Hour)
	e.record(arp(burnt2, "192.168.18.40")...)
	if d := e.only(); d.ID != id || d.MAC == nil || *d.MAC != burnt2 {
		t.Errorf("device %s mac %v; want %s with %s", d.ID, d.MAC, id, burnt2)
	}
}

// Gap 6 (C3): a sensor that sees an agent-bound machine at its new address before the agent's next report is a DHCP move, not a spoof:
// the report from that address keeps the binding. (A report from another address than the one the sensor saw is still a spoof's:
// TestContract_D598_ASpoofedBindingIsDropped.) A report by the agent's key alone (AssetHint.From) reaches the device only at the
// address a sensor saw it at, and moves nothing.
func TestContract_829_AnAgentFollowsADHCPMoveASensorSawFirst(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(burnt1, "192.168.18.20", "")...)
	id := e.idOf("192.168.18.20")
	e.record(osq("192.168.18.20")...)
	bound := func() bool {
		return e.count(`SELECT count(*) FROM inv_asset WHERE id = ? AND agent_key = 'osquery:node-a'`, id) == 1
	}
	if !bound() {
		t.Fatal("setup: not bound")
	}
	e.tick(time.Hour)
	e.record(dhcp(burnt1, "192.168.18.30", "")...) // the sensor sees the move first
	e.tick(time.Minute)
	// a report that names no MAC (a software list, the enrolment's name): the binding is not made again in the same batch
	e.record(observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("192.168.18.30"), Agent: "osquery:node-a"},
		Field: observe.Hostname, Value: "build01", Source: observe.Agent, Confidence: 0.9})
	if d := e.only(); d.ID != id || d.IP != "192.168.18.30" || !bound() {
		t.Errorf("after the report from the new address: id %s ip %s bound %v", d.ID, d.IP, bound())
	}

	e.tick(time.Hour)
	e.record(dhcp(burnt1, "192.168.18.40", "")...) // moved again, seen by the sensor
	e.tick(time.Minute)
	byKey := func(from, os string) {
		e.record(observe.Observation{AssetHint: observe.AssetHint{Agent: "osquery:node-a", From: netip.MustParseAddr(from)},
			Field: observe.OS, Value: os, Source: observe.Agent, Confidence: 0.95})
	}
	byKey("192.168.18.77", "Ubuntu 26.04") // not where the device is: nothing
	if d := e.only(); d.OS == nil || d.OS.Value != "Ubuntu 24.04" {
		t.Errorf("a key-only report from another address wrote %v", d.OS)
	}
	byKey("192.168.18.40", "Ubuntu 26.04")
	if d := e.only(); d.OS == nil || d.OS.Value != "Ubuntu 26.04" || d.IP != "192.168.18.40" || !bound() {
		t.Errorf("a key-only report from the device's address: os %v ip %s bound %v", d.OS, d.IP, bound())
	}
}

// Gap 2 for an agent that names no binding yet: at an address whose device no sighting confirmed within ipTrust, the agent's report goes
// to that device only when the agent reports that device's card (its own machine, then bound); an agent with a card of its own is a
// machine of its own (rule 4): a new device takes the address, the old one keeps its approval.
func TestContract_829_AnAgentAtAStaleAddress(t *testing.T) {
	for _, own := range []bool{true, false} {
		e := newEnv(t)
		card := burnt1
		if !own {
			card = burnt2
		}
		e.record(dhcp(burnt1, "192.168.18.20", "")...)
		id := e.idOf("192.168.18.20")
		if err := e.svc.Approve(e.ctx(), "kien", id); err != nil {
			t.Fatal(err)
		}
		e.tick(73 * time.Hour)
		e.record(sweep(router, "192.168.18.1")...) // the sweep runs
		h := observe.AssetHint{IP: netip.MustParseAddr("192.168.18.20"), Agent: "osquery:node-a"}
		e.record(observe.Observation{AssetHint: h, Field: observe.Hostname, Value: "build01", Source: observe.Agent, Confidence: 0.9},
			observe.Observation{AssetHint: h, Field: observe.MAC, Value: card, Source: observe.Agent, Confidence: 0.9})
		holder := e.idOf("192.168.18.20")
		switch {
		case own && (holder != id || e.devices() != 2): // and the router
			t.Errorf("its own card: holder %s (want %s), %d devices", holder, id, e.devices())
		case !own && (holder == id || e.devices() != 3 || !e.device(id).Approved || e.device(id).IP != "—"):
			t.Errorf("another card: holder %s (old %s), %d devices, old %+v", holder, id, e.devices(), e.device(id).AssetCore)
		}
		if e.count(`SELECT count(*) FROM inv_asset WHERE id = ? AND agent_key = 'osquery:node-a'`, holder) != 1 {
			t.Errorf("own %v: the address's device is not bound to the agent", own)
		}
	}
}

// A hint with only an agent is refused unless the source is an agent; From goes only with an agent and no address.
func TestContract_829_FromOnlyWithAnAgent(t *testing.T) {
	e := newEnv(t)
	for _, h := range []observe.AssetHint{
		{From: netip.MustParseAddr("192.168.18.30")},
		{IP: netip.MustParseAddr("192.168.18.30"), Agent: "osquery:node-a", From: netip.MustParseAddr("192.168.18.31")},
		{Agent: "osquery:node-a", From: netip.MustParseAddr("fd00::1")},
	} {
		if err := e.svc.Record(e.ctx(), []observe.Observation{{AssetHint: h, Field: observe.OS, Value: "x", Source: observe.Agent, Confidence: 0.5}}); err == nil {
			t.Errorf("%+v: accepted", h)
		}
	}
	// an agent-only hint of an unbound agent writes nothing
	if err := e.svc.Record(e.ctx(), []observe.Observation{{AssetHint: observe.AssetHint{Agent: "osquery:node-z"}, Field: observe.OS, Value: "x", Source: observe.Agent, Confidence: 0.5}}); err != nil || e.devices() != 0 {
		t.Errorf("unbound agent: %v, %d devices", err, e.devices())
	}
	if err := e.svc.Record(e.ctx(), []observe.Observation{{AssetHint: observe.AssetHint{Agent: "osquery:node-z"}, Field: observe.OS, Value: "x", Source: observe.Passive, Confidence: 0.5}}); err == nil {
		t.Error("a sensor's agent-only hint was accepted")
	}
}

// Review r1 H2 of #872: a hand-added device binds a MAC by its address alone only when the MAC is burned in and a person declared the
// address within 3 days. A private MAC (a guest phone given that lease) and any MAC at an address declared longer ago are a new,
// announced device; the old declaration gives the address to it, a recent one keeps it.
func TestContract_829_AHandAddedDeviceBindsOnlyABurnedInMACSoon(t *testing.T) {
	cases := []struct {
		name     string
		mac      string
		age      time.Duration
		keepsIP  bool
		newcomer bool
	}{
		{"burned-in MAC within 3 days", xenMAC, time.Hour, true, false},
		{"private MAC (a guest phone)", privMac1, time.Hour, true, true},
		{"burned-in MAC a month later", xenMAC, 30 * 24 * time.Hour, false, true},
	}
	for _, tc := range cases {
		e := newEnv(t)
		id := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.18.201", Name: "nas"})
		e.ev.reset()
		e.tick(tc.age)
		e.record(byAddress("192.168.18.201", "nas")...) // something answering at the address is not the person's word: no new window
		e.record(arp(tc.mac, "192.168.18.201")...)
		d := e.device(id)
		bound := d.MAC != nil && *d.MAC == tc.mac
		if bound == tc.newcomer || (len(e.ev.named(inventory.EventAssetDiscovered)) == 1) != tc.newcomer {
			t.Errorf("%s: bound %v, %d announced; want a newcomer %v", tc.name, bound, len(e.ev.named(inventory.EventAssetDiscovered)), tc.newcomer)
		}
		if (d.IP == "192.168.18.201") != tc.keepsIP {
			t.Errorf("%s: the hand-added device is at %s", tc.name, d.IP)
		}
	}
}

// Review r1 M1 of #872 (the n70 data on the N100): the MAC of a hand-added device was seen before its address (a MAC-only hint in an
// earlier batch, an LLDP frame), so a waiting discovered device holds it with no address. The next sighting of that MAC at the
// hand-added address folds the waiting one into the hand-added device: one device, the hand-added id, approval and name, the MAC, the
// address; the waiting one is announced merged then deleted, so its "new device" incident closes.
func TestContract_829_AWaitingDuplicateJoinsTheHandAddedDevice(t *testing.T) {
	e := newEnv(t)
	id := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.18.201", Name: "nas"})
	e.record(arp(xenMAC, "192.168.18.201")[:1]...) // the vendor alone, in a batch of its own
	dup := e.idByMAC(xenMAC)
	if dup == id || e.devices() != 2 {
		t.Fatalf("setup: %d devices", e.devices())
	}
	e.ev.reset()
	e.tick(time.Minute)
	e.record(dhcp(xenMAC, "192.168.18.201", "")...)
	d := e.only()
	if d.ID != id || d.MAC == nil || *d.MAC != xenMAC || d.IP != "192.168.18.201" || !d.Approved || d.Origin != "manual" || d.Vendor == nil {
		t.Errorf("after the sighting: %+v", d.AssetCore)
	}
	merged := e.ev.named(inventory.EventAssetMerged)
	if len(merged) != 1 || merged[0].Data.(inventory.MergeEvent).From != dup || len(e.ev.named(inventory.EventAssetDeleted)) != 1 {
		t.Errorf("events: merged %+v deleted %d", merged, len(e.ev.named(inventory.EventAssetDeleted)))
	}
	e.tick(time.Hour)
	e.record(dhcp(xenMAC, "192.168.18.202", "")...)
	if d := e.only(); d.ID != id || d.IP != "192.168.18.202" {
		t.Errorf("after the move: id %s ip %s", d.ID, d.IP)
	}
	// A private MAC, or an approved device, is never folded by an address alone.
	for _, approved := range []bool{false, true} {
		e := newEnv(t)
		hand := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.18.201"})
		mac := privMac1
		e.record(arp(mac, "192.168.18.201")[:1]...)
		if approved {
			mac = xenMAC
			e.record(arp(mac, "192.168.18.201")[:1]...)
			if err := e.svc.Approve(e.ctx(), "kien", e.idByMAC(mac)); err != nil {
				t.Fatal(err)
			}
		}
		e.record(dhcp(mac, "192.168.18.201", "")...)
		if e.count(`SELECT count(*) FROM inv_asset WHERE id = ? AND mac IS NULL`, hand) != 1 || e.count(`SELECT count(*) FROM inv_asset WHERE mac = ?`, mac) != 1 ||
			e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ? AND field = 'mac'`, hand) != 0 {
			t.Errorf("approved %v: the hand-added device took %s", approved, mac)
		}
	}
}

// Review r1 L1 of #872: a list (software, services) at an address whose device the sweep has not seen there for 3 days makes no device,
// even an agent's: an announced duplicate would go out before the agent's next observation batch.
func TestContract_829_AListAtAStaleAddressMakesNoDevice(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(burnt1, "192.168.18.20", "")...)
	e.tick(73 * time.Hour)
	e.record(sweep(router, "192.168.18.1")...)
	e.ev.reset()
	if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: netip.MustParseAddr("192.168.18.20"), Agent: "osquery:node-a"}, observe.Agent,
		[]observe.Software{{Display: "OpenSSH 9.6", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6", Confidence: 0.95}}); err != nil {
		t.Fatal(err)
	}
	if e.devices() != 2 || len(e.ev.named(inventory.EventAssetDiscovered)) != 0 {
		t.Errorf("%d devices, %d announced; want 2 and none", e.devices(), len(e.ev.named(inventory.EventAssetDiscovered)))
	}
}
