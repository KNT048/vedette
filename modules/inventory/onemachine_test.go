package inventory_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// kien's MacBook on the N100 (issue #829): macOS's private Wi-Fi address b2:f0:09:… has the locally administered bit set, so every
// new address made a new device and a "new unknown device" incident.
const (
	privMac1 = "b2:f0:09:23:2e:5b"
	privMac2 = "b2:f0:09:77:10:01"
	privMac3 = "b2:f0:09:77:10:02"
	burnt1   = "3c:22:fb:00:00:01" // Apple OUI, universally administered
	burnt2   = "3c:22:fb:00:00:02"
)

// dhcp is what the passive sensor sends for one DHCP request: the MAC and address, and the host name the client sends (option 12).
func dhcp(mac, ip, name string) []observe.Observation {
	h := observe.AssetHint{MAC: mac, IP: netip.MustParseAddr(ip)}
	list := []observe.Observation{{AssetHint: h, Field: observe.MAC, Value: mac, Source: observe.Passive, Confidence: 0.9}}
	if name != "" {
		list = append(list, observe.Observation{AssetHint: h, Field: observe.Hostname, Value: name, Source: observe.Passive, Confidence: 0.7})
	}
	return list
}

// byAddress is what a scan of a routed subnet sends: an address and its reverse-DNS name, no MAC.
func byAddress(ip, name string) []observe.Observation {
	return []observe.Observation{{AssetHint: observe.AssetHint{IP: netip.MustParseAddr(ip)}, Field: observe.Hostname, Value: name, Source: observe.Nmap, Confidence: 0.6}}
}

// osq is what agent-intake sends for one report of osquery node node-a (host build01, card burnt1) from ip: its host name, OS and the MAC of its card, hinted by address and node.
func osq(ip string) []observe.Observation {
	h := observe.AssetHint{IP: netip.MustParseAddr(ip), Agent: "osquery:node-a"}
	return []observe.Observation{
		{AssetHint: h, Field: observe.Hostname, Value: "build01", Source: observe.Agent, Confidence: 0.9},
		{AssetHint: h, Field: observe.OS, Value: "Ubuntu 24.04", Source: observe.Agent, Confidence: 0.95},
		{AssetHint: h, Field: observe.MAC, Value: burnt1, Source: observe.Agent, Confidence: 0.9},
	}
}

func (e *env) only() inventory.Device {
	e.t.Helper()
	if n := e.devices(); n != 1 {
		e.t.Fatalf("%d devices, want one", n)
	}
	var id string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT id FROM inv_asset WHERE is_box = 0`).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	d, err := e.svc.Device(e.ctx(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

// D-598 (1): a laptop whose private Wi-Fi address changes, with a new address from DHCP, stays one device: the approved one keeps its
// id and approval and takes the newest address and MAC; no "new device" goes out. One that first shows up by ARP alone (no name yet) is
// announced, then joined when its name arrives: merged, then deleted, so notify closes its incident.
func TestContract_D598_APrivateWiFiAddressIsOneDevice(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(privMac1, "192.168.18.145", "Kiens-MacBook-Air")...)
	id := e.idOf("192.168.18.145")
	if err := e.svc.Approve(e.ctx(), "kien", id); err != nil {
		t.Fatal(err)
	}
	e.ev.reset()
	e.tick(time.Hour)
	e.record(dhcp(privMac2, "192.168.18.138", "kiens-macbook-air.local")...)
	d := e.only()
	if d.ID != id || !d.Approved || d.IP != "192.168.18.138" || d.MAC == nil || *d.MAC != privMac2 {
		t.Errorf("joined device: id %s approved %v ip %s mac %v; want %s, approved, .138, %s", d.ID, d.Approved, d.IP, d.MAC, id, privMac2)
	}
	if got := e.ev.named(inventory.EventAssetDiscovered); len(got) != 0 {
		t.Errorf("a new device was announced: %v", got)
	}
	if !has(e.auditActions(), "inventory.merge") {
		t.Errorf("no inventory.merge audit row: %v", e.auditActions())
	}

	// ARP first: a new device, announced; the name a minute later joins it.
	e.ev.reset()
	e.tick(time.Hour)
	e.record(dhcp(privMac3, "192.168.18.137", "")...)
	if e.devices() != 2 || len(e.ev.named(inventory.EventAssetDiscovered)) != 1 {
		t.Fatalf("ARP only: %d devices, %d announced; want 2 and 1", e.devices(), len(e.ev.named(inventory.EventAssetDiscovered)))
	}
	arpID := e.idOf("192.168.18.137")
	e.tick(time.Minute)
	e.record(dhcp(privMac3, "192.168.18.137", "Kiens-MacBook-Air")...)
	d = e.only()
	if d.ID != id || d.IP != "192.168.18.137" || !d.Approved {
		t.Errorf("after the name: id %s ip %s approved %v", d.ID, d.IP, d.Approved)
	}
	merged := e.ev.named(inventory.EventAssetMerged)
	if len(merged) != 1 || merged[0].Data.(inventory.MergeEvent).From != arpID || merged[0].Data.(inventory.MergeEvent).Into != id {
		t.Errorf("merged events: %+v, want %s into %s", merged, arpID, id)
	}
	if len(e.ev.named(inventory.EventAssetDeleted)) != 1 {
		t.Errorf("deleted events: %v", e.ev.named(inventory.EventAssetDeleted))
	}
	// The same MAC again finds the device: no new row.
	e.record(dhcp(privMac3, "192.168.18.137", "Kiens-MacBook-Air")...)
	e.only()
}

// D-598 (1): what a host name alone must not join. Two machines with burned-in MACs and one name are two devices (a re-imaged PC next
// to the old one), and so are two rows known only by address (a server with two addresses); a private address never joins a device with a burned-in MAC (an intruder naming itself after a server stays new
// and is announced); a generic name ("iPhone", "localhost") or a name made of an address joins nothing; three rows of one name join
// nothing (which two?).
func TestContract_D598_WhatANameAloneDoesNotJoin(t *testing.T) {
	cases := []struct {
		name  string
		first []observe.Observation
		then  []observe.Observation
		more  []observe.Observation
	}{
		{"two burned-in MACs", dhcp(burnt1, "192.168.18.10", "accounting-pc"), dhcp(burnt2, "192.168.18.11", "accounting-pc"), nil},
		{"private address and a burned-in MAC", dhcp(burnt1, "192.168.18.10", "nas01"), dhcp(privMac1, "192.168.18.11", "nas01"), nil},
		{"generic name", dhcp(privMac1, "192.168.18.10", "iPhone"), dhcp(privMac2, "192.168.18.11", "iPhone"), nil},
		{"localhost", dhcp(privMac1, "192.168.18.10", "localhost"), dhcp(privMac2, "192.168.18.11", "localhost.localdomain"), nil},
		{"name from the address", dhcp(privMac1, "192.168.18.10", "dhcp-192-168-18-10"), dhcp(privMac2, "192.168.18.11", "dhcp-192-168-18-10"), nil},
		{"two rows known only by address", byAddress("10.20.0.5", "erp01"), byAddress("10.20.0.6", "erp01"), nil},
		{"three rows of one name", dhcp(burnt1, "192.168.18.10", "lab"), dhcp(burnt2, "192.168.18.11", "lab"), dhcp(privMac1, "192.168.18.12", "lab")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.record(c.first...)
			e.tick(time.Minute)
			e.record(c.then...)
			want := 2
			if c.more != nil {
				e.tick(time.Minute)
				e.record(c.more...)
				want = 3
			}
			if n := e.devices(); n != want {
				t.Errorf("%d devices, want %d", n, want)
			}
		})
	}
}

// D-598 (1): a row a person declared stays; the discovered row of the same machine joins it and the declared address stays.
func TestContract_D598_ADeclaredDeviceKeepsItsAddress(t *testing.T) {
	e := newEnv(t)
	id := e.addDevice(inventory.AddInput{CatalogID: "microsoft-office-desktop", Name: "reception-pc", IP: "192.168.18.50"})
	e.record(dhcp(privMac1, "192.168.18.60", "RECEPTION-PC")...)
	d := e.only()
	if d.ID != id || d.IP != "192.168.18.50" || d.Origin != "manual" {
		t.Errorf("device: id %s ip %s origin %s, want the declared one at .50", d.ID, d.IP, d.Origin)
	}
}

// D-598 (2): an osquery node is bound to the device its first report reached by address (the device a scan found), and its later
// reports find that device when the machine's address changes: still one device, at the new address.
func TestContract_D598_AnAgentFollowsItsDevice(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(burnt1, "192.168.18.20", "")...)
	id := e.idOf("192.168.18.20")
	e.tick(time.Minute)
	e.record(osq("192.168.18.20")...)
	if e.devices() != 1 || e.count(`SELECT count(*) FROM inv_asset WHERE id = ? AND agent_key = 'osquery:node-a'`, id) != 1 {
		t.Fatalf("after the first report: %d devices, agent bound %d", e.devices(), e.count(`SELECT count(*) FROM inv_asset WHERE agent_key IS NOT NULL`))
	}
	e.tick(time.Hour)
	e.record(osq("192.168.18.30")...)
	d := e.only()
	if d.ID != id || d.IP != "192.168.18.30" {
		t.Errorf("after the move: id %s ip %s, want %s at .30", d.ID, d.IP, id)
	}
	// Its software list goes to the same device.
	if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: netip.MustParseAddr("192.168.18.30"), Agent: "osquery:node-a"}, observe.Agent,
		[]observe.Software{{Display: "OpenSSH 9.6", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6", Confidence: 0.95}}); err != nil {
		t.Fatal(err)
	}
	e.only()
}

// D-598 (2): a node reporting on an address that another machine held (a row seen with another MAC) is not bound to that row.
func TestContract_D598_AnAgentIsNotBoundToAnotherMachinesRow(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(burnt2, "192.168.18.20", "")...)
	e.tick(time.Minute)
	e.record(osq("192.168.18.20")...)
	if n := e.count(`SELECT count(*) FROM inv_asset WHERE agent_key IS NOT NULL`); n != 0 {
		t.Errorf("%d rows bound to the node, want none", n)
	}
}

// D-598 (2): a node that reports from an address no device held makes a row; when a sensor then sees the machine's MAC at that
// address, that row joins the machine's device (its agent said that MAC, and lost the address to it): one device, and the node's
// next report finds it.
func TestContract_D598_AnAgentsRowJoinsItsMachine(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(burnt1, "192.168.18.20", "")...)
	id := e.idOf("192.168.18.20")
	e.tick(time.Hour)
	e.record(osq("192.168.18.40")...)
	if e.devices() != 2 {
		t.Fatalf("%d devices before a sensor sees the move, want 2", e.devices())
	}
	e.tick(time.Minute)
	e.record(dhcp(burnt1, "192.168.18.40", "")...)
	d := e.only()
	if d.ID != id || d.IP != "192.168.18.40" || d.Hostname == nil || *d.Hostname != "build01" {
		t.Errorf("device: id %s ip %s name %v", d.ID, d.IP, d.Hostname)
	}
	e.tick(time.Minute)
	e.record(osq("192.168.18.40")...)
	if d := e.only(); d.ID != id {
		t.Errorf("the next report went to %s, want %s", d.ID, id)
	}
}

// D-598: only an agent's report names an agent, in the shape core/observe gives it; a sensor's is refused before any write.
func TestContract_D598_OnlyAnAgentNamesAnAgent(t *testing.T) {
	e := newEnv(t)
	for _, o := range []observe.Observation{
		{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("192.168.18.20"), Agent: "osquery:node-a"}, Field: observe.Hostname, Value: "x1", Source: observe.Passive, Confidence: 0.5},
		{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("192.168.18.20"), Agent: "osquery node"}, Field: observe.Hostname, Value: "x1", Source: observe.Agent, Confidence: 0.5},
	} {
		err := e.svc.Record(e.ctx(), []observe.Observation{o})
		if !errors.Is(err, inventory.ErrInvalid) {
			t.Errorf("%+v: %v, want ErrInvalid", o.AssetHint, err)
		}
	}
	if e.devices() != 0 {
		t.Errorf("%d devices written", e.devices())
	}
}
