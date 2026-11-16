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

// D-598 (1): what a host name alone must not join (review #831 H1, M2): the newcomer stays a device of its own and is announced.
// Two burned-in MACs (a re-imaged PC next to the old one); a private address next to a burned-in MAC (an intruder naming itself after
// a server); a private address next to a row known only by address, approved (a server on a routed subnet); a generic or
// system-made name ("iPhone", "MacBook-Pro-2", "Galaxy-A52", "DESKTOP-7GH2K1L", "localhost"); a name made of an address; three
// rows of one name (which two?). The old row was last seen an hour before, so only the rule under test keeps them apart.
func TestContract_D598_WhatANameAloneDoesNotJoin(t *testing.T) {
	cases := []struct {
		name  string
		first []observe.Observation
		then  []observe.Observation
		more  []observe.Observation
	}{
		{"two burned-in MACs", dhcp(burnt1, "192.168.18.10", "accounting-pc"), dhcp(burnt2, "192.168.18.11", "accounting-pc"), nil},
		{"private address and a burned-in MAC", dhcp(burnt1, "192.168.18.10", "nas01"), dhcp(privMac1, "192.168.18.11", "nas01"), nil},
		{"private address and a row known only by address", byAddress("10.20.0.5", "erp01.corp.lan"), dhcp(privMac1, "192.168.18.66", "ERP01"), nil},
		{"generic name", dhcp(privMac1, "192.168.18.10", "iPhone"), dhcp(privMac2, "192.168.18.11", "iPhone"), nil},
		{"generic name with a Bonjour number", dhcp(privMac1, "192.168.18.10", "MacBook-Pro-2"), dhcp(privMac2, "192.168.18.11", "MacBook-Pro-2"), nil},
		{"model name", dhcp(privMac1, "192.168.18.10", "Galaxy-A52"), dhcp(privMac2, "192.168.18.11", "Galaxy-A52"), nil},
		{"Windows default name", dhcp(privMac1, "192.168.18.10", "DESKTOP-7GH2K1L"), dhcp(privMac2, "192.168.18.11", "DESKTOP-7GH2K1L"), nil},
		{"localhost", dhcp(privMac1, "192.168.18.10", "localhost"), dhcp(privMac2, "192.168.18.11", "localhost.localdomain"), nil},
		{"name from the address", dhcp(privMac1, "192.168.18.10", "dhcp-192-168-18-10"), dhcp(privMac2, "192.168.18.11", "dhcp-192-168-18-10"), nil},
		{"two rows known only by address", byAddress("10.20.0.5", "erp01"), byAddress("10.20.0.6", "erp01"), nil},
		{"three rows of one name", dhcp(privMac1, "192.168.18.10", "lab-tablet"), dhcp(privMac2, "192.168.18.11", "lab-tablet"), dhcp(privMac3, "192.168.18.12", "lab-tablet")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.record(c.first...)
			if err := e.svc.Approve(e.ctx(), "kien", e.idOf(c.first[0].AssetHint.IP.String())); err != nil {
				t.Fatal(err)
			}
			last := c.then
			want := 2
			if c.more != nil {
				// two rows of one name already apart (online together), then a third
				e.tick(time.Second)
				e.record(c.then...)
				last, want = c.more, 3
			}
			e.tick(time.Hour)
			e.ev.reset()
			e.record(last...)
			if n := e.devices(); n != want {
				t.Errorf("%d devices, want %d", n, want)
			}
			if got := e.discovered(); len(got) != 1 {
				t.Errorf("the newcomer was not announced: %v", got)
			}
			if d, err := e.svc.Device(e.ctx(), e.idOf(c.first[0].AssetHint.IP.String())); err != nil || !d.Approved || d.MAC != nil && last[0].AssetHint.MAC == *d.MAC {
				t.Errorf("the approved row changed: %+v %v", d.AssetCore, err)
			}
		})
	}
}

// D-598 (1), review #831 H1: a declared device without a MAC is never taken over by a private address carrying its name: two devices,
// the newcomer announced, the declared row keeps its address and has no MAC.
func TestContract_D598_ADeclaredDeviceIsNotTakenOver(t *testing.T) {
	e := newEnv(t)
	id := e.addDevice(inventory.AddInput{CatalogID: "microsoft-office-desktop", Name: "fileserver", IP: "10.30.0.9"})
	e.ev.reset()
	e.record(dhcp(privMac1, "192.168.18.60", "FILESERVER")...)
	if e.devices() != 2 || len(e.discovered()) != 1 {
		t.Fatalf("%d devices, %d announced; want 2 and 1", e.devices(), len(e.discovered()))
	}
	d, err := e.svc.Device(e.ctx(), id)
	if err != nil || d.IP != "10.30.0.9" || d.MAC != nil {
		t.Errorf("declared device: %+v %v", d.AssetCore, err)
	}
}

// D-598 (1), review #831 M2: two machines of one name online at the same time (two "Johns-iPhone", cloned VMs) stay two, however
// long they stay; a rotation whose old address answered a minute ago waits rotationQuiet, then joins when the old row stayed silent.
func TestContract_D598_TwoMachinesOfOneNameOnlineAtOnce(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(privMac1, "192.168.18.10", "Johns-iPhone")...)
	e.tick(time.Second)
	e.record(dhcp(privMac2, "192.168.18.11", "Johns-iPhone")...)
	for range 3 {
		e.tick(10 * time.Minute)
		e.record(dhcp(privMac1, "192.168.18.10", "Johns-iPhone")...)
		e.record(dhcp(privMac2, "192.168.18.11", "Johns-iPhone")...)
	}
	if n := e.devices(); n != 2 {
		t.Fatalf("%d devices, want the two phones", n)
	}

	r := newEnv(t)
	r.record(dhcp(privMac1, "192.168.18.20", "kiens-ipad")...)
	r.tick(time.Minute)
	r.record(dhcp(privMac2, "192.168.18.21", "kiens-ipad")...)
	if n := r.devices(); n != 2 {
		t.Fatalf("a minute after the old address: %d devices, want 2 until the old one is quiet", n)
	}
	r.tick(10 * time.Minute)
	r.record(dhcp(privMac2, "192.168.18.21", "kiens-ipad")...)
	if d := r.only(); d.IP != "192.168.18.21" || d.MAC == nil || *d.MAC != privMac2 {
		t.Errorf("after the quiet time: %+v", d.AssetCore)
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
// address, that row and the machine's device are one (its agent said that MAC, and lost the address to it): one device, which keeps
// the enrolment's approval (review #831 L5) and the node's binding, and the node's next report finds it.
func TestContract_D598_AnAgentsRowJoinsItsMachine(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(burnt1, "192.168.18.20", "")...)
	e.tick(time.Hour)
	e.record(osq("192.168.18.40")...)
	if e.devices() != 2 {
		t.Fatalf("%d devices before a sensor sees the move, want 2", e.devices())
	}
	orphan := e.idOf("192.168.18.40")
	if found, err := e.svc.ApproveEnrolled(e.ctx(), observe.AssetHint{IP: netip.MustParseAddr("192.168.18.40"), Agent: "osquery:node-a"}, burnt1, "enrolled", false); err != nil || !found {
		t.Fatalf("ApproveEnrolled: %v %v", found, err)
	}
	e.tick(time.Minute)
	e.record(dhcp(burnt1, "192.168.18.40", "")...)
	d := e.only()
	if d.ID != orphan || d.IP != "192.168.18.40" || d.Hostname == nil || *d.Hostname != "build01" || !d.Approved || d.MAC == nil || *d.MAC != burnt1 {
		t.Errorf("device: id %s (want the approved row %s, review #831 L5) ip %s name %v approved %v mac %v", d.ID, orphan, d.IP, d.Hostname, d.Approved, d.MAC)
	}
	if e.count(`SELECT count(*) FROM inv_asset WHERE agent_key = 'osquery:node-a'`) != 1 {
		t.Errorf("the node's binding did not survive the join")
	}
	id := d.ID
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

// D-598 (2), review #831 M4: a binding is never overwritten. A node reporting on a device another node is bound to (a reused lease)
// does not take it; once agent-intake releases the old node (re-enrolment, revoke, prune), the next node binds.
func TestContract_D598_ABindingIsNeverStolen(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(burnt1, "192.168.18.20", "")...)
	id := e.idOf("192.168.18.20")
	e.record(osq("192.168.18.20")...)
	other := []observe.Observation{{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("192.168.18.20"), Agent: "osquery:node-b"}, Field: observe.MAC, Value: burnt1, Source: observe.Agent, Confidence: 0.9}}
	e.record(other...)
	if e.count(`SELECT count(*) FROM inv_asset WHERE id = ? AND agent_key = 'osquery:node-a'`, id) != 1 || e.count(`SELECT count(*) FROM inv_asset WHERE agent_key = 'osquery:node-b'`) != 0 {
		t.Fatal("node-b took node-a's device")
	}
	if err := e.svc.ReleaseAgents(e.ctx(), []string{"osquery:node-a"}); err != nil {
		t.Fatal(err)
	}
	e.record(other...)
	if e.count(`SELECT count(*) FROM inv_asset WHERE id = ? AND agent_key = 'osquery:node-b'`, id) != 1 {
		t.Error("after the release, node-b is not bound")
	}
}

// D-598 (2), review #831 M3: a node that once reported with a machine's burned-in MAC and address (a spoof) is bound to that machine;
// when it then reports from its own address without that MAC, the binding is dropped: the machine stays where it is and the report
// goes by address (a device of its own).
func TestContract_D598_ASpoofedBindingIsDropped(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(burnt2, "192.168.18.20", "")...)
	victim := e.idOf("192.168.18.20")
	spoof := []observe.Observation{{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("192.168.18.20"), Agent: "osquery:node-x"}, Field: observe.MAC, Value: burnt2, Source: observe.Agent, Confidence: 0.9}}
	e.record(spoof...)
	if e.count(`SELECT count(*) FROM inv_asset WHERE id = ? AND agent_key = 'osquery:node-x'`, victim) != 1 {
		t.Fatal("setup: the spoof did not bind")
	}
	e.tick(time.Minute)
	e.record(observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("192.168.18.77"), Agent: "osquery:node-x"}, Field: observe.MAC, Value: burnt1, Source: observe.Agent, Confidence: 0.9},
		observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("192.168.18.77"), Agent: "osquery:node-x"}, Field: observe.Hostname, Value: "evil", Source: observe.Agent, Confidence: 0.9})
	d, err := e.svc.Device(e.ctx(), victim)
	if err != nil || d.IP != "192.168.18.20" || d.Hostname != nil {
		t.Errorf("the victim moved or was written on: %+v %v", d.AssetCore, err)
	}
	if e.devices() != 2 || e.count(`SELECT count(*) FROM inv_asset WHERE id = ? AND agent_key IS NOT NULL`, victim) != 0 {
		t.Errorf("%d devices; the victim's binding stayed", e.devices())
	}
}

// D-598 (2): ApproveEnrolled finds the device by the node first, wherever its address went.
func TestContract_D598_ApproveEnrolledFindsTheNodesDevice(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(burnt1, "192.168.18.20", "")...)
	id := e.idOf("192.168.18.20")
	e.record(osq("192.168.18.20")...)
	found, err := e.svc.ApproveEnrolled(e.ctx(), observe.AssetHint{IP: netip.MustParseAddr("192.168.18.99"), Agent: "osquery:node-a"}, burnt1, "enrolled", false)
	if err != nil || !found {
		t.Fatalf("found %v err %v", found, err)
	}
	if d, _ := e.svc.Device(e.ctx(), id); !d.Approved {
		t.Error("the node's device is not approved")
	}
}

// D-598, review #831 L6: a service list that moves an address (a sensor's MAC on the address an agent's row held) runs the joins as an
// observation batch does: the agent's address-less row joins the machine's device, one device.
func TestContract_D598_AListAlsoJoins(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(burnt1, "192.168.18.20", "")...)
	e.tick(time.Hour)
	e.record(osq("192.168.18.40")...)
	if e.devices() != 2 {
		t.Fatalf("setup: %d devices", e.devices())
	}
	e.tick(time.Minute)
	if err := e.svc.AddServices(e.ctx(), observe.AssetHint{IP: netip.MustParseAddr("192.168.18.40"), MAC: burnt1}, observe.Nmap,
		[]observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	if d := e.only(); d.IP != "192.168.18.40" || len(d.Services) != 1 {
		t.Errorf("device: %+v", d.AssetCore)
	}
}
