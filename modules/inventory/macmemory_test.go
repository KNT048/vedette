package inventory_test

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/inventory"
)

// kien's MacBook Air on the N100 (n69, #829 follow-up): its old private address, which nmap saw two days before, and the new one it
// rotated to.
const (
	n100OldMAC = "b2:f0:09:23:2e:5b"
	n100NewMAC = "b2:f9:5e:2c:c4:8f"
)

// nmapMAC is what a discovery scan sends for a host on the LAN: the MAC that answered at the address.
func nmapMAC(mac, ip string) observe.Observation {
	return observe.Observation{AssetHint: observe.AssetHint{MAC: mac, IP: netip.MustParseAddr(ip)}, Field: observe.MAC, Value: mac, Source: observe.Nmap, Confidence: 0.9}
}

// mdnsModel is the model a Mac's mDNS _device-info TXT record states, as the passive sensor sends it.
func mdnsModel(mac, ip, model string) observe.Observation {
	return observe.Observation{AssetHint: observe.AssetHint{MAC: mac, IP: netip.MustParseAddr(ip)}, Field: observe.Model, Value: model, Source: observe.Passive, Confidence: 0.5}
}

// n100MacBook replays the N100 up to the moment the new private address joined the approved device by its name (10:49:47Z): the
// old address seen by DHCP and by nmap, approved, two days of silence, then DHCP with the new address, the name and the model.
func n100MacBook(e *env) string {
	e.t.Helper()
	e.record(dhcp(n100OldMAC, "192.168.18.145", "kiens-macbook-air")...)
	e.record(nmapMAC(n100OldMAC, "192.168.18.145"))
	id := e.idOf("192.168.18.145")
	if err := e.svc.Approve(e.ctx(), "kien", id); err != nil {
		e.t.Fatal(err)
	}
	e.tick(48 * time.Hour)
	e.record(append(dhcp(n100NewMAC, "192.168.18.138", "kiens-macbook-air"), mdnsModel(n100NewMAC, "192.168.18.138", "Mac14,2"))...)
	if e.devices() != 1 {
		e.t.Fatalf("setup: the name rule did not join the new address: %d devices", e.devices())
	}
	return id
}

// D-598 (4), n69: the N100 sequence. The new private address joined the approved device, then a two-day-old nmap MAC outranked it
// (the device's MAC stayed the old one) and the next sighting of the new address, with an address and a model and no name, made a
// second device. Now the newest MAC is the device's MAC, and a row made by a MAC the device had joins it: one device, the approved
// one, at the new address, and no "new device" announced.
func TestContract_D598_TheN100MacBookStaysOneDevice(t *testing.T) {
	e := newEnv(t)
	id := n100MacBook(e)
	if d := e.only(); d.MAC == nil || *d.MAC != n100NewMAC {
		t.Errorf("after the join the device's MAC is %v, want the newest %s (a two-day-old nmap MAC outranked it)", d.MAC, n100NewMAC)
	}
	e.ev.reset()
	e.tick(19*time.Minute + 37*time.Second)
	e.record(dhcp(n100NewMAC, "192.168.18.138", "")...) // 11:09:24: ARP, no name
	e.tick(38 * time.Minute)
	e.record(mdnsModel(n100NewMAC, "192.168.18.138", "Mac14,2")) // 11:47:35
	e.tick(73 * time.Minute)
	e.record(dhcp(n100NewMAC, "192.168.18.138", "")...) // 13:00:10
	d := e.only()
	if d.ID != id || !d.Approved || d.IP != "192.168.18.138" || d.MAC == nil || *d.MAC != n100NewMAC {
		t.Errorf("device: id %s approved %v ip %s mac %v; want %s, approved, .138, %s", d.ID, d.Approved, d.IP, d.MAC, id, n100NewMAC)
	}
	if got := e.discovered(); len(got) != 0 {
		t.Errorf("a new device was announced: %v", got)
	}
}

// D-598 (4), review r1 of #862 H1: an older MAC of a device is no key. A machine that shows up with it while the device is away (an
// intruder who sniffed the iPad's earlier private MAC) is a device of its own and is announced; the approved device keeps its address,
// MAC and approval; when the iPad comes back under its current MAC nothing new appears, and the intruder's row never joins it.
// (A device that itself goes back to an older MAC is joined by the name rule when it carries its name, #831.)
func TestContract_D598_AnOlderMACOfAnAwayDeviceIsANewDevice(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(privMac1, "192.168.18.20", "kiens-ipad")...)
	id := e.idOf("192.168.18.20")
	if err := e.svc.Approve(e.ctx(), "kien", id); err != nil {
		t.Fatal(err)
	}
	e.tick(time.Hour)
	e.record(dhcp(privMac2, "192.168.18.21", "kiens-ipad")...)
	if d := e.only(); d.MAC == nil || *d.MAC != privMac2 {
		t.Fatalf("setup: %+v", d.AssetCore)
	}
	ipad := func(when string) {
		t.Helper()
		d, err := e.svc.Device(e.ctx(), id)
		if err != nil || !d.Approved || d.IP != "192.168.18.21" || d.MAC == nil || *d.MAC != privMac2 {
			t.Errorf("%s: the iPad's device changed: %+v %v", when, d.AssetCore, err)
		}
	}
	e.ev.reset()
	e.tick(25 * time.Minute) // the iPad sleeps
	e.record(dhcp(privMac1, "192.168.18.50", "")...)
	if n := e.devices(); n != 2 || len(e.discovered()) != 1 {
		t.Fatalf("intruder: %d devices, %d announced; want 2 and 1", n, len(e.discovered()))
	}
	ipad("intruder")
	e.tick(30 * time.Minute)
	e.record(dhcp(privMac1, "192.168.18.50", "")...)
	e.record(dhcp(privMac2, "192.168.18.21", "kiens-ipad")...) // the iPad wakes up
	if n := e.devices(); n != 2 || len(e.discovered()) != 1 {
		t.Errorf("iPad back: %d devices, %d announced; want 2 and still 1", n, len(e.discovered()))
	}
	ipad("iPad back")
	e.tick(25 * time.Minute) // the intruder left
	e.record(dhcp(privMac2, "192.168.18.21", "kiens-ipad")...)
	if n := e.devices(); n != 2 {
		t.Errorf("intruder gone: %d devices, want 2 (its row never joins the iPad)", n)
	}
	ipad("intruder gone")
}

// D-598 (4), review r1 of #862 M1: a private MAC never joins a row that carries a burned-in MAC (D-598): a laptop row with its dock's
// card and a newer private MAC, away for 25 minutes; a machine with that private MAC is a device of its own, announced.
func TestContract_D598_APrivateMACNeverJoinsABurnedInRow(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(burnt1, "192.168.18.20", "")...)
	id := e.idOf("192.168.18.20")
	if err := e.svc.Approve(e.ctx(), "kien", id); err != nil {
		t.Fatal(err)
	}
	e.tick(time.Minute)
	e.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES ('o-wifi', ?, 'mac', ?, 'passive', 0.9, ?)`,
		id, privMac3, store.FormatTS(e.now))
	e.ev.reset()
	e.tick(25 * time.Minute)
	e.record(dhcp(privMac3, "192.168.18.60", "")...)
	if n := e.devices(); n != 2 || len(e.discovered()) != 1 {
		t.Errorf("%d devices, %d announced; want 2 and 1", n, len(e.discovered()))
	}

	// The burned-in row is the touched one (review r2 of #862 L2): its newest wire MAC is a private one another row owns, quiet for 25
	// minutes; an address-only sighting of the burned-in row joins nothing.
	q := newEnv(t)
	q.record(dhcp(burnt1, "192.168.18.20", "")...)
	qid := q.idOf("192.168.18.20")
	if err := q.svc.Approve(q.ctx(), "kien", qid); err != nil {
		t.Fatal(err)
	}
	q.tick(time.Minute)
	ts := store.FormatTS(q.now)
	q.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES ('o-wifi', ?, 'mac', ?, 'passive', 0.9, ?)`, qid, privMac3, ts)
	q.exec(`INSERT INTO inv_asset (id, mac, ip, kind, origin, approved, fragile, first_seen, last_seen) VALUES ('a-wifi', ?, '192.168.18.61', 'unknown', 'discovered', 0, 0, ?, ?)`, privMac3, ts, ts)
	q.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES ('o-wifi2', 'a-wifi', 'mac', ?, 'passive', 0.9, ?)`, privMac3, ts)
	q.tick(25 * time.Minute)
	q.record(observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("192.168.18.20")}, Field: observe.Vendor, Value: "Apple", Source: observe.Nmap, Confidence: 0.5})
	if n := q.devices(); n != 2 {
		t.Errorf("touched burned-in row: %d devices, want 2", n)
	}
}

// D-598 (4), review r1 of #862 M2: what sameMAC never counts. A MAC only an agent claims on a row (self-declared, D-265 (4)), even its
// newest; a MAC observation on the box. Each newcomer stays a device of its own.
func TestContract_D598_AnAgentsClaimOrTheBoxIsNoSharedMAC(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(privMac2, "192.168.18.30", "")...)
	x := e.idOf("192.168.18.30")
	e.tick(time.Minute)
	e.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES ('o-claim', ?, 'mac', ?, 'agent', 0.9, ?)`,
		x, privMac1, store.FormatTS(e.now))
	e.tick(25 * time.Minute)
	e.record(dhcp(privMac1, "192.168.18.31", "")...)
	if n := e.devices(); n != 2 {
		t.Errorf("an agent's claim: %d devices, want 2", n)
	}

	b := newEnv(t)
	ts := store.FormatTS(b.now)
	b.exec(`INSERT INTO inv_asset (id, ip, kind, origin, approved, fragile, is_box, first_seen, last_seen) VALUES ('a-box', '192.168.18.2', 'server', 'manual', 1, 0, 1, ?, ?)`, ts, ts)
	b.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES ('o-box', 'a-box', 'mac', ?, 'passive', 0.9, ?)`, privMac1, ts)
	b.tick(25 * time.Minute)
	b.record(dhcp(privMac1, "192.168.18.40", "")...)
	if n := b.devices(); n != 1 {
		t.Errorf("a MAC on the box: %d devices besides the box, want 1", n)
	}
}

// D-598 (4), the spoof case: a machine that takes an earlier MAC of a device while the device is online under its current MAC is two
// machines at once, not the device: a device of its own, announced, and it stays apart while both are online. The device keeps its
// address, MAC and approval. A MAC two devices were seen with joins neither, and a burned-in MAC never joins two rows (D-598).
func TestContract_D598_AnEarlierMACInUseElsewhereIsNotTheDevice(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(privMac1, "192.168.18.20", "kiens-ipad")...)
	id := e.idOf("192.168.18.20")
	if err := e.svc.Approve(e.ctx(), "kien", id); err != nil {
		t.Fatal(err)
	}
	e.tick(time.Hour)
	e.record(dhcp(privMac2, "192.168.18.21", "kiens-ipad")...)
	e.tick(5 * time.Minute)
	e.ev.reset()
	e.record(dhcp(privMac1, "192.168.18.50", "")...) // the iPad answered as privMac2 five minutes ago
	if n := e.devices(); n != 2 || len(e.discovered()) != 1 {
		t.Fatalf("%d devices, %d announced; want 2 and 1", n, len(e.discovered()))
	}
	for range 3 {
		e.tick(10 * time.Minute)
		e.record(dhcp(privMac2, "192.168.18.21", "")...)
		e.record(dhcp(privMac1, "192.168.18.50", "")...)
	}
	if n := e.devices(); n != 2 {
		t.Fatalf("both online: %d devices, want 2", n)
	}
	d, err := e.svc.Device(e.ctx(), id)
	if err != nil || !d.Approved || d.IP != "192.168.18.21" || d.MAC == nil || *d.MAC != privMac2 {
		t.Errorf("the device changed: %+v %v", d.AssetCore, err)
	}

	// Two rows a sensor saw last with privMac1 (their columns hold other MACs): a third sighting joins neither.
	r := newEnv(t)
	ts := store.FormatTS(r.now)
	for i, m := range []string{privMac2, privMac3} {
		r.exec(`INSERT INTO inv_asset (id, mac, ip, kind, origin, approved, fragile, first_seen, last_seen) VALUES (?, ?, ?, 'unknown', 'discovered', 0, 0, ?, ?)`,
			fmt.Sprintf("a-r%d", i), m, fmt.Sprintf("192.168.18.%d", 30+i), ts, ts)
		r.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES (?, ?, 'mac', ?, 'passive', 0.9, ?)`,
			fmt.Sprintf("o-r%d", i), fmt.Sprintf("a-r%d", i), privMac1, ts)
	}
	r.tick(time.Hour)
	r.record(dhcp(privMac1, "192.168.18.40", "")...)
	if n := r.devices(); n != 3 {
		t.Errorf("a MAC two rows hold: %d devices, want a third", n)
	}

	// A burned-in MAC a device had (a dock's card) makes a row of its own when it comes back: no MAC-overlap join of burned-in MACs
	// (D-598, D-515).
	b := newEnv(t)
	b.record(dhcp(burnt2, "192.168.18.20", "")...)
	b.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES ('o-dock', ?, 'mac', ?, 'passive', 0.9, ?)`,
		b.idOf("192.168.18.20"), burnt1, store.FormatTS(b.now))
	b.tick(time.Hour)
	b.record(dhcp(burnt1, "192.168.18.21", "")...)
	if n := b.devices(); n != 2 {
		t.Errorf("a burned-in MAC on two rows: %d devices, want 2 (never joined)", n)
	}
}

// n69Leftover builds what build n69 left on the N100: the approved MacBook (kind laptop) kept the old MAC as its MAC and lost its
// address, and the next sighting of the new MAC made a second row a-dup at .138 stating dupModel. It returns the approved device.
func n69Leftover(e *env, dupModel string) string {
	e.t.Helper()
	id := n100MacBook(e)
	laptop := "laptop"
	if err := e.svc.PatchDevice(e.ctx(), "kien", id, inventory.Patch{Kind: &laptop}); err != nil {
		e.t.Fatal(err)
	}
	e.tick(19*time.Minute + 37*time.Second)
	e.exec(`UPDATE inv_asset SET mac = ?, ip = NULL WHERE id = ?`, n100OldMAC, id)
	ts := store.FormatTS(e.now)
	e.exec(`INSERT INTO inv_asset (id, mac, ip, kind, origin, approved, fragile, first_seen, last_seen) VALUES ('a-dup', ?, '192.168.18.138', 'unknown', 'discovered', 0, 0, ?, ?)`, n100NewMAC, ts, ts)
	e.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES ('o-dup', 'a-dup', 'mac', ?, 'passive', 0.9, ?)`, n100NewMAC, ts)
	e.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES ('o-dupm', 'a-dup', 'model', ?, 'passive', 0.5, ?)`, dupModel, ts)
	if e.devices() != 2 {
		e.t.Fatalf("setup: %d devices", e.devices())
	}
	return id
}

// D-598 (4), review r1 of #862 M2: two rows last seen with one private MAC that state another model are two machines (facts, differ):
// they stay apart.
func TestContract_D598_ASharedMACWithAnotherModelStaysApart(t *testing.T) {
	e := newEnv(t)
	n69Leftover(e, "iPhone15,2")
	e.tick(110 * time.Minute)
	e.record(dhcp(n100NewMAC, "192.168.18.138", "")...)
	if n := e.devices(); n != 2 {
		t.Errorf("%d devices, want 2", n)
	}
}

// D-598 (4), review r2 of #862 L2: the other row's sighting of the shared MAC must be within macMemory (30 days): the n69 leftover
// seen again 31 days later stays two devices.
func TestContract_D598_ASharedMACOlderThan30DaysIsNoKey(t *testing.T) {
	e := newEnv(t)
	n69Leftover(e, "Mac14,2")
	e.tick(31 * 24 * time.Hour)
	e.record(dhcp(n100NewMAC, "192.168.18.138", "")...)
	if n := e.devices(); n != 2 {
		t.Errorf("%d devices, want 2", n)
	}
}

// D-598 (4), review r2 of #862 L1: an agent-bound laptop whose agent reports another card than the MAC sensors last saw (a range
// extender rewrites client MACs) joins only on its agent's card: a machine that copies the sensor-only MAC while the laptop is away is a
// device of its own, announced.
func TestContract_D598_AnAgentBoundRowJoinsOnlyOnItsCard(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(privMac1, "192.168.18.20", "")...)
	id := e.idOf("192.168.18.20")
	if err := e.svc.Approve(e.ctx(), "kien", id); err != nil {
		t.Fatal(err)
	}
	e.tick(time.Minute)
	e.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES ('o-card', ?, 'mac', ?, 'agent', 0.9, ?)`,
		id, privMac3, store.FormatTS(e.now))
	e.exec(`UPDATE inv_asset SET agent_key = 'osquery:node-a', agent_ip = ip, mac = ? WHERE id = ?`, privMac3, id) // the column follows the agent's newest card
	e.ev.reset()
	e.tick(25 * time.Minute)
	e.record(dhcp(privMac1, "192.168.18.50", "")...)
	if n := e.devices(); n != 2 || len(e.discovered()) != 1 {
		t.Errorf("%d devices, %d announced; want 2 and 1", n, len(e.discovered()))
	}
}

// D-598 (4), review r2 of #862 L3: an agent's claim on the touched row is no shared MAC either (D-265 (4)): an intruder whose agent
// claims the away iPad's MAC does not join it when the intruder's row is seen again.
func TestContract_D598_AnAgentsClaimOnTheTouchedRowIsNoKey(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(privMac1, "192.168.18.20", "kiens-ipad")...)
	if err := e.svc.Approve(e.ctx(), "kien", e.idOf("192.168.18.20")); err != nil {
		t.Fatal(err)
	}
	e.record(dhcp(privMac2, "192.168.18.31", "")...)
	intruder := e.idOf("192.168.18.31")
	e.tick(time.Minute)
	e.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES ('o-claim', ?, 'mac', ?, 'agent', 0.9, ?)`,
		intruder, privMac1, store.FormatTS(e.now))
	e.tick(25 * time.Minute)
	e.record(observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("192.168.18.31")}, Field: observe.Vendor, Value: "Acme", Source: observe.Nmap, Confidence: 0.5})
	if n := e.devices(); n != 2 {
		t.Errorf("%d devices, want 2", n)
	}
}

// D-598 (4), the repair: the duplicate an older build left on the N100 (the approved device keeps the old MAC, has no address and holds
// the new MAC as an observation; a second row owns the new MAC at .138 with the model only) is joined by the next sighting of the second
// row. The approved device keeps its id, approval, kind and name, takes the address and the newest MAC; the duplicate is announced
// merged then deleted, so its "new device" incident closes.
func TestContract_D598_AnOldDuplicateJoinsOnItsNextSighting(t *testing.T) {
	e := newEnv(t)
	id := n69Leftover(e, "Mac14,2")
	e.ev.reset()
	e.record(dhcp(n100NewMAC, "192.168.18.138", "")...) // the approved row answered 19m37s ago: online together, not yet
	if n := e.devices(); n != 2 {
		t.Fatalf("less than rotationQuiet after the approved row: %d devices, want 2", n)
	}
	e.tick(110 * time.Minute)
	e.record(dhcp(n100NewMAC, "192.168.18.138", "")...)
	d := e.only()
	if d.ID != id || !d.Approved || d.IP != "192.168.18.138" || d.MAC == nil || *d.MAC != n100NewMAC || d.Kind != "laptop" ||
		d.Hostname == nil || *d.Hostname != "kiens-macbook-air" {
		t.Errorf("device: id %s approved %v ip %s mac %v kind %s name %v", d.ID, d.Approved, d.IP, d.MAC, d.Kind, d.Hostname)
	}
	merged := e.ev.named(inventory.EventAssetMerged)
	if len(merged) != 1 || merged[0].Data.(inventory.MergeEvent).From != "a-dup" || merged[0].Data.(inventory.MergeEvent).Into != id {
		t.Errorf("merged events: %+v, want a-dup into %s", merged, id)
	}
	if len(e.ev.named(inventory.EventAssetDeleted)) != 1 || len(e.discovered()) != 0 {
		t.Errorf("deleted %v, discovered %v", e.ev.named(inventory.EventAssetDeleted), e.discovered())
	}
	if !has(e.auditActions(), "inventory.merge") {
		t.Errorf("no inventory.merge audit row: %v", e.auditActions())
	}
}

// n69: a passive model without a letter that an older sensor stored ("0,1,2" from an mDNS TXT record) never becomes the device's model,
// even when it is the newest. A model of digits that SNMP states is a part number and wins as usual (review r1 of #862 L1).
func TestAModelWithoutALetterNamesNothing(t *testing.T) {
	e := newEnv(t)
	e.record(mdnsModel(privMac1, "192.168.18.20", "Mac14,2"))
	e.tick(time.Minute)
	e.record(mdnsModel(privMac1, "192.168.18.20", "0,1,2"))
	if d := e.only(); d.Model == nil || d.Model.Value != "Mac14,2" {
		t.Errorf("model %+v, want Mac14,2", d.Model)
	}
	e.record(observe.Observation{AssetHint: observe.AssetHint{MAC: privMac1, IP: netip.MustParseAddr("192.168.18.20")}, Field: observe.Model, Value: "1910", Source: observe.SNMP, Confidence: 0.8})
	if d := e.only(); d.Model == nil || d.Model.Value != "1910" {
		t.Errorf("model %+v, want SNMP's 1910", d.Model)
	}
}
