package inventory_test

import (
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

// D-598 (4): a private MAC a device had is that device after the device moved on to another one (macOS returning to an earlier
// private address), even with no name: the row it makes joins the device in the same write, never announced.
// Within macMemory (30 days), not after.
func TestContract_D598_AnEarlierMACFindsItsDevice(t *testing.T) {
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
	e.ev.reset()
	e.tick(time.Hour)
	e.record(dhcp(privMac1, "192.168.18.22", "")...)
	d := e.only()
	if d.ID != id || !d.Approved || d.IP != "192.168.18.22" || d.MAC == nil || *d.MAC != privMac1 {
		t.Errorf("device: id %s approved %v ip %s mac %v; want %s, approved, .22, %s", d.ID, d.Approved, d.IP, d.MAC, id, privMac1)
	}
	if got := e.discovered(); len(got) != 0 {
		t.Errorf("a new device was announced: %v", got)
	}

	// 31 days later privMac2 is forgotten: a new device.
	e.tick(31 * 24 * time.Hour)
	e.record(dhcp(privMac2, "192.168.18.23", "")...)
	if n := e.devices(); n != 2 {
		t.Errorf("a MAC last seen 31 days ago: %d devices, want 2", n)
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

	// Two devices were seen with privMac1 (the tablet, and another row): a third sighting with a new address joins neither.
	r := newEnv(t)
	r.record(dhcp(privMac1, "192.168.18.20", "lab-tablet")...)
	r.exec(`INSERT INTO inv_asset (id, mac, ip, kind, origin, approved, fragile, first_seen, last_seen) VALUES ('a-other', ?, '192.168.18.30', 'unknown', 'discovered', 0, 0, ?, ?)`,
		privMac3, store.FormatTS(r.now), store.FormatTS(r.now))
	r.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES ('o-other', 'a-other', 'mac', ?, 'passive', 0.9, ?)`, privMac1, store.FormatTS(r.now))
	r.tick(time.Hour)
	r.record(dhcp(privMac2, "192.168.18.21", "lab-tablet")...) // the tablet moves on (joined by its name): privMac1 is no device's MAC now
	if r.devices() != 2 {
		t.Fatalf("setup: %d devices", r.devices())
	}
	r.tick(time.Hour)
	r.record(dhcp(privMac1, "192.168.18.40", "")...)
	if n := r.devices(); n != 3 {
		t.Errorf("a MAC two devices had: %d devices, want a third", n)
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

// D-598 (4), the repair: the duplicate an older build left on the N100 (the approved device keeps the old MAC, has no address and holds
// the new MAC as an observation; a second row owns the new MAC at .138 with the model only) is joined by the next sighting of the second
// row. The approved device keeps its id, approval, kind and name, takes the address and the newest MAC; the duplicate is announced
// merged then deleted, so its "new device" incident closes.
func TestContract_D598_AnOldDuplicateJoinsOnItsNextSighting(t *testing.T) {
	e := newEnv(t)
	id := n100MacBook(e)
	laptop := "laptop"
	if err := e.svc.PatchDevice(e.ctx(), "kien", id, inventory.Patch{Kind: &laptop}); err != nil {
		t.Fatal(err)
	}
	// What build n69 left: the old MAC stayed the device's MAC, and the next sighting of the new one made a second row.
	e.tick(19*time.Minute + 37*time.Second)
	e.exec(`UPDATE inv_asset SET mac = ?, ip = NULL WHERE id = ?`, n100OldMAC, id)
	ts := store.FormatTS(e.now)
	e.exec(`INSERT INTO inv_asset (id, mac, ip, kind, origin, approved, fragile, first_seen, last_seen) VALUES ('a-dup', ?, '192.168.18.138', 'unknown', 'discovered', 0, 0, ?, ?)`, n100NewMAC, ts, ts)
	e.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES ('o-dup', 'a-dup', 'mac', ?, 'passive', 0.9, ?)`, n100NewMAC, ts)
	e.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES ('o-dupm', 'a-dup', 'model', 'Mac14,2', 'passive', 0.5, ?)`, ts)
	if e.devices() != 2 {
		t.Fatalf("setup: %d devices", e.devices())
	}
	e.ev.reset()
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

// n69: a model without a letter that an older sensor stored ("0,1,2" from an mDNS TXT record) never becomes the device's model, even
// when it is the newest.
func TestAModelWithoutALetterNamesNothing(t *testing.T) {
	e := newEnv(t)
	e.record(mdnsModel(privMac1, "192.168.18.20", "Mac14,2"))
	e.tick(time.Minute)
	e.record(mdnsModel(privMac1, "192.168.18.20", "0,1,2"))
	if d := e.only(); d.Model == nil || d.Model.Value != "Mac14,2" {
		t.Errorf("model %+v, want Mac14,2", d.Model)
	}
}
