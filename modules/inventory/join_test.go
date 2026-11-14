package inventory_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// The N100 lab switch of walk 1 (W1-37): a Juniper EX4200 whose LLDP names its chassis (base) MAC :80 while ARP and nmap see its
// management interface .47 with MAC :ff.
const (
	jnprBase = "3c:8a:b0:9c:85:80"
	jnprMgmt = "3c:8a:b0:9c:85:ff"
	jnprIP   = "192.168.18.47"
)

// lldp is what sensor-passive sends for one LLDP frame (capture/engine.go handleLLDP).
func lldp(chassis, name string) []observe.Observation {
	h := observe.AssetHint{MAC: chassis}
	o := func(f observe.Field, v string, c float64) observe.Observation {
		return observe.Observation{AssetHint: h, Field: f, Value: v, Source: observe.Passive, Confidence: c}
	}
	list := []observe.Observation{o(observe.MAC, chassis, 0.9), o(observe.Vendor, "Juniper Networks", 0.4), o(observe.Model, "EX4200-48T", 0.5), o(observe.OS, "JUNOS 15.1R7.9", 0.5), o(observe.Kind, "switch", 0.6)}
	if name != "" {
		list = append(list, o(observe.Hostname, name, 0.7))
	}
	return list
}

// seenAt is what ARP and an nmap scan send for a device with an address.
func seenAt(mac, ip, name string) []observe.Observation {
	h := observe.AssetHint{MAC: mac, IP: netip.MustParseAddr(ip)}
	list := []observe.Observation{
		{AssetHint: h, Field: observe.MAC, Value: mac, Source: observe.Passive, Confidence: 0.9},
		{AssetHint: h, Field: observe.Vendor, Value: "Juniper Networks", Source: observe.Nmap, Confidence: 0.6},
	}
	if name != "" {
		list = append(list, observe.Observation{AssetHint: h, Field: observe.Hostname, Value: name, Source: observe.Passive, Confidence: 0.7})
	}
	return list
}

func (e *env) devices() int { return e.count(`SELECT count(*) FROM inv_asset WHERE is_box = 0`) }

// W1-37, D-515 (c): the exact N100 values. A switch first seen by LLDP (no IP, base MAC :80, approved by a person) and then by ARP
// and nmap at .47 (MAC :ff) is one device after the next LLDP frame: the IP device's id, address and MAC, the model and OS from
// LLDP; one audit row; the LLDP row announced merged, then deleted. Later frames find the same device. The approval of the LLDP row
// does not move (review H1 of #722): a person approves the joined device.
func TestContract_D515_ASwitchSeenByLLDPAndByItsAddressIsOneDevice(t *testing.T) {
	e := newEnv(t)
	e.record(lldp(jnprBase, "")...)
	lldpID := e.idByMAC(jnprBase)
	if err := e.svc.Approve(e.ctx(), "kien", lldpID); err != nil {
		t.Fatal(err)
	}
	e.tick(time.Minute)
	e.record(seenAt(jnprMgmt, jnprIP, "")...)
	ipID := e.idByMAC(jnprMgmt)
	if e.devices() != 2 {
		t.Fatalf("before the next frame: %d devices, want the two of the walk", e.devices())
	}
	e.ev.reset()
	e.tick(time.Minute)
	e.record(lldp(jnprBase, "")...)
	if n := e.devices(); n != 1 {
		t.Fatalf("%d devices, want one switch", n)
	}
	d, err := e.svc.Device(e.ctx(), ipID)
	if err != nil {
		t.Fatal(err)
	}
	if d.IP != jnprIP || d.MAC == nil || *d.MAC != jnprMgmt || d.Model == nil || d.Model.Value != "EX4200-48T" || d.OS == nil || d.OS.Value != "JUNOS 15.1R7.9" || d.Kind != "switch" || d.Approved || d.ApprovedAt != nil {
		t.Errorf("joined device: ip %s mac %v model %v os %v kind %s approved %v", d.IP, d.MAC, d.Model, d.OS, d.Kind, d.Approved)
	}
	if !has(e.auditActions(), "inventory.merge") {
		t.Errorf("no inventory.merge audit row: %v", e.auditActions())
	}
	if m := e.ev.named(inventory.EventAssetMerged); len(m) != 1 || m[0].Data.(inventory.MergeEvent) != (inventory.MergeEvent{From: lldpID, Into: ipID, Actor: "system"}) {
		t.Errorf("merged events %+v", m)
	}
	if i, j := slices.IndexFunc(e.ev.events, func(ev inventory.Event) bool { return ev.Name == inventory.EventAssetMerged }),
		slices.IndexFunc(e.ev.events, func(ev inventory.Event) bool { return ev.Name == inventory.EventAssetDeleted }); i < 0 || j < i {
		t.Errorf("merged must go out before deleted: %d, %d", i, j)
	}
	del := e.ev.named(inventory.EventAssetDeleted)
	if len(del) != 1 || del[0].Data.(inventory.AssetEvent).AssetID != lldpID {
		t.Errorf("deleted events %+v, want the LLDP row", del)
	}
	upd := e.ev.named(inventory.EventAssetUpdated)
	if len(upd) != 1 || upd[0].Data.(inventory.AssetEvent).AssetID != ipID || !upd[0].Data.(inventory.AssetEvent).Match {
		t.Errorf("updated events %+v, want the IP device to be matched again", upd)
	}
	for range 2 { // the next frames, and ARP again: still one device, still the management MAC
		e.tick(20 * time.Minute)
		e.record(lldp(jnprBase, "")...)
		e.record(seenAt(jnprMgmt, jnprIP, "")...)
	}
	if d, _ := e.svc.Device(e.ctx(), ipID); e.devices() != 1 || d.MAC == nil || *d.MAC != jnprMgmt || d.IP != jnprIP {
		t.Errorf("after more frames: %d devices, mac %v ip %s", e.devices(), d.MAC, d.IP)
	}
	if n := len(e.ev.named(inventory.EventAssetDiscovered)); n != 0 {
		t.Errorf("%d discovered events: a frame made the switch again", n)
	}
}

// D-515 (c) the other way round: the address is known first, and the first LLDP frame never makes a second device.
func TestContract_D515_TheFirstFrameJoinsAKnownSwitch(t *testing.T) {
	e := newEnv(t)
	e.record(seenAt(jnprMgmt, jnprIP, "")...)
	e.ev.reset()
	e.record(lldp(jnprBase, "")...)
	if n := e.devices(); n != 1 {
		t.Fatalf("%d devices, want one", n)
	}
	if n := len(e.ev.named(inventory.EventAssetDiscovered)) + len(e.ev.named(inventory.EventAssetDeleted)); n != 0 {
		t.Errorf("%d discovered/deleted events for a row that never showed", n)
	}
}

// D-515 (b): the same system name joins a switch whose management MAC lies outside the block.
func TestContract_D515_TheSameNameJoins(t *testing.T) {
	const far = "3c:8a:b0:9c:00:10" // same maker, outside the block of :80
	e := newEnv(t)
	e.record(seenAt(far, jnprIP, "sw-office")...)
	e.record(lldp(jnprBase, "SW-OFFICE")...)
	if n := e.devices(); n != 1 {
		t.Errorf("%d devices, want one", n)
	}
}

// D-515 negatives (and review M1, LOW of #722): rows that are not one switch stay apart.
func TestContract_D515_DifferentDevicesStayApart(t *testing.T) {
	stated := func(mac, ip string, f observe.Field, v string) []observe.Observation {
		return []observe.Observation{{AssetHint: observe.AssetHint{MAC: mac, IP: netip.MustParseAddr(ip)}, Field: f, Value: v, Source: observe.SNMP, Confidence: 0.9}}
	}
	for name, c := range map[string]struct {
		ipMAC, ipName string
		extra         []observe.Observation // after the IP device
		setup         func(e *env)          // then, before the frame that decides
		frame         []observe.Observation
	}{
		"another maker":            {ipMAC: "00:11:22:9c:85:ff", frame: lldp(jnprBase, "")},
		"outside the block":        {ipMAC: "3c:8a:b0:9c:85:80", frame: lldp("3c:8a:b0:9c:85:00", "")},
		"below the base":           {ipMAC: "3c:8a:b0:9c:85:10", frame: lldp(jnprBase, "")},
		"two in one block":         {ipMAC: "3c:8a:b0:9c:85:90", extra: seenAt("3c:8a:b0:9c:85:a0", "192.168.18.49", ""), frame: lldp(jnprBase, "")},
		"both have addresses":      {ipMAC: jnprMgmt, frame: seenAt(jnprBase, "192.168.18.48", "")},
		"a random MAC":             {ipMAC: "3e:8a:b0:9c:85:ff", frame: lldp("3e:8a:b0:9c:85:80", "")},
		"not network gear":         {ipMAC: jnprMgmt, frame: []observe.Observation{{AssetHint: observe.AssetHint{MAC: jnprBase}, Field: observe.Hostname, Value: "laptop", Source: observe.Passive, Confidence: 0.5}}},
		"names differ":             {ipMAC: jnprMgmt, ipName: "sw-b", frame: lldp(jnprBase, "sw-a")},
		"models differ":            {ipMAC: jnprMgmt, extra: stated(jnprMgmt, jnprIP, observe.Model, "EX2300-24T"), frame: lldp(jnprBase, "")},
		"OSes differ":              {ipMAC: jnprMgmt, extra: stated(jnprMgmt, jnprIP, observe.OS, "JUNOS 18.2R3.4"), frame: lldp(jnprBase, "")},
		"a name on another maker":  {ipMAC: "00:11:22:9c:00:01", ipName: "sw-core", frame: lldp(jnprBase, "sw-core")},
		"a name on a far MAC":      {ipMAC: "3c:8a:b0:11:00:01", ipName: "sw-core", frame: lldp(jnprBase, "sw-core")},
		"a default name":           {ipMAC: "3c:8a:b0:9c:00:10", ipName: "Amnesiac", frame: lldp(jnprBase, "Amnesiac")},
		"a name two devices share": {ipMAC: "3c:8a:b0:9c:00:01", ipName: "sw-core", extra: seenAt("3c:8a:b0:9c:00:02", "192.168.18.49", "sw-core"), frame: lldp(jnprBase, "sw-core")},
		"another chassis":          {ipMAC: jnprMgmt, extra: lldp("3c:8a:b0:9c:85:81", ""), frame: lldp(jnprBase, "")},
		"a declared row": {ipMAC: jnprMgmt, frame: lldp(jnprBase, ""), setup: func(e *env) {
			e.exec(`UPDATE inv_asset SET origin = 'manual' WHERE mac = ?`, jnprBase)
		}},
		"the box": {ipMAC: jnprMgmt, frame: lldp(jnprBase, ""), setup: func(e *env) {
			e.exec(`UPDATE inv_asset SET is_box = 1 WHERE ip = ?`, jnprIP)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.record(c.frame...) // the frame first: a device with an address joining nothing by itself, the next frame decides
			e.record(seenAt(c.ipMAC, jnprIP, c.ipName)...)
			if c.extra != nil {
				e.record(c.extra...)
			}
			if c.setup != nil {
				c.setup(e)
			}
			want := e.count(`SELECT count(*) FROM inv_asset`)
			e.record(c.frame...)
			if n := e.count(`SELECT count(*) FROM inv_asset`); n != want {
				t.Errorf("%d devices, want %d", n, want)
			}
			if has(e.auditActions(), "inventory.merge") != (name == "another chassis") { // there :81 joined first, then :80 must not
				t.Errorf("inventory.merge audit rows: %v", e.auditActions())
			}
		})
	}
}

// Review M1 of #722: a scan's fingerprint is a guess, not what the switch states: nmap calling .47 "JUNOS 12" (the walk) does not keep
// the LLDP row apart.
func TestContract_D515_AScanGuessDoesNotKeepThemApart(t *testing.T) {
	e := newEnv(t)
	e.record(seenAt(jnprMgmt, jnprIP, "")...)
	e.record(observe.Observation{AssetHint: observe.AssetHint{MAC: jnprMgmt, IP: netip.MustParseAddr(jnprIP)}, Field: observe.OS, Value: "Juniper JUNOS 12.3", Source: observe.Nmap, Confidence: 0.9})
	e.record(lldp(jnprBase, "")...)
	if n := e.devices(); n != 1 {
		t.Errorf("%d devices, want one", n)
	}
}

// Review LOW of #722: an observation keeps its evidence when it moves.
func TestContract_D515_AMovedObservationKeepsItsEvidence(t *testing.T) {
	e := newEnv(t)
	e.record(lldp(jnprBase, "")...)
	e.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at, evidence) SELECT 'o-test', id, 'vendor', 'Juniper', 'passive', 0.1, last_seen, 'sysObjectID' FROM inv_asset WHERE mac = ?`, jnprBase)
	e.record(seenAt(jnprMgmt, jnprIP, "")...)
	ipID := e.idByMAC(jnprMgmt)
	e.record(lldp(jnprBase, "")...)
	if n := e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ? AND evidence = 'sysObjectID'`, ipID); n != 1 {
		t.Errorf("%d moved observations with their evidence, want 1", n)
	}
}
