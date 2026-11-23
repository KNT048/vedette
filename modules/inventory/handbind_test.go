package inventory_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// #829, on a test box: a device added by hand with its address only binds the MAC a sensor sees at that address only when
// that MAC is the first and only one seen there since the person added it. A person adds "printer .201", the printer is off, DHCP gives
// .201 to a laptop, then to another machine: neither may silently become the approved printer with its declared software.

const (
	xenMAC2 = "00:16:3e:5b:04:04" // the second test machine, burned in
	xenMAC3 = "00:16:3e:5b:01:01" // the machine that bound in the test (verified live)
)

// The first and only MAC at a freshly added address binds (C1); a second MAC seen there after another one does not: the newcomer is a
// new, announced device without the address, and the person is offered the pair.
func TestContract_829_OnlyTheFirstMACAtAHandAddedAddressBinds(t *testing.T) {
	cases := []struct {
		name  string
		first string // a MAC seen at the address before (it does not bind, or is known elsewhere); "" for none
	}{
		{"first MAC", ""},
		{"after a private MAC (a guest phone)", privMac1},
		{"after a machine known at another address", burnt1},
	}
	for _, tc := range cases {
		e := newEnv(t)
		id := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.142.201", Name: "nas"})
		if tc.first == burnt1 {
			e.record(dhcp(burnt1, "192.168.142.150", "laptop")...)
		}
		if tc.first != "" {
			e.tick(time.Minute)
			e.record(dhcp(tc.first, "192.168.142.201", "")...)
		}
		e.ev.reset()
		e.tick(time.Hour)
		e.record(arp(xenMAC3, "192.168.142.201")...)
		d := e.device(id)
		bound := d.MAC != nil && *d.MAC == xenMAC3
		announced := len(e.ev.named(inventory.EventAssetDiscovered))
		if bound != (tc.first == "") || announced != map[bool]int{true: 0, false: 1}[bound] {
			t.Fatalf("%s: bound %v, %d announced", tc.name, bound, announced)
		}
		if bound {
			continue
		}
		if d.IP != "192.168.142.201" || d.MAC != nil || !d.Approved {
			t.Errorf("%s: the hand-added device: ip %s mac %v approved %v; want .201, no MAC, approved", tc.name, d.IP, d.MAC, d.Approved)
		}
		newcomer := e.idByMAC(xenMAC3)
		if nd := e.device(newcomer); nd.Approved || nd.Origin != "discovered" {
			t.Errorf("%s: the newcomer is approved %v origin %s", tc.name, nd.Approved, nd.Origin)
		}
		offered := e.sameAs(id)
		if !offersWith(offered, newcomer, "00:16:3e:5b:01:01 was seen at 192.168.142.201, the address nas was added with") {
			t.Errorf("%s: the hand-added device offers %+v; want the newcomer, seen at its address", tc.name, offered)
		}
		if !offersWith(e.sameAs(newcomer), id, "the address nas was added with") {
			t.Errorf("%s: the newcomer offers %+v", tc.name, e.sameAs(newcomer))
		}
		// Merge: the person's answer makes them one device, the hand-added id kept.
		if err := e.svc.Merge(e.ctx(), admin, id, newcomer); err != nil {
			t.Fatalf("%s: merge: %v", tc.name, err)
		}
		if d := e.device(id); d.MAC == nil || *d.MAC != xenMAC3 || d.IP != "192.168.142.201" || !d.Approved {
			t.Errorf("%s: after the merge: mac %v ip %s approved %v", tc.name, d.MAC, d.IP, d.Approved)
		}
	}
}

func offersWith(list []inventory.PossibleSame, id, why string) bool {
	for _, p := range list {
		if p.ID == id && strings.Contains(p.Why, why) {
			return true
		}
	}
	return false
}

// The test session exactly, on this build: "ipchg-c1" added at .201 with no MAC at 15:02; the first machine (burned in) answers there 34 s
// later; the hand-added device binds it and follows it to .202; at 17:00:54 another machine with a burned-in MAC takes .201. It is a new,
// announced device; the hand-added device stays the first machine, approved, notes and software kept.
func TestContract_829_TheRecordedSessionKeepsTheHandAddedDevice(t *testing.T) {
	e := newEnv(t)
	id := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.142.201", Name: "ipchg-c1"})
	notes := "C1"
	if err := e.svc.PatchDevice(e.ctx(), admin, id, inventory.Patch{Notes: &notes}); err != nil {
		t.Fatal(err)
	}
	e.tick(34 * time.Second)
	e.record(arp(xenMAC, "192.168.142.201")...)
	e.tick(30 * time.Minute)
	e.record(dhcp(xenMAC, "192.168.142.202", "")...)
	e.ev.reset()
	e.tick(time.Hour + 28*time.Minute)
	e.record(arp(xenMAC2, "192.168.142.201")...)
	d := e.device(id)
	if d.MAC == nil || *d.MAC != xenMAC || d.IP != "192.168.142.202" || !d.Approved || d.Notes == nil || *d.Notes != notes || len(d.Software) != 1 {
		t.Errorf("the hand-added device: mac %v ip %s approved %v notes %v software %d; want %s at .202, approved, notes and software kept",
			d.MAC, d.IP, d.Approved, d.Notes, len(d.Software), xenMAC)
	}
	newcomer := e.idByMAC(xenMAC2)
	if newcomer == id || e.devices() != 2 || len(e.ev.named(inventory.EventAssetDiscovered)) != 1 || e.idOf("192.168.142.201") != newcomer {
		t.Errorf("the second machine: id %s, %d devices, %d announced; want a new announced device at .201", newcomer, e.devices(), len(e.ev.named(inventory.EventAssetDiscovered)))
	}
}

// The test data as the box holds it (the first machine's sighting at .201 did not bind: it was already a device of its own, which later
// moved to .202): the second machine at .201 within 72 h does not bind, is announced, and is offered with the hand-added device.
func TestContract_829_TheRecordedDataDoesNotBindTheSecondMachine(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(xenMAC, "192.168.142.150", "")...) // the first machine, already known
	id := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.142.201", Name: "ipchg-c1"})
	first := e.idByMAC(xenMAC)
	e.tick(34 * time.Second)
	e.record(arp(xenMAC, "192.168.142.201")...) // the hand-added device keeps .201; the first machine is not it
	e.tick(30 * time.Minute)
	e.record(dhcp(xenMAC, "192.168.142.202", "")...)
	e.ev.reset()
	e.tick(time.Hour + 28*time.Minute)
	e.record(arp(xenMAC2, "192.168.142.201")...)
	d := e.device(id)
	if d.MAC != nil || d.IP != "192.168.142.201" || !d.Approved {
		t.Errorf("the hand-added device bound %v (ip %s approved %v); want no MAC, at .201, approved", d.MAC, d.IP, d.Approved)
	}
	second := e.idByMAC(xenMAC2)
	if second == id || e.devices() != 3 || len(e.ev.named(inventory.EventAssetDiscovered)) != 1 {
		t.Errorf("%d devices, %d announced; want 3 and the second machine announced", e.devices(), len(e.ev.named(inventory.EventAssetDiscovered)))
	}
	if e.device(first).IP != "192.168.142.202" {
		t.Errorf("the first machine is at %s", e.device(first).IP)
	}
	got := e.sameAs(id)
	if !offersWith(got, second, "the address ipchg-c1 was added with") || !offersWith(got, first, "the address ipchg-c1 was added with") {
		t.Errorf("the hand-added device offers %+v; want both machines seen at its address", got)
	}
	// Keep separate is honoured: the pair is not offered again.
	if err := e.svc.KeepSeparate(e.ctx(), admin, id, first); err != nil {
		t.Fatal(err)
	}
	if offersWith(e.sameAs(id), first, "") {
		t.Errorf("a pair kept separate is offered again: %+v", e.sameAs(id))
	}
}

// The n70 fold (review r1 M1 of #872) follows the same rule: a waiting duplicate of a burned-in MAC is folded into the hand-added
// device only when no other MAC was seen at its address since it was added.
func TestContract_829_AWaitingDuplicateIsNotFoldedAfterAnotherMAC(t *testing.T) {
	e := newEnv(t)
	id := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.142.201", Name: "nas"})
	e.record(dhcp(privMac1, "192.168.142.201", "")...) // a guest phone first
	e.record(arp(xenMAC, "192.168.142.201")[:1]...)    // the vendor alone, in a batch of its own: a waiting duplicate
	e.tick(time.Minute)
	e.record(dhcp(xenMAC, "192.168.142.201", "")...)
	if d := e.device(id); d.MAC != nil || e.devices() != 3 {
		t.Errorf("the hand-added device bound %v; %d devices, want 3", d.MAC, e.devices())
	}
}

// An agent's report is hinted by its address only and carries its card as a mac observation (osquery, Wazuh): the same rule holds
// (review r1 H1 of the n71 fix). After another MAC was seen at the hand-added address, the agent's machine is a device of its own,
// announced; the hand-added device keeps no MAC, no agent and its own software. As the first and only machine there, it is the device
// (C1).
func TestContract_829_AnAgentAtASharedHandAddedAddressIsItsOwnDevice(t *testing.T) {
	sw := []observe.Software{{Display: "OpenSSH 9.6", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6", Confidence: 0.95}}
	at := netip.MustParseAddr("192.168.142.201")
	wazuh := func(mac string) []observe.Observation {
		h := observe.AssetHint{IP: at}
		return []observe.Observation{{AssetHint: h, Field: observe.Hostname, Value: "wz-host", Source: observe.Agent, Confidence: 0.9},
			{AssetHint: h, Field: observe.MAC, Value: mac, Source: observe.Agent, Confidence: 0.9}}
	}
	cases := []struct {
		name   string
		before []string // MACs a sensor saw at the address first
		wazuh  bool
		bound  bool
	}{
		{"osquery first (C1)", nil, false, true},
		{"osquery after a guest phone", []string{privMac1}, false, false},
		{"osquery after a phone and a sensor sighting of the laptop", []string{privMac1, burnt1}, false, false},
		{"wazuh first (C1)", nil, true, true},
		{"wazuh after two other machines", []string{privMac1, burnt2}, true, false},
	}
	for _, tc := range cases {
		e := newEnv(t)
		id := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.142.201", Name: "nas"})
		e.ev.reset()
		for _, m := range tc.before {
			e.tick(time.Minute)
			e.record(dhcp(m, "192.168.142.201", "")...)
		}
		e.tick(time.Minute)
		if tc.wazuh {
			e.record(wazuh(burnt1)...)
			if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: at}, observe.Osquery, nil, sw); err != nil {
				t.Fatal(err)
			}
		} else {
			e.record(osq("192.168.142.201")...)
			if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: at, Agent: "osquery:node-a"}, observe.Osquery, nil, sw); err != nil {
				t.Fatal(err)
			}
		}
		d := e.device(id)
		bound := d.MAC != nil && *d.MAC == burnt1
		agent := e.count(`SELECT count(*) FROM inv_asset WHERE id = ? AND agent_key IS NOT NULL`, id)
		if bound != tc.bound || len(d.Software) != map[bool]int{true: 2, false: 1}[tc.bound] || (agent == 1) != (tc.bound && !tc.wazuh) {
			t.Errorf("%s: the hand-added device: mac %v, %d software, agent %d; want bound %v", tc.name, d.MAC, len(d.Software), agent, tc.bound)
		}
		announced := 0 // the agent's machine
		for _, ev := range e.ev.named(inventory.EventAssetDiscovered) {
			if ev.Data.(inventory.AssetEvent).AssetID == e.idByMAC(burnt1) {
				announced++
			}
		}
		if merged := len(e.ev.named(inventory.EventAssetMerged)); merged != 0 || tc.bound != (announced == 0) {
			t.Errorf("%s: %d announced, %d merged", tc.name, announced, merged)
		}
		if !tc.bound && !offersWith(e.sameAs(id), e.idByMAC(burnt1), "the address nas was added with") {
			t.Errorf("%s: the agent's machine is not offered: %+v", tc.name, e.sameAs(id))
		}
	}
}

// Two MACs at a freshly added address in one batch: neither is known to be the person's machine, so neither binds (review r1 L2).
func TestContract_829_TwoMACsInOneBatchBindNothing(t *testing.T) {
	e := newEnv(t)
	id := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.142.201", Name: "nas"})
	e.record(append(dhcp(xenMAC, "192.168.142.201", ""), dhcp(xenMAC2, "192.168.142.201", "")...)...)
	if d := e.device(id); d.MAC != nil || d.IP != "192.168.142.201" || e.devices() != 3 {
		t.Errorf("the hand-added device: mac %v ip %s; %d devices, want no MAC, .201, 3", d.MAC, d.IP, e.devices())
	}
}

// The card an agent claims at a shared hand-added address is never a lookup key (review r2 H-new-1 of the n71 fix): a node there that
// names the MAC of an approved device elsewhere (osquery, or a Wazuh report with no key) writes nothing on that device, binds nothing
// to it, and moves nothing; it is a device of its own. With no card at all (a tun interface) the same holds, and the enrolment does
// not approve or type the hand-added device by its address (M-new-1); a Wazuh report with neither a key nor a card is held.
func TestContract_829_AClaimedCardAtASharedHandAddedAddressIsNoKey(t *testing.T) {
	at := netip.MustParseAddr("192.168.142.201")
	report := func(agent, card string) []observe.Observation {
		h := observe.AssetHint{IP: at, Agent: agent}
		out := []observe.Observation{{AssetHint: h, Field: observe.Hostname, Value: "evil", Source: observe.Agent, Confidence: 0.9},
			{AssetHint: h, Field: observe.OS, Value: "Microsoft Windows 11 Pro", Source: observe.Agent, Confidence: 0.95}}
		if card != "" {
			out = append(out, observe.Observation{AssetHint: h, Field: observe.MAC, Value: card, Source: observe.Agent, Confidence: 0.9})
		}
		return out
	}
	for _, tc := range []struct{ name, agent, card string }{
		{"osquery naming dc01", "osquery:evil", burnt2},
		{"wazuh naming dc01", "", burnt2},
		{"osquery with no card", "osquery:evil", ""},
		{"wazuh with no card: held", "", ""},
	} {
		e := newEnv(t)
		e.record(dhcp(burnt2, "192.168.142.50", "dc01")...)
		dc := e.idByMAC(burnt2)
		if err := e.svc.Approve(e.ctx(), admin, dc); err != nil {
			t.Fatal(err)
		}
		id := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.142.201", Name: "nas"})
		e.tick(time.Minute)
		e.record(dhcp(privMac1, "192.168.142.201", "")...)
		e.tick(time.Minute)
		e.ev.reset()
		e.record(report(tc.agent, tc.card)...)
		if tc.agent != "" {
			if _, err := e.svc.ApproveEnrolled(e.ctx(), observe.AssetHint{IP: at, Agent: tc.agent}, tc.card, "osquery enrolment", false); err != nil {
				t.Fatal(err)
			}
		}
		e.tick(time.Minute)
		again := "aa:00:00:00:00:77" // the same node again (osquery: another card; Wazuh, keyless: the same), then from elsewhere
		if tc.agent == "" {
			again = tc.card
		}
		e.record(report(tc.agent, again)...)
		e.tick(time.Minute)
		if tc.agent != "" {
			h := observe.AssetHint{IP: netip.MustParseAddr("192.168.142.77"), Agent: tc.agent}
			e.record(observe.Observation{AssetHint: h, Field: observe.MAC, Value: "aa:00:00:00:00:77", Source: observe.Agent, Confidence: 0.9})
		}
		d := e.device(dc)
		if d.IP != "192.168.142.50" || d.MAC == nil || *d.MAC != burnt2 || d.Hostname == nil || *d.Hostname != "dc01" || d.OS != nil ||
			e.count(`SELECT count(*) FROM inv_asset WHERE id = ? AND agent_key IS NOT NULL`, dc) != 0 {
			t.Errorf("%s: dc01 changed: ip %s mac %v host %v os %v", tc.name, d.IP, d.MAC, d.Hostname, d.OS)
		}
		h := e.device(id)
		if h.MAC != nil || h.OS != nil || h.Hostname == nil || *h.Hostname != "nas" || h.Kind != "unknown" || len(h.Software) != 1 ||
			e.count(`SELECT count(*) FROM inv_asset WHERE id = ? AND agent_key IS NOT NULL`, id) != 0 {
			t.Errorf("%s: the hand-added device changed: mac %v os %v host %v kind %s", tc.name, h.MAC, h.OS, h.Hostname, h.Kind)
		}
		want := 1 // the node's own device; a report with no key and no card is held (nothing would find its device again)
		if tc.agent == "" && tc.card == "" {
			want = 0
		}
		if got := len(e.ev.named(inventory.EventAssetDiscovered)); got != want {
			t.Errorf("%s: %d announced; want %d", tc.name, got, want)
		}
	}
}

// A binding keyHit dropped as a spoof stays dropped when the node then reports from a shared hand-added address (review r2 H-new-1).
func TestContract_829_ADroppedBindingStaysDroppedAtASharedHandAddedAddress(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(burnt1, "192.168.142.20", "")...)
	x := e.idOf("192.168.142.20")
	e.tick(time.Minute)
	e.record(osq("192.168.142.20")...)
	e.tick(time.Minute)
	e.record(osq("192.168.142.30")...)
	e.tick(time.Minute)
	e.record(dhcp(burnt1, "192.168.142.20", "")...)
	id := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.142.201", Name: "nas"})
	e.tick(time.Minute)
	e.record(dhcp(privMac1, "192.168.142.201", "")...)
	e.tick(time.Minute)
	e.record(osq("192.168.142.201")...)
	if e.count(`SELECT count(*) FROM inv_asset WHERE id IN (?, ?) AND agent_key IS NOT NULL`, x, id) != 0 || e.device(x).IP != "192.168.142.20" {
		t.Errorf("the dropped binding came back, or the hand-added device took the node: x at %s", e.device(x).IP)
	}
}
