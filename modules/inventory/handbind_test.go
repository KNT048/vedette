package inventory_test

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/inventory"
)

// #829 (J2), the N100 n71 walk: a device added by hand with its address only binds the MAC a sensor sees at that address only when
// that MAC is the first and only one seen there since the person added it. A person adds "printer .201", the printer is off, DHCP gives
// .201 to a laptop, then to another machine: neither may silently become the approved printer with its declared software.

const (
	xenMAC2 = "00:16:3e:5b:04:04" // the second machine of the n71 walk, burned in
	xenMAC3 = "00:16:3e:5b:01:01" // the machine that bound on n71 (C1, verified live)
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
		id := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.18.201", Name: "nas"})
		if tc.first == burnt1 {
			e.record(dhcp(burnt1, "192.168.18.150", "laptop")...)
		}
		if tc.first != "" {
			e.tick(time.Minute)
			e.record(dhcp(tc.first, "192.168.18.201", "")...)
		}
		e.ev.reset()
		e.tick(time.Hour)
		e.record(arp(xenMAC3, "192.168.18.201")...)
		d := e.device(id)
		bound := d.MAC != nil && *d.MAC == xenMAC3
		announced := len(e.ev.named(inventory.EventAssetDiscovered))
		if bound != (tc.first == "") || announced != map[bool]int{true: 0, false: 1}[bound] {
			t.Fatalf("%s: bound %v, %d announced", tc.name, bound, announced)
		}
		if bound {
			continue
		}
		if d.IP != "192.168.18.201" || d.MAC != nil || !d.Approved {
			t.Errorf("%s: the hand-added device: ip %s mac %v approved %v; want .201, no MAC, approved", tc.name, d.IP, d.MAC, d.Approved)
		}
		newcomer := e.idByMAC(xenMAC3)
		if nd := e.device(newcomer); nd.Approved || nd.Origin != "discovered" {
			t.Errorf("%s: the newcomer is approved %v origin %s", tc.name, nd.Approved, nd.Origin)
		}
		offered := e.sameAs(id)
		if !offersWith(offered, newcomer, "00:16:3e:5b:01:01 at 192.168.18.201, the address nas was added with") {
			t.Errorf("%s: the hand-added device offers %+v; want the newcomer, seen at its address", tc.name, offered)
		}
		if !offersWith(e.sameAs(newcomer), id, "the address nas was added with") {
			t.Errorf("%s: the newcomer offers %+v", tc.name, e.sameAs(newcomer))
		}
		// Merge: the person's answer makes them one device, the hand-added id kept.
		if err := e.svc.Merge(e.ctx(), admin, id, newcomer); err != nil {
			t.Fatalf("%s: merge: %v", tc.name, err)
		}
		if d := e.device(id); d.MAC == nil || *d.MAC != xenMAC3 || d.IP != "192.168.18.201" || !d.Approved {
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

// The n71 walk exactly, on this build: "ipchg-c1" added at .201 with no MAC at 15:02; the first machine (burned in) answers there 34 s
// later; the hand-added device binds it and follows it to .202; at 17:00:54 another machine with a burned-in MAC takes .201. It is a new,
// announced device; the hand-added device stays the first machine, approved, notes and software kept.
func TestContract_829_TheN71Walk(t *testing.T) {
	e := newEnv(t)
	id := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.18.201", Name: "ipchg-c1"})
	notes := "C1"
	if err := e.svc.PatchDevice(e.ctx(), admin, id, inventory.Patch{Notes: &notes}); err != nil {
		t.Fatal(err)
	}
	e.tick(34 * time.Second)
	e.record(arp(xenMAC, "192.168.18.201")...)
	e.tick(30 * time.Minute)
	e.record(dhcp(xenMAC, "192.168.18.202", "")...)
	e.ev.reset()
	e.tick(time.Hour + 28*time.Minute)
	e.record(arp(xenMAC2, "192.168.18.201")...)
	d := e.device(id)
	if d.MAC == nil || *d.MAC != xenMAC || d.IP != "192.168.18.202" || !d.Approved || d.Notes == nil || *d.Notes != notes || len(d.Software) != 1 {
		t.Errorf("the hand-added device: mac %v ip %s approved %v notes %v software %d; want %s at .202, approved, notes and software kept",
			d.MAC, d.IP, d.Approved, d.Notes, len(d.Software), xenMAC)
	}
	newcomer := e.idByMAC(xenMAC2)
	if newcomer == id || e.devices() != 2 || len(e.ev.named(inventory.EventAssetDiscovered)) != 1 || e.idOf("192.168.18.201") != newcomer {
		t.Errorf("the second machine: id %s, %d devices, %d announced; want a new announced device at .201", newcomer, e.devices(), len(e.ev.named(inventory.EventAssetDiscovered)))
	}
}

// The n71 data as the N100 holds it (the first machine's sighting at .201 did not bind: it was already a device of its own, which later
// moved to .202): the second machine at .201 within 72 h does not bind, is announced, and is offered with the hand-added device.
func TestContract_829_TheN71DataDoesNotBindTheSecondMachine(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(xenMAC, "192.168.18.150", "")...) // the first machine, already known
	id := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.18.201", Name: "ipchg-c1"})
	first := e.idByMAC(xenMAC)
	e.tick(34 * time.Second)
	e.record(arp(xenMAC, "192.168.18.201")...) // the hand-added device keeps .201; the first machine is not it
	e.tick(30 * time.Minute)
	e.record(dhcp(xenMAC, "192.168.18.202", "")...)
	e.ev.reset()
	e.tick(time.Hour + 28*time.Minute)
	e.record(arp(xenMAC2, "192.168.18.201")...)
	d := e.device(id)
	if d.MAC != nil || d.IP != "192.168.18.201" || !d.Approved {
		t.Errorf("the hand-added device bound %v (ip %s approved %v); want no MAC, at .201, approved", d.MAC, d.IP, d.Approved)
	}
	second := e.idByMAC(xenMAC2)
	if second == id || e.devices() != 3 || len(e.ev.named(inventory.EventAssetDiscovered)) != 1 {
		t.Errorf("%d devices, %d announced; want 3 and the second machine announced", e.devices(), len(e.ev.named(inventory.EventAssetDiscovered)))
	}
	if e.device(first).IP != "192.168.18.202" {
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
	id := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.18.201", Name: "nas"})
	e.record(dhcp(privMac1, "192.168.18.201", "")...) // a guest phone first
	e.record(arp(xenMAC, "192.168.18.201")[:1]...)    // the vendor alone, in a batch of its own: a waiting duplicate
	e.tick(time.Minute)
	e.record(dhcp(xenMAC, "192.168.18.201", "")...)
	if d := e.device(id); d.MAC != nil || e.devices() != 3 {
		t.Errorf("the hand-added device bound %v; %d devices, want 3", d.MAC, e.devices())
	}
}
