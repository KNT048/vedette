package inventory_test

import (
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/inventory"
)

// A router with two network cards from one block: the base MAC its LLDP frames name as the chassis, and the card that answers at its
// main address. The router answers on a second address too.
const (
	rtBase   = "00:0c:42:10:20:30"
	rtCard   = "00:0c:42:10:20:32"
	rtMain   = "192.0.2.10"
	rtSecond = "192.0.2.20"
	rtOther  = "3c:22:fb:00:00:77" // another machine that later answers at the second address
)

// mainIP is the main address of device id as every reader shows it (the Devices list and the device page read the same column).
func (e *env) mainIP(id string) string {
	e.t.Helper()
	return e.device(id).IP
}

// A card that answers on two addresses (a router with a second address on its LAN port, a router answering ARP for another
// address) keeps one main address: the second address becomes one of its other addresses, shown with when it was seen, and the
// sightings of either address that follow, in any order and hours apart, never move the main address back and forth. A run that
// checks the device at its main address is then never stopped as "no longer at the address", and the Devices list, the device
// page and the run title agree. Another machine that later answers at the second address is a device of its own.
func TestAddresses_ACardOnTwoAddressesKeepsOneMainAddress(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(dhcp(rtCard, rtMain, "edge-gw")...)
	id := e.idOf(rtMain)
	e.tick(2 * time.Minute)
	e.record(dhcp(rtCard, rtSecond, "")...) // the same card answers at the second address moments later: a second address, not a move
	if got := e.addresses(id); e.devices() != 1 || e.mainIP(id) != rtMain || !slices.Equal(got, []string{rtMain + " " + rtCard + " main", rtSecond + " -"}) {
		t.Fatalf("after the card answered at a second address: %d devices, main %s, addresses %v; want one device, main %s, %s as another address",
			e.devices(), e.mainIP(id), got, rtMain, rtSecond)
	}
	moves := 0
	for i, ip := range []string{rtMain, rtSecond, rtMain, rtSecond, rtSecond, rtMain, rtSecond} { // hours apart, as a sweep and the passive sensor see it
		e.tick(5 * time.Hour)
		e.ev.reset()
		e.record(dhcp(rtCard, ip, "")...)
		if e.mainIP(id) != rtMain {
			moves++
			t.Errorf("sighting %d at %s moved the main address to %s", i, ip, e.mainIP(id))
		}
	}
	if moves != 0 || e.devices() != 1 {
		t.Fatalf("%d moves of the main address, %d devices; want none and one", moves, e.devices())
	}
	e.record(byAddress(rtSecond, "edge-gw-2.example.com")...) // a scan by address only reaches the same router
	if e.devices() != 1 {
		t.Fatalf("a sighting by address only of the second address: %d devices", e.devices())
	}
	e.tick(time.Minute)
	e.record(dhcp(rtOther, rtSecond, "")...) // another machine now answers at the second address: never the router's card
	if got := e.addresses(id); e.devices() != 2 || e.idOf(rtSecond) == id || e.mainIP(id) != rtMain || !slices.Equal(got, []string{rtMain + " " + rtCard + " main"}) {
		t.Errorf("after another machine took the second address: %d devices, %s held by the router %v, addresses %v", e.devices(), rtSecond, e.idOf(rtSecond) == id, got)
	}
	if e.homeless() != 0 {
		t.Errorf("%d addresses in two places", e.homeless())
	}
}

// A card seen at a new address long after its last sighting at the old one moved (DHCP gave it a new lease): the main address
// follows it at once, and the old address is not kept, as before. A card that moves back later follows again.
func TestAddresses_ACardThatMovesIsFollowed(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(dhcp(rtCard, rtMain, "edge-gw")...)
	id := e.idOf(rtMain)
	e.tick(time.Hour)
	e.record(dhcp(rtCard, rtSecond, "")...)
	if got := e.addresses(id); e.mainIP(id) != rtSecond || !slices.Equal(got, []string{rtSecond + " " + rtCard + " main"}) {
		t.Fatalf("after the move: main %s, addresses %v; want %s only", e.mainIP(id), got, rtSecond)
	}
	e.tick(40 * time.Minute)
	e.record(dhcp(rtCard, rtMain, "")...)
	if got := e.addresses(id); e.mainIP(id) != rtMain || !slices.Equal(got, []string{rtMain + " " + rtCard + " main"}) {
		t.Errorf("after the move back: main %s, addresses %v; want %s only", e.mainIP(id), got, rtMain)
	}
}

// A card seen at both addresses and then only at the second one, long after the main address last answered, went there (a person
// re-addressed it): the second address becomes the main one, once, and the old one stays listed as an address of the card with when it
// last answered, so a later sighting there moves nothing back.
func TestAddresses_ACardThatLeftItsMainAddressIsFollowedOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(dhcp(rtCard, rtMain, "edge-gw")...)
	id := e.idOf(rtMain)
	e.tick(2 * time.Minute)
	e.record(dhcp(rtCard, rtSecond, "")...)
	e.tick(time.Hour)
	e.ev.reset()
	e.record(dhcp(rtCard, rtSecond, "")...)
	if got := e.addresses(id); e.mainIP(id) != rtSecond || !slices.Equal(got, []string{rtSecond + " " + rtCard + " main", rtMain + " -"}) || e.updatedFor(id) != 1 {
		t.Fatalf("after the card stayed at the second address: main %s, addresses %v, %d updated; want %s main, %s kept, announced once", e.mainIP(id), got, e.updatedFor(id), rtSecond, rtMain)
	}
	for range 3 {
		e.tick(3 * time.Hour)
		e.record(dhcp(rtCard, rtMain, "")...)
		e.record(dhcp(rtCard, rtSecond, "")...)
		if e.mainIP(id) != rtSecond {
			t.Fatalf("a later sighting moved the main address back to %s", e.mainIP(id))
		}
	}
	if e.devices() != 1 || e.homeless() != 0 {
		t.Errorf("%d devices, %d addresses in two places", e.devices(), e.homeless())
	}
}

// A router's second card, whose MAC its LLDP frames name as the chassis (a join left it on the router as a mark), seen at an address
// of its own is the same router: that address becomes one of the router's other addresses, with the card's MAC, and the router's
// main address stays. No second device of the router's name is made, announced or checked.
func TestAddresses_ARoutersSecondCardIsNotASecondDevice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(seenAt(rtCard, rtMain, "edge-gw")...)
	id := e.idByMAC(rtCard)
	e.tick(time.Minute)
	e.record(lldp(rtBase, "edge-gw")...)
	if e.devices() != 1 {
		t.Fatalf("%d devices after the LLDP frame; want the router only", e.devices())
	}
	e.tick(time.Minute)
	e.ev.reset()
	e.record(dhcp(rtBase, rtSecond, "")...)
	want := []string{rtMain + " " + rtCard + " main", rtSecond + " " + rtBase}
	if got := e.addresses(id); e.devices() != 1 || e.mainIP(id) != rtMain || !slices.Equal(got, want) {
		t.Fatalf("after the chassis card was seen at its address: %d devices, main %s, addresses %v; want one device, addresses %v", e.devices(), e.mainIP(id), got, want)
	}
	if n := len(e.ev.named(inventory.EventAssetDiscovered)); n != 0 {
		t.Errorf("%d discovered events: the second card was announced as a new device", n)
	}
	for range 2 { // the frames and both cards again: still one router, the same main address
		e.tick(20 * time.Minute)
		e.record(lldp(rtBase, "edge-gw")...)
		e.record(dhcp(rtBase, rtSecond, "")...)
		e.record(seenAt(rtCard, rtMain, "")...)
	}
	if got := e.addresses(id); e.devices() != 1 || !slices.Equal(got, want) {
		t.Errorf("after more sightings: %d devices, addresses %v", e.devices(), got)
	}
	if e.homeless() != 0 {
		t.Errorf("%d addresses in two places", e.homeless())
	}
}

// A second device an earlier version made of a router's chassis card (its MAC is the router's chassis mark, it has an address of its
// own) joins the router at its next sighting: one device, the router's id and main address, the card's address one of its others.
func TestAddresses_AnEarlierDuplicateOfAChassisCardJoinsTheRouter(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(seenAt(rtCard, rtMain, "edge-gw")...)
	id := e.idByMAC(rtCard)
	e.tick(time.Minute)
	e.record(lldp(rtBase, "edge-gw")...)
	// the duplicate as an earlier version stored it: a discovered device of the chassis MAC at the second address
	e.exec(`INSERT INTO inv_asset (id, ip, mac, ip_confirmed_at, kind, origin, approved, fragile, first_seen, last_seen) VALUES ('a-dup', ?, ?, '2026-01-01T00:00:00.000Z', 'switch', 'discovered', 0, 0, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`,
		rtSecond, rtBase)
	if e.devices() != 2 {
		t.Fatalf("%d devices before the next sighting", e.devices())
	}
	e.tick(time.Minute)
	e.record(dhcp(rtBase, rtSecond, "")...)
	want := []string{rtMain + " " + rtCard + " main", rtSecond + " " + rtBase}
	if got := e.addresses(id); e.devices() != 1 || e.mainIP(id) != rtMain || !slices.Equal(got, want) {
		t.Errorf("after the next sighting: %d devices, main %s, addresses %v; want one device, addresses %v", e.devices(), e.mainIP(id), got, want)
	}
	if !has(e.auditActions(), "inventory.merge") {
		t.Errorf("no inventory.merge audit row: %v", e.auditActions())
	}
}
