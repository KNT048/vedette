package inventory_test

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// Two network cards of one router, numbered by its maker from one block, each seen by a passive sensor at its own address.
const (
	card1 = "00:09:0f:09:00:01"
	card2 = "00:09:0f:09:00:02"
	card9 = "00:09:0f:77:00:09" // another machine of the same maker
)

func cardOf(mac, ip string) []observe.Observation {
	h := observe.AssetHint{MAC: mac, IP: netip.MustParseAddr(ip)}
	return append(dhcp(mac, ip, ""), observe.Observation{AssetHint: h, Field: observe.Kind, Value: "router", Source: observe.Passive, Confidence: 0.7})
}

// twoCards records the two cards as two rows and merges them as a person does; it returns the kept device (the second card's row,
// seen last, keeps the main address).
func twoCards(e *env) string {
	e.t.Helper()
	e.record(cardOf(card1, "192.0.2.1")...)
	e.tick(time.Minute)
	e.record(cardOf(card2, "198.51.100.1")...)
	a, b := e.idOf("192.0.2.1"), e.idOf("198.51.100.1")
	if err := e.svc.Merge(e.ctx(), admin, a, b); err != nil {
		e.t.Fatal(err)
	}
	return a
}

// homeless counts addresses held in two places (two devices, a device and a row, two rows): an address has one home (INV-57).
func (e *env) homeless() int {
	return e.count(`SELECT count(*) FROM (SELECT v FROM (SELECT ip AS v FROM inv_asset WHERE ip IS NOT NULL UNION ALL SELECT ip FROM inv_asset_address WHERE ip IS NOT NULL
		UNION ALL SELECT mac FROM inv_asset WHERE mac IS NOT NULL UNION ALL SELECT mac FROM inv_asset_address WHERE mac IS NOT NULL) GROUP BY v HAVING count(*) > 1)`)
}

// INV-57: the resolver finds a device by any of its addresses. A sighting of the merged card, by MAC or by address only, and a scan of
// its address reach the kept device and make no new one; a scan of one address replaces only what that address showed. The other
// readers (the sweep's address map and known MACs, the add form's duplicate check, the search) see every address.
func TestAddresses_TheDeviceIsFoundByAnyAddress(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := twoCards(e)
	e.tick(time.Minute)
	e.record(cardOf(card1, "192.0.2.1")...)
	e.record(byAddress("192.0.2.1", "rt1-lan.example.com")...)
	if e.devices() != 1 {
		t.Fatalf("%d devices after sightings of the merged card", e.devices())
	}
	scan := func(ip, version string) {
		t.Helper()
		e.tick(time.Minute)
		sw := []observe.Software{{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: version, Confidence: 0.8, Instance: "tcp/22"}}
		if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: netip.MustParseAddr(ip)}, observe.Nmap, nil, sw); err != nil {
			t.Fatal(err)
		}
		if err := e.svc.ReplaceServices(e.ctx(), observe.AssetHint{IP: netip.MustParseAddr(ip)}, observe.Nmap, observe.ServiceScope{},
			[]observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: version, Confidence: 0.8}}); err != nil {
			t.Fatal(err)
		}
	}
	scan("192.0.2.1", "9.6")
	scan("198.51.100.1", "9.8")
	scan("192.0.2.1", "9.6") // the first address again: the second address's reading stays
	if n := e.count(`SELECT count(*) FROM inv_software_reading`); n != 2 || e.devices() != 1 {
		t.Fatalf("%d readings, %d devices after scanning both addresses", n, e.devices())
	}
	d, err := e.svc.Detail(e.ctx(), id)
	if err != nil {
		t.Fatal(err)
	}
	var ports []string
	for _, sv := range d.Asset.Services {
		a := "main"
		if sv.Address != nil {
			a = *sv.Address
		}
		ports = append(ports, sv.Proto+"/"+strconv.Itoa(sv.Port)+" "+a)
	}
	slices.Sort(ports)
	if !slices.Equal(ports, []string{"tcp/22 192.0.2.1", "tcp/22 main"}) {
		t.Errorf("open ports: %v", ports)
	}
	if in, err := e.svc.AddressInUse(e.ctx(), "192.0.2.1"); err != nil || !in {
		t.Errorf("AddressInUse of the other address = %v %v", in, err)
	}
	if m, err := e.svc.AddressMap(e.ctx()); err != nil || m["192.0.2.1"] != id || m["198.51.100.1"] != id {
		t.Errorf("AddressMap = %v %v", m, err)
	}
	if macs, err := e.svc.KnownMACs(e.ctx()); err != nil || !slices.Contains(macs, card1) || !slices.Contains(macs, card2) {
		t.Errorf("KnownMACs = %v %v", macs, err)
	}
	_, err = e.svc.AddDevice(e.ctx(), admin, inventory.AddInput{Vendor: "Acme", Product: "Router", IP: "192.0.2.1"})
	wantAPIError(t, err, 409, "duplicate_ip")
	f, err := inventory.ParseDeviceFilter("false", "", "", "", "", "", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if l, err := e.svc.DevicesPage(e.ctx(), f); err != nil || len(l.Items) != 1 || l.Items[0].ID != id {
		t.Errorf("search by the other address: %+v %v", l.Items, err)
	}
	if e.homeless() != 0 {
		t.Errorf("%d addresses in two places", e.homeless())
	}
}

// An interface that DHCP moves keeps its row (found by its MAC, the row takes the new address); another machine that takes an
// interface's address takes it from the row, which keeps the MAC. No address is ever in two places.
func TestAddresses_AnInterfaceMovesAndLosesItsAddress(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := twoCards(e)
	e.tick(time.Minute)
	e.record(cardOf(card1, "192.0.2.7")...) // the first card's new lease
	if got := e.addresses(id); e.devices() != 1 || !slices.Equal(got, []string{"198.51.100.1 " + card2 + " main", "192.0.2.7 " + card1}) {
		t.Fatalf("after the card moved: %d devices, %v", e.devices(), got)
	}
	e.tick(time.Minute)
	e.record(dhcp(card9, "192.0.2.7", "")...) // another machine now answers there
	if got := e.addresses(id); e.devices() != 2 || !slices.Equal(got, []string{"198.51.100.1 " + card2 + " main", "- " + card1}) {
		t.Fatalf("after another machine took the address: %d devices, %v", e.devices(), got)
	}
	if e.idOf("192.0.2.7") == id || e.homeless() != 0 {
		t.Errorf("the address stayed with the router, or is in two places (%d)", e.homeless())
	}
}

// The merge preview says what a merge would do, and refuses as the merge does: the fields that differ with the value the kept device
// gets, the counts that move, and the refusal of two agents. A merge takes a person's choice of the name where the devices differ, and
// refuses a value none of them has.
func TestAddresses_MergePreviewAndChoice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(cardOf(card1, "192.0.2.1")...)
	e.tick(time.Minute)
	e.record(append(cardOf(card2, "198.51.100.1"), dhcp(card2, "198.51.100.1", "edge-fw")...)...)
	a, b := e.idOf("192.0.2.1"), e.idOf("198.51.100.1")
	p, err := e.svc.MergePreview(e.ctx(), a, []string{b})
	if err != nil {
		t.Fatal(err)
	}
	if p.Refusal != nil || p.Into.ID != a || len(p.From) != 1 || p.Moves.Addresses != 1 || len(p.Differs) != 1 || p.Differs[0].Field != "name" || !p.Differs[0].Choosable {
		t.Fatalf("preview: %+v", p)
	}
	for _, bad := range [][]string{{}, {a}, {b, b}} {
		_, err := e.svc.MergePreview(e.ctx(), a, bad)
		wantAPIError(t, err, 400, "invalid")
	}
	_, err = e.svc.MergePreview(e.ctx(), a, []string{"a-nope"})
	wantAPIError(t, err, 404, "not_found")
	other := "not one of theirs"
	wantAPIError(t, e.svc.MergeMany(e.ctx(), admin, a, []string{b}, inventory.MergeChoice{Name: &other}), 400, "bad_choice")
	pick := "" // the name the merge would not give: the person picks the other device's
	for _, v := range p.Differs[0].Values {
		if v.Value != p.Differs[0].Kept {
			pick = v.Value
		}
	}
	if p.Differs[0].Kept != "edge-fw" || pick == "" {
		t.Fatalf("name values: %+v", p.Differs[0])
	}
	if err := e.svc.MergeMany(e.ctx(), admin, a, []string{b}, inventory.MergeChoice{Name: &pick}); err != nil {
		t.Fatal(err)
	}
	if d, err := e.svc.Device(e.ctx(), a); err != nil || d.UserName == nil || *d.UserName != pick || e.devices() != 1 {
		t.Errorf("after the merge with a picked name: %+v %v; %d devices", d.UserName, err, e.devices())
	}
	e.record(cardOf(card9, "192.0.2.9")...)
	c := e.idOf("192.0.2.9")
	e.exec(`UPDATE inv_asset SET agent_key = 'osquery:node-a' WHERE id = ?`, a)
	e.exec(`UPDATE inv_asset SET agent_key = 'osquery:node-b' WHERE id = ?`, c)
	if p, err := e.svc.MergePreview(e.ctx(), a, []string{c}); err != nil || p.Refusal == nil || p.Refusal.Code != "not_same_device" {
		t.Errorf("two agents: %+v %v", p.Refusal, err)
	}
}

// Split refuses what it cannot do: a text that is no address, an address of another device, the only address, the box. Splitting
// the main address makes the other address the device's main one, approves the new device as the device was, keeps the pair apart and
// writes one audit row.
func TestAddresses_Split(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	box, err := e.svc.EnsureBox(e.ctx(), inventory.BoxInfo{Hostname: "vedette", IP: "192.0.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	id := twoCards(e)
	if err := e.svc.Approve(e.ctx(), admin, id); err != nil {
		t.Fatal(err)
	}
	e.record(cardOf(card9, "192.0.2.9")...)
	_, err = e.svc.Split(e.ctx(), admin, id, "not an address")
	wantAPIError(t, err, 400, "bad_address")
	_, err = e.svc.Split(e.ctx(), admin, id, "192.0.2.9")
	wantAPIError(t, err, 404, "address_not_found")
	_, err = e.svc.Split(e.ctx(), admin, e.idOf("192.0.2.9"), "192.0.2.9")
	wantAPIError(t, err, 409, "only_address")
	_, err = e.svc.Split(e.ctx(), admin, box, "192.0.2.2")
	wantAPIError(t, err, 409, "box_device")
	_, err = e.svc.Split(e.ctx(), admin, "a-nope", "192.0.2.9")
	wantAPIError(t, err, 404, "not_found")
	n := e.devices()
	nw, err := e.svc.Split(e.ctx(), admin, id, strings.ToUpper(card2)) // the main address, by its MAC in any case
	if err != nil {
		t.Fatal(err)
	}
	if got := e.addresses(id); e.devices() != n+1 || !slices.Equal(got, []string{"192.0.2.1 " + card1 + " main"}) {
		t.Fatalf("the device after the split: %d devices, %v", e.devices(), got)
	}
	if got := e.addresses(nw); !slices.Equal(got, []string{"198.51.100.1 " + card2 + " main"}) {
		t.Errorf("the new device: %v", got)
	}
	d, err := e.svc.Device(e.ctx(), nw)
	if err != nil || !d.Approved {
		t.Errorf("the new device is approved as the device was: %+v %v", d.Approved, err)
	}
	if got := e.sameAs(id); len(got) != 0 {
		t.Errorf("the split pair is offered again: %+v", got)
	}
	if got := e.auditBy("inventory.split"); len(got) != 1 || !strings.Contains(got[0], card2+" split off as a device of its own") {
		t.Errorf("audit: %v", got)
	}
	e.tick(time.Minute)
	e.record(cardOf(card2, "198.51.100.1")...)
	e.record(cardOf(card1, "192.0.2.1")...)
	if e.devices() != n+1 || e.homeless() != 0 {
		t.Errorf("after both cards were seen again: %d devices, %d addresses in two places", e.devices(), e.homeless())
	}
}

// A merge keeps each interface's IP and MAC together: a routed interface known by its address only (no MAC) merged with a card seen
// with its MAC never takes that card's MAC as its own. Split off again, the card is a device of its own, and seeing it again changes
// nothing: no device loses an address.
func TestAddresses_MergeKeepsEachInterfaceWhole(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(cardOf(card2, "198.51.100.1")...)
	e.tick(time.Minute)
	e.record(byAddress("192.0.2.1", "fw-wan.example.com")...) // seen last: it keeps the main address
	a, b := e.idOf("192.0.2.1"), e.idOf("198.51.100.1")
	if err := e.svc.Merge(e.ctx(), admin, a, b); err != nil {
		t.Fatal(err)
	}
	if got := e.addresses(a); !slices.Equal(got, []string{"192.0.2.1 - main", "198.51.100.1 " + card2}) {
		t.Fatalf("after the merge: %v", got)
	}
	nw, err := e.svc.Split(e.ctx(), admin, a, "198.51.100.1")
	if err != nil {
		t.Fatal(err)
	}
	e.tick(time.Minute)
	e.record(cardOf(card2, "198.51.100.1")...)
	if got := e.addresses(a); !slices.Equal(got, []string{"192.0.2.1 - main"}) {
		t.Errorf("the device after the card was seen again: %v", got)
	}
	if got := e.addresses(nw); !slices.Equal(got, []string{"198.51.100.1 " + card2 + " main"}) {
		t.Errorf("the split card after it was seen again: %v", got)
	}
	if e.homeless() != 0 {
		t.Errorf("%d addresses in two places", e.homeless())
	}
}
