package inventory_test

import (
	"context"
	"database/sql"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// sightedBy records what a report sends before its lists (agent-intake's pull and a device check record the device's facts first): a
// list by address only attaches to the device its report's observations made, never makes one (INV-59).
func sightedBy(ctx context.Context, t testing.TB, svc *inventory.Service, hint observe.AssetHint, src observe.Source) {
	t.Helper()
	if err := svc.Record(ctx, []observe.Observation{{AssetHint: hint, Field: observe.Kind, Value: "unknown", Source: observe.ClassOf(src), Confidence: 0.1}}); err != nil {
		t.Fatal(err)
	}
}

// ok fails the test on an error.
func (e *env) ok(err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatal(err)
	}
}

// auditDetails are the details of the audit rows of one action, oldest first.
func (e *env) auditDetails(action string) []string {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT detail FROM core_audit WHERE action = ? ORDER BY seq`, action)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

// The lifecycle of a found device, as one table (INV-9, INV-49, INV-59): every way a device comes in, and the one state each ends in.
// Every reader agrees with that state: the Devices list holds the added devices only, To review the review ones (its count, its notice
// list ToReviewIDs), its Seen briefly group the quiet ones, and a removed device is in none of them and is not made again by the same
// sightings.
func TestContract_DeviceLifecycleMatrix(t *testing.T) {
	t.Parallel()
	const (
		ip      = "10.0.10.31"
		burnt   = "3c:22:fb:00:00:31" // a MAC a maker burned in
		private = "c2:31:86:3f:8c:31" // a private Wi-Fi address
	)
	addr := netip.MustParseAddr(ip)
	scan := func(mac string) []observe.Observation {
		return []observe.Observation{obs(addr, mac, observe.Hostname, "host-31", observe.Nmap, 0.6)}
	}
	service := func(e *env, mac string) {
		e.t.Helper()
		if err := e.svc.AddServices(e.ctx(), observe.AssetHint{IP: addr, MAC: mac}, observe.Nmap, []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Confidence: 0.9}}); err != nil {
			e.t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name string
		// in brings the device in and returns its id ("" when it must not exist: removed)
		in   func(e *env) string
		want inventory.DeviceState
	}{
		{"found by a scan only", func(e *env) string { e.record(scan(burnt)...); return e.idByMAC(burnt) }, inventory.DeviceReview},
		{"heard by the passive sensor only", func(e *env) string { e.record(dhcp(burnt, ip, "")...); return e.idByMAC(burnt) }, inventory.DeviceReview},
		{"scan and passive", func(e *env) string {
			e.record(dhcp(burnt, ip, "printer")...)
			e.record(scan(burnt)...)
			return e.idByMAC(burnt)
		}, inventory.DeviceReview},
		{"found by a scan with an open service", func(e *env) string { e.record(scan(burnt)...); service(e, burnt); return e.idByMAC(burnt) }, inventory.DeviceReview},
		{"private address, nothing to look at, under a day", func(e *env) string { e.record(dhcp(private, ip, "iPhone")...); return e.idByMAC(private) }, inventory.DeviceSeen},
		{"private address with an open service", func(e *env) string {
			e.record(dhcp(private, ip, "iPhone")...)
			service(e, private)
			return e.idByMAC(private)
		}, inventory.DeviceReview},
		{"private address seen over more than a day", func(e *env) string {
			e.record(dhcp(private, ip, "iPhone")...)
			e.tick(25 * time.Hour)
			e.record(dhcp(private, ip, "iPhone")...)
			return e.idByMAC(private)
		}, inventory.DeviceReview},
		{"found, then added by a person", func(e *env) string {
			e.record(dhcp(private, ip, "iPhone")...)
			id := e.idByMAC(private)
			e.ok(e.svc.Approve(e.ctx(), "it@acme.example", id))
			return id
		}, inventory.DeviceAdded},
		{"added by hand", func(e *env) string {
			return e.addDevice(inventory.AddInput{Vendor: "Contoso", Product: "Gizmo 2", Version: "2", IP: ip})
		}, inventory.DeviceAdded},
		{"its agent enrolled and reported", func(e *env) string {
			e.record(osq(ip)...)
			id := e.idByMAC(burnt1)
			if _, err := e.svc.ApproveEnrolled(e.ctx(), observe.AssetHint{IP: addr, Agent: "osquery:node-a"}, burnt1, "osquery on \"build01\" enrolled", true); err != nil {
				e.t.Fatal(err)
			}
			return id
		}, inventory.DeviceAdded},
		{"SNMP turned on by a person, not added", func(e *env) string {
			e.record(scan(burnt)...)
			id := e.idByMAC(burnt)
			on := inventory.SourceOn
			if _, err := e.svc.ChangeSources(e.ctx(), "it@acme.example", id, inventory.SourcesChange{SNMP: &on}); err != nil {
				e.t.Fatal(err)
			}
			return id
		}, inventory.DeviceReview},
		{"ignored", func(e *env) string {
			e.record(scan(burnt)...)
			id := e.idByMAC(burnt)
			e.ok(e.svc.SetIgnored(e.ctx(), "it@acme.example", id, true))
			return id
		}, inventory.DeviceIgnored},
		{"removed, then seen again by scan and passive", func(e *env) string {
			e.record(dhcp(burnt, ip, "printer")...)
			e.ok(e.svc.DeleteDevice(e.ctx(), "it@acme.example", e.idByMAC(burnt), ""))
			e.ev.reset()
			e.tick(time.Hour)
			e.record(dhcp(burnt, ip, "printer")...)
			e.record(scan(burnt)...)
			service(e, burnt)
			if n := len(e.ev.named(inventory.EventAssetDiscovered)); n != 0 {
				e.t.Fatalf("%d new-device events for a removed device", n)
			}
			return ""
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t).quietEnv()
			id := tc.in(e)
			devices, review, seen := ids(e.list("", "true")), ids(e.review()), e.seenBriefly()
			queue, err := e.svc.ToReviewIDs(e.ctx())
			if err != nil {
				t.Fatal(err)
			}
			total, pending, err := e.svc.DeviceCounts(e.ctx())
			if err != nil {
				t.Fatal(err)
			}
			if total != len(devices) { // Home's "devices watched" tile links to the Devices list: the same count
				t.Errorf("DeviceCounts total %d, the Devices list holds %d", total, len(devices))
			}
			if id == "" {
				if n := e.count(`SELECT count(*) FROM inv_asset WHERE is_box = 0`); n != 0 || len(devices)+len(review)+len(seen)+len(queue) != 0 {
					t.Fatalf("a removed device came back: %d rows, Devices %v, To review %v, Seen briefly %v", n, devices, review, seen)
				}
				return
			}
			d := e.detail(id)
			if d.Asset.State != tc.want {
				t.Fatalf("state %q, want %q", d.Asset.State, tc.want)
			}
			is := func(s inventory.DeviceState) bool { return tc.want == s }
			for _, c := range []struct {
				where string
				in    bool
				want  bool
			}{
				{"Devices", slices.Contains(devices, id), is(inventory.DeviceAdded)},
				{"To review", slices.Contains(review, id), is(inventory.DeviceReview)},
				{"Seen briefly", slices.Contains(seen, id), is(inventory.DeviceSeen)},
				{"ToReviewIDs", slices.Contains(queue, id), is(inventory.DeviceReview)},
				{"the To review count", pending == 1, is(inventory.DeviceReview)},
				{"approved", d.Asset.Approved, is(inventory.DeviceAdded)},
			} {
				if c.in != c.want {
					t.Errorf("%s: %v, want %v (state %s)", c.where, c.in, c.want, tc.want)
				}
			}
		})
	}
}

// A removal keeps out what identified the device, and nothing more (INV-59): a burned-in MAC wherever it shows up; a device known by
// no such MAC by its address, for a sighting with no MAC only, so another machine DHCP gives the address to is a new device; a phone's
// private address not at all. A person brings it back by forgetting the removal or by adding a device by hand at its address; the
// machine's own agent brings it back too. The audit row says it was kept out.
func TestContract_INV59_ARemovalKeepsTheDeviceOut(t *testing.T) {
	t.Parallel()
	const ip, ip2 = "10.0.10.41", "10.0.10.42"
	const burnt, other, private = "3c:22:fb:00:00:41", "3c:22:fb:00:00:42", "c2:31:86:3f:8c:41"
	removed := func(e *env) []inventory.RemovedDevice {
		e.t.Helper()
		l, err := e.svc.RemovedDevices(e.ctx())
		if err != nil {
			e.t.Fatal(err)
		}
		return l
	}
	devices := func(e *env) int { return e.count(`SELECT count(*) FROM inv_asset WHERE is_box = 0`) }

	t.Run("a burned-in MAC, anywhere, until forgotten", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.record(dhcp(burnt, ip, "printer")...)
		e.ok(e.svc.DeleteDevice(e.ctx(), "it@acme.example", e.idByMAC(burnt), ""))
		e.record(dhcp(burnt, ip2, "printer")...) // moved by DHCP: still the same card
		e.record(obsv(burnt, observe.Vendor, "HP", observe.Passive, 0.5))
		if n := devices(e); n != 0 {
			t.Fatalf("%d devices: the removed card came back", n)
		}
		e.record(dhcp(other, ip, "laptop")...) // another machine at its old address
		if n := devices(e); n != 1 {
			t.Fatalf("%d devices: another machine at the removed device's address is a new device", n)
		}
		l := removed(e)
		if len(l) != 1 || l[0].Agent != "none" || l[0].IP == nil || *l[0].IP != ip || l[0].Identifiers != 1 {
			t.Fatalf("removed = %+v", l)
		}
		if !slices.ContainsFunc(e.auditDetails("inventory.delete"), func(d string) bool { return strings.Contains(d, "kept out of discovery") }) {
			t.Fatal("the audit row does not say the device was kept out")
		}
		e.ok(e.svc.ForgetRemoved(e.ctx(), "it@acme.example", l[0].ID))
		e.record(dhcp(burnt, ip2, "printer")...)
		if e.idByMAC(burnt) == "" || len(removed(e)) != 0 {
			t.Fatal("a forgotten removal still keeps the device out")
		}
		wantAPIError(t, e.svc.ForgetRemoved(e.ctx(), "it@acme.example", l[0].ID), 404, "not_found")
	})

	t.Run("an address, for sightings with no MAC, until a device is added there by hand", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.record(byAddress(ip, "web-01.corp.example")...)
		id := e.count(`SELECT count(*) FROM inv_asset WHERE ip = ?`, ip)
		if id != 1 {
			t.Fatal("no device for the address")
		}
		var dev string
		for _, d := range e.list("", "false").Items {
			dev = d.ID
		}
		e.ok(e.svc.DeleteDevice(e.ctx(), "it@acme.example", dev, ""))
		e.record(byAddress(ip, "web-01.corp.example")...)
		if n := devices(e); n != 0 {
			t.Fatalf("%d devices: the removed address came back", n)
		}
		e.record(dhcp(other, ip, "laptop")...) // a card at that address is a machine, not the removed address
		if n := devices(e); n != 1 {
			t.Fatalf("%d devices: a machine with a card at the removed address must be a new device", n)
		}
		e.ok(e.svc.DeleteDevice(e.ctx(), "it@acme.example", e.idByMAC(other), ""))
		if len(removed(e)) != 2 {
			t.Fatalf("removed = %+v", removed(e))
		}
		e.addDevice(inventory.AddInput{Vendor: "Contoso", Product: "Gizmo 2", Version: "2", IP: ip})
		// the person entered the address: the removal kept by that address goes; the laptop's card was not entered, so its removal
		// stays although the laptop was last seen at that address (DHCP reuses addresses)
		if l := removed(e); len(l) != 1 || l[0].Name != "laptop" {
			t.Fatalf("after adding a device by hand at the address: removals %+v, want only the laptop's", l)
		}
	})

	t.Run("a private Wi-Fi address keeps nothing out", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.record(dhcp(private, ip, "iPhone")...)
		e.ok(e.svc.DeleteDevice(e.ctx(), "it@acme.example", e.idByMAC(private), ""))
		if l := removed(e); len(l) != 0 {
			t.Fatalf("removed = %+v: a private address rotates, so it would keep nothing out", l)
		}
	})

	t.Run("an agent that brings back a device kept by its address clears its Removed entry", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.record(byAddress(ip, "build01.corp.example")...)
		e.ok(e.svc.DeleteDevice(e.ctx(), "it@acme.example", e.list("", "false").Items[0].ID, ""))
		if len(removed(e)) != 1 {
			t.Fatal("the address was not kept")
		}
		e.record(osq(ip)...) // the person installed an osquery agent on it
		if e.idByMAC(burnt1) == "" || len(removed(e)) != 0 {
			t.Fatalf("the agent brought the device back but its removal is still listed: %+v", removed(e))
		}
	})

	t.Run("the machine's own agent brings it back", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.record(dhcp(burnt1, ip, "build01")...)
		e.ok(e.svc.DeleteDevice(e.ctx(), "it@acme.example", e.idByMAC(burnt1), ""))
		e.record(osq(ip)...)
		if e.idByMAC(burnt1) == "" || len(removed(e)) != 0 {
			t.Fatalf("the agent a person installed did not bring the device back: removed %+v", removed(e))
		}
	})
}

// Every way a removed device's card could come back goes through the one admission check (INV-59, admit): whether it would make a
// device or give an existing one the card. Each row removes a device known by a burned-in card, then brings the card back one way; no
// device may hold it after, the sweep counts it as known (no new-device budget spent), and the removal stays listed. A person's own
// act is the exception the rule names: an osquery agent a person installed brings it back. An SNMP read names its device and carries no
// card (Record refuses a MAC with a device hint), so it cannot give a device a removed card. Merge and split move identifiers between
// devices that exist, and a card has one home, so neither can bring a removed one back.
func TestContract_INV59_EveryWayBackIsChecked(t *testing.T) {
	t.Parallel()
	const ip, ip2 = "10.0.10.51", "10.0.10.52"
	const card = "3c:22:fb:00:00:51"
	addr, addr2 := netip.MustParseAddr(ip), netip.MustParseAddr(ip2)
	for _, tc := range []struct {
		name string
		back func(e *env)
	}{
		{"an address-only sighting, then the card at that address", func(e *env) {
			e.record(byAddress(ip, "printer.corp.example")...)
			e.record(dhcp(card, ip, "printer")...)
		}},
		{"a Wazuh-shaped report: an address hint, the card as a value", func(e *env) {
			h := observe.AssetHint{IP: addr}
			e.record(observe.Observation{AssetHint: h, Field: observe.Hostname, Value: "pc-01", Source: observe.Agent, Confidence: 0.9},
				observe.Observation{AssetHint: h, Field: observe.MAC, Value: card, Source: observe.Agent, Confidence: 0.9})
		}},
		{"a Wazuh-shaped report, then its software list by address", func(e *env) {
			h := observe.AssetHint{IP: addr}
			e.record(observe.Observation{AssetHint: h, Field: observe.Hostname, Value: "pc-01", Source: observe.Agent, Confidence: 0.9},
				observe.Observation{AssetHint: h, Field: observe.MAC, Value: card, Source: observe.Agent, Confidence: 0.9})
			e.ok(e.svc.ReplaceSoftware(e.ctx(), h, observe.Wazuh, nil,
				[]observe.Software{{Display: "7-Zip 24.08", Vendor: "7-zip", Product: "7-zip", Version: "24.08", Confidence: 0.9}}))
			if n := e.count(`SELECT count(*) FROM inv_asset WHERE ip = ?`, ip); n != 0 {
				e.t.Fatalf("the removed machine's software list made a device at its address (%d)", n)
			}
		}},
		{"a Wazuh-shaped report and its software list from a new address", func(e *env) {
			h := observe.AssetHint{IP: addr2} // DHCP gave the removed machine another address
			e.record(observe.Observation{AssetHint: h, Field: observe.Hostname, Value: "pc-01", Source: observe.Agent, Confidence: 0.9},
				observe.Observation{AssetHint: h, Field: observe.MAC, Value: card, Source: observe.Agent, Confidence: 0.9})
			e.ok(e.svc.ReplaceSoftware(e.ctx(), h, observe.Wazuh, nil,
				[]observe.Software{{Display: "7-Zip 24.08", Vendor: "7-zip", Product: "7-zip", Version: "24.08", Confidence: 0.9}}))
			if n := e.count(`SELECT count(*) FROM inv_asset WHERE is_box = 0`); n != 0 {
				e.t.Fatalf("the removed machine's software list made a device at its new address (%d)", n)
			}
		}},
		{"a Wazuh-shaped report at the address of another device", func(e *env) {
			e.record(dhcp("3c:22:fb:00:00:52", ip2, "other")...)
			h := observe.AssetHint{IP: addr2}
			e.record(observe.Observation{AssetHint: h, Field: observe.MAC, Value: card, Source: observe.Agent, Confidence: 0.9})
		}},
		{"a device check that was running when the device was removed", func(e *env) {
			h := observe.AssetHint{IP: addr} // a device check reports by the address it was given, with no card
			e.record(observe.Observation{AssetHint: h, Field: observe.Hostname, Value: "printer", Source: observe.Nmap, Confidence: 0.6})
			e.ok(e.svc.ReplaceServices(e.ctx(), h, observe.Nmap, observe.ServiceScope{}, []observe.Service{{Port: 631, Proto: "tcp", Name: "ipp", Confidence: 0.9}}))
			if n := e.count(`SELECT count(*) FROM inv_asset WHERE is_box = 0`); n != 0 {
				e.t.Fatalf("the check's results made a device at the removed device's address (%d)", n)
			}
		}},
		{"a scan's open services with the card", func(e *env) {
			e.ok(e.svc.AddServices(e.ctx(), observe.AssetHint{IP: addr, MAC: card}, observe.Nmap, []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Confidence: 0.9}}))
		}},
		{"a scan's software list with the card", func(e *env) {
			e.ok(e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: addr, MAC: card}, observe.Nmap, nil,
				[]observe.Software{{Display: "OpenSSH 9.6", Vendor: "openbsd", Product: "openssh", Version: "9.6", Confidence: 0.6}}))
		}},
		{"a device added by hand at its old address", func(e *env) {
			e.addDevice(inventory.AddInput{Vendor: "Contoso", Product: "Gizmo 2", Version: "2", IP: ip})
			e.record(dhcp(card, ip, "printer")...)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.record(dhcp(card, ip, "printer")...)
			e.ok(e.svc.DeleteDevice(e.ctx(), "it@acme.example", e.idByMAC(card), ""))
			e.tick(time.Minute)
			tc.back(e)
			if n := e.count(`SELECT (SELECT count(*) FROM inv_asset WHERE mac = ?1) + (SELECT count(*) FROM inv_asset_address WHERE mac = ?1)
				+ (SELECT count(*) FROM inv_observation WHERE field = 'mac' AND value = ?1)`, card); n != 0 {
				t.Fatalf("the removed card is back (%d rows hold it)", n)
			}
			if l, err := e.svc.RemovedDevices(e.ctx()); err != nil || len(l) != 1 {
				t.Fatalf("removed = %+v, %v: the removal must stay listed", l, err)
			}
			known, err := e.svc.KnownMACs(e.ctx())
			if err != nil || !slices.Contains(known, card) {
				t.Fatalf("KnownMACs = %v, %v: the sweep would count the removed card as a new device", known, err)
			}
		})
	}
}

// With the Agents module off nothing reports for a device's agent, so the device page offers no agent choice (Detail.agent false) and
// a removal keeps the device out like one without an agent; once the module is on again, the agent's own report brings it back.
func TestContract_INV59_AnAgentOfAModuleThatIsOffIsNoChoice(t *testing.T) {
	t.Parallel()
	g := &gate{on: map[string]bool{"agent-intake": true}}
	e := newEnv(t, func(c *inventory.Config) { c.Modules = g })
	e.record(osq("10.0.10.61")...)
	id := e.idByMAC(burnt1)
	if !e.detail(id).Agent {
		t.Fatal("with the module on, the device's agent is a choice")
	}
	g.set("agent-intake", false)
	if e.detail(id).Agent {
		t.Fatal("with the module off, the device page offers an agent choice")
	}
	e.ok(e.svc.DeleteDevice(e.ctx(), "it@acme.example", id, ""))
	l, err := e.svc.RemovedDevices(e.ctx())
	if err != nil || len(l) != 1 || l[0].Agent != "none" {
		t.Fatalf("removed = %+v, %v: the device is kept out as one with no agent", l, err)
	}
}

// A row that stored a card as an agent's observation while another device owned it (Wazuh reporting a machine by an address another row
// held) does not take that card as its MAC once a person removed the card's device (INV-59).
func TestContract_INV59_ARowThatSawTheRemovedCardDoesNotTakeIt(t *testing.T) {
	t.Parallel()
	const ip, ip2 = "10.0.10.51", "10.0.10.52"
	const card = "3c:22:fb:00:00:51"
	e := newEnv(t)
	e.record(dhcp(card, ip, "printer")...)
	e.record(byAddress(ip2, "pc-01.corp.example")...)
	h := observe.AssetHint{IP: netip.MustParseAddr(ip2)}
	e.record(observe.Observation{AssetHint: h, Field: observe.Hostname, Value: "pc-01", Source: observe.Agent, Confidence: 0.9},
		observe.Observation{AssetHint: h, Field: observe.MAC, Value: card, Source: observe.Agent, Confidence: 0.9})
	if n := e.count(`SELECT count(*) FROM inv_asset WHERE is_box = 0`); n != 2 {
		t.Fatalf("%d devices before the removal, want the card's device and the address-only one", n)
	}
	e.ok(e.svc.DeleteDevice(e.ctx(), "it@acme.example", e.idByMAC(card), ""))
	e.tick(time.Minute)
	e.record(byAddress(ip2, "pc-01.corp.example")...)
	if n := e.count(`SELECT count(*) FROM inv_asset WHERE mac = ?`, card); n != 0 {
		t.Fatalf("the removed card is back as the MAC of another row (%d)", n)
	}
}

// The device page says whether a removal would keep the device out (Detail.removal_keeps), by the same rule the removal keeps
// (removedIdentifiers): a fixed card on any of its addresses, or an address when it has no card at all; a private Wi-Fi address only
// keeps nothing. A device whose main card is private but that has a fixed card on another address is kept out by that one.
func TestContract_INV59_TheDevicePageSaysWhatARemovalKeeps(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(dhcp("c2:31:86:3f:8c:71", "10.0.10.71", "laptop")...)
	id := e.idByMAC("c2:31:86:3f:8c:71")
	if e.detail(id).RemovalKeeps {
		t.Fatal("a device known only by a private address: a removal keeps nothing, the page must not say otherwise")
	}
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO inv_asset_address (id, asset_id, ip, mac, source, first_seen, last_seen)
			VALUES ('ad-71', ?, '10.0.10.72', '3c:22:fb:00:00:72', 'passive', '2026-11-09T10:00:00.000Z', '2026-11-09T10:00:00.000Z')`, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !e.detail(id).RemovalKeeps {
		t.Fatal("its docking-station card is fixed: a removal keeps it out, the page must say so")
	}
	e.record(byAddress("10.0.10.73", "routed.corp.example")...)
	for _, d := range e.list("", "false").Items {
		if d.IP == "10.0.10.73" && !e.detail(d.ID).RemovalKeeps {
			t.Fatal("a device with no card is kept out by its address")
		}
	}
}
