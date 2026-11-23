package inventory_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/inventory"
)

const admin = "admin@acme.example"

// sameAs is what the device page offers on id.
func (e *env) sameAs(id string) []inventory.PossibleSame {
	e.t.Helper()
	got, err := e.svc.PossibleSameAs(e.ctx(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

// addresses lists a device's addresses as "ip mac [main]" (a missing part is "-"), as GET /inventory/devices/{id} gives them.
func (e *env) addresses(id string) []string {
	e.t.Helper()
	d, err := e.svc.Detail(e.ctx(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, a := range d.Addresses {
		v := func(p *string) string {
			if p == nil {
				return "-"
			}
			return *p
		}
		line := v(a.IP) + " " + v(a.MAC)
		if a.Main {
			line += " main"
		}
		out = append(out, line)
	}
	return out
}

func (e *env) auditBy(action string) []string {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT user || ': ' || coalesce(detail, '') FROM core_audit WHERE action = ? ORDER BY seq`, action)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// phonePair is a person's iPhone: approved with a note under a private Wi-Fi address, then an hour later a new private address and a
// new lease under the same generic name "iPhone", which the join rules never take. It returns the approved row and the new one.
func phonePair(e *env) (old, newer string) {
	e.t.Helper()
	e.record(dhcp(privMac1, "192.168.142.10", "iPhone")...)
	old = e.idOf("192.168.142.10")
	if err := e.svc.Approve(e.ctx(), "anna", old); err != nil {
		e.t.Fatal(err)
	}
	notes := "Anna's phone"
	if err := e.svc.PatchDevice(e.ctx(), "anna", old, inventory.Patch{Notes: &notes}); err != nil {
		e.t.Fatal(err)
	}
	e.tick(time.Hour)
	e.record(dhcp(privMac2, "192.168.142.11", "iPhone")...)
	newer = e.idOf("192.168.142.11")
	if e.devices() != 2 {
		e.t.Fatalf("%d devices before the merge, want 2", e.devices())
	}
	return old, newer
}

// A new pending row with a new private Wi-Fi address and the generic name of an approved row that went quiet is offered on
// both device pages and in the list, with the words the page shows; Merge keeps the approved row (id, approval, notes), moves the
// newer address and MAC to it, deletes the newcomer, writes one audit row by the person and announces merged before deleted, so
// findings moves the newcomer's findings and notify closes its incident.
func TestContract_PossibleSameIsOfferedAndMerged(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	old, newer := phonePair(e)

	got := e.sameAs(newer)
	if len(got) != 1 || got[0].ID != old || !got[0].Approved || got[0].Name != "iPhone" ||
		got[0].Why != `Same name "iPhone", never online at the same time, and a private Wi-Fi address (phones and laptops change it).` {
		t.Fatalf("offered on the new row: %+v", got)
	}
	if back := e.sameAs(old); len(back) != 1 || back[0].ID != newer || back[0].Approved {
		t.Fatalf("offered on the approved row: %+v", back)
	}
	d, err := e.svc.DetailPage(e.ctx(), newer)
	if err != nil || len(d.PossibleSame) != 1 {
		t.Fatalf("detail possible_same: %+v %v", d.PossibleSame, err)
	}
	pairs, err := e.svc.PossibleSamePairs(e.ctx())
	if err != nil || len(pairs.Items) != 1 || pairs.Items[0].A.ID != old || pairs.Items[0].B.ID != newer {
		t.Fatalf("pairs: %+v %v", pairs, err)
	}

	e.ev.reset()
	if err := e.svc.Merge(e.ctx(), admin, old, newer); err != nil {
		t.Fatal(err)
	}
	k := e.only()
	if k.ID != old || !k.Approved || k.Notes == nil || *k.Notes != "Anna's phone" || k.IP != "192.168.142.11" || k.MAC == nil || *k.MAC != privMac2 {
		t.Errorf("kept device: id %s approved %v notes %v ip %s mac %v", k.ID, k.Approved, k.Notes, k.IP, k.MAC)
	}
	var names []string
	for _, ev := range e.ev.events {
		names = append(names, ev.Name)
	}
	if strings.Join(names, " ") != "inventory.asset.deleted inventory.asset.updated" {
		t.Errorf("events: %v", names)
	}
	if u := e.ev.named(inventory.EventAssetUpdated); len(u) != 1 || !u[0].Data.(inventory.AssetEvent).Match {
		t.Errorf("updated: %+v (the kept device must be matched again)", u)
	}
	if a := e.auditBy("inventory.merge"); len(a) != 1 || !strings.HasPrefix(a[0], admin+": ") {
		t.Errorf("merge audit rows: %v", a)
	}
	if got := e.sameAs(old); len(got) != 0 {
		t.Errorf("still offered after the merge: %+v", got)
	}
}

// A person decides, so unlike the join rules the approval moves when the kept row had none (approved_at kept, the suspicious
// mark cleared as Approve does; review r1 of #871 M2), both notes stay (the kept row's first), and inventory.asset.approved names the
// person.
func TestContract_MergeIntoAPendingRowKeepsTheApprovalAndBothNotes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	old, newer := phonePair(e)
	notes := "seen at the front desk"
	if err := e.svc.PatchDevice(e.ctx(), "anna", newer, inventory.Patch{Notes: &notes}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SetSuspicious(e.ctx(), "anna", newer, true); err != nil {
		t.Fatal(err)
	}
	approvedAt := *e.detail(old).Asset.ApprovedAt
	e.ev.reset()
	if err := e.svc.Merge(e.ctx(), admin, newer, old); err != nil {
		t.Fatal(err)
	}
	k := e.only()
	if k.Suspicious {
		t.Errorf("the kept device gained the approval and is still marked suspicious (Approve clears the mark)")
	}
	if k.ID != newer || !k.Approved || k.ApprovedAt == nil || *k.ApprovedAt != approvedAt || k.Notes == nil || *k.Notes != "seen at the front desk\n\nAnna's phone" {
		t.Errorf("kept device: id %s approved %v at %v notes %q", k.ID, k.Approved, k.ApprovedAt, deref(k.Notes))
	}
	if a := e.ev.named(inventory.EventAssetApproved); len(a) != 1 || a[0].Data != (inventory.AssetEvent{AssetID: newer, Actor: admin}) {
		t.Errorf("approved events: %+v", a)
	}
}

func deref(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// Two different agents are two machines: never offered, and a merge is refused with plain words (409 not_same_device), nothing
// changed. Two different burned-in MACs are not (INV-57): one machine with two cards carries two, so a host name both rows state is
// offered as two cards of one machine and a person may merge them. The same device twice is 400, an unknown one 404, the box 409
// box_device.
func TestContract_MergeRefusesTwoMachines(t *testing.T) {
	t.Parallel()
	t.Run("burned-in MACs", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.record(dhcp(burnt1, "192.168.142.10", "accounting-pc")...)
		e.tick(time.Hour)
		e.record(dhcp(burnt2, "192.168.142.11", "accounting-pc")...)
		a, b := e.idOf("192.168.142.10"), e.idOf("192.168.142.11")
		got := e.sameAs(a)
		if len(got) != 1 || got[0].ID != b || got[0].Reason != inventory.ReasonSameNameCards || !strings.Contains(got[0].Why, `Same name "accounting-pc" on two network cards`) {
			t.Fatalf("offered: %+v", got)
		}
		if err := e.svc.Merge(e.ctx(), admin, a, b); err != nil || e.devices() != 1 {
			t.Fatalf("merge: %v; %d devices", err, e.devices())
		}
		// both cards stay; the one seen last is the main address, as a merge of one machine's rows always had it
		if got := e.addresses(a); !slices.Equal(got, []string{"192.168.142.11 " + burnt2 + " main", "192.168.142.10 " + burnt1}) {
			t.Errorf("addresses after the merge: %v", got)
		}
	})
	t.Run("agents", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		old, newer := phonePair(e)
		e.exec(`UPDATE inv_asset SET agent_key = 'osquery:node-a' WHERE id = ?`, old)
		e.exec(`UPDATE inv_asset SET agent_key = 'osquery:node-b' WHERE id = ?`, newer)
		if got := e.sameAs(old); len(got) != 0 {
			t.Errorf("offered: %+v", got)
		}
		err := e.svc.Merge(e.ctx(), admin, old, newer)
		wantAPIError(t, err, 409, "not_same_device")
		if !strings.Contains(err.Error(), "an agent reports from each of them") || e.devices() != 2 {
			t.Errorf("refusal: %v; %d devices", err, e.devices())
		}
	})
	t.Run("bad pairs", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		box, err := e.svc.EnsureBox(e.ctx(), inventory.BoxInfo{Hostname: "vedette", IP: "192.168.142.2"})
		if err != nil {
			t.Fatal(err)
		}
		old, _ := phonePair(e)
		wantAPIError(t, e.svc.Merge(e.ctx(), admin, old, old), 400, "invalid")
		wantAPIError(t, e.svc.Merge(e.ctx(), admin, old, "a-nope"), 404, "not_found")
		wantAPIError(t, e.svc.Merge(e.ctx(), admin, box, old), 409, "box_device")
		wantAPIError(t, e.svc.KeepSeparate(e.ctx(), admin, old, box), 409, "box_device")
		if e.devices() != 2 {
			t.Errorf("%d devices after refusals", e.devices())
		}
	})
}

// What is not offered: a private address next to a row with burned-in MACs only (an intruder naming itself after a server,
// #831), two machines of one name online at the same time, two rows that state another OS.
func TestContract_WhatIsNotOffered(t *testing.T) {
	t.Parallel()
	t.Run("burned-in only", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.record(dhcp(burnt1, "192.168.142.10", "nas01")...)
		e.tick(time.Hour)
		e.record(dhcp(privMac1, "192.168.142.11", "nas01")...)
		if got := e.sameAs(e.idOf("192.168.142.11")); len(got) != 0 {
			t.Errorf("offered: %+v", got)
		}
	})
	t.Run("online together", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.record(dhcp(privMac1, "192.168.142.10", "iPhone")...)
		e.record(dhcp(privMac2, "192.168.142.11", "iPhone")...)
		e.tick(time.Hour)
		e.record(dhcp(privMac1, "192.168.142.10", "iPhone")...)
		e.record(dhcp(privMac2, "192.168.142.11", "iPhone")...)
		e.tick(time.Hour)
		if got := e.sameAs(e.idOf("192.168.142.11")); len(got) != 0 {
			t.Errorf("offered: %+v", got)
		}
	})
}

// Keep separate is stored: the pair is never offered again, on either page, in the list, or after new sightings of both;
// saying it again writes no second audit row. Deleting either row ends it (a new pair is a new question).
func TestContract_KeepSeparateIsNeverOfferedAgain(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	old, newer := phonePair(e)
	if err := e.svc.KeepSeparate(e.ctx(), admin, newer, old); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.KeepSeparate(e.ctx(), admin, old, newer); err != nil {
		t.Fatal(err)
	}
	e.tick(time.Hour)
	e.record(dhcp(privMac2, "192.168.142.11", "iPhone")...)
	e.tick(time.Hour)
	if a, b := e.sameAs(old), e.sameAs(newer); len(a)+len(b) != 0 {
		t.Errorf("offered again: %+v %+v", a, b)
	}
	if p, err := e.svc.PossibleSamePairs(e.ctx()); err != nil || len(p.Items) != 0 {
		t.Errorf("pairs: %+v %v", p, err)
	}
	if a := e.auditBy("inventory.keep_separate"); len(a) != 1 || !strings.HasPrefix(a[0], admin+": ") {
		t.Errorf("keep_separate audit rows: %v", a)
	}
	if e.devices() != 2 {
		t.Errorf("%d devices, want both kept", e.devices())
	}
	if err := e.svc.DeleteDevice(e.ctx(), admin, newer); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM inv_separate`); n != 0 {
		t.Errorf("%d separate rows after the delete", n)
	}
}

// The routes: anyone signed in reads the offers; only an admin merges or keeps apart (the route table); the answers' shapes.
func TestHandlers_MergeAndKeepSeparateAreForAdmins(t *testing.T) {
	t.Parallel()
	a := newAPI(t)
	old, newer := phonePair(a.env)
	for _, user := range []string{"viewer", "operator"} {
		a.want("POST", "/inventory/devices/"+old+"/merge", user, `{"from":["`+newer+`"]}`, 403, "forbidden")
		a.want("POST", "/inventory/devices/"+old+"/keep-separate", user, `{"other":"`+newer+`"}`, 403, "forbidden")
	}
	a.want("POST", "/inventory/devices/"+old+"/merge", "", `{"from":["`+newer+`"]}`, 401, "unauthenticated")
	if a.devices() != 2 {
		t.Fatalf("%d devices after refused calls", a.devices())
	}
	list := a.want("GET", "/inventory/possible-same", "viewer", "", 200, "")
	items := list["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["a"].(map[string]any)["id"] != old {
		t.Fatalf("possible-same: %v", list)
	}
	d := a.want("GET", "/inventory/devices/"+newer, "viewer", "", 200, "")
	if ps := d["possible_same"].([]any); len(ps) != 1 || ps[0].(map[string]any)["id"] != old || ps[0].(map[string]any)["why"] == "" {
		t.Fatalf("possible_same: %v", d["possible_same"])
	}
	a.want("POST", "/inventory/devices/"+old+"/merge", "admin", `{"from":["`+old+`"]}`, 400, "invalid")
	a.want("POST", "/inventory/devices/"+old+"/merge", "admin", `{"from":["a-nope"]}`, 404, "not_found")
	m := a.want("POST", "/inventory/devices/"+old+"/merge", "admin", `{"from":["`+newer+`"]}`, 200, "")
	if m["id"] != old || a.devices() != 1 {
		t.Fatalf("merge = %v; %d devices", m, a.devices())
	}
	if d := a.want("GET", "/inventory/devices/"+old, "viewer", "", 200, ""); len(d["possible_same"].([]any)) != 0 {
		t.Fatalf("possible_same after the merge: %v", d["possible_same"])
	}
}

// Review r1 of #871 H1: Keep separate binds the join rules too. Two rows of a non-generic name with private addresses, the second seen
// while the first had answered minutes before (no join yet), are offered; Keep separate; the next sighting of either does not join them.
func TestContract_KeepSeparateStopsTheJoinRules(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(dhcp(privMac1, "192.168.142.10", "annas-macbook-air")...)
	a := e.idOf("192.168.142.10")
	e.tick(10 * time.Minute)
	e.record(dhcp(privMac2, "192.168.142.11", "annas-macbook-air")...)
	b := e.idOf("192.168.142.11")
	e.tick(30 * time.Minute)
	if got := e.sameAs(b); len(got) != 1 || got[0].ID != a {
		t.Fatalf("offered: %+v", got)
	}
	if err := e.svc.KeepSeparate(e.ctx(), admin, b, a); err != nil {
		t.Fatal(err)
	}
	e.tick(time.Hour)
	e.record(dhcp(privMac2, "192.168.142.11", "annas-macbook-air")...)
	e.tick(time.Hour)
	e.record(dhcp(privMac1, "192.168.142.12", "annas-macbook-air")...)
	if n := e.devices(); n != 2 {
		t.Errorf("%d devices after Keep separate and new sightings, want 2", n)
	}
}

// Review r1 of #871 H2: a phone of the same generic name seen once while the approved one was online is not "never online at the same
// time": not offered, however short its visit.
func TestContract_AVisitorSeenWhileTheDeviceWasOnlineIsNotOffered(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(dhcp(privMac1, "192.168.142.10", "iPhone")...)
	old := e.idOf("192.168.142.10")
	if err := e.svc.Approve(e.ctx(), "anna", old); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		e.tick(15 * time.Minute)
		e.record(dhcp(privMac1, "192.168.142.10", "iPhone")...)
		if i == 1 {
			e.record(dhcp(privMac2, "192.168.142.11", "iPhone")...)
		}
	}
	e.tick(25 * time.Minute)
	if got := e.sameAs(e.idOf("192.168.142.11")); len(got) != 0 {
		t.Errorf("the visitor is offered as the approved phone: %+v", got)
	}
}

// Review r1 of #871 M1: rows of past months do not count against the group cap: after nine old rotations of "iPhone", a new one is still
// offered, with the maxOffered (5) seen last.
func TestContract_OldRowsDoNotSilenceTheOffer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	var olds []string
	for i := range 9 {
		ip := fmt.Sprintf("192.168.142.%d", 20+i)
		e.record(dhcp(fmt.Sprintf("b2:f0:09:00:00:%02x", i), ip, "iPhone")...)
		olds = append(olds, e.idOf(ip))
		e.tick(24 * time.Hour)
	}
	e.tick(40 * 24 * time.Hour)
	e.record(dhcp(privMac1, "192.168.142.60", "iPhone")...)
	got := e.sameAs(e.idOf("192.168.142.60"))
	if len(got) != 5 || got[0].ID != olds[8] || got[4].ID != olds[4] {
		t.Errorf("offered: %+v; want the five old rows seen last", got)
	}
}

// Review r2 of #871 M1: Keep separate on one of two rows of a name leaves the name ambiguous for a third row: the other row is not
// joined automatically because the person answered about a different pair.
func TestContract_KeepSeparateKeepsTheNameAmbiguous(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for range 3 { // two Macs of one name, online together: two devices
		e.record(dhcp(privMac1, "192.168.142.10", "annas-macbook-air")...)
		e.record(dhcp(privMac2, "192.168.142.11", "annas-macbook-air")...)
		e.tick(30 * time.Minute)
	}
	first := e.idOf("192.168.142.10")
	e.tick(time.Hour)
	e.record(dhcp(privMac3, "192.168.142.12", "annas-macbook-air")...)
	third := e.idOf("192.168.142.12")
	e.tick(30 * time.Minute)
	if err := e.svc.KeepSeparate(e.ctx(), admin, third, first); err != nil {
		t.Fatal(err)
	}
	e.tick(time.Hour)
	e.record(dhcp(privMac3, "192.168.142.12", "annas-macbook-air")...)
	if n := e.devices(); n != 3 {
		t.Errorf("%d devices, want 3: a pair nobody answered was joined", n)
	}
}

// Review r2 of #871 L1, L2: the device page finds the same pairs as the list for names SQLite cannot fold (Vietnamese, a trailing
// space); a late software list for the old row (no MAC sighting) does not make the two "online together".
func TestContract_PageFindsUnicodeNamesAndIgnoresLateLists(t *testing.T) {
	t.Parallel()
	for _, names := range [][2]string{{"BÌNH-PC", "bình-pc"}, {"iPhone ", "iPhone"}} {
		e := newEnv(t)
		e.record(dhcp(privMac1, "192.168.142.10", names[0])...)
		a := e.idOf("192.168.142.10")
		e.tick(time.Hour)
		e.record(dhcp(privMac2, "192.168.142.11", names[1])...)
		b := e.idOf("192.168.142.11")
		e.tick(time.Minute)
		e.exec(`UPDATE inv_asset SET last_seen = ? WHERE id = ?`, store.FormatTS(e.now), a) // a queued list for the old row
		e.tick(30 * time.Minute)
		if got := e.sameAs(b); len(got) != 1 || got[0].ID != a {
			t.Errorf("%q / %q: page offers %+v", names[0], names[1], got)
		}
	}
}
