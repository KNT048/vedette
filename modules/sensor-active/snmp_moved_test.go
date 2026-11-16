package sensoractive_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/sensorlink"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// #829 C4 (J2): a device that answered a credential and moved to an address outside that credential's scope is never sent the secret
// there (D-512), and the credential, Read now and the round's log say so instead of nothing.

// moveDevice gives device id a new address, as the inventory does when it follows the device's MAC.
func (w *snmpWorld) moveDevice(id, ip string) {
	w.t.Helper()
	w.inv.mu.Lock()
	defer w.inv.mu.Unlock()
	delete(w.inv.addrs, w.inv.assets[id])
	a := netip.MustParseAddr(ip)
	w.inv.assets[id], w.inv.addrs[a] = a, id
}

// movedOf is the MovedOut of the credential named name.
func (w *snmpWorld) movedOf(name string) []sa.SNMPMoved {
	w.t.Helper()
	list, err := w.svc.SNMPCredentials(w.t.Context())
	if err != nil {
		w.t.Fatal(err)
	}
	i := slices.IndexFunc(list, func(c sa.SNMPCredential) bool { return c.Name == name })
	if i < 0 {
		w.t.Fatalf("no credential %q", name)
	}
	return list[i].MovedOut
}

// sentTo reports whether any job given to the worker named ip.
func sentTo(r *fakeReader, ip string) bool {
	for _, j := range r.sent() {
		if slices.ContainsFunc(j.Targets, func(t sensorlink.SNMPTarget) bool { return t.IP == ip }) {
			return true
		}
	}
	return false
}

func TestSNMPADeviceThatMovedOutOfTheScopeIsNamedAndNeverSentTo(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	ctx := t.Context()
	c := w.add(v2cInput("ipchg-c4", "community-1", "192.168.10.20"))
	w.add(v2cInput("printers", "community-2", "192.168.10.24"))
	if res, err := w.svc.TestSNMP(ctx, "admin@example.com", c.ID, "192.168.10.20"); err != nil || !res.OK {
		t.Fatalf("first answer: %v %+v", err, res)
	}
	if got := w.movedOf("ipchg-c4"); len(got) != 0 {
		t.Fatalf("not moved yet: %+v", got)
	}
	w.moveDevice("a-sw", "192.168.10.30") // same device row, new address, still approved and in the scan scope

	got := w.movedOf("ipchg-c4")
	if len(got) != 1 || got[0].DeviceID != "a-sw" || got[0].Name != "device a-sw" || got[0].IP != "192.168.10.30" ||
		!strings.Contains(got[0].Message, "device a-sw moved to 192.168.10.30, outside the scope of this credential: add the address to the scope") {
		t.Fatalf("moved out %+v", got)
	}
	if o := w.movedOf("printers"); len(o) != 0 {
		t.Fatalf("a credential the device never answered: %+v", o)
	}

	// Read now: nothing to read, and the run says why in a skipped row; nothing goes to the new address.
	run, err := w.svc.ReadSNMP(ctx, "admin@example.com", c.ID)
	if err != nil {
		t.Fatal(err)
	}
	done := w.waitRead(c.ID)
	for _, x := range []sa.SNMPRead{run, done} {
		if x.Total != 0 || x.Skipped != 1 || len(x.Results) != 1 {
			t.Fatalf("read %+v", x)
		}
		row := x.Results[0]
		if row.IP != "192.168.10.30" || row.OK || row.Reason != sa.SNMPNotForThisCredential || row.DeviceID != "a-sw" || !strings.Contains(row.Message, "moved to 192.168.10.30") {
			t.Fatalf("skipped row %+v", row)
		}
	}
	if done.Status != "done" || done.Answered != 0 {
		t.Fatalf("finished %+v", done)
	}
	// A Test at the new address is refused as before, and the round sends nothing there either.
	if res, err := w.svc.TestSNMP(ctx, "admin@example.com", c.ID, "192.168.10.30"); err != nil || res.Reason != sa.SNMPNotForThisCredential {
		t.Fatalf("Test at the new address: %v %+v", err, res)
	}
	if err := w.svc.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if sentTo(r, "192.168.10.30") {
		t.Fatal("the secret was sent to the new address")
	}

	// Adding the address to the scope: no longer moved out, and Read now reads it.
	if _, err := w.svc.EditSNMP(ctx, "admin@example.com", c.ID, v2cInput("ipchg-c4", "community-1", "192.168.10.20", "192.168.10.30")); err != nil {
		t.Fatal(err)
	}
	if got := w.movedOf("ipchg-c4"); len(got) != 0 {
		t.Fatalf("after the scope was widened: %+v", got)
	}
	if _, err := w.svc.ReadSNMP(ctx, "admin@example.com", c.ID); err != nil {
		t.Fatal(err)
	}
	if x := w.waitRead(c.ID); x.Total != 1 || x.Answered != 1 || x.Skipped != 0 || !sentTo(r, "192.168.10.30") {
		t.Fatalf("read after the scope was widened %+v", x)
	}
}

func TestSNMPMovedOutFollowsTheNewestAnswerAndGoesWithTheCredential(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	ctx := t.Context()
	c := w.add(v2cInput("old", "community-1", "192.168.10.20"))
	// The window's round records the answer too (the asset comes from the batch's targets).
	if err := w.svc.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if w.count(`SELECT count(*) FROM sa_snmp_answer WHERE asset_id = 'a-sw' AND ip = '192.168.10.20'`) != 1 {
		t.Fatal("the round did not record which device answered")
	}
	w.moveDevice("a-sw", "192.168.10.30")
	if got := w.movedOf("old"); len(got) != 1 {
		t.Fatalf("moved out %+v", got)
	}
	// Moved back: nothing to say.
	w.moveDevice("a-sw", "192.168.10.20")
	if got := w.movedOf("old"); len(got) != 0 {
		t.Fatalf("moved back %+v", got)
	}
	// Moved again, and another credential whose scope holds the new address answers it: that one reads it now, the old one says nothing.
	w.moveDevice("a-sw", "192.168.10.30")
	n := w.add(v2cInput("new", "community-2", "192.168.10.30"))
	if res, err := w.svc.TestSNMP(ctx, "admin@example.com", n.ID, "192.168.10.30"); err != nil || !res.OK {
		t.Fatalf("answer with the new credential: %v %+v", err, res)
	}
	if got, got2 := w.movedOf("old"), w.movedOf("new"); len(got) != 0 || len(got2) != 0 {
		t.Fatalf("after a newer answer: old %+v, new %+v", got, got2)
	}
	// A device the inventory no longer has is not named; a deleted credential takes its rows with it.
	w.inv.mu.Lock()
	delete(w.inv.assets, "a-sw")
	w.inv.mu.Unlock()
	if got := w.movedOf("old"); len(got) != 0 {
		t.Fatalf("a deleted device %+v", got)
	}
	if err := w.svc.DeleteSNMP(ctx, "admin@example.com", c.ID); err != nil {
		t.Fatal(err)
	}
	if w.count(`SELECT count(*) FROM sa_snmp_answer WHERE credential_id = '`+c.ID+`'`) != 0 {
		t.Fatal("the deleted credential's answers stayed")
	}
}
