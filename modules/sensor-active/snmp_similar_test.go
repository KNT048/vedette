package sensoractive_test

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/secrets"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// "Use these settings on similar devices": the candidates are the inventory's similar devices without settings of their own; the
// apply copies the source's settings to the ticked ones only, each read at its own address, refuses what is no longer a candidate,
// audits the person, never returns the secret, and queues a read of each device it saved.
func TestSNMPApplyToSimilarDevices(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	ctx := t.Context()
	w.inv.similar = map[string][]sa.SimilarDevice{"a-sw": {
		{ID: "a-new", IP: "192.168.10.21", Vendor: "Acme", Kind: "switch", SameMaker: true, SameType: true},
		{ID: "a-printer", IP: "192.168.10.24", Vendor: "Other", Kind: "switch", SameType: true, Approved: true},
		{ID: "a-never", IP: "192.168.10.23", Vendor: "Acme", Kind: "printer", SameMaker: true, Approved: true},
		{ID: "a-sw", IP: "192.168.10.20", Vendor: "Acme", Kind: "switch", SameMaker: true, SameType: true},
	}}
	if _, err := w.svc.SNMPSimilar(ctx, "a-sw"); apiCode(err) != "not_set_up" {
		t.Fatalf("a source with no settings: %v", err)
	}
	w.inv.approved["a-new"] = true
	w.set("a-sw", sa.SNMPInput{Version: "v2c", Community: secrets.NewValue("community-1"), Port: 1161})
	w.set("a-never", sa.SNMPInput{Version: "v2c", Community: secrets.NewValue("its-own-one")})

	list, err := w.svc.SNMPSimilar(ctx, "a-sw")
	if err != nil || len(list) != 2 || list[0].DeviceID != "a-new" || !list[0].SameMaker || list[1].DeviceID != "a-printer" || list[1].SameMaker {
		t.Fatalf("candidates (own settings and the source left out, same maker first): %v %+v", err, list)
	}

	res, err := w.svc.ApplySNMPToSimilar(ctx, "admin@example.com", "a-sw", []string{"a-new", "a-never", "a-far"})
	if err != nil || len(res) != 3 || !res[0].OK || res[1].OK || res[1].Code != "not_a_candidate" || res[2].OK || res[2].Code != "not_a_candidate" {
		t.Fatalf("apply: %v %+v", err, res)
	}
	sa.WaitSNMPReads(w.svc)
	if b, _ := json.Marshal(res); strings.Contains(string(b), "community-1") {
		t.Fatal("the secret is in the result")
	}
	// the copy is the device's own, with its own address and the source's port and community; the other device is untouched
	if _, plain := w.secretOf("a-new", "secret_id"); plain != "community-1" {
		t.Fatalf("copied secret %q", plain)
	}
	if _, plain := w.secretOf("a-never", "secret_id"); plain != "its-own-one" {
		t.Fatal("a device with its own settings was overwritten")
	}
	if n := w.count(`SELECT count(*) FROM sa_snmp_device WHERE asset_id = 'a-printer'`); n != 0 {
		t.Fatal("a device that was not ticked got settings")
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE user = 'admin@example.com' AND action = 'inventory.snmp_set' AND detail LIKE '%copied from device a-sw'`); n != 1 {
		t.Errorf("%d audit rows of the copy", n)
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE user = 'admin@example.com' AND action = 'inventory.snmp_apply_similar' AND detail = '1 of 3 devices'`); n != 1 {
		t.Errorf("%d audit rows of the action", n)
	}
	// a read of the saved device was queued; it went to that device's own address with the copied settings
	var sent int
	for _, j := range r.sent() {
		for _, tg := range j.Targets {
			if tg.IP == "192.168.10.21" && tg.Credential.Community == "community-1" && tg.Credential.Port == 1161 {
				sent++
			} else if tg.IP != "192.168.10.21" {
				t.Errorf("a read went to %s", tg.IP)
			}
		}
	}
	if sent != 1 {
		t.Fatalf("%d reads of the applied device, want 1", sent)
	}

	// L2: settings a device saved itself between the list and the save are never overwritten (checked in the write)
	w.set("a-printer", sa.SNMPInput{Version: "v2c", Community: secrets.NewValue("printer-own")})
	if err := sa.SetSNMPOnlyIfNone(ctx, w.svc, "admin@example.com", "a-printer", "a-sw"); apiCode(err) != "has_own_settings" {
		t.Fatalf("a device with its own settings: %v", err)
	}
	if _, plain := w.secretOf("a-printer", "secret_id"); plain != "printer-own" {
		t.Fatal("the apply overwrote a device's own settings")
	}
	// L3: a device whose address is not local is refused with a clear result, and nothing is stored
	w.inv.assets["a-pub"] = netip.MustParseAddr("8.8.8.8")
	w.inv.similar["a-sw"] = append(w.inv.similar["a-sw"], sa.SimilarDevice{ID: "a-pub", IP: "8.8.8.8", Vendor: "Acme", Kind: "switch", SameMaker: true, SameType: true, Approved: true})
	res, err = w.svc.ApplySNMPToSimilar(ctx, "admin@example.com", "a-sw", []string{"a-pub"})
	if err != nil || len(res) != 1 || res[0].OK || res[0].Code != "read_from_not_local" {
		t.Fatalf("a public address: %v %+v", err, res)
	}
	if n := w.count(`SELECT count(*) FROM sa_snmp_device WHERE asset_id = 'a-pub'`); n != 0 {
		t.Fatal("settings were stored for a public address")
	}

	for _, bad := range [][]string{nil, make([]string, sa.MaxApplySimilar+1)} {
		if _, err := w.svc.ApplySNMPToSimilar(ctx, "a", "a-sw", bad); apiCode(err) != "bad_devices" {
			t.Fatalf("%d devices: %v", len(bad), err)
		}
	}
	w.loseSecret("a-sw", "secret_id")
	if _, err := w.svc.ApplySNMPToSimilar(ctx, "a", "a-sw", []string{"a-printer"}); apiCode(err) != "secret_lost" {
		t.Fatalf("a source whose secret is lost: %v", err)
	}
}
