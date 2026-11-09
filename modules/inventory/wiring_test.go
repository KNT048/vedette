package inventory_test

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"

	"github.com/knt048/vedette/modules/inventory"
)

// manual runs AddManualDevice in a caller transaction and settles it like feeds does.
func (e *env) manual(d inventory.ManualDevice, fail bool) error {
	e.t.Helper()
	var txp *sql.Tx
	err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		txp = tx
		if err := e.svc.AddManualDevice(e.ctx(), tx, "emily@acme.example", d); err != nil {
			return err
		}
		if fail {
			return errors.New("the caller's own write failed")
		}
		return nil
	})
	e.svc.Settle(e.ctx(), txp, err == nil)
	return err
}

func TestAddManualDeviceCommitsWithTheCallerAndAnnouncesAfterIt(t *testing.T) {
	kev := fakeKEV{cves: map[string][]string{"fortinet|fortios": {"CVE-2024-0001"}}}
	e := newEnv(t, withKEV(kev))
	d := inventory.ManualDevice{Kind: "firewall", Vendor: "Fortinet", Product: "FortiOS", Display: "FortiGate firewall (FortiOS)", Key: "fortinet|fortios"}
	if err := e.manual(d, false); err != nil {
		t.Fatal(err)
	}
	list, err := e.svc.Devices(e.ctx())
	if err != nil || len(list.Items) != 1 {
		t.Fatalf("devices: %v %v", list.Items, err)
	}
	dev := list.Items[0]
	if dev.Origin != "manual" || !dev.Approved || dev.Kind != "firewall" || len(dev.Software) != 1 || dev.Software[0].Display != "FortiGate firewall (FortiOS)" || dev.FirstScanAt != nil {
		t.Errorf("device %+v", dev)
	}
	if !slices.Contains(e.auditActions(), "inventory.add_manual") {
		t.Errorf("audit %v", e.auditActions())
	}
	if n, m := len(e.ev.named(inventory.EventAssetUpdated)), e.ev.named(inventory.EventMatchChanged); n != 1 || len(m) != 1 || m[0].Data.(inventory.MatchEvent).CVE != "CVE-2024-0001" {
		t.Errorf("events: updated %d, match %v", n, m)
	}
}

func TestAddManualDeviceRollsBackWithTheCaller(t *testing.T) {
	e := newEnv(t, withKEV(fakeKEV{cves: map[string][]string{"fortinet|fortios": {"CVE-2024-0001"}}}))
	d := inventory.ManualDevice{Vendor: "Fortinet", Product: "FortiOS", Key: "fortinet|fortios"}
	if err := e.manual(d, true); err == nil {
		t.Fatal("the caller failed and the transaction committed")
	}
	if n := e.count(`SELECT count(*) FROM inv_asset`) + e.count(`SELECT count(*) FROM inv_software`) + e.count(`SELECT count(*) FROM core_audit`); n != 0 {
		t.Errorf("%d rows survived the rollback", n)
	}
	if len(e.ev.events) != 0 {
		t.Errorf("events of a rolled-back change: %v", e.ev.events)
	}
	e.svc.Settle(e.ctx(), nil, true) // settling twice or for an unknown transaction is harmless
}

// The same checks as the normal add: a bad key, a bad kind hint, a name with markup, a long typed name.
func TestAddManualDeviceChecksLikeTheNormalAdd(t *testing.T) {
	e := newEnv(t)
	if err := e.manual(inventory.ManualDevice{Vendor: "Fortinet", Product: "FortiOS", Key: "fortinet|other"}, false); err == nil {
		t.Error("a key that is not the product's was accepted")
	}
	if err := e.manual(inventory.ManualDevice{Vendor: "<b>x</b>", Product: "y", Key: "<b>x</b>|y"}, false); err == nil {
		t.Error("markup in the vendor was accepted")
	}
	if n := e.count(`SELECT count(*) FROM inv_asset`); n != 0 {
		t.Fatalf("%d devices after refusals", n)
	}
	// a display name with markup is not used: the device is named after its product
	if err := e.manual(inventory.ManualDevice{Vendor: "Acme", Product: "Box", Display: "<script>", Key: "acme|box"}, false); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM inv_software WHERE display = 'Acme Box'`); n != 1 {
		t.Errorf("software display: %d rows named after the product", n)
	}
	// a kind that is not one of ours is ignored, not an error; the product's own kind applies
	if err := e.manual(inventory.ManualDevice{Kind: "toaster", Vendor: "MikroTik", Product: "RouterOS", Key: "mikrotik|routeros"}, false); err != nil { //nolint:misspell // RouterOS is the product name
		t.Fatal(err)
	}
	// a long name is fine only for an exact pair of the KEV list (data of the CISA list, not typed)
	long := "Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)"
	if err := e.manual(inventory.ManualDevice{Vendor: "Cisco", Product: long + " and more words to pass sixty-four characters of text", Key: "cisco|" + long + " and more words to pass sixty-four characters of text"}, false); err == nil {
		t.Error("a long product that is not in the KEV list was accepted")
	}
	if err := e.manual(inventory.ManualDevice{Kind: "firewall", Vendor: "Cisco", Product: long, Key: "cisco|adaptive security appliance (asa) and firepower threat defense (ftd)"}, false); err != nil {
		t.Errorf("a KEV pair longer than 64 characters: %v", err)
	}
}

func TestDevicesRunningYesMaybeNo(t *testing.T) {
	e := newEnv(t, withKEV(fakeKEV{cves: map[string][]string{}}))
	fg := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", IP: "192.168.30.1", Name: "fw1"})
	e.addDevice(inventory.AddInput{CatalogID: "mikrotik-routeros", IP: "192.168.30.2"}) //nolint:misspell // RouterOS is the product name
	q := []inventory.ProductQuery{{Vendor: "Fortinet", Product: "FortiOS"}, {Vendor: "Fortinet", Product: "Multiple Products"}, {Vendor: "MikroTik", Product: "RouterOS"}, {Vendor: "QNAP", Product: "QTS"}}
	got, err := e.svc.DevicesRunning(e.ctx(), q)
	if err != nil {
		t.Fatal(err)
	}
	if m := got["fortinet|fortios"]; len(m) != 1 || m[0].ID != fg || !m[0].Exact || m[0].Display != "FortiGate" || m[0].IP != "192.168.30.1" || m[0].Hostname == nil || *m[0].Hostname != "fw1" {
		t.Errorf("fortios: %+v", m)
	}
	if m := got["fortinet|multiple products"]; len(m) != 1 || m[0].ID != fg || m[0].Exact {
		t.Errorf("multiple products by vendor only must be maybe: %+v", m)
	}
	if m := got["mikrotik|routeros"]; len(m) != 1 || !m[0].Exact { //nolint:misspell // RouterOS is the product name
		t.Errorf("routeros: %+v", m) //nolint:misspell // RouterOS is the product name
	}
	if _, ok := got["qnap|qts"]; ok {
		t.Errorf("a product no device runs has an entry: %+v", got["qnap|qts"])
	}
	// "I have it" for Multiple products declares a device that runs it for sure
	if err := e.manual(inventory.ManualDevice{Vendor: "Fortinet", Product: "Multiple Products", Key: "fortinet|multiple products"}, false); err != nil {
		t.Fatal(err)
	}
	got, _ = e.svc.DevicesRunning(e.ctx(), q[1:2])
	m := got["fortinet|multiple products"]
	if len(m) != 2 || !m[0].Exact || m[1].Exact || m[1].ID != fg {
		t.Errorf("after I have it: %+v (the declared device is yes, the firewall maybe)", m)
	}
}

func TestMatchInputAndDeviceRefs(t *testing.T) {
	e := newEnv(t)
	id := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", IP: "192.168.30.1"})
	d, ok, err := e.svc.MatchInput(e.ctx(), id)
	if err != nil || !ok || d.Name != "192.168.30.1" || len(d.Software) != 1 || d.Software[0].Version != "7.2.5" || !slices.Contains(d.Software[0].KevKeys, "fortinet|fortios") {
		t.Fatalf("MatchInput: %+v %v %v", d, ok, err)
	}
	if _, ok, err = e.svc.MatchInput(e.ctx(), "nope"); ok || err != nil {
		t.Errorf("unknown device: %v %v", ok, err)
	}
	refs, err := e.svc.DeviceRefs(e.ctx(), []string{id, "nope"})
	if err != nil || len(refs) != 1 || refs[id].Display != "FortiGate" || refs[id].Kind != "firewall" || refs[id].Hostname != nil {
		t.Errorf("DeviceRefs: %+v %v", refs, err)
	}
	if refs, _ = e.svc.DeviceRefs(e.ctx(), nil); len(refs) != 0 {
		t.Errorf("no ids: %v", refs)
	}
}

func TestHasDevice(t *testing.T) {
	e := newEnv(t)
	if ok, err := e.svc.HasDevice(e.ctx(), []string{"firewall", "router"}, "fortinet"); ok || err != nil {
		t.Fatalf("empty inventory: %v %v", ok, err)
	}
	e.addDevice(inventory.AddInput{CatalogID: "fortigate"})
	e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager"}) // a NAS is not a firewall
	for vendor, want := range map[string]bool{"fortinet": true, "Fortinet": true, "mikrotik": false, "synology": false, "": false} {
		if ok, err := e.svc.HasDevice(e.ctx(), []string{"firewall", "router"}, vendor); ok != want || err != nil {
			t.Errorf("HasDevice(%q) = %v, %v; want %v", vendor, ok, err, want)
		}
	}
}

func TestRematch(t *testing.T) {
	kev := fakeKEV{cves: map[string][]string{"fortinet|fortios": {"CVE-2024-0001", "CVE-2024-0002"}, "mikrotik|routeros": {"CVE-2024-0003"}}} //nolint:misspell // RouterOS is the product name
	e := newEnv(t)                                                                                                                            // no KEV yet: the devices are added without matches
	e.addDevice(inventory.AddInput{CatalogID: "fortigate"})
	if n, err := e.svc.RematchAll(e.ctx()); n != 0 || err != nil {
		t.Fatalf("without KEV: %d %v", n, err)
	}
	e = newEnv(t, withKEV(kev))
	fg := e.addDevice(inventory.AddInput{CatalogID: "fortigate"})
	rt := e.addDevice(inventory.AddInput{CatalogID: "mikrotik-routeros", IP: "192.168.30.2"}) //nolint:misspell // RouterOS is the product name
	e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.30.5"})
	e.ev.reset()
	n, err := e.svc.RematchAll(e.ctx())
	if err != nil || n != 3 {
		t.Fatalf("RematchAll = %d, %v; want 3", n, err)
	}
	got := map[string][]string{}
	for _, ev := range e.ev.named(inventory.EventMatchChanged) {
		m := ev.Data.(inventory.MatchEvent)
		got[m.AssetID] = append(got[m.AssetID], m.CVE)
	}
	if !slices.Equal(got[fg], []string{"CVE-2024-0001", "CVE-2024-0002"}) || !slices.Equal(got[rt], []string{"CVE-2024-0003"}) || len(got) != 2 {
		t.Errorf("events %v", got)
	}
	// one new CVE of FortiOS reaches the devices that run it only
	e.ev.reset()
	if n, err = e.svc.RematchCVE(e.ctx(), "CVE-2024-0009", "Fortinet", "FortiOS"); err != nil || n != 1 {
		t.Fatalf("RematchCVE = %d, %v", n, err)
	}
	if ev := e.ev.named(inventory.EventMatchChanged); len(ev) != 1 || ev[0].Data.(inventory.MatchEvent) != (inventory.MatchEvent{AssetID: fg, CVE: "CVE-2024-0009", Basis: "product"}) {
		t.Errorf("events %v", ev)
	}
	// a CVE of "Multiple products" reaches every device with software of the vendor
	if n, _ = e.svc.RematchCVE(e.ctx(), "CVE-2024-0010", "Fortinet", "Multiple Products"); n != 1 {
		t.Errorf("multiple products: %d", n)
	}
	if n, _ = e.svc.RematchCVE(e.ctx(), "CVE-2024-0011", "Nobody", "Nothing"); n != 0 {
		t.Errorf("unknown product: %d", n)
	}
}

// DevicesOfKind is the uncapped read the never-touch list needs: devices of the kinds asked, the id, the addresses and the host name,
// beyond the MaxListed rows that Devices stops at; an empty kinds is an empty answer; a read that fails is an error, never a short list.
func TestDevicesOfKindIsUncapped(t *testing.T) {
	e := newEnv(t)
	if l, err := e.svc.DevicesOfKind(e.ctx(), []string{"firewall", "router"}); len(l) != 0 || err != nil {
		t.Fatalf("empty inventory: %v %v", l, err)
	}
	fw := e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "192.168.10.1"})
	e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.10.21"}) // a NAS
	e.exec(`UPDATE inv_asset SET mac = 'aa:bb:cc:dd:ee:ff' WHERE id = ?`, fw)
	l, err := e.svc.DevicesOfKind(e.ctx(), []string{"firewall", "router"})
	if err != nil || len(l) != 1 || l[0].ID != fw || l[0].IP != "192.168.10.1" || l[0].MAC == nil || *l[0].MAC != "aa:bb:cc:dd:ee:ff" || l[0].Kind != "firewall" {
		t.Fatalf("firewall: %+v, %v", l, err)
	}
	if l, err := e.svc.DevicesOfKind(e.ctx(), nil); len(l) != 0 || err != nil {
		t.Fatalf("no kinds: %v %v", l, err)
	}
	e.exec(`WITH RECURSIVE c(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM c WHERE n < ?)
INSERT INTO inv_asset (id, kind, origin, first_seen, last_seen) SELECT 'bulk-' || n, 'router', 'manual', '2026-11-09T10:00:00.000Z', '2026-11-09T10:00:00.000Z' FROM c`, inventory.MaxListed+99)
	l, err = e.svc.DevicesOfKind(e.ctx(), []string{"router", "firewall"})
	if err != nil || len(l) != inventory.MaxListed+100+1 {
		t.Fatalf("%d devices, want %d (no cap): %v", len(l), inventory.MaxListed+101, err)
	}
	if !slices.ContainsFunc(l, func(d inventory.KindDevice) bool { return d.ID == fw }) {
		t.Fatal("the oldest firewall dropped out of the answer")
	}
	for _, d := range l {
		if d.ID != fw && (d.IP != "—" || d.MAC != nil) {
			t.Fatalf("a device without addresses: %+v", d)
		}
	}
	ctx, cancel := context.WithCancel(e.ctx())
	cancel()
	if l, err := e.svc.DevicesOfKind(ctx, []string{"router"}); err == nil || l != nil {
		t.Fatalf("a failed read answered %d devices without an error", len(l))
	}
}

// exec runs a write statement behind the service, for fixtures.
func (e *env) exec(query string, args ...any) {
	e.t.Helper()
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error { _, err := tx.ExecContext(e.ctx(), query, args...); return err }); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
}
