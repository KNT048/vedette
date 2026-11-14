package notify_test

import (
	"testing"
	"time"

	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/notify"
)

// D-554 (MK-1): a device a sensor found while it was learning the network (inventory's learning flag) goes into the one
// first-discovery summary, long after notify's own first run; a device found by a sensor past its learning is its own incident, and
// notify:false opens nothing.
func TestLearningSensorFoldsItsDevicesIntoOneSummary(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) {
		c.Devices = fakeDevices{"a1": "PC-01", "a2": "NAS-01", "a3": "CAM-3", "a9": "LAPTOP-NEW"}
	})
	e.firstRunAt(e.clock.Now().AddDate(0, -2, 0)) // the box ran for months: notify's own window is long over
	e.svc.Subscribe(e.bus)
	found := func(ev inventory.AssetEvent) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), eventOf(inventory.EventAssetDiscovered, ev)); err != nil {
			t.Fatal(err)
		}
	}
	found(inventory.AssetEvent{AssetID: "a1", Notify: true, Learning: true})
	found(inventory.AssetEvent{AssetID: "a2", Notify: true, Learning: true})
	found(inventory.AssetEvent{AssetID: "a3", Notify: false, Learning: true})
	l, _ := e.svc.Incidents(e.ctx())
	if len(l) != 1 || l[0].Title != "2 devices found on your network: approve them in Devices" || l[0].Link != "/devices" || len(l[0].Devices) != 2 {
		t.Fatalf("incidents = %+v", l)
	}
	e.clock.Add(37 * time.Hour)
	found(inventory.AssetEvent{AssetID: "a9", Notify: true})
	if l, _ = e.svc.Incidents(e.ctx()); len(l) != 2 || l[0].Title != "A new unknown device appeared: LAPTOP-NEW" {
		t.Fatalf("incidents = %+v", l)
	}
}

// D-554 (W1-37): the row inventory joined into another device leaves its new-device incidents with "merged into <name>", whether
// inventory.asset.merged comes before or after the inventory.asset.deleted of the same join: one close, one audit row. The device it
// joined keeps its own incident.
func TestMergedDeviceLeavesItsIncidentNamingWhereItWent(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) {
		c.Devices = fakeDevices{"lldp-1": "Juniper", "ip-1": "EX2300", "lldp-2": "Juniper", "ip-2": "EX4300", "s1": "PC-01", "s2": "NAS-01"}
	})
	e.firstRunAt(e.clock.Now().AddDate(0, -2, 0))
	e.svc.Subscribe(e.bus)
	publish := func(name string, data any) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), eventOf(name, data)); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"lldp-1", "ip-1", "lldp-2"} {
		publish(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: id, Notify: true})
	}
	own := func(asset string) notify.Incident {
		t.Helper()
		l, _ := e.svc.Incidents(e.ctx())
		for _, i := range l {
			if i.Link == "/devices/"+asset {
				return i
			}
		}
		t.Fatalf("no incident of %s in %+v", asset, l)
		return notify.Incident{}
	}
	// merged first, then deleted
	publish(notify.EventAssetMerged, map[string]string{"from": "lldp-1", "into": "ip-1"})
	publish(inventory.EventAssetDeleted, map[string]string{"asset_id": "lldp-1"})
	if i := own("lldp-1"); i.Status != notify.StatusResolved || i.ResolvedReason == nil || *i.ResolvedReason != "Closed by Vedette: merged into EX2300." {
		t.Fatalf("merged then deleted = %+v", i)
	}
	if i := own("ip-1"); i.Status != notify.StatusNew {
		t.Fatalf("the device it joined = %+v", i)
	}
	// deleted first, then merged: the reason is rewritten, not closed twice
	publish(inventory.EventAssetDeleted, map[string]string{"asset_id": "lldp-2"})
	e.clock.Add(20 * time.Second)
	publish(notify.EventAssetMerged, map[string]string{"from": "lldp-2", "into": "ip-2"})
	if i := own("lldp-2"); i.Status != notify.StatusResolved || i.ResolvedReason == nil || *i.ResolvedReason != "Closed by Vedette: merged into EX4300." {
		t.Fatalf("deleted then merged = %+v", i)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.incident_status' AND user = 'system'`); n != 2 {
		t.Fatalf("audit rows = %d, want one per closed incident", n)
	}
	// a merge long after a delete does not rewrite a person's delete
	publish(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: "s1", Notify: true})
	publish(inventory.EventAssetDeleted, map[string]string{"asset_id": "s1", "actor": "an@acme.example"})
	e.clock.Add(2 * time.Minute)
	publish(notify.EventAssetMerged, map[string]string{"from": "s1", "into": "ip-1"})
	if i := own("s1"); i.ResolvedReason == nil || *i.ResolvedReason != "Closed by Vedette: the device was deleted in Devices by an@acme.example." {
		t.Fatalf("old delete = %+v", i)
	}
	// on an open first-discovery summary the row leaves the list
	e.firstRunAt(e.clock.Now())
	publish(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: "s2", Notify: true})
	publish(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: "lldp-2", Notify: true})
	publish(notify.EventAssetMerged, map[string]string{"from": "lldp-2", "into": "ip-2"})
	l, _ := e.svc.Incidents(e.ctx())
	if l[0].Link != "/devices" || l[0].Title != "1 device found on your network: approve it in Devices" || len(l[0].Devices) != 1 || l[0].Devices[0].ID != "s2" {
		t.Fatalf("summary = %+v", l[0])
	}
}
