package notify_test

import (
	"strings"
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
	publish(inventory.EventAssetDeleted, map[string]string{"asset_id": "lldp-2"})
	publish(notify.EventAssetMerged, map[string]string{"from": "s2", "into": "ip-2"})
	if i := e.detail(l[0].ID); i.Status != notify.StatusResolved || i.ResolvedReason == nil ||
		*i.ResolvedReason != "Closed by Vedette: every device on it was approved or deleted in Devices, the last one merged into EX4300." {
		t.Fatalf("summary whose last device was merged = %+v", i)
	}
}

// D-554 (Opus review HIGH): devices that leave the summary do not hide the ones added later. Told at 4 devices, 3 deleted, a month
// later a new sensor learns 2 more: each is told ("1 more device found"), and an acknowledged summary that takes a device is New again.
// A device that leaves before it was told does not count as told: the next update still names every untold device.
func TestDiscoverySummaryTellsDevicesAddedAfterOthersLeft(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) {
		c.Devices = fakeDevices{"a1": "D-a1", "a2": "D-a2", "a3": "D-a3", "a4": "D-a4", "b1": "D-b1", "b2": "D-b2", "b3": "D-b3", "b4": "D-b4"}
	})
	e.firstRunAt(e.clock.Now())
	e.telegram(notify.Low)
	e.plain()
	e.svc.Subscribe(e.bus)
	pub := func(name string, d any) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), eventOf(name, d)); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"a1", "a2", "a3", "a4"} {
		pub(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: id, Notify: true})
		e.clock.Add(2 * time.Hour)
	}
	e.flush()
	sent := func() []string {
		t.Helper()
		var out []string
		for _, c := range e.net.to("api.telegram.org") {
			out = append(out, c.Body)
		}
		return out
	}
	before := len(sent())
	for _, id := range []string{"a1", "a2", "a3"} {
		pub(inventory.EventAssetDeleted, map[string]string{"asset_id": id})
	}
	l, _ := e.svc.Incidents(e.ctx())
	if _, err := e.svc.HandleIncident(e.ctx(), "u-op", l[0].ID, notify.StatusAcknowledged, "seen"); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(30 * 24 * time.Hour)
	pub(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: "b1", Notify: true, Learning: true})
	e.flush()
	got := sent()
	if len(got) != before+1 || !strings.Contains(got[len(got)-1], "2 devices found on your network") || !strings.Contains(got[len(got)-1], "1 more device found") {
		t.Fatalf("after b1: %d messages (was %d), last %.300s", len(got), before, got[len(got)-1])
	}
	if i := e.detail(l[0].ID); i.Status != notify.StatusNew || i.HandledBy != nil || i.Note == nil || *i.Note != "seen" {
		t.Fatalf("acknowledged summary that took a device = %+v", i)
	}
	// b2 comes within the hour (untold) and leaves before it is told; b3 comes later: the update counts only b3
	e.clock.Add(10 * time.Minute)
	pub(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: "b2", Notify: true, Learning: true})
	pub(inventory.EventAssetDeleted, map[string]string{"asset_id": "b2"})
	e.clock.Add(2 * time.Hour)
	pub(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: "b3", Notify: true, Learning: true})
	e.flush()
	if got = sent(); len(got) != before+2 || !strings.Contains(got[len(got)-1], "3 devices found on your network") || !strings.Contains(got[len(got)-1], "1 more device found") {
		t.Fatalf("after b3: %d messages, last %.300s", len(got), got[len(got)-1])
	}
}

// D-554 (Opus review MED): a burst within the hour after a message is told by the hourly job, once, with every untold device.
func TestDiscoveryBurstIsToldByTheHourlyJob(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) {
		c.Devices = fakeDevices{"a1": "D-a1", "a2": "D-a2", "a3": "D-a3", "a4": "D-a4"}
	})
	e.firstRunAt(e.clock.Now().AddDate(0, -2, 0))
	e.telegram(notify.Low)
	e.plain()
	e.svc.Subscribe(e.bus)
	for _, id := range []string{"a1", "a2", "a3", "a4"} {
		if err := e.bus.Publish(e.ctx(), eventOf(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: id, Notify: true, Learning: true})); err != nil {
			t.Fatal(err)
		}
		e.clock.Add(time.Minute)
	}
	e.flush()
	if n := len(e.net.to("api.telegram.org")); n != 1 {
		t.Fatalf("messages after the burst = %d, want the summary", n)
	}
	l, _ := e.svc.Incidents(e.ctx())
	if !strings.Contains(l[0].What, "A sensor started watching your network") {
		t.Fatalf("what = %q", l[0].What)
	}
	e.autoClose() // within the hour: nothing yet
	e.flush()
	e.clock.Add(time.Hour)
	e.autoClose()
	e.flush()
	e.autoClose() // nothing left to tell
	e.flush()
	calls := e.net.to("api.telegram.org")
	if len(calls) != 2 || !strings.Contains(calls[1].Body, "4 devices found on your network") || !strings.Contains(calls[1].Body, "3 more devices found") {
		t.Fatalf("calls = %d, last %.300s", len(calls), calls[len(calls)-1].Body)
	}
}
