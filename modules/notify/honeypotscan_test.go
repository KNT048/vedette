package notify_test

import (
	"testing"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/notify"
)

// W1-13 (honeypot INV-24): the hits of one source make one Critical trap incident per Trap IP service it touched and one High
// scan incident per source while it is open; a later scan hit of the same source repeats that incident (count), it opens no
// other. The source device the honeypot named is on the incident.
func TestHoneypotScanIsOneHighIncidentPerSourceWithTheDevice(t *testing.T) {
	e := newEnv(t)
	e.svc.Subscribe(e.bus)
	pub := func(data map[string]any) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), events.Event{Name: notify.EventHoneypotHit, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	src := "192.168.10.145"
	touch := func(id, svc, decoy string) map[string]any {
		return map[string]any{"id": id, "ts": "2026-11-13T07:10:58Z", "kind": "service", "service": svc, "port": 80, "src_ip": src, "label": svc,
			"decoy": decoy, "src_asset_id": "a-laptop", "src_name": "LAPTOP-KIEN"}
	}
	scan := func(id, decoys string) map[string]any {
		return map[string]any{"id": id, "ts": "2026-11-13T07:10:59Z", "kind": "scan", "service": "", "src_ip": src, "label": "Scan across the Trap IPs",
			"decoy": decoys, "src_asset_id": "a-laptop", "src_name": "LAPTOP-KIEN"}
	}
	pub(touch("hit-1", "http", "BUILD-SRV-02"))
	pub(touch("hit-2", "ssh", "BUILD-SRV-02"))
	pub(scan("hit-3", "BUILD-SRV-02, NAS-ARCHIVE"))
	pub(scan("hit-4", "BUILD-SRV-02, FILESRV-OLD")) // the same source scanning on, in a later window: the same open incident
	pub(scan("hit-5", "NAS-ARCHIVE, PRN-FLOOR2"))
	l, err := e.svc.Incidents(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	var scans, critical []notify.Incident
	for _, i := range l {
		switch {
		case i.Kind == notify.IncidentTrap && i.Severity == notify.High:
			scans = append(scans, i)
		case i.Kind == notify.IncidentTrap && i.Severity == notify.Critical:
			critical = append(critical, i)
		}
	}
	if len(scans) != 1 || scans[0].Title != src+" scanned the Trap IPs" || scans[0].Count != 3 {
		t.Fatalf("scan incidents = %+v", scans)
	}
	if len(critical) != 2 {
		t.Fatalf("the touches are %d Critical incidents, want one per service: %+v", len(critical), critical)
	}
	for _, i := range append(scans, critical...) {
		if len(i.Devices) != 1 || i.Devices[0].ID != "a-laptop" || i.Devices[0].Name != "LAPTOP-KIEN" {
			t.Fatalf("%q does not name the source device: %+v", i.Title, i.Devices)
		}
	}
	// Another source scanning is its own incident; a hit without a device name names no device.
	pub(map[string]any{"id": "hit-6", "kind": "scan", "src_ip": "192.168.10.99", "label": "Scan across the Trap IPs", "decoy": "NAS-ARCHIVE, PRN-FLOOR2", "src_asset_id": "a-x"})
	l, _ = e.svc.Incidents(e.ctx())
	n := 0
	for _, i := range l {
		if i.Severity == notify.High && i.Kind == notify.IncidentTrap {
			n++
			if i.Title == "192.168.10.99 scanned the Trap IPs" && len(i.Devices) != 0 {
				t.Fatalf("a device without a name was put on the incident: %+v", i.Devices)
			}
		}
	}
	if n != 2 {
		t.Fatalf("%d scan incidents for two sources", n)
	}
}
