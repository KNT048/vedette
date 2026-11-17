package main

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/notify"
)

// D-628 (kien 2026-11-17): Ignore through the API (operator) removes the device's findings and makes none, even after a reconcile;
// stopping matches it again.
func TestWiringIgnoredDeviceHasNoFindings(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.kev("CVE-2026-1001", "Fortinet", "FortiOS")
	s.kev("CVE-2026-1002", "Fortinet", "FortiOS")
	id := s.addFortiGate()
	if n := s.nf(id, ""); n != 2 {
		t.Fatalf("findings before = %d", n)
	}
	if c, _ := s.do("POST", "/inventory/devices/"+id+"/ignore", "viewer", `{"ignored":true}`); c != 403 {
		t.Fatalf("a viewer ignored a device: %d", c)
	}
	if c, b := s.do("POST", "/inventory/devices/"+id+"/ignore", "operator", `{"ignored":true}`); c != 200 {
		t.Fatalf("ignore: %d %v", c, b)
	}
	if n := s.nf("", ""); n != 0 {
		t.Fatalf("%d findings of an ignored device", n)
	}
	if err := findingsJobs(*s.d)[0].Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := s.nf("", ""); n != 0 {
		t.Fatalf("the reconcile made %d findings for an ignored device", n)
	}
	if c, b := s.do("GET", "/inventory/devices", "viewer", ""); c != 200 || at(b, "counts", "ignored") != float64(1) || len(at(b, "items").([]any)) != 0 {
		t.Fatalf("GET /inventory/devices: %d %v", c, b)
	}
	if c, b := s.do("GET", "/inventory/devices?ignored=true", "viewer", ""); c != 200 || at(b, "items", 0, "id") != id || at(b, "items", 0, "ignored_at") == nil {
		t.Fatalf("GET /inventory/devices?ignored=true: %d %v", c, b)
	}
	if c, b := s.do("POST", "/inventory/devices/"+id+"/ignore", "operator", `{"ignored":false}`); c != 200 {
		t.Fatalf("stop ignoring: %d %v", c, b)
	}
	if n := s.nf(id, ""); n != 2 {
		t.Fatalf("findings after stopping = %d, want 2", n)
	}
}

// D-628: ignoring closes the device's new-device incident, naming the person; a trap hit from the ignored device still opens a
// Critical incident (the security exception: a staff phone touching a honeypot is what the customer must hear about).
func TestWiringIgnoredDeviceClosesItsIncidentButATrapHitStillAlerts(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.enableNotify()
	ctx := t.Context()
	const mac = "c2:31:86:3f:8c:a0" // the N100's iPhone: a private MAC
	if err := s.d.Inventory.Record(ctx, []observe.Observation{
		{AssetHint: observe.AssetHint{MAC: mac, IP: netip.MustParseAddr("192.168.18.129")}, Field: observe.Hostname, Value: "iPhone", Source: observe.Passive, Confidence: 0.7},
	}); err != nil {
		t.Fatal(err)
	}
	l, err := s.d.Inventory.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, d := range l.Items {
		if d.MAC != nil && *d.MAC == mac {
			id = d.ID
		}
	}
	if err := s.d.Bus.Publish(ctx, events.Event{Name: inventory.EventAssetDiscovered, Data: inventory.AssetEvent{AssetID: id, Notify: true}}); err != nil {
		t.Fatal(err)
	}
	svc := newNotify(s.d)
	openFor := func(kind notify.IncidentKind) []notify.Incident {
		t.Helper()
		list, err := svc.Incidents(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var out []notify.Incident
		for _, in := range list {
			if in.Kind == kind && in.Status != notify.StatusResolved && slices.ContainsFunc(in.Devices, func(d notify.Device) bool { return d.ID == id }) {
				out = append(out, in)
			}
		}
		return out
	}
	if len(openFor(notify.IncidentUnknownDevice)) != 1 {
		t.Fatal("no new-device incident before ignoring")
	}
	if err := s.d.Inventory.SetIgnored(ctx, "it@acme.example", id, true); err != nil {
		t.Fatal(err)
	}
	if open := openFor(notify.IncidentUnknownDevice); len(open) != 0 {
		t.Fatalf("the new-device incident stays open for an ignored device: %+v", open)
	}
	if err := s.d.Bus.Publish(ctx, events.Event{Name: notify.EventHoneypotHit, Data: map[string]any{
		"id": "h-1", "kind": "touch", "service": "smb", "src_ip": "192.168.18.129", "label": "File share", "src_asset_id": id, "src_name": "iPhone",
	}}); err != nil {
		t.Fatal(err)
	}
	if open := openFor(notify.IncidentTrap); len(open) != 1 || open[0].Severity != notify.Critical {
		t.Fatalf("a trap hit from an ignored device must still alert: %+v", open)
	}
}
