package main

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// D-630 (kien 2026-11-17, review: never throw away a person's decisions): Ignore through the API (operator) closes the device's open
// findings with a readable reason and no notice; a finding a person settled keeps its status; a reconcile makes nothing new; Stop
// ignoring reopens only what Ignore closed and the device is matched again.
func TestWiringIgnoredDeviceClosesItsOpenFindingsAndKeepsDecisions(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	svc, err := notify.New(notify.Config{DB: s.d.DB, Secrets: s.d.Secrets, Audit: s.d.Audit, Users: notifyUsers{s.d}, Log: s.d.Log, Modules: s.d.Reg, Bus: s.d.Bus, Findings: anyFinding{}, Clock: s.d.Clock})
	if err != nil {
		t.Fatal(err)
	}
	svc.Subscribe(s.d.Bus)
	if _, err := svc.SaveChannel(ctx, "admin@acme.example", channel.Telegram, notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": "-1002145678901"},
		Secret: "123456789:AAHexampleExampleExample0123456789ab", MinSeverity: notify.Low}); err != nil { // not a real token
		t.Fatal(err)
	}
	s.kev("CVE-2026-1001", "Fortinet", "FortiOS")
	s.kev("CVE-2026-1002", "Fortinet", "FortiOS")
	id := s.addFortiGate()
	byCVE := func() map[string]findings.Record {
		t.Helper()
		recs, err := s.d.Findings.List(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]findings.Record{}
		for _, r := range recs {
			out[r.CVE] = r
		}
		return out
	}
	recs := byCVE()
	if len(recs) != 2 {
		t.Fatalf("findings before = %d", len(recs))
	}
	// a person's decision on one of them
	if _, err := s.d.Findings.SetStatus(ctx, recs["CVE-2026-1002"].ID, findings.ActionFalsePositive, "not this model", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	notices := pendingNotices(s)
	if notices == 0 {
		t.Fatal("the new findings queued no notice, so the no-notice check below would prove nothing")
	}

	if c, _ := s.do("POST", "/inventory/devices/"+id+"/ignore", "viewer", `{"ignored":true}`); c != 403 {
		t.Fatalf("a viewer ignored a device: %d", c)
	}
	if c, b := s.do("POST", "/inventory/devices/"+id+"/ignore", "operator", `{"ignored":true}`); c != 200 {
		t.Fatalf("ignore: %d %v", c, b)
	}
	recs = byCVE()
	open := recs["CVE-2026-1001"]
	if len(recs) != 2 || open.Status != findings.StatusNotRelevant || !strings.HasPrefix(open.ResolutionNote, "Closed by Vedette: the device was ignored by ") {
		t.Fatalf("after ignore: %+v", recs)
	}
	if fp := recs["CVE-2026-1002"]; fp.Status != findings.StatusFalsePositive || fp.ResolutionNote != "not this model" {
		t.Fatalf("a person's decision changed: %+v", fp)
	}
	if err := findingsJobs(*s.d)[0].Run(ctx); err != nil {
		t.Fatal(err)
	}
	if recs = byCVE(); len(recs) != 2 || recs["CVE-2026-1001"].Status != findings.StatusNotRelevant {
		t.Fatalf("the reconcile touched an ignored device's findings: %+v", recs)
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
	recs = byCVE()
	if r := recs["CVE-2026-1001"]; r.Status != findings.StatusSuspected || r.ResolutionNote != "" {
		t.Fatalf("the finding Ignore closed is not open again: %+v", r)
	}
	if fp := recs["CVE-2026-1002"]; fp.Status != findings.StatusFalsePositive {
		t.Fatalf("Stop ignoring reopened a person's decision: %+v", fp)
	}
	if n := pendingNotices(s); n != notices {
		t.Fatalf("ignore and stop ignoring queued %d notices", n-notices)
	}
}

// D-630: ignoring closes the device's new-device incident, naming the person; a trap hit from the ignored device still opens a
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
