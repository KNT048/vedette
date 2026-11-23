package main

import (
	"context"
	"database/sql"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/logs"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
	"github.com/knt048/vedette/modules/reports"
)

// review: never throw away a person's decisions: Ignore through the API (operator) closes the device's open
// findings with a readable reason and no notice; a finding a person settled keeps its status; a reconcile makes nothing new; Stop
// ignoring reopens only what Ignore closed and the device is matched again.
func TestWiringIgnoredDeviceKeepsItsFindingsAsTheyAre(t *testing.T) {
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
	if _, _, err := s.d.Findings.Handle(ctx, []string{recs["CVE-2026-1002"].ID}, findings.ResolutionFalsePositive, "not this model", time.Time{}, "it@acme.example"); err != nil {
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
	recs = byCVE() // ignoring is an attribute of the device: its findings stay as they are, and every list leaves them out
	open := recs["CVE-2026-1001"]
	if len(recs) != 2 || open.Status != findings.StatusSuspected {
		t.Fatalf("after ignore: %+v", recs)
	}
	if fp := recs["CVE-2026-1002"]; fp.Status != findings.StatusFalsePositive || fp.ResolutionNote != "not this model" {
		t.Fatalf("a person's decision changed: %+v", fp)
	}
	if err := findingsJobs(*s.d)[0].Run(ctx); err != nil {
		t.Fatal(err)
	}
	if recs = byCVE(); len(recs) != 2 || recs["CVE-2026-1001"].Status != findings.StatusSuspected {
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
		t.Fatalf("the open finding changed: %+v", r)
	}
	if fp := recs["CVE-2026-1002"]; fp.Status != findings.StatusFalsePositive {
		t.Fatalf("Stop ignoring reopened a person's decision: %+v", fp)
	}
	if n := pendingNotices(s); n != notices {
		t.Fatalf("ignore and stop ignoring queued %d notices", n-notices)
	}
}

// ignoring closes the device's new-device incident, naming the person; a trap hit from the ignored device still opens a
// Critical incident (the security exception: a staff phone touching a honeypot is what the customer must hear about).
func TestWiringIgnoredDeviceClosesItsIncidentButATrapHitStillAlerts(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.enableNotify()
	ctx := t.Context()
	const mac = "c2:31:86:3f:8c:a0" // a phone's private MAC
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

// ignoreAt records a passive sighting of a phone at ip with a private MAC, ignores it and returns its id.
func ignoreAt(t *testing.T, s *stack, ip, mac string) string {
	t.Helper()
	ctx := t.Context()
	if err := s.d.Inventory.Record(ctx, []observe.Observation{
		{AssetHint: observe.AssetHint{MAC: mac, IP: netip.MustParseAddr(ip)}, Field: observe.Hostname, Value: "staff-phone", Source: observe.Passive, Confidence: 0.7},
	}); err != nil {
		t.Fatal(err)
	}
	l, err := s.d.Inventory.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range l.Items {
		if d.MAC != nil && *d.MAC == mac {
			if err := s.d.Inventory.SetIgnored(ctx, "it@acme.example", d.ID, true); err != nil {
				t.Fatal(err)
			}
			return d.ID
		}
	}
	t.Fatalf("no device with MAC %s", mac)
	return ""
}

// Security exception (#945): a URL token opened from an ignored device goes through the honeypot module's own
// path (OpenURLToken: the hit, its source device, honeypot.hit.created) and still opens a Critical trap incident naming the device.
func TestWiringATrapHitFromAnIgnoredDeviceStillAlerts(t *testing.T) {
	t.Parallel()
	s, path := urlTokenStack(t)
	id := ignoreAt(t, s, "192.168.10.107", "c2:31:86:3f:8c:a0")
	h := tokenRouter(s, honeyTokenPerMinute)
	sameAnswer(t, "the token", open(t, h, http.MethodGet, path, "192.168.10.107:51234", "Mozilla/5.0"))
	if n := s.count(`SELECT count(*) FROM notify_incident i JOIN notify_incident_device d ON d.incident_id = i.id
		WHERE i.kind = 'trap' AND i.severity = 'critical' AND i.status <> 'resolved' AND d.asset_id = ?`, id); n != 1 {
		t.Fatalf("%d open trap incidents for the ignored device, want 1", n)
	}
}

// Security exception (#945): a log line of an ignored device that reaches a known-bad address still opens the
// intrusion-detection incident (logs.bad_address.detected through the logs module's own ingest).
func TestWiringAnIntrusionAlertFromAnIgnoredDeviceStillAlerts(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.enableNotify()
	ctx := t.Context()
	s.setModule("feeds", true)
	s.setModule("logs", true)
	id := ignoreAt(t, s, "192.168.30.7", "c2:31:86:3f:8c:a1")
	var feedID string
	if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT id FROM feeds_source ORDER BY id LIMIT 1`).Scan(&feedID); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_ioc (id, type, value, first_seen, last_seen) VALUES ('ioc-i1', 'ip', '185.220.101.47', ?1, ?1)`, stamp); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO feeds_ioc_source (ioc_id, source_id, last_seen, confidence) VALUES ('ioc-i1', ?1, ?2, 0.9)`, feedID, stamp)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var got []logs.BadAddressEvent
	s.d.Bus.Subscribe(logs.EventBadAddress, func(_ context.Context, e events.Event) error {
		got = append(got, e.Data.(logs.BadAddressEvent))
		return nil
	})
	svc := logsService(*s.d)
	src, err := svc.AddSource(ctx, "admin@acme.example", logs.Input{Kind: "fortigate", Name: "FW-HQ", SenderIP: "192.168.30.1", Proto: "udp", Port: 514})
	if err != nil {
		t.Fatal(err)
	}
	line := `date=2026-11-09 time=10:20:00 devname="FW-HQ" logid="0000000013" type="traffic" subtype="forward" srcip=192.168.30.7 dstip=185.220.101.47 dstport=443 action="accept"`
	if res, err := svc.Ingest(ctx, []logs.Line{{SourceID: src.ID, At: time.Now(), Text: line}}); err != nil || res.Stored != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if len(got) != 1 {
		t.Fatalf("bad-address events = %+v, want 1 for the ignored device", got)
	}
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE kind = 'bad_address' AND status <> 'resolved'`); n != 1 {
		t.Fatalf("%d open intrusion incidents, want 1", n)
	}
	if d, err := s.d.Inventory.Device(ctx, id); err != nil || d.IgnoredAt == nil {
		t.Fatalf("the device is no longer ignored: %+v %v", d.AssetCore, err)
	}
}

// The reports leave an ignored device out with its findings: no row named by an id, no "resolved" for
// Ignore's closes, no "new this week".
func TestWiringReportsLeaveAnIgnoredDeviceAndItsFindingsOut(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.kev("CVE-2026-1001", "Fortinet", "FortiOS")
	id := s.addFortiGate()
	if n := s.nf(id, ""); n != 1 {
		t.Fatalf("findings = %d", n)
	}
	in := reportsFindings{s.d.Findings}
	all, err := in.All(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("before: %+v %v", all, err)
	}
	if err := s.d.Inventory.SetIgnored(ctx, "it@acme.example", id, true); err != nil {
		t.Fatal(err)
	}
	if all, err = in.All(ctx); err != nil || len(all) != 0 {
		t.Fatalf("an ignored device's findings reach the reports: %+v %v", all, err)
	}
	if vs, err := (reportsViews{s.d.Findings}).Views(ctx); err != nil || len(vs) != 0 {
		t.Fatalf("an ignored device's findings reach the periodic report: %+v %v", vs, err)
	}
	if devs, err := (reportsInventory{s.d.Inventory}).Devices(ctx); err != nil || slices.ContainsFunc(devs, func(d reports.Device) bool { return d.ID == id }) {
		t.Fatalf("an ignored device reaches the reports: %v", err)
	}
	if err := s.d.Inventory.SetIgnored(ctx, "it@acme.example", id, false); err != nil {
		t.Fatal(err)
	}
	if all, err = in.All(ctx); err != nil || len(all) != 1 || all[0].Status != "suspected" {
		t.Fatalf("after stop ignoring: %+v %v", all, err)
	}
}
