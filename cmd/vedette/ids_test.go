package main

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/logs"
)

// An IPS event in a received firewall log, on the real wiring (test addresses: 10.0.10.x devices, 198.51.100.x attackers): the logs module stores the line and hands it to the ids module, whose
// flush stores the alert and announces it; notify opens an intrusion incident. The alert names a CVE the attacked device is affected by
// (an open finding), so the alert is critical, its finding is under attack and the incident is critical. An event naming no CVE is an
// alert of its rule. The overview reports the IPS watcher and the alerts; with the module off its routes are gone and the overview says
// it is off.
func TestWiringFirewallIPSEventRaisesAnIntrusionIncidentAndTheFindingIsUnderAttack(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.enableNotify()
	s.telegramOn()
	ctx := t.Context()
	s.setModule("logs", true)
	s.setModule("ids", true)
	s.kev("CVE-2026-1001", "Fortinet", "FortiOS")
	r, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", IP: "10.0.10.1"})
	if err != nil {
		t.Fatal(err)
	}
	dev := r.ID // FortiOS 7.2.5: affected by CVE-2026-1001
	if s.nf(dev, "CVE-2026-1001") != 1 {
		t.Fatal("the test needs the device's finding")
	}
	lsvc := logsService(*s.d)
	src, err := lsvc.AddSource(ctx, "admin@acme.example", logs.Input{Kind: "fortigate", Name: "FW-HQ", SenderIP: "10.0.10.1", Proto: "udp", Port: 514})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lines := []logs.Line{
		{SourceID: src.ID, At: now, Text: `<185>date=2026-11-20 time=10:15:22 devname="FW-HQ" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" severity="high" srcip=198.51.100.23 dstip=10.0.10.1 action="dropped" proto=6 service="HTTPS" attack="FortiOS.SSL.VPN.Heap.Buffer.Overflow" srcport=44312 dstport=10443 attackid=52976 msg="misc: FortiOS.SSL.VPN.Heap.Buffer.Overflow" cve="CVE-2026-1001"`},
		{SourceID: src.ID, At: now, Text: `<185>date=2026-11-20 time=10:15:23 devname="FW-HQ" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" severity="medium" srcip=198.51.100.24 dstip=10.0.10.80 action="detected" proto=6 service="HTTP" attack="Nmap.Script.Scanner" srcport=50000 dstport=80 attackid=19100 msg="scanner: Nmap.Script.Scanner"`},
		{SourceID: src.ID, At: now, Text: `<189>date=2026-11-20 time=10:15:24 devname="FW-HQ" logid="0000000013" type="traffic" subtype="forward" srcip=10.0.10.30 dstip=192.0.2.80 dstport=443 proto=6 action="accept"`},
	}
	// The attacker first fires the CVE's rule at an address no device has: the incident opens at the rule's level (medium).
	first := logs.Line{SourceID: src.ID, At: now.Add(-time.Minute), Text: strings.Replace(lines[0].Text, "dstip=10.0.10.1", "dstip=10.0.10.90", 1)}
	if _, err := lsvc.Ingest(ctx, []logs.Line{first}); err != nil {
		t.Fatal(err)
	}
	if err := idsService(*s.d).Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE kind = 'intrusion' AND severity = 'medium'`); n != 1 {
		t.Fatalf("%d medium intrusion incidents after the first attack, want 1", n)
	}
	// Then at the affected device (and a rule with no CVE elsewhere): the same incident is raised to critical, with a notice of the raise.
	if _, err := lsvc.Ingest(ctx, lines); err != nil {
		t.Fatal(err)
	}
	if err := idsService(*s.d).Flush(ctx); err != nil {
		t.Fatal(err)
	}

	code, list := s.do("GET", "/detection/alerts?window=24h&sort=last", "viewer", "")
	if code != 200 || at(list, "total") != float64(3) {
		t.Fatalf("GET /detection/alerts: %d %v", code, list)
	}
	// The rating pass an intrusion alert triggers runs in the background: wait until it has stored the finding's layer.
	var one map[string]any
	waitUntil(t, func() bool {
		code, one = s.do("GET", "/detection/alerts?window=24h&cve=CVE-2026-1001&device="+dev, "viewer", "")
		return code == 200 && at(one, "items", 0, "findings", 0, "status") == "under_attack"
	})
	if code != 200 || at(one, "total") != float64(1) {
		t.Fatalf("by CVE and device: %d %v", code, one)
	}
	a := at(one, "items", 0)
	if at(a, "severity") != "critical" || at(a, "dst_device", "id") != dev || at(a, "sid") != float64(52976) || at(a, "dst_port") != float64(10443) {
		t.Errorf("alert %v", a)
	}
	if at(a, "findings", 0, "cve") != "CVE-2026-1001" || at(a, "findings", 0, "status") != "under_attack" || at(a, "findings", 0, "device", "id") != dev {
		t.Errorf("linked finding %v", at(a, "findings"))
	}
	incID, _ := at(a, "incident", "id").(string)
	if incID == "" || at(a, "incident", "status") != "new" {
		t.Fatalf("incident %v", at(a, "incident"))
	}
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE kind = 'intrusion'`); n != 2 {
		t.Fatalf("%d intrusion incidents, want 2", n)
	}
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE id = ? AND kind = 'intrusion' AND severity = 'critical' AND link LIKE '/detection/alerts/ida-%'`, incID); n != 1 {
		t.Fatalf("the incident of the alert is not a critical intrusion incident linking to its alert")
	}
	if n := s.count(`SELECT count(*) FROM notify_pending WHERE notice_id = ?`, incID+"-raised-critical"); n != 1 {
		t.Fatal("no notice of the raise to critical")
	}
	if n := s.count(`SELECT count(*) FROM notify_pending WHERE notice_id = ?`, incID); n != 1 {
		t.Fatal("the first notice of the incident was not queued")
	}
	if code, b := s.do("GET", "/detection/alerts/"+at(a, "id").(string), "viewer", ""); code != 200 || at(b, "incident", "id") != incID {
		t.Fatalf("GET one alert: %d %v", code, b)
	}
	// a repeat in the same hour counts on the same alert and the same incident
	if _, err := lsvc.Ingest(ctx, lines[:1]); err != nil {
		t.Fatal(err)
	}
	if err := idsService(*s.d).Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if n := s.count(`SELECT count(*) FROM ids_alert`); n != 3 {
		t.Fatalf("%d alerts after a repeat", n)
	}
	if n := s.count(`SELECT count FROM ids_alert WHERE dst_ip = '10.0.10.1'`); n != 2 {
		t.Fatalf("alert count %d after a repeat", n)
	}
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE kind = 'intrusion'`); n != 2 {
		t.Fatalf("%d intrusion incidents after a repeat, want 2", n)
	}

	code, ov := s.do("GET", "/detection/overview", "viewer", "")
	if code != 200 {
		t.Fatalf("GET /detection/overview: %d %v", code, ov)
	}
	if at(ov, "alerts", "total") != float64(3) || at(ov, "alerts", "affected") != float64(1) {
		t.Errorf("overview alerts %v", at(ov, "alerts"))
	}
	if at(ov, "watchers", 3, "id") != "ips_events" || at(ov, "watchers", 3, "state") != "watching" || at(ov, "watchers", 3, "detections_7d") != float64(3) {
		t.Errorf("IPS watcher %v", at(ov, "watchers", 3))
	}
	if at(ov, "watchers", 1, "id") != "logs" || at(ov, "watchers", 1, "state") != "watching" {
		t.Errorf("logs watcher %v", at(ov, "watchers", 1))
	}
	if at(ov, "kinds", 4, "kind") != "intrusion" || at(ov, "kinds", 4, "incidents") != float64(2) || at(ov, "kinds", 4, "new") != float64(2) {
		t.Errorf("intrusion kind %v", at(ov, "kinds", 4))
	}

	s.setModule("ids", false)
	if code, _ := s.do("GET", "/detection/alerts?window=24h", "viewer", ""); code != 404 {
		t.Fatalf("alerts with the module off: %d", code)
	}
	code, ov = s.do("GET", "/detection/overview", "viewer", "")
	if code != 200 || at(ov, "watchers", 3, "state") != "off" || at(ov, "watchers", 3, "action") != "turn_on" || at(ov, "alerts", "total") != float64(0) {
		t.Fatalf("overview with ids off: %d %v", code, ov)
	}
	// lines received while the module is off are not read, then or later
	if _, err := lsvc.Ingest(ctx, lines[1:2]); err != nil {
		t.Fatal(err)
	}
	s.setModule("ids", true)
	if err := idsService(*s.d).Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if n := s.count(`SELECT sum(count) FROM ids_alert`); n != 4 {
		t.Fatalf("events %d, want 4: a line received while off was read", n)
	}
}

// The overview never fails as a whole: with Logs off the IPS watcher says that Logs is what is missing, and a watcher whose module
// cannot be read says failed while the others still answer.
func TestDetectionOverviewSaysLogsIsOffAndDegradesOnReadErrors(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.enableNotify()
	s.setModule("logs", true)
	s.setModule("ids", true)
	s.setModule("logs", false) // allowed: ids stays on and is listed as affected
	code, ov := s.do("GET", "/detection/overview", "viewer", "")
	if code != 200 || at(ov, "watchers", 3, "state") != "not_set_up" || at(ov, "watchers", 3, "action") != "set_up" ||
		!strings.Contains(at(ov, "watchers", 3, "detail").(string), "The Logs module is off") {
		t.Fatalf("IPS watcher with Logs off: %d %v", code, at(ov, "watchers", 3))
	}
	s.setModule("logs", true)
	s.exec(`DROP TABLE ids_alert_cve`)
	s.exec(`DROP TABLE ids_alert`)
	s.exec(`DROP TABLE logs_sources`)
	code, ov = s.do("GET", "/detection/overview", "viewer", "")
	if code != 200 || at(ov, "watchers", 1, "state") != "failed" || at(ov, "watchers", 3, "state") != "failed" || at(ov, "alerts", "total") != float64(0) {
		t.Fatalf("overview with unreadable logs and alerts: %d %v", code, ov)
	}
}
