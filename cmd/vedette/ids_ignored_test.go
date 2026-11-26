package main

import (
	"testing"
	"time"

	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/logs"
)

// An IPS event aimed at an ignored device, through the real logs -> ids -> notify path (test addresses: 10.0.10.x devices,
// 198.51.100.x attacker): the device keeps its open finding of the CVE the event names, but a person chose not to watch it, so the
// finding does not make the alert or its incident critical, the alert lists no finding of it, the overview counts no affected alert,
// and no rise of the finding is told. The same event at a watched device is critical (TestWiringFirewallIPSEventRaisesAnIntrusionIncidentAndTheFindingIsUnderAttack).
func TestWiringIPSEventAtAnIgnoredDeviceIsNotCriticalOrAffected(t *testing.T) {
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
	dev := r.ID
	if s.nf(dev, "CVE-2026-1001") != 1 {
		t.Fatal("the test needs the device's finding")
	}
	if err := s.d.Inventory.SetIgnored(ctx, "it@acme.example", dev, true); err != nil {
		t.Fatal(err)
	}
	layer := s.count(`SELECT urgency FROM fnd_finding WHERE asset_id = ? AND cve = 'CVE-2026-1001'`, dev)
	notices := len(s.queuedNotices())

	lsvc := logsService(*s.d)
	src, err := lsvc.AddSource(ctx, "admin@acme.example", logs.Input{Kind: "fortigate", Name: "FW-HQ", SenderIP: "10.0.10.254", Proto: "udp", Port: 514})
	if err != nil {
		t.Fatal(err)
	}
	line := logs.Line{SourceID: src.ID, At: time.Now().UTC(), Text: `<185>date=2026-11-20 time=10:15:22 devname="FW-HQ" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" severity="high" srcip=198.51.100.23 dstip=10.0.10.1 action="dropped" proto=6 service="HTTPS" attack="FortiOS.SSL.VPN.Heap.Buffer.Overflow" srcport=44312 dstport=10443 attackid=52976 msg="misc: FortiOS.SSL.VPN.Heap.Buffer.Overflow" cve="CVE-2026-1001"`}
	if _, err := lsvc.Ingest(ctx, []logs.Line{line}); err != nil {
		t.Fatal(err)
	}
	if err := idsService(*s.d).Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.d.Findings.RateUrgency(ctx, ""); err != nil { // the pass an alert triggers, run here so the check below is not early
		t.Fatal(err)
	}

	code, list := s.do("GET", "/detection/alerts?window=24h&device="+dev, "viewer", "")
	if code != 200 || at(list, "total") != float64(1) {
		t.Fatalf("GET /detection/alerts: %d %v", code, list)
	}
	a := at(list, "items", 0)
	if at(a, "severity") == "critical" {
		t.Errorf("an alert at an ignored device is critical: %v", a)
	}
	if fs, _ := at(a, "findings").([]any); len(fs) != 0 {
		t.Errorf("the alert lists the ignored device's findings: %v", fs)
	}
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE kind = 'intrusion'`); n != 1 {
		t.Fatalf("%d intrusion incidents, want 1", n)
	}
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE kind = 'intrusion' AND severity = 'critical'`); n != 0 {
		t.Error("the intrusion incident of an ignored device is critical")
	}
	code, ov := s.do("GET", "/detection/overview", "viewer", "")
	if code != 200 || at(ov, "alerts", "total") != float64(1) || at(ov, "alerts", "affected") != float64(0) {
		t.Errorf("overview alerts: %d %v", code, at(ov, "alerts"))
	}
	if got := s.count(`SELECT urgency FROM fnd_finding WHERE asset_id = ? AND cve = 'CVE-2026-1001'`, dev); got != layer {
		t.Errorf("the ignored device's finding moved from layer %d to %d", layer, got)
	}
	if n := s.count(`SELECT count(*) FROM notify_pending WHERE notice_id LIKE '%-raised-critical'`); n != 0 {
		t.Error("a raise to critical was queued")
	}
	// no rise of the finding, and the incident itself is below high, where the intrusion trigger sends from by default
	if n := len(s.queuedNotices()) - notices; n != 0 {
		t.Errorf("%d notices queued, want none", n)
	}
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE kind = 'intrusion' AND severity <> 'critical' AND unsent = 'trigger_off'`); n != 1 {
		t.Error("the intrusion incident does not say its trigger held it back")
	}
}
