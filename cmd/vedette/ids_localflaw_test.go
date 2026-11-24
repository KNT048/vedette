package main

import (
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/logs"
)

// An IPS event naming a CVE that needs local access (CVSS AV:L) at a device with an open finding of it, through the real
// logs -> ids -> notify path (test addresses: 10.0.10.x devices, 198.51.100.x attacker): network traffic can carry such an exploit but
// cannot be its exploitation, so the alert and its incident keep the rule's own severity, the overview counts no affected alert, and
// the finding is not raised to under attack here. The same event for a network flaw is critical
// (TestWiringFirewallIPSEventRaisesAnIntrusionIncidentAndTheFindingIsUnderAttack).
func TestWiringIPSEventNamingALocalOnlyFlawIsNotCriticalOrAffected(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.enableNotify()
	s.telegramOn()
	ctx := t.Context()
	s.setModule("logs", true)
	s.setModule("ids", true)
	s.kev("CVE-2026-1001", "Fortinet", "FortiOS")
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		now := store.FormatTS(time.Now().UTC())
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve (cve, updated_at) VALUES ('CVE-2026-1001', ?) ON CONFLICT(cve) DO NOTHING`, now); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_metric (cve, source, version, score, vector) VALUES ('CVE-2026-1001', 'nvd', '3.1', 8.2, 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", IP: "10.0.10.1"})
	if err != nil {
		t.Fatal(err)
	}
	dev := r.ID
	if s.nf(dev, "CVE-2026-1001") != 1 {
		t.Fatal("the test needs the device's finding")
	}

	lsvc := logsService(*s.d)
	src, err := lsvc.AddSource(ctx, "admin@acme.example", logs.Input{Kind: "fortigate", Name: "FW-HQ", SenderIP: "10.0.10.254", Proto: "udp", Port: 514})
	if err != nil {
		t.Fatal(err)
	}
	line := logs.Line{SourceID: src.ID, At: time.Now().UTC(), Text: `<185>date=2026-11-20 time=10:15:22 devname="FW-HQ" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" severity="high" srcip=198.51.100.23 dstip=10.0.10.1 action="dropped" proto=6 service="HTTPS" attack="Linux.Kernel.skbuff.Overflow" srcport=44312 dstport=10443 attackid=52976 msg="misc: Linux.Kernel.skbuff.Overflow" cve="CVE-2026-1001"`}
	if _, err := lsvc.Ingest(ctx, []logs.Line{line}); err != nil {
		t.Fatal(err)
	}
	if err := idsService(*s.d).Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.d.Findings.RateUrgency(ctx, ""); err != nil {
		t.Fatal(err)
	}

	code, list := s.do("GET", "/detection/alerts?window=24h&device="+dev, "viewer", "")
	if code != 200 || at(list, "total") != float64(1) {
		t.Fatalf("GET /detection/alerts: %d %v", code, list)
	}
	if a := at(list, "items", 0); at(a, "severity") == "critical" {
		t.Errorf("an alert naming a local-only flaw is critical: %v", a)
	}
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE kind = 'intrusion' AND severity = 'critical'`); n != 0 {
		t.Error("the intrusion incident of a local-only flaw is critical")
	}
	code, ov := s.do("GET", "/detection/overview", "viewer", "")
	if code != 200 || at(ov, "alerts", "affected") != float64(0) {
		t.Errorf("overview alerts: %d %v", code, at(ov, "alerts"))
	}
	if got := s.count(`SELECT urgency FROM fnd_finding WHERE asset_id = ? AND cve = 'CVE-2026-1001'`, dev); got == 1 {
		t.Error("the local-only finding is under attack here")
	}
}
