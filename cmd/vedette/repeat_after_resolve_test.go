package main

import (
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/logs"
	"github.com/knt048/vedette/modules/notify"
)

// A person resolves an incident while the attack goes on, on the real wiring (logs -> ids -> notify, and logs -> notify): the same IPS
// line after the resolve, inside the ids module's hourly announcement dedupe, opens a new intrusion incident and queues its message;
// the same holds for failed logins inside the logs module's dedupe time. While the new incident is open, repeats only count.
func TestWiringARepeatAfterAResolveOpensANewIncidentAndAlerts(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Date(2026, 11, 24, 8, 30, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	s := newStackWith(t, func(d *deps) { d.Clock = clock })
	s.enableNotify()
	s.telegramOn()
	ctx := t.Context()
	s.setModule("logs", true)
	s.setModule("ids", true)
	lsvc := logsService(*s.d)
	fw, err := lsvc.AddSource(ctx, "admin@acme.example", logs.Input{Kind: "fortigate", Name: "FW-HQ", SenderIP: "10.0.10.1", Proto: "udp", Port: 514})
	if err != nil {
		t.Fatal(err)
	}
	ips := `<185>date=2026-11-24 time=08:30:00 devname="FW-HQ" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" severity="high" srcip=198.51.100.23 dstip=10.0.10.67 action="dropped" proto=6 service="HTTPS" attack="VMware.ESXi.Heap.Overflow" srcport=44312 dstport=443 attackid=52976 cve="CVE-2025-22224"`
	attack := func() {
		t.Helper()
		if _, err := lsvc.Ingest(ctx, []logs.Line{{SourceID: fw.ID, At: clock(), Text: ips}}); err != nil {
			t.Fatal(err)
		}
		if err := idsService(*s.d).Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	nf := newNotify(s.d)
	// every intrusion alert sends here (the default sends from high): the test is about the repeat, not the trigger
	if _, err := nf.SaveTriggers(ctx, "admin@acme.example", []notify.Trigger{{ID: "intrusion", On: true, Min: notify.Low}}); err != nil {
		t.Fatal(err)
	}
	resolveAll := func(kind string) {
		t.Helper()
		var ids []string
		rows, err := s.d.DB.Reader().QueryContext(ctx, `SELECT id FROM notify_incident WHERE kind = ? AND status <> 'resolved'`, kind)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		_ = rows.Close()
		if len(ids) != 1 {
			t.Fatalf("%d open %s incidents to resolve, want 1", len(ids), kind)
		}
		advance(5 * time.Second)
		if _, err := nf.HandleIncident(ctx, "admin@acme.example", ids[0], notify.StatusResolved, ""); err != nil {
			t.Fatal(err)
		}
		advance(5 * time.Second)
	}

	attack()
	advance(5 * time.Second)
	attack()
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE kind = 'intrusion'`); n != 1 {
		t.Fatalf("%d intrusion incidents while the first is open, want 1", n)
	}
	resolveAll("intrusion")
	attack()
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE kind = 'intrusion'`); n != 2 {
		t.Fatalf("%d intrusion incidents after the resolve, want a new one", n)
	}
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE kind = 'intrusion' AND status = 'new'`); n != 1 {
		t.Fatalf("%d new intrusion incidents, want the one the repeat opened", n)
	}
	if n := s.count(`SELECT count(*) FROM notify_pending WHERE notice_id IN (SELECT id FROM notify_incident WHERE kind = 'intrusion')`); n != 2 {
		t.Fatalf("%d intrusion messages queued, want one per incident", n)
	}
	advance(5 * time.Second)
	attack()
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE kind = 'intrusion'`); n != 2 {
		t.Fatalf("%d intrusion incidents while the new one is open, want 2", n)
	}
	if n := s.count(`SELECT sum(count) FROM ids_alert`); n != 4 {
		t.Fatalf("%d IPS events counted, want 4", n)
	}

	web, err := lsvc.AddSource(ctx, "admin@acme.example", logs.Input{Kind: "syslog-generic", Name: "Web-server", SenderIP: "10.0.10.200", Proto: "udp", Port: 514})
	if err != nil {
		t.Fatal(err)
	}
	fail := func(n int) {
		t.Helper()
		var ls []logs.Line
		for range n {
			ls = append(ls, logs.Line{SourceID: web.ID, At: clock(), Text: "<38>Nov 24 08:31:00 web1 sshd[123]: Failed password for invalid user admin from 203.0.113.9 port 41022 ssh2"})
		}
		if _, err := lsvc.Ingest(ctx, ls); err != nil {
			t.Fatal(err)
		}
	}
	authIncidents := func() int {
		return s.count(`SELECT count(*) FROM notify_incident WHERE kind = 'log_anomaly' AND title LIKE '%failed logins from 203.0.113.9%'`)
	}
	fail(logs.AuthFailThreshold)
	advance(5 * time.Second)
	fail(1)
	if n := authIncidents(); n != 1 {
		t.Fatalf("%d failed-login incidents while the first is open, want 1", n)
	}
	resolveAll("log_anomaly")
	fail(1)
	if n := authIncidents(); n != 2 {
		t.Fatalf("%d failed-login incidents after the resolve, want a new one", n)
	}
}
