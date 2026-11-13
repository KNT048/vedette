package main

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/honeypot"
)

// D-509 (W1-16): Respond on a trap incident reads the incident through notify and the source of its hit through honeypot, through the
// generated HTTP handlers, and a public source can be asked for the block list as a pending request.
func TestResponseIncidentRespondReadsTheTrapSource(t *testing.T) {
	t.Parallel()
	s := responseOn(t)
	ctx := t.Context()
	exec := func(q string, args ...any) {
		t.Helper()
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	// store: none (the hit is gone), "real", "test"; kind: service or scan. The event is what notify opens the incident from.
	hitAt := func(id, src, kind, store, ts string) {
		t.Helper()
		if store != "none" {
			svc, port := any("ssh"), any(22)
			if kind == "scan" {
				svc, port = nil, nil
			}
			exec(`INSERT INTO hp_hits (id, ts, kind, service, label, port, src_ip, is_test, excerpt, trap_ip, trap_hostname, events)
				VALUES (?, ?, ?, ?, 'SSH', ?, ?, ?, '', '192.168.18.240', 'FILESRV-OLD', '[]')`, id, ts, kind, svc, port, src, store == "test")
		}
		ev := honeypot.HitEventData{ID: id, TS: ts, Kind: honeypot.HitKind(kind), Service: "ssh", Port: 22, SrcIP: src, Label: "SSH", Decoy: "FILESRV-OLD"}
		if err := s.d.Bus.Publish(ctx, events.Event{Name: honeypot.EventHitCreated, Data: ev}); err != nil {
			t.Fatal(err)
		}
	}
	hit := func(id, src string) { t.Helper(); hitAt(id, src, "service", "real", "2026-11-13T07:14:00.000Z") }
	hit("hit-pub", "203.0.113.9")
	pub := incidentOf(s, "203.0.113.9")
	c, v := s.do("GET", "/response/incidents/"+pub, "viewer", "")
	src, _ := v["source"].(map[string]any)
	if c != 200 || src["ip"] != "203.0.113.9" || src["scope"] != "public" {
		t.Fatalf("panel: %d %v", c, v)
	}
	if c, v := s.do("POST", "/response/incidents/"+pub+"/request", "operator", `{"action_id":"blocklist_add"}`); c != 201 || v["source"] != "person" || v["status"] != "pending" || v["proposal_id"] != "incident:"+pub {
		t.Fatalf("ask: %d %v", c, v)
	}
	hit("hit-lan", "192.168.18.145")
	lan := incidentOf(s, "192.168.18.145")
	_, v = s.do("GET", "/response/incidents/"+lan, "viewer", "")
	if src, _ := v["source"].(map[string]any); src["scope"] != "lan" || len(v["options"].([]any)) != 0 {
		t.Fatalf("LAN panel: %v", v)
	}
	if c, v := s.do("POST", "/response/incidents/"+lan+"/request", "operator", `{"action_id":"blocklist_add"}`); c != 403 || v["error"].(map[string]any)["code"] != "tool_not_allowed" {
		t.Fatalf("LAN block list: %d %v", c, v)
	}
	if c, _ := s.do("GET", "/response/incidents/in-nope", "viewer", ""); c != 404 {
		t.Fatalf("unknown incident: %d", c)
	}

	// A test hit and a hit that is gone name no source.
	hitAt("hit-test", "192.168.18.160", "service", "test", "2026-11-13T07:14:00.000Z")
	hitAt("hit-gone", "192.168.18.161", "service", "none", "2026-11-13T07:14:00.000Z")
	for _, src := range []string{"192.168.18.160", "192.168.18.161"} {
		if _, v := s.do("GET", "/response/incidents/"+incidentOf(s, src), "viewer", ""); v["source"] != nil {
			t.Errorf("%s: a source from a test or missing hit: %v", src, v)
		}
	}

	// A scan of attempts only: its source may be forged. A service hit of the same source within the hour confirms it.
	hitAt("hit-scan", "192.168.18.170", "scan", "real", "2026-11-13T07:20:00.000Z")
	scan := incidentOf(s, "192.168.18.170")
	if _, v := s.do("GET", "/response/incidents/"+scan, "viewer", ""); v["note"] == nil || !strings.Contains(v["note"].(string), "forged") {
		t.Fatalf("unconfirmed scan: %v", v)
	}
	exec(`INSERT INTO hp_hits (id, ts, kind, service, label, port, src_ip, is_test, excerpt, trap_ip, trap_hostname, events)
		VALUES ('hit-scan-conn', '2026-11-13T07:50:00.000Z', 'service', 'smb', 'SMB', 445, '192.168.18.170', 0, '', '192.168.18.241', 'NAS', '[]')`)
	if _, v := s.do("GET", "/response/incidents/"+scan, "viewer", ""); v["note"] != nil {
		t.Fatalf("a scan whose source completed a connection is still unconfirmed: %v", v)
	}

	// A source that is one of the box's decoys is never-touch through the real BoxAddrs (the honeypot's applied Trap IPs).
	exec(`INSERT INTO hp_config (key, value, updated_at, updated_by) VALUES ('applied', '["192.168.18.240"]', '2026-11-13T07:00:00.000Z', 'system')`)
	if c, v := s.do("PUT", "/response/catalog/fgt_addrgrp_add", "admin", `{"enabled":true}`); c != 200 {
		t.Fatalf("enable the action: %d %v", c, v)
	}
	hit("hit-decoy", "192.168.18.240")
	_, v = s.do("GET", "/response/incidents/"+incidentOf(s, "192.168.18.240"), "viewer", "")
	opts, _ := v["options"].([]any)
	if len(opts) != 1 || !strings.Contains(fmt.Sprint(opts[0].(map[string]any)["why"]), "matches the never-touch list (This Vedette box, 192.168.18.240)") {
		t.Fatalf("decoy source: %v", v)
	}
}

// incidentOf is the id of the open incident whose title starts with the address (notify opened it from the hit event).
func incidentOf(s *stack, src string) string {
	s.t.Helper()
	_, v := s.do("GET", "/notify/incidents", "admin", "")
	for _, x := range v["incidents"].([]any) {
		if m := x.(map[string]any); strings.HasPrefix(m["title"].(string), src+" ") {
			return m["id"].(string)
		}
	}
	s.t.Fatalf("no incident for %s: %v", src, v)
	return ""
}
