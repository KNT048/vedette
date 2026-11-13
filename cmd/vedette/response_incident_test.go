package main

import (
	"database/sql"
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
	hit := func(id, src string) {
		t.Helper()
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO hp_hits (id, ts, kind, service, label, port, src_ip, is_test, excerpt, trap_ip, trap_hostname, events)
				VALUES (?, '2026-11-13T07:14:00.000Z', 'service', 'ssh', 'SSH', 22, ?, 0, '', '192.168.18.240', 'FILESRV-OLD', '[]')`, id, src)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		ev := honeypot.HitEventData{ID: id, TS: "2026-11-13T07:14:00.000Z", Kind: honeypot.KindService, Service: "ssh", Port: 22, SrcIP: src, Label: "SSH", Decoy: "FILESRV-OLD"}
		if err := s.d.Bus.Publish(ctx, events.Event{Name: honeypot.EventHitCreated, Data: ev}); err != nil {
			t.Fatal(err)
		}
	}
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
