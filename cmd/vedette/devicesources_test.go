package main

import (
	"database/sql"
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
)

// #849: the Devices list says "wazuh" for a device at an address the saved Wazuh connection delivered to, through the real wiring
// (inventory Config.WazuhAgents → agent-intake's intake_wazuh_agent); the source: filter finds it.
func TestDevicesListSaysWazuhThroughTheWiring(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	if !s.d.Reg.Enabled("agent-intake") {
		s.setModule("agent-intake", true)
	}
	ctx := t.Context()
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO core_secret (id, purpose, nonce, ciphertext, key_version, created_at) VALUES ('sec-wz', 'intake_wazuh.password', zeroblob(12), zeroblob(16), 1, '2026-11-16T08:00:00.000Z')`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO intake_wazuh (id, url, username, secret_id, password_last4, tls_pin, tls_pin_first_seen, next_pull, updated_at)
			VALUES (1, 'https://wazuh.example:55000', 'vedette', 'sec-wz', '', 'system', '2026-11-16T08:00:00.000Z', '2026-11-16T09:00:00.000Z', '2026-11-16T08:00:00.000Z')`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO intake_wazuh_agent (agent_id, generation, ip, mac, seen_at) VALUES ('001', 1, '192.168.10.30', '', '2026-11-16T08:00:00.000Z')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"192.168.10.30", "192.168.10.31"} { // .31 is an agent device Wazuh did not deliver to
		if err := s.d.Inventory.Record(ctx, []observe.Observation{{AssetHint: observe.AssetHint{IP: netip.MustParseAddr(ip)}, Field: observe.Hostname, Value: "files-" + ip[len(ip)-2:], Source: observe.Agent, Confidence: 1}}); err != nil {
			t.Fatal(err)
		}
	}
	code, v := s.do("GET", "/inventory/devices?source=wazuh", "viewer", "")
	items, _ := v["items"].([]any)
	if code != 200 || len(items) != 1 {
		t.Fatalf("source=wazuh: %d %v", code, v)
	}
	d := items[0].(map[string]any)
	if src, _ := d["sources"].([]any); d["ip"] != "192.168.10.30" || len(src) != 1 || src[0] != "wazuh" {
		t.Fatalf("device %v", d)
	}
}

// The device page's agent row through the real wiring: a token made for the device is shown under Show setup before any agent reads
// it (its details to administrators only: the tokens list is theirs), the token follows the device through a merge and is let go when
// the device is deleted, and the person's agent switch turns the row off and stops "I updated it" for the device.
func TestDeviceSourcesAgentRowThroughTheWiring(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	if !s.d.Reg.Enabled("agent-intake") {
		s.setModule("agent-intake", true)
	}
	ctx := t.Context()
	idAt := func(ip string) string {
		t.Helper()
		if err := s.d.Inventory.Record(ctx, []observe.Observation{{AssetHint: observe.AssetHint{IP: netip.MustParseAddr(ip)}, Field: observe.Hostname, Value: "files-" + ip[len(ip)-2:], Source: observe.Nmap, Confidence: 0.7}}); err != nil {
			t.Fatal(err)
		}
		l, err := s.d.Inventory.Devices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range l.Items {
			if d.IP == ip {
				return d.ID
			}
		}
		t.Fatalf("no device at %s", ip)
		return ""
	}
	id, other := idAt("192.0.2.40"), idAt("192.0.2.41")
	agentRow := func(role string) map[string]any {
		t.Helper()
		code, v := s.do("GET", "/inventory/devices/"+id+"/sources", role, "")
		rows, _ := v["rows"].([]any)
		if code != 200 || len(rows) != 3 {
			t.Fatalf("sources as %s: %d %v", role, code, v)
		}
		return rows[2].(map[string]any)
	}
	if r := agentRow("admin"); r["state"] != "none" || r["action"] != "create_token" || r["token"] != nil {
		t.Fatalf("no agent: %v", r)
	}
	code, v := s.do("POST", "/inventory/agents/tokens", "admin", `{"name":"files-40","device_id":"`+id+`"}`)
	tok, _ := v["token"].(map[string]any)
	if code != 201 || tok == nil {
		t.Fatalf("token for the device: %d %v", code, v)
	}
	r := agentRow("admin")
	shown, _ := r["token"].(map[string]any)
	if r["state"] != "waiting" || r["action"] != "show_setup" || shown == nil || shown["id"] != tok["id"] || shown["last4"] != tok["last4"] || shown["device_id"] != id {
		t.Fatalf("a token made for the device, as an administrator: %v", r)
	}
	for _, role := range []string{"viewer", "operator"} {
		if r := agentRow(role); r["state"] != "waiting" || r["action"] != "show_setup" || r["token"] != nil {
			t.Fatalf("a token made for the device, as %s: %v", role, r)
		}
	}
	tokenDevice := func(id string) string {
		t.Helper()
		var dev sql.NullString
		if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT device_id FROM intake_agent_tokens WHERE id = ?`, id).Scan(&dev); err != nil {
			t.Fatal(err)
		}
		return dev.String
	}
	// a token made for the other row follows it into this device when a person merges the two, and is let go when it is deleted
	_, v = s.do("POST", "/inventory/agents/tokens", "admin", `{"name":"files-41","device_id":"`+other+`"}`)
	otherTok, _ := v["token"].(map[string]any)
	if code, v := s.do("POST", "/inventory/devices/"+id+"/merge", "admin", `{"from":"`+other+`"}`); code != 200 {
		t.Fatalf("merge: %d %v", code, v)
	}
	if got := tokenDevice(otherTok["id"].(string)); got != id {
		t.Fatalf("the merged row's token names %q, want the kept device", got)
	}

	if code, v := s.do("PUT", "/inventory/devices/"+id+"/sources", "admin", `{"agent":"off"}`); code != 200 || v["agent_source"] != "off" {
		t.Fatalf("agent off: %d %v", code, v)
	}
	if r := agentRow("viewer"); r["state"] != "off" || r["switch"] != "off" || r["dot"] != "grey" {
		t.Fatalf("agent off: %v", r)
	}
	if code, v := s.do("GET", "/inventory/agents/devices/"+id+"/report", "viewer", ""); code != 200 || v["off"] != true {
		t.Fatalf("report of a device whose agent is off: %d %v", code, v)
	}
	if code, v := s.do("DELETE", "/inventory/devices/"+id, "admin", ""); code != 204 && code != 200 {
		t.Fatalf("delete: %d %v", code, v)
	}
	if got := tokenDevice(tok["id"].(string)); got != "" {
		t.Fatalf("the deleted device's token still names it: %q", got)
	}
}
