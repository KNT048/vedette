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
		if _, err := tx.ExecContext(ctx, `INSERT INTO intake_wazuh (id, url, username, secret_id, password_last4, interval_minutes, tls_pin, tls_pin_first_seen, next_pull, updated_at)
			VALUES (1, 'https://wazuh.example:55000', 'vedette', 'sec-wz', '', 60, 'system', '2026-11-16T08:00:00.000Z', '2026-11-16T09:00:00.000Z', '2026-11-16T08:00:00.000Z')`); err != nil {
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
