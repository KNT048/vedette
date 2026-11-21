package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/knt048/vedette/core/secrets"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// The Sources page through the real wiring: a firewall found at 192.168.10.1 has its SNMP read from 192.168.20.1. A log source added
// at either address is that firewall; the read address says how it was found. A source at an address no device has is not in the
// inventory. A device whose SNMP is read from its own IP, and then moves, leaves its old address to the machine that takes it.
func TestLogSourceIsMatchedByTheReadAddressOverHTTP(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.setModule("logs", true)
	ctx := t.Context()
	svc, err := newSensorActive(context.Background(), *s.d, newHeldWorker(), nil)
	if err != nil {
		t.Fatal(err)
	}
	saMu.Lock()
	saServices[s.d.DB] = svc
	saMu.Unlock()
	fw := s.seen(t, "192.168.10.1", "aa:bb:cc:00:10:01", "firewall")
	if _, err := svc.SetSNMP(ctx, "admin@acme.example", fw, sensoractive.SNMPInput{Version: "v2c", Community: secrets.NewValue("community-1"), ReadFrom: "192.168.20.1"}); err != nil {
		t.Fatal(err)
	}
	sw := s.seen(t, "192.168.10.2", "aa:bb:cc:00:10:02", "switch")
	if _, err := svc.SetSNMP(ctx, "admin@acme.example", sw, sensoractive.SNMPInput{Version: "v2c", Community: secrets.NewValue("community-2")}); err != nil {
		t.Fatal(err)
	}
	s.seen(t, "192.168.10.2", "aa:bb:cc:00:10:02", "switch")
	s.seen(t, "192.168.10.9", "aa:bb:cc:00:10:02", "switch") // the switch moves; its default read address is its old IP
	add := func(name, ip string) {
		t.Helper()
		if code, out := s.do("POST", "/logs/sources", "admin", `{"kind":"fortigate","name":"`+name+`","sender_ip":"`+ip+`","proto":"udp","port":514}`); code != http.StatusCreated {
			t.Fatalf("add %s: %d %v", name, code, out)
		}
	}
	add("FW-LISTED", "192.168.10.1")
	add("FW-MGMT", "192.168.20.1")
	add("OLD-SW", "192.168.10.2")
	code, out := s.do("GET", "/logs/sources", "viewer", "")
	if code != http.StatusOK {
		t.Fatalf("GET: %d %v", code, out)
	}
	byName := map[string]map[string]any{}
	for _, x := range out["sources"].([]any) {
		r := x.(map[string]any)
		byName[r["name"].(string)] = r
	}
	if r := byName["FW-LISTED"]; r["asset_id"] != fw || r["asset_via"] != nil {
		t.Errorf("at the listed IP: %v, want the firewall and no via", r)
	}
	if r := byName["FW-MGMT"]; r["asset_id"] != fw || r["asset_via"] != "snmp_read" || len(r["asset_matches"].([]any)) != 0 {
		t.Errorf("at the read address: %v, want the firewall via snmp_read", r)
	}
	if r := byName["OLD-SW"]; r["asset_id"] != nil || len(r["asset_matches"].([]any)) != 0 {
		t.Errorf("at the old address of a device that moved: %v, want no device", r)
	}
}
