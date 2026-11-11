package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/honeypot"
)

// The bugs the WP-30 e2e-real specs found in the response module, each through the generated HTTP handler (the service-level tests
// never went through the generated encoder, so they stayed green).

func responseOn(t *testing.T) *stack {
	t.Helper()
	s := newStack(t)
	s.setModule("notify", true)
	s.setModule("inventory", true)
	s.setModule("response", true)
	return s
}

// #302, #305: after the emergency stop the settings carry stopped_at, and GET and PUT /response/settings still answer 200; Resume clears it.
func TestResponseSettingsReadableAfterEmergencyStop(t *testing.T) {
	t.Parallel()
	s := responseOn(t)
	if c, v := s.do("POST", "/response/emergency-stop", "operator", ""); c != 200 {
		t.Fatalf("emergency stop: %d %v", c, v)
	}
	c, v := s.do("GET", "/response/settings", "admin", "")
	if c != 200 {
		t.Fatalf("GET /response/settings after the stop: %d %v", c, v)
	}
	if at, _ := v["stopped_at"].(string); at == "" || v["breaker_tripped_at"] == nil {
		t.Errorf("the stop is not in the settings: %v", v)
	}
	in, _ := json.Marshal(map[string]any{"max_per_hour": v["max_per_hour"], "expiry_min": v["expiry_min"], "approval_channels": v["approval_channels"],
		"breaker_max_per_hour": v["breaker_max_per_hour"], "multi_target_max": v["multi_target_max"], "maintenance": v["maintenance"],
		"ai": map[string]any{"triggers": at(v, "ai", "triggers"), "budget_hour": at(v, "ai", "budget_hour"), "budget_day": at(v, "ai", "budget_day")}})
	if c, v := s.do("PUT", "/response/settings", "admin", string(in)); c != 200 || v["stopped_at"] == nil {
		t.Errorf("PUT /response/settings after the stop: %d %v", c, v)
	}
	if c, v := s.do("POST", "/response/breaker/reset", "admin", ""); c != 200 || v["stopped_at"] != nil || v["breaker_tripped_at"] != nil {
		t.Errorf("resume: %d %v", c, v)
	}
}

// #308: GET /response/log serves every line exactly as it is stored and hashed, so the served chain re-verifies with the one formula (INV-19).
func TestResponseLogServesTheHashedTimestamp(t *testing.T) {
	t.Parallel()
	s := responseOn(t)
	if c, _ := s.do("POST", "/response/emergency-stop", "operator", ""); c != 200 {
		t.Fatal("emergency stop")
	}
	if c, _ := s.do("POST", "/response/breaker/reset", "admin", ""); c != 200 {
		t.Fatal("resume")
	}
	c, v := s.do("GET", "/response/log", "operator", "")
	items, _ := v["items"].([]any)
	if c != 200 || len(items) < 2 {
		t.Fatalf("log: %d %v", c, v)
	}
	prev := strings.Repeat("0", 64)
	for i, it := range items {
		l := it.(map[string]any)
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false) // JSON.stringify does not escape <, > and &
		if err := enc.Encode(map[string]any{"actor": l["actor"], "detail": l["detail"], "id": l["id"], "kind": l["kind"], "prev_hash": prev, "ts": l["ts"]}); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(prev + "\n" + strings.TrimSuffix(b.String(), "\n")))
		if l["prev_hash"] != prev || l["hash"] != hex.EncodeToString(sum[:]) {
			t.Fatalf("entry #%d (ts %v) does not verify from what the API serves", i, l["ts"])
		}
		if !strings.HasSuffix(l["ts"].(string), "Z") || !strings.Contains(l["ts"].(string), ".") {
			t.Errorf("entry #%d: ts %v is not the stored form", i, l["ts"])
		}
		prev = l["hash"].(string)
	}
}

// #306: the block list feed is text/plain; charset=utf-8 (docs/specs/blocklist-format.md §4), not application/octet-stream.
func TestResponseBlocklistIsPlainText(t *testing.T) {
	t.Parallel()
	s := responseOn(t)
	c, v := s.do("GET", "/response/blocklist", "admin", "")
	url, _ := v["url"].(string)
	if c != 200 || url == "" {
		t.Fatalf("blocklist: %d %v", c, v)
	}
	r := s.pullRaw(url[strings.Index(url, "/response/"):])
	if r.Code != 200 || r.Header().Get("Content-Type") != "text/plain; charset=utf-8" || !strings.HasPrefix(r.Body.String(), "# vedette blocklist") {
		t.Errorf("feed: %d %q %q", r.Code, r.Header().Get("Content-Type"), r.Body.String())
	}
}

// #304: a real honeypot hit (honeypot.hit.created on the bus) fires a live rule with the honeypot trigger, with the trigger fields filled.
func TestResponseHoneypotHitFiresTheRule(t *testing.T) {
	t.Parallel()
	s := responseOn(t)
	rule := `{"name":"Trap source","enabled":true,"live":false,"trigger":"honeypot","match":"all","conditions":[{"field":"kind","op":"eq","value":"service","n":null,"window_min":null}],` +
		`"actions":[{"action_id":"blocklist_add","params":{"ip":"{{trigger.source_ip}}"},"ttl_min":60}],"pre_approved":false,"max_per_hour":5,"schedule_min":null}`
	c, v := s.do("POST", "/response/rules", "admin", rule)
	if c != 201 {
		t.Fatalf("add rule: %d %v", c, v)
	}
	if c, v := s.do("PUT", "/response/rules/"+v["id"].(string), "admin", strings.Replace(rule, `"live":false`, `"live":true`, 1)); c != 200 || v["live"] != true {
		t.Fatalf("rule live: %d %v", c, v)
	}
	ctx := t.Context()
	hit := honeypot.HitEventData{ID: "hit-1", TS: "2026-11-11T10:00:00.000Z", Kind: honeypot.KindService, Service: "ssh", Port: 22, SrcIP: "185.220.101.47", Label: "SSH", Decoy: "FILESRV-OLD"}
	if err := s.d.Bus.Publish(ctx, events.Event{Name: honeypot.EventHitCreated, Data: hit}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.d.Response.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	c, v = s.do("GET", "/response/actions", "admin", "")
	reqs, _ := v["items"].([]any)
	if c != 200 || len(reqs) != 1 {
		t.Fatalf("a request to block the source of the hit: %d %v", c, v)
	}
	if got, _ := json.Marshal(reqs[0]); !strings.Contains(string(got), "185.220.101.47") || !strings.Contains(string(got), "Trap source") {
		t.Errorf("request: %s", got)
	}
}
