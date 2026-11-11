package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// The mcp-server module on the binary's real wiring (S-MCP-1): the admin turns it on and makes a token through the API, an
// agent connects to the loopback port over a real socket and reads a device, a finding and a CVE through the real inventory,
// findings and feeds; what stays on the box (MAC, notes, the scan's summary, request and response, who changed a finding and
// what they wrote) never reaches the agent (INV-7, D-233). Off, the port closes and /core/mcp is 404 (SYS-5).
func TestMCPServerOnTheRealWiring(t *testing.T) {
	t.Parallel()
	s := newStackWith(t, func(d *deps) { d.MCPListen = netip.MustParseAddrPort("127.0.0.1:0") })
	if code, _ := s.do("GET", "/core/mcp", "admin", ""); code != http.StatusNotFound {
		t.Fatalf("GET /core/mcp while off = %d", code)
	}
	if code, body := s.do("GET", "/core/privacy", "viewer", ""); code != 200 || flowState(body, 13) != "off" {
		t.Fatalf("privacy flow 13 while off: %d %v", code, body)
	}
	if err := startMCP(t.Context(), *s.d); err != nil {
		t.Fatal(err)
	}
	s.kev("CVE-2024-21762", "Fortinet", "FortiOS")
	id := s.addFortiGate() // 192.168.30.1, FortiOS 7.2.5: matched to the CVE through the events
	notes := "NOTE-on-the-device"
	if err := s.d.Inventory.PatchDevice(t.Context(), "it@acme.example", id, inventory.Patch{Notes: &notes}); err != nil {
		t.Fatal(err)
	}
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.168.30.1")}
	if err := s.d.Inventory.Record(t.Context(), []observe.Observation{{AssetHint: hint, Field: observe.MAC, Value: "aa:bb:cc:dd:ee:01", Source: observe.Passive, Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	if dev, err := s.d.Inventory.Device(t.Context(), id); err != nil || dev.MAC == nil || dev.Notes == nil {
		t.Fatalf("the device has no MAC or notes to keep back: %+v, %v", dev, err)
	}
	if _, err := s.d.Findings.ConfirmFromScan(t.Context(), id, "CVE-2024-21762", findings.Evidence{Summary: "SUMMARY-names-the-device",
		Template: "CVE-2024-21762", Request: "GET /remote/REQUEST-raw", Response: "HTTP/1.1 200 RESPONSE-raw", CheckedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	recs, err := s.d.Findings.List(t.Context(), id)
	if err != nil || len(recs) != 1 {
		t.Fatalf("findings = %v, %v", recs, err)
	}
	if _, err := s.d.Findings.SetStatus(t.Context(), recs[0].ID, findings.ActionMitigated, "NOTE-of-the-admin: VPN portal turned off", "admin@acme.example"); err != nil {
		t.Fatal(err)
	}

	s.setModule("mcp-server", true)
	code, created := s.do("POST", "/core/mcp/tokens", "admin", `{"name":"SOC agent","scopes":["assets","findings","feeds"]}`)
	if code != http.StatusCreated {
		t.Fatalf("create token: %d %v", code, created)
	}
	token := created["token"].(string)
	var state map[string]any
	waitUntil(t, func() bool {
		_, state = s.do("GET", "/core/mcp", "admin", "")
		return state["port"] != nil && state["port"] != 0.0
	})
	if state["bind"] != "127.0.0.1" || state["enabled"] != true || len(state["tools"].([]any)) != 7 {
		t.Fatalf("GET /core/mcp = %v", state)
	}
	if b, _ := json.Marshal(state); bytes.Contains(b, []byte(token[5:])) {
		t.Fatal("GET /core/mcp carries the token")
	}
	endpoint := state["endpoint"].(string)
	if _, body := s.do("GET", "/core/privacy", "viewer", ""); flowState(body, 13) != "conditional" {
		t.Fatalf("privacy flow 13 while on = %v", flowState(body, 13))
	}

	post := func(body string) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("MCP-Protocol-Version", "2025-06-18")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	if code, b := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`); code != 200 {
		t.Fatalf("initialize: %d %s", code, b)
	}
	var seen []byte
	for _, call := range []string{
		`{"name":"list_assets"}`,
		`{"name":"get_asset","arguments":{"id":"` + id + `"}}`,
		`{"name":"list_findings","arguments":{"status":"all"}}`,
		`{"name":"get_finding","arguments":{"id":"` + recs[0].ID + `"}}`,
		`{"name":"lookup_cve","arguments":{"cve":"CVE-2024-21762"}}`,
		`{"name":"hot_vulnerabilities","arguments":{"window":"24h"}}`,
		`{"name":"lookup_ioc","arguments":{"value":"8.8.8.8"}}`,
	} {
		code, b := post(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":` + call + `}`)
		var r struct {
			Result struct {
				IsError    bool            `json:"isError"`
				Structured json.RawMessage `json:"structuredContent"`
			} `json:"result"`
		}
		if code != 200 || json.Unmarshal(b, &r) != nil || r.Result.IsError || len(r.Result.Structured) == 0 {
			t.Fatalf("%s: %d %s", call, code, b)
		}
		seen = append(seen, b...)
	}
	for _, kept := range []string{"aa:bb:cc:dd:ee:01", "AA:BB:CC", "NOTE-on-the-device", "REQUEST-raw", "RESPONSE-raw", "NOTE-of-the-admin", "admin@acme.example", "SUMMARY-names-the-device"} {
		if bytes.Contains(seen, []byte(kept)) {
			t.Errorf("an agent read %q", kept)
		}
	}
	for _, shown := range []string{"192.168.30.1", "CVE-2024-21762", `"template":"CVE-2024-21762"`, `"mitigated"`, "FortiOS"} {
		if !bytes.Contains(seen, []byte(shown)) {
			t.Errorf("the answers miss %q", shown)
		}
	}
	if n := s.count(`SELECT count(*) FROM core_audit WHERE action = 'mcp.call' AND target = 'SOC agent'`); n != 7 {
		t.Fatalf("%d audit rows for 7 calls", n)
	}

	s.setModule("mcp-server", false)
	if code, _ := s.do("GET", "/core/mcp", "admin", ""); code != http.StatusNotFound {
		t.Fatalf("GET /core/mcp after off = %d", code)
	}
	addr := strings.TrimSuffix(strings.TrimPrefix(endpoint, "http://"), "/mcp")
	waitUntil(t, func() bool {
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", addr)
		if err == nil {
			_ = c.Close()
		}
		return err != nil
	})
	if n := s.count(`SELECT count(*) FROM mcp_tokens`); n != 1 {
		t.Fatalf("tokens after off = %d", n)
	}
}

func flowState(body map[string]any, id int) any {
	flows, _ := body["flows"].([]any)
	for _, f := range flows {
		m := f.(map[string]any)
		if m["id"] == float64(id) {
			return m["state"]
		}
	}
	return nil
}

func waitUntil(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		<-time.After(10 * time.Millisecond)
	}
}

// -mcp-listen takes a loopback address and port only (INV-5).
func TestParseMCPListen(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"127.0.0.1:8765", "[::1]:8765", "127.0.0.2:9000"} {
		if _, err := parseMCPListen(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:8765", ":8765", "localhost:8765", "192.168.1.5:8765", "127.0.0.1:0", "127.0.0.1", ""} {
		if _, err := parseMCPListen(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
