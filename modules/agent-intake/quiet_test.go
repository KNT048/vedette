package agentintake_test

import (
	"testing"
	"time"
)

// A person opens an agent's device page and Settings > Agents: an agent that stopped calling is quiet since its last call, whatever
// the system, and it is back to reporting when it calls again. The limit is three of its own 5-minute config calls.
func TestAgentStateFromItsOwnSchedule(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("servers", 7)
	key := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, fullLog(key))
	d, ok := w.device(peerA)
	if !ok {
		t.Fatal("no device")
	}
	path := "/inventory/agents/devices/" + d.ID + "/report"
	lastCall := w.clock.Now()

	state := func() map[string]any {
		t.Helper()
		r := w.req("viewer", "GET", path)
		if r.code != 200 {
			t.Fatalf("GET report: %d %s", r.code, r.raw)
		}
		return r.body
	}
	if b := state(); b["state"] != "reporting" || b["quiet_since"] != nil || b["os"] != "linux" {
		t.Fatalf("just reported: %v", b)
	}

	w.clock.Advance(14 * time.Minute) // two missed calls are not quiet
	if b := state(); b["state"] != "reporting" {
		t.Fatalf("14 minutes: %v", b)
	}
	w.clock.Advance(2 * time.Minute) // more than three
	b := state()
	if b["state"] != "quiet" || b["os"] != "linux" {
		t.Fatalf("16 minutes: %v", b)
	}
	if since, _ := b["quiet_since"].(string); since == "" || !sameInstant(t, since, lastCall) {
		t.Fatalf("quiet_since %v, want its last call %s", b["quiet_since"], lastCall)
	}

	// Settings > Agents lists it with the same state, the quiet ones first.
	_, other := w.token("others", 7)
	w.enroll(other, "srv-2", "192.0.2.11")
	page := w.admin("GET", "/inventory/agents", nil)
	nodes, _ := page.body["nodes"].([]any)
	if len(nodes) != 2 {
		t.Fatalf("nodes: %s", page.raw)
	}
	first, _ := nodes[0].(map[string]any)
	second, _ := nodes[1].(map[string]any)
	if first["host"] != "srv-1" || first["state"] != "quiet" || first["quiet_since"] == nil || second["host"] != "srv-2" || second["state"] != "reporting" {
		t.Fatalf("nodes: %s", page.raw)
	}

	// It calls again: reporting.
	w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key})
	if b := state(); b["state"] != "reporting" || b["quiet_since"] != nil {
		t.Fatalf("after a call: %v", b)
	}
}

// An agent that calls but never delivered anything is "never reported" once its first hour is over, not before.
func TestAgentNeverReported(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("servers", 7)
	key := w.enroll(secret, "srv-1", peerA)
	state := func() string {
		t.Helper()
		nodes, _ := w.admin("GET", "/inventory/agents", nil).body["nodes"].([]any)
		n, _ := nodes[0].(map[string]any)
		s, _ := n["state"].(string)
		return s
	}
	for range 4 { // 20 minutes, calling every 5
		w.clock.Advance(5 * time.Minute)
		w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key})
	}
	if s := state(); s != "reporting" {
		t.Fatalf("20 minutes after enrolling: %s", s)
	}
	for range 10 { // 70 minutes
		w.clock.Advance(5 * time.Minute)
		w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key})
	}
	if s := state(); s != "never_reported" {
		t.Fatalf("70 minutes after enrolling, no result: %s", s)
	}
}

// Windows machines are told apart, since the person restarts the service with a different command there.
func TestAgentStateKnowsWindows(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("servers", 7)
	body := enrollBody(secret, "win-1")
	body["host_details"].(map[string]any)["os_version"] = map[string]any{"platform": "windows", "name": "Microsoft Windows Server 2025 Standard"}
	r := w.post("/intake/osquery/enroll", peerA, body)
	if r.code != 200 {
		t.Fatalf("enroll: %d %s", r.code, r.raw)
	}
	nodes, _ := w.admin("GET", "/inventory/agents", nil).body["nodes"].([]any)
	if n, _ := nodes[0].(map[string]any); n["os"] != "windows" {
		t.Fatalf("node: %v", n)
	}
}

func sameInstant(t *testing.T, s string, want time.Time) bool {
	t.Helper()
	got, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return got.Equal(want)
}
