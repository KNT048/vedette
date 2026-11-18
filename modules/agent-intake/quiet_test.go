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

func (w *world) nodeList() []map[string]any {
	w.t.Helper()
	raw, _ := w.admin("GET", "/inventory/agents", nil).body["nodes"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, n := range raw {
		m, _ := n.(map[string]any)
		out = append(out, m)
	}
	return out
}

// A machine installed again under another token: the older record never shows as quiet with restart commands. The device page and
// Settings show the live agent; the older record says it was replaced and sorts last.
func TestAgentReEnrolledUnderAnotherTokenIsNotQuiet(t *testing.T) {
	w := newWorld(t)
	_, first := w.token("first", 7)
	oldKey := w.enroll(first, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, fullLog(oldKey))
	d, ok := w.device(peerA)
	if !ok {
		t.Fatal("no device")
	}
	path := "/inventory/agents/devices/" + d.ID + "/report"
	w.clock.Advance(20 * time.Minute) // the install script stopped the old agent; time passes

	_, second := w.token("second", 7)
	newKey := w.enroll(second, "srv-1", peerA)
	w.post("/intake/osquery/config", peerA, map[string]any{"node_key": newKey})
	w.clock.Advance(10 * time.Minute)
	w.post("/intake/osquery/config", peerA, map[string]any{"node_key": newKey})

	if b := w.req("viewer", "GET", path).body; b["state"] != "reporting" || b["quiet_since"] != nil || b["stale"] != false {
		t.Fatalf("device page after the re-install: %v", b)
	}
	nodes := w.nodeList()
	if len(nodes) != 2 || nodes[0]["state"] != "reporting" || nodes[1]["state"] != "replaced" || nodes[1]["quiet_since"] != nil {
		t.Fatalf("nodes: %v", nodes)
	}
	// the new agent then stops: the device page says quiet, from the new agent's last call
	w.clock.Advance(16 * time.Minute)
	if b := w.req("viewer", "GET", path).body; b["state"] != "quiet" {
		t.Fatalf("new agent silent: %v", b)
	}
}

// Two machines that share a name under different tokens are not one machine: the older one still calling keeps its own state.
func TestAgentSameNameStillCallingIsNotReplaced(t *testing.T) {
	w := newWorld(t)
	_, a := w.token("a", 7)
	_, b := w.token("b", 7)
	keyA := w.enroll(a, "srv-1", peerA)
	w.clock.Advance(5 * time.Minute)
	w.enroll(b, "srv-1", "192.0.2.11")
	w.clock.Advance(5 * time.Minute)
	w.post("/intake/osquery/config", peerA, map[string]any{"node_key": keyA}) // still calling
	for _, n := range w.nodeList() {
		if n["state"] == "replaced" {
			t.Fatalf("a record that is still calling is shown as replaced: %v", n)
		}
	}
}

// An uninstalled agent: the person removes its record in Settings; the token stays, the device is released, the record is audited.
func TestAgentUninstalledIsRemovedFromSettings(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("servers", 7)
	key := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, fullLog(key))
	_, other := w.token("others", 7)
	w.enroll(other, "srv-2", "192.0.2.11")
	d, _ := w.device(peerA)
	w.clock.Advance(3 * time.Hour)
	nodes := w.nodeList()
	if nodes[0]["host"] != "srv-1" || nodes[0]["state"] != "quiet" {
		t.Fatalf("nodes: %v", nodes)
	}
	id, _ := nodes[0]["id"].(string)

	if r := w.as("viewer", "DELETE", "/inventory/agents/nodes/"+id, true); r.code != 403 {
		t.Fatalf("remove as viewer: %d", r.code)
	}
	if r := w.admin("DELETE", "/inventory/agents/nodes/"+id, nil); r.code != 204 {
		t.Fatalf("remove: %d %s", r.code, r.raw)
	}
	if r := w.admin("DELETE", "/inventory/agents/nodes/"+id, nil); r.code != 404 {
		t.Fatalf("remove again: %d", r.code)
	}
	if left := w.nodeList(); len(left) != 1 || left[0]["host"] != "srv-2" {
		t.Fatalf("after removing: %v", left)
	}
	if n := w.count(`SELECT count(*) FROM intake_agent_tokens`); n != 2 {
		t.Fatalf("the token must stay: %d", n)
	}
	if r := w.req("viewer", "GET", "/inventory/agents/devices/"+d.ID+"/report"); r.code != 200 || r.body["agent"] != "none" || r.body["state"] != nil {
		t.Fatalf("device page after removing: %s", r.raw)
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.agent_node_remove' AND target = 'srv-1'`); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
}

// "Quiet since" is the node's real last call, even when the box was off for hours and the prune job moved last_seen.
func TestAgentQuietSinceIgnoresThePruneClock(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("servers", 7)
	key := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, fullLog(key))
	lastCall := w.clock.Now()
	d, _ := w.device(peerA)
	w.clock.Advance(10 * time.Hour)
	w.exec(`UPDATE intake_osquery_nodes SET last_seen = '` + w.clock.Now().UTC().Format("2006-01-02T15:04:05.000Z") + `'`) // what node-prune does after a long gap
	r := w.req("viewer", "GET", "/inventory/agents/devices/"+d.ID+"/report")
	since, _ := r.body["quiet_since"].(string)
	if r.body["state"] != "quiet" || since == "" || !sameInstant(t, since, lastCall) {
		t.Fatalf("quiet_since %v, want the last call %s: %s", since, lastCall, r.raw)
	}
}
