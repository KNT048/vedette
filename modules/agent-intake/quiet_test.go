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
	w.refresh(key) // its rhythm: a config fetch every 5 minutes
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

// The package reporter (Alpine, Arch: no osquery) enrols without an osquery version and reports once an hour. Between two of its runs the
// device is still reported (the plan and the finding page must not say "no agent reports this device now"); it is quiet only after three
// missed hourly runs.
func TestReporterIsQuietOnlyAfterThreeMissedHours(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("firewalls", 7)
	body := enrollBody(secret, "fw-1")
	delete(body["host_details"].(map[string]any), "osquery_info") // as scripts/osquery.sh's reporter enrols
	body["host_details"].(map[string]any)["os_version"] = map[string]any{"platform": "alpine"}
	r := w.post("/intake/osquery/enroll", peerA, body)
	key, _ := r.body["node_key"].(string)
	if r.code != 200 || key == "" {
		t.Fatalf("enroll: %d %s", r.code, r.raw)
	}
	rep := func() {
		t.Helper()
		if r := w.post("/intake/osquery/log", peerA, logBody(key, snap("os_version", map[string]string{"name": "Alpine Linux", "version": "3.23.2", "platform": "alpine"}),
			snap("interfaces", ifaceRow(macA, peerA)), snap("apk_packages", map[string]string{"name": "openssh-server", "version": "10.2_p1-r1", "arch": "x86_64", "origin": "openssh"}))); r.code != 200 || r.invalid() {
			t.Fatalf("report: %d %s", r.code, r.raw)
		}
	}
	rep()
	d, ok := w.device(peerA)
	if !ok {
		t.Fatal("no device")
	}
	state := func() map[string]any {
		t.Helper()
		r := w.req("viewer", "GET", "/inventory/agents/devices/"+d.ID+"/report")
		if r.code != 200 {
			t.Fatalf("GET report: %d %s", r.code, r.raw)
		}
		return r.body
	}
	w.clock.Advance(59 * time.Minute) // the next hourly run is not due yet
	if b := state(); b["state"] != "reporting" || b["stale"] == true {
		t.Fatalf("59 minutes after its report: %v", b)
	}
	rep()
	w.clock.Advance(2*time.Hour + 30*time.Minute) // two missed runs
	if b := state(); b["state"] != "reporting" {
		t.Fatalf("two missed hourly runs: %v", b)
	}
	w.clock.Advance(time.Hour) // three
	if b := state(); b["state"] != "quiet" || b["stale"] != true {
		t.Fatalf("three missed hourly runs: %v", b)
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

// A machine installed again under another token (same source address): the older record never shows as quiet with restart commands. The device page and
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
	w.report(newKey, peerA, macA) // the new agent's first report binds it to the same address
	w.refresh(newKey)             // its 5-minute config refresh

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

// report sends an agent's operating system and its card, from the address it connects from: the box binds the node to that address.
func (w *world) report(key, peer, mac string) {
	w.t.Helper()
	w.post("/intake/osquery/log", peer, logBody(key,
		snap("os_version", map[string]string{"name": "Ubuntu", "version": "24.04.1 LTS (Noble Numbat)", "major": "24", "minor": "4", "patch": "1", "build": "", "platform": "ubuntu", "arch": "x86_64"}),
		snap("interfaces", ifaceRow(mac, peer))))
}

func (w *world) devicePage(ip string) map[string]any {
	w.t.Helper()
	d, ok := w.device(ip)
	if !ok {
		w.t.Fatalf("no device at %s", ip)
	}
	r := w.req("viewer", "GET", "/inventory/agents/devices/"+d.ID+"/report")
	if r.code != 200 {
		w.t.Fatalf("report of %s: %d %s", ip, r.code, r.raw)
	}
	return r.body
}

func stateOfHost(t *testing.T, nodes []map[string]any, host string) string {
	t.Helper()
	for _, n := range nodes {
		if n["host"] == host {
			s, _ := n["state"].(string)
			return s
		}
	}
	t.Fatalf("no node %s in %v", host, nodes)
	return ""
}

// A holder of another token enrols under a live machine's name, even declaring that machine's MAC, but from its own address: it is
// not the same machine. The victim keeps its own state and its device page says quiet once it stops, while the other node keeps calling.
func TestAgentForgedNameDoesNotSupersede(t *testing.T) {
	w := newWorld(t)
	_, victimTok := w.token("servers", 7)
	_, attackerTok := w.token("other", 7)
	const peerB = "192.0.2.11"
	victim := w.enroll(victimTok, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, fullLog(victim))
	forged := w.enroll(attackerTok, "srv-1", peerB)
	w.report(forged, peerB, macA) // declares the victim's MAC from its own address
	w.post("/intake/osquery/config", peerA, map[string]any{"node_key": victim})
	w.refresh(victim)
	if b := w.devicePage(peerA); b["state"] != "reporting" {
		t.Fatalf("victim, calling: %v", b)
	}

	// the victim stops; the forged node keeps calling every 5 minutes
	for range 4 {
		w.clock.Advance(5 * time.Minute)
		w.post("/intake/osquery/config", peerB, map[string]any{"node_key": forged})
	}
	if b := w.devicePage(peerA); b["state"] != "quiet" || b["quiet_since"] == nil {
		t.Fatalf("the forged node hid the silent victim: %v", b)
	}
	nodes := w.nodeList()
	for _, n := range nodes {
		if n["state"] == "replaced" {
			t.Fatalf("a node was marked replaced by a forged name: %v", nodes)
		}
	}
	if len(nodes) != 2 || stateOfHost(t, nodes, "srv-1") == "" {
		t.Fatalf("nodes: %v", nodes)
	}
}

// Two honest machines that share a default name on different tokens keep their own state, whichever enrolled last.
func TestAgentTwoMachinesWithTheSameNameKeepTheirState(t *testing.T) {
	w := newWorld(t)
	_, tokA := w.token("a", 7)
	_, tokB := w.token("b", 7)
	const peerB, macB = "192.0.2.11", "52:54:00:aa:bb:78"
	keyA := w.enroll(tokA, "ubuntu", peerA)
	w.report(keyA, peerA, macA)
	w.post("/intake/osquery/log", peerA, fullLog(keyA))
	w.refresh(keyA)
	w.clock.Advance(2 * time.Minute)
	keyB := w.enroll(tokB, "ubuntu", peerB)
	w.report(keyB, peerB, macB)
	// A is off; B calls
	for range 4 {
		w.clock.Advance(5 * time.Minute)
		w.post("/intake/osquery/config", peerB, map[string]any{"node_key": keyB})
	}
	if a, b := w.devicePage(peerA), w.devicePage(peerB); a["state"] != "quiet" || b["state"] != "reporting" {
		t.Fatalf("A (off) %v, B (calling) %v", a["state"], b["state"])
	}
	for _, n := range w.nodeList() {
		if n["state"] == "replaced" {
			t.Fatalf("honest machines with one name: %v", n)
		}
	}
	// A comes back
	w.post("/intake/osquery/config", peerA, map[string]any{"node_key": keyA})
	if a := w.devicePage(peerA); a["state"] != "reporting" {
		t.Fatalf("A back: %v", a)
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
	software := len(d.Software)
	if software == 0 {
		t.Fatal("the device has no software to keep")
	}
	w.refresh(key)
	w.clock.Advance(3 * time.Hour)
	nodes := w.nodeList()
	if nodes[0]["host"] != "srv-1" || nodes[0]["state"] != "quiet" {
		t.Fatalf("nodes: %v", nodes)
	}
	id, _ := nodes[0]["id"].(string)

	for _, role := range []string{"viewer", "operator"} {
		if r := w.as(role, "DELETE", "/inventory/agents/nodes/"+id, true); r.code != 403 {
			t.Fatalf("remove as %s: %d", role, r.code)
		}
	}
	if r := w.admin("DELETE", "/inventory/agents/nodes/node_nope", nil); r.code != 404 {
		t.Fatalf("remove an unknown id: %d", r.code)
	}
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes`); n != 2 {
		t.Fatalf("a refused removal deleted a node: %d", n)
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
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.agent_node_remove' AND target = 'srv-1' AND user = 'admin@acme.example' AND detail = 'token "servers"'`); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
	if after, ok := w.device(peerA); !ok || len(after.Software) != software {
		t.Fatalf("the device lost its software: %d of %d (found %v)", len(after.Software), software, ok)
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

// refresh is two of the node's config fetches from peerA, five minutes apart (the install scripts' --config_refresh=300): the box has
// seen two fetches in a row, so it knows the node refreshes its config (NodeHealth judges a node it has not seen do so by its report
// schedule).
func (w *world) refresh(key string) {
	w.t.Helper()
	for range 2 {
		w.clock.Advance(5 * time.Minute)
		if r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key}); r.code != 200 || r.invalid() {
			w.t.Fatalf("config: %d %s", r.code, r.raw)
		}
	}
}
