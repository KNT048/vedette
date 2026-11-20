package agentintake_test

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
	"github.com/knt048/vedette/modules/inventory"
)

// replayNode is one agent record of the anonymised inventory export (testdata/agent_nodes.json).
type replayNode struct {
	ID             string  `json:"id"`
	Platform       string  `json:"platform"`
	OsqueryVersion *string `json:"osquery_version"`
	EnrolledAt     string  `json:"enrolled_at"`
	LastCallAt     string  `json:"last_call_at"`
	LastResultAt   string  `json:"last_result_at"`
}

// The kinds of call timeline an agent of the export has, read from its own record.
const (
	kindRefresh = "osquery, 5-minute config refresh" // its last call is after its last result: it fetches its config between reports
	kindResults = "osquery, hourly results only"     // its last call is its last result: no config fetch seen (an install without the refresh flag)
	kindHourly  = "package reporter, hourly"         // enrolled without an osquery version
)

// replayCall is one call of a replayed agent to the box.
type replayCall struct {
	at     time.Time
	node   int
	result bool // a result post (log); otherwise a config fetch
}

// timeline is the calls of one agent from its enrolment to its last call, as its kind makes them. The times are drawn from a fixed
// seed, so the replay is the same at every run: config fetches every 300 s plus a few seconds; osquery's hourly queries each on their own
// splayed period (±10 % of 3600 s, as osquery splays them); every other hour a service start 1 to 15 minutes after a result (one config
// fetch); the reporter once an hour at its minute plus up to 60 s of random delay.
func timeline(i int, n replayNode, kind string) []replayCall {
	enrolled, _ := time.Parse(time.RFC3339Nano, n.EnrolledAt)
	last, _ := time.Parse(time.RFC3339Nano, n.LastCallAt)
	rnd := rand.New(rand.NewPCG(uint64(i)+1, 7)) //nolint:gosec // a fixed replay, not a secret
	var out []replayCall
	add := func(at time.Time, result bool) {
		if at.After(enrolled) && at.Before(last) {
			out = append(out, replayCall{at: at, node: i, result: result})
		}
	}
	switch kind {
	case kindRefresh:
		for t := enrolled.Add(time.Minute); t.Before(last); t = t.Add(time.Minute) { // the first report: asked every minute for a few minutes
			if t.Sub(enrolled) > 4*time.Minute {
				break
			}
			add(t, true)
		}
		for t := enrolled; t.Before(last); {
			t = t.Add(5*time.Minute + time.Duration(rnd.IntN(4000))*time.Millisecond)
			add(t, false)
		}
		fallthrough
	case kindResults:
		for _, period := range []time.Duration{3240 * time.Second, 3600 * time.Second, 3960 * time.Second} {
			k := 0
			for t := enrolled.Add(time.Duration(rnd.IntN(3600)) * time.Second); t.Before(last); t = t.Add(period) {
				add(t, true)
				// every other hourly result of one query, the service starts again 1 to 15 minutes later (an update, a reboot): osquery
				// fetches its config when it starts, whether or not it refreshes it afterwards
				if k++; period == 3600*time.Second && k%2 == 0 {
					add(t.Add(time.Minute+time.Duration(rnd.IntN(14*60))*time.Second), false)
				}
			}
		}
	case kindHourly:
		for t := enrolled.Add(time.Hour); t.Before(last); t = t.Add(time.Hour) {
			add(t.Add(time.Duration(rnd.IntN(60))*time.Second), true)
		}
	}
	return append(out, replayCall{at: last, node: i, result: n.LastResultAt == n.LastCallAt})
}

// interval is the rhythm an agent of a kind really keeps: what "its next call arrived within three intervals" is measured by.
func interval(kind string) time.Duration {
	if kind == kindRefresh {
		return 5 * time.Minute
	}
	return time.Hour + time.Minute
}

// The class of "quiet beside a recent report" on the seven agents of an anonymised inventory export: their call timelines are replayed through the
// box (enrolment, config fetches and result posts at their own times), and the agents list is read every minute from the first
// enrolment to the export. An agent is never quiet at a moment when its next call came within three of its own intervals. The count of
// such agent-minutes is logged per agent; it must be 0.
func TestAgentCadence_ReplayOfSevenAgents(t *testing.T) {
	raw, err := os.ReadFile("testdata/agent_nodes.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Nodes []replayNode `json:"agent_nodes"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	if len(fx.Nodes) != 7 {
		t.Fatalf("%d agents in the export, want 7", len(fx.Nodes))
	}
	w := newWorld(t)
	kinds := make([]string, len(fx.Nodes))
	var calls []replayCall
	var start, end time.Time
	for i, n := range fx.Nodes {
		switch {
		case n.OsqueryVersion == nil:
			kinds[i] = kindHourly
		case n.LastCallAt != n.LastResultAt:
			kinds[i] = kindRefresh
		default:
			kinds[i] = kindResults
		}
		enrolled, _ := time.Parse(time.RFC3339Nano, n.EnrolledAt)
		last, _ := time.Parse(time.RFC3339Nano, n.LastCallAt)
		if start.IsZero() || enrolled.Before(start) {
			start = enrolled
		}
		if last.After(end) {
			end = last
		}
		calls = append(calls, replayCall{at: enrolled, node: i, result: false}) // the enrolment, then the agent's own calls
		calls = append(calls, timeline(i, n, kinds[i])...)
	}
	end = end.Add(3 * time.Minute) // the export ran just after the last call
	slices.SortStableFunc(calls, func(a, b replayCall) int { return a.at.Compare(b.at) })

	// the calls of each agent, to find the one before and the one after a moment
	byNode := make([][]time.Time, len(fx.Nodes))
	for _, c := range calls {
		byNode[c.node] = append(byNode[c.node], c.at)
	}
	keys := make([]string, len(fx.Nodes))
	hosts := map[string]int{}
	peer := func(i int) string { return fmt.Sprintf("192.0.2.%d", 30+i) }
	mac := func(i int) string { return fmt.Sprintf("52:54:00:aa:cc:%02x", i) }

	w.clock.Advance(start.Sub(w.clock.Now()) - time.Minute)
	_, secret := w.token("replay", 0) // never expires once a machine enrolled with it
	bad := make([]int, len(fx.Nodes))
	found, silent := 0, 0 // agents that stopped calling before the export, and those of them the box called quiet by then
	sampled := 0
	next := 0
	for at := start.Truncate(time.Minute); !at.After(end); at = at.Add(time.Minute) {
		for ; next < len(calls) && !calls[next].at.After(at); next++ {
			c := calls[next]
			w.clock.Advance(c.at.Sub(w.clock.Now()))
			switch {
			case keys[c.node] == "":
				body := enrollBody(secret, fmt.Sprintf("host-%02d", c.node))
				hd := body["host_details"].(map[string]any)
				hd["os_version"] = map[string]any{"platform": fx.Nodes[c.node].Platform}
				if fx.Nodes[c.node].OsqueryVersion == nil {
					delete(hd, "osquery_info") // the package reporter enrols as scripts/osquery.sh does
				}
				r := w.post("/intake/osquery/enroll", peer(c.node), body)
				keys[c.node], _ = r.body["node_key"].(string)
				if r.code != 200 || keys[c.node] == "" {
					t.Fatalf("enroll %d: %d %s", c.node, r.code, r.raw)
				}
				hosts[fmt.Sprintf("host-%02d", c.node)] = c.node
				if kinds[c.node] != kindHourly { // osquery fetches its config when it starts
					w.post("/intake/osquery/config", peer(c.node), map[string]any{"node_key": keys[c.node]})
				} else { // the reporter sends its list in the same run
					w.post("/intake/osquery/log", peer(c.node), logBody(keys[c.node], snap("interfaces", ifaceRow(mac(c.node), peer(c.node)))))
				}
			case c.result:
				if r := w.post("/intake/osquery/log", peer(c.node), logBody(keys[c.node], snap("interfaces", ifaceRow(mac(c.node), peer(c.node))))); r.code != 200 || r.invalid() {
					t.Fatalf("log %d: %d %s", c.node, r.code, r.raw)
				}
			default:
				if r := w.post("/intake/osquery/config", peer(c.node), map[string]any{"node_key": keys[c.node]}); r.code != 200 || r.invalid() {
					t.Fatalf("config %d: %d %s", c.node, r.code, r.raw)
				}
			}
		}
		w.clock.Advance(at.Sub(w.clock.Now()))
		nodes, err := w.svc.Nodes(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range nodes {
			i := hosts[n.Host]
			times := byNode[i]
			if at.Add(time.Minute).After(end) && at.Sub(times[len(times)-1]) > 3*interval(kinds[i])+time.Minute { // the export: a stopped agent is quiet
				silent++
				if n.State == agentintake.StateQuiet {
					found++
				}
			}
			k := slices.IndexFunc(times, func(c time.Time) bool { return c.After(at) })
			if k <= 0 { // no call after this moment: a quiet agent here is really silent
				continue
			}
			sampled++
			if n.State == agentintake.StateQuiet && times[k].Sub(times[k-1]) <= 3*interval(kinds[i]) {
				bad[i]++
			}
		}
	}
	total := 0
	var per []string
	for i, b := range bad {
		total += b
		per = append(per, fmt.Sprintf("%s (%s): %d", fx.Nodes[i].ID[:9], kinds[i], b))
	}
	t.Logf("agent-minutes quiet although the next call came within three intervals: %d of %d sampled; %s", total, sampled, strings.Join(per, "; "))
	t.Logf("agents that stopped calling before the export: %d, quiet at the export: %d", silent, found)
	if total != 0 {
		t.Fatalf("%d agent-minutes were quiet beside a recent report", total)
	}
	if silent == 0 || found != silent {
		t.Fatalf("%d of %d stopped agents are quiet at the export", found, silent)
	}
}

// An agent that calls less often than it was told (an install without the config refresh, calling only with its hourly results) is
// learned: never quiet between two of its own calls, quiet after three of them missed. One that keeps its five-minute refresh is
// still quiet a quarter of an hour after it stops.
func TestAgentCadence_SlowerThanToldIsNotQuietBetweenItsCalls(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("servers", 7)
	key := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key})
	report := func() {
		t.Helper()
		if r := w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)))); r.code != 200 || r.invalid() {
			t.Fatalf("log: %d %s", r.code, r.raw)
		}
	}
	state := func() agentintake.NodeState {
		t.Helper()
		nodes, err := w.svc.Nodes(t.Context())
		if err != nil || len(nodes) != 1 {
			t.Fatalf("nodes: %v %v", nodes, err)
		}
		return nodes[0]
	}
	for h := range 6 {
		last := w.clock.Now()
		for _, m := range []time.Duration{16, 30, 59} {
			w.clock.Advance(last.Add(m * time.Minute).Sub(w.clock.Now()))
			if s := state(); s.State != agentintake.StateReporting {
				t.Fatalf("hour %d, %d minutes after its last call: %s (rhythm %v)", h, m, s.State, s.Rhythm)
			}
		}
		w.clock.Advance(time.Minute)
		report()
	}
	if s := state(); s.Rhythm != time.Hour {
		t.Fatalf("learned rhythm %v, want its hour", s.Rhythm)
	}
	w.clock.Advance(3*time.Hour + time.Minute)
	if s := state(); s.State != agentintake.StateQuiet {
		t.Fatalf("three hourly reports missed: %s", s.State)
	}
	// it starts again (a config fetch first, as osquery does): the silence was an outage, not its rhythm
	w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key})
	if s := state(); s.State != agentintake.StateReporting || s.Rhythm != time.Hour {
		t.Fatalf("back: %s, rhythm %v", s.State, s.Rhythm)
	}
}

// An agent without the config refresh whose service starts twice with no result in between (an upgrade, then a reboot; the install
// command run again) is not taken for a refreshing one: it stays judged by its report schedule and is never quiet before its next
// hourly result. Only two starts within ten seconds of the 300 s refresh would look like one (refreshSlack). A refreshing agent is
// still quiet a quarter of an hour after it stops.
func TestAgentCadence_TwoServiceStartsAreNoRefresh(t *testing.T) {
	for _, apart := range []time.Duration{time.Minute, 2 * time.Minute, 4*time.Minute + 45*time.Second, 5*time.Minute + 15*time.Second, 10 * time.Minute, 14 * time.Minute} {
		w := newWorld(t)
		_, secret := w.token("servers", 7)
		key := w.enroll(secret, "srv-1", peerA)
		w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key})
		w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA))))
		state := func() agentintake.NodeState {
			t.Helper()
			nodes, err := w.svc.Nodes(t.Context())
			if err != nil || len(nodes) != 1 {
				t.Fatalf("nodes: %v %v", nodes, err)
			}
			return nodes[0]
		}
		for h := range 3 {
			w.clock.Advance(3 * time.Minute) // the service starts, and again
			w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key})
			w.clock.Advance(apart)
			w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key})
			last := w.clock.Now()
			for _, at := range []time.Duration{16 * time.Minute, 30 * time.Minute, 45 * time.Minute} {
				if left := last.Add(at); left.Before(last.Add(57*time.Minute - apart)) {
					w.clock.Advance(left.Sub(w.clock.Now()))
					if s := state(); s.State != agentintake.StateReporting {
						t.Fatalf("starts %v apart, hour %d, %v after the second: %s (rhythm %v)", apart, h, at, s.State, s.Rhythm)
					}
				}
			}
			w.clock.Advance(last.Add(57*time.Minute - apart).Sub(w.clock.Now())) // its next hourly result
			w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA))))
		}
		w.refresh(key) // it is a refreshing agent after all: two fetches 5 minutes apart
		w.clock.Advance(16 * time.Minute)
		if s := state(); s.State != agentintake.StateQuiet {
			t.Fatalf("starts %v apart, then a refreshing agent that stopped: %s (rhythm %v)", apart, s.State, s.Rhythm)
		}
	}
}

// A device Wazuh reads is judged at the pull's rhythm by when Wazuh last heard from its agent: the pull's time while Wazuh lists the
// agent active (whatever the manager's clock says: here it runs 20 minutes behind the box's), its keep-alive while Wazuh lists it
// disconnected (the pull still reads its inventory for a week). Reporting while that is within three pull intervals, quiet after, back
// with the next pull.
func TestAgentCadence_WazuhByWhatWazuhHears(t *testing.T) {
	r := newWzRig(t)
	r.fake.agents[1]["lastKeepAlive"] = r.clock.Now().Add(-20 * time.Minute).Format(time.RFC3339) // web01, by a manager 20 minutes behind
	r.save()
	r.pull()
	pulled := r.clock.Now()
	report := func(ip string) map[string]any {
		t.Helper()
		d, ok := r.device(ip)
		if !ok {
			t.Fatalf("no Wazuh device at %s", ip)
		}
		g := r.req("viewer", "GET", "/inventory/agents/devices/"+d.ID+"/report")
		if g.code != 200 || g.body["agent"] != "wazuh" {
			t.Fatalf("GET: %d %s", g.code, g.raw)
		}
		return g.body
	}
	if b := report(ipLinux); b["state"] != "reporting" || b["stale"] != false || b["rhythm_s"] != float64(3600) || !sameInstant(t, b["last_seen"].(string), pulled) {
		t.Fatalf("just pulled: %v", b)
	}
	// WIN-FS01 is disconnected since 9 November: quiet since then, and no agent reports the device now
	if b := report(ipWindows); b["state"] != "quiet" || b["stale"] != true || !sameInstant(t, b["quiet_since"].(string), time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("disconnected agent: %v", b)
	}
	r.clock.Advance(3 * time.Hour) // three pull intervals with no pull
	if b := report(ipLinux); b["state"] != "reporting" {
		t.Fatalf("three intervals: %v", b)
	}
	r.clock.Advance(time.Minute)
	if b := report(ipLinux); b["state"] != "quiet" || b["stale"] != true || !sameInstant(t, b["quiet_since"].(string), pulled) {
		t.Fatalf("past three intervals: %v", b)
	}
	r.pull()
	if b := report(ipLinux); b["state"] != "reporting" {
		t.Fatalf("pulled again: %v", b)
	}
}

// A token made for a device is what that device's agent row shows under Show setup until a machine enrols with it; then the token its
// agent enrolled with. An unknown device is 404, the box 409. A device whose agent a person turned off says so, and cannot be asked.
func TestAgentToken_MadeForADevice(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	if err := w.inv.Record(ctx, []observe.Observation{hostnameAt(peerA, "srv-1")}); err != nil {
		t.Fatal(err)
	}
	d, ok := w.device(peerA)
	if !ok {
		t.Fatal("no device")
	}
	if st, err := w.svc.ReportState(ctx, d.ID); err != nil || st.Agent != agentintake.ReportNone || st.Setup != nil {
		t.Fatalf("before any token: %+v %v", st, err)
	}
	r := w.admin("POST", "/inventory/agents/tokens", map[string]any{"name": "srv-1", "device_id": d.ID})
	tok, _ := r.body["token"].(map[string]any)
	if r.code != 201 || tok["device_id"] != d.ID {
		t.Fatalf("token for the device: %d %s", r.code, r.raw)
	}
	st, err := w.svc.ReportState(ctx, d.ID)
	if err != nil || st.Setup == nil || st.Setup.ID != tok["id"] || st.Setup.DeviceID != d.ID {
		t.Fatalf("Show setup before the agent: %+v %v", st, err)
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.agent_token_create' AND detail LIKE '%for device ` + d.ID + `'`); n != 1 {
		t.Fatalf("audit of the token: %d", n)
	}
	// the machine enrols with another token: its row shows the token its agent used
	_, other := w.token("all servers", 7)
	key := w.enroll(other, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, fullLog(key))
	if st, err = w.svc.ReportState(ctx, d.ID); err != nil || st.Agent != agentintake.ReportOsquery || st.Setup == nil || st.Setup.Name != "all servers" {
		t.Fatalf("Show setup after the agent enrolled: %+v %v", st, err)
	}

	if r := w.admin("POST", "/inventory/agents/tokens", map[string]any{"name": "x", "device_id": "a-nothing"}); r.code != 404 {
		t.Fatalf("token for an unknown device: %d %s", r.code, r.raw)
	}
	box, err := w.inv.EnsureBox(ctx, inventory.BoxInfo{Hostname: "vedette", IP: "192.0.2.2", OS: "Ubuntu 26.04"})
	if err != nil {
		t.Fatal(err)
	}
	if r := w.admin("POST", "/inventory/agents/tokens", map[string]any{"name": "x", "device_id": box}); r.code != 409 || r.errCode() != "box_device" {
		t.Fatalf("token for the box: %d %s", r.code, r.raw)
	}

	// a person turns the agent off for the device: GET says so, an ask is refused
	off := "off"
	if _, err := w.inv.ChangeSources(ctx, "admin@acme.example", d.ID, inventory.SourcesChange{Agent: &off}); err != nil {
		t.Fatal(err)
	}
	path := "/inventory/agents/devices/" + d.ID + "/report"
	if g := w.req("viewer", "GET", path); g.code != 200 || g.body["off"] != true {
		t.Fatalf("GET of a device whose agent is off: %d %s", g.code, g.raw)
	}
	if p := w.req("operator", "POST", path); p.code != 409 || p.errCode() != "agent_off" {
		t.Fatalf("ask a device whose agent is off: %d %s", p.code, p.raw)
	}
}

// hostnameAt is a scan's observation of a host name at an address: it makes the device the tests start from.
func hostnameAt(ip, name string) observe.Observation {
	return observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr(ip)}, Field: observe.Hostname, Value: name, Source: observe.Nmap, Confidence: 0.7}
}
