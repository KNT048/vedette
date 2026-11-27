package inventory_test

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// A person turns the agent off for one device: every agent's data for it is refused from then on, what the agents read stops counting
// at once (a line only an agent read is removed with its history, a line a scan also reads falls back to the scan), the agents' open
// ports go, and one audit row says who did it. Turned on again, the agents' data is taken again and the agent is asked to report now.
func TestAgentSwitch_RefusesTheAgentsDataAndIsAudited(t *testing.T) {
	t.Parallel()
	var asked []string
	e := newEnv(t, func(c *inventory.Config) {
		c.AskAgent = func(_ context.Context, actor, id string) { asked = append(asked, actor+" "+id) }
	})
	ctx := e.ctx()
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.0.2.71")}
	send := func(src observe.Source, items ...observe.Software) {
		t.Helper()
		e.tick(time.Minute)
		sightedBy(ctx, t, e.svc, hint, src)
		if err := e.svc.ReplaceSoftware(ctx, hint, src, nil, items); err != nil {
			t.Fatal(err)
		}
	}
	nginx := observe.Software{Display: "nginx", Vendor: "F5", Product: "nginx", Version: "1.24.0", Confidence: 1, Packaged: true}
	send(observe.Osquery, ssh("9.6p1", ""), nginx)
	send(observe.Nmap, ssh("9.6p1", "tcp/22"))
	sightedBy(ctx, t, e.svc, hint, observe.Agent)
	if err := e.svc.ReplaceServices(ctx, hint, observe.Agent, observe.ServiceScope{}, []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Confidence: 1}}); err != nil {
		t.Fatal(err)
	}
	e.record(observe.Observation{AssetHint: hint, Field: observe.OS, Value: "Ubuntu 24.04", Source: observe.Agent, Confidence: 1},
		observe.Observation{AssetHint: hint, Field: observe.OS, Value: "Linux 6", Source: observe.Nmap, Confidence: 0.6})
	id := deviceAt(t, e, hint.IP)
	if o, _ := currentOf(e.detail(id), "os"); o.Value != "Ubuntu 24.04" {
		t.Fatalf("the agent's OS before: %+v", o)
	}
	lines := func() map[string]string {
		t.Helper()
		l, err := e.svc.SoftwareLines(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, s := range l { // the lines the device runs: a removed line is not listed
			out[s.Product] = ver(s) + " " + s.Source
		}
		return out
	}
	if got := lines(); got["nginx"] != "1.24.0 agent" || got["OpenSSH"] != "9.6p1 agent" {
		t.Fatalf("before: %v", got)
	}

	off, on := "off", "on"
	got, err := e.svc.ChangeSources(ctx, "admin@example.com", id, inventory.SourcesChange{Agent: &off})
	if err != nil || got.Agent != off {
		t.Fatalf("agent off: %+v, %v", got, err)
	}
	if got := lines(); got["nginx"] != "" || got["OpenSSH"] != "9.6p1 nmap" {
		t.Fatalf("agent off: the agent's readings still count: %v", got)
	}
	if n := e.count(`SELECT count(*) FROM inv_software_event WHERE asset_id = ? AND kind = 'removed' AND product_key LIKE '%nginx%'`, id); n != 1 {
		t.Fatalf("the removed line's history: %d removed events", n)
	}
	if n := e.count(`SELECT count(*) FROM inv_service WHERE asset_id = ? AND source = 'agent'`, id); n != 0 {
		t.Fatalf("the agent's open ports stayed: %d", n)
	}
	if o, _ := currentOf(e.detail(id), "os"); o.Value != "Linux 6" || o.Source != "nmap" {
		t.Fatalf("agent off: the device's OS is still the agent's: %+v", o)
	}
	if n := e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ? AND source = 'agent'`, id); n != 0 {
		t.Fatalf("the agent's observations stayed: %d", n)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.set_source' AND user = 'admin@example.com' AND detail = 'agent: off'`); n != 1 {
		t.Fatalf("audit rows of the switch: %d (%v)", n, e.auditActions())
	}

	// refused: a new list, open ports and observations of the agents do not reach the device
	send(observe.Osquery, ssh("9.9p1", ""), nginx)
	send(observe.Wazuh, nginx)
	sightedBy(ctx, t, e.svc, hint, observe.Agent)
	if err := e.svc.ReplaceServices(ctx, hint, observe.Agent, observe.ServiceScope{}, []observe.Service{{Port: 443, Proto: "tcp", Confidence: 1}}); err != nil {
		t.Fatal(err)
	}
	e.record(observe.Observation{AssetHint: hint, Field: observe.Hostname, Value: "agent-name", Source: observe.Agent, Confidence: 1})
	if got := lines(); got["nginx"] != "" || got["OpenSSH"] != "9.6p1 nmap" {
		t.Fatalf("refused lists reached the device: %v", got)
	}
	if n := e.count(`SELECT count(*) FROM inv_service WHERE asset_id = ? AND source = 'agent'`, id) + e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ? AND source = 'agent'`, id); n != 0 {
		t.Fatalf("refused ports or observations were stored: %d", n)
	}
	// a sensor's data is not the agent's: still taken
	e.record(observe.Observation{AssetHint: hint, Field: observe.Hostname, Value: "files-71", Source: observe.Nmap, Confidence: 0.7})
	if n := e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ? AND source = 'nmap' AND value = 'files-71'`, id); n != 1 {
		t.Fatal("a scan's observation was refused with the agent")
	}
	if len(asked) != 0 {
		t.Fatalf("asked while off: %v", asked)
	}

	got, err = e.svc.ChangeSources(ctx, "admin@example.com", id, inventory.SourcesChange{Agent: &on})
	if err != nil || got.Agent != on {
		t.Fatalf("agent on: %+v, %v", got, err)
	}
	if !slices.Equal(asked, []string{"admin@example.com " + id}) {
		t.Fatalf("the agent was not asked to report now: %v", asked)
	}
	send(observe.Osquery, ssh("9.9p1", ""), nginx)
	if got := lines(); got["nginx"] != "1.24.0 agent" || got["OpenSSH"] != "9.9p1 agent" {
		t.Fatalf("agent on again: %v", got)
	}
	// saying it again changes nothing and asks nothing
	if _, err := e.svc.ChangeSources(ctx, "admin@example.com", id, inventory.SourcesChange{Agent: &on}); err != nil || len(asked) != 1 {
		t.Fatalf("on again: asked %v, %v", asked, err)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.set_source' AND detail LIKE 'agent: %'`); n != 2 {
		t.Fatalf("audit rows of the switch: %d", n)
	}

	// the box reads its own packages: its agent switch is refused
	box, err := e.svc.EnsureBox(ctx, inventory.BoxInfo{Hostname: "vedette", IP: "10.0.0.2", OS: "Ubuntu 26.04"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.ChangeSources(ctx, "admin@example.com", box, inventory.SourcesChange{Agent: &off})
	wantAPIError(t, err, 409, "box_device")
	bad := "maybe"
	_, err = e.svc.ChangeSources(ctx, "admin@example.com", id, inventory.SourcesChange{Agent: &bad})
	wantAPIError(t, err, 400, "bad_source")
}

// The agent row: its switch, the token Show setup shows, a token made for the device before any agent reads it, and quiet as the agent
// itself is judged (with the time it was judged by, never a newer one beside quiet).
func TestDeviceSources_AgentRow(t *testing.T) {
	t.Parallel()
	agent := map[string]inventory.AgentFact{}
	e := newEnv(t, func(c *inventory.Config) {
		c.AgentOf = func(_ context.Context, id string) (inventory.AgentFact, error) { return agent[id], nil }
	})
	ctx := e.ctx()
	e.record(observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("10.0.0.21")}, Field: observe.Hostname, Value: "files-21", Source: observe.Nmap, Confidence: 0.7})
	id := e.idOf("10.0.0.21")
	row := func() inventory.SourceRow {
		t.Helper()
		v, err := e.svc.DeviceSources(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return v.Rows[2]
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	tok := &inventory.AgentToken{ID: "tok-1", Name: "files-21", Kind: "osquery", Last4: "k3pq", CreatedAt: "2026-11-09T09:00:00.000Z", DeviceID: &id}
	for _, c := range []struct {
		name                       string
		fact                       inventory.AgentFact
		state, dot, sw, action, at string
	}{
		{"no agent, no token", inventory.AgentFact{Agent: inventory.AgentNone}, "none", "grey", "", "create_token", ""},
		{"a token made for the device", inventory.AgentFact{Agent: inventory.AgentNone, Token: tok}, "waiting", "grey", "", "show_setup", ""},
		{"enrolled, never reported", inventory.AgentFact{Agent: inventory.AgentOsquery, State: "never_reported", LastSeen: e.now, Token: tok}, "never_reported", "amber", "on", "show_setup", "2026-11-09T10:00:00.000Z"},
		{"osquery reporting", inventory.AgentFact{Agent: inventory.AgentOsquery, State: "reporting", LastSeen: e.now.Add(-16 * time.Minute), Token: tok}, "reporting", "green", "on", "check", "2026-11-09T09:44:00.000Z"},
		{"wazuh quiet by its pull", inventory.AgentFact{Agent: inventory.AgentWazuh, State: "quiet", LastSeen: e.now.Add(-4 * time.Hour)}, "quiet", "amber", "on", "check", "2026-11-09T06:00:00.000Z"},
	} {
		agent[id] = c.fact
		r := row()
		if r.State != c.state || r.Dot != c.dot || str(r.Switch) != c.sw || str(r.Action) != c.action || str(r.LastAt) != c.at || (r.Token != nil) != (c.fact.Token != nil) {
			t.Errorf("%s: %+v (switch %q action %q at %q)", c.name, r, str(r.Switch), str(r.Action), str(r.LastAt))
		}
	}
	off := "off"
	if _, err := e.svc.ChangeSources(ctx, "admin@example.com", id, inventory.SourcesChange{Agent: &off}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []inventory.AgentFact{{Agent: inventory.AgentOsquery, State: "reporting", LastSeen: e.now}, {Agent: inventory.AgentNone}} {
		agent[id] = f
		if r := row(); r.State != "off" || r.Dot != "grey" || str(r.Switch) != "off" {
			t.Errorf("off (%s): %+v switch %q", f.Agent, r, str(r.Switch))
		}
	}
}

// A device whose agent a person turned off is merged with a row that holds an agent's data (the same machine seen twice): the kept
// device's agent is off, and nothing any agent read on either row counts.
func TestAgentSwitch_MergeKeepsTheAgentOff(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := e.ctx()
	a, b := observe.AssetHint{IP: netip.MustParseAddr("192.0.2.72")}, observe.AssetHint{IP: netip.MustParseAddr("192.0.2.73")}
	nginx := observe.Software{Display: "nginx", Vendor: "F5", Product: "nginx", Version: "1.24.0", Confidence: 1, Packaged: true}
	for _, h := range []observe.AssetHint{a, b} {
		if err := e.svc.ReplaceSoftware(ctx, h, observe.Osquery, nil, []observe.Software{nginx}); err != nil {
			t.Fatal(err)
		}
		e.record(observe.Observation{AssetHint: h, Field: observe.OS, Value: "Ubuntu 24.04", Source: observe.Agent, Confidence: 1})
	}
	off := "off"
	ida, idb := deviceAt(t, e, a.IP), deviceAt(t, e, b.IP)
	if _, err := e.svc.ChangeSources(ctx, "admin@example.com", ida, inventory.SourcesChange{Agent: &off}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Merge(ctx, "admin@example.com", ida, idb); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM inv_software_reading r JOIN inv_software s ON s.id = r.software_id WHERE s.asset_id = ? AND r.source IN ('osquery', 'wazuh')`, ida); n != 0 {
		t.Fatalf("the merged row's agent readings count on a device whose agent is off: %d", n)
	}
	if n := e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ? AND source = 'agent'`, ida); n != 0 {
		t.Fatalf("the merged row's agent observations count: %d", n)
	}
	if n := e.count(`SELECT count(*) FROM inv_asset WHERE id = ? AND agent_source = 'off'`, ida); n != 1 {
		t.Fatal("the kept device's agent is not off")
	}
}
