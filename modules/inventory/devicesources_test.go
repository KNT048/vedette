package inventory_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// The device page's three source rows are decided on the server: each says its state, colour, last time, switch and one button.
func TestDeviceSources_ThreeRowsDecidedOnTheServer(t *testing.T) {
	t.Parallel()
	snmp := map[string]inventory.SNMPFact{}
	agent := map[string]inventory.AgentFact{}
	e := newEnv(t, func(c *inventory.Config) {
		c.SNMPOf = func(_ context.Context, id string) (inventory.SNMPFact, error) {
			if f, ok := snmp[id]; ok {
				return f, nil
			}
			return inventory.SNMPFact{State: "not_set_up"}, nil
		}
		c.AgentOf = func(_ context.Context, id string) (inventory.AgentFact, error) {
			if f, ok := agent[id]; ok {
				return f, nil
			}
			return inventory.AgentFact{Agent: inventory.AgentNone}, nil
		}
	})
	ctx := e.ctx()
	ip := netip.MustParseAddr("10.0.0.20")
	e.record(observe.Observation{AssetHint: observe.AssetHint{IP: ip}, Field: observe.Hostname, Value: "files-20", Source: observe.Nmap, Confidence: 0.7})
	id := e.idOf("10.0.0.20")
	if err := e.svc.Approve(ctx, "op@example.com", id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetSources(ctx, "admin@example.com", id, nil, ptr("on")); err != nil { // outside the LAN ranges SNMP starts off
		t.Fatal(err)
	}
	answered := e.now.Add(-time.Hour)
	snmp[id] = inventory.SNMPFact{State: "not_answering", LastAnswerAt: answered}
	agent[id] = inventory.AgentFact{Agent: inventory.AgentOsquery, State: "quiet", LastSeen: answered}

	v, err := e.svc.DeviceSources(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Rows) != 3 || v.Only != nil {
		t.Fatalf("rows %+v only %v", v.Rows, v.Only)
	}
	type want struct{ source, state, dot, sw, action string }
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	for i, w := range []want{
		{"scan", "working", "green", "on", ""},
		{"snmp", "not_answering", "red", "on", "check_now"},
		{"agent", "quiet", "amber", "on", "check"},
	} {
		r := v.Rows[i]
		if r.Source != w.source || r.State != w.state || r.Dot != w.dot || str(r.Switch) != w.sw || str(r.Action) != w.action {
			t.Errorf("row %d: %+v (switch %q action %q), want %+v", i, r, str(r.Switch), str(r.Action), w)
		}
	}
	if str(v.Rows[0].LastAt) == "" || str(v.Rows[1].LastAt) == "" || str(v.Rows[2].LastAt) == "" || str(v.Rows[2].Agent) != "osquery" {
		t.Fatalf("last times and agent: %+v", v.Rows)
	}

	// a person turns the scan off: the row says so and keeps the switch
	if _, err := e.svc.SetSources(ctx, "admin@example.com", id, ptr("off"), nil); err != nil {
		t.Fatal(err)
	}
	if v, _ = e.svc.DeviceSources(ctx, id); v.Rows[0].State != "off" || v.Rows[0].Dot != "grey" || str(v.Rows[0].Switch) != "off" {
		t.Fatalf("scan off: %+v", v.Rows[0])
	}

	// a device added by hand without an address: no row can reach it; only what the person entered feeds it
	r, err := e.svc.AddDevice(ctx, "op@example.com", inventory.AddInput{Vendor: "Fortinet", Product: "FortiGate", Version: "7.2.5"})
	if err != nil {
		t.Fatal(err)
	}
	v, err = e.svc.DeviceSources(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if v.Rows[0].State != "off" || v.Rows[1].State != "no_address" || v.Rows[2].State != "none" || str(v.Rows[2].Action) != "create_token" || str(v.Only) != "manual" || v.ManualAt == nil {
		t.Fatalf("hand-added: %+v only %q", v.Rows, str(v.Only))
	}
	// an ignored device and the box itself: no switch and no button the server would refuse (409 device_ignored, 409 box_device)
	if err := e.svc.SetIgnored(ctx, "op@example.com", id, true); err != nil {
		t.Fatal(err)
	}
	box, err := e.svc.EnsureBox(ctx, inventory.BoxInfo{Hostname: "vedette", IP: "10.0.0.2", OS: "Ubuntu 26.04"})
	if err != nil {
		t.Fatal(err)
	}
	for dev, state := range map[string]string{id: "ignored", box: "box"} {
		v, err := e.svc.DeviceSources(ctx, dev)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range v.Rows[:2] {
			if r.State != state || r.Dot != "grey" || r.Switch != nil || r.Action != nil {
				t.Errorf("%s %s row: %+v (switch %q action %q), want %s with no switch or button", state, r.Source, r, str(r.Switch), str(r.Action), state)
			}
		}
		if dev == box && (v.Rows[2].State != "reporting" || str(v.Rows[2].Agent) != "box" || v.Rows[2].Action != nil || v.Rows[2].Switch != nil) {
			t.Errorf("the box's agent row: %+v", v.Rows[2])
		}
	}
	if _, err := e.svc.DeviceSources(ctx, "a-missing"); !errors.Is(err, inventory.ErrNotFound) {
		t.Fatalf("unknown device: %v", err)
	}
}

// After a reinstall or a data purge the box has a new certificate authority, and every agent installed before pins the old one: it can
// never report again. Its agent row says so, with the install command as the button, instead of none or quiet.
func TestDeviceSources_AgentRowSaysTheBoxCertificateChanged(t *testing.T) {
	t.Parallel()
	agent := map[string]inventory.AgentFact{}
	refused := map[string]inventory.TLSRefusal{}
	var since time.Time
	e := newEnv(t, func(c *inventory.Config) {
		c.AgentOf = func(_ context.Context, id string) (inventory.AgentFact, error) {
			if f, ok := agent[id]; ok {
				return f, nil
			}
			return inventory.AgentFact{Agent: inventory.AgentNone}, nil
		}
		c.TLSRefusals = func(ip string) inventory.TLSRefusal { return refused[ip] }
		c.TrustSince = func(context.Context) time.Time { return since }
	})
	ctx := e.ctx()
	for _, a := range []string{"10.0.0.31", "10.0.0.32", "10.0.0.33", "10.0.0.34", "10.0.0.35"} {
		e.record(observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr(a)}, Field: observe.Hostname, Value: "srv-" + a[len(a)-2:], Source: observe.Nmap, Confidence: 0.7})
	}
	fresh, purged, quietOld, quietNew, reporting := e.idOf("10.0.0.31"), e.idOf("10.0.0.32"), e.idOf("10.0.0.33"), e.idOf("10.0.0.34"), e.idOf("10.0.0.35")
	since = e.now.Add(-24 * time.Hour)
	// a purged box: no token, no node; the machine's old agent keeps refusing the new certificate
	refused["10.0.0.32"] = inventory.TLSRefusal{First: e.now.Add(-50 * time.Minute), Last: e.now.Add(-time.Minute), Count: 40}
	// a single odd refusal does not count
	refused["10.0.0.31"] = inventory.TLSRefusal{First: e.now.Add(-time.Minute), Last: e.now.Add(-time.Minute), Count: 1}
	// an osquery agent silent since before the CA began (kept data, CA replaced) and one silent since after (ordinary quiet)
	agent[quietOld] = inventory.AgentFact{Agent: inventory.AgentOsquery, State: "quiet", LastSeen: since.Add(-time.Hour)}
	agent[quietNew] = inventory.AgentFact{Agent: inventory.AgentOsquery, State: "quiet", LastSeen: since.Add(time.Hour)}
	// an agent that reports is never cert_changed, whatever else its address sends
	agent[reporting] = inventory.AgentFact{Agent: inventory.AgentOsquery, State: "reporting", LastSeen: e.now.Add(-time.Minute)}
	refused["10.0.0.35"] = refused["10.0.0.32"]

	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	for _, c := range []struct {
		id, state, dot, action string
		refused                bool
	}{
		{fresh, "none", "grey", "create_token", false},
		{purged, "cert_changed", "red", "create_token", true},
		{quietOld, "cert_changed", "red", "create_token", false},
		{quietNew, "quiet", "amber", "check", false},
		{reporting, "reporting", "green", "check", false},
	} {
		v, err := e.svc.DeviceSources(ctx, c.id)
		if err != nil {
			t.Fatal(err)
		}
		r := v.Rows[2]
		if r.State != c.state || r.Dot != c.dot || str(r.Action) != c.action || (r.Refused != nil) != c.refused {
			t.Errorf("device %s agent row: %+v (action %q refused %+v), want %s %s %s refused=%v", c.id, r, str(r.Action), r.Refused, c.state, c.dot, c.action, c.refused)
		}
		if c.refused && r.Refused != nil && (r.Refused.Count != 40 || r.Refused.Since == "" || r.Refused.Last == "") {
			t.Errorf("refused of %s: %+v", c.id, r.Refused)
		}
	}
	// refusals older than two hours are history: the machine was fixed or is gone
	refused["10.0.0.32"] = inventory.TLSRefusal{First: e.now.Add(-5 * time.Hour), Last: e.now.Add(-3 * time.Hour), Count: 40}
	if v, _ := e.svc.DeviceSources(ctx, purged); v.Rows[2].State != "none" {
		t.Fatalf("old refusals: %+v", v.Rows[2])
	}
	// a person turned the agent off for the device: off wins and says nothing of refusals
	refused["10.0.0.32"] = inventory.TLSRefusal{First: e.now.Add(-time.Hour), Last: e.now, Count: 9}
	if _, err := e.svc.ChangeSources(ctx, "admin@example.com", purged, inventory.SourcesChange{Agent: ptr("off")}); err != nil {
		t.Fatal(err)
	}
	if v, _ := e.svc.DeviceSources(ctx, purged); v.Rows[2].State != "off" || v.Rows[2].Refused != nil {
		t.Fatalf("agent off: %+v", v.Rows[2])
	}
}
