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
