package main

import (
	"testing"

	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/modules/inventory"
)

// Review r2 L4 of #935: device_updates' door reads the feeds switch as GET /findings/plan does: feeds off, no recommended update
// (PlanOff), feeds on or no gate, they are listed.
func TestAIDeviceUpdatesFollowsTheFeedsSwitch(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	added, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Name: "fw-hq", IP: "192.168.30.1"})
	if err != nil {
		t.Fatal(err)
	}
	id := added.ID
	gate := servertest.NewGate("feeds")
	ask := aiAsk{findings: s.d.Findings, inv: s.d.Inventory, gate: gate}
	if u, ok, err := ask.DeviceUpdates(ctx, id); err != nil || !ok || !u.PlanOff {
		t.Fatalf("feeds off: %+v %v %v", u, ok, err)
	}
	gate.Set("feeds", true)
	if u, ok, err := ask.DeviceUpdates(ctx, id); err != nil || !ok || u.PlanOff {
		t.Fatalf("feeds on: %+v %v %v", u, ok, err)
	}
	if u, _, _ := (aiAsk{findings: s.d.Findings, inv: s.d.Inventory}).DeviceUpdates(ctx, id); u.PlanOff {
		t.Fatalf("no gate is on: %+v", u)
	}
}
