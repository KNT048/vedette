package main

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/modules/inventory"
)

// Review r2 L4 of #935: device_updates' door reads the feeds switch: feeds off, no recommended update
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

// device_updates reads the By device card of the device (the fix blocks the Findings page shows): the FortiGate's two exploited CVEs are
// one software with no named update (the list names no versions), counted as open urgent findings, and no recommended update is listed
// for them.
func TestAIDeviceUpdatesReadsTheFixBlocks(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.kev("CVE-2026-1001", "Fortinet", "FortiOS")
	s.kev("CVE-2026-1002", "Fortinet", "FortiOS")
	id := s.addFortiGate()
	u, ok, err := aiAsk{findings: s.d.Findings, inv: s.d.Inventory}.DeviceUpdates(ctx, id)
	if err != nil || !ok {
		t.Fatalf("%+v %v %v", u, ok, err)
	}
	if u.Open != 2 || len(u.Exploited) != 0 || len(u.Planned) != 0 || len(u.NoUpdate) != 1 {
		t.Fatalf("open %d, %d updates, %d recommended, %d with no named update", u.Open, len(u.Exploited), len(u.Planned), len(u.NoUpdate))
	}
	row := u.NoUpdate[0]
	if len(row.CVEs) != 2 || !strings.HasPrefix(row.Action, "No fixed release is named for ") || row.Suspected != 2 || row.Fixed != "" {
		t.Fatalf("row = %+v", row)
	}
	if _, ok, err := (aiAsk{findings: s.d.Findings, inv: s.d.Inventory}).DeviceUpdates(ctx, "gone"); ok || err != nil {
		t.Fatalf("a device that is not there: ok %v, %v", ok, err)
	}
}
