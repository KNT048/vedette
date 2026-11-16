package main

import (
	"testing"
)

// #825: the binary gives GET /findings/summary inventory's device counts and notify's sent messages (findings imports neither).
func TestWiringHomeSummaryCarriesDevicesAndAlerts(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.addFortiGate()
	sum, err := s.d.FindingHandlers.Summary(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	total, pending, err := s.d.Inventory.DeviceCounts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if total == 0 || sum.Devices.Total != total || sum.Devices.Pending != pending {
		t.Fatalf("summary devices %+v, inventory %d/%d", sum.Devices, total, pending)
	}
	if sum.Alerts == nil || sum.Alerts.Days != 7 {
		t.Fatalf("alerts = %+v, want notify's counts", sum.Alerts)
	}
}
