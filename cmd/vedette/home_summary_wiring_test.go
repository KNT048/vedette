package main

import (
	"testing"
)

// The binary gives GET /findings/overview inventory's device counts and notify's sent messages and open incidents (findings imports neither).
func TestWiringHomeSummaryCarriesDevicesAndAlerts(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.addFortiGate()
	sum, err := s.d.FindingHandlers.Overview(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	total, pending, err := s.d.Inventory.DeviceCounts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if total == 0 || sum.Devices.Total != total || sum.Devices.NotAdded != pending {
		t.Fatalf("summary devices %+v, inventory %d/%d", sum.Devices, total, pending)
	}
	if sum.Alerts == nil || sum.Alerts.Days != 7 || sum.Incidents == nil {
		t.Fatalf("alerts = %+v, incidents = %+v, want notify's counts", sum.Alerts, sum.Incidents)
	}
}
