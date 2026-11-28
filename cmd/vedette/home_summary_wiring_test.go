package main

import (
	"strings"
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

// Home shows the box's first look: the overview carries notify's first-run summary while it waits in the queue (the box has a channel),
// and the API answer passes the contract.
func TestWiringHomeSummaryCarriesTheFirstRunSummary(t *testing.T) {
	t.Parallel()
	s := newStack(t) // notify first ran now: the box's first run
	s.telegramOn()
	seedUrgencyCatalogue(t, s)
	seedExploitedClaims(s)
	s.addFortiGate()
	sum, err := s.d.FindingHandlers.Overview(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f := sum.FirstRun
	if f == nil || f.Load != "install" || f.State != "waiting" || f.Title != "Patch first: 2 urgent findings on 1 device" || f.DueAt == nil ||
		f.SentAt != nil || f.NotSent != nil || f.Channels == nil || !strings.HasPrefix(f.Link, "/findings?tab=device") {
		t.Fatalf("first-run summary = %+v", f)
	}
	ok, err := s.d.FindingHandlers.FindingsGetFindingsOverview(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if v, set := ok.FirstRunSummary.Get(); !set || v.Title != f.Title || string(v.State) != "waiting" {
		t.Fatalf("API first_run_summary = %+v", ok.FirstRunSummary)
	}
}
