package main

import (
	"testing"
	"time"

	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// G4 (kien): the Devices list's risk marker comes from findings through the wiring (findingCounts.RiskByAsset, the same rule as
// Findings › To fix): a device with a finding the box proved is "exploited"; a clean one has none; findings off marks nothing.
func TestDeviceRiskThroughTheWiring(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.setModule("inventory", true)
	s.setModule("findings", true)
	s.kev("CVE-2024-21762", "Fortinet", "FortiOS")
	fw, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", Name: "fw-hq", IP: "192.168.30.1"})
	if err != nil {
		t.Fatal(err)
	}
	clean, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{Vendor: "Acme", Product: "Widget", Name: "widget", IP: "192.168.30.2"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.d.Findings.ConfirmFromScan(ctx, fw.ID, "CVE-2024-21762", findings.Evidence{Summary: "x", Template: "CVE-2024-21762", CheckedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	risks := func(f inventory.DeviceFilter) map[string]*inventory.Risk {
		t.Helper()
		l, err := s.d.Inventory.DevicesPage(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]*inventory.Risk{}
		for _, d := range l.Items {
			out[d.ID] = d.Risk
		}
		return out
	}
	got := risks(inventory.DeviceFilter{})
	if r := got[fw.ID]; r == nil || r.Level != inventory.RiskExploited || r.Exploited != 1 {
		t.Fatalf("fw-hq risk = %+v", r)
	}
	if got[clean.ID] != nil {
		t.Fatalf("clean device risk = %+v", got[clean.ID])
	}
	// the same value as To fix shows for the device
	tf, err := s.d.Findings.ToFix(ctx, true, fw.ID)
	if err != nil || len(tf.Devices) != 1 || findings.RiskOf(tf.Devices[0]).Exploited != 1 {
		t.Fatalf("To fix = %+v, %v", tf, err)
	}
	if d, err := s.d.Inventory.DetailPage(ctx, fw.ID); err != nil || d.Risk == nil || d.Risk.Exploited != 1 {
		t.Fatalf("detail risk = %+v, %v", d.Risk, err)
	}
	f, err := inventory.ParseDeviceSearch("", "", "", "", "", "exploited", "")
	if err != nil {
		t.Fatal(err)
	}
	if only := risks(f); len(only) != 1 || only[fw.ID] == nil {
		t.Fatalf("risk=exploited = %v", only)
	}
	s.setModule("findings", false)
	if r := risks(inventory.DeviceFilter{})[fw.ID]; r != nil {
		t.Fatalf("findings off: %+v", r)
	}
}
