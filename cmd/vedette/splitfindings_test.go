package main

import (
	"testing"

	"github.com/knt048/vedette/modules/inventory"
)

// openOn counts the open findings of a device, from the findings rows.
func (s *stack) openOn(assetID string) int {
	s.t.Helper()
	return s.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = ? AND state = 'open'`, assetID)
}

// A device added by hand and merged into a found one brings its software and so its findings; splitting its address off gives the
// software back, and the findings follow it through the software events: open on the device given back, closed on the one that kept
// none of that software.
func TestWiringSplitGivesTheMergedDeviceItsFindingsBack(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.kev("CVE-2026-1001", "Fortinet", "FortiOS")
	r, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", Name: "fw-hq", IP: "10.0.10.1"})
	if err != nil {
		t.Fatal(err)
	}
	fw := r.ID
	if s.openOn(fw) != 1 {
		t.Fatal("the test needs the hand-added device's finding")
	}
	vm := s.seen(t, "10.0.10.2", "02:00:00:00:10:02", "")
	if err := s.d.Inventory.Merge(ctx, "it@acme.example", vm, fw); err != nil {
		t.Fatal(err)
	}
	if s.openOn(vm) != 1 {
		t.Fatalf("the merge did not move the finding: %d open on the kept device", s.openOn(vm))
	}
	back, err := s.d.Inventory.Split(ctx, "it@acme.example", vm, "10.0.10.1")
	if err != nil {
		t.Fatal(err)
	}
	if back != fw {
		t.Fatalf("split gave %s, want %s", back, fw)
	}
	if n := s.openOn(back); n != 1 {
		t.Errorf("open findings on the device given back: %d, want 1", n)
	}
	if n := s.openOn(vm); n != 0 {
		t.Errorf("open findings left on the kept device: %d, want 0", n)
	}
}
