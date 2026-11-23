package main

import (
	"testing"

	"github.com/knt048/vedette/modules/findings"
)

// A device nobody approved still has findings, marked "not added yet" (asset.approved false); Ignore hides the device and all its
// findings, a sighting of it later makes none; Restore (stop ignoring) shows them again at once.
func TestWiringFindingsOfADeviceNotAddedYet(t *testing.T) {
	t.Parallel()
	s, cves, lldp := junosSwitch(t)
	ctx := t.Context()
	lldp()
	if n := s.nf("", ""); n != len(cves) {
		t.Fatalf("%d findings for an unapproved device, want %d", n, len(cves))
	}
	list, err := s.d.Inventory.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, d := range list.Items {
		if !d.IsBox {
			id = d.ID
		}
	}
	if id == "" {
		t.Fatal("no device")
	}
	c, b := s.do("GET", "/findings?asset="+id, "viewer", "")
	if c != 200 || at(b, "items", 0, "asset", "approved") != false || at(b, "items", 0, "asset", "ignored") != false {
		t.Fatalf("the finding's device: %d %v", c, at(b, "items", 0, "asset"))
	}
	if err := s.d.Inventory.SetIgnored(ctx, "it@acme.example", id, true); err != nil {
		t.Fatal(err)
	}
	c, b = s.do("GET", "/findings?asset="+id, "viewer", "")
	if c != 200 || at(b, "items", 0, "asset", "ignored") != true {
		t.Fatalf("an ignored device's findings are not marked: %d %v", c, at(b, "items", 0, "asset"))
	}
	open := func() int {
		return s.count(`SELECT count(*) FROM fnd_finding WHERE state = 'open'`)
	}
	if open() != len(cves) { // ignoring is an attribute of the device: its findings stay as they are, every list leaves them out
		t.Fatalf("%d findings open on the ignored device, want them kept: %d", open(), len(cves))
	}
	lldp() // seen again: the same device, still ignored, nothing new
	if err := findingsJobs(*s.d)[0].Run(ctx); err != nil {
		t.Fatal(err)
	}
	if open() != len(cves) || s.nf("", "") != len(cves) {
		t.Fatalf("after the sighting: %d open, %d findings", open(), s.nf("", ""))
	}
	if err := s.d.Inventory.SetIgnored(ctx, "it@acme.example", id, false); err != nil {
		t.Fatal(err)
	}
	if open() != len(cves) {
		t.Fatalf("Restore left %d findings open, want %d", open(), len(cves))
	}
	recs, _ := s.d.Findings.List(ctx, id)
	if len(recs) == 0 || recs[0].Status == findings.StatusNotRelevant {
		t.Fatalf("restored findings: %+v", recs)
	}
}
