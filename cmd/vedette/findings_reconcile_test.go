package main

import (
	"slices"
	"testing"

	"github.com/knt048/vedette/modules/inventory"
)

// findings' reconcile job (D-144) is wired for the module, and its device list is every device of the real inventory.
func TestFindingsReconcileJobAndDeviceList(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	jobs := findingsJobs(*s.d)
	if len(jobs) != 1 || jobs[0].Module != "findings" || jobs[0].Name != "reconcile" {
		t.Fatalf("jobs = %+v", jobs)
	}
	var want []string
	for i, ip := range []string{"192.168.50.1", "192.168.50.2"} {
		r, err := s.d.Inventory.AddDevice(t.Context(), "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Name: []string{"fw-a", "fw-b"}[i], IP: ip})
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, r.ID)
	}
	got, err := findingsInventory{s.d.Inventory}.AssetIDs(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range want {
		if !slices.Contains(got, id) {
			t.Fatalf("AssetIDs = %v, missing %s", got, id)
		}
	}
}
