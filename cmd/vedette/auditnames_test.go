package main

import (
	"testing"
	"time"

	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// D-416: Settings → Audit log names a device by its host name and a finding as "<CVE> on <device>"; ids the box does not have are left out.
func TestAuditNamerNamesDevicesAndFindings(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.setModule("inventory", true)
	s.setModule("findings", true)
	s.kev("CVE-2024-21762", "Fortinet", "FortiOS")
	add, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", Name: "fw-hq", IP: "192.168.30.1"})
	if err != nil {
		t.Fatal(err)
	}
	f, err := s.d.Findings.ConfirmFromScan(ctx, add.ID, "CVE-2024-21762", findings.Evidence{Summary: "x", Template: "CVE-2024-21762", CheckedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	names, err := auditNamer{d: s.d}.AuditNames(ctx, []string{add.ID, f.ID, "a-gone", "f-gone"})
	if err != nil {
		t.Fatal(err)
	}
	if names[add.ID] != "fw-hq" || names[f.ID] != "CVE-2024-21762 on fw-hq" || len(names) != 2 {
		t.Fatalf("names = %v", names)
	}
}
