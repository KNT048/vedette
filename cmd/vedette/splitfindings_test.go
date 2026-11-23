package main

import (
	"testing"
	"time"

	"github.com/knt048/vedette/modules/findings"
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

// A split moves the finding with the software line it is on: the finding the device had (its id, the person's decision and note) is
// the restored device's again, not a new one beside a handled copy on the kept device, and nothing on the kept device names a line it
// no longer has.
func TestWiringSplitMovesTheFindingWithItsLine(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.kev("CVE-2026-1001", "Fortinet", "FortiOS")
	r, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", Name: "fw-hq", IP: "10.0.10.1"})
	if err != nil {
		t.Fatal(err)
	}
	fw := r.ID
	var id string
	if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT id FROM fnd_finding WHERE asset_id = ? AND cve = 'CVE-2026-1001'`, fw).Scan(&id); err != nil {
		t.Fatalf("the test needs the hand-added device's finding: %v", err)
	}
	const note = "the management interface is not reachable from outside"
	if n, _, err := s.d.Findings.Handle(ctx, []string{id}, findings.ResolutionMitigated, note, time.Time{}, "it@acme.example"); err != nil || n != 1 {
		t.Fatalf("handle: %d, %v", n, err)
	}
	vm := s.seen(t, "10.0.10.2", "02:00:00:00:10:02", "")
	if err := s.d.Inventory.Merge(ctx, "it@acme.example", vm, fw); err != nil {
		t.Fatal(err)
	}
	// a request about the finding still waiting for a decision, and one already carried out, while the finding is on the kept device
	for _, r := range [][2]string{{"r-pending", "pending"}, {"r-executed", "executed"}} {
		s.exec(`INSERT INTO resp_actions (id, source, proposal_id, finding_id, cve, asset_id, asset_name, title, risk, status, requested_at, expires_at, requires_approvals, items)
			VALUES (?, 'ai', 'p', ?, 'CVE-2026-1001', ?, 'fw', 'Block', 'low', ?, '2026-01-01T00:00:00.000Z', '2026-01-02T00:00:00.000Z', 1, '[]')`, r[0], id, vm, r[1])
	}
	back, err := s.d.Inventory.Split(ctx, "it@acme.example", vm, "10.0.10.1")
	if err != nil {
		t.Fatal(err)
	}
	// its items hold the kept device's address: approving it would act there under the restored device's name, so it is withdrawn
	if n := s.count(`SELECT count(*) FROM resp_actions WHERE id = 'r-pending' AND asset_id = ? AND status = 'expired' AND note LIKE 'Withdrawn:%'`, vm); n != 1 {
		t.Error("the request still waiting for a decision was not withdrawn on the device it was made for")
	}
	if n := s.count(`SELECT count(*) FROM resp_actions WHERE id = 'r-executed' AND asset_id = ?`, vm); n != 1 {
		t.Error("the request already carried out left the device it acted on")
	}
	f, err := s.d.Findings.Finding(ctx, id)
	if err != nil {
		t.Fatalf("the device's finding is gone after the split: %v", err)
	}
	if f.AssetID != back || f.State != findings.StateHandled || f.Resolution != findings.ResolutionMitigated || f.Note != note {
		t.Errorf("the finding after the split: device %s (want %s), %s %s, note %q", f.AssetID, back, f.State, f.Resolution, f.Note)
	}
	if n := s.count(`SELECT count(*) FROM inv_software WHERE id = ? AND asset_id = ?`, f.SoftwareID, back); n != 1 {
		t.Errorf("the finding names line %s, which is not the restored device's", f.SoftwareID)
	}
	if n := s.count(`SELECT count(*) FROM fnd_finding WHERE cve = 'CVE-2026-1001'`); n != 1 {
		t.Errorf("%d findings of the CVE, want the one that moved", n)
	}
	if n := s.count(`SELECT count(*) FROM fnd_finding_event WHERE finding_id = ? AND actor = 'it@acme.example'`, id); n == 0 {
		t.Error("the person's decision is not in the finding's history any more")
	}
	for _, q := range []string{
		`SELECT count(*) FROM fnd_finding f WHERE f.asset_id = ? AND f.software_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inv_software s WHERE s.id = f.software_id AND s.asset_id = f.asset_id)`,
		`SELECT count(*) FROM fnd_question q WHERE q.asset_id = ? AND q.software_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inv_software s WHERE s.id = q.software_id AND s.asset_id = q.asset_id)`,
	} {
		for _, dev := range []string{vm, back} {
			if n := s.count(q, dev); n != 0 {
				t.Errorf("%d rows of %s name a software line the device does not have: %s", n, dev, q)
			}
		}
	}
}
