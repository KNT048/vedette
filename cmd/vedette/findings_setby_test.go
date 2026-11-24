package main

import (
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// The person who changes the version of a line they entered is named from inventory's match input (MatchSoftware.SetBy): their move
// past the fix is handled by them, not by Vedette, and the person who sets it back is named on the finding's reopen and its audit row.
func TestWiringAPersonsVersionChangeNamesThatPerson(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	const cve = "CVE-2026-7201"
	s.kevAdded(cve, "OpenBSD", "OpenSSH", time.Now().AddDate(0, -1, 0))
	s.exec(`UPDATE feeds_cve SET nvd_at = ?2, nvd_status = 'Analyzed' WHERE cve = ?1`, cve, store.FormatTS(time.Now().UTC()))
	s.exec(`INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl) VALUES (?, 'nvd', 'a', 'openbsd', 'openssh', 'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*', '', '', '', '10.6p2')`, cve)
	r, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6p1", Name: "jump-01", IP: "10.0.20.1"})
	if err != nil {
		t.Fatal(err)
	}
	var id, line string
	if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT id, software_id FROM fnd_finding WHERE asset_id = ? AND cve = ?`, r.ID, cve).Scan(&id, &line); err != nil {
		t.Fatalf("the test needs the hand-added device's finding: %v", err)
	}
	edit := func(who, version string) {
		t.Helper()
		if err := s.d.Inventory.EditSoftware(ctx, who, r.ID, line, inventory.SoftwareEdit{Version: &version}); err != nil {
			t.Fatal(err)
		}
	}
	edit("op@acme.example", "10.6p2")
	f, err := s.d.Findings.Finding(ctx, id)
	if err != nil || f.State != findings.StateHandled || f.Via != findings.ViaVersionMoved || f.ResolvedBy != "op@acme.example" {
		t.Fatalf("after the person's update: %s via %s by %q (%v), want handled via version_moved by op@acme.example", f.State, f.Via, f.ResolvedBy, err)
	}
	edit("lead@acme.example", "9.6p1")
	if f, err := s.d.Findings.Finding(ctx, id); err != nil || f.State != findings.StateOpen {
		t.Fatalf("after the version was set back: %s (%v), want open", f.State, err)
	}
	if n := s.count(`SELECT count(*) FROM core_audit WHERE user = 'lead@acme.example' AND detail LIKE '%the version was set back by lead@acme.example'`); n != 1 {
		t.Errorf("%d audit rows naming the person who set the version back, want 1", n)
	}
}
