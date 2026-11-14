package main

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// D-516 end to end: the feeds' distribution rows and the inventory's full package version reach the matcher. A packaged
// OpenSSH below Ubuntu's fixed version is a version finding that names the fix; after the package update (the upstream
// number stays 9.6p1) the finding closes by itself.
func TestDistroFixReachesFindings(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	const cve = "CVE-2026-7101"
	s.kevAdded(cve, "OpenBSD", "OpenSSH", time.Now().AddDate(0, -1, 0))
	now := store.FormatTS(time.Now().UTC())
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO feeds_affected_cve (cve, updated_at) VALUES (?, ?)`, []any{cve, now}},
			{`INSERT INTO feeds_affected (cve, cpe, start_incl, start_excl, end_incl, end_excl) VALUES (?, 'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*', '', '', '', '10.6p2')`, []any{cve}},
			{`INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version) VALUES ('ubuntu-osv', 'ubuntu', '24.04', 'openssh', ?, 'fixed', '1:9.6p1-3ubuntu13.5')`, []any{cve}},
		} {
			if _, err := tx.ExecContext(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.d.Inventory.EnsureBox(ctx, inventory.BoxInfo{Hostname: "web-01", OS: "Ubuntu 24.04"})
	if err != nil {
		t.Fatal(err)
	}
	install := func(full string) {
		t.Helper()
		it := inventory.SoftwareItem{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6p1", KevKeys: []string{"openbsd|openssh"}, Confidence: 0.95,
			Packaged: true, PkgVersion: full, PkgSource: "openssh"}
		if err := s.d.Inventory.UpsertSoftware(ctx, id, []inventory.SoftwareItem{it}, "agent"); err != nil {
			t.Fatal(err)
		}
		if err := findingsJobs(*s.d)[0].Run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	finding := func() findings.Record {
		t.Helper()
		recs, err := s.d.Findings.List(ctx, id)
		if err != nil || len(recs) != 1 || recs[0].CVE != cve {
			t.Fatalf("findings %+v %v", recs, err)
		}
		return recs[0]
	}
	install("1:9.6p1-3ubuntu13.4")
	if f := finding(); f.Status != findings.StatusSuspected || f.Basis != findings.BasisVersion || !strings.Contains(f.Evidence.Summary, "Ubuntu fixed "+cve+" in openssh 1:9.6p1-3ubuntu13.5") {
		t.Fatalf("below the fix: %+v", f)
	}
	install("1:9.6p1-3ubuntu13.14")
	if f := finding(); f.Status != findings.StatusNotRelevant || f.ResolutionReason != findings.ReasonNotAffectedVersion || !strings.Contains(f.ResolutionNote, "this device has 1:9.6p1-3ubuntu13.14") {
		t.Fatalf("after the update: %+v", f)
	}
}
