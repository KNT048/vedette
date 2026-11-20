package main

import (
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// Review r1 #1 of #804: a version change of a product with no exploited-list key emits only inventory.software.changed, and
// "Updates to plan" still follows it at the next run of the plan job, without waiting for the hourly full pass. Through the real
// inventory and bus, not by calling findings.
func TestWiringPlanFollowsASoftwareVersionChange(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.kevAdded("CVE-2024-1111", "Acme", "Gizmo", time.Now().AddDate(0, -2, 0)) // the exploited list is loaded, with nothing of this device
	now := time.Now().UTC()
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO feeds_cve (cve, published, modified, nvd_status, nvd_at, updated_at) VALUES ('CVE-2026-50001', ?1, ?2, 'Analyzed', ?2, ?2)`,
				[]any{store.FormatTS(now.AddDate(0, 0, -30)), store.FormatTS(now.AddDate(0, 0, -20))}},
			{`INSERT INTO feeds_cve_metric (cve, source, version, score, vector) VALUES ('CVE-2026-50001', 'nvd', '3.1', 8.1, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H')`, nil},
			{`INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, platforms) VALUES ('CVE-2026-50001', 'nvd', 'o', 'fortinet', 'fortios', 'cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*', '7.2.0', '', '', '7.2.9', '[]')`, nil},
			{`INSERT INTO feeds_nvd_cursor (selector, url, mode, win_from, win_to, until, next_index, total) VALUES ('recent', 'https://services.nvd.nist.gov/rest/json/cves/2.0', 'done', ?1, ?1, ?1, 0, 0)`,
				[]any{store.FormatTS(now)}},
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
	id := s.addFortiGate() // FortiOS 7.2.5, typed by a person
	plan := findingsJobs(*s.d)[1]
	if err := plan.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if v := s.d.Findings.Plan(); len(v.Items) != 1 || v.Items[0].Fixed != "7.2.9" {
		t.Fatalf("first pass: %+v", v)
	}
	a, ok, err := s.d.Inventory.MatchInput(ctx, id)
	if err != nil || !ok || len(a.Software) == 0 {
		t.Fatalf("device %+v %v %v", a, ok, err)
	}
	if err := s.d.Inventory.SetSoftwareVersion(ctx, "it@acme.example", id, a.Software[0].ID, "7.2.9"); err != nil {
		t.Fatal(err)
	}
	if err := plan.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if v := s.d.Findings.Plan(); len(v.Items) != 0 || v.Compared != 1 {
		t.Fatalf("after the upgrade the item must go at the next run: %+v", v)
	}
}
