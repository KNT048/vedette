package main

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/selfcheck"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
)

// The self-check of a box filled by the fixture replay prints all zeros. The box is the binary's real wiring; the catalogue is the
// whole CISA KEV list with NVD's affected entries of each CVE as a test box held them (testdata/kev-nvd-2026-11-16.json.gz); the
// inventory is the anonymised test-network inventory replayed through the write paths (modules/inventory/testdata/software_lines.json,
// people's corrections included); then the match pass and the urgency pass run as the scheduler runs them. `vedette selfcheck` then
// reads the database file the way it reads a box's.
//
// VEDETTE_SELFCHECK_DB=<path> keeps the replayed database at path, for `vedette selfcheck -db <path>` by hand.
func TestSelfcheck_FixtureReplayHoldsEveryInvariant(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	s := newStack(t)
	devices, _ := replaySoftwareLines(t, s) // before the catalogue: the hourly pass below matches every device once
	vulns := loadReachFixture(t)
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error { // as seedKEVRow, seedNVD and seedRange write them, through prepared statements
		now := store.FormatTS(time.Now().UTC())
		var stmts []*sql.Stmt
		prep := func(q string) *sql.Stmt {
			st, perr := tx.PrepareContext(ctx, q)
			if perr != nil {
				t.Fatal(perr)
			}
			stmts = append(stmts, st)
			return st
		}
		defer func() {
			for _, st := range stmts {
				_ = st.Close()
			}
		}()
		cve := prep(`INSERT INTO feeds_cve (cve, published, modified, nvd_status, nvd_at, updated_at) VALUES (?, ?, ?, 'Analyzed', ?, ?)`)
		kev := prep(`INSERT INTO feeds_kev (cve, list, source_id, vendor, product, name, date_added, ransomware, updated_at) VALUES (?, 'cisa', 'cisa-kev', ?, ?, ?, ?, 0, ?)`)
		signal := prep(`INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies) VALUES (?, 'exploited', 'cisa-kev', ?, ?, ?, 1)`)
		metric := prep(`INSERT INTO feeds_cve_metric (cve, source, version, score, vector) VALUES (?, 'nvd', '3.1', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')`)
		rng := prep(`INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, platforms) VALUES (?, 'nvd', ?, ?, ?, ?, ?, ?, ?, ?, '[]')`)
		for _, v := range vulns {
			added := v.DateAdded.Format(time.DateOnly)
			if _, err := cve.ExecContext(ctx, v.CVE, store.FormatTS(v.DateAdded.AddDate(0, 0, -7)), now, now, now); err != nil {
				return err
			}
			if _, err := kev.ExecContext(ctx, v.CVE, v.Vendor, v.Product, v.Name, added, now); err != nil {
				return err
			}
			if _, err := signal.ExecContext(ctx, v.CVE, added+"T00:00:00.000Z", now, now); err != nil {
				return err
			}
			if _, err := metric.ExecContext(ctx, v.CVE); err != nil {
				return err
			}
			for _, a := range v.Affected {
				f := strings.SplitN(strings.TrimPrefix(a.CPE, "cpe:2.3:"), ":", 4)
				for len(f) < 3 {
					f = append(f, "")
				}
				r := a.Range
				if _, err := rng.ExecContext(ctx, v.CVE, f[0], strings.ToLower(f[1]), strings.ToLower(f[2]), a.CPE, r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.d.Findings.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC()
	if err := urgencyJob(t, s).Run(ctx); err != nil {
		t.Fatal(err)
	}
	s.exec(`INSERT INTO core_job_run (id, module, job, started_at, finished_at, status) VALUES ('jr-urgency-replay', 'findings', ?, ?, ?, 'ok')`,
		findings.UrgencyJob, store.FormatTS(started), store.FormatTS(time.Now().UTC().Add(time.Millisecond)))

	counts := map[string]int{}
	for _, tbl := range []string{"feeds_kev", "feeds_cve_range", "inv_asset", "inv_software", "inv_software_reading", "fnd_finding", "fnd_finding_event", "fnd_question", "core_schedule"} {
		counts[tbl] = s.count(`SELECT count(*) FROM "` + tbl + `"`)
	}
	t.Logf("replayed: %d devices; rows %v", len(devices), counts)
	if counts["fnd_finding"] == 0 || counts["inv_software"] == 0 || counts["feeds_kev"] != len(vulns) {
		t.Fatalf("the replay wrote too little to check: %v", counts)
	}

	path := os.Getenv("VEDETTE_SELFCHECK_DB")
	if path == "" {
		path = filepath.Join(t.TempDir(), "replay.db")
	}
	_ = os.Remove(path) //nolint:gosec // a path the person running the test names, or the test's own temp file
	if err := s.d.DB.SnapshotTo(ctx, path); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := selfcheck.Command(ctx, path, selfcheck.Registered(), &out); err != nil {
		t.Errorf("selfcheck on the replayed box: %v\n%s", err, out.String())
	}
	t.Logf("vedette selfcheck on the replayed box:\n%s", strings.TrimSpace(out.String()))
}
