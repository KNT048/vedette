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
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, v := range vulns {
			if err := seedKEVRow(ctx, tx, v.CVE, v.Vendor, v.Product, v.Name, v.DateAdded, false, false); err != nil {
				return err
			}
			if err := seedNVD(ctx, tx, v.CVE, v.DateAdded.AddDate(0, 0, -7), 9.8); err != nil {
				return err
			}
			for _, a := range v.Affected {
				r := a.Range
				if err := seedRange(ctx, tx, v.CVE, a.CPE, r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl); err != nil {
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
