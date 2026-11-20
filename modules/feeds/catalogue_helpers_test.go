package feeds

import (
	"context"
	"database/sql"
	"fmt"
	"maps"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// applyAffected writes NVD answers of these CVEs into the catalogue as an NVD pull does (writeNVDRecords), whatever their age: the
// NVD ranges of each CVE are replaced by its rows (none: NVD answered without a vulnerable entry); the CVE's dates stay as stored. It
// returns the CVEs whose NVD ranges changed. The full flag of the old store is
// ignored: the catalogue never drops a CVE because one NVD pull did not return it.
func applyAffected(ctx context.Context, tx *sql.Tx, got map[string][]AffectedRow, _ bool, now time.Time) (changed []string, err error) {
	recs := make([]NVDRecord, 0, len(got))
	for _, cve := range slices.Sorted(maps.Keys(got)) {
		rows := got[cve]
		if rows == nil {
			rows = []AffectedRow{}
		}
		r := NVDRecord{CVE: cve, Status: "Analyzed", Affected: rows}
		var known bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM feeds_cve WHERE cve = ? AND nvd_at IS NOT NULL)`, cve).Scan(&known); err != nil {
			return nil, err
		}
		same, err := sameNVDRanges(ctx, tx, r)
		if err != nil {
			return nil, err
		}
		if !same || !known {
			changed = append(changed, cve)
		}
		recs = append(recs, r)
	}
	_, err = writeNVDRecords(ctx, tx, recs, retention{all: true}, now)
	return changed, err
}

// applyPublished sets the published day NVD gives these CVEs (a catalogue row is made when there is none).
func applyPublished(ctx context.Context, tx *sql.Tx, got map[string]string) error {
	for _, cve := range slices.Sorted(maps.Keys(got)) {
		if err := ensureCVE(ctx, tx, cve, "2026-01-01T00:00:00.000Z"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET published = ? WHERE cve = ?`, got[cve]+"T00:00:00.000Z", cve); err != nil {
			return fmt.Errorf("published %s: %w", cve, err)
		}
	}
	return nil
}

// affectedCount is how many catalogue CVEs NVD answered for.
func (s *Store) affectedCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM feeds_cve WHERE nvd_at IS NOT NULL`).Scan(&n)
	return n, err
}

// readAffected is the stored NVD ranges of the CVEs, by CVE.
func readAffected(ctx context.Context, q queryer, where string, args ...any) (map[string][]AffectedRow, error) {
	rows, err := readRanges(ctx, q, where, args...)
	if err != nil {
		return nil, err
	}
	out := map[string][]AffectedRow{}
	for _, r := range rows {
		if r.Origin == OriginNVD {
			out[r.CVE] = append(out[r.CVE], r.AffectedRow())
		}
	}
	return out, nil
}

// templateList is the nuclei templates of these CVEs, without links.
func templateList(cves ...string) []Template {
	out := make([]Template, len(cves))
	for i, c := range cves {
		out[i] = Template{CVE: c}
	}
	return out
}

// storeRecords writes NVD records into the catalogue with the retention rule of now.
func storeRecords(ctx context.Context, tx *sql.Tx, recs []NVDRecord, now time.Time) error {
	ret, err := retentionOf(ctx, tx, now, nil)
	if err != nil {
		return err
	}
	_, err = writeNVDRecords(ctx, tx, recs, ret, now)
	return err
}

// epssDayForTests is FIRST's day of the scores applyEPSS stores; the "week ago" scores are of seven days before it.
const epssDayForTests = "2026-11-05"

// applyEPSS stores today's EPSS scores (feeds_epss, the store epss-all writes) and the scores of a week before (feeds_epss_hist) of
// these CVEs. It returns how many of latest are on an exploited list.
func applyEPSS(ctx context.Context, tx *sql.Tx, latest, ago map[string]float64) (int, error) {
	if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_epss_baseline (id, url, count, score_date) VALUES (1, 'https://epss.example.com/x.csv.gz', ?, ?)
ON CONFLICT(id) DO UPDATE SET count = excluded.count, score_date = excluded.score_date`, len(latest), epssDayForTests); err != nil {
		return 0, err
	}
	n := 0
	for _, cve := range slices.Sorted(maps.Keys(latest)) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_epss (cve, epss, percentile, gen) VALUES (?, ?, 0.5, 1)
ON CONFLICT(cve) DO UPDATE SET epss = excluded.epss`, cve, latest[cve]); err != nil {
			return 0, err
		}
		var on bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM feeds_kev WHERE cve = ?)`, cve).Scan(&on); err != nil {
			return 0, err
		}
		if on {
			n++
		}
	}
	for _, cve := range slices.Sorted(maps.Keys(ago)) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_epss_hist (cve, day, epss) VALUES (?, date(?, '-7 days'), ?)
ON CONFLICT(cve, day) DO UPDATE SET epss = excluded.epss`, cve, epssDayForTests, ago[cve]); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// byCVE is the records of a page by CVE.
func byCVE(d NVDPage) map[string]NVDRecord {
	out := map[string]NVDRecord{}
	for _, r := range d.Records {
		out[r.CVE] = r
	}
	return out
}

// pageCVSS is the picked score of each record of a page that has one (PickCVSS).
func pageCVSS(d NVDPage) map[string]CVSS {
	out := map[string]CVSS{}
	for _, r := range d.Records {
		if c, ok := r.CVSS(); ok {
			out[r.CVE] = c
		}
	}
	return out
}

// seedKEV puts CVE-2024-0000 … CVE-2024-<n-1> on the CISA list, so the catalogue keeps their NVD records (the retention rule).
func seedKEV(t testing.TB, db *store.DB, n int) {
	t.Helper()
	vs := make([]Vuln, n)
	for i := range vs {
		vs[i] = vuln(fmt.Sprintf("CVE-2024-%04d", i), "Acme", "Box", "2024-02-01")
	}
	applyV(t, db, epoch0, "cisa-kev", vs, false)
}

func writeFile(path, s string) error { return os.WriteFile(path, []byte(s), 0o600) }
