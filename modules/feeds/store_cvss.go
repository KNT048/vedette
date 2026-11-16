package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
)

// cvssChunk bounds the CVEs of one read (one JSON parameter each).
const cvssChunk = 500

// applyCVSS stores the CVSS base scores of an nvd-kev pull (INV-28) in the pull's transaction: a full pull replaces the table; an
// update replaces the rows of the CVEs NVD answered for (seen), so a score NVD took away goes too. A CVE rejected for its affected
// entries is in seen and keeps its score (review r1 L2).
func applyCVSS(ctx context.Context, tx *sql.Tx, seen map[string]bool, got map[string]CVSS, full bool) error {
	if full && len(seen) > 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_cvss`); err != nil {
			return fmt.Errorf("feeds: cvss: %w", err)
		}
	}
	up, err := tx.PrepareContext(ctx, `INSERT INTO feeds_cvss (cve, score, version, source, vector) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(cve) DO UPDATE SET score = excluded.score, version = excluded.version, source = excluded.source, vector = excluded.vector`)
	if err != nil {
		return fmt.Errorf("feeds: cvss: %w", err)
	}
	defer func() { _ = up.Close() }()
	for _, cve := range slices.Sorted(maps.Keys(seen)) {
		c, ok := got[cve]
		if !ok {
			if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_cvss WHERE cve = ?`, cve); err != nil {
				return fmt.Errorf("feeds: cvss %s: %w", cve, err)
			}
			continue
		}
		if _, err := up.ExecContext(ctx, cve, c.Score, c.Version, c.Source, c.Vector); err != nil {
			return fmt.Errorf("feeds: cvss %s: %w", cve, err)
		}
	}
	return nil
}

// fullDue says a migration asked for one full pull of the feed (feeds_source.full_due, migration 0015 for nvd-kev, INV-28).
func (s *Store) fullDue(ctx context.Context, id string) (bool, error) {
	var due bool
	err := s.db.Reader().QueryRowContext(ctx, `SELECT full_due FROM feeds_source WHERE id = ?`, id).Scan(&due)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("feeds: full pull due: %w", err)
	}
	return due, nil
}

// CVSSOf returns the CVSS base score of each of these CVEs that has one (INV-28): nvd-kev's (feeds_cvss, the exploited lists),
// else nvd-recent's (feeds_recent_cve.cvss_*, any CVE of the last 12 months). Every score comes with its version, source and
// vector. A CVE without a score is absent: the pages say "No CVSS score", never 0.
func (s *Store) CVSSOf(ctx context.Context, cves []string) (map[string]CVSS, error) {
	out := make(map[string]CVSS, len(cves))
	for chunk := range slices.Chunk(cves, cvssChunk) {
		part, err := json.Marshal(chunk) // one parameter: the CVEs as a JSON array (json_each), no SQL built from strings
		if err != nil {
			return nil, fmt.Errorf("feeds: cvss: %w", err)
		}
		rs, err := s.db.Reader().QueryContext(ctx, `SELECT j.value,
  CASE WHEN c.cve IS NOT NULL THEN c.score ELSE r.cvss_score END,
  CASE WHEN c.cve IS NOT NULL THEN c.version ELSE r.cvss_version END,
  CASE WHEN c.cve IS NOT NULL THEN c.source ELSE r.cvss_source END,
  CASE WHEN c.cve IS NOT NULL THEN c.vector ELSE r.cvss_vector END
FROM json_each(?) j LEFT JOIN feeds_cvss c ON c.cve = j.value LEFT JOIN feeds_recent_cve r ON r.cve = j.value AND r.cvss_score IS NOT NULL
WHERE c.cve IS NOT NULL OR r.cve IS NOT NULL`, string(part))
		if err != nil {
			return nil, fmt.Errorf("feeds: cvss: %w", err)
		}
		for rs.Next() {
			var cve string
			var c CVSS
			if err := rs.Scan(&cve, &c.Score, &c.Version, &c.Source, &c.Vector); err != nil {
				_ = rs.Close()
				return nil, fmt.Errorf("feeds: cvss: %w", err)
			}
			out[cve] = c
		}
		err = rs.Err()
		_ = rs.Close()
		if err != nil {
			return nil, fmt.Errorf("feeds: cvss: %w", err)
		}
	}
	return out, nil
}
