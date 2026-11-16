package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
)

// cvssChunk bounds the CVEs of one read (one JSON parameter each).
const cvssChunk = 500

// applyCVSS stores the CVSS base scores of an nvd-kev pull (INV-28) in the pull's transaction: a full pull replaces the table; an
// update replaces the rows of the CVEs NVD answered for (answered), so a score NVD took away goes too. A CVE NVD rejected (a bad
// entry, ParseNVD) is not in answered and keeps its row.
func applyCVSS(ctx context.Context, tx *sql.Tx, answered map[string][]AffectedRow, got map[string]CVSS, full bool) error {
	if full && len(answered) > 0 {
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
	for _, cve := range slices.Sorted(maps.Keys(answered)) {
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

// cvssCount is how many CVEs have nvd-kev's score; 0 makes the next nvd-kev pull a full one (a box from before migration 0015).
func (s *Store) cvssCount(ctx context.Context) (int, error) {
	var n int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM feeds_cvss`).Scan(&n); err != nil {
		return 0, fmt.Errorf("feeds: count cvss: %w", err)
	}
	return n, nil
}

// CVSSOf returns the CVSS base score of each of these CVEs that has one (INV-28): nvd-kev's (feeds_cvss, the exploited lists),
// else nvd-recent's (feeds_recent_cve, any CVE of the last 12 months; Version and Source are "" for a row stored before migration
// 0015). A CVE without a score is absent: the pages say "No score", never 0.
func (s *Store) CVSSOf(ctx context.Context, cves []string) (map[string]CVSS, error) {
	out := make(map[string]CVSS, len(cves))
	for chunk := range slices.Chunk(cves, cvssChunk) {
		part, err := json.Marshal(chunk) // one parameter: the CVEs as a JSON array (json_each), no SQL built from strings
		if err != nil {
			return nil, fmt.Errorf("feeds: cvss: %w", err)
		}
		rs, err := s.db.Reader().QueryContext(ctx, `SELECT j.value,
  CASE WHEN c.cve IS NOT NULL THEN c.score ELSE r.score END,
  CASE WHEN c.cve IS NOT NULL THEN c.version ELSE coalesce(r.cvss_version, '') END,
  CASE WHEN c.cve IS NOT NULL THEN c.source ELSE coalesce(r.cvss_source, '') END,
  CASE WHEN c.cve IS NOT NULL THEN c.vector ELSE coalesce(r.cvss_vector, '') END
FROM json_each(?) j LEFT JOIN feeds_cvss c ON c.cve = j.value LEFT JOIN feeds_recent_cve r ON r.cve = j.value AND r.score IS NOT NULL
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
