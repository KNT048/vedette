package feeds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/store"
)

// applyAffected stores the NVD entries of a pull (D-500): the rows of every CVE in got are replaced; a full pull
// also drops the CVEs it did not get (NVD no longer lists them with hasKev). NVD's ranges replace CVE.org's (D-556),
// but an NVD answer without a vulnerable entry keeps the CVE.org ranges a CVE has. It returns how many CVEs changed
// and how many CVEs have NVD's answer afterwards.
func applyAffected(ctx context.Context, tx *sql.Tx, got map[string][]AffectedRow, full bool, now time.Time) (changed []string, total int, err error) {
	if full {
		if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE IF NOT EXISTS feeds_affected_keep (cve TEXT PRIMARY KEY)`); err != nil {
			return nil, 0, fmt.Errorf("feeds: affected: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_affected_keep`); err != nil {
			return nil, 0, fmt.Errorf("feeds: affected: %w", err)
		}
		for cve := range got {
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_affected_keep (cve) VALUES (?)`, cve); err != nil {
				return nil, 0, fmt.Errorf("feeds: affected: %w", err)
			}
		}
		// the CVEs NVD no longer lists are news too: a device closed on their old ranges is matched again (review LOW of #663)
		rows, err := tx.QueryContext(ctx, `SELECT cve FROM feeds_affected_cve WHERE source = 'nvd' AND cve NOT IN (SELECT cve FROM feeds_affected_keep)`)
		if err != nil {
			return nil, 0, fmt.Errorf("feeds: affected: %w", err)
		}
		for rows.Next() {
			var cve string
			if err := rows.Scan(&cve); err != nil {
				_ = rows.Close()
				return nil, 0, fmt.Errorf("feeds: affected: %w", err)
			}
			changed = append(changed, cve)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return nil, 0, fmt.Errorf("feeds: affected: %w", err)
		}
		for _, q := range []string{
			`DELETE FROM feeds_affected WHERE cve IN (SELECT cve FROM feeds_affected_cve WHERE source = 'nvd' AND cve NOT IN (SELECT cve FROM feeds_affected_keep))`,
			`DELETE FROM feeds_affected_cve WHERE source = 'nvd' AND cve NOT IN (SELECT cve FROM feeds_affected_keep)`,
			`DELETE FROM feeds_affected_keep`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return nil, 0, fmt.Errorf("feeds: affected: %w", err)
			}
		}
	}
	ts := store.FormatTS(now)
	for cve, rows := range got {
		src, err := affectedSource(ctx, tx, cve)
		if err != nil {
			return nil, 0, err
		}
		if src != rangesNVD && src != "" && len(rows) == 0 {
			continue // NVD has no vulnerable entry yet: the CNA's CVE.org ranges stay (D-556)
		}
		same, err := sameAffected(ctx, tx, cve, rangesNVD, rows)
		if err != nil {
			return nil, 0, err
		}
		if same {
			continue
		}
		changed = append(changed, cve)
		if err := putAffected(ctx, tx, cve, rangesNVD, rows, ts); err != nil {
			return nil, 0, err
		}
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM feeds_affected_cve WHERE source = 'nvd'`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("feeds: affected: %w", err)
	}
	return changed, total, nil
}

// Where the ranges of a CVE come from (feeds_affected_cve.source, D-556): NVD, or the CNA's CVE.org record whose list is
// complete (CVEOrgResult.Complete) or partial.
const (
	rangesNVD           = "nvd"
	rangesCVEOrg        = "cve.org"
	rangesCVEOrgPartial = "cve.org-partial"
)

// affectedSource is the source of the stored ranges of cve, "" when the box has none.
func affectedSource(ctx context.Context, tx *sql.Tx, cve string) (string, error) {
	var src string
	err := tx.QueryRowContext(ctx, `SELECT source FROM feeds_affected_cve WHERE cve = ?`, cve).Scan(&src)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("feeds: affected: %w", err)
	}
	return src, nil
}

// putAffected replaces the stored ranges of cve with rows from src.
func putAffected(ctx context.Context, tx *sql.Tx, cve, src string, rows []AffectedRow, ts string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_affected WHERE cve = ?`, cve); err != nil {
		return fmt.Errorf("feeds: affected: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_affected_cve (cve, updated_at, source) VALUES (?, ?, ?)
ON CONFLICT(cve) DO UPDATE SET updated_at = excluded.updated_at, source = excluded.source`, cve, ts, src); err != nil {
		return fmt.Errorf("feeds: affected: %w", err)
	}
	for _, r := range rows {
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_affected (cve, cpe, start_incl, start_excl, end_incl, end_excl) VALUES (?, ?, ?, ?, ?, ?)`,
			cve, r.CPE, r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl); err != nil {
			return fmt.Errorf("feeds: affected: %w", err)
		}
	}
	return nil
}

// sameAffected reports whether the stored rows of cve are exactly rows from src (a CVE the source did not change is
// not news).
func sameAffected(ctx context.Context, tx *sql.Tx, cve, src string, rows []AffectedRow) (bool, error) {
	var known int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM feeds_affected_cve WHERE cve = ? AND source = ?`, cve, src).Scan(&known); err != nil {
		return false, fmt.Errorf("feeds: affected: %w", err)
	}
	if known == 0 {
		return false, nil
	}
	have, err := readAffected(ctx, tx, `WHERE cve = ?`, cve)
	if err != nil {
		return false, err
	}
	old := have[cve]
	if len(old) != len(rows) {
		return false, nil
	}
	for i := range rows {
		if old[i] != rows[i] {
			return false, nil
		}
	}
	return true, nil
}

func readAffected(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, where string, args ...any) (map[string][]AffectedRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT cve, cpe, start_incl, start_excl, end_incl, end_excl FROM feeds_affected `+where+` ORDER BY rowid`, args...)
	if err != nil {
		return nil, fmt.Errorf("feeds: read affected: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]AffectedRow{}
	for rows.Next() {
		var cve string
		var r AffectedRow
		if err := rows.Scan(&cve, &r.CPE, &r.StartIncl, &r.StartExcl, &r.EndIncl, &r.EndExcl); err != nil {
			return nil, fmt.Errorf("feeds: read affected: %w", err)
		}
		out[cve] = append(out[cve], r)
	}
	return out, rows.Err()
}

// KevAffected returns the NVD affected entries of the CISA list's CVEs (D-500), for findings. A CVE NVD has not
// answered for is absent; one NVD lists without a vulnerable entry is present with an empty list.
func (s *Store) KevAffected(ctx context.Context) (map[string][]AffectedRow, error) {
	out, err := readAffected(ctx, s.db.Reader(), `WHERE cve IN (SELECT cve FROM feeds_vuln WHERE source_id = 'cisa-kev')`)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT cve FROM feeds_affected_cve WHERE cve IN (SELECT cve FROM feeds_vuln WHERE source_id = 'cisa-kev')`)
	if err != nil {
		return nil, fmt.Errorf("feeds: read affected: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var cve string
		if err := rows.Scan(&cve); err != nil {
			return nil, fmt.Errorf("feeds: read affected: %w", err)
		}
		if _, ok := out[cve]; !ok {
			out[cve] = []AffectedRow{}
		}
	}
	return out, rows.Err()
}

// MatchStamp changes whenever what KevVulns, KevAffected and DistroFixes return may have changed: the last pull time and
// rev (turned on or off) of the feeds that write them (cisa-kev, first-epss, nvd-kev, cve-org and the distribution feeds of
// D-516; each written in the pull's own transaction), and the count and
// newest change of the CISA rows and of the NVD answers. findings
// (through cmd/vedette) keeps one read of the list per stamp, instead of reading 33k NVD rows per device (review H3).
func (s *Store) MatchStamp(ctx context.Context) (string, error) {
	var stamp sql.NullString
	err := s.db.Reader().QueryRowContext(ctx, `SELECT (SELECT group_concat(id || '=' || COALESCE(last_fetch, '') || '/' || rev, ',') FROM
(SELECT id, last_fetch, rev FROM feeds_source WHERE id IN ('cisa-kev', 'cve-org', 'debian-tracker', 'first-epss', 'nvd-kev', 'ubuntu-osv', 'ubuntu-vex') ORDER BY id))
|| ';' || (SELECT count(*) || '/' || COALESCE(max(updated_at), '') FROM feeds_vuln WHERE source_id = 'cisa-kev')
|| ';' || (SELECT count(*) || '/' || COALESCE(max(updated_at), '') FROM feeds_affected_cve)`).Scan(&stamp)
	if err != nil {
		return "", fmt.Errorf("feeds: match stamp: %w", err)
	}
	return stamp.String, nil
}

// affectedCount is how many CVEs have NVD's answer.
func (s *Store) affectedCount(ctx context.Context) (int, error) {
	var n int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM feeds_affected_cve WHERE source = 'nvd'`).Scan(&n); err != nil {
		return 0, fmt.Errorf("feeds: count affected: %w", err)
	}
	return n, nil
}

// RangesFromCVEOrg returns the CVEs whose affected versions (KevAffected) come from the CNA's record on CVE.org, not
// from NVD (D-556), with their source: "cve.org" (a complete list) or "cve.org-partial" (findings may raise a match on
// it, never close one), so findings names the right source and knows what the rows can prove.
func (s *Store) RangesFromCVEOrg(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT cve, source FROM feeds_affected_cve WHERE source <> 'nvd'`)
	if err != nil {
		return nil, fmt.Errorf("feeds: read affected: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var cve, src string
		if err := rows.Scan(&cve, &src); err != nil {
			return nil, fmt.Errorf("feeds: read affected: %w", err)
		}
		out[cve] = src
	}
	return out, rows.Err()
}
