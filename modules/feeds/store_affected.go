package feeds

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/store"
)

// applyAffected stores the NVD entries of a pull (D-500): the rows of every CVE in got are replaced; a full pull
// also drops the CVEs it did not get (NVD no longer lists them with hasKev). It returns how many CVEs changed and
// how many the table holds afterwards.
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
		for _, q := range []string{
			`DELETE FROM feeds_affected WHERE cve NOT IN (SELECT cve FROM feeds_affected_keep)`,
			`DELETE FROM feeds_affected_cve WHERE cve NOT IN (SELECT cve FROM feeds_affected_keep)`,
			`DELETE FROM feeds_affected_keep`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return nil, 0, fmt.Errorf("feeds: affected: %w", err)
			}
		}
	}
	ts := store.FormatTS(now)
	for cve, rows := range got {
		same, err := sameAffected(ctx, tx, cve, rows)
		if err != nil {
			return nil, 0, err
		}
		if same {
			continue
		}
		changed = append(changed, cve)
		if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_affected WHERE cve = ?`, cve); err != nil {
			return nil, 0, fmt.Errorf("feeds: affected: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_affected_cve (cve, updated_at) VALUES (?, ?) ON CONFLICT(cve) DO UPDATE SET updated_at = excluded.updated_at`, cve, ts); err != nil {
			return nil, 0, fmt.Errorf("feeds: affected: %w", err)
		}
		for _, r := range rows {
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_affected (cve, cpe, start_incl, start_excl, end_incl, end_excl) VALUES (?, ?, ?, ?, ?, ?)`,
				cve, r.CPE, r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl); err != nil {
				return nil, 0, fmt.Errorf("feeds: affected: %w", err)
			}
		}
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM feeds_affected_cve`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("feeds: affected: %w", err)
	}
	return changed, total, nil
}

// sameAffected reports whether the stored rows of cve are exactly rows (a CVE NVD did not change is not news).
func sameAffected(ctx context.Context, tx *sql.Tx, cve string, rows []AffectedRow) (bool, error) {
	var known int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM feeds_affected_cve WHERE cve = ?`, cve).Scan(&known); err != nil {
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

func (s *Store) affectedCount(ctx context.Context) (int, error) {
	var n int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM feeds_affected_cve`).Scan(&n); err != nil {
		return 0, fmt.Errorf("feeds: count affected: %w", err)
	}
	return n, nil
}
