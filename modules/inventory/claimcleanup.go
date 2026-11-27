package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/knt048/vedette/core/pkgrel"
)

// UnknownAuthor is the author of a version a person entered while a device added by hand kept no author for its version (before this
// release): who typed it is not known, but a person did, so the version stays a person's word and says plainly that the name is lost.
const UnknownAuthor = "unknown (entered before this release)"

// CleanStoredClaims brings a person's stored entries to the rules a new entry follows (Edit's checkClaim, createManual's author), once:
//   - a package release on a line that is no distribution package (firmware such as Junos OS, an application with only an upstream
//     version on a device with no distribution; packageLine) is dropped: it was never evidence of a package, and findings judged such a
//     line as a distribution's package because of it;
//   - an entry with no author (a device added by hand, a CSV import) gets UnknownAuthor.
//
// The OS a person set on a device is left out: syncStatedOS rebuilds that reading from the OS correction (its author is the
// correction's), so naming an author on the reading would be undone by the next observation and written again by every run.
//
// Each change is one audit row (inventory.entry_cleaned) and the device is matched again. With nothing left to clean a run reads one
// query: the job runs it at start and every day after, and it is idempotent.
func (s *Service) CleanStoredClaims(ctx context.Context) error {
	type stray struct{ asset, line string }
	var todo []stray
	err := func() error {
		rows, err := s.db.Reader().QueryContext(ctx, `SELECT DISTINCT s.asset_id, s.id FROM inv_software_reading r JOIN inv_software s ON s.id = r.software_id
			WHERE r.source = 'manual' AND r.instance <> ? AND (r.pkg_version IS NOT NULL OR r.set_by IS NULL) ORDER BY s.asset_id, s.id`, instanceOS)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var x stray
			if err := rows.Scan(&x.asset, &x.line); err != nil {
				return err
			}
			todo = append(todo, x)
		}
		return rows.Err()
	}()
	if err != nil {
		return fmt.Errorf("inventory: read stored entries: %w", err)
	}
	var errs []error
	for i := 0; i < len(todo); {
		j := i
		var lines []string
		for ; j < len(todo) && todo[j].asset == todo[i].asset; j++ {
			lines = append(lines, todo[j].line)
		}
		if err := s.cleanDeviceClaims(ctx, todo[i].asset, lines); err != nil {
			errs = append(errs, fmt.Errorf("inventory: clean the entries of %s: %w", todo[i].asset, err))
		}
		i = j
	}
	return errors.Join(errs...)
}

// cleanDeviceClaims cleans the entries of one device's lines in one write (CleanStoredClaims).
func (s *Service) cleanDeviceClaims(ctx context.Context, assetID string, lineIDs []string) error {
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		var osName string
		if err := tx.QueryRowContext(ctx, `SELECT ifnull(os, '') FROM inv_asset WHERE id = ?`, assetID).Scan(&osName); errors.Is(err, sql.ErrNoRows) {
			return nil // deleted meanwhile
		} else if err != nil {
			return fmt.Errorf("inventory: read device: %w", err)
		}
		before, err := deviceKeys(ctx, tx, assetID)
		if err != nil {
			return err
		}
		var touched []string
		for _, id := range lineIDs {
			l, err := readLine(ctx, tx, id)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return fmt.Errorf("inventory: read software: %w", err)
			}
			rs, err := readingsOf(ctx, tx, id)
			if err != nil {
				return err
			}
			for _, r := range rs {
				if !r.entry() || r.Instance == instanceOS { // the person's OS: rebuilt from the OS correction, which holds its author
					continue
				}
				what := ""
				if r.PkgVersion != "" && !packageLine(osName, rs) && !pkgrel.Release(r.PkgVersion) {
					if _, err := tx.ExecContext(ctx, `UPDATE inv_software_reading SET pkg_version = NULL, pkg_source = CASE WHEN packaged = 1 THEN pkg_source END
						WHERE software_id = ? AND source = 'manual' AND instance = ? AND addr_id = ?`, id, r.Instance, r.Addr); err != nil {
						return fmt.Errorf("inventory: clean an entry: %w", err)
					}
					what = "package release " + r.PkgVersion + " dropped: " + r.Display + " is not a distribution package on this device"
				}
				if r.SetBy == "" {
					if _, err := tx.ExecContext(ctx, `UPDATE inv_software_reading SET set_by = ? WHERE software_id = ? AND source = 'manual' AND instance = ? AND addr_id = ?`,
						UnknownAuthor, id, r.Instance, r.Addr); err != nil {
						return fmt.Errorf("inventory: clean an entry: %w", err)
					}
					if what != "" {
						what += "; "
					}
					what += "entered by " + UnknownAuthor
				}
				if what == "" {
					continue
				}
				if err := s.auditTx(ctx, tx, systemActor, "inventory.entry_cleaned", deviceName(ctx, tx, assetID)+": "+l.display,
					swText(r.Display, r.Version, r.PkgVersion)+": "+what); err != nil {
					return err
				}
				if !slices.Contains(touched, id) {
					touched = append(touched, id)
				}
			}
		}
		if len(touched) == 0 {
			return nil
		}
		return s.settled(ctx, tx, o, assetID, before, touched...)
	})
}
