package scan

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/store"
)

// catchUpPage is how many announced KEV entries one pass of the rescan job reads from feeds (S4b).
const catchUpPage = 100

// catchUp records the KEV entries feeds announced since the last one read, as OnNewKEV does for the bus: the bus is
// best-effort (D-144), so an entry announced while scan was off or the process was down is found here. One page per
// pass. The rows and the read point are written in one transaction, and an entry already queued (from the bus) is
// kept, so a pass can be repeated. The event keeps the time feeds announced it, so its latency says how late the
// rescan came. Entries announced more than pendingFor ago are passed over (the read point moves on): an event that old
// would only wait out its expiry, and a scan module turned on for the first time does not rescan a year of entries;
// the scheduled scan still covers their devices.
func (s *Service) catchUp(ctx context.Context) error {
	if s.cfg.KEV == nil {
		return nil
	}
	var at sql.NullString
	var cve string
	if err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT kev_read_at, kev_read_cve FROM scan_setting WHERE id = 1`).Scan(&at, &cve); err != nil {
		return fmt.Errorf("scan: reading the KEV catch-up point: %w", err)
	}
	var after time.Time
	if at.Valid {
		t, err := time.Parse(time.RFC3339Nano, at.String)
		if err != nil {
			return fmt.Errorf("scan: reading the KEV catch-up point: %w", err)
		}
		after = t
	}
	list, err := s.cfg.KEV.NewKEVSince(ctx, after, cve, catchUpPage)
	if err != nil {
		return fmt.Errorf("scan: reading the announced KEV entries: %w", err)
	}
	if len(list) == 0 {
		return nil
	}
	now := s.now()
	last := list[len(list)-1]
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, k := range list {
			if !k.HasTemplate || !validCVE(k.CVE) || now.Sub(k.At) > pendingFor {
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO scan_event (id, ts, cve, product) VALUES (?, ?, ?, ?) ON CONFLICT (cve) DO NOTHING`,
				store.NewID("ev"), store.FormatTS(k.At), k.CVE, plainLine(k.Vendor+" "+k.Product, 300)); err != nil {
				return fmt.Errorf("scan: recording a missed KEV entry: %w", err)
			}
		}
		_, err := tx.ExecContext(ctx, `UPDATE scan_setting SET kev_read_at = ?, kev_read_cve = ? WHERE id = 1`, store.FormatTS(last.At), last.CVE)
		return err
	})
}
