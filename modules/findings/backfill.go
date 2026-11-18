package findings

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/knt048/vedette/core/audit"
)

// backfillPending says whether the first full match pass after the device-version rule arrived has not ended yet (migration 0015's
// marker): until it ends, an open finding that rule alone confirms is recorded for the summary instead of sending its own notice.
func backfillPending(ctx context.Context, tx *sql.Tx) (bool, error) {
	var one int
	switch err := tx.QueryRowContext(ctx, `SELECT 1 FROM fnd_device_backfill_pending`).Scan(&one); {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("findings: reading the first-pass marker: %w", err)
	}
	return true, nil
}

// finishBackfill ends the first full match pass after the device-version rule arrived: the findings it recorded that are still
// confirmed become one findings.device_version.backfilled event and an audit row that says how many (neither when there are none); the
// marker and the list are emptied, so every later confirmation by the device's version is told on its own. Nothing happens once
// the marker is gone.
func (s *Service) finishBackfill(ctx context.Context) error {
	return s.write(ctx, func(tx *sql.Tx, _ time.Time, emit func(string, any)) error {
		pending, err := backfillPending(ctx, tx)
		if err != nil || !pending {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT f.id, f.asset_id, f.cve, f.severity FROM fnd_device_backfill b JOIN fnd_finding f ON f.id = b.finding_id
			WHERE f.status = 'confirmed' ORDER BY f.cve, f.id`)
		if err != nil {
			return fmt.Errorf("findings: reading the confirmations of the first pass: %w", err)
		}
		type row struct{ id, asset, cve, sev string }
		var list []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.asset, &r.cve, &r.sev); err != nil {
				_ = rows.Close()
				return fmt.Errorf("findings: reading the confirmations of the first pass: %w", err)
			}
			list = append(list, r)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("findings: reading the confirmations of the first pass: %w", err)
		}
		for _, q := range []string{`DELETE FROM fnd_device_backfill`, `DELETE FROM fnd_device_backfill_pending`} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return fmt.Errorf("findings: ending the first pass: %w", err)
			}
		}
		devices, cves := map[string]bool{}, map[string]bool{}
		ev := DeviceBackfillEvent{Findings: len(list)}
		slices.SortStableFunc(list, func(a, b row) int { return cmp.Compare(sevRank(Severity(b.sev)), sevRank(Severity(a.sev))) })
		for _, r := range list {
			devices[r.asset] = true
			if !cves[r.cve] && len(ev.CVEList) < MaxBackfillListed {
				ev.CVEList = append(ev.CVEList, r.cve)
			}
			cves[r.cve] = true
			if len(ev.FindingIDs) < MaxBackfillListed {
				ev.FindingIDs = append(ev.FindingIDs, r.id)
			}
			if sevRank(Severity(r.sev)) > sevRank(ev.Severity) {
				ev.Severity = Severity(r.sev)
			}
		}
		ev.Devices, ev.CVEs = len(devices), len(cves)
		if ev.Findings == 0 { // a new box, or nothing the rule alone confirmed: nothing to tell
			return nil
		}
		if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.device_backfill", Target: "findings",
			Detail: fmt.Sprintf("%d open findings on %d devices (%d CVEs) confirmed by the version their device reports; one summary notice", ev.Findings, ev.Devices, ev.CVEs)}); err != nil {
			return err
		}
		emit(EventDeviceBackfill, ev)
		return nil
	})
}
