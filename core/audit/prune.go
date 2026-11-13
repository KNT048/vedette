package audit

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/chain/chainhead"
	"github.com/knt048/vedette/core/store"
)

// Retention of core_audit (D-416, core INV-37): the lines of the last RetentionDays days, at most MaxRows lines; the oldest go first.
// The Settings → Audit log page says the same numbers (core.json audit.meta).
const (
	RetentionDays       = 365
	MaxRows       int64 = 200_000
	// PruneEvery is how often the core job "audit-prune" runs.
	PruneEvery = 6 * time.Hour
)

// Prune removes the lines past the retention and returns how many it removed. Only the oldest run of lines goes: it stops at the first
// line that is still to be kept (newer than the cutoff and among the newest MaxRows), even if a later line is older (the clock stepped
// back), so the chain stays one piece. The newest line is never removed: the chain head names it. The lines, the anchor and the head
// (chainhead.Prune) change in one transaction, with an "audit.pruned" line by "system" that says how many lines went and why.
func (l *Log) Prune(ctx context.Context, db *store.DB) (int64, error) {
	return l.prune(ctx, db, RetentionDays, MaxRows)
}

func (l *Log) prune(ctx context.Context, db *store.DB, days int, maxRows int64) (int64, error) {
	now := l.now()
	cutoff := store.FormatTS(now.AddDate(0, 0, -days))
	var removed int64
	err := db.Write(ctx, func(tx *sql.Tx) error {
		removed = 0 // the write may be retried
		// keepFrom: the first line to keep. By age: the first line at or after the cutoff (none: the newest line). By count: the
		// maxRows-th newest line (fewer lines: 0, nothing to remove by count). The later of the two, never past the newest line.
		var byAge, byCount, newest int64
		err := tx.QueryRowContext(ctx, `SELECT
			COALESCE((SELECT seq FROM core_audit WHERE ts >= ? ORDER BY seq LIMIT 1), (SELECT MAX(seq) FROM core_audit), 0),
			COALESCE((SELECT seq FROM core_audit ORDER BY seq DESC LIMIT 1 OFFSET ?), 0),
			COALESCE((SELECT MAX(seq) FROM core_audit), 0)`, cutoff, maxRows-1).Scan(&byAge, &byCount, &newest)
		if err != nil {
			return fmt.Errorf("audit: prune: %w", err)
		}
		keepFrom := min(max(byAge, byCount), newest)
		var n, lastSeq int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MAX(seq), 0) FROM core_audit WHERE seq < ?`, keepFrom).Scan(&n, &lastSeq); err != nil {
			return fmt.Errorf("audit: prune: %w", err)
		}
		if n == 0 {
			return nil
		}
		var lastID, lastHash string
		if err := tx.QueryRowContext(ctx, `SELECT id, hash FROM core_audit WHERE seq = ?`, lastSeq).Scan(&lastID, &lastHash); err != nil {
			return fmt.Errorf("audit: prune: %w", err)
		}
		// The anchor moves first: core_audit's delete trigger (migration 0011) lets a line go only when it is at or before the line the
		// anchor names. That line goes last, on its own, so the trigger's lookup still finds it while the older lines are deleted.
		if err := chainhead.Prune(ctx, tx, chainName, lastID, lastHash, n, now); err != nil {
			return fmt.Errorf("audit: prune: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM core_audit WHERE seq < ?`, lastSeq); err != nil {
			return fmt.Errorf("audit: prune: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM core_audit WHERE seq = ?`, lastSeq); err != nil {
			return fmt.Errorf("audit: prune: %w", err)
		}
		detail := fmt.Sprintf("%d lines: older than %d days (before %s) or beyond the newest %d", n, days, cutoff, maxRows)
		if err := l.Append(ctx, tx, Entry{User: "system", Action: "audit.pruned", Target: "core_audit", Detail: detail}); err != nil {
			return err
		}
		removed = n
		return nil
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}
