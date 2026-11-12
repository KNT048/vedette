package notify

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/store"
)

// Retention of the history: DATA_MODEL 4.4 keeps notify_send, resolved notify_incident and notify_notice for 1 year. The
// delete job runs while the module is off too (Housekeeping, D-160): it only deletes data past the retention the product states
// (DATA_MODEL, CONTRACT, and the line on the History and Incidents screens, D-215), opens no route and no connection, and writes one audit line for every run that deleted
// something.
const (
	retentionJob   = "retention"
	retentionEvery = time.Hour
	retention      = 365 * 24 * time.Hour
)

// RunRetention deletes, in one transaction, what is older than the retention (D-215):
//   - notify_send rows whose attempt (at) is older than a year;
//   - notify_incident rows with status resolved whose handled_at (last_seen when it is missing) is older than a year, unless a send
//     newer than the cut still points to it (a resend of an old incident); an incident that is new or acknowledged is open work and is
//     never deleted, however old (its devices go with it, ON DELETE CASCADE);
//   - notify_notice rows created over a year ago, except one a queued message still names (notify_pending) or a send newer than
//     the cut still covers (a resend of an old notice): the notice rows of a grouped message are only removed with the last send
//     that covers them.
//
// notify_pending (the queue of what is not sent yet) is never touched: it is not history, and the stale rule of D-86 (7) owns it.
// notify_kev has its own, shorter, clean-up.
func (s *Service) RunRetention(ctx context.Context) error {
	cut := store.FormatTS(s.now().Add(-retention))
	var sends, incidents, notices int64
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, d := range []struct {
			n *int64
			q string
		}{
			// notices first: whether a send newer than the cut still covers one is read from notify_send_notice, before the old sends go
			{&notices, `DELETE FROM notify_notice WHERE created_at < ?1
				AND NOT EXISTS (SELECT 1 FROM notify_pending p WHERE p.notice_id = notify_notice.id)
				AND NOT EXISTS (SELECT 1 FROM notify_send_notice sn JOIN notify_send s ON s.id = sn.send_id WHERE sn.notice_id = notify_notice.id AND s.at >= ?1)`},
			{&sends, `DELETE FROM notify_send WHERE at < ?1`},
			{&incidents, `DELETE FROM notify_incident WHERE status = 'resolved' AND COALESCE(handled_at, last_seen) < ?1
				AND NOT EXISTS (SELECT 1 FROM notify_send s WHERE s.kind = 'incident' AND s.ref_id = notify_incident.id AND s.at >= ?1)`},
		} {
			r, err := tx.ExecContext(ctx, d.q, cut)
			if err != nil {
				return fmt.Errorf("notify: retention: %w", err)
			}
			if *d.n, err = r.RowsAffected(); err != nil {
				return fmt.Errorf("notify: retention: %w", err)
			}
		}
		if sends+incidents+notices == 0 {
			return nil
		}
		return s.record(ctx, tx, systemUser, "notify.retention", "notify_send, notify_incident, notify_notice",
			fmt.Sprintf("deleted %d send record(s), %d resolved incident(s), %d vulnerability notice(s) older than 1 year", sends, incidents, notices))
	})
	if err != nil {
		return err
	}
	if sends+incidents+notices > 0 {
		s.cfg.Log.InfoContext(ctx, "notify: history past its retention deleted", "sends", sends, "incidents", incidents, "notices", notices)
	}
	return nil
}
