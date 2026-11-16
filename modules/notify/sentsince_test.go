package notify_test

import (
	"database/sql"
	"testing"
	"time"
)

// SentSince (#825, Home's "alerts sent"): arrived and failed delivery attempts since a time; a delayed row (rate limited, it resends by
// itself, D-483) is not a failure; rows before the time do not count.
func TestSentSinceCountsArrivedAndFailedNotDelayed(t *testing.T) {
	e := newEnv(t)
	e.write(func(tx *sql.Tx) error {
		for _, r := range []struct {
			id, at      string
			ok, delayed int
		}{
			{"s-1", "2026-11-09T01:00:00.000Z", 1, 0},
			{"s-2", "2026-11-09T02:00:00.000Z", 1, 0},
			{"s-3", "2026-11-09T03:00:00.000Z", 0, 0},
			{"s-4", "2026-11-09T04:00:00.000Z", 0, 1},
			{"s-5", "2026-11-01T04:00:00.000Z", 1, 0}, // before the window
			{"s-6", "2026-11-01T05:00:00.000Z", 0, 0}, // before the window
		} {
			if _, err := tx.ExecContext(e.ctx(), `INSERT INTO notify_send (id, kind, ref_id, channel, "to", at, ok, delayed, error, what, link, message, recipient) VALUES (?, 'incident', 'ref', 'slack', '#it', ?, ?, ?, NULL, 'a title', '/incidents/i1', '{}', NULL)`,
				r.id, r.at, r.ok, r.delayed); err != nil {
				return err
			}
		}
		return nil
	})
	sent, failed, err := e.svc.SentSince(e.ctx(), time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC))
	if err != nil || sent != 2 || failed != 1 {
		t.Fatalf("SentSince = %d sent, %d failed, %v; want 2, 1", sent, failed, err)
	}
	if sent, failed, err = e.svc.SentSince(e.ctx(), time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)); err != nil || sent != 0 || failed != 0 {
		t.Fatalf("SentSince of an empty window = %d, %d, %v", sent, failed, err)
	}
}
