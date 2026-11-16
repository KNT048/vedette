package notify_test

import (
	"database/sql"
	"fmt"
	"testing"
	"time"
)

// SentSince (#825, Home's "alerts sent"): alert messages (incident, vuln) that arrived and that failed since a time. Not a failure: a
// delayed row (rate limited, it resends by itself, D-483), or a failure resent later with success to the same channel for the same item.
// An approval request is not an alert; rows before the time do not count.
func TestSentSinceCountsAlertsArrivedAndFailedNotDelayedNotResent(t *testing.T) {
	e := newEnv(t)
	e.write(func(tx *sql.Tx) error {
		for _, r := range []struct {
			id, kind, ref, channel, at string
			ok, delayed                int
		}{
			{"s-1", "incident", "i1", "slack", "2026-11-09T01:00:00.000Z", 1, 0},
			{"s-2", "vuln", "v1", "slack", "2026-11-09T02:00:00.000Z", 1, 0},
			{"s-3", "incident", "i2", "slack", "2026-11-09T03:00:00.000Z", 0, 0}, // failed, never resent: failed
			{"s-4", "incident", "i3", "slack", "2026-11-09T04:00:00.000Z", 0, 1}, // delayed: not failed
			{"s-5", "vuln", "v2", "email", "2026-11-09T05:00:00.000Z", 0, 0},     // failed ...
			{"s-6", "vuln", "v2", "email", "2026-11-09T06:00:00.000Z", 1, 0},     // ... resent with success: sent, s-5 not failed
			{"s-7", "incident", "i4", "slack", "2026-11-09T07:00:00.000Z", 0, 0}, // failed on slack ...
			{"s-8", "incident", "i4", "email", "2026-11-09T08:00:00.000Z", 1, 0}, // ... arrived on another channel: s-7 still failed
			{"s-9", "approval", "r1", "slack", "2026-11-09T09:00:00.000Z", 1, 0}, // approval requests are not alerts
			{"s-10", "approval", "r2", "slack", "2026-11-09T09:30:00.000Z", 0, 0},
			{"s-11", "incident", "i5", "slack", "2026-11-01T04:00:00.000Z", 1, 0}, // before the window
			{"s-12", "incident", "i6", "slack", "2026-11-01T05:00:00.000Z", 0, 0}, // before the window
		} {
			if _, err := tx.ExecContext(e.ctx(), `INSERT INTO notify_send (id, kind, ref_id, channel, "to", at, ok, delayed, error, what, link, message, recipient) VALUES (?, ?, ?, ?, '#it', ?, ?, ?, NULL, 'a title', '/incidents/i1', '{}', NULL)`,
				r.id, r.kind, r.ref, r.channel, r.at, r.ok, r.delayed); err != nil {
				return err
			}
		}
		return nil
	})
	sent, failed, err := e.svc.SentSince(e.ctx(), time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC))
	if err != nil || sent != 4 || failed != 2 {
		t.Fatalf("SentSince = %d sent, %d failed, %v; want 4, 2", sent, failed, err)
	}
	if sent, failed, err = e.svc.SentSince(e.ctx(), time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)); err != nil || sent != 0 || failed != 0 {
		t.Fatalf("SentSince of an empty window = %d, %d, %v", sent, failed, err)
	}
}

// OpenIncidents (#825, the shell's nav badge and Home): the incidents of the Open tab (new, acknowledged) and, of them, the high and
// critical ones; resolved incidents do not count.
func TestOpenIncidentsCountsOpenAndUrgent(t *testing.T) {
	e := newEnv(t)
	if open, urgent, err := e.svc.OpenIncidents(e.ctx()); err != nil || open != 0 || urgent != 0 {
		t.Fatalf("none: %d, %d, %v", open, urgent, err)
	}
	e.write(func(tx *sql.Tx) error {
		for i, r := range []struct{ severity, status string }{
			{"critical", "new"}, {"high", "acknowledged"}, {"medium", "new"}, {"low", "acknowledged"}, {"critical", "resolved"}, {"high", "resolved"},
		} {
			handled := any(nil)
			if r.status != "new" {
				handled = "2026-11-09T02:00:00.000Z"
			}
			if _, err := tx.ExecContext(e.ctx(), `INSERT INTO notify_incident (id, kind, title, link, severity, what, action, first_seen, last_seen, status, handled_at, dedupe_key)
				VALUES (?, 'trap', 't', '/x', ?, 'w', 'a', '2026-11-09T01:00:00.000Z', '2026-11-09T01:00:00.000Z', ?, ?, ?)`,
				fmt.Sprintf("in-%d", i), r.severity, r.status, handled, fmt.Sprintf("%064d", i)); err != nil {
				return err
			}
		}
		return nil
	})
	if open, urgent, err := e.svc.OpenIncidents(e.ctx()); err != nil || open != 4 || urgent != 2 {
		t.Fatalf("OpenIncidents = %d open, %d urgent, %v; want 4, 2", open, urgent, err)
	}
}
