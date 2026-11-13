package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// Incidents close themselves (D-550, INV-22) and the first-run window is told in a summary (INV-23).
const (
	autoCloseJob   = "autoclose"
	autoCloseEvery = time.Hour
	// maxAutoClose is the most incidents one run closes per kind: one bounded transaction; the next run takes the rest.
	maxAutoClose = 500
)

// quietWindows is how long an open (new or acknowledged) incident of each kind may see no new activity (last_seen does not move)
// before Vedette closes it (D-550): a trap or a bad connection that has not come back for a week, a log anomaly after three days
// (the logs digest keeps its lines; a new kind of message an hour is its own incident). A new hit afterwards opens a new incident:
// the dedupe of INV-10 only joins incidents that are not resolved. New-device incidents close on approve or delete, never by time.
var quietWindows = []struct {
	kind IncidentKind
	days int
}{{IncidentTrap, 7}, {IncidentBadAddress, 7}, {IncidentLogAnomaly, 3}}

// heldKind is a kind whose low and medium incidents the first-run window holds for the summary (INV-23): on a fresh box the
// existing state of the network (devices that already talk to listed addresses, a log source read for the first time) all looks
// new. Traps are never held (nobody has a reason to touch one), and devices have their own first-discovery summary (INV-10, B9).
func heldKind(k IncidentKind) bool { return k == IncidentBadAddress || k == IncidentLogAnomaly }

// runAutoClose is the body of the "autoclose" job: the first-run summary first (an incident held in it may also be quiet), then the
// quiet incidents.
func (s *Service) runAutoClose(ctx context.Context) error {
	return errors.Join(s.firstRunSummary(ctx), s.closeQuiet(ctx))
}

// closeBySystem resolves an open incident on Vedette's behalf, like a person's resolve (handled_by system, one audit row
// notify.incident_status), with reason in resolved_reason. A person's note stays. Nothing is sent.
func (s *Service) closeBySystem(ctx context.Context, tx *sql.Tx, id, title, reason string) error {
	r, err := tx.ExecContext(ctx, `UPDATE notify_incident SET status = 'resolved', handled_by = ?, handled_at = ?, resolved_reason = ? WHERE id = ? AND status <> 'resolved'`,
		systemUser, store.FormatTS(s.now()), clip(reason, maxNote), id)
	if err != nil {
		return fmt.Errorf("notify: close an incident: %w", err)
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return nil
	}
	return s.record(ctx, tx, systemUser, "notify.incident_status", clip(title, 400), "resolved: "+reason)
}

// closeQuiet resolves the open incidents of quietWindows that have seen nothing new for their window (INV-22).
func (s *Service) closeQuiet(ctx context.Context) error {
	now := s.now()
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, w := range quietWindows {
			rows, err := tx.QueryContext(ctx, `SELECT id, title FROM notify_incident WHERE kind = ? AND status <> 'resolved' AND last_seen < ? ORDER BY last_seen LIMIT ?`,
				string(w.kind), store.FormatTS(now.AddDate(0, 0, -w.days)), maxAutoClose)
			if err != nil {
				return fmt.Errorf("notify: find quiet incidents: %w", err)
			}
			var ids, titles []string
			for rows.Next() {
				var id, title string
				if err := rows.Scan(&id, &title); err != nil {
					_ = rows.Close()
					return fmt.Errorf("notify: find quiet incidents: %w", err)
				}
				ids, titles = append(ids, id), append(titles, title)
			}
			if err := errors.Join(rows.Err(), rows.Close()); err != nil {
				return fmt.Errorf("notify: find quiet incidents: %w", err)
			}
			reason := fmt.Sprintf("Closed by Vedette: no new activity for %d days.", w.days)
			for k, id := range ids {
				if err := s.closeBySystem(ctx, tx, id, titles[k], reason); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// firstRunSummary sends one message for the incidents the first-run window held since the last summary (INV-23), at most one an
// hour (the job's period): how many, of which kinds, the highest severity, a link to Incidents. Held incidents a person or Vedette
// already resolved are marked told without a message. The id is per UTC hour, so a run repeated within the hour queues nothing new.
func (s *Service) firstRunSummary(ctx context.Context) error {
	now := s.now()
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT kind, severity, COUNT(*) FROM notify_incident WHERE first_run = 1 AND status <> 'resolved' GROUP BY kind, severity`)
		if err != nil {
			return fmt.Errorf("notify: read held incidents: %w", err)
		}
		byKind := map[IncidentKind]int{}
		total, top := 0, Info
		for rows.Next() {
			var k, sev string
			var n int
			if err := rows.Scan(&k, &sev, &n); err != nil {
				_ = rows.Close()
				return fmt.Errorf("notify: read held incidents: %w", err)
			}
			byKind[IncidentKind(k)] += n
			total += n
			if Severity(sev).rank() > top.rank() {
				top = Severity(sev)
			}
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("notify: read held incidents: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET first_run = 2 WHERE first_run = 1`); err != nil {
			return fmt.Errorf("notify: mark held incidents told: %w", err)
		}
		if total == 0 {
			return nil
		}
		kind := IncidentBadAddress // the webhook's "kind": the one with more incidents
		if byKind[IncidentLogAnomaly] > byKind[IncidentBadAddress] {
			kind = IncidentLogAnomaly
		}
		var parts []string
		if n := byKind[IncidentBadAddress]; n > 0 {
			parts = append(parts, plural(n, "connection to a known-bad address", "connections to known-bad addresses"))
		}
		if n := byKind[IncidentLogAnomaly]; n > 0 {
			parts = append(parts, plural(n, "log anomaly", "log anomalies"))
		}
		title := "First-run summary: " + plural(total, "new incident", "new incidents")
		return s.enqueue(ctx, tx, Notice{ID: "fr-" + now.UTC().Format("2006010215"), Kind: KindIncident, IncidentKind: string(kind), Severity: top, Title: title,
			What: "Vedette is new on this network, so what was already happening on it looks new too. Instead of one message each, the " +
				"low and medium incidents of its first 36 hours are told together: " + strings.Join(parts, ", ") + ". High and critical incidents and trap touches are still sent at once.",
			Action: "Open Incidents, look at each one, and resolve the ones you know about.", Link: s.link("/incidents"), At: now})
	})
}
