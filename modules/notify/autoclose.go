package notify

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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

// quietWindows is how long an open (new or acknowledged) incident of each kind may see no new activity (quietSince)
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
// quiet incidents, then the new-device incidents of devices approved or renamed in Devices (D-552).
func (s *Service) runAutoClose(ctx context.Context) error {
	return errors.Join(s.firstRunSummary(ctx), s.closeQuiet(ctx), s.followDevices(ctx))
}

// followDevices is assetUpdated for the devices on open new-device incidents (D-552): a device approved before this version, or while
// notify was off (events are not replayed), leaves its incidents on the next run, which is also the run at start, and a name Devices
// learnt since shows. At most maxAutoClose devices a run, oldest incident first. The inventory is read before the one write.
// ponytail: a box with more than 500 devices on open new-device incidents checks the 500 oldest each hour (an approval now closes
// through its event); upgrade path: a cursor over the asset ids.
func (s *Service) followDevices(ctx context.Context) error {
	if s.cfg.Devices == nil {
		return nil
	}
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT d.asset_id, MIN(i.first_seen) AS f FROM notify_incident i JOIN notify_incident_device d ON d.incident_id = i.id
		WHERE i.kind = ? AND i.status <> 'resolved' GROUP BY d.asset_id ORDER BY f, d.asset_id LIMIT ?`, string(IncidentUnknownDevice), maxAutoClose)
	if err != nil {
		return fmt.Errorf("notify: find the devices of new-device incidents: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id, first string
		if err := rows.Scan(&id, &first); err != nil {
			_ = rows.Close()
			return fmt.Errorf("notify: find the devices of new-device incidents: %w", err)
		}
		ids = append(ids, id)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("notify: find the devices of new-device incidents: %w", err)
	}
	states := make(map[string]DeviceState, len(ids))
	for _, id := range ids {
		st, ok, err := s.cfg.Devices.DeviceState(ctx, id)
		if err != nil {
			return err
		}
		if ok { // a device the inventory no longer has is INV-20's
			states[id] = st
		}
	}
	if len(states) == 0 {
		return nil
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, id := range ids {
			if st, ok := states[id]; ok {
				if err := s.followDevice(ctx, tx, id, st); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// closeBySystem resolves an open incident on Vedette's behalf, like a person's resolve (handled_by system, one audit row
// notify.incident_status), with reason in resolved_reason. A person's note stays; who acknowledged it stays in the reason ("… after
// an@x acknowledged it."), since handled_by becomes system. Nothing is sent.
func (s *Service) closeBySystem(ctx context.Context, tx *sql.Tx, id, title, reason string) error {
	var status string
	var by sql.NullString
	switch err := tx.QueryRowContext(ctx, `SELECT status, handled_by FROM notify_incident WHERE id = ?`, id).Scan(&status, &by); {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("notify: read an incident to close: %w", err)
	}
	if status == string(StatusResolved) {
		return nil
	}
	if status == string(StatusAcknowledged) && by.String != "" && by.String != systemUser {
		reason = strings.TrimSuffix(reason, ".") + " after " + by.String + " acknowledged it."
	}
	if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET status = 'resolved', handled_by = ?, handled_at = ?, resolved_reason = ? WHERE id = ?`,
		systemUser, store.FormatTS(s.now()), clip(reason, maxNote), id); err != nil {
		return fmt.Errorf("notify: close an incident: %w", err)
	}
	return s.record(ctx, tx, systemUser, "notify.incident_status", clip(title, 400), "resolved: "+reason)
}

// quietSince is when an incident last showed life (INV-22): the latest of when the box last received a hit of it or a person reopened
// it (active_at, by the box's clock: a hit carrying an old time does not count as old) and a person's acknowledgement (handled_at).
// Rows from before migration 0013 have no active_at: last_seen stands in.
const quietSince = `MAX(COALESCE(active_at, last_seen), COALESCE(handled_at, ''))`

// closeQuiet resolves the open incidents of quietWindows that have seen nothing new for their window (INV-22).
func (s *Service) closeQuiet(ctx context.Context) error {
	now := s.now()
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, w := range quietWindows {
			rows, err := tx.QueryContext(ctx, `SELECT id, title FROM notify_incident WHERE kind = ? AND status <> 'resolved' AND `+quietSince+` < ? ORDER BY last_seen LIMIT ?`,
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

// raiseHeld is a repeat of a held incident with a higher severity (INV-23): the incident takes it, and from high up it leaves the
// summary and is queued as usual, as if it had been opened at that severity.
func (s *Service) raiseHeld(ctx context.Context, tx *sql.Tx, id string, sev Severity, at time.Time) error {
	release := sev.rank() >= High.rank()
	if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET severity = ?, first_run = CASE WHEN ? THEN 0 ELSE first_run END,
		summary_id = CASE WHEN ? THEN NULL ELSE summary_id END WHERE id = ?`, string(sev), release, release, id); err != nil {
		return fmt.Errorf("notify: raise a held incident: %w", err)
	}
	if !release {
		return nil
	}
	i, err := scanIncident(tx.QueryRowContext(ctx, `SELECT `+incidentCols+` FROM notify_incident WHERE id = ?`, id))
	if err != nil {
		return fmt.Errorf("notify: read a raised incident: %w", err)
	}
	if err := fillIncident(ctx, tx, &i); err != nil {
		return err
	}
	names, ids := make([]string, 0, len(i.Devices)), make([]string, 0, len(i.Devices))
	for _, d := range i.Devices {
		names, ids = append(names, d.Name), append(ids, d.ID)
	}
	return s.enqueue(ctx, tx, Notice{ID: id, Kind: KindIncident, Severity: sev, Title: i.Title, What: i.What, Action: i.Action,
		Devices: names, DeviceIDs: ids, IncidentKind: string(i.Kind), Link: s.link("/incidents/" + id), At: at})
}

// unsentSummaries are the first-run summaries still waiting in the queue on every channel they went to (quiet hours): none of their
// rows is claimed or sent, and no channel has a send of them.
const unsentSummaries = `SELECT DISTINCT p.notice_id FROM notify_pending p WHERE p.notice_id GLOB 'fr-*'
	AND NOT EXISTS (SELECT 1 FROM notify_pending q WHERE q.notice_id = p.notice_id AND q.state <> 'pending')
	AND NOT EXISTS (SELECT 1 FROM notify_send d WHERE d.ref_id = p.notice_id)`

// heldOpen selects the held incidents a summary tells: open, and not yet in a summary that went out.
const heldOpen = `first_run = 1 AND status <> 'resolved' AND (summary_id IS NULL OR summary_id IN (` + unsentSummaries + `))`

// firstRunSummary sends one message for the incidents the first-run window held (INV-23), at most one an hour (the job's period): how
// many, of which kinds, the highest current severity, a link to Incidents. The incidents of a summary that is still waiting in the
// queue (quiet hours) are folded into the new one, which replaces it, so the night ends with one message, not one per hour. The id is
// a hash of the incident ids it tells, and the incidents are marked told (summary_id) in the same transaction that queues it.
func (s *Service) firstRunSummary(ctx context.Context) error {
	now := s.now()
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, kind, severity FROM notify_incident WHERE `+heldOpen+` ORDER BY id`)
		if err != nil {
			return fmt.Errorf("notify: read held incidents: %w", err)
		}
		byKind := map[IncidentKind]int{}
		top, h := Info, sha256.New()
		var total int
		for rows.Next() {
			var id, k, sev string
			if err := rows.Scan(&id, &k, &sev); err != nil {
				_ = rows.Close()
				return fmt.Errorf("notify: read held incidents: %w", err)
			}
			byKind[IncidentKind(k)]++
			total++
			if Severity(sev).rank() > top.rank() {
				top = Severity(sev)
			}
			_, _ = h.Write([]byte(id + "\n"))
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("notify: read held incidents: %w", err)
		}
		if total == 0 { // a summary still waiting whose incidents were all resolved or raised since: it would tell a stale count
			if _, err := tx.ExecContext(ctx, `DELETE FROM notify_pending WHERE notice_id IN (`+unsentSummaries+`)`); err != nil {
				return fmt.Errorf("notify: drop a waiting summary: %w", err)
			}
			return nil
		}
		sid := "fr-" + hex.EncodeToString(h.Sum(nil)[:12])
		if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET summary_id = ? WHERE `+heldOpen, sid); err != nil {
			return fmt.Errorf("notify: mark held incidents told: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM notify_pending WHERE notice_id <> ? AND notice_id IN (`+unsentSummaries+`)`, sid); err != nil {
			return fmt.Errorf("notify: replace a waiting summary: %w", err)
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
		return s.enqueue(ctx, tx, Notice{ID: sid, Kind: KindIncident, IncidentKind: string(kind), Severity: top, Title: title,
			What: "Vedette is new on this network, so what was already happening on it looks new too. Instead of one message each, the " +
				"low and medium incidents of its first 36 hours are told together: " + strings.Join(parts, ", ") + ". High and critical incidents and trap touches are still sent at once.",
			Action: "Open Incidents, look at each one, and resolve the ones you know about.", Link: s.link("/incidents"), At: now})
	})
}
