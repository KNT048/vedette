package exposure

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
)

// termsSlack is how long after an older stopped OpenVAS step its terms row may be written: that row was written after the run was
// cancelled, while OpenVAS stopped its task, so it can come just after the step's own row.
const termsSlack = 2 * time.Minute

// StopsAtStart gives an OpenVAS step stored as stopped before the reason was kept (state stopped, no stop, the older stop line) its
// stop time and, when the audit log proves it, its reason, in exposure's own rows (INV-34). The older version wrote, with every such
// step, an exposure.greenbone_scan row in the same transaction: its time is the stop time. A terms change that stopped the scan
// wrote its own row (stoppedNote, who), and switching the module off wrote module.disable: those prove the reason. A Stop and a
// shutdown wrote nothing, so a step with neither keeps no reason and the page says it was one of those two. A step whose stop time
// is not in the log either (pruned after 365 days, or a write that failed) is left as it is. It runs at start-up, after
// CutOffAtStart; a step it gave a reason is not read again. Failures are logged.
func (s *Service) StopsAtStart(ctx context.Context) {
	if err := s.stopsAtStart(ctx); err != nil {
		s.cfg.Log.ErrorContext(ctx, "exposure: giving older stopped OpenVAS steps their stop time and reason failed", "error", err)
	}
}

type oldStopRow struct {
	id, target, value, date, scanned, next string
}

func (s *Service) stopsAtStart(ctx context.Context) error {
	db := s.cfg.DB.Reader()
	rows, err := db.QueryContext(ctx, `SELECT s.id, s.target_id, t.value, s.date, s.scanned_at,
		coalesce((SELECT min(n.scanned_at) FROM exp_snapshot AS n WHERE n.target_id = s.target_id AND n.scanned_at > s.scanned_at), '9999')
		FROM exp_snapshot AS s JOIN exp_target AS t ON t.id = s.target_id
		WHERE coalesce(json_extract(s.greenbone_run, '$.state'), 'stopped') = 'stopped' AND json_extract(s.greenbone_run, '$.stop') IS NULL
		ORDER BY s.scanned_at`)
	if err != nil {
		return err
	}
	var todo []oldStopRow
	for rows.Next() {
		var r oldStopRow
		if err := rows.Scan(&r.id, &r.target, &r.value, &r.date, &r.scanned, &r.next); err != nil {
			_ = rows.Close()
			return err
		}
		todo = append(todo, r)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	for _, r := range todo {
		if err := s.oldStopOf(ctx, db, r); err != nil {
			return fmt.Errorf("snapshot %s: %w", r.id, err)
		}
	}
	return nil
}

// oldStopOf classifies one candidate and stores what it found.
func (s *Service) oldStopOf(ctx context.Context, db *sql.DB, r oldStopRow) error {
	snap, ok, err := loadSnapshot(ctx, db, r.target, r.date)
	if err != nil || !ok {
		return err
	}
	run := snap.GreenboneRun
	if run.State != GBRunStopped || run.Stop != nil || !hasOldStopLine(snap.NotChecked) {
		return nil
	}
	end := ""
	gb, err := audit.Find(ctx, db, []string{"exposure.greenbone_scan"}, r.value, r.scanned, r.next, 1)
	if err != nil {
		return err
	}
	switch {
	case len(gb) > 0:
		end = gb[0].TS
	case run.EndedAt != nil:
		end = *run.EndedAt
	default:
		return nil // no time on record: the page says so
	}
	from := r.scanned
	if run.StartedAt != nil && *run.StartedAt < from {
		from = *run.StartedAt
	}
	endT, err := parseTS(end)
	if err != nil {
		return nil
	}
	var stop *GreenboneStop
	terms, err := audit.Find(ctx, db, []string{"exposure.terms_revoke", "exposure.terms_accept"}, r.value, from, store.FormatTS(endT.Add(termsSlack)), maxFindRows)
	if err != nil {
		return err
	}
	for _, a := range terms {
		if strings.HasPrefix(a.Detail, stoppedNote) {
			by := a.User
			stop = &GreenboneStop{Reason: StopTerms, By: &by}
			break
		}
	}
	if stop == nil {
		off, err := audit.Find(ctx, db, []string{"module.disable"}, ModuleID, from, end, 1)
		if err != nil {
			return err
		}
		if len(off) > 0 {
			stop = &GreenboneStop{Reason: StopModule}
		}
	}
	if stop == nil && run.EndedAt != nil && snap.FinishedAt != nil {
		return nil // nothing new to store
	}
	return s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		return storeOldStop(ctx, tx, r.target, r.date, end, stop)
	})
}

// maxFindRows bounds the terms rows read for one step.
const maxFindRows = 50

// storeOldStop stores the stop time (when the step had none) and the reason (when proved) of an older stopped step, read again in
// the write so a run that changed it meanwhile is left alone; a proved reason replaces the older stop line with that reason's line.
func storeOldStop(ctx context.Context, tx *sql.Tx, target, date, end string, stop *GreenboneStop) error {
	snap, ok, err := loadSnapshot(ctx, tx, target, date)
	if err != nil || !ok || snap.GreenboneRun.State != GBRunStopped || snap.GreenboneRun.Stop != nil {
		return err
	}
	run := snap.GreenboneRun
	if run.EndedAt == nil {
		run.EndedAt = &end
	}
	not := snap.NotChecked
	if stop != nil {
		run.Stop = stop
		not = make([]NotCheckedRow, len(snap.NotChecked))
		for i, n := range snap.NotChecked {
			not[i] = n
			switch {
			case n.Kind != "greenbone":
			case strings.HasSuffix(n.Text, notGBStoppedSome):
				not[i].Text = strings.TrimSuffix(n.Text, notGBStoppedSome) + gbStoppedLine(stop, true)
			case strings.HasSuffix(n.Text, notGBStopped):
				not[i].Text = strings.TrimSuffix(n.Text, notGBStopped) + gbStoppedLine(stop, false)
			}
		}
	}
	c := snap.Content
	c.NotChecked = not
	docs, err := snapshotDocs(c, snap.Counts)
	if err != nil {
		return err
	}
	doc, err := json.Marshal(run)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE exp_snapshot SET not_checked = ?, greenbone_run = ?, finished_at = coalesce(finished_at, ?) WHERE id = ?`,
		docs[7], string(doc), *run.EndedAt, snap.ID)
	return err
}

// hasOldStopLine says the step's line is the one an older running Vedette stored for a Stop, a shutdown, the module switched off and
// the terms withdrawn or lowered alike (also after a domain address's prefix).
func hasOldStopLine(rows []NotCheckedRow) bool {
	for _, n := range rows {
		if n.Kind == "greenbone" && (strings.HasSuffix(n.Text, notGBStopped) || strings.HasSuffix(n.Text, notGBStoppedSome)) {
			return true
		}
	}
	return false
}
