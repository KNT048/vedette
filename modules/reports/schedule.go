package reports

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/schedule"
)

// scheduleLimits is what the report's schedule allows: weekly or monthly, at any time, outside the scan window (a report is not a
// scan). A report covers a week or a month, so an interval or a single run would not match a period.
var scheduleLimits = schedule.Limits{Freqs: []schedule.Freq{schedule.Weekly, schedule.Monthly}, Windows: []schedule.WindowMode{schedule.WindowNone},
	Reason: "A report covers a week or a month."}

// ScheduleOwner is what the report registers with core/schedule (key reports.def:<id>). It is off until an administrator turns it on
// (a clean install sends nothing), Monday 08:00 in the organisation's zone by default. When it comes due nothing is mailed inside the
// schedule's transaction: Start marks the definition (send_due_at) and the send job mails it, because sending talks to a mail server.
func (s *Service) ScheduleOwner() schedule.Owner {
	return schedule.Owner{Module: ModuleID, Key: ScheduleOwnerKey, PerSubject: true, AdminOnly: true, Limits: scheduleLimits,
		Default: schedule.WeeklyAt("08:00", 1), DefaultOn: false,
		Subject: func(_ context.Context, id string) (bool, error) { return id == DefinitionID, nil },
		Start:   s.startSend}
}

// startSend marks the definition for the send job, inside the schedule's transaction. It skips, saying why, when there is no recipient
// or the email channel is not ready, so the schedule shows the reason instead of a failed send in the history.
func (s *Service) startSend(ctx context.Context, tx *sql.Tx, f schedule.Fire) (string, error) {
	var rec string
	err := tx.QueryRowContext(ctx, `SELECT recipients FROM rep_definition WHERE id = ?`, f.Subject).Scan(&rec)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("reports: reading the recipients: %w", err)
	}
	var to []string
	if rec != "" {
		if err := json.Unmarshal([]byte(rec), &to); err != nil {
			return "", fmt.Errorf("reports: reading the recipients: %w", err)
		}
	}
	if len(to) == 0 {
		return "", schedule.Skip("The report has no recipient. Add an email in Reports, Settings.")
	}
	if s.cfg.Mail == nil {
		return "", schedule.Skip("The email channel is not ready. Set it up in Settings, Alert channels.")
	}
	if ok, _ := s.cfg.Mail.Ready(ctx); !ok {
		return "", schedule.Skip("The email channel is not ready. Set it up in Settings, Alert channels.")
	}
	var by any // nil: the schedule
	if f.Trigger == run.Manual && f.By != "" && f.By != run.System {
		by = f.By
	}
	if _, err := tx.ExecContext(ctx, `UPDATE rep_definition SET send_due_at = ?, send_by = ? WHERE id = ?`, ts(f.DueAt), by, f.Subject); err != nil {
		return "", fmt.Errorf("reports: marking the send: %w", err)
	}
	return "", nil
}

// catchUp is how late the job may still send a due time it found marked (the box or the module was off): once, and only within this
// window. A report that arrives days late would show the wrong period.
const catchUp = 24 * time.Hour

// RunPending is the body of the send job: every definition the schedule marked is unmarked, then sent once (POST-2). The mark is
// cleared before the send, so a crash cannot send it twice; a failed send is in the history and is not retried by itself.
func (s *Service) RunPending(ctx context.Context) error {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT id, send_due_at, send_by FROM rep_definition WHERE send_due_at IS NOT NULL`)
	if err != nil {
		return fmt.Errorf("reports: reading the due sends: %w", err)
	}
	type due struct {
		id, at string
		by     sql.NullString
	}
	var list []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.at, &d.by); err != nil {
			_ = rows.Close()
			return fmt.Errorf("reports: reading the due sends: %w", err)
		}
		list = append(list, d)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("reports: reading the due sends: %w", err)
	}
	var errs []error
	for _, d := range list {
		var n int64
		err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			res, err := tx.ExecContext(ctx, `UPDATE rep_definition SET send_due_at = NULL, send_by = NULL WHERE id = ? AND send_due_at = ?`, d.id, d.at)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("reports: clearing a due send: %w", err))
			continue
		}
		if n == 0 { // another run of the job took it
			continue
		}
		if at := parseTS(d.at); !at.IsZero() && s.clock().Sub(at) > catchUp {
			s.cfg.Log.WarnContext(ctx, "reports: a scheduled send is more than a day late and is dropped", "due", d.at)
			continue
		}
		trigger, by := triggerSched, ""
		if d.by.Valid {
			trigger, by = triggerManual, d.by.String
		}
		if _, err := s.send(ctx, trigger, by); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
