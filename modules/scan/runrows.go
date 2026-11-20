package scan

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/run"
)

// A vulnerability check keeps what it found as the items of its core_run (DB-DESIGN core_run_item). Four kinds of item, all
// written as the device they are about ends:
//
//	device         one per result row: subject_id the device, label "name (address)", outcome the row's result, note its words
//	finding        follows the device item of a row that has a finding: subject_id the finding, label the template that
//	               checked it, outcome "template", or "no_template" when none exists (label then says so)
//	identification one per device of a Scan now run: subject_id the device, outcome the reason nothing was recorded, or
//	               "recorded", note the sentence for it
//	identified     one per line the identification recorded: subject_id the device, label the line
const (
	kindDevice         = "device"
	kindFinding        = "finding"
	kindIdentification = "identification"
	kindIdentified     = "identified"

	outcomeTemplate    = "template"
	outcomeNoTemplate  = "no_template"
	outcomeRecorded    = "recorded"
	outcomeFound       = "found"
	labelNoTemplate    = "no template"
	itemLabelMax       = 200
	recordWriteTimeout = 30 * time.Second
)

// itemLabel is what the run page shows for a device: its name and address. The address has no spaces or brackets (an IP, or a
// dash), so splitLabel reads it back from the end.
func itemLabel(name, ip string) string {
	suffix := " (" + ip + ")"
	room := max(1, itemLabelMax-utf8.RuneCountInString(suffix))
	if utf8.RuneCountInString(name) > room {
		name = string([]rune(name)[:room-1]) + "…"
	}
	return name + suffix
}

// splitLabel is the inverse of itemLabel.
func splitLabel(label string) (name, ip string) {
	i := strings.LastIndex(label, " (")
	if i < 0 || !strings.HasSuffix(label, ")") {
		return label, "—"
	}
	return label[:i], label[i+2 : len(label)-1]
}

// record writes the rows of one device as items. The run may be stopping, so the write does not depend on the run's context.
func (s *Service) record(ctx context.Context, x *run.Exec, rows []RunRow, ident *IdentRow) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordWriteTimeout)
	defer cancel()
	add := func(it run.Item) {
		if err := x.AddItem(ctx, it); err != nil {
			s.cfg.Log.ErrorContext(ctx, "scan: recording a result of a run failed", "run", x.ID(), "kind", it.SubjectKind, "error", err)
		}
	}
	for _, r := range rows {
		add(run.Item{SubjectKind: kindDevice, SubjectID: r.TargetID, Label: itemLabel(r.Label, r.IP), Outcome: r.Result, Note: r.Note})
		if r.FindingID != nil {
			it := run.Item{SubjectKind: kindFinding, SubjectID: *r.FindingID, Label: labelNoTemplate, Outcome: outcomeNoTemplate}
			if r.Template != nil {
				it.Label, it.Outcome = *r.Template, outcomeTemplate
			}
			add(it)
		}
	}
	if ident == nil {
		return
	}
	outcome := outcomeRecorded
	if ident.Reason != nil {
		outcome = *ident.Reason
	}
	add(run.Item{SubjectKind: kindIdentification, SubjectID: ident.TargetID, Label: itemLabel(ident.Label, ident.IP), Outcome: outcome, Note: ident.Note})
	for _, f := range ident.Found {
		add(run.Item{SubjectKind: kindIdentified, SubjectID: ident.TargetID, Label: f, Outcome: outcomeFound})
	}
}

// ---- reading ----

// coreStatus is the state of a run in the words of contract.ts RunStatus: a queued run is shown as running (nothing else queues in
// its lane), one that ended partly (a window that closed, an unresponsive device) as auto_stopped, a failed one as stopped.
func viewStatus(st run.Status) string {
	switch st {
	case run.Queued, run.Waiting, run.Running:
		return "running"
	case run.Stopping:
		return "stopping"
	case run.Done:
		return "done"
	case run.Partial:
		return "auto_stopped"
	}
	return "stopped"
}

const runCols = `r.id, r.trigger, r.trigger_note, COALESCE(r.started_at, r.queued_at), r.requested_by, r.ended_at, r.status, r.total, r.done, r.stop_reason, r.error`

var triggerNames = map[run.Trigger]string{run.Manual: "manual", run.Schedule: "schedule", run.Event: "new_kev"}

type rowScanner interface{ Scan(...any) error }

func scanRunHead(row rowScanner) (RunView, error) {
	var v RunView
	var trig, st string
	var stop, errText sql.NullString
	if err := row.Scan(&v.ID, &trig, &v.TriggerNote, &v.StartedAt, &v.StartedBy, &v.EndedAt, &st, &v.Total, &v.Done, &stop, &errText); err != nil {
		return RunView{}, err
	}
	v.Trigger = triggerNames[run.Trigger(trig)]
	v.Status = viewStatus(run.Status(st))
	switch run.Status(st) {
	case run.Partial, run.Failed:
		if errText.Valid {
			v.StopReason = &errText.String
		}
	default:
		if stop.Valid {
			v.StopReason = &stop.String
		}
	}
	v.Results, v.Identification = []RunRow{}, []IdentRow{}
	return v, nil
}

// loadItems fills the results and the identification of the runs from their items.
func (s *Service) loadItems(ctx context.Context, runs []RunView) error {
	if len(runs) == 0 {
		return nil
	}
	at := make(map[string]int, len(runs))
	args := make([]any, len(runs))
	marks := make([]string, len(runs))
	for i, v := range runs {
		at[v.ID], args[i], marks[i] = i, v.ID, "?"
	}
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT run_id, subject_kind, subject_id, label, outcome, note FROM core_run_item
WHERE run_id IN (`+strings.Join(marks, ",")+`) ORDER BY run_id, seq`, args...)
	if err != nil {
		return fmt.Errorf("scan: reading the results of the runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	identAt := map[string]int{} // run id + device id -> index in Identification
	for rows.Next() {
		var runID, kind, label, outcome string
		var subject, note sql.NullString
		if err := rows.Scan(&runID, &kind, &subject, &label, &outcome, &note); err != nil {
			return fmt.Errorf("scan: reading the results of the runs: %w", err)
		}
		v := &runs[at[runID]]
		switch kind {
		case kindDevice:
			name, ip := splitLabel(label)
			v.Results = append(v.Results, RunRow{TargetID: subject.String, Label: name, IP: ip, Result: outcome, Note: note.String})
			if outcome == "matched" {
				v.Matched++
			}
		case kindFinding:
			if n := len(v.Results); n > 0 && subject.Valid {
				last := &v.Results[n-1]
				last.FindingID = &subject.String
				if outcome == outcomeTemplate {
					last.Template = &label
				}
			}
		case kindIdentification:
			name, ip := splitLabel(label)
			r := IdentRow{TargetID: subject.String, Label: name, IP: ip, Found: []string{}, Note: note.String}
			if outcome != outcomeRecorded {
				r.Reason = &outcome
			}
			identAt[runID+"\x00"+subject.String] = len(v.Identification)
			v.Identification = append(v.Identification, r)
		case kindIdentified:
			if i, ok := identAt[runID+"\x00"+subject.String]; ok {
				v.Identification[i].Found = append(v.Identification[i].Found, label)
			}
		}
	}
	return rows.Err()
}

// Run returns one run.
func (s *Service) Run(ctx context.Context, id string) (RunView, error) {
	v, err := scanRunHead(s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT `+runCols+` FROM core_run r WHERE r.id = ? AND r.module = ? AND r.kind = ?`, id, ModuleID, runKindName))
	if errors.Is(err, sql.ErrNoRows) {
		return RunView{}, errNoRun
	}
	if err != nil {
		return RunView{}, fmt.Errorf("scan: reading run %s: %w", id, err)
	}
	runs := []RunView{v}
	if err := s.loadItems(ctx, runs); err != nil {
		return RunView{}, err
	}
	s.live1(&runs[0])
	return runs[0], nil
}

// live1 adds what only the process executing the run knows: the device it is on and how far that device is.
func (s *Service) live1(v *RunView) {
	if v.Status == "running" || v.Status == "stopping" {
		v.Current = s.currentOf(v.ID)
		v.Progress = s.progressOf(v.ID)
	}
}

// Runs returns the newest runs, newest first, with their per-device results (S-SCAN-3).
func (s *Service) Runs(ctx context.Context) ([]RunView, error) {
	return s.runs(ctx, ``)
}

// RunsOf returns the newest runs that checked this device (the device page's Last checks), newest first, however many runs of
// other devices came after.
func (s *Service) RunsOf(ctx context.Context, asset string) ([]RunView, error) {
	return s.runs(ctx, `AND EXISTS (SELECT 1 FROM core_run_item i WHERE i.run_id = r.id AND i.subject_kind = 'device' AND i.subject_id = ?)`, asset)
}

func (s *Service) runs(ctx context.Context, where string, args ...any) ([]RunView, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT `+runCols+` FROM core_run r WHERE r.module = ? AND r.kind = ? `+where+
		` ORDER BY r.queued_at DESC, r.rowid DESC LIMIT ?`, append([]any{ModuleID, runKindName}, append(args, keepRuns)...)...)
	if err != nil {
		return nil, fmt.Errorf("scan: listing runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []RunView{}
	for rows.Next() {
		v, err := scanRunHead(rows)
		if err != nil {
			return nil, fmt.Errorf("scan: listing runs: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.loadItems(ctx, out); err != nil {
		return nil, err
	}
	for i := range out {
		s.live1(&out[i])
	}
	return out, nil
}
