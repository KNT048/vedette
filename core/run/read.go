package run

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Run is the read model of a run: the Runs tab, the run page and every "Open the run" link read this.
type Run struct {
	ID          string   `json:"id"`
	Module      string   `json:"module"`
	Kind        string   `json:"kind"`
	Lane        string   `json:"lane"`
	Title       string   `json:"title"`
	Trigger     Trigger  `json:"trigger"`
	TriggerNote *string  `json:"trigger_note"`
	RequestedBy string   `json:"requested_by"`
	ScheduleID  *string  `json:"schedule_id"`
	Subject     *Subject `json:"subject"`
	ParentID    *string  `json:"parent_id"`
	Status      Status   `json:"status"`
	WaitingFor  *string  `json:"waiting_for"`
	StopReason  *string  `json:"stop_reason"`
	Error       *string  `json:"error"`
	Total       int      `json:"total"`
	Done        int      `json:"done"`
	QueuedAt    string   `json:"queued_at"`
	StartedAt   *string  `json:"started_at"`
	EndedAt     *string  `json:"ended_at"`
	UpdatedAt   string   `json:"updated_at"`
	CanStop     bool     `json:"can_stop"`
	CanResume   bool     `json:"can_resume"`
	// Summary is the run's state in one line of words, made by the box (summary.go): what it waits for, how far it got, why it
	// stopped. Every page shows this line rather than building its own.
	Summary string `json:"summary"`
	// BlockedBy is the run that holds the lane a queued run waits for; nil when the run is not queued or its lane is free.
	BlockedBy *Ref `json:"blocked_by"`
}

// Ref names another run.
type Ref struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Step is a step of a run.
type Step struct {
	Seq       int     `json:"seq"`
	Name      string  `json:"name"`
	Status    Status  `json:"status"`
	Total     int     `json:"total"`
	Done      int     `json:"done"`
	Note      *string `json:"note"`
	StartedAt *string `json:"started_at"`
	EndedAt   *string `json:"ended_at"`
}

// ItemRow is a device or host the run touched, as stored.
type ItemRow struct {
	Seq         int     `json:"seq"`
	SubjectKind string  `json:"subject_kind"`
	SubjectID   *string `json:"subject_id"`
	Label       string  `json:"label"`
	Outcome     string  `json:"outcome"`
	Note        *string `json:"note"`
}

// LogLine is a line of a run's log.
type LogLine struct {
	TS    string `json:"ts"`
	Level Level  `json:"level"`
	Text  string `json:"text"`
}

// Detail is a run with its steps, the devices it touched, the tail of its log and the runs under it.
type Detail struct {
	Run
	Steps      []Step    `json:"steps"`
	Items      []ItemRow `json:"items"`
	ItemsTotal int       `json:"items_total"`
	Log        []LogLine `json:"log"`
	Children   []Run     `json:"children"`
}

// What Get returns at most.
const (
	DetailItems = 500 // the first items, in the order they came
	DetailLog   = 200 // the newest log lines, oldest first
	MaxPage     = 200 // rows of a page of List
)

// Filter narrows List. Empty fields do not filter.
type Filter struct {
	Module, Kind string
	Status       Status
	SubjectKind  string
	SubjectID    string
	Q            string // searched in the title, the subject's name, who asked and the id
	Offset       int
	Limit        int // 1 to MaxPage; 0 or more than MaxPage means MaxPage
}

const runCols = `r.id, r.module, r.kind, r.lane, r.title, r.trigger, r.trigger_note, r.requested_by, r.schedule_id, r.subject_kind,
	r.subject_id, r.subject_label, r.parent_id, r.status, r.waiting_for, r.stop_reason, r.error, r.total, r.done, r.queued_at,
	r.started_at, r.ended_at, r.updated_at,
	(SELECT h.id FROM core_run h WHERE r.status = 'queued' AND h.lane = r.lane AND h.status IN ('running', 'stopping') AND h.id <> r.id LIMIT 1),
	(SELECT h.title FROM core_run h WHERE r.status = 'queued' AND h.lane = r.lane AND h.status IN ('running', 'stopping') AND h.id <> r.id LIMIT 1),
	(NOT EXISTS (SELECT 1 FROM core_run_step s WHERE s.run_id = r.id)
	 OR EXISTS (SELECT 1 FROM core_run_step s WHERE s.run_id = r.id AND s.status <> 'done'))`

type querier interface {
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

type scanner interface{ Scan(dest ...any) error }

func (m *Manager) scanRun(ctx context.Context, s scanner) (Run, error) {
	var r Run
	var subKind, subID, subLabel, blockID, blockTitle *string
	var workLeft bool
	err := s.Scan(&r.ID, &r.Module, &r.Kind, &r.Lane, &r.Title, &r.Trigger, &r.TriggerNote, &r.RequestedBy, &r.ScheduleID, &subKind,
		&subID, &subLabel, &r.ParentID, &r.Status, &r.WaitingFor, &r.StopReason, &r.Error, &r.Total, &r.Done, &r.QueuedAt,
		&r.StartedAt, &r.EndedAt, &r.UpdatedAt, &blockID, &blockTitle, &workLeft)
	if err != nil {
		return Run{}, err
	}
	if blockID != nil && blockTitle != nil {
		r.BlockedBy = &Ref{ID: *blockID, Title: *blockTitle}
	}
	if subKind != nil && subID != nil {
		r.Subject = &Subject{Kind: *subKind, ID: *subID}
		if subLabel != nil {
			r.Subject.Label = *subLabel
		}
	}
	r.CanStop = r.Status == Queued || r.Status == Waiting || r.Status == Running
	r.CanResume = m.canResume(r, workLeft)
	r.Summary = m.summary(ctx, r)
	return r, nil
}

// canResume is the one rule of the Resume button: a waiting run, or a stopped run with work left whose kind is registered
// and can go on from its steps.
func (m *Manager) canResume(r Run, workLeft bool) bool {
	if r.Status == Waiting {
		return true
	}
	if r.Status != Stopped || !workLeft {
		return false
	}
	k, ok := m.kind(r.Module, r.Kind)
	return ok && k.Resumable
}

// List returns one page of runs, newest first, and the number of runs that match.
func (m *Manager) List(ctx context.Context, f Filter) ([]Run, int, error) {
	var where []string
	var args []any
	add := func(cond string, v any) { where, args = append(where, cond), append(args, v) }
	if f.Module != "" {
		add("r.module = ?", f.Module)
	}
	if f.Kind != "" {
		add("r.kind = ?", f.Kind)
	}
	if f.Status != "" {
		add("r.status = ?", string(f.Status))
	}
	if f.SubjectKind != "" {
		add("r.subject_kind = ?", f.SubjectKind)
	}
	if f.SubjectID != "" {
		add("r.subject_id = ?", f.SubjectID)
	}
	if q := strings.TrimSpace(f.Q); q != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(q)) + "%"
		where = append(where, `(lower(r.title) LIKE ? ESCAPE '\' OR lower(COALESCE(r.subject_label, '')) LIKE ? ESCAPE '\'
			OR lower(r.requested_by) LIKE ? ESCAPE '\' OR r.id = ?)`)
		args = append(args, like, like, like, q)
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	db := m.cfg.DB.Reader()
	var total int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM core_run r`+cond, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("run: count: %w", err)
	}
	limit := f.Limit
	if limit <= 0 || limit > MaxPage {
		limit = MaxPage
	}
	offset := max(f.Offset, 0)
	runs, err := m.readRuns(ctx, db, `SELECT `+runCols+` FROM core_run r`+cond+` ORDER BY r.queued_at DESC, r.rowid DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	return runs, total, nil
}

func (m *Manager) readRuns(ctx context.Context, q querier, query string, args ...any) ([]Run, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("run: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Run{}
	for rows.Next() {
		r, err := m.scanRun(ctx, rows)
		if err != nil {
			return nil, fmt.Errorf("run: list: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (m *Manager) getTx(ctx context.Context, q querier, id string) (Run, error) {
	r, err := m.scanRun(ctx, q.QueryRowContext(ctx, `SELECT `+runCols+` FROM core_run r WHERE r.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	if err != nil {
		return Run{}, fmt.Errorf("run: read: %w", err)
	}
	return r, nil
}

// AdminResume says the run's kind lets only an administrator resume it (Kind.AdminResume); an unknown kind says false.
func (m *Manager) AdminResume(r Run) bool {
	k, ok := m.kind(r.Module, r.Kind)
	return ok && k.AdminResume
}

// Read returns a run without its steps, items, log and children.
func (m *Manager) Read(ctx context.Context, id string) (Run, error) {
	return m.getTx(ctx, m.cfg.DB.Reader(), id)
}

// Get returns a run with its steps, its first DetailItems items, its last DetailLog log lines and the runs under it.
func (m *Manager) Get(ctx context.Context, id string) (Detail, error) {
	db := m.cfg.DB.Reader()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true}) // one snapshot: the steps add up to the run's totals
	if err != nil {
		return Detail{}, err
	}
	defer func() { _ = tx.Rollback() }()
	r, err := m.getTx(ctx, tx, id)
	if err != nil {
		return Detail{}, err
	}
	d := Detail{Run: r, Steps: []Step{}, Items: []ItemRow{}, Log: []LogLine{}}
	rows, err := tx.QueryContext(ctx, `SELECT seq, name, status, total, done, note, started_at, ended_at FROM core_run_step WHERE run_id = ? ORDER BY seq`, id)
	if err != nil {
		return Detail{}, err
	}
	for rows.Next() {
		var s Step
		if err := rows.Scan(&s.Seq, &s.Name, &s.Status, &s.Total, &s.Done, &s.Note, &s.StartedAt, &s.EndedAt); err != nil {
			_ = rows.Close()
			return Detail{}, err
		}
		d.Steps = append(d.Steps, s)
	}
	if err := rows.Close(); err != nil {
		return Detail{}, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM core_run_item WHERE run_id = ?`, id).Scan(&d.ItemsTotal); err != nil {
		return Detail{}, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT seq, subject_kind, subject_id, label, outcome, note FROM core_run_item WHERE run_id = ? ORDER BY seq LIMIT ?`, id, DetailItems)
	if err != nil {
		return Detail{}, err
	}
	for rows.Next() {
		var it ItemRow
		if err := rows.Scan(&it.Seq, &it.SubjectKind, &it.SubjectID, &it.Label, &it.Outcome, &it.Note); err != nil {
			_ = rows.Close()
			return Detail{}, err
		}
		d.Items = append(d.Items, it)
	}
	if err := rows.Close(); err != nil {
		return Detail{}, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT ts, level, text FROM (SELECT id, ts, level, text FROM core_run_log WHERE run_id = ? ORDER BY id DESC LIMIT ?) ORDER BY id`, id, DetailLog)
	if err != nil {
		return Detail{}, err
	}
	for rows.Next() {
		var l LogLine
		if err := rows.Scan(&l.TS, &l.Level, &l.Text); err != nil {
			_ = rows.Close()
			return Detail{}, err
		}
		d.Log = append(d.Log, l)
	}
	if err := rows.Close(); err != nil {
		return Detail{}, err
	}
	d.Children, err = m.readRuns(ctx, tx, `SELECT `+runCols+` FROM core_run r WHERE r.parent_id = ? ORDER BY r.queued_at, r.rowid LIMIT ?`, id, MaxPage)
	if err != nil {
		return Detail{}, err
	}
	return d, nil
}
