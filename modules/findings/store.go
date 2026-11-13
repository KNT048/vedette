package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/store"
)

// Record is one stored finding: the pair, its lifecycle state, timestamps and history.
type Record struct {
	ID      string
	AssetID string
	CVE     string
	Finding
	FirstSeen time.Time
	LastSeen  time.Time
	History   []HistoryEntry
}

// querier is what both *sql.DB (reads) and *sql.Tx (inside a write) offer.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// evidenceDoc is the JSON of fnd_finding.evidence and of the evidence field of the API.
type evidenceDoc struct {
	Summary   string    `json:"summary"`
	Template  string    `json:"template,omitempty"`
	Request   string    `json:"request,omitempty"`
	Response  string    `json:"response,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

func newEvidenceDoc(e *Evidence) *evidenceDoc {
	if e == nil {
		return nil
	}
	return &evidenceDoc{Summary: e.Summary, Template: e.Template, Request: e.Request, Response: e.Response, CheckedAt: e.CheckedAt.UTC()}
}

func (d *evidenceDoc) evidence() *Evidence {
	if d == nil {
		return nil
	}
	return &Evidence{Summary: d.Summary, Template: d.Template, Request: d.Request, Response: d.Response, CheckedAt: d.CheckedAt}
}

const findingColumns = `id, asset_id, cve, status, severity, confidence, basis, evidence, first_seen, last_seen, resolved_by, resolved_at, resolution_note, resolution_reason`

type scanner interface{ Scan(dest ...any) error }

func scanRecord(s scanner) (Record, error) {
	var (
		r                                      Record
		status, severity, basis                string
		evidence, resolvedBy, resolvedAt, note sql.NullString
		reason                                 sql.NullString
		first, last                            string
	)
	if err := s.Scan(&r.ID, &r.AssetID, &r.CVE, &status, &severity, &r.Confidence, &basis, &evidence, &first, &last, &resolvedBy, &resolvedAt, &note, &reason); err != nil {
		return Record{}, err
	}
	r.Status, r.Severity, r.Basis = Status(status), Severity(severity), Basis(basis)
	var err error
	if r.FirstSeen, err = parseTS(first); err != nil {
		return Record{}, err
	}
	if r.LastSeen, err = parseTS(last); err != nil {
		return Record{}, err
	}
	if evidence.Valid {
		var d evidenceDoc
		if err := json.Unmarshal([]byte(evidence.String), &d); err != nil {
			return Record{}, fmt.Errorf("evidence: %w", err)
		}
		r.Evidence = d.evidence()
	}
	r.ResolvedBy, r.ResolutionNote, r.ResolutionReason = resolvedBy.String, note.String, reason.String
	if resolvedAt.Valid {
		if r.ResolvedAt, err = parseTS(resolvedAt.String); err != nil {
			return Record{}, err
		}
	}
	return r, nil
}

func parseTS(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("timestamp: %w", err)
	}
	return t, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullTS(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return store.FormatTS(t)
}

// loadHistory appends the history rows of the findings in byID (for one asset, or all when assetID is empty).
func loadHistory(ctx context.Context, q querier, assetID string, byID map[string]*Record) error {
	rows, err := q.QueryContext(ctx, `SELECT h.finding_id, h.ts, h.user, h.action, coalesce(h.note, '')
		FROM fnd_finding_history h JOIN fnd_finding f ON f.id = h.finding_id
		WHERE (?1 = '' OR f.asset_id = ?1) ORDER BY h.ts, h.rowid`, assetID)
	if err != nil {
		return fmt.Errorf("history: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, ts string
		var h HistoryEntry
		if err := rows.Scan(&id, &ts, &h.User, &h.Action, &h.Note); err != nil {
			return fmt.Errorf("history: %w", err)
		}
		r, ok := byID[id]
		if !ok {
			continue
		}
		if h.TS, err = parseTS(ts); err != nil {
			return err
		}
		r.History = append(r.History, h)
	}
	return rows.Err()
}

// listRecords returns the findings of one asset (assetID != "") or all of them, newest first (the
// mock lists the most recently matched first; findings of one match keep their match order).
func listRecords(ctx context.Context, q querier, assetID string) ([]Record, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+findingColumns+` FROM fnd_finding
		WHERE (?1 = '' OR asset_id = ?1) ORDER BY first_seen DESC, rowid ASC`, assetID)
	if err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("list: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	byID := make(map[string]*Record, len(out))
	for i := range out {
		byID[out[i].ID] = &out[i]
	}
	if err := loadHistory(ctx, q, assetID, byID); err != nil {
		return nil, err
	}
	return out, nil
}

func loadRecord(ctx context.Context, q querier, where string, args ...any) (Record, error) {
	r, err := scanRecord(q.QueryRowContext(ctx, `SELECT `+findingColumns+` FROM fnd_finding WHERE `+where, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, fmt.Errorf("findings: loading finding: %w", ErrNotFound)
	}
	if err != nil {
		return Record{}, fmt.Errorf("findings: loading finding: %w", err)
	}
	rows, err := q.QueryContext(ctx, `SELECT ts, user, action, coalesce(note, '') FROM fnd_finding_history WHERE finding_id = ? ORDER BY ts, rowid`, r.ID)
	if err != nil {
		return Record{}, fmt.Errorf("findings: loading history: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var ts string
		var h HistoryEntry
		if err := rows.Scan(&ts, &h.User, &h.Action, &h.Note); err != nil {
			return Record{}, fmt.Errorf("findings: loading history: %w", err)
		}
		if h.TS, err = parseTS(ts); err != nil {
			return Record{}, err
		}
		r.History = append(r.History, h)
	}
	if err := rows.Err(); err != nil {
		return Record{}, fmt.Errorf("findings: loading history: %w", err)
	}
	return r, nil
}

func loadByID(ctx context.Context, q querier, id string) (Record, error) {
	return loadRecord(ctx, q, "id = ?", id)
}

func loadByPair(ctx context.Context, q querier, assetID, cve string) (Record, error) {
	return loadRecord(ctx, q, "asset_id = ? AND cve = ?", assetID, cve)
}

func insertRecord(ctx context.Context, tx *sql.Tx, r Record) error {
	ev, err := encodeEvidence(r.Evidence)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO fnd_finding (`+findingColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.AssetID, r.CVE, string(r.Status), string(r.Severity), r.Confidence, string(r.Basis), ev,
		store.FormatTS(r.FirstSeen), store.FormatTS(r.LastSeen), nullString(r.ResolvedBy), nullTS(r.ResolvedAt), nullString(r.ResolutionNote), nullString(r.ResolutionReason))
	if err != nil {
		return fmt.Errorf("findings: inserting finding: %w", err)
	}
	return nil
}

func updateRecord(ctx context.Context, tx *sql.Tx, r Record) error {
	ev, err := encodeEvidence(r.Evidence)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE fnd_finding SET status = ?, severity = ?, confidence = ?, basis = ?, evidence = ?, last_seen = ?,
		resolved_by = ?, resolved_at = ?, resolution_note = ?, resolution_reason = ? WHERE id = ?`,
		string(r.Status), string(r.Severity), r.Confidence, string(r.Basis), ev, store.FormatTS(r.LastSeen),
		nullString(r.ResolvedBy), nullTS(r.ResolvedAt), nullString(r.ResolutionNote), nullString(r.ResolutionReason), r.ID)
	if err != nil {
		return fmt.Errorf("findings: updating finding: %w", err)
	}
	return nil
}

func encodeEvidence(e *Evidence) (any, error) {
	if e == nil {
		return nil, nil
	}
	b, err := json.Marshal(newEvidenceDoc(e))
	if err != nil {
		return nil, fmt.Errorf("findings: encoding evidence: %w", err)
	}
	return string(b), nil
}

func insertHistory(ctx context.Context, tx *sql.Tx, findingID string, h HistoryEntry) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO fnd_finding_history (id, finding_id, ts, user, action, note) VALUES (?, ?, ?, ?, ?, ?)`,
		store.NewID("fh"), findingID, store.FormatTS(h.TS), h.User, h.Action, nullString(h.Note))
	if err != nil {
		return fmt.Errorf("findings: inserting history: %w", err)
	}
	return nil
}
