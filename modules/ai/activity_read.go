package ai

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/core/chain/chainhead"
	"github.com/knt048/vedette/core/store/coredb"
)

// The activity log as people read it (S-AI-8, D-48): the list, the check that nobody edited it, and how long it is kept.

// The retention of the log in days (INV-19).
const (
	DefaultRetentionDays = 365
	MinRetentionDays     = 90
	MaxRetentionDays     = 3650
)

// MaxActivityItems is the most rows one list answers with: the newest ones.
// ponytail: no paging, the newest 1000 rows with the filters applied; add a cursor when someone needs to page back further.
const MaxActivityItems = 1000

// activityChain is the name of the chain in core_chain_head and core_chain_anchor.
const activityChain = "ai_activity"

// RetentionDays is how long the activity log is kept.
func (s *Service) RetentionDays(ctx context.Context) (int, error) {
	var raw string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT value FROM ai_setting WHERE key = 'activity'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultRetentionDays, nil
	}
	if err != nil {
		return 0, fmt.Errorf("ai: read retention: %w", err)
	}
	var v struct {
		RetentionDays int `json:"retention_days"`
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil || v.RetentionDays < MinRetentionDays || v.RetentionDays > MaxRetentionDays {
		return 0, fmt.Errorf("ai: the saved retention is not valid (%d days)", v.RetentionDays)
	}
	return v.RetentionDays, nil
}

// SetRetention saves how long the log is kept (admin). It is the setting only: removing old rows is PruneActivity.
func (s *Service) SetRetention(ctx context.Context, who string, days int) (int, error) {
	if days < MinRetentionDays || days > MaxRetentionDays {
		return 0, perr("invalid_retention", "Keep the activity log for %d to %d days.", MinRetentionDays, MaxRetentionDays)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Clock()
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := upsertSetting(ctx, tx, "activity", map[string]int{"retention_days": days}, now, who); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, who, "ai.activity_retention", fmt.Sprintf("%d days", days), "")
	})
	if err != nil {
		return 0, err
	}
	return days, nil
}

// ActivityFilter narrows the list; a zero value does not narrow.
type ActivityFilter struct {
	Job      string
	Result   ActivityResult
	From, To time.Time // inclusive
}

// ActivityPage is the answer of `GET /ai/activity`: the newest rows that match, and the size of the whole log.
type ActivityPage struct {
	Items         []ActivityEntry `json:"items"`
	Total         int             `json:"total"`
	RetentionDays int             `json:"retention_days"`
}

const activityCols = `id, ts, job, profile, model, trigger, hooks, tools, input_hash, output_hash, summary, tokens_in, tokens_out, result, links, prev_hash, hash`

type rowScanner interface{ Scan(dest ...any) error }

func scanActivity(r rowScanner) (ActivityEntry, error) {
	var e ActivityEntry
	var hooks, tools, result string
	var links sql.NullString
	if err := r.Scan(&e.ID, &e.TS, &e.Job, &e.Profile, &e.Model, &e.Trigger, &hooks, &tools, &e.InputHash, &e.OutputHash, &e.Summary, &e.TokensIn, &e.TokensOut, &result, &links, &e.PrevHash, &e.Hash); err != nil {
		return ActivityEntry{}, err
	}
	e.Result = ActivityResult(result)
	if err := json.Unmarshal([]byte(hooks), &e.Hooks); err != nil {
		return ActivityEntry{}, fmt.Errorf("ai: stored hooks of %s: %w", e.ID, err)
	}
	if err := json.Unmarshal([]byte(tools), &e.Tools); err != nil {
		return ActivityEntry{}, fmt.Errorf("ai: stored tools of %s: %w", e.ID, err)
	}
	if links.Valid {
		if err := json.Unmarshal([]byte(links.String), &e.Links); err != nil {
			return ActivityEntry{}, fmt.Errorf("ai: stored links of %s: %w", e.ID, err)
		}
	}
	return e.normalized(), nil
}

// ListActivity returns the newest rows that match the filter, newest first (INV-17). Total is the size of the whole log, not of the match.
func (s *Service) ListActivity(ctx context.Context, f ActivityFilter) (ActivityPage, error) {
	days, err := s.RetentionDays(ctx)
	if err != nil {
		return ActivityPage{}, err
	}
	from, to := "", ""
	if !f.From.IsZero() {
		from = FormatTS(f.From)
	}
	if !f.To.IsZero() {
		to = FormatTS(f.To)
	}
	page := ActivityPage{Items: []ActivityEntry{}, RetentionDays: days}
	// one read transaction: the rows and the total are of the same moment
	tx, err := s.cfg.DB.Reader().BeginTx(ctx, nil)
	if err != nil {
		return ActivityPage{}, fmt.Errorf("ai: list activity: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // read-only
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ai_activity`).Scan(&page.Total); err != nil {
		return ActivityPage{}, fmt.Errorf("ai: list activity: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+activityCols+` FROM ai_activity
		WHERE (? = '' OR job = ?) AND (? = '' OR result = ?) AND (? = '' OR ts >= ?) AND (? = '' OR ts <= ?)
		ORDER BY seq DESC LIMIT ?`, f.Job, f.Job, string(f.Result), string(f.Result), from, from, to, to, MaxActivityItems)
	if err != nil {
		return ActivityPage{}, fmt.Errorf("ai: list activity: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		e, err := scanActivity(rows)
		if err != nil {
			return ActivityPage{}, err
		}
		page.Items = append(page.Items, e)
	}
	return page, rows.Err()
}

// VerifyActivity checks the whole log (INV-18): every row links to the one before and hashes to what is stored, the first row
// links to the anchor of the last prune (or Genesis), and the head that core keeps matches the newest row and the count. The
// anchor, the head and the rows are read in one read transaction, so an append that commits meanwhile cannot look like a break.
func (s *Service) VerifyActivity(ctx context.Context) (VerifyResult, error) {
	tx, err := s.cfg.DB.Reader().BeginTx(ctx, nil)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("ai: verify activity: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // read-only
	anchor, err := activityAnchor(ctx, tx)
	if err != nil {
		return VerifyResult{}, err
	}
	head, err := chainhead.Load(ctx, tx, activityChain)
	if err != nil {
		return VerifyResult{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+activityCols+` FROM ai_activity ORDER BY seq`)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("ai: verify activity: %w", err)
	}
	defer func() { _ = rows.Close() }()
	v := chain.NewVerifierWithHead(anchor, head)
	for rows.Next() {
		e, err := scanActivity(rows)
		if err != nil {
			return VerifyResult{}, err
		}
		recomputed, herr := entryHash(e)
		if herr != nil {
			recomputed = "" // a row that cannot be hashed does not match
		}
		v.Add(e.ID, e.PrevHash, e.Hash, recomputed)
	}
	if err := rows.Err(); err != nil {
		return VerifyResult{}, fmt.Errorf("ai: verify activity: %w", err)
	}
	return v.Result(), nil
}

// activityAnchor is the hash of the last pruned row (core_chain_anchor), "" when the log was never pruned. Core owns the table; this
// only reads it, through core's own query.
func activityAnchor(ctx context.Context, q coredb.DBTX) (string, error) {
	a, err := coredb.New(q).GetChainAnchor(ctx, activityChain)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("ai: read the chain anchor: %w", err)
	}
	return a.LastPrunedHash, nil
}
