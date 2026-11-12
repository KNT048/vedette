package ai

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/logexport"
)

// ChainPruner is core's part of a retention prune: it moves the anchor (core_chain_anchor) and lowers the head (core_chain_head) of a
// chain when old rows are removed, in the caller's transaction, so the chain keeps verifying. Core owns both tables and offers
// the helper (chainhead.Prune, issue #194); the module never writes them itself.
type ChainPruner interface {
	Prune(ctx context.Context, tx *sql.Tx, chain, lastPrunedID, lastPrunedHash string, removed int64, now time.Time) error
}

// ErrNoPruner means the box has no ChainPruner: the retention prune is off and nothing is removed.
var ErrNoPruner = errors.New("ai: the retention prune needs core's chain pruner")

// pruneEvery is how often the prune job looks for rows past the retention.
const pruneEvery = 6 * time.Hour

// PruneActivity removes the rows older than the retention (INV-19) and returns how many it removed. Only the oldest run of rows
// goes: it stops at the first row that is not past the retention, even if a later row is older (the clock stepped back), so a row
// is never removed before its time and the chain stays one piece. The rows, the anchor and the head change in one transaction.
func (s *Service) PruneActivity(ctx context.Context) (int, error) {
	if s.cfg.ChainPruner == nil {
		return 0, ErrNoPruner
	}
	days, err := s.RetentionDays(ctx)
	if err != nil {
		return 0, err
	}
	now := s.cfg.Clock()
	cutoff := FormatTS(now.Add(-time.Duration(days) * 24 * time.Hour))
	removed := 0
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		removed = 0 // the write may be retried
		// The first row that is still to be kept; every row before it is past the retention. The newest row is always kept: the head
		// of the chain names it, and chainhead.Prune never removes it. Both come from one statement.
		var keepFrom int64
		err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT seq FROM ai_activity WHERE ts >= ? ORDER BY seq LIMIT 1), (SELECT MAX(seq) FROM ai_activity), 0)`, cutoff).Scan(&keepFrom)
		if err != nil {
			return fmt.Errorf("ai: prune activity: %w", err)
		}
		var lastSeq int64
		var lastID, lastHash string
		var n int64
		err = tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MAX(seq), 0) FROM ai_activity WHERE seq < ?`, keepFrom).Scan(&n, &lastSeq)
		if err != nil {
			return fmt.Errorf("ai: prune activity: %w", err)
		}
		if n == 0 {
			return nil
		}
		if err := tx.QueryRowContext(ctx, `SELECT id, hash FROM ai_activity WHERE seq = ?`, lastSeq).Scan(&lastID, &lastHash); err != nil {
			return fmt.Errorf("ai: prune activity: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM ai_activity WHERE seq <= ?`, lastSeq); err != nil {
			return fmt.Errorf("ai: prune activity: %w", err)
		}
		if err := s.cfg.ChainPruner.Prune(ctx, tx, activityChain, lastID, lastHash, n, now); err != nil {
			return fmt.Errorf("ai: prune activity: %w", err)
		}
		if err := s.auditTx(ctx, tx, "system:ai", "ai.activity_pruned", fmt.Sprintf("%d rows", n), "older than "+cutoff); err != nil {
			return err
		}
		removed = int(n)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}

// verifyEvery is how often the verify job checks the chain of the activity log.
const verifyEvery = 24 * time.Hour

// Jobs are the scheduled jobs of the module. "activity-prune" is offered only when core's ChainPruner is wired; it only deletes rows
// past the retention, so it is housekeeping (D-160) and keeps its timer while the module is off. "activity-verify" is offered only
// when Alert is wired; it calls out to notify, so it is no housekeeping and runs only while the module is on.
func (s *Service) Jobs() []jobs.Job {
	var out []jobs.Job
	if s.cfg.ChainPruner != nil {
		out = append(out, jobs.Job{Module: "ai", Name: "activity-prune", Every: pruneEvery, Housekeeping: true, Run: func(ctx context.Context) error {
			_, err := s.PruneActivity(ctx)
			return err
		}})
	}
	if s.cfg.Alert != nil {
		out = append(out, jobs.Job{Module: "ai", Name: "activity-verify", Every: verifyEvery, Run: s.verifyAndAlert})
	}
	return out
}

// verifyAndAlert checks the chain (INV-18) and, when it is broken, raises one incident notice (S-AI-8, D-430). The text names the
// count and the first bad row, never the content of a row. The same break (first bad row and count) is raised once per process: the
// box does not repeat a notice every day, and a restart raises a break that is still there once more. A chain that verifies again
// (the log was restored) clears the memory, so a new break is raised.
func (s *Service) verifyAndAlert(ctx context.Context) error {
	res, err := s.VerifyActivity(ctx)
	if err != nil {
		return err
	}
	if res.OK {
		s.alerted.Store(nil)
		return nil
	}
	key := fmt.Sprintf("%s/%d", res.EntryID, res.Count)
	if last := s.alerted.Load(); last != nil && *last == key {
		return nil
	}
	text := fmt.Sprintf("The hash chain of the AI activity log is broken at row %d of %d (entry %s). Someone may have edited or removed rows of the log. Open AI, Activity and use Verify to see it.", res.BrokenAt, res.Count, res.EntryID)
	if res.EntryID == "" {
		text = fmt.Sprintf("The hash chain of the AI activity log does not match what the box recorded (%d rows). Rows at the end of the log may have been removed. Open AI, Activity and use Verify to see it.", res.Count)
	}
	if err := s.cfg.Alert(ctx, "ai-activity-chain-"+key, "The AI activity log failed its check", text); err != nil {
		return fmt.Errorf("ai: raise the broken chain: %w", err)
	}
	s.alerted.Store(&key)
	return nil
}

// exportCols are the columns of the hash and nothing else: no seq, no profile_id, so an export verifies offline.
const exportCols = `id, ts, job, profile, model, trigger, hooks, tools, input_hash, output_hash, summary, tokens_in, tokens_out, result, links, prev_hash, hash`

// ExportActivity is the ai_activity source of GET /core/logs/export (core INV-13, D-132): JSON lines of the rows in the range, oldest
// first, with the chain fields unchanged. Core adds the anchor and the head so the file says whether the chain is complete.
func (s *Service) ExportActivity(ctx context.Context, from, to time.Time, w io.Writer) error {
	q := logexport.ChainRows("ai_activity", activityChain, exportCols, from, to)
	q.JSON = []string{"hooks", "tools", "links"}
	return q.Write(ctx, s.cfg.DB.Reader(), w)
}
