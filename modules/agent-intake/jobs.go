package agentintake

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
)

// ModuleID is the id of the module in MANIFEST.yaml.
const ModuleID = "agent-intake"

// pruneEvery is the pace of node-prune; a gap longer than pruneGap between two runs means the job did not run (module off, box down).
const (
	pruneEvery = time.Hour
	pruneGap   = 3 * time.Hour
)

// Jobs returns the jobs of the module. node-prune is a normal job, not Housekeeping: while the module is off every route is 404, so every
// node is silent by construction, and silence must not count (a box left off for 90 days would otherwise cut every enrolled machine
// for good, MEDIUM-1 of the round 1 review; modules.md: off keeps the data).
func (s *Service) Jobs() []jobs.Job {
	return []jobs.Job{{Module: ModuleID, Name: "node-prune", Every: pruneEvery, Run: s.Prune}}
}

// Prune deletes the nodes silent for NodeSilentDays and the tokens that expired more than 30 days ago and have no node left. A token with
// nodes stays, listed as expired, until it is revoked: deleting it would cut machines that expiry must not cut (POST-4, D-169 (4)).
// Silence counts only while the module is on: the first run after a gap (the module was off, or the process just started) starts the
// clock again, so nodes are pruned only once the job has run unbroken for the whole period (a restart restarts the count).
// ponytail: in memory; upgrade path: persist the time the module was last on.
func (s *Service) Prune(ctx context.Context) error {
	now := s.now()
	s.pruneMu.Lock()
	if s.pruneLast.IsZero() || now.Sub(s.pruneLast) > pruneGap {
		s.onSince = now
	}
	s.pruneLast = now
	observed := s.onSince
	s.pruneMu.Unlock()

	silent := now.Add(-NodeSilentDays * 24 * time.Hour)
	pruneNodes := !observed.After(silent) // the job has been watching for the whole period
	cutoff := store.FormatTS(silent)
	expired := store.FormatTS(now.Add(-expiredTokenGrace))
	var nodes, tokens int64
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		if pruneNodes {
			r, err := tx.ExecContext(ctx, `DELETE FROM intake_osquery_nodes WHERE last_seen < ?`, cutoff)
			if err != nil {
				return fmt.Errorf("agentintake: prune nodes: %w", err)
			}
			nodes, _ = r.RowsAffected()
		}
		r, err := tx.ExecContext(ctx, `DELETE FROM intake_agent_tokens WHERE expires_at IS NOT NULL AND expires_at < ?
			AND NOT EXISTS (SELECT 1 FROM intake_osquery_nodes n WHERE n.token_id = intake_agent_tokens.id)`, expired)
		if err != nil {
			return fmt.Errorf("agentintake: prune tokens: %w", err)
		}
		tokens, _ = r.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if nodes+tokens > 0 {
		s.cfg.Log.InfoContext(ctx, "agent-intake: pruned", "nodes", nodes, "tokens", tokens)
	}
	return nil
}
