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

// Jobs returns the jobs of the module. node-prune is Housekeeping (D-160): it runs while the module is off too, only to delete data past
// the retention the product states (CONTRACT POST-4: a node silent 90 days, a token expired 30 days that no node uses); it opens no
// route and calls nothing out.
func (s *Service) Jobs() []jobs.Job {
	return []jobs.Job{{Module: ModuleID, Name: "node-prune", Every: time.Hour, Housekeeping: true, Run: s.Prune}}
}

// Prune deletes the nodes silent for NodeSilentDays and the tokens that expired more than 30 days ago and have no node left. A token with
// nodes stays, listed as expired, until it is revoked: deleting it would cut machines that expiry must not cut (POST-4, D-169 (4)).
func (s *Service) Prune(ctx context.Context) error {
	now := s.now()
	cutoff := store.FormatTS(now.Add(-NodeSilentDays * 24 * time.Hour))
	expired := store.FormatTS(now.Add(-expiredTokenGrace))
	var nodes, tokens int64
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		r, err := tx.ExecContext(ctx, `DELETE FROM intake_osquery_nodes WHERE last_seen < ?`, cutoff)
		if err != nil {
			return fmt.Errorf("agentintake: prune nodes: %w", err)
		}
		nodes, _ = r.RowsAffected()
		r, err = tx.ExecContext(ctx, `DELETE FROM intake_agent_tokens WHERE expires_at IS NOT NULL AND expires_at < ?
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
