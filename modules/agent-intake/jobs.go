package agentintake

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
)

// ModuleID is the id of the module in MANIFEST.yaml.
const ModuleID = "agent-intake"

// approveEvery is the pace of approve-enrolled (it matters at start; the daily run only retries). pruneEvery is the pace of node-prune; a
// gap longer than pruneGap between two runs means the job did not run (module off, box down).
const (
	approveEvery = 24 * time.Hour
	pruneEvery   = time.Hour
	pruneGap     = 3 * time.Hour
)

// Jobs returns the jobs of the module. node-prune is a normal job, not Housekeeping: while the module is off every route is 404, so every
// node is silent by construction, and silence must not count (a box left off for 90 days would otherwise cut every enrolled machine
// for good, MEDIUM-1 of the round 1 review; modules.md: off keeps the data). wazuh-pull ticks every minute and pulls when the interval
// of the saved connection is due (D-169 (13)); a normal job too, so nothing is pulled while the module is off (SYS-5). approve-enrolled
// (D-503, the upgrade path) approves the device of every bound node not approved yet: a job runs at once at start and when the module is
// turned on, so a machine enrolled before the upgrade is approved and typed at the first start after it; the daily run only retries.
func (s *Service) Jobs() []jobs.Job {
	return []jobs.Job{
		{Module: ModuleID, Name: "node-prune", Every: pruneEvery, Run: s.Prune},
		{Module: ModuleID, Name: "wazuh-pull", Every: wazuhPullEvery, Run: s.WazuhPull},
		{Module: ModuleID, Name: "approve-enrolled", Every: approveEvery, Run: s.ApproveBound},
	}
}

// Prune deletes the nodes silent for NodeSilentDays and the tokens that expired more than 30 days ago and have no node left. A token with
// nodes stays, listed as expired, until it is revoked: deleting it would cut machines that expiry must not cut (POST-4, D-169 (4)).
// Silence counts only while the module is on. The time of the last run is kept in intake_prune_clock: at the first run after a gap of
// more than pruneGap (the module was off, or the box was down or restarting) the gap is added to every node's last_seen, so the 90 days
// are 90 days of a running job even across restarts and upgrades. With no clock row yet (the first run after this table exists) the
// gap is not known: every node's silence starts at this run, as a restart used to do.
func (s *Service) Prune(ctx context.Context) error {
	now := s.now()
	silent := now.Add(-NodeSilentDays * 24 * time.Hour)
	cutoff := store.FormatTS(silent)
	expired := store.FormatTS(now.Add(-expiredTokenGrace))
	var nodes, tokens int64
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		var last string
		err := tx.QueryRowContext(ctx, `SELECT last_run FROM intake_prune_clock WHERE id = 1`).Scan(&last)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if _, err := tx.ExecContext(ctx, `UPDATE intake_osquery_nodes SET last_seen = ? WHERE last_seen < ?`, store.FormatTS(now), store.FormatTS(now)); err != nil {
				return fmt.Errorf("agentintake: start the prune clock: %w", err)
			}
		case err != nil:
			return fmt.Errorf("agentintake: read the prune clock: %w", err)
		default:
			if prev, perr := time.Parse(time.RFC3339Nano, last); perr == nil && now.Sub(prev) > pruneGap {
				// last_seen + gap, but never after now: a node seen a minute before the gap is still "seen a minute before it".
				if _, err := tx.ExecContext(ctx, `UPDATE intake_osquery_nodes SET last_seen = min(strftime('%Y-%m-%dT%H:%M:%fZ', last_seen, ?), ?)`,
					fmt.Sprintf("+%.3f seconds", now.Sub(prev).Seconds()), store.FormatTS(now)); err != nil {
					return fmt.Errorf("agentintake: add the gap to last_seen: %w", err)
				}
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO intake_prune_clock (id, last_run) VALUES (1, ?) ON CONFLICT (id) DO UPDATE SET last_run = excluded.last_run`, store.FormatTS(now)); err != nil {
			return fmt.Errorf("agentintake: write the prune clock: %w", err)
		}
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
