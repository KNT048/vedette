package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/store"
)

// Retention of agent software (DATA_MODEL inv_software; deferred sweep item 9, D-327): software an agent (osquery, Wazuh) has not
// reported for 30 days is deleted. Services have their own retention (PruneServices, INV-23, D-350). It is a normal job, not
// Housekeeping: while the inventory is off nothing is observed, so silence must not count (the agent-intake precedent, D-265 (8)). The
// time counts only while the job runs unbroken, and only while agent-intake is on too: agent-intake promises that turning it off keeps
// what it delivered. An agent that keeps reporting an empty list (or a Wazuh server that stays unreachable) delivers nothing, so its last
// list goes after 30 days: it is no longer reported.
// ponytail: the unbroken run is kept in memory (a restart starts the count again); upgrade path: persist when the modules were last on.
const (
	AgentSoftwareRetention = 30 * 24 * time.Hour
	retentionGap           = 3 * time.Hour // a longer gap between two runs means the module was off or the box down
	pruneBatch             = 2000          // devices per run: the single writer is never held for long
)

// retention is the in-memory state of the prune job.
type retention struct {
	last       time.Time // the previous run
	onSince    time.Time // start of the current unbroken run of the job (inventory on)
	agentSince time.Time // start of the current unbroken stretch with agent-intake on; zero while it is off
}

// PruneAgentSoftware deletes the agent software past its retention. It is the job "agent-software-prune" of the module.
func (s *Service) PruneAgentSoftware(ctx context.Context) error {
	now := s.clock().UTC()
	s.retMu.Lock()
	r := &s.ret
	if r.last.IsZero() || now.Sub(r.last) > retentionGap {
		r.onSince, r.agentSince = now, time.Time{}
	}
	r.last = now
	switch {
	case s.modules == nil || !s.modules.Enabled("agent-intake"):
		r.agentSince = time.Time{}
	case r.agentSince.IsZero():
		r.agentSince = now
	}
	onSince, agentSince := r.onSince, r.agentSince
	s.retMu.Unlock()

	cut := now.Add(-AgentSoftwareRetention)
	if agentSince.IsZero() || agentSince.After(cut) || onSince.After(cut) {
		return nil
	}
	n, err := s.pruneAgentSoftware(ctx, store.FormatTS(cut))
	if n > 0 {
		s.log.InfoContext(ctx, "inventory: pruned agent software past its retention", "items", n)
	}
	return err
}

// pruneAgentSoftware deletes, device by device, the agent rows not reported since cut, at most pruneBatch devices a run (the job runs
// every hour, so a larger backlog is done over a few runs). Each device is one transaction with its audit row
// and the software-changed event, like a sync that dropped them; rows of other sources (manual, nmap, passive) are not touched.
func (s *Service) pruneAgentSoftware(ctx context.Context, cut string) (int64, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT DISTINCT asset_id FROM inv_software WHERE source = 'agent' AND seen_at < ? LIMIT ?`, cut, pruneBatch)
	if err != nil {
		return 0, fmt.Errorf("inventory: read stale agent software: %w", err)
	}
	var assets []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("inventory: read stale agent software: %w", err)
		}
		assets = append(assets, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	_ = rows.Close()
	var total int64
	for _, id := range assets {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		err := s.write(ctx, func(tx *sql.Tx, o *outbox) error {
			before, err := softwareKeys(ctx, tx, id)
			if err != nil {
				return err
			}
			r, err := tx.ExecContext(ctx, `DELETE FROM inv_software WHERE asset_id = ? AND source = 'agent' AND seen_at < ?`, id, cut)
			if err != nil {
				return fmt.Errorf("inventory: prune agent software: %w", err)
			}
			n, _ := r.RowsAffected()
			if n == 0 {
				return nil // reported again since the list was read
			}
			total += n
			if err := s.auditTx(ctx, tx, systemActor, "inventory.software_expired", deviceName(ctx, tx, id), fmt.Sprintf("agent: %d items not reported for 30 days", n)); err != nil {
				return err
			}
			after, err := softwareKeys(ctx, tx, id)
			if err != nil {
				return err
			}
			o.add(EventSoftwareChanged, AssetEvent{AssetID: id})
			o.after = append(o.after, s.matchEvents(id, before, after))
			return nil
		})
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
