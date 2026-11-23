package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/store"
)

// Retention of agent software (DATA_MODEL inv_software; deferred sweep item 9): software an agent (osquery, Wazuh) has not
// reported for 30 days is deleted. Services have their own retention (PruneServices, INV-23). It is a normal job, not
// Housekeeping: while the inventory is off nothing is observed, so silence must not count (the agent-intake precedent). The
// time counts only while the job runs unbroken, and only while agent-intake is on too: agent-intake promises that turning it off keeps
// what it delivered. An agent that keeps reporting an empty list (or a Wazuh server that stays unreachable) delivers nothing, so its last
// list goes after 30 days: it is no longer reported.
// ponytail: the unbroken run is kept in memory (a restart starts the count again); upgrade path: persist when the modules were last on.
const (
	AgentSoftwareRetention = 30 * 24 * time.Hour
	retentionGap           = 3 * time.Hour // a longer gap between two runs means the module was off or the box down
	pruneBatch             = 2000          // devices per run: the single writer is never held for long
	// RemovedSoftwareRetention is how long a removed software line is kept (findings keep pointing at it, the device history
	// names it) before it is deleted. Its history rows stay.
	RemovedSoftwareRetention = 400 * 24 * time.Hour
)

// retention is the in-memory state of the prune job.
type retention struct {
	last       time.Time // the previous run
	onSince    time.Time // start of the current unbroken run of the job (inventory on)
	agentSince time.Time // start of the current unbroken stretch with agent-intake on; zero while it is off
}

// PruneAgentSoftware deletes the agent software past its retention. It is the job "agent-software-prune" of the module.
// The same job deletes the removed software lines past their retention (a fixed date, whatever ran meanwhile).
func (s *Service) PruneAgentSoftware(ctx context.Context) error {
	// the agent readings expire whatever the removed lines' prune did: a failure there must not stop the lines from going removed
	removedErr := s.pruneRemovedSoftware(ctx)
	if removedErr != nil {
		s.log.WarnContext(ctx, "inventory: the removed software lines past their retention stay until the next run", "error", removedErr)
	}
	return errors.Join(removedErr, s.expireAgentSoftware(ctx))
}

// expireAgentSoftware deletes the agent software past its retention, once agent-intake has been on long enough to have read it again.
func (s *Service) expireAgentSoftware(ctx context.Context) error {
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

// pruneAgentSoftware deletes, device by device, the readings of an agent (osquery, Wazuh) not reported since cut, at most pruneBatch
// devices a run (the job runs every hour, so a larger backlog is done over a few runs), and settles the lines they were on: a line
// with no reading left is removed, as when a list dropped it. Each device is one transaction with its audit row and the
// software-changed event; readings of other sources (a person's entry, nmap, SNMP) are not touched. The box itself is never pruned:
// its readings are its own package list, which only a successful read replaces; a host that cannot be read for a month must not
// empty the box and close its findings.
func (s *Service) pruneAgentSoftware(ctx context.Context, cut string) (int64, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT DISTINCT w.asset_id FROM inv_software_reading r JOIN inv_software w ON w.id = r.software_id
		WHERE r.source IN ('osquery', 'wazuh') AND r.seen_at < ? AND w.asset_id NOT IN (SELECT id FROM inv_asset WHERE is_box = 1) LIMIT ?`, cut, pruneBatch)
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
			before, err := deviceKeys(ctx, tx, id)
			if err != nil {
				return err
			}
			lines, err := candidates(ctx, tx, `SELECT DISTINCT r.software_id FROM inv_software_reading r JOIN inv_software w ON w.id = r.software_id
				WHERE w.asset_id = ? AND r.source IN ('osquery', 'wazuh') AND r.seen_at < ?`, id, cut)
			if err != nil {
				return err
			}
			r, err := tx.ExecContext(ctx, `DELETE FROM inv_software_reading WHERE source IN ('osquery', 'wazuh') AND seen_at < ? AND software_id IN
				(SELECT w.id FROM inv_software w JOIN inv_asset a ON a.id = w.asset_id WHERE w.asset_id = ? AND a.is_box = 0)`, cut, id)
			if err != nil {
				return fmt.Errorf("inventory: prune agent software: %w", err)
			}
			n, _ := r.RowsAffected()
			if n == 0 {
				return nil // reported again since the list was read
			}
			total += n
			now := s.now()
			for _, l := range lines {
				if _, err := s.settleLine(ctx, tx, l, now, nil); err != nil {
					return err
				}
			}
			moved, err := s.RecomputeAsset(ctx, tx, id) // an agent row that covered a person's OS row is gone
			if err != nil {
				return err
			}
			if moved {
				o.add(EventAssetUpdated, AssetEvent{AssetID: id})
			}
			if err := s.auditTx(ctx, tx, systemActor, "inventory.software_expired", deviceName(ctx, tx, id), fmt.Sprintf("agent: %d items not reported for 30 days", n)); err != nil {
				return err
			}
			after, err := deviceKeys(ctx, tx, id)
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

// pruneRemovedSoftware deletes the software lines removed longer than RemovedSoftwareRetention ago. The modules that point at a line
// settle their rows on them first, in the same write (lifecycle LinesDeleted), with the exact ids the delete removes.
func (s *Service) pruneRemovedSoftware(ctx context.Context) error {
	return s.write(ctx, func(tx *sql.Tx, _ *outbox) error {
		ids, err := candidates(ctx, tx, `SELECT id FROM inv_software WHERE state = 'removed' AND removed_at < ? ORDER BY id`,
			store.FormatTS(s.clock().Add(-RemovedSoftwareRetention)))
		if err != nil {
			return fmt.Errorf("inventory: prune removed software: %w", err)
		}
		if len(ids) == 0 {
			return nil
		}
		if err := s.lifecycle.LinesDeleted(ctx, tx, lifecycle.LinesDelete{Lines: ids}); err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := tx.ExecContext(ctx, `DELETE FROM inv_software WHERE id = ?`, id); err != nil {
				return fmt.Errorf("inventory: prune removed software: %w", err)
			}
		}
		return nil
	})
}
