package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/store"
)

// Retention of observed data (DATA_MODEL inv_service, inv_software; deferred sweep item 9, D-327): an open service not seen for 90 days and
// software an agent (osquery, Wazuh) has not reported for 30 days are deleted. It is a normal job, not Housekeeping: while the inventory
// is off nothing is observed, so silence must not count (the agent-intake precedent, D-265 (8)). The time counts only while the job runs
// unbroken, for services only while a module that observes them is on (sensor-passive, sensor-active, scan), and for agent software only
// while agent-intake is on too: agent-intake promises that turning it off keeps what it delivered. An agent that keeps reporting an empty
// list (or a Wazuh server that stays unreachable) delivers nothing, so its last list goes after 30 days: it is no longer reported.
// ponytail: the unbroken run is kept in memory (a restart starts the count again); upgrade path: persist when the modules were last on.
const (
	ServiceRetention       = 90 * 24 * time.Hour
	AgentSoftwareRetention = 30 * 24 * time.Hour
	retentionGap           = 3 * time.Hour // a longer gap between two runs means the module was off or the box down
	pruneBatch             = 2000          // rows or devices per transaction: the single writer is never held for long
)

// serviceSources are the modules that observe services: their silence counts only while one of them is on (D-327 review, MEDIUM-1).
var serviceSources = []string{"sensor-passive", "sensor-active", "scan"}

// retention is the in-memory state of the prune job.
type retention struct {
	last         time.Time // the previous run
	onSince      time.Time // start of the current unbroken run of the job (inventory on)
	agentSince   time.Time // start of the current unbroken stretch with agent-intake on; zero while it is off
	serviceSince time.Time // start of the current unbroken stretch with a service source on; zero while none is
}

// since moves the start of an unbroken stretch: zero while the condition is off, now when it turns on.
func since(cur time.Time, on bool, now time.Time) time.Time {
	switch {
	case !on:
		return time.Time{}
	case cur.IsZero():
		return now
	}
	return cur
}

// Prune deletes what is past its retention. It is the job "retention" of the module.
func (s *Service) Prune(ctx context.Context) error {
	now := s.clock().UTC()
	s.retMu.Lock()
	r := &s.ret
	if r.last.IsZero() || now.Sub(r.last) > retentionGap {
		r.onSince, r.agentSince, r.serviceSince = now, time.Time{}, time.Time{}
	}
	r.last = now
	r.agentSince = since(r.agentSince, s.enabled("agent-intake"), now)
	r.serviceSince = since(r.serviceSince, s.enabled(serviceSources...), now)
	onSince, agentSince, serviceSince := r.onSince, r.agentSince, r.serviceSince
	s.retMu.Unlock()

	var services, software int64
	var errS, errA error
	if cut := now.Add(-ServiceRetention); !serviceSince.IsZero() && !serviceSince.After(cut) && !onSince.After(cut) {
		services, errS = s.pruneServices(ctx, storeTS(cut))
	}
	if cut := now.Add(-AgentSoftwareRetention); !agentSince.IsZero() && !agentSince.After(cut) && !onSince.After(cut) {
		software, errA = s.pruneAgentSoftware(ctx, storeTS(cut))
	}
	if services+software > 0 {
		s.log.InfoContext(ctx, "inventory: pruned data past its retention", "services", services, "agent_software", software)
	}
	return errors.Join(errS, errA)
}

// enabled says whether one of the modules is on.
func (s *Service) enabled(ids ...string) bool {
	if s.modules == nil {
		return false
	}
	for _, id := range ids {
		if s.modules.Enabled(id) {
			return true
		}
	}
	return false
}

// pruneServices deletes observed services not seen since cut (a service a person declared stays), pruneBatch rows per transaction.
func (s *Service) pruneServices(ctx context.Context, cut string) (int64, error) {
	var total int64
	for {
		var n int64
		err := s.db.Write(ctx, func(tx *sql.Tx) error {
			r, err := tx.ExecContext(ctx, `DELETE FROM inv_service WHERE id IN (SELECT id FROM inv_service WHERE seen_at < ? AND source <> 'manual' LIMIT ?)`, cut, pruneBatch)
			if err != nil {
				return fmt.Errorf("inventory: prune services: %w", err)
			}
			n, _ = r.RowsAffected()
			return nil
		})
		if err != nil {
			return total, err
		}
		total += n
		if n < pruneBatch || ctx.Err() != nil {
			return total, ctx.Err()
		}
	}
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

func storeTS(t time.Time) string { return store.FormatTS(t) }
