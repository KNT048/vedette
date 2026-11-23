package response

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/knt048/vedette/core/lifecycle"
)

// DeviceMerged is response's part of a device merge (core/lifecycle, inside the inventory's write): the plans, events and requests of
// device m.From are about device m.Into now; each keeps the device name it stored. A deleted device needs nothing here: they are a
// log of what was proposed and done, kept with that name.
func (s *Service) DeviceMerged(ctx context.Context, tx *sql.Tx, m lifecycle.Merge) error {
	if m.From == "" || m.Into == "" || m.From == m.Into {
		return nil
	}
	for _, q := range []string{
		`UPDATE resp_plans SET asset_id = ?2 WHERE asset_id = ?1`,
		`UPDATE resp_events SET asset_id = ?2 WHERE asset_id = ?1`,
		`UPDATE resp_actions SET asset_id = ?2 WHERE asset_id = ?1`,
	} {
		if _, err := tx.ExecContext(ctx, q, m.From, m.Into); err != nil {
			return fmt.Errorf("response: move the requests of a merged device: %w", err)
		}
	}
	return nil
}

// FindingFolded is response's part of a merge that folds finding f.From into f.Into (same device and CVE): its plans, events and
// requests name the finding that stays.
func (s *Service) FindingFolded(ctx context.Context, tx *sql.Tx, f lifecycle.FindingFold) error {
	for _, q := range []string{
		`UPDATE resp_plans SET finding_id = ?2 WHERE finding_id = ?1`,
		`UPDATE resp_events SET finding_id = ?2 WHERE finding_id = ?1`,
		`UPDATE resp_actions SET finding_id = ?2 WHERE finding_id = ?1`,
	} {
		if _, err := tx.ExecContext(ctx, q, f.From, f.Into); err != nil {
			return fmt.Errorf("response: follow a folded finding: %w", err)
		}
	}
	return nil
}

// FindingMoved is response's part of a finding that went to another device with its software line (findings, inside its match write):
// the events the rules have not run on yet follow it to f.Into, with that device's name when the directory knows it (a finding event
// also takes the device's kind, name and address, which a rule reads). Its plan is retired, not moved: its proposals hold values built
// for the old device's address, so it is deleted (logged and audited) and the planner writes a new plan for the finding on its new
// device. A pending request is withdrawn, not moved: its items hold the values it was rendered with (the old device's address), so
// approving it would act on the old device under the new one's name. It ends expired with the reason, keeps the device it was made
// for, and is logged and audited; a new request is asked for from the new plan. What was decided or done keeps the device it was
// about: a request approved, executed, rejected, expired, failed or rolled back, and an event the rules already ran on.
func (s *Service) FindingMoved(ctx context.Context, tx *sql.Tx, f lifecycle.FindingMove) error {
	if f.Finding == "" || f.From == "" || f.Into == "" || f.From == f.Into {
		return nil
	}
	var name, kind, ip sql.NullString
	if s.cfg.Directory != nil {
		d, ok, err := s.cfg.Directory.Device(ctx, f.Into)
		if err != nil {
			return fmt.Errorf("response: name the device a finding moved to: %w", err)
		}
		if ok {
			name = nullIfEmpty(oneLine(firstNonEmpty(d.Name, d.IP), 120))
			kind, ip = nullIfEmpty(d.Kind), nullIfEmpty(d.IP)
		}
	}
	to := "another device"
	if name.Valid {
		to = name.String
	}
	why := "the finding moved to " + to + " after a device split"
	if err := s.withdrawMoved(ctx, tx, f, why); err != nil {
		return err
	}
	if err := s.retireMovedPlans(ctx, tx, f, why); err != nil {
		return err
	}
	for _, q := range []string{
		`UPDATE resp_events SET asset_id = ?3 WHERE finding_id = ?1 AND asset_id = ?2 AND processed = 0 AND trigger <> 'finding'`,
		`UPDATE resp_events SET asset_id = ?3, device_kind = coalesce(?5, device_kind),
			fields = CASE WHEN ?4 IS NULL THEN fields ELSE json_set(fields, '$.device', substr(?4, 1, 100), '$.ip', coalesce(?6, '')) END
			WHERE finding_id = ?1 AND asset_id = ?2 AND processed = 0 AND trigger = 'finding'`,
	} {
		if _, err := tx.ExecContext(ctx, q, f.Finding, f.From, f.Into, name, kind, ip); err != nil {
			return fmt.Errorf("response: follow a finding to another device: %w", err)
		}
	}
	return nil
}

// withdrawMoved ends the pending requests about finding f on the device it left, without a decision: every item skipped, nothing
// changed on any device, one log line and one audit row each (response.expire).
func (s *Service) withdrawMoved(ctx context.Context, tx *sql.Tx, f lifecycle.FindingMove, why string) error {
	pending, err := loadReqs(ctx, tx, `WHERE finding_id = ? AND asset_id = ? AND status = 'pending'`, f.Finding, f.From)
	if err != nil {
		return fmt.Errorf("response: read the pending requests of a moved finding: %w", err)
	}
	for _, r := range pending {
		if err := s.step(ctx, tx, "response.expire", r.ID, LogExpired, "Request withdrawn without a decision, nothing was changed: "+r.Title+": "+why, "system"); err != nil {
			return err
		}
		r.Status, r.DecidedAt = StatusExpired, strp(s.ts())
		r.Note = strp("Withdrawn: " + why + ". Nothing was changed. A new plan is written for the finding on its new device; ask again from that plan.")
		for i := range r.recs {
			r.recs[i].Status = ItemSkipped
		}
		if err := updateReq(ctx, tx, r); err != nil {
			return err
		}
	}
	return nil
}

// retireMovedPlans deletes the plans of finding f written for the device it left: their proposals hold values built for that device's
// address. One log line and one audit row each (response.plan_retired); the plan's own line from when it was stored stays in the log.
// With no plan left for the finding, the planner writes a new one for the device the finding is on now (PlanOpen, one plan per finding).
func (s *Service) retireMovedPlans(ctx context.Context, tx *sql.Tx, f lifecycle.FindingMove, why string) error {
	plans, err := loadPlans(ctx, tx, `WHERE finding_id = ? AND asset_id = ?`, f.Finding, f.From)
	if err != nil {
		return fmt.Errorf("response: read the plans of a moved finding: %w", err)
	}
	for _, p := range plans {
		if err := s.step(ctx, tx, "response.plan_retired", p.ID, LogProposal, "Plan for "+p.CVE+" on "+p.AssetName+" retired, its proposals can no longer be requested: "+why, "system"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM resp_plans WHERE id = ?`, p.ID); err != nil {
			return fmt.Errorf("response: retire the plan of a moved finding: %w", err)
		}
	}
	return nil
}

func nullIfEmpty(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }
