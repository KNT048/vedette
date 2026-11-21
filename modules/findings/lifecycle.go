package findings

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/lifecycle"
)

// Findings' part of a device merge or delete (core/lifecycle): the inventory calls these inside its own write transaction, so the
// findings change with the device or not at all. The plan in memory follows after the commit.

// DeviceDeleted removes what findings keeps about a deleted device, in the inventory's transaction: its findings with their events
// and, through the foreign keys of mitigation, their applied log and AI results, and its questions. One audit row
// findings.deleted_with_asset when it had findings. (The foreign keys to inv_asset would remove them too; removing them here first
// keeps the order of the cascade out of it.)
func (s *Service) DeviceDeleted(ctx context.Context, tx *sql.Tx, d lifecycle.Delete) error {
	_, err := deleteAssetTx(ctx, tx, s.cfg.Audit, d.Device)
	return err
}

// DeleteCommitted forgets the deleted device's plan items.
func (s *Service) DeleteCommitted(_ context.Context, d lifecycle.Delete) {
	s.dropPlan(d.Device)
	s.gen.Add(1)
}

// deleteAsset removes the findings of a device in a write of its own (Reconcile: a device the inventory no longer has).
func (s *Service) deleteAsset(ctx context.Context, assetID string) (int, error) {
	var n int
	err := s.write(ctx, func(tx *sql.Tx, _ time.Time, _ func(string, any)) error {
		var err error
		n, err = deleteAssetTx(ctx, tx, s.cfg.Audit, assetID)
		return err
	})
	return n, err
}

func deleteAssetTx(ctx context.Context, tx *sql.Tx, log *audit.Log, assetID string) (int, error) {
	res, err := tx.ExecContext(ctx, `DELETE FROM fnd_finding WHERE asset_id = ?`, assetID)
	if err != nil {
		return 0, fmt.Errorf("findings: deleting findings of device: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("findings: deleting findings of device: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_question WHERE asset_id = ?`, assetID); err != nil {
		return 0, fmt.Errorf("findings: deleting the questions of a device: %w", err)
	}
	if n == 0 {
		return 0, nil
	}
	return int(n), log.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.deleted_with_asset", Target: assetID,
		Detail: fmt.Sprintf("%d findings removed with the device", n)})
}

// DeviceMerged moves what findings keeps about device m.From to m.Into, in the inventory's transaction (From was the same machine as
// Into). Nothing a person decided is lost:
//   - Each finding of From becomes Into's, with its handling, events, mitigation log and AI results (those key on the finding id),
//     and follows its software line when the merge folded that line into another (m.Software).
//   - When both devices hold a finding of the same (CVE, software line), one row stays: the one a person decided (handled it, wrote
//     an event, or marked a mitigation item applied), else a confirmed one, else Into's. The other is folded into it: its events are
//     copied onto the one that stays (a person's decision on the other copy stays readable there), the first and last seen times
//     widen, and the modules that keep rows by finding id move them (lifecycle FindingFolded) before the folded row is deleted.
//   - Questions are recomputed when Into is matched again; From's go.
//
// One audit row findings.merged_with_asset names both devices and how many findings moved.
func (s *Service) DeviceMerged(ctx context.Context, tx *sql.Tx, m lifecycle.Merge) error {
	from, into := m.From, m.Into
	if from == "" || into == "" || from == into {
		return nil
	}
	fs, err := queryFindings(ctx, tx, `asset_id IN (?, ?)`, from, into)
	if err != nil {
		return fmt.Errorf("findings: reading the findings of a merged device: %w", err)
	}
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.ID)
	}
	applied := map[string]bool{}
	if s.cfg.Applied != nil && len(ids) > 0 {
		if applied, err = s.cfg.Applied(ctx, tx, ids); err != nil {
			return fmt.Errorf("findings: reading the applied mitigation items: %w", err)
		}
	}
	rank := func(f Finding) (int, error) {
		var byPerson bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM fnd_finding_event WHERE finding_id = ? AND actor <> ?)`, f.ID, SystemUser).Scan(&byPerson); err != nil {
			return 0, fmt.Errorf("findings: reading a finding of a merged device: %w", err)
		}
		switch {
		case byPerson || f.Via == ViaPerson || applied[f.ID]:
			return 3, nil
		case f.Confirmed():
			return 2, nil
		case f.AssetID == into:
			return 1, nil
		}
		return 0, nil
	}
	// Each finding claims its key (CVE, the line that stays); a second one with the same key folds. Into's findings whose key does not
	// change claim first, then Into's that follow a folded line, then From's, so no update lands on a key another row still holds.
	target := func(f Finding) string {
		if f.SoftwareID == "" {
			return ""
		}
		return m.SoftwareID(f.SoftwareID)
	}
	order := func(f Finding) int {
		switch {
		case f.AssetID == into && target(f) == f.SoftwareID:
			return 0
		case f.AssetID == into:
			return 1
		}
		return 2
	}
	ordered := slices.Clone(fs)
	slices.SortStableFunc(ordered, func(a, b Finding) int { return order(a) - order(b) })
	type holder struct {
		f    Finding
		rank int
	}
	byKey := map[string]holder{}
	moved, folded := 0, 0
	var decidedBoth []string // (CVE, kept finding) both devices held a decided finding for: the events of both are on the kept one
	place := func(f Finding, line string) error {
		if f.AssetID == into && f.SoftwareID == line {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE fnd_finding SET asset_id = ?, software_id = ? WHERE id = ?`, into, nullString(line), f.ID); err != nil {
			return fmt.Errorf("findings: moving a finding of a merged device: %w", err)
		}
		if f.AssetID == from {
			moved++
		}
		return nil
	}
	for _, f := range ordered {
		line := target(f)
		r, err := rank(f)
		if err != nil {
			return err
		}
		k := lineKey(f.CVE, line)
		h, clash := byKey[k]
		switch {
		case !clash:
			byKey[k] = holder{f, r}
			if err := place(f, line); err != nil {
				return err
			}
		case r > h.rank: // f outranks the one that holds the key: that one folds into f, which then takes the key
			if h.rank == 3 {
				decidedBoth = append(decidedBoth, f.CVE+" "+f.ID)
			}
			if err := s.foldFinding(ctx, tx, h.f.ID, f.ID); err != nil {
				return err
			}
			byKey[k] = holder{f, r}
			if err := place(f, line); err != nil {
				return err
			}
			folded++
		default:
			if r == 3 {
				decidedBoth = append(decidedBoth, f.CVE+" "+h.f.ID)
			}
			if err := s.foldFinding(ctx, tx, f.ID, h.f.ID); err != nil {
				return err
			}
			folded++
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_question WHERE asset_id = ?`, from); err != nil {
		return fmt.Errorf("findings: removing the questions of a merged device: %w", err)
	}
	if moved == 0 && folded == 0 {
		return nil
	}
	detail := fmt.Sprintf("from %s: %d findings moved, %d held by both and folded", from, moved, folded)
	if len(decidedBoth) > 0 {
		detail += "; decided on both, the history of both kept on: " + strings.Join(decidedBoth, ", ")
	}
	return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.merged_with_asset", Target: into, Detail: detail})
}

// MergeCommitted forgets From's plan items and marks Into's to compare again.
func (s *Service) MergeCommitted(_ context.Context, m lifecycle.Merge) {
	s.dropPlan(m.From)
	s.markPlan(m.Into)
	s.gen.Add(1)
}

// foldFinding folds finding gone into finding kept and deletes gone: its events are copied onto kept (the table is append-only; same
// time, actor, kind and detail), the seen times widen, and the other modules move their rows keyed by finding id first (lifecycle
// FindingFolded).
func (s *Service) foldFinding(ctx context.Context, tx *sql.Tx, gone, kept string) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO fnd_finding_event (finding_id, ts, actor, kind, detail)
		SELECT ?2, ts, actor, kind, detail FROM fnd_finding_event WHERE finding_id = ?1 ORDER BY id`, gone, kept); err != nil {
		return fmt.Errorf("findings: folding a finding of a merged device: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE fnd_finding SET first_seen = min(first_seen, (SELECT first_seen FROM fnd_finding WHERE id = ?1)),
		last_seen = max(last_seen, (SELECT last_seen FROM fnd_finding WHERE id = ?1)) WHERE id = ?2`, gone, kept); err != nil {
		return fmt.Errorf("findings: folding a finding of a merged device: %w", err)
	}
	if err := s.cfg.Lifecycle.FindingFolded(ctx, tx, lifecycle.FindingFold{From: gone, Into: kept}); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_finding WHERE id = ?`, gone); err != nil {
		return fmt.Errorf("findings: folding a finding of a merged device: %w", err)
	}
	return nil
}

