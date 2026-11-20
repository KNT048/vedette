package findings

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/store"
)

// Findings' part of a device merge or delete (core/lifecycle): the inventory calls these inside its own write transaction, so the
// findings change with the device or not at all. The plan in memory follows after the commit.

// DeviceDeleted removes what findings keeps about a deleted device, in the inventory's transaction: its findings, their history and,
// through the foreign keys of mitigation, their applied log and AI results (INV-7), its version-needed items, unchecked rows and done
// marks. One audit row findings.deleted_with_asset when it had findings.
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
	for _, q := range []string{
		`DELETE FROM fnd_version_needed WHERE asset_id = ?`,
		`DELETE FROM fnd_unchecked WHERE asset_id = ?`,
		`DELETE FROM fnd_unchecked_seen WHERE asset_id = ?`,
		`DELETE FROM fnd_plan_done WHERE asset_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, assetID); err != nil {
			return 0, fmt.Errorf("findings: deleting the rows of a device: %w", err)
		}
	}
	if n == 0 {
		return 0, nil
	}
	return int(n), log.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.deleted_with_asset", Target: assetID,
		Detail: fmt.Sprintf("%d findings removed with the device", n)})
}

// DeviceMerged moves what findings keeps about device m.From to m.Into, in the inventory's transaction (From was the same machine as
// Into). Nothing a person decided is lost:
//   - Each finding of From becomes Into's, with its status, history, mitigation log and AI results (those key on the finding id).
//   - For a CVE both devices hold, one row stays (UNIQUE (asset_id, cve)): the one that ranks higher, decided (a person closed it,
//     wrote its history, or marked a mitigation item applied) over confirmed over suspected, Into's on a tie. The other is folded into
//     it: every history row is copied onto the one that stays (a person's decision on the other copy stays readable there), the first
//     and last seen times widen, and the modules that keep rows by finding id move them (lifecycle FindingFolded: mitigation,
//     response) before the folded row is deleted.
//   - Findings, version-needed items and done marks that named a software row the merge folded name the row that stays.
//   - Done marks of From's recommended updates become Into's ("Updates to plan", INV-20); of two marks of one item the newer stays.
//   - "Could not be checked" rows of both are recomputed when Into is matched again (one place per CVE); the CVEs From announced
//     stay announced.
//
// One audit row findings.merged_with_asset names both devices, how many findings moved and every CVE both held a decided finding
// for. It runs before Into is matched again, which then finds the moved findings and creates and announces nothing new.
func (s *Service) DeviceMerged(ctx context.Context, tx *sql.Tx, m lifecycle.Merge) error {
	from, into := m.From, m.Into
	if from == "" || into == "" || from == into {
		return nil
	}
	type pair struct{ cve, fromID, intoID string }
	rows, err := tx.QueryContext(ctx, `SELECT f.cve, f.id, t.id FROM fnd_finding f JOIN fnd_finding t ON t.cve = f.cve AND t.asset_id = ?2 WHERE f.asset_id = ?1 ORDER BY f.cve`, from, into)
	if err != nil {
		return fmt.Errorf("findings: reading the findings of a merged device: %w", err)
	}
	var both []pair
	var ids []string
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.cve, &p.fromID, &p.intoID); err != nil {
			_ = rows.Close()
			return fmt.Errorf("findings: reading the findings of a merged device: %w", err)
		}
		both = append(both, p)
		ids = append(ids, p.fromID, p.intoID)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("findings: reading the findings of a merged device: %w", err)
	}
	applied := map[string]bool{}
	if s.cfg.Applied != nil && len(ids) > 0 {
		if applied, err = s.cfg.Applied(ctx, ids); err != nil {
			return fmt.Errorf("findings: reading the applied mitigation items: %w", err)
		}
	}
	rank := func(id string) (int, error) {
		var decided bool
		var status string
		err := tx.QueryRowContext(ctx, `SELECT status, (resolved_by IS NOT NULL AND resolved_by <> ?2)
			OR EXISTS (SELECT 1 FROM fnd_finding_history h WHERE h.finding_id = fnd_finding.id AND h.user <> ?2) FROM fnd_finding WHERE id = ?1`, id, SystemUser).Scan(&status, &decided)
		switch {
		case err != nil:
			return 0, fmt.Errorf("findings: reading a finding of a merged device: %w", err)
		case decided || applied[id]:
			return 2, nil
		case status == string(StatusConfirmed):
			return 1, nil
		}
		return 0, nil
	}
	var decidedBoth []string // CVEs both devices held a decided finding for: the history of both is on the one kept
	for _, p := range both {
		rf, err := rank(p.fromID)
		if err != nil {
			return err
		}
		ri, err := rank(p.intoID)
		if err != nil {
			return err
		}
		gone, kept := p.fromID, p.intoID
		if rf > ri {
			gone, kept = p.intoID, p.fromID
		}
		if rf == 2 && ri == 2 {
			decidedBoth = append(decidedBoth, p.cve+" "+kept)
		}
		if err := s.foldFinding(ctx, tx, gone, kept); err != nil {
			return err
		}
	}
	res, err := tx.ExecContext(ctx, `UPDATE fnd_finding SET asset_id = ?2 WHERE asset_id = ?1`, from, into)
	if err != nil {
		return fmt.Errorf("findings: moving the findings of a merged device: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("findings: moving the findings of a merged device: %w", err)
	}
	for gone, kept := range m.Software {
		for _, q := range []string{
			`UPDATE fnd_finding SET software_id = ?3 WHERE asset_id = ?1 AND software_id = ?2`,
			`UPDATE OR IGNORE fnd_version_needed SET software_id = ?3 WHERE asset_id IN (?1, ?4) AND software_id = ?2`,
		} {
			if _, err := tx.ExecContext(ctx, q, into, gone, kept, from); err != nil {
				return fmt.Errorf("findings: following a folded software row: %w", err)
			}
		}
	}
	for _, q := range []string{
		// version-needed items are rewritten at every match of the device: one both held is the same item, into's stays
		`UPDATE OR IGNORE fnd_version_needed SET asset_id = ?2 WHERE asset_id = ?1`,
		`DELETE FROM fnd_version_needed WHERE asset_id = ?1`,
		`DELETE FROM fnd_unchecked WHERE asset_id IN (?1, ?2)`,                                                                                        // not moved: recomputed when into is matched (one place per CVE)
		`INSERT OR IGNORE INTO fnd_unchecked_seen (asset_id, cve, first_seen) SELECT ?2, cve, first_seen FROM fnd_unchecked_seen WHERE asset_id = ?1`, // announced once per device
		`UPDATE fnd_unchecked_seen SET first_seen = min(first_seen, (SELECT f.first_seen FROM fnd_unchecked_seen f WHERE f.asset_id = ?1 AND f.cve = fnd_unchecked_seen.cve))
			WHERE asset_id = ?2 AND cve IN (SELECT cve FROM fnd_unchecked_seen WHERE asset_id = ?1)`,
		`DELETE FROM fnd_unchecked_seen WHERE asset_id = ?1`,
	} {
		if _, err := tx.ExecContext(ctx, q, from, into); err != nil {
			return fmt.Errorf("findings: moving the findings of a merged device: %w", err)
		}
	}
	marks, err := movePlanDone(ctx, tx, m)
	if err != nil {
		return err
	}
	if n == 0 && len(both) == 0 && marks == 0 {
		return nil
	}
	detail := fmt.Sprintf("from %s: %d findings moved, %d held by both", from, n, len(both))
	if len(decidedBoth) > 0 {
		detail += "; decided on both, the history of both kept on: " + strings.Join(decidedBoth, ", ")
	}
	if marks > 0 {
		detail += fmt.Sprintf("; %d done marks moved", marks)
	}
	return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.merged_with_asset", Target: into, Detail: detail})
}

// MergeCommitted forgets From's plan items, marks Into's to compare again and reads the done marks again (some moved to Into).
func (s *Service) MergeCommitted(ctx context.Context, m lifecycle.Merge) {
	s.dropPlan(m.From)
	s.markPlan(m.Into)
	s.gen.Add(1)
	if err := s.loadMarks(ctx); err != nil {
		s.cfg.Log.WarnContext(ctx, "findings: reading the done marks after a merge", "error", err.Error())
	}
}

// foldFinding folds finding gone into finding kept (same device after the merge, same CVE) and deletes gone: its history is copied
// onto kept (the table is append-only; same time, user, action and note), the seen times widen, and the other modules move their rows
// keyed by finding id first (lifecycle FindingFolded).
func (s *Service) foldFinding(ctx context.Context, tx *sql.Tx, gone, kept string) error {
	if err := copyHistory(ctx, tx, gone, kept); err != nil {
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

// movePlanDone moves the done marks of m.From's recommended updates to m.Into: the item key (PlanItem.Group, "<device>/<software
// row>[/<suffix>]") names Into and the software row that stays. Of two marks of the same item the newer stays. It returns how many
// marks moved.
func movePlanDone(ctx context.Context, tx *sql.Tx, m lifecycle.Merge) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT item_key, done_at FROM fnd_plan_done WHERE asset_id = ?`, m.From)
	if err != nil {
		return 0, fmt.Errorf("findings: reading the done marks of a merged device: %w", err)
	}
	type mark struct{ key, at string }
	var marks []mark
	for rows.Next() {
		var k mark
		if err := rows.Scan(&k.key, &k.at); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("findings: reading the done marks of a merged device: %w", err)
		}
		marks = append(marks, k)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return 0, fmt.Errorf("findings: reading the done marks of a merged device: %w", err)
	}
	moved := 0
	for _, k := range marks {
		key := k.key
		if rest, ok := strings.CutPrefix(key, m.From+"/"); ok {
			sw, suffix, _ := strings.Cut(rest, "/")
			key = m.Into + "/" + m.SoftwareID(sw)
			if suffix != "" {
				key += "/" + suffix
			}
		}
		var other string
		err := tx.QueryRowContext(ctx, `SELECT done_at FROM fnd_plan_done WHERE item_key = ?`, key).Scan(&other)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return 0, fmt.Errorf("findings: moving a done mark: %w", err)
		case key == k.key:
		case other >= k.at: // Into's own mark of the item is the newer one: it stays
			if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_plan_done WHERE item_key = ?`, k.key); err != nil {
				return 0, fmt.Errorf("findings: moving a done mark: %w", err)
			}
			continue
		default:
			if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_plan_done WHERE item_key = ?`, key); err != nil {
				return 0, fmt.Errorf("findings: moving a done mark: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE fnd_plan_done SET item_key = ?, asset_id = ? WHERE item_key = ?`, key, m.Into, k.key); err != nil {
			return 0, fmt.Errorf("findings: moving a done mark: %w", err)
		}
		moved++
	}
	return moved, nil
}

// copyHistory appends to finding to every history row of finding from, in their order.
func copyHistory(ctx context.Context, tx *sql.Tx, from, to string) error {
	rows, err := tx.QueryContext(ctx, `SELECT ts, user, action, note FROM fnd_finding_history WHERE finding_id = ? ORDER BY ts, rowid`, from)
	if err != nil {
		return err
	}
	type row struct {
		ts, user, action string
		note             sql.NullString
	}
	var rs []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.ts, &r.user, &r.action, &r.note); err != nil {
			_ = rows.Close()
			return err
		}
		rs = append(rs, r)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	for _, r := range rs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO fnd_finding_history (id, finding_id, ts, user, action, note) VALUES (?, ?, ?, ?, ?, ?)`,
			store.NewID("fh"), to, r.ts, r.user, r.action, r.note); err != nil {
			return err
		}
	}
	return nil
}
