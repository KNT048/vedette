package findings

import (
	"context"
	"database/sql"
	"fmt"
	"maps"
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

// DeleteCommitted drops the kept Home answer (overview.go): the deleted device's findings are gone.
func (s *Service) DeleteCommitted(_ context.Context, _ lifecycle.Delete) {
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
	ranks, err := s.ranks(ctx, tx, fs)
	if err != nil {
		return err
	}
	rank := func(f Finding) int {
		r := ranks[f.ID]
		if r == 0 && f.AssetID == into { // a tie keeps the kept device's finding
			r = 1
		}
		return r
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
		r := rank(f)
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
	n, err := s.settleNoLine(ctx, tx, into)
	if err != nil {
		return err
	}
	folded += n
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

// MergeCommitted drops the kept Home answer (overview.go): the merged devices' findings changed.
func (s *Service) MergeCommitted(_ context.Context, _ lifecycle.Merge) {
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

// ranks orders findings for a fold: 3 a person decided it (handled it, wrote an event, or marked a mitigation item applied), 2 it is
// confirmed, 0 otherwise.
func (s *Service) ranks(ctx context.Context, tx *sql.Tx, fs []Finding) (map[string]int, error) {
	ids := make([]string, 0, len(fs))
	for _, f := range fs {
		ids = append(ids, f.ID)
	}
	applied := map[string]bool{}
	if s.cfg.Applied != nil && len(ids) > 0 {
		var err error
		if applied, err = s.cfg.Applied(ctx, tx, ids); err != nil {
			return nil, fmt.Errorf("findings: reading the applied mitigation items: %w", err)
		}
	}
	out := make(map[string]int, len(fs))
	for _, f := range fs {
		var byPerson bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM fnd_finding_event WHERE finding_id = ? AND actor <> ?)`, f.ID, SystemUser).Scan(&byPerson); err != nil {
			return nil, fmt.Errorf("findings: reading a finding to fold: %w", err)
		}
		switch {
		case byPerson || f.Via == ViaPerson || applied[f.ID]:
			out[f.ID] = 3
		case f.Confirmed():
			out[f.ID] = 2
		}
	}
	return out, nil
}

// foldGroup folds every finding of fs (one device, one CVE) into the one that ranks highest (first on a tie) and returns it.
// detectedFirst puts every finding the data still detects above every one it does not, whatever a person decided on the latter.
func (s *Service) foldGroup(ctx context.Context, tx *sql.Tx, fs []Finding, detectedFirst bool) (Finding, error) {
	ranks, err := s.ranks(ctx, tx, fs)
	if err != nil {
		return Finding{}, err
	}
	if detectedFirst {
		for _, f := range fs {
			if f.Detected {
				ranks[f.ID] += 10
			}
		}
	}
	kept := fs[0]
	for _, f := range fs[1:] {
		if ranks[f.ID] > ranks[kept.ID] {
			kept = f
		}
	}
	for _, f := range fs {
		if f.ID == kept.ID {
			continue
		}
		if err := s.foldFinding(ctx, tx, f.ID, kept.ID); err != nil {
			return Finding{}, err
		}
	}
	return kept, nil
}

// settleNoLine folds, for each CVE of the device that has both a finding on no line and findings on lines, the no-line finding into
// the first line's finding (the decided one keeps its id and takes that line): a safe check's hit is about the software the line is.
// It returns how many it folded.
func (s *Service) settleNoLine(ctx context.Context, tx *sql.Tx, assetID string) (int, error) {
	fs, err := queryFindings(ctx, tx, `asset_id = ?1 AND cve IN (SELECT cve FROM fnd_finding WHERE asset_id = ?1 AND software_id IS NULL)
		AND cve IN (SELECT cve FROM fnd_finding WHERE asset_id = ?1 AND software_id IS NOT NULL)`, assetID)
	if err != nil {
		return 0, err
	}
	byCVE := map[string][]Finding{}
	for _, f := range fs {
		byCVE[f.CVE] = append(byCVE[f.CVE], f)
	}
	n := 0
	for _, cve := range slices.Sorted(maps.Keys(byCVE)) {
		group := byCVE[cve]
		slices.SortStableFunc(group, func(a, b Finding) int { return strings.Compare(a.SoftwareID, b.SoftwareID) })
		var noLine, line Finding
		for _, f := range group {
			switch {
			case f.SoftwareID == "":
				noLine = f
			case line.ID == "":
				line = f
			}
		}
		if _, err := s.absorbNoLine(ctx, tx, noLine, line); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// absorbNoLine folds the finding on no line and the finding on a line of the same CVE into one on that line: the one that ranks
// higher keeps its id (the line finding on a tie). It returns the finding that stays, as stored.
func (s *Service) absorbNoLine(ctx context.Context, tx *sql.Tx, noLine, line Finding) (Finding, error) {
	kept, err := s.foldGroup(ctx, tx, []Finding{line, noLine}, false)
	if err != nil {
		return Finding{}, err
	}
	if kept.ID == noLine.ID {
		if _, err := tx.ExecContext(ctx, `UPDATE fnd_finding SET software_id = ? WHERE id = ?`, line.SoftwareID, kept.ID); err != nil {
			return Finding{}, fmt.Errorf("findings: giving a finding its line: %w", err)
		}
	}
	return loadFinding(ctx, tx, kept.ID)
}

// LinesDeleted is findings' part of the inventory deleting software lines for good (removed lines past their retention), in the
// inventory's write: the foreign key then sets software_id NULL on the findings of those lines, so every group that would meet on one
// (device, CVE, no line) key is folded first into the one that ranks highest (a person's decision, else a confirmed one), with its
// events, mitigation and response rows (FindingFolded): two removed lines of one CVE, or a removed line beside a finding on no line.
// A finding the data still detects always stays; the decisions on the others join it as history.
func (s *Service) LinesDeleted(ctx context.Context, tx *sql.Tx, l lifecycle.LinesDelete) error {
	if len(l.Lines) == 0 {
		return nil
	}
	gone := make(map[string]bool, len(l.Lines))
	for _, id := range l.Lines {
		gone[id] = true
	}
	var fs []Finding
	for _, id := range l.Lines {
		got, err := queryFindings(ctx, tx, `software_id = ?`, id)
		if err != nil {
			return err
		}
		fs = append(fs, got...)
	}
	groups := map[string][]Finding{}
	for _, f := range fs {
		k := f.AssetID + "\x1f" + f.CVE
		if _, ok := groups[k]; !ok {
			noLine, err := queryFindings(ctx, tx, `asset_id = ? AND cve = ? AND software_id IS NULL`, f.AssetID, f.CVE)
			if err != nil {
				return err
			}
			groups[k] = noLine // the finding on no line first: it keeps the key on a tie
		}
		groups[k] = append(groups[k], f)
	}
	folded := 0
	for _, k := range slices.Sorted(maps.Keys(groups)) {
		if len(groups[k]) < 2 {
			continue
		}
		// a finding the data still detects stays: a person's decision on software that went is history, never a cover for a live flaw
		if _, err := s.foldGroup(ctx, tx, groups[k], true); err != nil {
			return err
		}
		folded += len(groups[k]) - 1
	}
	if folded == 0 {
		return nil
	}
	return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.lines_deleted", Target: l.Lines[0],
		Detail: fmt.Sprintf("%d software lines deleted: %d findings of one CVE on them folded into one", len(l.Lines), folded)})
}
