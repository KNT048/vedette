package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
)

// A recommended update a person marked as done (INV-20, S-TIER-1): the plan can be wrong (the device was updated and its agent did not
// report yet, a backport the data does not know, a fix applied another way), so an operator marks the item done with an optional
// note, the way a finding is marked handled. The item leaves the plan, the device's To fix card and its risk marker, and is listed under
// Done. The mark holds only while the item is what it was: it comes back by itself when the device reports another version of that
// software (PlanItem.Version) or a CVE that was not in it joins the item. Stored in fnd_plan_done by item key (PlanItem.Group).

// PlanDone is one mark.
type PlanDone struct {
	Group, AssetID string
	Version        string   // the item's version when it was marked
	CVEs           []string // the item's CVEs when it was marked
	Note, By       string
	At             time.Time
}

// ErrPlanItemNotFound is the error of a key no current item of the plan has.
var ErrPlanItemNotFound = &APIError{"not_found", 404, "No such recommended update: the plan may have changed. Reload the page."}

// applies says the mark still holds for the item: the same version, and no CVE that was not in it.
func (m PlanDone) applies(it PlanItem) bool {
	if m.Version != it.Version {
		return false
	}
	for _, c := range it.CVEs {
		if !slices.Contains(m.CVEs, c.CVE) {
			return false
		}
	}
	return true
}

// doneOf is the mark that holds for the item, if any.
func (s *Service) doneOf(it PlanItem) (PlanDone, bool) {
	s.plan.mu.RLock()
	defer s.plan.mu.RUnlock()
	return s.doneLocked(it)
}

func (s *Service) doneLocked(it PlanItem) (PlanDone, bool) {
	m, ok := s.plan.marks[it.Group]
	if !ok || !m.applies(it) {
		return PlanDone{}, false
	}
	return m, true
}

// notDone are the items no mark holds for.
func (s *Service) notDone(items []PlanItem) []PlanItem {
	s.plan.mu.RLock()
	defer s.plan.mu.RUnlock()
	return slices.DeleteFunc(slices.Clone(items), func(it PlanItem) bool { _, done := s.doneLocked(it); return done })
}

// loadMarks reads the marks into the plan state (the plan job, at each full pass).
func (s *Service) loadMarks(ctx context.Context) error {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT item_key, asset_id, version, cves, coalesce(note, ''), done_by, done_at FROM fnd_plan_done`)
	if err != nil {
		return fmt.Errorf("findings: reading the done marks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	marks := map[string]PlanDone{}
	for rows.Next() {
		var m PlanDone
		var cves, at string
		if err := rows.Scan(&m.Group, &m.AssetID, &m.Version, &cves, &m.Note, &m.By, &at); err != nil {
			return fmt.Errorf("findings: reading the done marks: %w", err)
		}
		if json.Unmarshal([]byte(cves), &m.CVEs) != nil {
			continue // the CHECK keeps this from happening; an unreadable mark holds for nothing
		}
		m.At, _ = time.Parse(time.RFC3339Nano, at)
		marks[m.Group] = m
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("findings: reading the done marks: %w", err)
	}
	s.plan.mu.Lock()
	if !maps.EqualFunc(s.plan.marks, marks, func(a, b PlanDone) bool { return a.At.Equal(b.At) && a.Version == b.Version }) {
		s.plan.ver++
	}
	s.plan.marks = marks
	s.plan.mu.Unlock()
	return nil
}

// pruneMarks deletes the marks that no longer hold on a device the last pass compared: its item is gone (the update was installed) or
// changed (another version, a new CVE: the item is back on the plan). A device the pass could not read keeps its marks, and so does a
// device the pass lacked data for (hadData false: nvd-recent not ready or switched off, a distribution feed loading, switched off or
// re-pulling): an item missing for that reason is not an installed update, and the mark must still hold when the data is back.
func (s *Service) pruneMarks(ctx context.Context, compared map[string]planDevice, hadData map[string]bool) error {
	s.plan.mu.RLock()
	var stale []string
	for g, m := range s.plan.marks {
		d, ok := compared[m.AssetID]
		if !ok || !hadData[m.AssetID] {
			continue
		}
		i := slices.IndexFunc(d.items, func(it PlanItem) bool { return it.Group == g })
		if i < 0 || !m.applies(d.items[i]) {
			stale = append(stale, g)
		}
	}
	s.plan.mu.RUnlock()
	if len(stale) == 0 {
		return nil
	}
	if err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, g := range stale {
			if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_plan_done WHERE item_key = ?`, g); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("findings: dropping the done marks that no longer hold: %w", err)
	}
	s.plan.mu.Lock()
	for _, g := range stale {
		delete(s.plan.marks, g)
	}
	s.plan.ver++
	s.plan.mu.Unlock()
	return nil
}

// planItem is the current item of the plan with that key.
func (s *Service) planItem(group string) (PlanItem, bool) {
	s.plan.mu.RLock()
	defer s.plan.mu.RUnlock()
	for _, d := range s.plan.devices {
		for _, it := range d.items {
			if it.Group == group {
				return it, true
			}
		}
	}
	return PlanItem{}, false
}

// MarkPlanDone marks a current item of the plan done by a person (operator), with an optional note: audited as findings.plan_done
// (who, the device, the software and version, how many CVEs, the note). Marking it again replaces the mark.
func (s *Service) MarkPlanDone(ctx context.Context, user, group, note string) (PlanDone, error) {
	if err := ValidUser(user); err != nil {
		return PlanDone{}, err
	}
	note = jsTrim(note)
	if jsLen(note) > MaxNote {
		return PlanDone{}, fmt.Errorf("findings: marking a recommended update done: %w", ErrNoteTooLong)
	}
	it, ok := s.planItem(group)
	if !ok {
		return PlanDone{}, fmt.Errorf("findings: marking %q done: %w", group, ErrPlanItemNotFound)
	}
	m := PlanDone{Group: it.Group, AssetID: it.AssetID, Version: it.Version, Note: note, By: user}
	for _, c := range it.CVEs {
		m.CVEs = append(m.CVEs, c.CVE)
	}
	if m.CVEs == nil {
		m.CVEs = []string{}
	}
	cves, err := json.Marshal(m.CVEs)
	if err != nil {
		return PlanDone{}, err
	}
	err = s.write(ctx, func(tx *sql.Tx, now time.Time, _ func(string, any)) error {
		m.At = now
		if _, err := tx.ExecContext(ctx, `INSERT INTO fnd_plan_done (item_key, asset_id, version, cves, note, done_by, done_at) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (item_key) DO UPDATE SET asset_id = excluded.asset_id, version = excluded.version, cves = excluded.cves, note = excluded.note,
			done_by = excluded.done_by, done_at = excluded.done_at`, m.Group, m.AssetID, m.Version, string(cves), nullString(note), user, store.FormatTS(now)); err != nil {
			return fmt.Errorf("findings: marking a recommended update done: %w", err)
		}
		detail := fmt.Sprintf("%s %s on %s: %d CVEs marked done", clean(it.Software), clean(it.Version), it.AssetID, len(m.CVEs))
		if note != "" {
			detail += " (" + note + ")"
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "findings.plan_done", Target: m.Group, Detail: detail})
	})
	if err != nil {
		return PlanDone{}, err
	}
	s.plan.mu.Lock()
	if s.plan.marks == nil {
		s.plan.marks = map[string]PlanDone{}
	}
	s.plan.marks[m.Group] = m
	s.plan.ver++
	s.plan.mu.Unlock()
	return m, nil
}

// UnmarkPlanDone puts an item a person marked done back on the plan (operator), audited as findings.plan_undone. A key with no mark is
// ErrPlanItemNotFound.
func (s *Service) UnmarkPlanDone(ctx context.Context, user, group string) error {
	if err := ValidUser(user); err != nil {
		return err
	}
	err := s.write(ctx, func(tx *sql.Tx, _ time.Time, _ func(string, any)) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM fnd_plan_done WHERE item_key = ?`, group)
		if err != nil {
			return fmt.Errorf("findings: undoing a done mark: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("findings: undoing the done mark of %q: %w", group, ErrPlanItemNotFound)
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "findings.plan_undone", Target: group, Detail: "back on the plan"})
	})
	if err != nil {
		return err
	}
	s.plan.mu.Lock()
	delete(s.plan.marks, group)
	s.plan.ver++
	s.plan.mu.Unlock()
	return nil
}

// cleanNote refuses a note with a NUL or a control character other than a new line or a tab (the API's rule for notes).
func cleanNote(note string) error {
	if strings.ContainsFunc(note, func(r rune) bool { return r == 0 || r < 0x20 && r != '\n' && r != '\t' || r == 0x7f }) {
		return errors.New("the note contains a character that is not allowed")
	}
	return nil
}
