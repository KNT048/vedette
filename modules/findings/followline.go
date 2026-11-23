package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/audit"
)

// A finding is about one software line of one device (fnd_finding.software_id), and the line decides the device: when inventory gives
// a line to another device with its id (a split gives a merged device its software back whole), the finding and the questions on that
// line go with it, keeping the finding's id, its handling, its notes and events and the rows other modules keep by its id. Inventory
// commits the move before it announces the software change, so findings follow at the next match write of either device.

// followLines runs at the start of a match write of device a, inside its transaction, before a's findings are read. The findings and
// questions of another device that name one of a's lines become a's; those of a that name a line another device has now become that
// device's. A finding that lands on a (CVE, line) another finding already holds there is folded with it (the one a person decided
// stays, lifecycle FindingFolded). One audit row findings.moved_with_line per pair of devices that findings moved between.
func (s *Service) followLines(ctx context.Context, tx *sql.Tx, a Asset) error {
	mine := lineSet(a)
	type move struct{ from, line, to string }
	var moves []move
	// The lines of the other device, as inventory reads it now: a row moves only when the device it is on lists the line no more and the
	// device it goes to lists it (inventory's word on both sides, not one read alone).
	others := map[string]map[string]bool{}
	linesOf := func(id string) (map[string]bool, error) {
		if l, ok := others[id]; ok {
			return l, nil
		}
		d, ok, err := s.cfg.Inventory.MatchInput(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("findings: reading the device a software line is on: %w", err)
		}
		var l map[string]bool
		if ok {
			l = lineSet(d)
		}
		others[id] = l
		return l, nil
	}
	// a's lines named by another device's rows
	if len(mine) > 0 {
		ids, err := json.Marshal(slices.Sorted(maps.Keys(mine)))
		if err != nil {
			return fmt.Errorf("findings: reading the findings of a device's lines: %w", err)
		}
		rows, err := tx.QueryContext(ctx, `SELECT asset_id, software_id FROM fnd_finding WHERE software_id IN (SELECT value FROM json_each(?1)) AND asset_id <> ?2
			UNION SELECT asset_id, software_id FROM fnd_question WHERE software_id IN (SELECT value FROM json_each(?1)) AND asset_id <> ?2`, string(ids), a.ID)
		if err != nil {
			return fmt.Errorf("findings: reading the findings of a device's lines: %w", err)
		}
		var found []move
		for rows.Next() {
			var m move
			if err := rows.Scan(&m.from, &m.line); err != nil {
				_ = rows.Close()
				return fmt.Errorf("findings: reading the findings of a device's lines: %w", err)
			}
			m.to = a.ID
			found = append(found, m)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("findings: reading the findings of a device's lines: %w", err)
		}
		for _, m := range found {
			l, err := linesOf(m.from)
			if err != nil {
				return err
			}
			if l != nil && !l[m.line] {
				moves = append(moves, m)
			}
		}
	}
	// lines a's rows name that a does not list now: inventory says which device has each (a removed line is still a's)
	var gone []string
	rows, err := tx.QueryContext(ctx, `SELECT software_id FROM fnd_finding WHERE asset_id = ?1 AND software_id IS NOT NULL
		UNION SELECT software_id FROM fnd_question WHERE asset_id = ?1 AND software_id IS NOT NULL`, a.ID)
	if err != nil {
		return fmt.Errorf("findings: reading the lines of a device's findings: %w", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return fmt.Errorf("findings: reading the lines of a device's findings: %w", err)
		}
		if !mine[id] {
			gone = append(gone, id)
		}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("findings: reading the lines of a device's findings: %w", err)
	}
	if len(gone) > 0 {
		ls, err := s.cfg.Inventory.Lines(ctx, gone)
		if err != nil {
			return fmt.Errorf("findings: reading where a device's lines are: %w", err)
		}
		for _, id := range gone {
			l, ok := ls[id]
			if !ok || l.AssetID == "" || l.AssetID == a.ID {
				continue
			}
			to, err := linesOf(l.AssetID)
			if err != nil {
				return err
			}
			if to[id] {
				moves = append(moves, move{from: a.ID, line: id, to: l.AssetID})
			}
		}
	}
	if len(moves) == 0 {
		return nil
	}
	slices.SortFunc(moves, func(x, y move) int {
		return strings.Compare(x.from+"\x1f"+x.to+"\x1f"+x.line, y.from+"\x1f"+y.to+"\x1f"+y.line)
	})
	movedBy := map[[2]string][]string{} // (from, to): the CVEs of the findings that moved
	settle := map[string]bool{}
	for _, m := range moves {
		fs, err := queryFindings(ctx, tx, `asset_id = ? AND software_id = ?`, m.from, m.line)
		if err != nil {
			return err
		}
		for _, f := range fs {
			if err := s.moveFinding(ctx, tx, f, m.to); err != nil {
				return err
			}
			movedBy[[2]string{m.from, m.to}] = append(movedBy[[2]string{m.from, m.to}], f.CVE)
			settle[m.to] = true
		}
		// a question already asked on the device the line is on now keeps that row (and its answer); the others move
		if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_question WHERE asset_id = ?1 AND software_id = ?2 AND EXISTS (SELECT 1 FROM fnd_question o
			WHERE o.asset_id = ?3 AND o.software_id = ?2 AND o.cve IS fnd_question.cve AND o.kind = fnd_question.kind)`, m.from, m.line, m.to); err != nil {
			return fmt.Errorf("findings: moving the questions of a software line: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE fnd_question SET asset_id = ? WHERE asset_id = ? AND software_id = ?`, m.to, m.from, m.line); err != nil {
			return fmt.Errorf("findings: moving the questions of a software line: %w", err)
		}
	}
	for _, dev := range slices.Sorted(maps.Keys(settle)) {
		if _, err := s.settleNoLine(ctx, tx, dev); err != nil {
			return err
		}
	}
	for _, k := range slices.SortedFunc(maps.Keys(movedBy), func(x, y [2]string) int { return strings.Compare(x[0]+x[1], y[0]+y[1]) }) {
		cves := movedBy[k]
		detail := fmt.Sprintf("from %s: %d findings moved with their software line (%s)", k[0], len(cves), strings.Join(cves, ", "))
		if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.moved_with_line", Target: k[1], Detail: clipBytes(detail, 1000)}); err != nil {
			return err
		}
	}
	return nil
}

// moveFinding gives finding f to device to, on the same line. When to already holds a finding of the same (CVE, line), the two fold
// into the one that ranks higher (a person's decision, else a confirmed one, else the one that was there).
func (s *Service) moveFinding(ctx context.Context, tx *sql.Tx, f Finding, to string) error {
	held, err := queryFindings(ctx, tx, `asset_id = ? AND cve = ? AND software_id IS ? AND id <> ?`, to, f.CVE, nullString(f.SoftwareID), f.ID)
	if err != nil {
		return err
	}
	if len(held) > 0 {
		kept, err := s.foldGroup(ctx, tx, []Finding{held[0], f}, false)
		if err != nil {
			return err
		}
		if kept.ID != f.ID {
			return nil
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE fnd_finding SET asset_id = ? WHERE id = ?`, to, f.ID); err != nil {
		return fmt.Errorf("findings: moving a finding with its software line: %w", err)
	}
	return nil
}

// lineSet is the ids of a's software lines, the ones a person said are not installed included: those are still the device's lines (a
// network OS a device states without a line has none).
func lineSet(a Asset) map[string]bool {
	out := map[string]bool{}
	for _, sw := range slices.Concat(a.Software, a.NotInstalled) {
		if id := storedLine(sw.ID); id != "" {
			out[id] = true
		}
	}
	return out
}
