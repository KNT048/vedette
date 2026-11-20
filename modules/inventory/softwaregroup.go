package inventory

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/pkgrel"
)

// EffectiveSoftware is one software line the way a device has it, whatever number of sources read it (INV-50, INV-52;
// contract.ts EffectiveSoftware): its values are the line's effective reading (Resolve); the other readings are AlsoSeen.
type EffectiveSoftware struct {
	// ID is the id of the software line: stable across version moves.
	ID         string `json:"id"`
	Vendor     string `json:"vendor"`
	Product    string `json:"product"`
	Display    string `json:"display"`
	Version    string `json:"version"`     // "" when the source gave none
	PkgVersion string `json:"pkg_version"` // the package release; "" when none
	Packaged   bool   `json:"packaged"`    // read from the operating system's package database
	CPE        string `json:"cpe"`         // "" when none
	Source     string `json:"source"`      // the class of the effective reading's source: "agent" for every agent
	SetBy      string `json:"set_by"`      // who entered it (a person's entry); "" otherwise
	SeenAt     string `json:"seen_at"`
	// CanCorrect: a person may give this line a version (PATCH /inventory/devices/{id}/software/{id} with {"version": ...}),
	// whatever source it was read from (INV-52). true on every line.
	CanCorrect bool `json:"can_correct"`
	// Corrected: the value is a person's entry that a source reads otherwise (Source is "manual", SetBy says who); CorrectedFrom is
	// what the strongest source reads. An entry that lapsed (a newer reading) is no longer on the device: it is in the line's history.
	Corrected     bool           `json:"corrected"`
	CorrectedFrom *CorrectedFrom `json:"corrected_from"`
	// AlsoSeen lists the other readings of the line, strongest source first, never as rows of their own.
	AlsoSeen []AlsoSeen `json:"also_seen"`
	// Differs: another reading of another release still feeds matching (Resolve rule 4); the first AlsoSeen with SameRelease false
	// that is not the person's entry is the one to name.
	Differs bool `json:"differs"`
}

// CorrectedFrom is what a source reads of a line a person gave another version: its source and version.
type CorrectedFrom struct {
	Source     string `json:"source"`
	Version    string `json:"version"`
	PkgVersion string `json:"pkg_version"`
}

// AlsoSeen is another reading of an effective software.
type AlsoSeen struct {
	ID          string `json:"id"` // the line's id: a reading is not a row of its own
	Source      string `json:"source"`
	Version     string `json:"version"`
	PkgVersion  string `json:"pkg_version"`
	SeenAt      string `json:"seen_at"`
	SameRelease bool   `json:"same_release"` // the effective release with more or less detail (10.2, 10.2p1, 10.2_p1-r1)
}

// effectiveSoftware reads the present lines of a device with their readings (INV-50): one row per line, never an nmap OS guess the
// device does not use, never a line a person said is not installed.
func effectiveSoftware(ctx context.Context, q querier, assetID string) ([]EffectiveSoftware, error) {
	rows, err := q.QueryContext(ctx, `SELECT s.id, s.vendor, s.product, s.display, ifnull(s.version, ''), ifnull(s.pkg_version, ''), s.packaged, ifnull(s.cpe, ''), s.source,
		ifnull(s.set_by, ''), s.seen_at, s.differs FROM inv_software s WHERE s.asset_id = ? AND `+liveSW+` ORDER BY s.display, s.id`, assetID)
	if err != nil {
		return nil, fmt.Errorf("inventory: read software: %w", err)
	}
	var out []EffectiveSoftware
	idx := map[string]int{}
	for rows.Next() {
		var e EffectiveSoftware
		if err := rows.Scan(&e.ID, &e.Vendor, &e.Product, &e.Display, &e.Version, &e.PkgVersion, &e.Packaged, &e.CPE, &e.Source, &e.SetBy, &e.SeenAt, &e.Differs); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("inventory: read software: %w", err)
		}
		e.CanCorrect, e.AlsoSeen = true, []AlsoSeen{}
		idx[e.ID] = len(out)
		out = append(out, e)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("inventory: read software: %w", err)
	}
	rrows, err := q.QueryContext(ctx, `SELECT s.id, `+readingCols+` FROM inv_software s JOIN inv_software_reading r ON r.software_id = s.id
		WHERE s.asset_id = ? AND `+liveSW+` ORDER BY s.id`, assetID)
	if err != nil {
		return nil, fmt.Errorf("inventory: read software readings: %w", err)
	}
	byLine := map[string][]Reading{}
	for rrows.Next() {
		var id string
		var r Reading
		dst := []any{&id, &r.Source, &r.Instance, &r.Display, &r.Version, &r.PkgVersion, &r.PkgSource, &r.CPE, &r.SetBy, &r.Packaged, &r.Confidence, &r.FirstSeen, &r.SeenAt}
		if err := rrows.Scan(dst...); err != nil {
			_ = rrows.Close()
			return nil, fmt.Errorf("inventory: read software readings: %w", err)
		}
		byLine[id] = append(byLine[id], r)
	}
	if err := errors.Join(rrows.Err(), rrows.Close()); err != nil {
		return nil, fmt.Errorf("inventory: read software readings: %w", err)
	}
	for id, rs := range byLine {
		e := &out[idx[id]]
		res := Resolve(LineState{State: statePresent}, rs)
		eff := res.Effective
		if eff.entry() {
			if det := detectedOf(rs); det != nil && !pkgrel.Same(eff.Version, eff.PkgVersion, det.Version, det.PkgVersion) {
				e.Corrected = true
				e.CorrectedFrom = &CorrectedFrom{Source: sourceClass(det.Source), Version: det.Version, PkgVersion: det.PkgVersion}
			}
		}
		ordered := sortedReadings(rs)
		for _, r := range ordered {
			if r.Source == eff.Source && r.Instance == eff.Instance || r.guess() {
				continue
			}
			e.AlsoSeen = append(e.AlsoSeen, AlsoSeen{ID: id, Source: sourceClass(r.Source), Version: r.Version, PkgVersion: r.PkgVersion, SeenAt: r.SeenAt,
				SameRelease: pkgrel.Same(eff.Version, eff.PkgVersion, r.Version, r.PkgVersion)})
		}
	}
	for i := range out {
		out[i].Source = sourceClass(out[i].Source)
	}
	return out, nil
}

// sortedReadings are readings strongest source first, then the newest.
func sortedReadings(rs []Reading) []Reading {
	out := slices.Clone(rs)
	slices.SortStableFunc(out, func(a, b Reading) int {
		return cmp.Or(readingRank(b)-readingRank(a), strings.Compare(b.SeenAt, a.SeenAt))
	})
	return out
}

// EffectiveSoftware is the one reading of a device's software that every surface shows (INV-50): the device page, findings,
// the plan, reports. ErrNotFound when the device does not exist.
func (s *Service) EffectiveSoftware(ctx context.Context, assetID string) ([]EffectiveSoftware, error) {
	var one int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT 1 FROM inv_asset WHERE id = ?`, assetID).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("inventory: read device: %w", err)
	}
	out, err := effectiveSoftware(ctx, s.db.Reader(), assetID)
	if out == nil {
		out = []EffectiveSoftware{}
	}
	return out, err
}
