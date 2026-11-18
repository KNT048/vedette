package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/pkgrel"
)

// EffectiveSoftware is one software the way a device has it, whatever number of sources read it (INV-50; contract.ts
// EffectiveSoftware). Its values are the strongest source's reading; the other sources are AlsoSeen.
type EffectiveSoftware struct {
	// ID is the id of the software row the values are read from.
	ID         string `json:"id"`
	Vendor     string `json:"vendor"`
	Product    string `json:"product"`
	Display    string `json:"display"`
	Version    string `json:"version"`     // "" when the source gave none
	PkgVersion string `json:"pkg_version"` // the package release; "" when none
	Packaged   bool   `json:"packaged"`    // read from the operating system's package database
	CPE        string `json:"cpe"`         // "" when none
	Source     string `json:"source"`
	SetBy      string `json:"set_by"` // who entered it (a person's entry or correction); "" otherwise
	SeenAt     string `json:"seen_at"`
	// AlsoSeen lists the other rows of the same software, strongest source first, never as rows of their own.
	AlsoSeen []AlsoSeen `json:"also_seen"`
	// Differs: a weaker source reads another release (not the same one with more or less detail) and read it after this row's
	// source did; the strongest such source is the first AlsoSeen with SameRelease false.
	Differs bool `json:"differs"`

	key, corrects string // the row's identity (rowKey) and, on a person's correction, the row it corrects
}

// AlsoSeen is another source's reading of an effective software.
type AlsoSeen struct {
	ID          string `json:"id"`
	Source      string `json:"source"`
	Version     string `json:"version"`
	PkgVersion  string `json:"pkg_version"`
	SeenAt      string `json:"seen_at"`
	SameRelease bool   `json:"same_release"` // the effective row's release with more or less detail (10.2, 10.2p1, 10.2_p1-r1)
}

// effectiveSoftware reads the software of a device as one row per software (INV-50). Identity: the same vendor and product
// (case folded) or the same CPE application, however many sources read it. The row of the strongest source gives the values
// (agent > a person's entry > SNMP, the device's own statement > a scan banner); every other row is AlsoSeen. Rows a person said
// are not installed, an OS guess the device does not use and a correction that rests (its source reads another version) are not
// readings. Several rows of the strongest source (two installs at other versions) stay rows of their own; a weaker reading goes
// under the one it is the same release as, else the newest.
func effectiveSoftware(ctx context.Context, q querier, assetID string) ([]EffectiveSoftware, error) {
	rows, err := q.QueryContext(ctx, `SELECT s.id, s.vendor, s.product, s.display, ifnull(s.version, ''), ifnull(s.pkg_version, ''), s.packaged, ifnull(s.cpe, ''), s.source, ifnull(s.set_by, ''), s.seen_at, ifnull(s.corrects, ''), `+rowKey("s")+`
		FROM inv_software s WHERE s.asset_id = ? AND NOT `+hiddenGuess+` AND NOT `+notInstalledSW+` AND (s.corrects IS NULL OR `+correctionLive+`) ORDER BY s.seen_at DESC, s.id`, assetID)
	if err != nil {
		return nil, fmt.Errorf("inventory: read software: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var all []EffectiveSoftware
	for rows.Next() {
		var e EffectiveSoftware
		if err := rows.Scan(&e.ID, &e.Vendor, &e.Product, &e.Display, &e.Version, &e.PkgVersion, &e.Packaged, &e.CPE, &e.Source, &e.SetBy, &e.SeenAt, &e.corrects, &e.key); err != nil {
			return nil, fmt.Errorf("inventory: read software: %w", err)
		}
		all = append(all, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read software: %w", err)
	}
	return effectiveOf(all), nil
}

// cpeApp is the "vendor:product" of an application CPE (cpe:/a:vendor:product:version or cpe:2.3:a:...), "" for any other.
func cpeApp(cpe string) string {
	c := strings.ToLower(cpe)
	var rest string
	switch {
	case strings.HasPrefix(c, "cpe:/a:"):
		rest = c[len("cpe:/a:"):]
	case strings.HasPrefix(c, "cpe:2.3:a:"):
		rest = c[len("cpe:2.3:a:"):]
	default:
		return ""
	}
	p := strings.SplitN(rest, ":", 3)
	if len(p) < 2 || p[0] == "" || p[1] == "" || p[1] == "*" {
		return ""
	}
	return p[0] + ":" + p[1]
}

// effectiveOf folds readings (newest first) into effective rows; see effectiveSoftware.
func effectiveOf(all []EffectiveSoftware) []EffectiveSoftware {
	// identity classes: rows sharing a name key or a CPE key are one software
	parent := make([]int, len(all))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	first := map[string]int{}
	join := func(key string, i int) {
		if j, ok := first[key]; ok {
			parent[find(i)] = find(j)
		} else {
			first[key] = i
		}
	}
	for i, r := range all {
		join("n\x1f"+strings.ToLower(r.Vendor)+"\x1f"+strings.ToLower(r.Product), i)
		if k := cpeApp(r.CPE); k != "" {
			join("c\x1f"+k, i)
		}
	}
	classes := map[int][]int{}
	var order []int
	for i := range all {
		root := find(i)
		if _, ok := classes[root]; !ok {
			order = append(order, root)
		}
		classes[root] = append(classes[root], i)
	}
	var out []EffectiveSoftware
	for _, root := range order {
		idx := classes[root]
		// a person's entry beats the very row it corrects, whatever that row's source (INV-41, INV-50): that row is not a candidate
		// for the effective row, it is listed under the entry
		corrected := map[int]int{} // row index -> the entry index that corrects it
		for _, c := range idx {
			if all[c].corrects == "" {
				continue
			}
			for _, r := range idx {
				if r != c && all[r].key == all[c].corrects && all[r].Source != "manual" {
					corrected[r] = c
				}
			}
		}
		// an entry that corrects an agent's row is that agent install's own value: it ranks with the agent rows (another agent row of the
		// product, a second kernel, does not hide it); once the corrected row is gone, it is an entry like any other
		rank := func(i int) int {
			for _, c := range corrected {
				if c == i && all[i].Source == "manual" {
					for r, cc := range corrected {
						if cc == i && all[r].Source == "agent" {
							return softwareRank("agent")
						}
					}
				}
			}
			return softwareRank(all[i].Source)
		}
		var cand []int
		for _, i := range idx {
			if _, ok := corrected[i]; !ok {
				cand = append(cand, i)
			}
		}
		slices.SortStableFunc(cand, func(a, b int) int { return rank(b) - rank(a) }) // newest first kept
		top := rank(cand[0])
		var shown []EffectiveSoftware
		var rest []int
		for _, i := range cand {
			if rank(i) == top {
				r := all[i]
				r.AlsoSeen = []AlsoSeen{}
				shown = append(shown, r)
			} else {
				rest = append(rest, i)
			}
		}
		for _, r := range idx { // the corrected rows go after the lower readings, strongest source first
			if _, ok := corrected[r]; ok {
				rest = append(rest, r)
			}
		}
		decided := map[int]bool{} // the strongest reading of another release is the one that counts
		for _, w := range rest {
			ti := 0
			if c, ok := corrected[w]; ok {
				for k := range shown {
					if shown[k].ID == all[c].ID {
						ti = k
					}
				}
			} else {
				ti = -1
			}
			for k := 0; ti < 0 && k < len(shown); k++ {
				if pkgrel.Same(shown[k].Version, shown[k].PkgVersion, all[w].Version, all[w].PkgVersion) {
					ti = k
				}
			}
			if ti < 0 {
				ti = 0
			}
			t := &shown[ti]
			same := pkgrel.Same(t.Version, t.PkgVersion, all[w].Version, all[w].PkgVersion)
			t.AlsoSeen = append(t.AlsoSeen, AlsoSeen{ID: all[w].ID, Source: all[w].Source, Version: all[w].Version, PkgVersion: all[w].PkgVersion, SeenAt: all[w].SeenAt, SameRelease: same})
			if !same && !decided[ti] {
				decided[ti] = true
				t.Differs = all[w].SeenAt > t.SeenAt
			}
		}
		out = append(out, shown...)
	}
	return out
}

// softwareRank is the order the effective row is picked by: an agent reads the package database, so it outranks what a person
// typed; a person's entry outranks what the device announces over SNMP and a scan's banner.
func softwareRank(source string) int {
	switch source {
	case "agent":
		return 6
	case "manual":
		return 5
	}
	return sourceRank(source)
}

// EffectiveSoftware is the one reading of a device's software that every surface shows (INV-50): the device page, findings,
// the plan, reports. ErrNotFound when the device does not exist.
func (s *Service) EffectiveSoftware(ctx context.Context, assetID string) ([]EffectiveSoftware, error) {
	var one int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT 1 FROM inv_asset WHERE id = ?`, assetID).Scan(&one); err != nil {
		if err == sql.ErrNoRows {
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

// markShadowed makes matching follow the effective rows (INV-50): a row another row of the same software outranks (it is listed under
// that row's AlsoSeen) is left out of what MatchInput returns, so findings matches the effective row of each software and every row
// of another product or install as before. A missed CVE is worse than a duplicate, so a row stays when it is a scan, SNMP or passive
// reading of another release under an agent's row (an install on another port next to the agent's package): both are matched. It goes
// when it is the same release as the effective row, when the effective row is a person's entry (the entry holds), or when it is itself a
// person's entry (the agent outranks it). ShadowedBy is "" on every row returned.
func markShadowed(ctx context.Context, q querier, assetID string, d *MatchDevice) error {
	eff, err := effectiveSoftware(ctx, q, assetID)
	if err != nil {
		return err
	}
	shadowed := map[string]bool{}
	for _, e := range eff {
		for _, o := range e.AlsoSeen {
			if e.Source == "agent" && o.Source != "manual" && !o.SameRelease {
				continue
			}
			shadowed[o.ID] = true
		}
	}
	d.Software = slices.DeleteFunc(d.Software, func(sw MatchSoftware) bool { return shadowed[sw.ID] })
	return nil
}
