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

// The one software line (INV-50, INV-54): every reader of a device's software reads inv_software, whose row is the line and whose
// columns hold its effective reading (written only by the resolver). This file is the only reader of what each source read
// (inv_software_reading) outside the write paths and the matcher's input (MatchInput): the other readings of a line, a person's entry
// and what the sources read against it, the sources that feed a device. A guard test (TestGuard_SoftwareReadingsAreReadOnlyThroughTheLine)
// keeps it so. The Devices list, the device page, the export, the names, the search, "Do you have it?", the assistant's and MCP's
// device data and findings all take these rows.

// SoftwareLine is one software line of a device as every surface shows it (contract.ts SoftwareLine): the line's effective reading,
// with the other readings, a person's entry or "not installed" mark, and the exploited CVEs of its match keys.
type SoftwareLine struct {
	// ID is the id of the line: stable across version moves (a finding names it).
	ID      string  `json:"id"`
	Display string  `json:"display"`
	Vendor  string  `json:"vendor"`
	Product string  `json:"product"`
	Version *string `json:"version"` // nil when the source gave none
	// PkgVersion is the full package release (an agent's packaged reading, or a person's entry); absent when none.
	PkgVersion *string  `json:"pkg_version,omitempty"`
	Packaged   bool     `json:"packaged"` // read from the operating system's package database
	CPE        string   `json:"cpe"`      // "" when none
	KevCVEs    []string `json:"kev_cves"` // the exploited CVEs of its match keys; none on a line a person said is not installed
	// Source is the class of the effective reading's source ("agent" for every agent, "manual" for a person's entry).
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
	Basis      string  `json:"basis,omitempty"` // "guess" on nmap's OS fingerprint (no version, no match key)
	SetBy      string  `json:"set_by"`          // who entered the value, when it is a person's entry; "" otherwise
	SeenAt     string  `json:"seen_at"`         // when the effective reading's source last read it
	// NotInstalled: a person said this software is not installed on the device (INV-41 (6)). It matches nothing; the readers that
	// tell what the device runs (the assistant, MCP) leave it out, the export marks it.
	NotInstalled bool `json:"not_installed"`
	// AlsoSeen lists the other readings of the line, strongest source first, never as rows of their own.
	AlsoSeen []AlsoSeen `json:"also_seen"`
	// Differs: another reading of another release still feeds matching (Resolve rule 4); the first AlsoSeen with SameRelease false
	// is the one to name.
	Differs bool `json:"differs"`
	// Corrected: the value is a person's entry that a source reads otherwise; CorrectedFrom is what the strongest source reads.
	Corrected     bool           `json:"corrected"`
	CorrectedFrom *CorrectedFrom `json:"corrected_from"`
	// Correction, on a line a person gave a version or marked not installed, says when, by whom, and what the sources read now.
	Correction *SoftwareCorrection `json:"correction,omitempty"`
	// CanCorrect: a person may give this line a version (PATCH, INV-52), whatever source it was read from. true on every line.
	CanCorrect bool `json:"can_correct"`

	kev   []string // the match keys
	live  bool     // a person's entry that is the line's value on a present line (declaredIdentity reads it)
	state string
}

// CorrectedFrom is what a source reads of a line a person gave another version: its source and version.
type CorrectedFrom struct {
	Source     string `json:"source"`
	Version    string `json:"version"`
	PkgVersion string `json:"pkg_version"`
}

// AlsoSeen is another reading of a software line.
type AlsoSeen struct {
	ID          string `json:"id"` // the line's id: a reading is not a row of its own
	Source      string `json:"source"`
	Version     string `json:"version"`
	PkgVersion  string `json:"pkg_version"`
	SeenAt      string `json:"seen_at"`
	SameRelease bool   `json:"same_release"` // the effective release with more or less detail (10.2, 10.2p1, 10.2_p1-r1)
}

// guessLine is the SQL condition on a software line (alias s) that its value is a guess (observe.Software.Guess): nmap read it only
// as its OS fingerprint or as the Windows release a device named in its NTLM answer (the reading's instance os_guess), and no other
// reading of nmap backs it. Such a line has no match key.
const guessLine = `(s.source = 'nmap' AND EXISTS (SELECT 1 FROM inv_software_reading gr WHERE gr.software_id = s.id AND gr.source = 'nmap' AND gr.instance = '` +
	instanceOSGuess + `') AND NOT EXISTS (SELECT 1 FROM inv_software_reading gr WHERE gr.software_id = s.id AND gr.source = 'nmap' AND gr.instance <> '` + instanceOSGuess + `'))`

// shownLine is the SQL condition on a software line (alias s) that a device shows it: not removed, never an nmap OS guess the device
// does not use (hiddenGuess). A line a person said is not installed is shown, marked.
var shownLine = `(s.state <> 'removed' AND NOT ` + hiddenGuess + `)`

// lineCols are the columns of a line every reader takes (scanLine), in the order of scanLine.
var lineCols = `s.asset_id, s.id, s.display, s.vendor, s.product, s.version, s.pkg_version, s.packaged, ifnull(s.cpe, ''), s.source, s.confidence,
	ifnull(s.set_by, ''), s.seen_at, s.differs, s.state, s.product_key, ` + fingerprintRow + `, ` + guessLine

// scanLine reads one row of lineCols.
func scanLine(sc interface{ Scan(...any) error }) (asset string, l SoftwareLine, err error) {
	var ver, pkg sql.NullString
	var key string
	var fingerprint, guess bool
	if err := sc.Scan(&asset, &l.ID, &l.Display, &l.Vendor, &l.Product, &ver, &pkg, &l.Packaged, &l.CPE, &l.Source, &l.Confidence,
		&l.SetBy, &l.SeenAt, &l.Differs, &l.state, &key, &fingerprint, &guess); err != nil {
		return "", SoftwareLine{}, err
	}
	l.Version, l.PkgVersion = ptr(ver), ptr(pkg)
	if fingerprint {
		l.Basis = basisGuess
	}
	l.NotInstalled = l.state == stateNotInstalled
	l.live = l.state == statePresent && l.Source == sourceManual // a person's entry in use (declaredIdentity reads it)
	l.Source = sourceClass(l.Source)
	l.kev = matchKeys(key, guess)
	l.KevCVEs, l.AlsoSeen, l.CanCorrect = []string{}, []AlsoSeen{}, true
	return asset, l, nil
}

// row is the line as a row of a device list (contract.ts Software).
func (l SoftwareLine) row() Software {
	return Software{ID: l.ID, Display: l.Display, Vendor: l.Vendor, Product: l.Product, Version: l.Version, Kev: l.kev, Source: l.Source, Confidence: l.Confidence,
		Basis: l.Basis, NotInstalled: l.NotInstalled, live: l.live, seenAt: l.SeenAt}
}

// loadSoftware reads the shown lines of the devices sub selects (a subquery on inv_asset a) into their rows of out.
func loadSoftware(ctx context.Context, q querier, sub string, idx map[string]int, out []Device, args []any) error {
	rows, err := q.QueryContext(ctx, `SELECT `+lineCols+` FROM inv_software s WHERE s.asset_id IN `+sub+` AND `+shownLine+` ORDER BY s.asset_id, s.display, s.id`, args...)
	if err != nil {
		return fmt.Errorf("inventory: read software: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		asset, l, err := scanLine(rows)
		if err != nil {
			return fmt.Errorf("inventory: read software: %w", err)
		}
		d := &out[idx[asset]]
		d.Software = append(d.Software, l.row())
	}
	return rows.Err()
}

// softwareLines reads the shown lines of one device with their readings: the other readings, a person's entry and what the sources
// read against it. KevCVEs is left empty (the caller asks feeds when it shows them).
func softwareLines(ctx context.Context, q querier, assetID string) ([]SoftwareLine, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+lineCols+`, ifnull(s.not_installed_at, ''), ifnull(s.not_installed_by, '')
		FROM inv_software s WHERE s.asset_id = ? AND `+shownLine+` ORDER BY s.display, s.id`, assetID)
	if err != nil {
		return nil, fmt.Errorf("inventory: read software: %w", err)
	}
	out := []SoftwareLine{}
	idx := map[string]int{}
	marked := map[string][2]string{} // line id: when and by whom it was marked not installed
	for rows.Next() {
		var at, by string
		_, l, err := scanLine(scanInto{rows, []any{&at, &by}})
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("inventory: read software: %w", err)
		}
		marked[l.ID] = [2]string{at, by}
		idx[l.ID] = len(out)
		out = append(out, l)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("inventory: read software: %w", err)
	}
	rrows, err := q.QueryContext(ctx, `SELECT s.id, `+readingCols+` FROM inv_software s JOIN inv_software_reading r ON r.software_id = s.id
		WHERE s.asset_id = ? AND `+shownLine+` ORDER BY s.id`, assetID)
	if err != nil {
		return nil, fmt.Errorf("inventory: read software readings: %w", err)
	}
	byLine := map[string][]Reading{}
	for rrows.Next() {
		var id string
		var r Reading
		if err := rrows.Scan(&id, &r.Source, &r.Instance, &r.Display, &r.Version, &r.PkgVersion, &r.PkgSource, &r.CPE, &r.SetBy, &r.Packaged, &r.Confidence, &r.FirstSeen, &r.SeenAt); err != nil {
			_ = rrows.Close()
			return nil, fmt.Errorf("inventory: read software readings: %w", err)
		}
		byLine[id] = append(byLine[id], r)
	}
	if err := errors.Join(rrows.Err(), rrows.Close()); err != nil {
		return nil, fmt.Errorf("inventory: read software readings: %w", err)
	}
	for id, rs := range byLine {
		readingsOn(&out[idx[id]], rs, marked[id])
	}
	return out, nil
}

// scanInto scans a row whose first columns are lineCols and whose last columns go to extra.
type scanInto struct {
	sc    interface{ Scan(...any) error }
	extra []any
}

func (s scanInto) Scan(dst ...any) error { return s.sc.Scan(append(dst, s.extra...)...) }

// readingsOn fills what a line's readings say: the other readings (AlsoSeen), whether its value is a person's entry that a source
// reads otherwise (Corrected), and the person's entry or "not installed" mark with what the sources read now (Correction).
func readingsOn(l *SoftwareLine, rs []Reading, marked [2]string) {
	eff := Resolve(LineState{State: statePresent}, rs).Effective
	entry, det := entryOf(rs), detectedOf(rs)
	if eff.entry() && det != nil && !pkgrel.Same(eff.Version, eff.PkgVersion, det.Version, det.PkgVersion) {
		l.Corrected = true
		l.CorrectedFrom = &CorrectedFrom{Source: sourceClass(det.Source), Version: det.Version, PkgVersion: det.PkgVersion}
	}
	for _, r := range sortedReadings(rs) {
		if r.Source == eff.Source && r.Instance == eff.Instance || r.guess() {
			continue
		}
		l.AlsoSeen = append(l.AlsoSeen, AlsoSeen{ID: l.ID, Source: sourceClass(r.Source), Version: r.Version, PkgVersion: r.PkgVersion, SeenAt: r.SeenAt,
			SameRelease: pkgrel.Same(eff.Version, eff.PkgVersion, r.Version, r.PkgVersion)})
	}
	var c *SoftwareCorrection
	switch {
	case l.NotInstalled:
		c = &SoftwareCorrection{SetAt: marked[0], SetBy: marked[1], NotInstalled: true, Active: true}
	case entry != nil && det != nil:
		c = &SoftwareCorrection{SetAt: entry.FirstSeen, SetBy: entry.SetBy, Active: true}
	default:
		return
	}
	if det != nil {
		c.Detected = &SoftwareDetected{ID: l.ID, Display: det.Display, Version: optional(det.Version), PkgVersion: optional(det.PkgVersion), Source: sourceClass(det.Source), SeenAt: det.SeenAt}
		if entry != nil && !c.NotInstalled {
			c.Disagrees = !strings.EqualFold(det.Display, entry.Display) || det.Version != entry.Version ||
				det.PkgVersion != "" && entry.PkgVersion != "" && det.PkgVersion != entry.PkgVersion
		}
	}
	l.Correction = c
}

// sortedReadings are readings strongest source first, then the newest.
func sortedReadings(rs []Reading) []Reading {
	out := slices.Clone(rs)
	slices.SortStableFunc(out, func(a, b Reading) int {
		return cmp.Or(readingRank(b)-readingRank(a), strings.Compare(b.SeenAt, a.SeenAt))
	})
	return out
}

// SoftwareLines is the software of a device as every surface shows it (findings' port, the device page): one row per line, the line's
// effective reading with its other readings; the lines a person said are not installed are in it, marked. ErrNotFound when the
// device does not exist. KevCVEs is left empty.
func (s *Service) SoftwareLines(ctx context.Context, assetID string) ([]SoftwareLine, error) {
	q := s.db.Reader()
	if ok, err := assetExists(ctx, q, assetID); err != nil {
		return nil, fmt.Errorf("inventory: read device: %w", err)
	} else if !ok {
		return nil, ErrNotFound
	}
	return softwareLines(ctx, q, assetID)
}

// readingSourcesSQL selects (asset_id, source class) for every source with a reading on a line a device still has: the agents as
// "agent" (deviceSources).
const readingSourcesSQL = `SELECT DISTINCT w.asset_id, CASE WHEN r.source IN ('osquery', 'wazuh', 'box') THEN 'agent' ELSE r.source END
	FROM inv_software_reading r JOIN inv_software w ON w.id = r.software_id WHERE w.state <> 'removed'`

// manualAt is when a person last entered or changed something on the device (INV-46): the newest of its manual observations (the
// type, maker and name typed when it was added, a type or OS set later) and its software entries (a line added or edited, a version
// given, "not installed"; each write sets the time to now). A device added by hand with none of these has the time it was added. nil
// when no person entered anything on it.
func manualAt(ctx context.Context, db querier, id string) (*string, error) {
	var at sql.NullString
	err := db.QueryRowContext(ctx, `SELECT coalesce((SELECT max(t) FROM (
			SELECT seen_at AS t FROM inv_observation WHERE asset_id = ?1 AND source = 'manual'
			UNION ALL SELECT r.seen_at FROM inv_software_reading r JOIN inv_software w ON w.id = r.software_id WHERE w.asset_id = ?1 AND r.source = 'manual'
			UNION ALL SELECT not_installed_at FROM inv_software WHERE asset_id = ?1 AND not_installed_at IS NOT NULL)),
		CASE WHEN origin = 'manual' THEN first_seen END)
		FROM inv_asset WHERE id = ?1`, id).Scan(&at)
	if err != nil {
		return nil, fmt.Errorf("inventory: read when a person last changed the device: %w", err)
	}
	if !at.Valid {
		return nil, nil
	}
	return &at.String, nil
}

// sourceTimes is, for one device, the newest time each class of source read something about it (an observation, a reading, an open
// port): scan (nmap and the vulnerability scan), snmp, agent (osquery, Wazuh, the box's own list), passive, manual.
func sourceTimes(ctx context.Context, q querier, id string) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT src, max(t) FROM (
			SELECT source AS src, seen_at AS t FROM inv_observation WHERE asset_id = ?1
			UNION ALL SELECT r.source, r.seen_at FROM inv_software_reading r JOIN inv_software w ON w.id = r.software_id WHERE w.asset_id = ?1 AND w.state <> 'removed'
			UNION ALL SELECT source, seen_at FROM inv_service WHERE asset_id = ?1) GROUP BY src`, id)
	if err != nil {
		return nil, fmt.Errorf("inventory: read source times: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var src, at string
		if err := rows.Scan(&src, &at); err != nil {
			return nil, fmt.Errorf("inventory: read source times: %w", err)
		}
		switch src {
		case "nmap", "scan":
			src = "scan"
		case "osquery", "wazuh", "box":
			src = "agent"
		}
		out[src] = max(out[src], at)
	}
	return out, rows.Err()
}

// Running is the software the device runs, as the readers that tell it say it (the assistant's device data, MCP): its lines but the
// ones a person said are not installed.
func (d Device) Running() []Software {
	return slices.DeleteFunc(slices.Clone(d.Software), func(s Software) bool { return s.NotInstalled })
}

// NotInstalledMark ends a line a person said is not installed in a text list of a device's software (the export).
const NotInstalledMark = " (not installed)"

// declaredLineSQL is the condition on a software line (alias w) a person declared of an OS product: present, with a reading of
// source manual that is the person's own entry, not the copy of a network OS the person typed in the OS field (syncStatedOS, instance
// os). The %s is the product keys' placeholders.
const declaredLineSQL = `(w.state = 'present' AND w.product_key IN (%s) AND EXISTS (SELECT 1 FROM inv_software_reading r WHERE r.software_id = w.id AND r.source = 'manual' AND r.instance <> '` + instanceOS + `'))`

// declaredLines are the ids of the device's lines a person declared of an OS product (keys: osProducts), none for most devices.
func declaredLines(ctx context.Context, q querier, assetID string, keys []string) ([]string, error) {
	args := append([]any{assetID}, anyOf(keys)...)
	return idsOf(ctx, q, `SELECT w.id FROM inv_software w WHERE w.asset_id = ? AND `+fmt.Sprintf(declaredLineSQL, placeholders(len(keys))), args...)
}

// devicesToDecide are the devices whose stored declared-OS decision may be missing (a declared line and no decision) or stale (a
// decision and no declared line): the work of ReconcileDeclaredOS.
func devicesToDecide(ctx context.Context, q querier, keys []string) ([]string, error) {
	in := fmt.Sprintf(declaredLineSQL, placeholders(len(keys)))
	return idsOf(ctx, q, `SELECT a.id FROM inv_asset a WHERE
		(EXISTS (SELECT 1 FROM inv_software w WHERE w.asset_id = a.id AND `+in+`) AND NOT EXISTS (SELECT 1 FROM inv_observation WHERE asset_id = a.id AND `+declaredObsSQL+`))
		OR (EXISTS (SELECT 1 FROM inv_observation WHERE asset_id = a.id AND `+declaredObsSQL+`) AND NOT EXISTS (SELECT 1 FROM inv_software w WHERE w.asset_id = a.id AND `+in+`))
		ORDER BY a.id`, append(anyOf(keys), anyOf(keys)...)...)
}

func placeholders(n int) string { return "?" + strings.Repeat(", ?", n-1) }

func anyOf(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// idsOf is the first column of a query, as strings.
func idsOf(ctx context.Context, q querier, query string, args ...any) ([]string, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: read declared software: %w", err)
	}
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("inventory: read declared software: %w", err)
		}
		out = append(out, id)
	}
	return out, errors.Join(rows.Err(), rows.Close())
}
