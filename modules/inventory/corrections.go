package inventory

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

// Corrections (BN340, INV-39): a person says what a device really runs where Vedette shows it. The device's OS is a manual
// observation, which wins the field over every sensor and agent (INV-1); a software row a sensor or agent reported is corrected by a
// manual row linked to it (inv_software.corrects), which replaces it for matching while it stands. Neither is ever touched by a later
// scan or report: what the sources read keeps being recorded, and the device page shows it next to the correction when they disagree.
// Clearing a correction deletes the person's value, and the device is back to what its sources read. Every change is audited.

// liveSW is the SQL condition on a software row (alias s) that counts for matching and the "Do you have it?" lists: every row but a
// row a sensor or agent reported that a person's correction replaces (INV-39).
const liveSW = `(s.source = 'manual' OR NOT EXISTS (SELECT 1 FROM inv_software c WHERE c.asset_id = s.asset_id AND c.corrects = lower(s.vendor) || '|' || lower(s.product)))`

// pkgVersionRE is a distribution's full package version as a person copies it from the device: Debian's "1:9.6p1-3ubuntu13.14",
// Alpine's "10.2_p1-r1", RPM's "8.7p1-38.el9_4.4".
var pkgVersionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+~:-]{0,99}$`)

const badPkgVersion = "The package release is the full version the device's package manager shows, for example 10.2_p1-r1 or 1:9.6p1-3ubuntu13.14: letters, digits and . _ + ~ : -, up to 100 characters."

// osText checks the OS a person types: 1..200 characters (the inv_asset.os column), no < >, control or invisible characters.
func osText(s string) bool {
	return cleanText(s) && len([]rune(s)) <= 200 && !strings.ContainsAny(s, "<>")
}

const badOS = "The operating system is at most 200 characters and cannot contain < or >, control characters or invisible characters. Example: Alpine Linux 3.23."

// manualOS is the OS a person set on the device and when, ok false when none.
func manualOS(ctx context.Context, q querier, id string) (value, setAt string, ok bool, err error) {
	err = q.QueryRowContext(ctx, `SELECT value, seen_at FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source = 'manual' ORDER BY seen_at DESC, id DESC LIMIT 1`, id).Scan(&value, &setAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("inventory: read the corrected OS: %w", err)
	}
	return value, setAt, true, nil
}

// detectedOS is the OS the device's sources read, the person's left out: the value that would win without the correction.
func detectedOS(ctx context.Context, q querier, id string) (*Observed, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, value, source, confidence, seen_at FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source <> 'manual'`, id)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the detected OS: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []obs
	for rows.Next() {
		o := obs{field: "os"}
		if err := rows.Scan(&o.id, &o.value, &o.source, &o.confidence, &o.seenAt); err != nil {
			return nil, fmt.Errorf("inventory: read the detected OS: %w", err)
		}
		list = append(list, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read the detected OS: %w", err)
	}
	w, ok := winners(list)["os"]
	if !ok {
		return nil, nil
	}
	return &Observed{Value: w.value, Source: w.source, Confidence: w.confidence, SeenAt: w.seenAt}, nil
}

// setOSTx sets (os != "") or clears (os == "") the person's OS of a device, in PatchDevice's transaction. changed is false when
// nothing changes (the same value again, or clearing a device with no correction): no audit row then.
func (s *Service) setOSTx(ctx context.Context, tx *sql.Tx, actor, id, name, os string) (changed bool, err error) {
	old, _, had, err := manualOS(ctx, tx, id)
	if err != nil {
		return false, err
	}
	if (os == "" && !had) || (had && old == os) {
		return false, nil
	}
	var shown sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT os FROM inv_asset WHERE id = ?`, id).Scan(&shown); err != nil {
		return false, fmt.Errorf("inventory: read device OS: %w", err)
	}
	// One correction per device: the previous one goes, so an older value set again cannot lose to a newer one.
	if _, err := tx.ExecContext(ctx, `DELETE FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source = 'manual'`, id); err != nil {
		return false, fmt.Errorf("inventory: clear the corrected OS: %w", err)
	}
	if os != "" {
		if err := insertObs(ctx, tx, id, "os", os, "manual", 1, s.now()); err != nil {
			return false, err
		}
	}
	if _, err := s.RecomputeAsset(ctx, tx, id); err != nil {
		return false, err
	}
	if os == "" {
		var now sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT os FROM inv_asset WHERE id = ?`, id).Scan(&now); err != nil {
			return false, fmt.Errorf("inventory: read device OS: %w", err)
		}
		return true, s.auditTx(ctx, tx, actor, "inventory.clear_os", name, old+" → back to detected: "+cmp.Or(now.String, "unknown"))
	}
	return true, s.auditTx(ctx, tx, actor, "inventory.correct_os", name, cmp.Or(shown.String, "unknown")+" → "+os)
}

// OSCorrection is the OS a person set on a device (contract.ts OsCorrection), with what the sources read now.
type OSCorrection struct {
	Value string `json:"value"`
	SetAt string `json:"set_at"`
	// Detected is the OS the device's sources read without the correction (the value that would win), nil when none read one.
	Detected *Observed `json:"detected"`
	// Disagrees: the sources read another OS than the person's ("You set X on <date>; the last scan reads Y").
	Disagrees bool `json:"disagrees"`
}

func osCorrection(ctx context.Context, q querier, id string) (*OSCorrection, error) {
	v, at, ok, err := manualOS(ctx, q, id)
	if err != nil || !ok {
		return nil, err
	}
	det, err := detectedOS(ctx, q, id)
	if err != nil {
		return nil, err
	}
	return &OSCorrection{Value: v, SetAt: at, Detected: det, Disagrees: det != nil && !sameOS(det.Value, v)}, nil
}

// sameOS says two OS texts do not contradict each other: equal without case, or one the other with more detail after a space (SNMP's
// "Alpine Linux" and a person's "Alpine Linux 3.23").
func sameOS(a, b string) bool {
	a, b = strings.ToLower(strings.TrimSpace(a)), strings.ToLower(strings.TrimSpace(b))
	return a == b || strings.HasPrefix(a, b+" ") || strings.HasPrefix(b, a+" ")
}

// SoftwareEdit is PATCH /inventory/devices/{id}/software/{sid}: a nil field or an empty product is left as it is.
type SoftwareEdit struct {
	Version    *string // "" removes the version
	PkgVersion *string // the distribution's package release ("10.2_p1-r1"); "" removes it
	CatalogID  string  // another product, from the catalog...
	Vendor     string  // ...or typed
	Product    string
}

func (e SoftwareEdit) product() bool { return e.CatalogID != "" || e.Vendor != "" || e.Product != "" }

// EditSoftware changes a software row of a device (INV-39). A row a person declared changes in place; changing only its version is
// SetSoftwareVersion (D-471). A row a sensor or agent reported is corrected: the person's values go in a manual row linked to it
// (the existing correction of that product when there is one), and that row replaces it for matching while it stands; the next scan
// or report keeps writing its own row, shown next to the correction. Fields not given keep the corrected row's values (a new
// correction starts from the detected row, its package release excepted). The device's findings are matched again after the commit.
func (s *Service) EditSoftware(ctx context.Context, actor, assetID, softwareID string, e SoftwareEdit) error {
	if err := s.requireDevice(ctx, assetID); err != nil {
		return err
	}
	if e.Version == nil && e.PkgVersion == nil && !e.product() {
		return badRequest("bad_edit", "Say what to change: the product, the version or the package release.")
	}
	if e.Version != nil {
		v := strings.TrimSpace(*e.Version)
		if v != "" && !versionRE.MatchString(v) {
			return badRequest("bad_version", "The version may only contain letters, digits, dots, hyphens and brackets, up to 40 characters. Example 7.2.5.")
		}
		e.Version = &v
	}
	if e.PkgVersion != nil {
		v := strings.TrimSpace(*e.PkgVersion)
		if v != "" && !pkgVersionRE.MatchString(v) {
			return badRequest("bad_pkg_version", badPkgVersion)
		}
		e.PkgVersion = &v
	}
	var entry *catEntry
	if e.product() {
		c, err := s.Catalog(ctx)
		if err != nil {
			return err
		}
		var aerr *apierr.Error
		if entry, aerr = resolveProduct(c, AddInput{CatalogID: e.CatalogID, Vendor: e.Vendor, Product: e.Product}); aerr != nil {
			return aerr
		}
	}
	var source string
	err := s.db.Reader().QueryRowContext(ctx, `SELECT source FROM inv_software WHERE id = ? AND asset_id = ?`, softwareID, assetID).Scan(&source)
	if errors.Is(err, sql.ErrNoRows) {
		return apierr.New(404, apierr.CodeNotFound, "No such software on this device.")
	} else if err != nil {
		return fmt.Errorf("inventory: read software: %w", err)
	}
	if source == "manual" && e.PkgVersion == nil && entry == nil {
		return s.SetSoftwareVersion(ctx, actor, assetID, softwareID, *e.Version)
	}
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		return s.editSoftwareTx(ctx, tx, o, actor, assetID, softwareID, e, entry)
	})
}

// swRow is a software row as EditSoftware reads it.
type swRow struct {
	id, display, vendor, product, version, source, pkgVersion, pkgSource, corrects string
}

func readSW(ctx context.Context, q querier, where string, args ...any) (swRow, error) {
	var r swRow
	err := q.QueryRowContext(ctx, `SELECT id, display, vendor, product, ifnull(version, ''), source, ifnull(pkg_version, ''), ifnull(pkg_source, ''), ifnull(corrects, '')
		FROM inv_software WHERE `+where, args...).Scan(&r.id, &r.display, &r.vendor, &r.product, &r.version, &r.source, &r.pkgVersion, &r.pkgSource, &r.corrects)
	return r, err
}

// swText names a row's value in an audit row: "OpenSSH 10.2 (package 10.2_p1-r1)".
func swText(display, version, pkg string) string {
	t := strings.TrimSpace(display + " " + version)
	if pkg != "" {
		t += " (package " + pkg + ")"
	}
	return t
}

func (s *Service) editSoftwareTx(ctx context.Context, tx *sql.Tx, o *outbox, actor, assetID, softwareID string, e SoftwareEdit, entry *catEntry) error {
	ok, err := assetExists(ctx, tx, assetID)
	if err != nil {
		return err
	}
	if !ok {
		return notFoundDevice()
	}
	row, err := readSW(ctx, tx, `id = ? AND asset_id = ?`, softwareID, assetID)
	if errors.Is(err, sql.ErrNoRows) {
		return apierr.New(404, apierr.CodeNotFound, "No such software on this device.")
	} else if err != nil {
		return fmt.Errorf("inventory: read software: %w", err)
	}
	detected := row
	target := row // the manual row that takes the person's values; id "" = a new correction
	if row.source != "manual" {
		target, err = readSW(ctx, tx, `asset_id = ? AND corrects = lower(?) || '|' || lower(?)`, assetID, row.vendor, row.product)
		switch {
		case errors.Is(err, sql.ErrNoRows): // a new correction starts from what the source read, its package release excepted
			target = swRow{display: row.display, vendor: row.vendor, product: row.product, version: row.version, source: "manual", pkgSource: row.pkgSource}
		case err != nil:
			return fmt.Errorf("inventory: read the correction: %w", err)
		}
	} else if row.corrects != "" { // editing a correction: the audit names what it corrects
		if d, err := readSW(ctx, tx, `asset_id = ? AND source <> 'manual' AND lower(vendor) || '|' || lower(product) = ? ORDER BY seen_at DESC, id LIMIT 1`, assetID, row.corrects); err == nil {
			detected = d
		}
	}
	next := target
	keys := []string(nil) // nil: the target's keys stay (a new correction copies the detected row's)
	if entry != nil {
		next.display, next.vendor, next.product, keys = entry.display, entry.vendor, entry.product, entry.kev
		if keys == nil {
			keys = []string{}
		}
		next.pkgSource = "" // the package of another product is not known
	}
	if e.Version != nil {
		next.version = *e.Version
	}
	if e.PkgVersion != nil {
		next.pkgVersion = *e.PkgVersion
	}
	if target.id != "" && next == target && keys == nil {
		return nil // nothing changes: no audit row, no rematch
	}
	before, err := softwareKeys(ctx, tx, assetID)
	if err != nil {
		return err
	}
	now := s.now()
	pkgSrc := nullStr(next.pkgSource)
	if next.pkgVersion == "" {
		pkgSrc = nil
	}
	if target.id == "" {
		next.id = store.NewID("s")
		_, err = tx.ExecContext(ctx, `INSERT INTO inv_software (id, asset_id, display, vendor, product, version, source, confidence, seen_at, packaged, pkg_version, pkg_source, corrects)
			VALUES (?, ?, ?, ?, ?, ?, 'manual', 1, ?, 0, ?, ?, (SELECT lower(vendor) || '|' || lower(product) FROM inv_software WHERE id = ?))`,
			next.id, assetID, next.display, next.vendor, next.product, nullStr(next.version), now, nullStr(next.pkgVersion), pkgSrc, row.id)
		if err == nil && keys == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO inv_software_kev (software_id, kev_key) SELECT ?, kev_key FROM inv_software_kev WHERE software_id = ?`, next.id, row.id)
		}
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE inv_software SET display = ?, vendor = ?, product = ?, version = ?, pkg_version = ?, pkg_source = ?, seen_at = ? WHERE id = ?`,
			next.display, next.vendor, next.product, nullStr(next.version), nullStr(next.pkgVersion), pkgSrc, now, next.id)
	}
	if err != nil {
		if store.IsUniqueViolation(err) {
			return conflict("duplicate_software", swText(next.display, next.version, "")+" is already on this device.")
		}
		return fmt.Errorf("inventory: correct software: %w", err)
	}
	if keys != nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_software_kev WHERE software_id = ?`, next.id); err != nil {
			return fmt.Errorf("inventory: correct match keys: %w", err)
		}
		if err := insertKeys(ctx, tx, next.id, keys); err != nil {
			return err
		}
	}
	after, err := softwareKeys(ctx, tx, assetID)
	if err != nil {
		return err
	}
	o.add(EventSoftwareChanged, AssetEvent{AssetID: assetID}) // findings matches the device again on it (#910)
	o.after = append(o.after, s.matchEvents(assetID, before, after))
	from := swText(target.display, target.version, target.pkgVersion)
	if target.id == "" {
		from = swText(detected.display, detected.version, detected.pkgVersion) + " (" + detected.source + ")"
	}
	return s.auditTx(ctx, tx, actor, "inventory.correct_software", deviceName(ctx, tx, assetID)+": "+detected.display, from+" → "+swText(next.display, next.version, next.pkgVersion))
}

// SoftwareDetected is the row a sensor or agent reports for the product a person corrected (contract.ts SoftwareCorrection).
type SoftwareDetected struct {
	ID         string  `json:"id"`
	Display    string  `json:"display"`
	Version    *string `json:"version"`
	PkgVersion *string `json:"pkg_version"`
	Source     string  `json:"source"`
	SeenAt     string  `json:"seen_at"`
}

// SoftwareCorrection is on a person's correction of a reported row: when it was set and what the sources read now.
type SoftwareCorrection struct {
	SetAt     string            `json:"set_at"`
	Detected  *SoftwareDetected `json:"detected"`  // the newest row the sources report for the corrected product; nil when none does now
	Disagrees bool              `json:"disagrees"` // the sources read another product, version or package release than the person's
}

// addCorrections fills the correction fields of a device's software views: on a correction, what it corrects; on a reported row a
// correction replaces, the id of that correction.
func addCorrections(ctx context.Context, q querier, assetID string, views []SoftwareView) error {
	rows, err := q.QueryContext(ctx, `SELECT s.id, ifnull(s.pkg_version, ''), ifnull(s.corrects, ''), s.seen_at, lower(s.vendor) || '|' || lower(s.product) FROM inv_software s WHERE s.asset_id = ?`, assetID)
	if err != nil {
		return fmt.Errorf("inventory: read corrections: %w", err)
	}
	type info struct{ pkg, corrects, seenAt, key string }
	byID := map[string]info{}
	for rows.Next() {
		var id string
		var i info
		if err := rows.Scan(&id, &i.pkg, &i.corrects, &i.seenAt, &i.key); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inventory: read corrections: %w", err)
		}
		byID[id] = i
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("inventory: read corrections: %w", err)
	}
	correctionOf := map[string]string{} // product key -> correction id
	for i := range views {
		if c := byID[views[i].ID].corrects; c != "" && views[i].Source == "manual" {
			correctionOf[c] = views[i].ID
		}
	}
	for i := range views {
		v := &views[i]
		in := byID[v.ID]
		if in.pkg != "" {
			v.PkgVersion = &in.pkg
		}
		if v.Source != "manual" {
			if id, ok := correctionOf[in.key]; ok {
				v.CorrectedBy = &id
			}
		}
	}
	for i := range views {
		v := &views[i]
		in := byID[v.ID]
		if v.Source != "manual" || in.corrects == "" {
			continue
		}
		c := &SoftwareCorrection{SetAt: in.seenAt}
		for j := range views { // the newest reported row of the corrected product
			d := views[j]
			if d.Source == "manual" || byID[d.ID].key != in.corrects {
				continue
			}
			if c.Detected == nil || byID[d.ID].seenAt > c.Detected.SeenAt {
				c.Detected = &SoftwareDetected{ID: d.ID, Display: d.Display, Version: d.Version, PkgVersion: d.PkgVersion, Source: d.Source, SeenAt: byID[d.ID].seenAt}
			}
		}
		if d := c.Detected; d != nil {
			c.Disagrees = !strings.EqualFold(d.Display, v.Display) || deref(d.Version) != deref(v.Version) ||
				deref(d.PkgVersion) != "" && deref(v.PkgVersion) != "" && deref(d.PkgVersion) != deref(v.PkgVersion)
		}
		v.Correction = c
	}
	return nil
}
