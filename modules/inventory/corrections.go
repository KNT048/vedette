package inventory

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

// Corrections (BN340, INV-41): a person says what a device really runs where Vedette shows it. The device's OS is a manual
// observation, which wins the field over every sensor and agent (INV-1); a software row a sensor or agent reported is corrected by a
// manual row linked to exactly that row (inv_software.corrects: its source, product and version), which replaces it for matching
// while it stands; another install of the product (another version, another source) keeps matching (review r1 H1 of #950). Neither is ever touched by a later
// scan or report: what the sources read keeps being recorded, and the device page shows it next to the correction when they disagree.
// Clearing a correction deletes the person's value, and the device is back to what its sources read. Every change is audited.

// rowKey is the SQL identity of a reported row (alias s) a correction stores in corrects: source, lower(vendor), lower(product) and
// version, joined by char(31) (no stored name holds a control character, review r1 L5). inv_software_uq allows one row per key.
func rowKey(s string) string {
	return s + `.source || char(31) || lower(` + s + `.vendor) || char(31) || lower(` + s + `.product) || char(31) || ifnull(` + s + `.version, '')`
}

// productKey is the start of rowKey without the version: the rows one source reports for one product.
func productKey(s string) string {
	return s + `.source || char(31) || lower(` + s + `.vendor) || char(31) || lower(` + s + `.product) || char(31)`
}

// correctionLive is the SQL condition on a correction (alias s) that it is in use: the row it corrects is still reported (review r2 M-B
// of #950). When that source moves on (a scan now reads 10.3 and its 10.2 row is gone) or stops reporting the product (the agent's
// package was removed, or its row expired), the correction rests: the source's current reading decides again, under the source's own
// rules, and the device shows the correction as not in use until the person sets it again on what the source reads now.
var correctionLive = `EXISTS (SELECT 1 FROM inv_software r WHERE r.asset_id = s.asset_id AND r.source <> 'manual' AND ` + rowKey("r") + ` = s.corrects)`

// liveSW is the SQL condition on a software row (alias s) that counts for matching and the "Do you have it?" lists (INV-41): a row a
// person declared; a correction in use (correctionLive) that is not a "not installed" one (INV-41 (6): it replaces its row with
// nothing); a reported row no correction in use replaces.
var liveSW = `(CASE WHEN s.corrects IS NOT NULL THEN s.not_installed = 0 AND ` + correctionLive + ` WHEN s.source = 'manual' THEN 1
	ELSE NOT EXISTS (SELECT 1 FROM inv_software c WHERE c.asset_id = s.asset_id AND c.corrects = ` + rowKey("s") + `) END)`

// pkgVersionRE is a distribution's full package version as a person copies it from the device: Debian's "1:9.6p1-3ubuntu13.14",
// Alpine's "10.2_p1-r1", RPM's "8.7p1-38.el9_4.4".
var pkgVersionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+~:-]{0,99}$`)

const badPkgVersion = "The package release is the full version the device's package manager shows, for example 10.2_p1-r1 or 1:9.6p1-3ubuntu13.14: letters, digits and . _ + ~ : -, up to 100 characters."

// osText checks the OS a person types: 1..200 characters (the inv_asset.os column), no < >, control or invisible characters.
func osText(s string) bool {
	return cleanText(s) && len([]rune(s)) <= 200 && !strings.ContainsAny(s, "<>")
}

const badOS = "The operating system is at most 200 characters and cannot contain < or >, control characters or invisible characters. Example: Alpine Linux 3.23."

// manualOS is the OS a person set on the device, when and who (the observation's evidence), ok false when none.
func manualOS(ctx context.Context, q querier, id string) (value, setAt, setBy string, ok bool, err error) {
	err = q.QueryRowContext(ctx, `SELECT value, seen_at, ifnull(evidence, '') FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source = 'manual' ORDER BY seen_at DESC, id DESC LIMIT 1`, id).Scan(&value, &setAt, &setBy)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, fmt.Errorf("inventory: read the corrected OS: %w", err)
	}
	return value, setAt, setBy, true, nil
}

// correctionDay is the day of a stored time in the findings history's words ("17 Nov 2026"); the stored text when it does not parse.
func correctionDay(at string) string {
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return at
	}
	return t.UTC().Format("2 Jan 2006")
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
	old, _, _, had, err := manualOS(ctx, tx, id)
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
		if _, err := tx.ExecContext(ctx, `INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at, evidence) VALUES (?, ?, 'os', ?, 'manual', 1, ?, ?)`,
			store.NewID("o"), id, os, s.now(), nullStr(actor)); err != nil { // evidence: who set it, for the findings history
			return false, fmt.Errorf("inventory: record the corrected OS: %w", err)
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
	v, at, _, ok, err := manualOS(ctx, q, id)
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
	// NotInstalled: the person says the reported row is not installed on the device (INV-41 (6)). It takes no other field; a later
	// edit of the version, release or product of the correction makes it an ordinary correction again (the person says what is there).
	NotInstalled bool
}

func (e SoftwareEdit) product() bool { return e.CatalogID != "" || e.Vendor != "" || e.Product != "" }

// EditSoftware changes a software row of a device (INV-41). A row a person declared changes in place (D-471). A row a sensor or agent
// reported is corrected: the person's values go in a manual row linked to exactly that row (its source, product and version), the
// existing correction of that row when there is one, and that row replaces it for matching while it stands; another install of the
// product keeps matching. What the person does not change is kept (review r1 M1): the CPE, the packaged flag and the source package,
// and the package release while the version stays; another product starts clean. The device's findings are matched again after the
// commit.
func (s *Service) EditSoftware(ctx context.Context, actor, assetID, softwareID string, e SoftwareEdit) error {
	if err := s.requireDevice(ctx, assetID); err != nil {
		return err
	}
	if e.Version == nil && e.PkgVersion == nil && !e.product() && !e.NotInstalled {
		return badRequest("bad_edit", "Say what to change: the product, the version or the package release, or that it is not installed.")
	}
	if e.NotInstalled && (e.Version != nil || e.PkgVersion != nil || e.product()) {
		return badRequest("bad_edit", "\"Not installed\" takes no version, package release or product: send it alone.")
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
	var corrects sql.NullString
	err := s.db.Reader().QueryRowContext(ctx, `SELECT source, corrects FROM inv_software WHERE id = ? AND asset_id = ?`, softwareID, assetID).Scan(&source, &corrects)
	if errors.Is(err, sql.ErrNoRows) {
		return apierr.New(404, apierr.CodeNotFound, "No such software on this device.")
	} else if err != nil {
		return fmt.Errorf("inventory: read software: %w", err)
	}
	if source == "manual" && !corrects.Valid && e.NotInstalled {
		return badRequest("bad_edit", "A person added this software: remove it instead (Not installed on a row a person added deletes it).")
	}
	if source == "manual" && !corrects.Valid && e.PkgVersion == nil && entry == nil {
		return s.SetSoftwareVersion(ctx, actor, assetID, softwareID, *e.Version) // a declared row's version (D-471)
	}
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		return s.editSoftwareTx(ctx, tx, o, actor, assetID, softwareID, e, entry)
	})
}

// swRow is a software row as EditSoftware reads it.
type swRow struct {
	id, display, vendor, product, version, cpe, source, pkgVersion, pkgSource, corrects, key string
	packaged, notInstalled                                                                   bool
}

func readSW(ctx context.Context, q querier, where string, args ...any) (swRow, error) {
	var r swRow
	err := q.QueryRowContext(ctx, `SELECT id, display, vendor, product, ifnull(version, ''), ifnull(cpe, ''), source, packaged, ifnull(pkg_version, ''), ifnull(pkg_source, ''),
		ifnull(corrects, ''), not_installed, `+rowKey("inv_software")+` FROM inv_software WHERE `+where, args...).
		Scan(&r.id, &r.display, &r.vendor, &r.product, &r.version, &r.cpe, &r.source, &r.packaged, &r.pkgVersion, &r.pkgSource, &r.corrects, &r.notInstalled, &r.key)
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
	detected := row // what the person corrects, for the audit row
	target := row   // the manual row that takes the person's values; id "" = a new correction
	relink := ""    // the reported row a resting correction is set on again (review r2 M-B): the person re-confirms it
	if row.source != "manual" {
		target, err = readSW(ctx, tx, `asset_id = ? AND corrects = ?`, assetID, row.key)
		if errors.Is(err, sql.ErrNoRows) { // a resting correction of this source's product is set on this row again
			target, err = readSW(ctx, tx, `asset_id = ? AND corrects IS NOT NULL AND substr(corrects, 1, length(?)) = ? AND NOT EXISTS
				(SELECT 1 FROM inv_software r WHERE r.asset_id = inv_software.asset_id AND r.source <> 'manual' AND `+rowKey("r")+` = inv_software.corrects)
				ORDER BY seen_at DESC, id LIMIT 1`, assetID, productPrefix(row.key), productPrefix(row.key))
			relink = row.key
		}
		switch {
		case errors.Is(err, sql.ErrNoRows): // a new correction starts from what the source read (review r1 M1)
			target = row
			target.id, target.source, target.corrects, relink = "", "manual", row.key, ""
		case err != nil:
			return fmt.Errorf("inventory: read the correction: %w", err)
		}
	} else if row.corrects != "" {
		if d, err := readSW(ctx, tx, `asset_id = ? AND source <> 'manual' AND `+rowKey("inv_software")+` = ?`, assetID, row.corrects); err == nil {
			detected = d
		} else if d, err := readSW(ctx, tx, `asset_id = ? AND source <> 'manual' AND `+productKey("inv_software")+` = ? AND NOT EXISTS
			(SELECT 1 FROM inv_software c WHERE c.asset_id = inv_software.asset_id AND c.corrects = `+rowKey("inv_software")+`) ORDER BY seen_at DESC, id LIMIT 1`,
			assetID, productPrefix(row.corrects)); err == nil {
			detected, relink = d, d.key // resting: the edit sets it on what the source reads now
		} else { // the source reports it no more: what the correction says it corrected
			src, _, _, ver := correctedFrom(row.corrects)
			detected = swRow{display: row.display, version: ver, source: src}
		}
	}
	next := target
	if relink != "" {
		next.corrects = relink
	}
	keys := []string(nil) // nil: the target's keys stay (a new correction copies the reported row's)
	keysFrom := ""        // an existing correction takes the keys of this reported row (Not installed, INV-41 (6))
	next.notInstalled = e.NotInstalled
	if e.NotInstalled && detected.id != "" && (target.id == "" || detected.id != target.id) {
		// The person says the row the source reports is not there: the correction holds what that row says (a version the person
		// gave before no longer matters), so the device page and findings name what the source reads.
		next.display, next.vendor, next.product, next.version, next.cpe = detected.display, detected.vendor, detected.product, detected.version, detected.cpe
		next.packaged, next.pkgVersion, next.pkgSource = detected.packaged, detected.pkgVersion, detected.pkgSource
		if target.id != "" {
			keysFrom = detected.id
		}
	}
	if entry != nil && (!strings.EqualFold(entry.vendor, target.vendor) || !strings.EqualFold(entry.product, target.product)) {
		next.display, next.vendor, next.product, keys = entry.display, entry.vendor, entry.product, entry.kev
		if keys == nil {
			keys = []string{}
		}
		next.cpe, next.packaged, next.pkgSource, next.pkgVersion = "", false, "", "" // nothing of another product is known
	}
	if e.Version != nil && *e.Version != next.version {
		next.version = *e.Version
		if e.PkgVersion == nil {
			next.pkgVersion = "" // the release of another version is not known (review r1 L3)
		}
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
	if !next.packaged && next.pkgVersion == "" {
		pkgSrc = nil
	}
	if target.id == "" {
		next.id = store.NewID("s")
		_, err = tx.ExecContext(ctx, `INSERT INTO inv_software (id, asset_id, display, vendor, product, version, cpe, source, confidence, seen_at, packaged, pkg_version, pkg_source, corrects, set_by, not_installed)
			VALUES (?, ?, ?, ?, ?, ?, ?, 'manual', 1, ?, ?, ?, ?, ?, ?, ?)`,
			next.id, assetID, next.display, next.vendor, next.product, nullStr(next.version), nullStr(next.cpe), now, next.packaged, nullStr(next.pkgVersion), pkgSrc, next.corrects, nullStr(actor), next.notInstalled)
		if err == nil && keys == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO inv_software_kev (software_id, kev_key) SELECT ?, kev_key FROM inv_software_kev WHERE software_id = ?`, next.id, row.id)
		}
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE inv_software SET display = ?, vendor = ?, product = ?, version = ?, cpe = ?, packaged = ?, pkg_version = ?, pkg_source = ?, seen_at = ?, set_by = ?, corrects = ?, not_installed = ? WHERE id = ?`,
			next.display, next.vendor, next.product, nullStr(next.version), nullStr(next.cpe), next.packaged, nullStr(next.pkgVersion), pkgSrc, now, nullStr(actor), nullStr(next.corrects), next.notInstalled, next.id)
	}
	if err != nil {
		if store.IsUniqueViolation(err) {
			return conflict("duplicate_software", swText(next.display, next.version, "")+" is already on this device.")
		}
		return fmt.Errorf("inventory: correct software: %w", err)
	}
	if keys != nil || keysFrom != "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_software_kev WHERE software_id = ?`, next.id); err != nil {
			return fmt.Errorf("inventory: correct match keys: %w", err)
		}
	}
	if keys != nil {
		if err := insertKeys(ctx, tx, next.id, keys); err != nil {
			return err
		}
	} else if keysFrom != "" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO inv_software_kev (software_id, kev_key) SELECT ?, kev_key FROM inv_software_kev WHERE software_id = ?`, next.id, keysFrom); err != nil {
			return fmt.Errorf("inventory: correct match keys: %w", err)
		}
	}
	after, err := softwareKeys(ctx, tx, assetID)
	if err != nil {
		return err
	}
	o.add(EventSoftwareChanged, AssetEvent{AssetID: assetID}) // findings matches the device again on it (#910)
	o.after = append(o.after, s.matchEvents(assetID, before, after))
	from := swText(target.display, target.version, target.pkgVersion)
	if target.id == "" || next.notInstalled {
		from = swText(detected.display, detected.version, detected.pkgVersion) + " (" + detected.source + ")"
	}
	if next.notInstalled { // INV-41 (6): "OpenSSH 10.2 (nmap) → not installed"
		return s.auditTx(ctx, tx, actor, "inventory.mark_not_installed", deviceName(ctx, tx, assetID)+": "+detected.display, from+" → not installed")
	}
	if target.notInstalled { // the person now says what is installed
		from = "not installed"
	}
	return s.auditTx(ctx, tx, actor, "inventory.correct_software", deviceName(ctx, tx, assetID)+": "+detected.display, from+" → "+swText(next.display, next.version, next.pkgVersion))
}

// productPrefix is the rowKey of a key without its version: the source, vendor and product, with the closing separator.
func productPrefix(key string) string {
	if i := strings.LastIndex(key, "\x1f"); i >= 0 {
		return key[:i+1]
	}
	return key
}

// correctedFrom splits a corrects value into the reported row's source and version (the vendor and product are lower case).
func correctedFrom(corrects string) (source, vendor, product, version string) {
	p := strings.SplitN(corrects, "\x1f", 4)
	for len(p) < 4 {
		p = append(p, "")
	}
	return p[0], p[1], p[2], p[3]
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

// SoftwareCorrection is on a person's correction of a reported row: when it was set, by whom, and what that source reads now.
type SoftwareCorrection struct {
	SetAt string `json:"set_at"`
	SetBy string `json:"set_by"`
	// Detected is the corrected row when its source still reports it, else that source's newest row of the product (another version,
	// which matches on its own); nil when the source reports the product no more: say so (review r1 L2).
	Detected  *SoftwareDetected `json:"detected"`
	Disagrees bool              `json:"disagrees"` // the source reads another product, version or package release than the person's
	// Active: the row it corrects is still reported, so matching uses the correction (review r2 M-B). false: the source moved on
	// (Detected is what it reads now) or reports the product no more (Detected nil); the source's reading decides until the person
	// sets the correction again (PATCH on Detected or on this row), and Disagrees is true.
	Active bool `json:"active"`
	// NotInstalled: the person said the row is not installed on the device (INV-41 (6)); while Active it matches nothing, and Disagrees
	// is false (the source still reading the row is what the person corrected). Not active: the source now reads another version
	// (Detected), a new install that matches.
	NotInstalled bool `json:"not_installed"`
}

// addCorrections fills the correction fields of a device's software views: on a correction, what it corrects; on the reported row a
// correction replaces, the id of that correction.
func addCorrections(ctx context.Context, q querier, assetID string, views []SoftwareView) error {
	rows, err := q.QueryContext(ctx, `SELECT s.id, ifnull(s.pkg_version, ''), ifnull(s.corrects, ''), ifnull(s.set_by, ''), s.seen_at, s.not_installed, `+rowKey("s")+`, `+productKey("s")+`
		FROM inv_software s WHERE s.asset_id = ?`, assetID)
	if err != nil {
		return fmt.Errorf("inventory: read corrections: %w", err)
	}
	type info struct {
		pkg, corrects, setBy, seenAt, key, product string
		notInstalled                               bool
	}
	byID := map[string]info{}
	for rows.Next() {
		var id string
		var i info
		if err := rows.Scan(&id, &i.pkg, &i.corrects, &i.setBy, &i.seenAt, &i.notInstalled, &i.key, &i.product); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inventory: read corrections: %w", err)
		}
		byID[id] = i
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("inventory: read corrections: %w", err)
	}
	correctionOf := map[string]string{} // reported row key -> correction id
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
		c := &SoftwareCorrection{SetAt: in.seenAt, SetBy: in.setBy, NotInstalled: in.notInstalled}
		var best *SoftwareView // the corrected row itself, else that source's newest row of the product
		for j := range views {
			d := &views[j]
			dk := byID[d.ID]
			if d.Source == "manual" || !strings.HasPrefix(in.corrects, dk.product) {
				continue
			}
			if dk.key == in.corrects {
				best = d
				break
			}
			if best == nil || dk.seenAt > byID[best.ID].seenAt {
				best = d
			}
		}
		c.Active = best != nil && byID[best.ID].key == in.corrects
		if best != nil {
			c.Detected = &SoftwareDetected{ID: best.ID, Display: best.Display, Version: best.Version, PkgVersion: best.PkgVersion, Source: best.Source, SeenAt: byID[best.ID].seenAt}
		}
		if d := c.Detected; d != nil {
			c.Disagrees = !strings.EqualFold(d.Display, v.Display) || deref(d.Version) != deref(v.Version) ||
				deref(d.PkgVersion) != "" && deref(v.PkgVersion) != "" && deref(d.PkgVersion) != deref(v.PkgVersion)
		}
		c.Disagrees = c.Disagrees || !c.Active
		if c.NotInstalled { // the source reading the row the person said is not there is the state corrected, not a disagreement
			c.Disagrees = !c.Active
			v.KevCVEs = []string{} // it matches nothing
		}
		v.Correction = c
	}
	return nil
}

// correctionNote names a person's software correction for the findings history (review r1 M3): "it@acme.example corrected OpenSSH
// 10.2 (nmap) to OpenSSH 10.2p1 (package 10.2_p1-r1) on 17 Nov 2026"; a "not installed" one (INV-41 (6)): "it@acme.example said
// OpenSSH 10.2 (nmap) is not installed on 17 Nov 2026".
func correctionNote(display, version, pkg, corrects, setBy, setAt string, notInstalled bool) string {
	src, _, product, from := correctedFrom(corrects)
	was := display
	if !strings.EqualFold(strings.ToLower(display), product) && !strings.Contains(strings.ToLower(display), product) {
		was = product
	}
	if notInstalled {
		return cmp.Or(setBy, "a person") + " said " + swText(was, from, "") + " (" + src + ") is not installed on " + correctionDay(setAt)
	}
	return cmp.Or(setBy, "a person") + " corrected " + swText(was, from, "") + " (" + src + ") to " + swText(display, version, pkg) + " on " + correctionDay(setAt)
}

// restingCorrections names the device's corrections that rest (review r2 M-B of #950: the row each corrects is no longer reported) on
// the reported rows of the same source and product that decide now (Superseded) and in StaleCorrections.
func restingCorrections(ctx context.Context, q querier, id string, d *MatchDevice, prefix map[string]string) error {
	rows, err := q.QueryContext(ctx, `SELECT s.display, ifnull(s.version, ''), ifnull(s.pkg_version, ''), s.corrects, ifnull(s.set_by, ''), s.seen_at, s.not_installed
		FROM inv_software s WHERE s.asset_id = ? AND s.corrects IS NOT NULL AND NOT `+correctionLive+` ORDER BY s.seen_at, s.id`, id)
	if err != nil {
		return fmt.Errorf("inventory: read resting corrections: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var display, version, pkg, corrects, setBy, setAt string
		var notInstalled bool
		if err := rows.Scan(&display, &version, &pkg, &corrects, &setBy, &setAt, &notInstalled); err != nil {
			return fmt.Errorf("inventory: read resting corrections: %w", err)
		}
		src, _, _, _ := correctedFrom(corrects)
		note := correctionNote(display, version, pkg, corrects, setBy, setAt, notInstalled)
		var now []int
		for i, sw := range d.Software {
			if prefix[sw.ID] == productPrefix(corrects) {
				now = append(now, i)
			}
		}
		if len(now) == 0 {
			note += "; " + src + " reports it no more, so Vedette does not use the correction"
		} else {
			reads := make([]string, len(now))
			for j, i := range now {
				reads[j] = swText(d.Software[i].Display, d.Software[i].Version, "")
			}
			note += "; " + src + " now reads " + strings.Join(reads, " and ") + ", so Vedette uses that until the correction is set again"
			for _, i := range now {
				d.Software[i].Superseded = note
			}
		}
		d.StaleCorrections = append(d.StaleCorrections, note)
	}
	return rows.Err()
}
