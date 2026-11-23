package inventory

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/productid"
)

// A person's software entries (INV-41, INV-52): the version a person gives a line (a reading of source manual), software a person
// declares by hand (a line whose only reading is the entry), and "not installed" (a state of the line). The resolver decides what
// the line shows; these functions only write what the person said, settle the line and say so in the history and the audit trail.

// SoftwareEdit is PATCH /inventory/devices/{id}/software/{sid}: a nil field or an empty product is left as it is.
type SoftwareEdit struct {
	Version    *string // "" removes the version
	PkgVersion *string // the distribution's package release ("10.2_p1-r1"); "" removes it
	CatalogID  string  // another product, from the catalog...
	Vendor     string  // ...or typed
	Product    string
	// NotInstalled: the person says the software is not installed on the device (INV-41 (6)). It takes no other field; a later
	// version, release or product a person gives makes the line installed again (the person says what is there).
	NotInstalled bool
}

func (e SoftwareEdit) product() bool { return e.CatalogID != "" || e.Vendor != "" || e.Product != "" }

// swText names a value in an audit row: "OpenSSH 10.2 (package 10.2_p1-r1)".
func swText(display, version, pkg string) string {
	t := strings.TrimSpace(display + " " + version)
	if pkg != "" {
		t += " (package " + pkg + ")"
	}
	return t
}

// noSoftware is the 404 of a software line the device does not have.
func noSoftware() *apierr.Error {
	return apierr.New(404, apierr.CodeNotFound, "No such software on this device.")
}

// lineOfDevice reads a line of a device that is not removed; a 404 when there is none.
func lineOfDevice(ctx context.Context, q querier, assetID, lineID string) (lineRow, error) {
	l, err := readLine(ctx, q, lineID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (l.assetID != assetID || l.state == stateRemoved) {
		return lineRow{}, noSoftware()
	}
	if err != nil {
		return lineRow{}, fmt.Errorf("inventory: read software: %w", err)
	}
	return l, nil
}

// entryOf is the person's entry among a line's readings, nil when none.
func entryOf(rs []Reading) *Reading {
	for i := range rs {
		if rs[i].entry() {
			return &rs[i]
		}
	}
	return nil
}

// detectedOf is the strongest reading of a source (not the person's entry, not a guess) of a line, nil when none.
func detectedOf(rs []Reading) *Reading {
	var best *Reading
	for i := range rs {
		r := &rs[i]
		if r.entry() {
			continue
		}
		if best == nil || readingRank(*r) > readingRank(*best) || readingRank(*r) == readingRank(*best) && r.SeenAt > best.SeenAt {
			best = r
		}
	}
	return best
}

// trainOf is the line a version of a stored product belongs to: the catalogue's train rule, "" for a product without trains.
func trainOf(productKey, version string) string {
	if p, ok := productid.ByKey(productKey); ok {
		return p.Line(version)
	}
	return ""
}

// EditSoftware changes what a person says about a software line of a device (INV-41, INV-52): its version or package release (the
// person's entry, which is the line until a newer reading), another product (the entry goes to that product's line and this one is
// marked not installed), or that it is not installed. What the person does not change is kept: the CPE, the packaged flag and the
// source package, and the package release while the version stays. The device's findings are matched again after the commit.
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
	var cat *catEntry
	if e.product() {
		c, err := s.Catalog(ctx)
		if err != nil {
			return err
		}
		var aerr *apierr.Error
		if cat, aerr = resolveProduct(c, AddInput{CatalogID: e.CatalogID, Vendor: e.Vendor, Product: e.Product}); aerr != nil {
			return aerr
		}
	}
	if e.NotInstalled {
		var box bool
		if err := s.db.Reader().QueryRowContext(ctx, `SELECT is_box FROM inv_asset WHERE id = ?`, assetID).Scan(&box); err != nil {
			return fmt.Errorf("inventory: read device: %w", err)
		}
		if box { // the box reads its own package list: what it reports is installed
			return conflict("box_device", "This is the Vedette box itself: it reads its own software, so a row cannot be marked not installed.")
		}
	}
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		ok, err := assetExists(ctx, tx, assetID)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundDevice()
		}
		l, err := lineOfDevice(ctx, tx, assetID, softwareID)
		if err != nil {
			return err
		}
		rs, err := readingsOf(ctx, tx, l.id)
		if err != nil {
			return err
		}
		if e.NotInstalled {
			return s.markNotInstalledTx(ctx, tx, o, actor, l, rs)
		}
		return s.editEntryTx(ctx, tx, o, actor, l, rs, e, cat, false)
	})
}

// markNotInstalledTx marks a line not installed (INV-41 (6)): it matches nothing until a source reads something new on it.
func (s *Service) markNotInstalledTx(ctx context.Context, tx *sql.Tx, o *outbox, actor string, l lineRow, rs []Reading) error {
	det := detectedOf(rs)
	if det == nil {
		return badRequest("bad_edit", "A person added this software: remove it instead (Not installed on a row a person added deletes it).")
	}
	if l.state == stateNotInstalled {
		return nil
	}
	before, err := deviceKeys(ctx, tx, l.assetID)
	if err != nil {
		return err
	}
	now := s.now()
	if _, err := tx.ExecContext(ctx, `UPDATE inv_software SET state = 'not_installed', not_installed_at = ?, not_installed_by = ? WHERE id = ?`, now, nullStr(actor), l.id); err != nil {
		return fmt.Errorf("inventory: mark not installed: %w", err)
	}
	if err := softwareEvent(ctx, tx, l.assetID, l.id, l.productKey, l.display, now, "marked_not_installed", l.version, "", "", actor); err != nil {
		return err
	}
	if err := s.settled(ctx, tx, o, l.assetID, before, l.id); err != nil {
		return err
	}
	from := swText(det.Display, det.Version, det.PkgVersion) + " (" + sourceClass(det.Source) + ")"
	return s.auditTx(ctx, tx, actor, "inventory.mark_not_installed", deviceName(ctx, tx, l.assetID)+": "+det.Display, from+" → not installed")
}

// settled settles the lines a person's change touched and announces it: the device's software changed, and its findings are
// matched again (a match event even when the keys stay: the version moved).
func (s *Service) settled(ctx context.Context, tx *sql.Tx, o *outbox, assetID string, before []string, lines ...string) error {
	now := s.now()
	for _, id := range lines {
		if _, err := s.settleLine(ctx, tx, id, now, nil); err != nil {
			return err
		}
	}
	moved, err := s.RecomputeAsset(ctx, tx, assetID) // a declared OS row may now be (or no longer be) the device's OS
	if err != nil {
		return err
	}
	if moved {
		o.add(EventAssetUpdated, AssetEvent{AssetID: assetID})
	}
	after, err := deviceKeys(ctx, tx, assetID)
	if err != nil {
		return err
	}
	o.add(EventSoftwareChanged, AssetEvent{AssetID: assetID}) // findings matches the device again on it (#910)
	o.after = append(o.after, s.matchAfter(assetID, before, after, true))
	return nil
}

// editEntryTx writes the person's entry of a line: the version and package release they give, or another product.
// versionOnly is SetSoftwareVersion's edit: its own audit row ("7.2.5 → 7.4.8").
func (s *Service) editEntryTx(ctx context.Context, tx *sql.Tx, o *outbox, actor string, l lineRow, rs []Reading, e SoftwareEdit, cat *catEntry, versionOnly bool) error {
	cur := entryOf(rs)
	base := Reading{}
	switch {
	case cur != nil:
		base = *cur
	default:
		if det := detectedOf(rs); det != nil {
			base = *det
		}
	}
	// the line as it reads now, for the audit trail
	var shownVersion, shownPkg, shownSource, shownDisplay string
	if err := tx.QueryRowContext(ctx, `SELECT ifnull(version, ''), ifnull(pkg_version, ''), source, display FROM inv_software WHERE id = ?`, l.id).
		Scan(&shownVersion, &shownPkg, &shownSource, &shownDisplay); err != nil {
		return fmt.Errorf("inventory: read software: %w", err)
	}
	next := Reading{Source: sourceManual, Display: base.Display, Version: base.Version, PkgVersion: base.PkgVersion, PkgSource: base.PkgSource, CPE: base.CPE,
		Packaged: base.Packaged, Confidence: 1, SetBy: actor}
	target := lineIdentity{productKey: l.productKey, line: l.line}
	var catID lineIdentity
	if cat != nil {
		catID, _ = identify(SoftwareItem{Display: cat.display, Vendor: cat.vendor, Product: cat.product, KevKeys: cat.kev}, sourceManual)
	}
	other := cat != nil && catID.productKey != l.productKey
	if other { // another product: nothing of this one is known
		target = catID
		next.Display, next.CPE, next.Packaged, next.PkgSource, next.PkgVersion = cat.display, "", false, "", ""
	}
	if e.Version != nil && *e.Version != next.Version {
		next.Version = *e.Version
		if e.PkgVersion == nil {
			next.PkgVersion = "" // the release of another version is not known
		}
	}
	if e.PkgVersion != nil {
		next.PkgVersion = *e.PkgVersion
	}
	if next.PkgVersion == "" && !next.Packaged {
		next.PkgSource = ""
	}
	if other {
		target.line = trainOf(target.productKey, next.Version)
	} else if t := trainOf(l.productKey, next.Version); t != l.line && next.Version != "" {
		target.line = t // the person's version is another train of the product: its own line
	}
	same := cur != nil && cur.Version == next.Version && cur.PkgVersion == next.PkgVersion && cur.Display == next.Display
	if same && target.productKey == l.productKey && target.line == l.line && l.state == statePresent {
		return nil // nothing changes: no audit row, no rematch
	}
	before, err := deviceKeys(ctx, tx, l.assetID)
	if err != nil {
		return err
	}
	now := s.now()
	next.FirstSeen, next.SeenAt = now, now
	lines := []string{l.id}
	if target.productKey == l.productKey && target.line == l.line {
		if l.state == stateNotInstalled { // the person now says what is installed
			if _, err := tx.ExecContext(ctx, `UPDATE inv_software SET state = 'present', not_installed_at = NULL, not_installed_by = NULL WHERE id = ?`, l.id); err != nil {
				return fmt.Errorf("inventory: correct software: %w", err)
			}
		}
		if err := putReading(ctx, tx, l.id, next); err != nil {
			return err
		}
		if err := softwareEvent(ctx, tx, l.assetID, l.id, l.productKey, next.Display, now, "entry_set", releaseText(shownVersion, shownPkg), releaseText(next.Version, next.PkgVersion), sourceManual, actor); err != nil {
			return err
		}
	} else {
		if target.vendor == "" { // the same product on another train keeps the line's names
			if err := tx.QueryRowContext(ctx, `SELECT vendor, product FROM inv_software WHERE id = ?`, l.id).Scan(&target.vendor, &target.product); err != nil {
				return fmt.Errorf("inventory: read software: %w", err)
			}
		}
		id, err := s.lineOf(ctx, tx, l.assetID, target, next)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE inv_software SET state = 'present', not_installed_at = NULL, not_installed_by = NULL WHERE id = ? AND state = 'not_installed'`, id); err != nil {
			return fmt.Errorf("inventory: correct software: %w", err)
		}
		if err := putReading(ctx, tx, id, next); err != nil {
			return err
		}
		if err := softwareEvent(ctx, tx, l.assetID, id, target.productKey, next.Display, now, "entry_set", "", releaseText(next.Version, next.PkgVersion), sourceManual, actor); err != nil {
			return err
		}
		if cur != nil { // the entry moved: this line is back to its sources
			if _, err := tx.ExecContext(ctx, `DELETE FROM inv_software_reading WHERE software_id = ? AND source = 'manual'`, l.id); err != nil {
				return fmt.Errorf("inventory: correct software: %w", err)
			}
		}
		if other && detectedOf(rs) != nil && l.state == statePresent { // the sources' product is not what runs there
			if _, err := tx.ExecContext(ctx, `UPDATE inv_software SET state = 'not_installed', not_installed_at = ?, not_installed_by = ? WHERE id = ?`, now, nullStr(actor), l.id); err != nil {
				return fmt.Errorf("inventory: correct software: %w", err)
			}
			if err := softwareEvent(ctx, tx, l.assetID, l.id, l.productKey, l.display, now, "marked_not_installed", l.version, "", "", actor); err != nil {
				return err
			}
		}
		lines = append(lines, id)
	}
	if err := s.settled(ctx, tx, o, l.assetID, before, lines...); err != nil {
		return err
	}
	if versionOnly {
		return s.auditTx(ctx, tx, actor, "inventory.set_software_version", deviceName(ctx, tx, l.assetID)+": "+shownDisplay,
			cmp.Or(cur.Version, "no version")+" → "+cmp.Or(next.Version, "no version"))
	}
	from := swText(shownDisplay, shownVersion, shownPkg) + " (" + sourceClass(shownSource) + ")"
	switch {
	case l.state == stateNotInstalled:
		from = "not installed"
	case cur != nil:
		from = swText(cur.Display, cur.Version, cur.PkgVersion)
	}
	return s.auditTx(ctx, tx, actor, "inventory.correct_software", deviceName(ctx, tx, l.assetID)+": "+shownDisplay, from+" → "+swText(next.Display, next.Version, next.PkgVersion))
}

// addEntryTx declares software on a device by hand (INV-4): the person's entry on the product's line. dup is true when the device
// already has the software from a source or a person (a guess is no duplicate: adding the product is how a person confirms it).
func (s *Service) addEntryTx(ctx context.Context, tx *sql.Tx, actor, assetID string, it SoftwareItem) (dup, moved bool, err error) {
	id, version := identify(it, sourceManual)
	var lineID, state string
	var guess bool
	err = tx.QueryRowContext(ctx, `SELECT s.id, s.state, `+guessLine+` FROM inv_software s WHERE s.asset_id = ? AND s.product_key = ? AND s.line = ?`, assetID, id.productKey, id.line).
		Scan(&lineID, &state, &guess)
	switch {
	case err == nil && state == statePresent && !guess:
		return true, false, nil
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return false, false, fmt.Errorf("inventory: check software: %w", err)
	}
	now := s.now()
	r := Reading{Source: sourceManual, Display: it.Display, Version: version, Confidence: 1, SetBy: actor, FirstSeen: now, SeenAt: now}
	lineID, err = s.lineOf(ctx, tx, assetID, id, r)
	if err != nil {
		return false, false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE inv_software SET state = 'present', not_installed_at = NULL, not_installed_by = NULL WHERE id = ? AND state = 'not_installed'`, lineID); err != nil {
		return false, false, fmt.Errorf("inventory: store software: %w", err)
	}
	if err := putReading(ctx, tx, lineID, r); err != nil {
		return false, false, err
	}
	if err := softwareEvent(ctx, tx, assetID, lineID, id.productKey, it.Display, now, "entry_set", "", version, sourceManual, actor); err != nil {
		return false, false, err
	}
	if _, err := s.settleLine(ctx, tx, lineID, now, map[[2]string][2]string{{sourceManual, ""}: {it.Vendor, it.Product}}); err != nil {
		return false, false, err
	}
	moved, err = s.RecomputeAsset(ctx, tx, assetID) // a declared OS row is the device's OS in the same transaction
	return false, moved, err
}

// RemoveSoftware takes back what a person said about a software line: the version they gave (the line is back to what its sources
// read; a line only the person declared is removed) or their "not installed". What a sensor or agent read is not removable.
func (s *Service) RemoveSoftware(ctx context.Context, actor, assetID, softwareID string) error {
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		ok, err := assetExists(ctx, tx, assetID)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundDevice()
		}
		l, err := lineOfDevice(ctx, tx, assetID, softwareID)
		if err != nil {
			return err
		}
		rs, err := readingsOf(ctx, tx, l.id)
		if err != nil {
			return err
		}
		entry := entryOf(rs)
		if entry == nil && l.state != stateNotInstalled {
			return badRequest("not_manual", "Only manually declared software can be removed. Software seen by a sensor or agent updates on the next scan.")
		}
		before, err := deviceKeys(ctx, tx, assetID)
		if err != nil {
			return err
		}
		now := s.now()
		if l.state == stateNotInstalled { // clearing "not installed": the line is what its sources read again
			if _, err := tx.ExecContext(ctx, `UPDATE inv_software SET state = 'present', not_installed_at = NULL, not_installed_by = NULL WHERE id = ?`, l.id); err != nil {
				return fmt.Errorf("inventory: clear not installed: %w", err)
			}
			if err := softwareEvent(ctx, tx, assetID, l.id, l.productKey, l.display, now, "unmarked", "", l.version, "", actor); err != nil {
				return err
			}
		} else {
			if _, err := tx.ExecContext(ctx, `DELETE FROM inv_software_reading WHERE software_id = ? AND source = 'manual'`, l.id); err != nil {
				return fmt.Errorf("inventory: remove software: %w", err)
			}
			if err := softwareEvent(ctx, tx, assetID, l.id, l.productKey, entry.Display, now, "entry_cleared", entry.Version, "", sourceManual, actor); err != nil {
				return err
			}
		}
		if err := s.settled(ctx, tx, o, assetID, before, l.id); err != nil {
			return err
		}
		if l.state == stateNotInstalled || detectedOf(rs) != nil { // clearing a correction (INV-41): the device is back to what its sources report
			return s.auditTx(ctx, tx, actor, "inventory.clear_software_correction", deviceName(ctx, tx, assetID)+": "+l.display, "back to detected")
		}
		return s.auditTx(ctx, tx, actor, "inventory.remove_software", deviceName(ctx, tx, assetID)+": "+l.display, "")
	})
}

// SetSoftwareVersion changes the version of a person's entry ("edit version": Accept on the device page's "the device reports X"
// hint, and findings' "I updated it"); "" removes the version. A line no person gave a version is not editable here: it changes with
// its source's next report (EditSoftware sets a version on any line). The device's findings are matched again after the commit.
func (s *Service) SetSoftwareVersion(ctx context.Context, actor, assetID, softwareID, version string) error {
	if err := s.requireDevice(ctx, assetID); err != nil { // 404 before 400, like AddSoftware
		return err
	}
	version = strings.TrimSpace(version)
	if version != "" && !versionRE.MatchString(version) {
		return badRequest("bad_version", "The version may only contain letters, digits, dots, hyphens and brackets, up to 40 characters. Example 7.2.5.")
	}
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		ok, err := assetExists(ctx, tx, assetID)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundDevice()
		}
		l, err := lineOfDevice(ctx, tx, assetID, softwareID)
		if err != nil {
			return err
		}
		rs, err := readingsOf(ctx, tx, l.id)
		if err != nil {
			return err
		}
		entry := entryOf(rs)
		if entry == nil {
			return badRequest("not_manual", "Only the version of manually declared software can be changed. Software seen by a sensor or agent updates on its next report.")
		}
		if entry.Version == version {
			return nil // nothing changes: no audit row, no rematch
		}
		v := version
		return s.editEntryTx(ctx, tx, o, actor, l, rs, SoftwareEdit{Version: &v}, nil, true)
	})
}

// SoftwareDetected is what the sources read of a line a person gave a version or marked not installed (contract.ts
// SoftwareCorrection.detected).
type SoftwareDetected struct {
	ID         string  `json:"id"`
	Display    string  `json:"display"`
	Version    *string `json:"version"`
	PkgVersion *string `json:"pkg_version"`
	Source     string  `json:"source"`
	SeenAt     string  `json:"seen_at"`
}

// SoftwareCorrection is on a line a person gave a version or marked not installed: when, by whom, and what the sources read now.
type SoftwareCorrection struct {
	SetAt string `json:"set_at"`
	SetBy string `json:"set_by"`
	// Detected is the strongest reading of a source of the line; nil when only the person says it is there.
	Detected  *SoftwareDetected `json:"detected"`
	Disagrees bool              `json:"disagrees"` // the sources read another version or package release than the person's
	// Active: the person's value is in use. It always is: a newer reading ends an entry (it lapses), and a new reading ends a "not
	// installed" mark (the line is then shown as the sources read it, with no correction).
	Active bool `json:"active"`
	// NotInstalled: the person said the software is not installed (INV-41 (6)); it matches nothing while the mark holds.
	NotInstalled bool `json:"not_installed"`
}

// optional is a text as an optional field: nil when empty.
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// correctionNote names a person's entry for the findings history: "it@acme.example corrected OpenSSH 10.2 (nmap) to OpenSSH
// 10.2p1 (package 10.2_p1-r1) on 17 Nov 2026" ("set OpenSSH to 10.2p1" when no source reads it); a "not installed" mark:
// "it@acme.example said OpenSSH 10.2 (nmap) is not installed on 17 Nov 2026".
func correctionNote(entry, det *Reading, display, setBy, setAt string, notInstalled bool, loc *time.Location) string {
	who := cmp.Or(setBy, "a person")
	if notInstalled {
		if det == nil {
			return who + " said " + display + " is not installed on " + correctionDay(setAt, loc)
		}
		return who + " said " + swText(det.Display, det.Version, "") + " (" + sourceClass(det.Source) + ") is not installed on " + correctionDay(setAt, loc)
	}
	if det == nil {
		return who + " set " + swText(entry.Display, entry.Version, entry.PkgVersion) + " on " + correctionDay(setAt, loc)
	}
	return who + " corrected " + swText(det.Display, det.Version, "") + " (" + sourceClass(det.Source) + ") to " + swText(entry.Display, entry.Version, entry.PkgVersion) +
		" on " + correctionDay(setAt, loc)
}
