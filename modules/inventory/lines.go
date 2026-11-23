package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/store"
)

// A software line (inv_software) is one installed software of a device: one product (core/productid), or one release train of a
// product whose trains install side by side. Its id never changes. Its readings (inv_software_reading) are what each source reads
// now; its effective columns are written only by settleLine, from Resolve, in the transaction that changed a reading. Its history
// is inv_software_event.

// lineIdentity is where a reading belongs: the product key and the train, and the names a new line takes.
type lineIdentity struct {
	productKey, line string
	vendor, product  string
}

// identify is the line of a software item a source sent and the version it reads. An agent names its products itself (it reads a
// package or program name with core/productid, and leaves a component of a product unnamed on purpose): an agent's item without a
// match key is a product of its own. Any other item is core/productid's product when the catalogue knows its name or CPE (its key,
// its train rule; a version the name states replaces one that is not the product's own release, ".NET Runtime - 6.0.25 (x64)" read
// as 48.100.4028) when its exploited-list names hold the item's first match key; else the product that first key belongs to
// (productid.ByKEV), else that key; else the key of its vendor and product.
func identify(it SoftwareItem, source string) (lineIdentity, string) {
	id := lineIdentity{vendor: it.Vendor, product: it.Product}
	version := it.Version
	var p productid.Product
	ok := false
	if !agentSource(source) || len(it.KevKeys) > 0 {
		p, ok = productid.ResolveStored(it.Vendor, it.Product, it.Display, it.CPE)
	}
	first := ""
	if len(it.KevKeys) > 0 {
		first = productid.NormalizeKey(it.KevKeys[0])
	}
	switch {
	case ok && p.Key != "" && (p.ID != "" || first == "") && (first == "" || slices.Contains(p.KEV, first)):
		id.productKey = p.Key
		if p.VersionNotOwn {
			version = p.Version
		}
		id.line = p.Line(version)
	case first != "":
		// the product the item's own exploited-list name belongs to ("Edge and Internet Explorer" is Internet Explorer), else that name
		id.productKey = first
		if q, ok := productid.ByKEV(first); ok {
			id.productKey, id.line = q.Key, q.Line(version)
		}
	default:
		id.productKey = productid.Key(it.Vendor, it.Product)
		if p, ok := productid.ByKey(id.productKey); ok && agentSource(source) { // the agent's own name of a catalogue product
			id.line = p.Line(version)
		}
	}
	if len(id.productKey) > 400 {
		id.productKey = id.productKey[:400]
	}
	return id, version
}

// matchKeys are the exploited-list keys a line is matched by: the catalogue's keys of its product, else its own key. A guess has
// none: it raises no finding until a person adds the software with its version.
func matchKeys(productKey string, guess bool) []string {
	if guess {
		return []string{}
	}
	if p, ok := productid.ByKey(productKey); ok && len(p.KEV) > 0 {
		out := slices.Clone(p.KEV)
		if !slices.Contains(out, productKey) {
			out = append(out, productKey)
		}
		return out
	}
	return []string{productKey}
}

// lineRow is a line as the write paths read it.
type lineRow struct {
	id, assetID, productKey, line, display, version, pkgVersion, source, state, notInstalledAt string
}

func readLine(ctx context.Context, q querier, id string) (lineRow, error) {
	var l lineRow
	err := q.QueryRowContext(ctx, `SELECT id, asset_id, product_key, line, display, ifnull(version, ''), ifnull(pkg_version, ''), source, state, ifnull(not_installed_at, '')
		FROM inv_software WHERE id = ?`, id).Scan(&l.id, &l.assetID, &l.productKey, &l.line, &l.display, &l.version, &l.pkgVersion, &l.source, &l.state, &l.notInstalledAt)
	return l, err
}

const readingCols = `r.source, r.instance, r.display, ifnull(r.version, ''), ifnull(r.pkg_version, ''), ifnull(r.pkg_source, ''), ifnull(r.cpe, ''),
	ifnull(r.set_by, ''), r.packaged, r.confidence, r.first_seen, r.seen_at, r.addr_id`

func scanReading(sc interface{ Scan(...any) error }, extra ...any) (Reading, error) {
	var r Reading
	dst := append([]any{&r.Source, &r.Instance, &r.Display, &r.Version, &r.PkgVersion, &r.PkgSource, &r.CPE, &r.SetBy, &r.Packaged, &r.Confidence, &r.FirstSeen, &r.SeenAt, &r.Addr}, extra...)
	return r, sc.Scan(dst...)
}

// readingsOf reads the readings of one line.
func readingsOf(ctx context.Context, tx *sql.Tx, lineID string) ([]Reading, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+readingCols+` FROM inv_software_reading r WHERE r.software_id = ? ORDER BY r.source, r.instance, r.addr_id`, lineID)
	if err != nil {
		return nil, fmt.Errorf("inventory: read software readings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Reading
	for rows.Next() {
		r, err := scanReading(rows)
		if err != nil {
			return nil, fmt.Errorf("inventory: read software readings: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// lineOf finds the line of a device for an identity, or creates it (state present, its effective reading the first one, history
// "appeared"). A removed line found again comes back through settleLine.
func (s *Service) lineOf(ctx context.Context, tx *sql.Tx, assetID string, id lineIdentity, first Reading) (lineID string, err error) {
	err = tx.QueryRowContext(ctx, `SELECT id FROM inv_software WHERE asset_id = ? AND product_key = ? AND line = ?`, assetID, id.productKey, id.line).Scan(&lineID)
	if err == nil {
		return lineID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("inventory: read software line: %w", err)
	}
	lineID = store.NewID("s")
	vendor, product := clip(id.vendor, maxSwField), clip(id.product, maxSwField)
	if _, err := tx.ExecContext(ctx, `INSERT INTO inv_software (id, asset_id, product_key, line, display, vendor, product, cpe, version, pkg_version, pkg_source, packaged,
		source, set_by, confidence, seen_at, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		lineID, assetID, id.productKey, id.line, first.Display, vendor, product, nullStr(first.CPE), nullStr(first.Version), nullStr(first.PkgVersion), nullStr(first.PkgSource),
		first.Packaged, first.Source, nullStr(first.SetBy), first.Confidence, first.SeenAt, first.SeenAt, first.SeenAt); err != nil {
		return "", fmt.Errorf("inventory: store software line: %w", err)
	}
	actor := first.SetBy
	if !first.entry() {
		actor = ""
	}
	if err := softwareEvent(ctx, tx, assetID, lineID, id.productKey, first.Display, first.SeenAt, "appeared", "", first.Version, first.Source, actor); err != nil {
		return "", err
	}
	return lineID, nil
}

// putReading writes one reading of a line: a new one, or the same source and instance read again. first_seen stays while the
// release stays (version and package release); a new release is a new reading (the lapse and "not installed" rules read it).
func putReading(ctx context.Context, tx *sql.Tx, lineID string, r Reading) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO inv_software_reading (software_id, source, instance, display, version, pkg_version, pkg_source, packaged, cpe, confidence, set_by, first_seen, seen_at, addr_id)
		VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
		ON CONFLICT (software_id, source, instance, addr_id) DO UPDATE SET
			first_seen = CASE WHEN ifnull(inv_software_reading.version, '') = ifnull(excluded.version, '') AND ifnull(inv_software_reading.pkg_version, '') = ifnull(excluded.pkg_version, '')
				AND excluded.source <> 'manual' THEN inv_software_reading.first_seen ELSE excluded.first_seen END,
			display = excluded.display, version = excluded.version, pkg_version = excluded.pkg_version, pkg_source = excluded.pkg_source, packaged = excluded.packaged,
			cpe = excluded.cpe, confidence = excluded.confidence, set_by = excluded.set_by, seen_at = excluded.seen_at`,
		lineID, r.Source, r.Instance, clip(r.Display, maxSwField), nullStr(r.Version), nullStr(r.PkgVersion), nullStr(r.PkgSource), r.Packaged, nullStr(r.CPE), r.Confidence,
		nullStr(r.SetBy), r.FirstSeen, r.SeenAt, r.Addr)
	if err != nil {
		return fmt.Errorf("inventory: store software reading: %w", err)
	}
	return nil
}

// softwareEvent appends one row to a line's history.
func softwareEvent(ctx context.Context, tx *sql.Tx, assetID, lineID, productKey, display, ts, kind, from, to, source, actor string) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO inv_software_event (asset_id, software_id, product_key, display, ts, kind, from_version, to_version, source, actor)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, assetID, lineID, productKey, clip(display, maxSwField), ts, kind, nullStr(from), nullStr(to), nullStr(source), nullStr(actor)); err != nil {
		return fmt.Errorf("inventory: record software history: %w", err)
	}
	return nil
}

// settled is what settleLine changed on a line.
type settled struct {
	changed bool   // the effective value or the state moved
	lapsed  string // the audit detail of a lapsed entry ("" when none)
}

// settleLine runs the resolver on one line and stores its answer, with the history of what moved. names, when set, gives the
// vendor and product the effective reading's source wrote in this transaction (they become the line's names).
func (s *Service) settleLine(ctx context.Context, tx *sql.Tx, lineID, now string, names map[[2]string][2]string) (settled, error) {
	var out settled
	l, err := readLine(ctx, tx, lineID)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	} else if err != nil {
		return out, fmt.Errorf("inventory: read software line: %w", err)
	}
	readings, err := readingsOf(ctx, tx, lineID)
	if err != nil {
		return out, err
	}
	res := Resolve(LineState{State: l.state, NotInstalledAt: l.notInstalledAt}, readings)
	if res.Lapsed != nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_software_reading WHERE software_id = ? AND source = 'manual'`, lineID); err != nil {
			return out, fmt.Errorf("inventory: lapse the entry: %w", err)
		}
		e, b := res.Lapsed, res.LapsedBy
		if err := softwareEvent(ctx, tx, l.assetID, lineID, l.productKey, e.Display, now, "entry_lapsed", e.Version, b.Version, b.Source, ""); err != nil {
			return out, err
		}
		out.lapsed = swText(e.Display, e.Version, e.PkgVersion) + " → " + swText(b.Display, b.Version, b.PkgVersion) + " (" + sourceClass(b.Source) + ")"
		out.changed = true
		if e.Instance == instanceOS { // the entry was the person's OS of the device (syncStatedOS): it ends with it, or it would come back
			if err := s.endOSCorrection(ctx, tx, l.assetID, b); err != nil {
				return out, err
			}
		}
	}
	if res.Unmarked {
		if err := softwareEvent(ctx, tx, l.assetID, lineID, l.productKey, l.display, now, "unmarked", "", res.Effective.Version, res.Effective.Source, ""); err != nil {
			return out, err
		}
	}
	switch {
	case res.State == stateRemoved && l.state != stateRemoved:
		if err := softwareEvent(ctx, tx, l.assetID, lineID, l.productKey, l.display, now, "removed", l.version, "", "", ""); err != nil {
			return out, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE inv_software SET state = 'removed', removed_at = ?, differs = 0 WHERE id = ?`, now, lineID); err != nil { // a person's mark stays
			return out, fmt.Errorf("inventory: remove software line: %w", err)
		}
		out.changed = true
		return out, nil
	case res.State == stateRemoved:
		return out, nil
	case l.state == stateRemoved:
		if err := softwareEvent(ctx, tx, l.assetID, lineID, l.productKey, res.Effective.Display, now, "reappeared", "", res.Effective.Version, res.Effective.Source, ""); err != nil {
			return out, err
		}
		out.changed = true
	}
	e := res.Effective
	if l.state != stateRemoved && (e.Version != l.version || e.PkgVersion != l.pkgVersion) {
		if err := softwareEvent(ctx, tx, l.assetID, lineID, l.productKey, e.Display, now, "version_changed", releaseText(l.version, l.pkgVersion), releaseText(e.Version, e.PkgVersion), e.Source, e.SetBy); err != nil {
			return out, err
		}
		out.changed = true
	}
	if e.Source != l.source || res.State != l.state || res.Unmarked {
		out.changed = true
	}
	lastSeen := ""
	for _, r := range readings {
		lastSeen = max(lastSeen, r.SeenAt)
	}
	notInstalled := "CASE WHEN ?12 = 'not_installed' THEN not_installed_at END"
	set := `UPDATE inv_software SET display = ?1, cpe = ?2, version = ?3, pkg_version = ?4, pkg_source = ?5, packaged = ?6, source = ?7, set_by = ?8, confidence = ?9,
		seen_at = ?10, differs = ?11, state = ?12, removed_at = NULL, not_installed_at = ` + notInstalled + `,
		not_installed_by = CASE WHEN ?12 = 'not_installed' THEN not_installed_by END, last_seen = max(last_seen, ?13)`
	args := []any{clip(e.Display, maxSwField), nullStr(e.CPE), nullStr(e.Version), nullStr(e.PkgVersion), nullStr(e.PkgSource), e.Packaged, e.Source, nullStr(e.SetBy), e.Confidence,
		e.SeenAt, res.Differs, res.State, cmpOr(lastSeen, now)}
	if vp, ok := names[[2]string{e.Source, e.Instance}]; ok {
		set += `, vendor = ?14, product = ?15`
		args = append(args, clip(vp[0], maxSwField), clip(vp[1], maxSwField))
	}
	if _, err := tx.ExecContext(ctx, set+` WHERE id = ?`+fmt.Sprint(len(args)+1), append(args, lineID)...); err != nil {
		return out, fmt.Errorf("inventory: store software line: %w", err)
	}
	return out, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// releaseText is a version with its package release, as the history keeps it ("10.2p1 (1:10.2p1-2ubuntu3.8)").
func releaseText(version, pkg string) string {
	if pkg == "" || pkg == version {
		return version
	}
	return strings.TrimSpace(version + " (" + pkg + ")")
}

// endOSCorrection ends a person's OS of a device whose stated-OS line a newer reading outgrew (Resolve rule 1): the manual OS
// observation goes, the device's columns are folded again, and the audit trail says so as for lapseOS.
func (s *Service) endOSCorrection(ctx context.Context, tx *sql.Tx, assetID string, by *Reading) error {
	person, _, _, ok, err := manualOS(ctx, tx, assetID)
	if err != nil || !ok {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source = 'manual'`, assetID); err != nil {
		return fmt.Errorf("inventory: lapse the corrected OS: %w", err)
	}
	if _, err := s.recomputeColumns(ctx, tx, assetID); err != nil {
		return err
	}
	return s.auditTx(ctx, tx, systemActor, "inventory.os_correction_lapsed", deviceName(ctx, tx, assetID),
		person+" → "+swText(by.Display, by.Version, by.PkgVersion)+" ("+sourceClass(by.Source)+")")
}
