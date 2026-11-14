package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/knt048/vedette/core/debver"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
)

// hintConfidence is the confidence of the MAC an agent gave to find its device.
const hintConfidence = 0.9

const (
	maxItems   = 5000
	maxKeys    = 64
	maxCPE     = 500
	maxSwField = 200
	maxSwVer   = 100
)

// checkItems validates software that comes from an agent (SYS-6) and fills in the defaults. An item that does not pass (a name with an
// invisible character, L12) is dropped and logged on its own: one such name must not reject the rest of a device's list. Any other bad
// item is still refused (PRE-2).
func (s *Service) checkItems(ctx context.Context, items []SoftwareItem) ([]SoftwareItem, error) {
	if len(items) > maxItems {
		return nil, invalid("a software list has at most %d items", maxItems)
	}
	out := make([]SoftwareItem, 0, len(items))
	for i, it := range items {
		it, err := checkItem(i, it)
		if err != nil {
			if !hasInvisible(it.Vendor, it.Product, it.Display, it.Version) {
				return nil, err
			}
			s.log.WarnContext(ctx, "inventory: a software item with an invisible character was dropped", "index", i)
			continue
		}
		out = append(out, it)
	}
	return out, nil
}

// hasInvisible says whether a text holds a character cleanText refuses as invisible (not a C0 control: those stay a refusal).
func hasInvisible(texts ...string) bool {
	for _, t := range texts {
		if strings.ContainsFunc(t, invisible) {
			return true
		}
	}
	return false
}

// checkItem validates one item.
func checkItem(i int, it SoftwareItem) (SoftwareItem, error) {
	{
		it.Vendor, it.Product, it.Display, it.Version = stripIgnorable(it.Vendor), stripIgnorable(it.Product), stripIgnorable(it.Display), stripIgnorable(it.Version)
		if !cleanText(it.Vendor) || !cleanText(it.Product) {
			return it, invalid("software %d: vendor and product must be 1 to %d printable characters", i, maxSwField)
		}
		if it.Display == "" {
			it.Display = it.Vendor + " " + it.Product
		}
		if !cleanText(it.Display) {
			return it, invalid("software %d: display must be 1 to %d printable characters", i, maxSwField)
		}
		if it.Version != "" && (!cleanText(it.Version) || utf8.RuneCountInString(it.Version) > maxSwVer) {
			return it, invalid("software %d: version must be at most %d printable characters", i, maxSwVer)
		}
		if utf8.RuneCountInString(it.CPE) > maxCPE || strings.ContainsFunc(it.CPE, func(r rune) bool { return r < 0x20 }) {
			return it, invalid("software %d: cpe is not valid", i)
		}
		if it.Confidence < 0 || it.Confidence > 1 || it.Confidence != it.Confidence {
			return it, invalid("software %d: confidence must be between 0 and 1", i)
		}
		if !debver.Valid(it.PkgVersion) || !pkgSourceRE.MatchString(it.PkgSource) || !it.Packaged {
			it.PkgVersion, it.PkgSource = "", "" // D-516: only a well-formed pair of a package database row is kept
		}
		if len(it.KevKeys) > maxKeys {
			return it, invalid("software %d: at most %d match keys", i, maxKeys)
		}
		keys := make([]string, 0, len(it.KevKeys))
		for _, k := range it.KevKeys {
			k = strings.ToLower(strings.TrimSpace(k))
			if !cleanText(k) || len(k) > 400 {
				return it, invalid("software %d: a match key is not valid", i)
			}
			if !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
		if len(keys) == 0 {
			keys = []string{kevKey(it.Vendor, it.Product)}
		}
		if it.Guess { // a guess is never matched (D-501): it waits for a person to add the software with its version
			keys = nil
		}
		it.KevKeys = keys
	}
	return it, nil
}

// pkgSourceRE is a Debian source package name (Policy §5.6.1).
var pkgSourceRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,99}$`)

func swKey(vendor, product, version string) string {
	return strings.ToLower(vendor) + "\x00" + strings.ToLower(product) + "\x00" + version
}

// softwareKeys lists the distinct KEV keys of all software of a device.
func softwareKeys(ctx context.Context, q querier, assetID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT DISTINCT k.kev_key FROM inv_software s JOIN inv_software_kev k ON k.software_id = s.id WHERE s.asset_id = ? ORDER BY 1`, assetID)
	if err != nil {
		return nil, fmt.Errorf("inventory: read match keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, fmt.Errorf("inventory: read match keys: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func insertKeys(ctx context.Context, tx *sql.Tx, softwareID string, keys []string) error {
	for _, k := range keys {
		if _, err := tx.ExecContext(ctx, `INSERT INTO inv_software_kev (software_id, kev_key) VALUES (?, ?) ON CONFLICT DO NOTHING`, softwareID, k); err != nil {
			return fmt.Errorf("inventory: store match key: %w", err)
		}
	}
	return nil
}

func insertSoftware(ctx context.Context, tx *sql.Tx, assetID string, it SoftwareItem, source, seenAt string) error {
	id := store.NewID("s")
	pv, ps := pkgOf(it, source)
	_, err := tx.ExecContext(ctx, `INSERT INTO inv_software (id, asset_id, display, vendor, product, version, cpe, source, confidence, seen_at, packaged, pkg_version, pkg_source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, assetID, it.Display, it.Vendor, it.Product, nullStr(it.Version), nullStr(it.CPE), source, it.Confidence, seenAt, packaged(it, source), pv, ps)
	if err != nil {
		return fmt.Errorf("inventory: store software: %w", err)
	}
	return insertKeys(ctx, tx, id, it.KevKeys)
}

// packaged is the stored flag of a row (D-474, MK-2): only an agent reads a package database; a sensor's claim is not stored.
func packaged(it SoftwareItem, source string) bool {
	return it.Packaged && source == string(observe.Agent)
}

// pkgOf is the stored full version and source package of a row (D-516): only with packaged, both or neither.
func pkgOf(it SoftwareItem, source string) (version, src any) {
	if !packaged(it, source) || it.PkgVersion == "" || it.PkgSource == "" {
		return nil, nil
	}
	return it.PkgVersion, it.PkgSource
}

// matchEvents is run after the commit: the CVEs of the keys after the change that were not matched before
// become inventory.match.changed events, basis "product" (KEV has no affected ranges, and only a scan confirms).
func (s *Service) matchEvents(assetID string, before, after []string) func(context.Context) []Event {
	return func(ctx context.Context) []Event {
		if s.kev == nil || slices.Equal(before, after) {
			return nil
		}
		was, err1 := s.cves(ctx, before)
		now, err2 := s.cves(ctx, after)
		if err1 != nil || err2 != nil {
			s.log.WarnContext(ctx, "inventory: KEV match failed", "asset", assetID, "error", fmt.Sprint(err1, err2))
			return nil
		}
		var out []Event
		for _, cve := range slices.Compact(slices.Sorted(slices.Values(now))) {
			if !slices.Contains(was, cve) {
				out = append(out, Event{Name: EventMatchChanged, Data: MatchEvent{AssetID: assetID, CVE: cve, Basis: "product"}})
			}
		}
		return out
	}
}

// replaceSoftwareTx makes the software a source reported equal to items: rows of that source that are not in
// the list go, new ones come, the rest are refreshed. Rows of other sources are not touched.
func (s *Service) replaceSoftwareTx(ctx context.Context, tx *sql.Tx, o *outbox, assetID string, items []SoftwareItem, source, seenAt string) error {
	before, err := softwareKeys(ctx, tx, assetID)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, vendor, product, ifnull(version, ''), ifnull(pkg_version, '') FROM inv_software WHERE asset_id = ? AND source = ?`, assetID, source)
	if err != nil {
		return fmt.Errorf("inventory: read software: %w", err)
	}
	have := map[string]string{}
	havePkg := map[string]string{} // D-516: the full version a row had, to see a package update that keeps the upstream number
	for rows.Next() {
		var id, v, p, ver, pv string
		if err := rows.Scan(&id, &v, &p, &ver, &pv); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inventory: read software: %w", err)
		}
		have[swKey(v, p, ver)] = id
		havePkg[id] = pv
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	changed, pkgChanged := false, false
	keep := map[string]bool{}
	for _, it := range items {
		k := swKey(it.Vendor, it.Product, it.Version)
		if keep[k] {
			continue // the same product twice in one list
		}
		keep[k] = true
		if id, ok := have[k]; ok {
			pv, ps := pkgOf(it, source)
			if now, _ := pv.(string); now != havePkg[id] { // 1:9.6p1-3ubuntu13.5 -> 13.14: the same row, a different package
				pkgChanged = true
			}
			if _, err := tx.ExecContext(ctx, `UPDATE inv_software SET display = ?, cpe = ?, confidence = ?, seen_at = ?, packaged = ?, pkg_version = ?, pkg_source = ? WHERE id = ?`,
				it.Display, nullStr(it.CPE), it.Confidence, seenAt, packaged(it, source), pv, ps, id); err != nil {
				return fmt.Errorf("inventory: refresh software: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM inv_software_kev WHERE software_id = ?`, id); err != nil {
				return fmt.Errorf("inventory: refresh match keys: %w", err)
			}
			if err := insertKeys(ctx, tx, id, it.KevKeys); err != nil {
				return err
			}
			continue
		}
		if err := insertSoftware(ctx, tx, assetID, it, source, seenAt); err != nil {
			return err
		}
		changed = true
	}
	for k, id := range have {
		if keep[k] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_software WHERE id = ?`, id); err != nil {
			return fmt.Errorf("inventory: remove software: %w", err)
		}
		changed = true
	}
	if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET last_seen = max(last_seen, ?) WHERE id = ?`, seenAt, assetID); err != nil {
		return fmt.Errorf("inventory: touch device: %w", err)
	}
	if !changed && !pkgChanged {
		return nil
	}
	if err := s.auditTx(ctx, tx, systemActor, "inventory.software_sync", deviceName(ctx, tx, assetID), fmt.Sprintf("%s: %d items", source, len(items))); err != nil {
		return err
	}
	after, err := softwareKeys(ctx, tx, assetID)
	if err != nil {
		return err
	}
	o.add(EventSoftwareChanged, AssetEvent{AssetID: assetID})
	o.after = append(o.after, s.matchEvents(assetID, before, after))
	if pkgChanged { // D-516: the keys did not change, so matchEvents says nothing; one event makes findings read the device again
		o.after = append(o.after, func(ctx context.Context) []Event {
			cves, err := s.cves(ctx, after)
			if err != nil || len(cves) == 0 {
				return nil
			}
			return []Event{{Name: EventMatchChanged, Data: MatchEvent{AssetID: assetID, CVE: slices.Min(cves), Basis: "product"}}}
		})
	}
	return nil
}

// UpsertSoftware replaces the software a source reported for a device (PRE-2, POST-2): rows of that source
// not in items are removed, rows of other sources stay. "manual" is refused: manual rows are declared one by
// one (AddSoftware) and a sync must never delete what a person declared.
func (s *Service) UpsertSoftware(ctx context.Context, assetID string, items []SoftwareItem, source string) error {
	if !observe.ValidSource(observe.Source(source)) || source == "manual" {
		return invalid("software source %q is not allowed", source)
	}
	clean, err := s.checkItems(ctx, items)
	if err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		ok, err := assetExists(ctx, tx, assetID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		return s.replaceSoftwareTx(ctx, tx, o, assetID, clean, source, s.now())
	})
}

// ReplaceSoftware implements observe.SoftwareSink: the device is found by MAC or IP, or created unapproved.
func (s *Service) ReplaceSoftware(ctx context.Context, hint observe.AssetHint, source observe.Source, items []observe.Software) error {
	ip, mac, err := checkHint(hint)
	if err != nil {
		return err
	}
	if !observe.ValidSource(source) || source == observe.Manual {
		return invalid("software source %q is not allowed", source)
	}
	conv := make([]SoftwareItem, len(items))
	cat := s.cpeCatalog(ctx, items)
	for i, it := range items {
		conv[i] = SoftwareItem{Display: it.Display, Vendor: it.Vendor, Product: it.Product, Version: it.Version, CPE: it.CPE, KevKeys: it.KevKeys, Confidence: it.Confidence, Guess: it.Guess, Packaged: it.Packaged,
			PkgVersion: it.PkgVersion, PkgSource: it.PkgSource}
		if len(it.KevKeys) == 0 && it.CPE != "" && cat != nil && !it.Guess {
			conv[i].KevKeys = cat.keysForCPE(it.CPE) // nmap's "apple:iphone_os" is CISA's "Apple|iOS" (D-501); nil keeps the vendor|product key
		}
	}
	clean, err := s.checkItems(ctx, conv)
	if err != nil {
		return err
	}
	if isBox := s.ownedFilter(ctx); isBox != nil && isBox(ip, mac) { // a box-owned address is no device (Config.BoxOwnedIPs, BoxOwnedMACs)
		s.ownedHit.Add(1)
		return nil
	}
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		now := s.seen(s.clock())
		id, err := s.deviceFor(ctx, tx, o, ip, mac, source, now)
		if err != nil {
			return err
		}
		return s.replaceSoftwareTx(ctx, tx, o, id, clean, string(source), now)
	})
}

// cpeCatalog is the catalog when an item of the list has a CPE, for its KEV keys (keysForCPE); nil otherwise, or when it cannot
// be read: the items then keep their vendor|product key, as before D-501, and the failure is logged.
func (s *Service) cpeCatalog(ctx context.Context, items []observe.Software) *Catalog {
	if !slices.ContainsFunc(items, func(it observe.Software) bool { return it.CPE != "" && len(it.KevKeys) == 0 && !it.Guess }) {
		return nil
	}
	cat, err := s.Catalog(ctx)
	if err != nil {
		s.log.WarnContext(ctx, "inventory: the catalog could not be read; software from a CPE keeps its vendor and product key", "error", err)
		return nil
	}
	return cat
}

// deviceFor finds the device of a sensor's list (software, services) by its MAC or IP, or creates it unapproved and announces it.
// Every call is a contact of the source (D-474), whether or not it creates a device.
func (s *Service) deviceFor(ctx context.Context, tx *sql.Tx, o *outbox, ip netip.Addr, mac string, source observe.Source, now string) (string, error) {
	learning, err := s.learning(ctx, tx, string(source))
	if err != nil {
		return "", err
	}
	id, isNew, err := s.resolve(ctx, tx, cleanObs{ip: ip, mac: mac, seenAt: now})
	if err != nil || !isNew {
		return id, err
	}
	notify, err := notifyNew(ctx, tx)
	if err != nil {
		return "", err
	}
	if mac != "" {
		if err := insertObs(ctx, tx, id, "mac", mac, string(source), hintConfidence, now); err != nil {
			return "", err
		}
		if _, err := s.RecomputeAsset(ctx, tx, id); err != nil {
			return "", err
		}
	}
	target := mac
	if target == "" {
		target = ip.String()
	}
	if err := s.auditTx(ctx, tx, systemActor, "inventory.discover", target, id); err != nil {
		return "", err
	}
	o.add(EventAssetDiscovered, AssetEvent{AssetID: id, Notify: notify, Learning: learning})
	return id, nil
}
