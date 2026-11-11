package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

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
		it.KevKeys = keys
	}
	return it, nil
}

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
	_, err := tx.ExecContext(ctx, `INSERT INTO inv_software (id, asset_id, display, vendor, product, version, cpe, source, confidence, seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, assetID, it.Display, it.Vendor, it.Product, nullStr(it.Version), nullStr(it.CPE), source, it.Confidence, seenAt)
	if err != nil {
		return fmt.Errorf("inventory: store software: %w", err)
	}
	return insertKeys(ctx, tx, id, it.KevKeys)
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
	rows, err := tx.QueryContext(ctx, `SELECT id, vendor, product, ifnull(version, '') FROM inv_software WHERE asset_id = ? AND source = ?`, assetID, source)
	if err != nil {
		return fmt.Errorf("inventory: read software: %w", err)
	}
	have := map[string]string{}
	for rows.Next() {
		var id, v, p, ver string
		if err := rows.Scan(&id, &v, &p, &ver); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inventory: read software: %w", err)
		}
		have[swKey(v, p, ver)] = id
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	changed := false
	keep := map[string]bool{}
	for _, it := range items {
		k := swKey(it.Vendor, it.Product, it.Version)
		if keep[k] {
			continue // the same product twice in one list
		}
		keep[k] = true
		if id, ok := have[k]; ok {
			if _, err := tx.ExecContext(ctx, `UPDATE inv_software SET display = ?, cpe = ?, confidence = ?, seen_at = ? WHERE id = ?`, it.Display, nullStr(it.CPE), it.Confidence, seenAt, id); err != nil {
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
	if !changed {
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
	for i, it := range items {
		conv[i] = SoftwareItem{Display: it.Display, Vendor: it.Vendor, Product: it.Product, Version: it.Version, CPE: it.CPE, KevKeys: it.KevKeys, Confidence: it.Confidence}
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
		id, isNew, err := s.resolve(ctx, tx, cleanObs{ip: ip, mac: mac, seenAt: now})
		if err != nil {
			return err
		}
		if isNew {
			notify, err := notifyNew(ctx, tx)
			if err != nil {
				return err
			}
			if mac != "" {
				if err := insertObs(ctx, tx, id, "mac", mac, string(source), hintConfidence, now); err != nil {
					return err
				}
				if _, err := s.RecomputeAsset(ctx, tx, id); err != nil {
					return err
				}
			}
			target := mac
			if target == "" {
				target = ip.String()
			}
			if err := s.auditTx(ctx, tx, systemActor, "inventory.discover", target, id); err != nil {
				return err
			}
			o.add(EventAssetDiscovered, AssetEvent{AssetID: id, Notify: notify})
		}
		return s.replaceSoftwareTx(ctx, tx, o, id, clean, string(source), now)
	})
}
