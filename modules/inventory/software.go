package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/knt048/vedette/core/apkver"
	"github.com/knt048/vedette/core/debver"
	"github.com/knt048/vedette/core/observe"
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
		if !instanceOK(it.Instance) {
			return it, invalid("software %d: instance must be at most 120 printable characters", i)
		}
		if utf8.RuneCountInString(it.CPE) > maxCPE || strings.ContainsFunc(it.CPE, func(r rune) bool { return r < 0x20 }) {
			return it, invalid("software %d: cpe is not valid", i)
		}
		if it.Confidence < 0 || it.Confidence > 1 || it.Confidence != it.Confidence {
			return it, invalid("software %d: confidence must be between 0 and 1", i)
		}
		if !debver.Valid(it.PkgVersion) && !apkver.Valid(it.PkgVersion) || !pkgSourceRE.MatchString(it.PkgSource) || !it.Packaged {
			it.PkgVersion, it.PkgSource = "", "" // Only a well-formed pair of a package database row is kept
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
		if it.Guess { // a guess is never matched: it waits for a person to add the software with its version
			keys = nil
		}
		it.KevKeys = keys
	}
	return it, nil
}

// pkgSourceRE is a Debian source package name (Policy §5.6.1).
var pkgSourceRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{0,99}$`)

// deviceKeys lists the distinct match keys of the software of a device that counts for matching (matchedLine): present, not a guess
// the device does not show.
func deviceKeys(ctx context.Context, q querier, assetID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT DISTINCT s.product_key, `+guessLine+` FROM inv_software s WHERE s.asset_id = ? AND `+liveSW, assetID)
	if err != nil {
		return nil, fmt.Errorf("inventory: read match keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var keys []string
	for rows.Next() {
		var k string
		var guess bool
		if err := rows.Scan(&k, &guess); err != nil {
			return nil, fmt.Errorf("inventory: read match keys: %w", err)
		}
		keys = append(keys, matchKeys(k, guess)...)
	}
	slices.Sort(keys)
	return slices.Compact(keys), rows.Err()
}

// packaged is the stored flag of a reading (MK-2): only an agent reads a package database; a sensor's claim is not stored.
func packaged(it SoftwareItem, source string) bool {
	return it.Packaged && agentSource(source)
}

// pkgOf is the stored full version and source package of a reading: only with packaged, both or neither.
func pkgOf(it SoftwareItem, source string) (version, src string) {
	if !packaged(it, source) || it.PkgVersion == "" || it.PkgSource == "" {
		return "", ""
	}
	return it.PkgVersion, it.PkgSource
}

// matchEvents is run after the commit: the CVEs of the keys after the change that were not matched before
// become inventory.match.changed events, basis "product" (KEV has no affected ranges, and only a scan confirms).
func (s *Service) matchEvents(assetID string, before, after []string) func(context.Context) []Event {
	return s.matchAfter(assetID, before, after, false)
}

// matchAfter is matchEvents; with rematch it adds one match event naming the device's first CVE after the change, for a device whose
// versions changed (a package update, a person's version): findings matches the whole device again on it. The exploited lists are
// read once for both.
func (s *Service) matchAfter(assetID string, before, after []string, rematch bool) func(context.Context) []Event {
	return func(ctx context.Context) []Event {
		changed := !slices.Equal(before, after)
		if s.kev == nil || !changed && !rematch {
			return nil
		}
		cves, err := s.kevIndex(ctx)
		if err != nil {
			s.log.WarnContext(ctx, "inventory: KEV match failed", "asset", assetID, "error", err)
			return nil
		}
		now := cves(after)
		var out []Event
		if changed {
			was := cves(before)
			for _, cve := range slices.Compact(slices.Sorted(slices.Values(now))) {
				if !slices.Contains(was, cve) {
					out = append(out, Event{Name: EventMatchChanged, Data: MatchEvent{AssetID: assetID, CVE: cve, Basis: "product"}})
				}
			}
		}
		if rematch && len(now) > 0 {
			out = append(out, Event{Name: EventMatchChanged, Data: MatchEvent{AssetID: assetID, CVE: slices.Min(now), Basis: "product"}})
		}
		return out
	}
}

// listed is one item of a list as it lands: its line and its reading.
type listed struct {
	id      lineIdentity
	reading Reading
}

// readingsOfList turns a validated list into readings, one per line and instance. An item without an instance that shares its line
// with another item of the list at another version (two installs the source does not tell apart) gets its version as instance; the
// same product at the same version twice is one reading.
func readingsOfList(items []SoftwareItem, source, seenAt string) []listed {
	out := make([]listed, 0, len(items))
	for _, it := range items {
		id, version := identify(it, source)
		pv, ps := pkgOf(it, source)
		inst := it.Instance
		if it.Guess && inst == "" {
			inst = instanceOSGuess
		}
		out = append(out, listed{id: id, reading: Reading{Source: source, Instance: inst, Display: it.Display, Version: version, PkgVersion: pv, PkgSource: ps,
			CPE: it.CPE, Packaged: packaged(it, source), Confidence: it.Confidence, FirstSeen: seenAt, SeenAt: seenAt}})
	}
	type slot struct{ key, line, inst string }
	versions := map[slot]map[string]bool{}
	for _, l := range out {
		k := slot{l.id.productKey, l.id.line, l.reading.Instance}
		if versions[k] == nil {
			versions[k] = map[string]bool{}
		}
		versions[k][l.reading.Version+"\x00"+l.reading.PkgVersion] = true
	}
	seen := map[slot]bool{}
	kept := out[:0]
	for _, l := range out {
		k := slot{l.id.productKey, l.id.line, l.reading.Instance}
		if len(versions[k]) > 1 {
			l.reading.Instance = clip(strings.TrimPrefix(l.reading.Instance+"@"+cmpOr(l.reading.PkgVersion, l.reading.Version), "@"), 120)
			if l.reading.Instance == "" {
				l.reading.Instance = "@"
			}
		}
		k.inst = l.reading.Instance
		if seen[k] {
			continue
		}
		seen[k] = true
		kept = append(kept, l)
	}
	return kept
}

// replaceSoftwareTx makes what a source reads of a device equal to items: the readings of that source (of the instances scope
// names, all of them when scope is nil) that are not in the list go, new ones come, the rest are refreshed; then every line the
// change touched is settled. Readings of other sources are not touched.
func (s *Service) replaceSoftwareTx(ctx context.Context, tx *sql.Tx, o *outbox, assetID string, items []SoftwareItem, source string, scope []string, seenAt string) error {
	before, err := deviceKeys(ctx, tx, assetID)
	if err != nil {
		return err
	}
	type have struct {
		line, version, pkg string
	}
	rows, err := tx.QueryContext(ctx, `SELECT r.software_id, r.instance, ifnull(r.version, ''), ifnull(r.pkg_version, '') FROM inv_software_reading r
		JOIN inv_software s ON s.id = r.software_id WHERE s.asset_id = ? AND r.source = ?`, assetID, source)
	if err != nil {
		return fmt.Errorf("inventory: read software: %w", err)
	}
	old := map[[2]string]have{} // line, instance -> what it read
	for rows.Next() {
		var h have
		var inst string
		if err := rows.Scan(&h.line, &inst, &h.version, &h.pkg); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inventory: read software: %w", err)
		}
		old[[2]string{h.line, inst}] = h
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("inventory: read software: %w", err)
	}
	inScope := func(inst string) bool { return scope == nil || slices.Contains(scope, inst) }
	touched := map[string]bool{}
	names := map[string]map[[2]string][2]string{} // line -> the names its readings of this list carry
	kept := map[[2]string]bool{}
	changed, released := false, false
	for _, l := range readingsOfList(items, source, seenAt) {
		if !inScope(l.reading.Instance) {
			continue // a list covers only the instances of its scope
		}
		lineID, err := s.lineOf(ctx, tx, assetID, l.id, l.reading)
		if err != nil {
			return err
		}
		k := [2]string{lineID, l.reading.Instance}
		if kept[k] {
			continue
		}
		kept[k] = true
		h, had := old[k]
		if !had { // the line's own release read again (after a removal, or by another instance) is no new reading
			var v, pv, first string
			if err := tx.QueryRowContext(ctx, `SELECT ifnull(version, ''), ifnull(pkg_version, ''), first_seen FROM inv_software WHERE id = ?`, lineID).Scan(&v, &pv, &first); err != nil {
				return fmt.Errorf("inventory: read software line: %w", err)
			}
			if v == l.reading.Version && pv == l.reading.PkgVersion && first < l.reading.FirstSeen {
				l.reading.FirstSeen = first
			}
		}
		switch {
		case !had:
			changed = true
		case h.version != l.reading.Version || h.pkg != l.reading.PkgVersion:
			released = true
		}
		if err := putReading(ctx, tx, lineID, l.reading); err != nil {
			return err
		}
		touched[lineID] = true
		if names[lineID] == nil {
			names[lineID] = map[[2]string][2]string{}
		}
		names[lineID][[2]string{source, l.reading.Instance}] = [2]string{l.id.vendor, l.id.product}
	}
	for k, h := range old {
		if kept[k] || !inScope(k[1]) {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_software_reading WHERE software_id = ? AND source = ? AND instance = ?`, h.line, source, k[1]); err != nil {
			return fmt.Errorf("inventory: remove software reading: %w", err)
		}
		touched[h.line] = true
		changed = true
	}
	if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET last_seen = max(last_seen, ?) WHERE id = ?`, seenAt, assetID); err != nil {
		return fmt.Errorf("inventory: touch device: %w", err)
	}
	if err := s.earnReview(ctx, tx, o, assetID, false); err != nil { // the sync moved last_seen (INV-49)
		return err
	}
	var lapsed []string
	for _, id := range slices.Sorted(maps.Keys(touched)) {
		st, err := s.settleLine(ctx, tx, id, seenAt, names[id])
		if err != nil {
			return err
		}
		if st.lapsed != "" {
			lapsed = append(lapsed, st.lapsed)
		}
		changed = changed || st.changed
	}
	for _, d := range lapsed {
		if err := s.auditTx(ctx, tx, systemActor, "inventory.software_correction_lapsed", deviceName(ctx, tx, assetID), d); err != nil {
			return err
		}
	}
	if !changed && !released {
		return nil
	}
	if err := s.auditTx(ctx, tx, systemActor, "inventory.software_sync", deviceName(ctx, tx, assetID), fmt.Sprintf("%s: %d items", source, len(items))); err != nil {
		return err
	}
	moved, err := s.RecomputeAsset(ctx, tx, assetID) // a source that outranks a declared OS row may have come or gone
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
	o.add(EventSoftwareChanged, AssetEvent{AssetID: assetID})
	// the keys did not change but a version did: matchEvents says nothing, so the device is matched again
	o.after = append(o.after, s.matchAfter(assetID, before, after, released && slices.Equal(before, after)))
	return nil
}

// UpsertSoftware replaces the software a source read on a device (PRE-2, POST-2): the readings of that source not in items go,
// readings of other sources stay. "manual" and "agent" are refused: a person's entries are set one by one, and an agent list
// names the agent that read it ("box" for the box's own packages).
func (s *Service) UpsertSoftware(ctx context.Context, assetID string, items []SoftwareItem, source string) error {
	if !observe.ValidSoftwareSource(observe.Source(source)) {
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
		return s.replaceSoftwareTx(ctx, tx, o, assetID, clean, source, nil, s.now())
	})
}

// ReplaceSoftware implements observe.SoftwareSink: the device is found by MAC or IP, or created unapproved.
func (s *Service) ReplaceSoftware(ctx context.Context, hint observe.AssetHint, source observe.Source, scope []string, items []observe.Software) error {
	ip, mac, err := checkHint(hint)
	if err != nil {
		return err
	}
	if !observe.ValidSoftwareSource(source) {
		return invalid("software source %q is not allowed", source)
	}
	class := observe.ClassOf(source)
	agent, err := checkAgent(hint, class)
	if err != nil {
		return err
	}
	from, err := checkFrom(hint)
	if err != nil {
		return err
	}
	if len(scope) > maxItems {
		return invalid("a software list has a scope of at most %d instances", maxItems)
	}
	for _, inst := range scope {
		if !instanceOK(inst) {
			return invalid("a scope instance is not valid")
		}
	}
	conv := make([]SoftwareItem, len(items))
	cat := s.cpeCatalog(ctx, items)
	for i, it := range items {
		conv[i] = SoftwareItem{Display: it.Display, Vendor: it.Vendor, Product: it.Product, Version: it.Version, CPE: it.CPE, KevKeys: it.KevKeys, Confidence: it.Confidence, Guess: it.Guess, Packaged: it.Packaged,
			PkgVersion: it.PkgVersion, PkgSource: it.PkgSource, Instance: it.Instance}
		if len(it.KevKeys) == 0 && it.CPE != "" && cat != nil && !it.Guess {
			conv[i].KevKeys = cat.keysForCPE(it.CPE) // nmap's "apple:iphone_os" is CISA's "Apple|iOS"; nil keeps the vendor|product key
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
		id, err := s.deviceFor(ctx, tx, o, cleanObs{ip: ip, mac: mac, agent: agent, from: from, source: string(class), seenAt: now})
		if err != nil || id == "" { // "": no device may take the list (resolve)
			return err
		}
		if class == observe.Agent {
			if off, err := agentRefused(ctx, tx, id); err != nil || off { // a person turned the agent off for this device (ChangeSources)
				return err
			}
		}
		return s.replaceSoftwareTx(ctx, tx, o, id, clean, string(source), scope, now)
	})
}

// instanceOK checks an instance a source gives: at most 120 printable characters ("" is the source's only reading).
func instanceOK(inst string) bool {
	return inst == "" || cleanText(inst) && utf8.RuneCountInString(inst) <= 120
}

// cpeCatalog is the catalog when an item of the list has a CPE, for its KEV keys (keysForCPE); nil otherwise, or when it cannot
// be read: the items then keep their vendor|product key, and the failure is logged.
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

// deviceFor finds the device of a sensor's list (software, services) by its MAC or IP, or creates it unapproved and announces it;
// "" when no device may take it (resolve: an agent's key alone that is bound to nothing, an address no sighting confirmed lately).
// Every call is a contact of the source, whether or not it creates a device.
func (s *Service) deviceFor(ctx context.Context, tx *sql.Tx, o *outbox, c cleanObs) (string, error) {
	ip, mac, source, now := c.ip, c.mac, observe.Source(c.source), c.seenAt
	learning, err := s.learning(ctx, tx, string(source))
	if err != nil {
		return "", err
	}
	find := c
	find.list = true
	find.source = ""                              // a list moves no address by its source; the agent bound to a device does, in resolve
	id, isNew, err := s.resolve(ctx, tx, o, find) // binds no agent: the observation batch of the same report does (Record)
	if err != nil || id == "" {
		return "", err
	}
	if !isNew {
		return s.settle(ctx, tx, o, id, false)
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
	kept, err := s.settle(ctx, tx, o, id, true)
	if err != nil || kept != id { // joined into a known device in the same write: never announced
		return kept, err
	}
	quiet, err := isQuiet(ctx, tx, id) // a rotating private address is announced only once it earns a look (INV-49)
	if err != nil {
		return "", err
	}
	o.add(EventAssetDiscovered, AssetEvent{AssetID: id, Notify: notify && !quiet, Learning: learning})
	return id, nil
}

// settle runs the join rules (joinSame) on the device a list reached, as Record does for its batch: finding
// the device may have taken an address from another row (claimIP), which a join then resolves. It returns the device the list
// belongs to: the one a joined row went into. A device that received another is folded again and announced updated.
func (s *Service) settle(ctx context.Context, tx *sql.Tx, o *outbox, id string, isNew bool) (string, error) {
	view, err := matchView(ctx, tx, id)
	if err != nil {
		return "", err
	}
	before := map[string]string{id: view}
	created := map[string]string{}
	if isNew {
		created[id] = "list"
	}
	gone, joined, err := s.joinSame(ctx, tx, o, []string{id}, created, before)
	if err != nil {
		return "", err
	}
	for _, j := range joined {
		if _, err := s.RecomputeAsset(ctx, tx, j); err != nil {
			return "", err
		}
		o.add(EventAssetUpdated, AssetEvent{AssetID: j, Match: true})
		if err := s.earnReview(ctx, tx, o, j, false); err != nil {
			return "", err
		}
	}
	if gone[id] && len(joined) > 0 {
		return joined[len(joined)-1], nil
	}
	return id, nil
}
