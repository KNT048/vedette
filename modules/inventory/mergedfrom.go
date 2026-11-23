package inventory

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/knt048/vedette/core/store"
)

// A person's merge is undone by Split off of the address the merged device brought: the split gives back that device as it was, not
// a new "Unknown" row. The merge keeps what the device brought on the kept one (inv_merged_from): its id, its main interface, its
// origin, its name in Vedette, the observations only it held and its software readings (inv_merged_reading); and what the kept device
// was before the merge (its name in Vedette, and its type and OS as a person set them), when the merge changed them. The split of that
// interface takes them back (its id when no device holds it), and gives the kept device its own back unless a person changed it since.

// maxMergedFacts is the largest inv_merged_from.facts the table takes.
const maxMergedFacts = 65536

// mergedFacts is inv_merged_from.facts.
type mergedFacts struct {
	Obs []mergedObs `json:"obs"`
	// TookName (rows of older merges): the kept device had no name in Vedette and took the merged device's (joinAs); the split gives
	// it back. Newer rows say it with Kept.
	TookName bool `json:"took_name,omitempty"`
	// Origin is how the merged device came to be known ("manual": a person added it, so it is not scanned like a found one); ""
	// in rows of older merges, which give back a found device.
	Origin string `json:"origin,omitempty"`
	// Kept is what the kept device was before the merge and right after it: the split gives the "before" back when it still is the
	// "after" (nobody changed it since). nil in rows of older merges and once the row followed the kept device into another merge.
	Kept *keptOwn `json:"kept,omitempty"`
	// Series are the observation series (field and source) the kept device held none of before the merge, set when Obs had to be
	// cut to the newest of each series to fit (maxMergedFacts): the split takes every observation of those series the merge brought.
	Series []obsSeries `json:"series,omitempty"`
}

type mergedObs struct {
	Field      string  `json:"field"`
	Value      string  `json:"value"`
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
	SeenAt     string  `json:"seen_at"`
	// Only: the kept device held no such observation before the merge, so it goes back with the split; the others are copied.
	Only bool `json:"only,omitempty"`
}

type obsSeries struct {
	Field  string `json:"field"`
	Source string `json:"source"`
}

// keptOwn is the kept device's own name, type and OS before a merge and right after it.
type keptOwn struct {
	Before keptState `json:"before"`
	After  keptState `json:"after"`
}

// keptState is a device's name in Vedette and the type and OS a person set on it (its manual observations of kind and os).
type keptState struct {
	Name   *string     `json:"name"`
	Manual []manualObs `json:"manual"`
}

type manualObs struct {
	Field      string  `json:"field"`
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence"`
	SeenAt     string  `json:"seen_at"`
	FirstSeen  *string `json:"first_seen,omitempty"`
	Evidence   *string `json:"evidence,omitempty"`
}

// keptStateOf reads device id's keptState.
func keptStateOf(ctx context.Context, tx *sql.Tx, id string) (keptState, error) {
	var out keptState
	var name sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT user_name FROM inv_asset WHERE id = ?`, id).Scan(&name); err != nil {
		return out, fmt.Errorf("inventory: read device: %w", err)
	}
	if name.Valid {
		out.Name = &name.String
	}
	rows, err := tx.QueryContext(ctx, `SELECT field, value, confidence, seen_at, first_seen, evidence FROM inv_observation
		WHERE asset_id = ? AND source = 'manual' AND field IN ('kind', 'os') ORDER BY field, value, seen_at`, id)
	if err != nil {
		return out, fmt.Errorf("inventory: read observations: %w", err)
	}
	out.Manual = []manualObs{}
	for rows.Next() {
		var o manualObs
		var first, ev sql.NullString
		if err := rows.Scan(&o.Field, &o.Value, &o.Confidence, &o.SeenAt, &first, &ev); err != nil {
			_ = rows.Close()
			return out, fmt.Errorf("inventory: read observations: %w", err)
		}
		if first.Valid {
			o.FirstSeen = &first.String
		}
		if ev.Valid {
			o.Evidence = &ev.String
		}
		out.Manual = append(out.Manual, o)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return out, fmt.Errorf("inventory: read observations: %w", err)
	}
	return out, nil
}

// manualOf is what a keptState holds of field, as value and time.
func (k keptState) manualOf(field string) [][2]string {
	out := [][2]string{}
	for _, o := range k.Manual {
		if o.Field == field {
			out = append(out, [2]string{o.Value, o.SeenAt})
		}
	}
	return out
}

func sameName(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }

// rememberMerged keeps what device from brings to into in a person's merge, before the merge moves it: from's main interface, its
// origin, its name in Vedette, its observations, marked when into does not hold them (a MAC goes with its interface; a declared OS is
// decided again), and its software readings (inv_merged_reading). Nothing is kept for a device without an address: there is nothing
// to split off.
func rememberMerged(ctx context.Context, tx *sql.Tx, into, from, now string) error {
	var ip, mac, fromName sql.NullString
	var origin string
	if err := tx.QueryRowContext(ctx, `SELECT ip, mac, user_name, origin FROM inv_asset WHERE id = ?`, from).Scan(&ip, &mac, &fromName, &origin); err != nil {
		return fmt.Errorf("inventory: read devices: %w", err)
	}
	if !ip.Valid && !mac.Valid {
		return nil
	}
	// from's main interface may be one an earlier merge into from brought (the card seen last becomes the main one): the interface
	// from brings of its own is then the first of its other addresses no earlier merge brought, so a split of each interface gives
	// back the device that had it.
	if claimed, err := broughtBefore(ctx, tx, from, ip, mac); err != nil {
		return err
	} else if claimed {
		extras, err := extrasOf(ctx, tx, from)
		if err != nil {
			return err
		}
		for _, x := range extras {
			if c, err := broughtBefore(ctx, tx, from, x.ip, x.mac); err != nil {
				return err
			} else if !c {
				ip, mac = x.ip, x.mac
				break
			}
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT f.field, f.value, f.source, f.confidence, f.seen_at,
		NOT EXISTS (SELECT 1 FROM inv_observation i WHERE i.asset_id = ?2 AND i.field = f.field AND i.source = f.source AND i.value = f.value)
		FROM inv_observation f WHERE f.asset_id = ?1 AND f.source <> 'declared' AND f.field <> 'mac' ORDER BY f.field, f.source, f.value`, from, into)
	if err != nil {
		return fmt.Errorf("inventory: read observations: %w", err)
	}
	facts := mergedFacts{Obs: []mergedObs{}, Origin: origin}
	for rows.Next() {
		var o mergedObs
		if err := rows.Scan(&o.Field, &o.Value, &o.Source, &o.Confidence, &o.SeenAt, &o.Only); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inventory: read observations: %w", err)
		}
		facts.Obs = append(facts.Obs, o)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("inventory: read observations: %w", err)
	}
	raw, err := json.Marshal(facts)
	if err != nil {
		return fmt.Errorf("inventory: keep the merged device: %w", err)
	}
	if len(raw) > maxMergedFacts {
		if raw, err = cutFacts(ctx, tx, into, facts); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO inv_merged_from (asset_id, from_id, ip, mac, user_name, facts, merged_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (asset_id, from_id) DO UPDATE SET ip = excluded.ip, mac = excluded.mac, user_name = excluded.user_name, facts = excluded.facts, merged_at = excluded.merged_at`,
		into, from, ip, mac, fromName, string(raw), now); err != nil {
		return fmt.Errorf("inventory: keep the merged device: %w", err)
	}
	// Every reading of from's lines, but the ones an earlier merge into from brought (they go back with the device that brought them).
	// shared: into reads the same product, train, source and instance, so a copy goes back and into's own stays.
	for _, q := range []string{
		`DELETE FROM inv_merged_reading WHERE asset_id = ?2 AND from_id = ?1`,
		`INSERT OR IGNORE INTO inv_merged_reading (asset_id, from_id, software_id, product_key, line, source, instance, shared)
		SELECT ?2, ?1, w.id, w.product_key, w.line, r.source, r.instance,
			EXISTS (SELECT 1 FROM inv_software k JOIN inv_software_reading kr ON kr.software_id = k.id WHERE k.asset_id = ?2 AND k.product_key = w.product_key
				AND k.line = w.line AND kr.source = r.source AND kr.instance = r.instance)
		FROM inv_software w JOIN inv_software_reading r ON r.software_id = w.id WHERE w.asset_id = ?1
			AND NOT EXISTS (SELECT 1 FROM inv_merged_reading m WHERE m.asset_id = ?1 AND m.product_key = w.product_key AND m.line = w.line
				AND m.source = r.source AND m.instance = r.instance)`,
	} {
		if _, err := tx.ExecContext(ctx, q, from, into); err != nil {
			return fmt.Errorf("inventory: keep the merged device's software: %w", err)
		}
	}
	return nil
}

// cutFacts is facts cut to fit maxMergedFacts: of each observation series (field and source) the one that counts most (the highest
// confidence, then the newest), so the device given back still states its maker, model, host name, type and OS, and the series into
// held none of, whose other observations the split takes from into by series (Series).
func cutFacts(ctx context.Context, tx *sql.Tx, into string, facts mergedFacts) ([]byte, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT field, source FROM inv_observation WHERE asset_id = ?`, into)
	if err != nil {
		return nil, fmt.Errorf("inventory: read observations: %w", err)
	}
	held := map[obsSeries]bool{}
	for rows.Next() {
		var s obsSeries
		if err := rows.Scan(&s.Field, &s.Source); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("inventory: read observations: %w", err)
		}
		held[s] = true
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("inventory: read observations: %w", err)
	}
	best := map[obsSeries]mergedObs{}
	for _, o := range facts.Obs {
		s := obsSeries{o.Field, o.Source}
		if b, ok := best[s]; !ok || o.Confidence > b.Confidence || o.Confidence == b.Confidence && o.SeenAt > b.SeenAt {
			best[s] = o
		}
	}
	keys := slices.SortedFunc(maps.Keys(best), func(a, b obsSeries) int {
		return cmp.Or(cmp.Compare(a.Field, b.Field), cmp.Compare(a.Source, b.Source))
	})
	facts.Obs, facts.Series = make([]mergedObs, 0, len(keys)), []obsSeries{}
	for _, s := range keys {
		facts.Obs = append(facts.Obs, best[s])
		if !held[s] {
			facts.Series = append(facts.Series, s)
		}
	}
	raw, err := json.Marshal(facts)
	if err == nil && len(raw) > maxMergedFacts { // a series holds one observation of at most 253 characters: never reached
		facts.Obs, facts.Series = []mergedObs{}, nil
		raw, err = json.Marshal(facts)
	}
	if err != nil {
		return nil, fmt.Errorf("inventory: keep the merged device: %w", err)
	}
	return raw, nil
}

// noteKept writes into the merge rows of from what device into was before the merge and is after it (with the choice a person made),
// so the split gives into its own name, type and OS back.
func noteKept(ctx context.Context, tx *sql.Tx, into string, from []string, before keptState) error {
	after, err := keptStateOf(ctx, tx, into)
	if err != nil {
		return err
	}
	for _, f := range from {
		var raw string
		err := tx.QueryRowContext(ctx, `SELECT facts FROM inv_merged_from WHERE asset_id = ? AND from_id = ?`, into, f).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			continue // a device without an address: nothing to split off
		} else if err != nil {
			return fmt.Errorf("inventory: read the merged device: %w", err)
		}
		var facts mergedFacts
		if err := json.Unmarshal([]byte(raw), &facts); err != nil {
			return fmt.Errorf("inventory: read the merged device: %w", err)
		}
		facts.Kept = &keptOwn{Before: before, After: after}
		out, err := json.Marshal(facts)
		if err != nil {
			return fmt.Errorf("inventory: keep the merged device: %w", err)
		}
		if len(out) > maxMergedFacts { // the type and OS a person set are a few rows: keep the merge rather than refuse it
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE inv_merged_from SET facts = ? WHERE asset_id = ? AND from_id = ?`, string(out), into, f); err != nil {
			return fmt.Errorf("inventory: keep the merged device: %w", err)
		}
	}
	return nil
}

// broughtBefore reports whether an earlier merge into device id brought the interface ip/mac.
func broughtBefore(ctx context.Context, tx *sql.Tx, id string, ip, mac sql.NullString) (bool, error) {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM inv_merged_from WHERE asset_id = ? AND (ip = ? OR mac = ?)`, id, ip, mac).Scan(&n); err != nil {
		return false, fmt.Errorf("inventory: read the merged devices: %w", err)
	}
	return n > 0, nil
}

// mergedFrom is a row of inv_merged_from.
type mergedFrom struct {
	fromID   string
	userName sql.NullString
	mergedAt string
	facts    mergedFacts
}

// origin is the origin the device split off takes: its own, as the merge kept it; "discovered" for rows of older merges.
func (m *mergedFrom) origin() string {
	if m != nil && m.facts.Origin == "manual" {
		return "manual"
	}
	return "discovered"
}

// mergedAt finds what a merge kept of the device whose main interface was the one split off (ip or mac of it), nil when none.
func mergedAt(ctx context.Context, tx *sql.Tx, id string, ip, mac sql.NullString) (*mergedFrom, error) {
	var m mergedFrom
	var raw string
	err := tx.QueryRowContext(ctx, `SELECT from_id, user_name, merged_at, facts FROM inv_merged_from WHERE asset_id = ? AND (ip = ? OR mac = ?) ORDER BY merged_at DESC LIMIT 1`,
		id, ip, mac).Scan(&m.fromID, &m.userName, &m.mergedAt, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inventory: read the merged device: %w", err)
	}
	if err := json.Unmarshal([]byte(raw), &m.facts); err != nil {
		return nil, fmt.Errorf("inventory: read the merged device: %w", err)
	}
	return &m, nil
}

// splitID is the id the device split off takes: the merged device's own when a merge kept it and no device holds it, else a new one.
func splitID(ctx context.Context, tx *sql.Tx, m *mergedFrom, fresh string) (string, error) {
	if m == nil {
		return fresh, nil
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM inv_asset WHERE id = ?`, m.fromID).Scan(&n); err != nil {
		return "", fmt.Errorf("inventory: read devices: %w", err)
	}
	if n > 0 {
		return fresh, nil
	}
	return m.fromID, nil
}

// mergedReading is a row of inv_merged_reading.
type mergedReading struct {
	source, instance string
	shared           bool
}

// giveBackSoftware moves the software readings a merge kept of the device back from id to the device split off as newID, before the
// interface moves (moveInterface takes what a scan read at it). A line the merged device brought whole, that nothing else reads now,
// goes back whole: its id, its history and a person's "not installed" mark with it, so its findings are the device's own again when
// both devices are matched. Else each reading goes to newID's line of that product and train (a reading into read too is copied, the
// others leave id); a scan's readings are the interface's, and the OS a device states is a line its observations make again.
func (s *Service) giveBackSoftware(ctx context.Context, tx *sql.Tx, id, newID string, m *mergedFrom) error {
	if m == nil {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT software_id, product_key, line, source, instance, shared FROM inv_merged_reading WHERE asset_id = ? AND from_id = ?
		ORDER BY software_id, source, instance`, id, m.fromID)
	if err != nil {
		return fmt.Errorf("inventory: read the merged software: %w", err)
	}
	type line struct {
		key, train string
		readings   []mergedReading
	}
	lines := map[string]*line{}
	for rows.Next() {
		var sid string
		var l line
		var r mergedReading
		if err := rows.Scan(&sid, &l.key, &l.train, &r.source, &r.instance, &r.shared); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inventory: read the merged software: %w", err)
		}
		if lines[sid] == nil {
			lines[sid] = &l
		}
		lines[sid].readings = append(lines[sid].readings, r)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("inventory: read the merged software: %w", err)
	}
	now := s.now()
	touched := map[string]bool{}
	for _, sid := range slices.Sorted(maps.Keys(lines)) {
		l := lines[sid]
		var cur, vendor, product string
		err := tx.QueryRowContext(ctx, `SELECT id, vendor, product FROM inv_software WHERE asset_id = ?1 AND (id = ?2 OR product_key = ?3 AND line = ?4) ORDER BY id = ?2 DESC LIMIT 1`,
			id, sid, l.key, l.train).Scan(&cur, &vendor, &product)
		if errors.Is(err, sql.ErrNoRows) {
			continue // the line is gone since the merge (a person removed it)
		} else if err != nil {
			return fmt.Errorf("inventory: read software: %w", err)
		}
		brought := func(src, inst string) (mergedReading, bool) {
			i := slices.IndexFunc(l.readings, func(r mergedReading) bool { return r.source == src && r.instance == inst })
			if i < 0 {
				return mergedReading{}, false
			}
			return l.readings[i], true
		}
		type reading struct {
			r  Reading
			ev itemEvidence
		}
		rs, err := tx.QueryContext(ctx, `SELECT `+readingCols+`, `+evidenceCols+` FROM inv_software_reading r WHERE r.software_id = ? ORDER BY r.source, r.instance, r.addr_id`, cur)
		if err != nil {
			return fmt.Errorf("inventory: read software: %w", err)
		}
		var list []reading
		for rs.Next() {
			evDst, ev := evidenceDest()
			r, err := scanReading(rs, evDst...)
			if err != nil {
				_ = rs.Close()
				return fmt.Errorf("inventory: read software: %w", err)
			}
			list = append(list, reading{r, ev()})
		}
		if err := errors.Join(rs.Err(), rs.Close()); err != nil {
			return fmt.Errorf("inventory: read software: %w", err)
		}
		whole := cur == sid && len(list) > 0 && !slices.ContainsFunc(list, func(x reading) bool {
			b, ok := brought(x.r.Source, x.r.Instance)
			return !ok || b.shared
		})
		if whole {
			for _, q := range []string{
				`UPDATE inv_software SET asset_id = ?1 WHERE id = ?2`,
				`UPDATE inv_software_reading SET addr_id = '' WHERE software_id = ?2`, // newID has one address: the interface split off
				`UPDATE inv_software_event SET asset_id = ?1 WHERE software_id = ?2`,  // the line's history follows it
			} {
				if _, err := tx.ExecContext(ctx, q, newID, cur); err != nil {
					return fmt.Errorf("inventory: give the software back: %w", err)
				}
			}
			continue
		}
		for _, x := range list {
			b, ok := brought(x.r.Source, x.r.Instance)
			if !ok || x.r.Addr != "" || x.r.Source == "nmap" || x.r.Source == "scan" || x.r.Instance == instanceOS {
				continue
			}
			target, err := s.lineOf(ctx, tx, newID, lineIdentity{productKey: l.key, line: l.train, vendor: vendor, product: product}, x.r)
			if err != nil {
				return err
			}
			if err := putReading(ctx, tx, target, x.r, x.ev); err != nil {
				return err
			}
			if !b.shared {
				if _, err := tx.ExecContext(ctx, `DELETE FROM inv_software_reading WHERE software_id = ? AND source = ? AND instance = ? AND addr_id = ''`,
					cur, x.r.Source, x.r.Instance); err != nil {
					return fmt.Errorf("inventory: give the software back: %w", err)
				}
			}
			touched[cur], touched[target] = true, true
		}
	}
	for _, l := range slices.Sorted(maps.Keys(touched)) {
		if _, err := s.settleLine(ctx, tx, l, now, nil); err != nil {
			return err
		}
	}
	return nil
}

// giveBack moves what a merge kept of the device back from id to the device split off as newID: its observations (one id held only
// through the merge leaves id, the others are copied), its name in Vedette, and id's own name, type and OS when the merge changed them
// and nobody changed them since; then it forgets the row (and its readings).
func giveBack(ctx context.Context, tx *sql.Tx, id, newID string, m *mergedFrom) error {
	if m == nil {
		return nil
	}
	if err := restoreKept(ctx, tx, id, m); err != nil {
		return err
	}
	for _, o := range m.facts.Obs {
		if o.Only {
			if _, err := tx.ExecContext(ctx, `DELETE FROM inv_observation WHERE asset_id = ? AND field = ? AND source = ? AND value = ?`, id, o.Field, o.Source, o.Value); err != nil {
				return fmt.Errorf("inventory: give the observations back: %w", err)
			}
		}
		if err := insertObs(ctx, tx, newID, o.Field, o.Value, o.Source, o.Confidence, o.SeenAt); err != nil {
			return err
		}
	}
	for _, sr := range m.facts.Series { // the facts were cut: what the merge brought of a series id held none of goes
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_observation WHERE asset_id = ? AND field = ? AND source = ? AND seen_at <= ?`, id, sr.Field, sr.Source, m.mergedAt); err != nil {
			return fmt.Errorf("inventory: give the observations back: %w", err)
		}
	}
	if m.userName.Valid {
		if m.facts.Kept == nil && m.facts.TookName {
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET user_name = NULL WHERE id = ? AND user_name = ?`, id, m.userName.String); err != nil {
				return fmt.Errorf("inventory: give the name back: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET user_name = ? WHERE id = ?`, m.userName.String, newID); err != nil {
			return fmt.Errorf("inventory: give the name back: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM inv_merged_from WHERE asset_id = ? AND from_id = ?`, id, m.fromID); err != nil {
		return fmt.Errorf("inventory: forget the merged device: %w", err)
	}
	return nil
}

// restoreKept gives device id its own name in Vedette, and the type and OS a person set on it, as they were before the merge, each
// when the merge changed it and it still is what the merge left (a person who renamed or retyped the device since decided again).
func restoreKept(ctx context.Context, tx *sql.Tx, id string, m *mergedFrom) error {
	k := m.facts.Kept
	if k == nil {
		return nil
	}
	cur, err := keptStateOf(ctx, tx, id)
	if err != nil {
		return err
	}
	if !sameName(k.Before.Name, k.After.Name) && sameName(cur.Name, k.After.Name) {
		if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET user_name = ? WHERE id = ?`, k.Before.Name, id); err != nil {
			return fmt.Errorf("inventory: give the name back: %w", err)
		}
	}
	for _, field := range []string{"kind", "os"} {
		before, after := k.Before.manualOf(field), k.After.manualOf(field)
		if slices.Equal(before, after) || !slices.Equal(cur.manualOf(field), after) {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_observation WHERE asset_id = ? AND source = 'manual' AND field = ?`, id, field); err != nil {
			return fmt.Errorf("inventory: give the %s back: %w", fieldWords[field], err)
		}
		for _, o := range k.Before.Manual {
			if o.Field != field {
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at, evidence, first_seen) VALUES (?, ?, ?, ?, 'manual', ?, ?, ?, ?)
				ON CONFLICT (asset_id, field, source, value) DO NOTHING`, store.NewID("o"), id, field, o.Value, o.Confidence, o.SeenAt, o.Evidence, o.FirstSeen); err != nil {
				return fmt.Errorf("inventory: give the %s back: %w", fieldWords[field], err)
			}
		}
	}
	return nil
}
