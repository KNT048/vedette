package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/core/selfcheck"
)

func init() {
	// A device's chosen reading of a field is one of that device's own observations.
	selfcheck.Register(selfcheck.Invariant{
		Name:  "inventory.chosen_observation_is_the_devices_own",
		Query: `SELECT count(*) FROM (SELECT a.id FROM inv_asset a WHERE a.kind_obs_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inv_observation o WHERE o.id = a.kind_obs_id AND o.asset_id = a.id) UNION ALL SELECT a.id FROM inv_asset a WHERE a.hostname_obs_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inv_observation o WHERE o.id = a.hostname_obs_id AND o.asset_id = a.id) UNION ALL SELECT a.id FROM inv_asset a WHERE a.mac_obs_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inv_observation o WHERE o.id = a.mac_obs_id AND o.asset_id = a.id) UNION ALL SELECT a.id FROM inv_asset a WHERE a.vendor_obs_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inv_observation o WHERE o.id = a.vendor_obs_id AND o.asset_id = a.id) UNION ALL SELECT a.id FROM inv_asset a WHERE a.model_obs_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inv_observation o WHERE o.id = a.model_obs_id AND o.asset_id = a.id) UNION ALL SELECT a.id FROM inv_asset a WHERE a.os_obs_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inv_observation o WHERE o.id = a.os_obs_id AND o.asset_id = a.id))`,
	})
	// One software line per device, product and release train.
	selfcheck.Register(selfcheck.Invariant{
		Name:  "inventory.one_line_per_product_and_train",
		Query: `SELECT count(*) FROM (SELECT 1 FROM inv_software GROUP BY asset_id, product_key, line HAVING count(*) > 1)`,
	})
	// A line's stored value, state and "differs" flag are what Resolve says of its readings (the whole resolver rule, INV-52).
	selfcheck.Register(selfcheck.Invariant{Name: "inventory.line_value_is_the_resolvers", Count: countLines(storedLine.resolveBreak)})
	// Every reading of a line with a release is of the line's train (the catalogue's train rule): a reading of another train is a
	// line of its own.
	selfcheck.Register(selfcheck.Invariant{Name: "inventory.line_is_the_train_of_its_readings", Count: countLines(storedLine.trainBreak)})
	// A line's state agrees with its readings: a removed line has none, a line in use has one (a source's or a person's entry).
	selfcheck.Register(selfcheck.Invariant{
		Name:  "inventory.removed_line_has_no_reading",
		Query: `SELECT count(*) FROM inv_software s WHERE s.state = 'removed' AND EXISTS (SELECT 1 FROM inv_software_reading r WHERE r.software_id = s.id)`,
	})
	// An address has one home (INV-57): an IP or a MAC is the main address of one device or one row of inv_asset_address, never both or
	// two of them; and what a scan read at an address row points at a row of the same device.
	selfcheck.Register(selfcheck.Invariant{
		Name: "inventory.address_has_one_home",
		Query: `SELECT (SELECT count(*) FROM (SELECT v FROM (SELECT ip AS v FROM inv_asset WHERE ip IS NOT NULL UNION ALL SELECT ip FROM inv_asset_address WHERE ip IS NOT NULL
			UNION ALL SELECT mac FROM inv_asset WHERE mac IS NOT NULL UNION ALL SELECT mac FROM inv_asset_address WHERE mac IS NOT NULL) GROUP BY v HAVING count(*) > 1))
			+ (SELECT count(*) FROM inv_software_reading r JOIN inv_software w ON w.id = r.software_id WHERE r.addr_id <> ''
				AND NOT EXISTS (SELECT 1 FROM inv_asset_address x WHERE x.id = r.addr_id AND x.asset_id = w.asset_id))
			+ (SELECT count(*) FROM inv_service s WHERE s.addr_id <> '' AND NOT EXISTS (SELECT 1 FROM inv_asset_address x WHERE x.id = s.addr_id AND x.asset_id = s.asset_id))`,
	})
	// A present line has a reading (a source's or a person's entry).
	selfcheck.Register(selfcheck.Invariant{
		Name:  "inventory.present_line_has_a_reading",
		Query: `SELECT count(*) FROM inv_software s WHERE s.state = 'present' AND NOT EXISTS (SELECT 1 FROM inv_software_reading r WHERE r.software_id = s.id)`,
	})
}

// storedLine is a software line as stored, with its readings: what the line rules are checked on.
type storedLine struct {
	id, state, marked, source, version, pkg, key, line string
	differs                                            bool
	readings                                           []Reading
}

// resolveBreak says how a line that is not removed differs from what Resolve says of its readings; "" when it agrees. A removed
// line has no reading (inventory.removed_line_has_no_reading) and keeps the value it had.
func (l storedLine) resolveBreak() string {
	if l.state == stateRemoved {
		return ""
	}
	res := Resolve(LineState{State: l.state, NotInstalledAt: l.marked}, l.readings)
	if res.Lapsed == nil && res.State == l.state && res.Effective.Source == l.source && res.Effective.Version == l.version &&
		res.Effective.PkgVersion == l.pkg && res.Differs == l.differs {
		return ""
	}
	return fmt.Sprintf("line %s stores %s %s %q %q differs %v, the resolver says %s %s %q %q differs %v (an entry lapsed: %v)", l.id, l.state, l.source,
		l.version, l.pkg, l.differs, res.State, res.Effective.Source, res.Effective.Version, res.Effective.PkgVersion, res.Differs, res.Lapsed != nil)
}

// trainBreak says which reading of a line is of another release train than the line; "" when every reading with a release is of
// the line's train.
func (l storedLine) trainBreak() string {
	for _, rd := range l.readings {
		if rd.Version != "" && trainOf(l.key, rd.Version) != l.line {
			return fmt.Sprintf("line %s is train %q, its %s reading %q is train %q", l.id, l.line, rd.Source, rd.Version, trainOf(l.key, rd.Version))
		}
	}
	return ""
}

// countLines is a selfcheck count: the software lines check says break.
func countLines(check func(storedLine) string) func(context.Context, *sql.DB) (int64, error) {
	return func(ctx context.Context, db *sql.DB) (int64, error) {
		var n int64
		err := eachStoredLine(ctx, db, func(l storedLine) {
			if check(l) != "" {
				n++
			}
		})
		return n, err
	}
}

// storedLinesPage is how many lines eachStoredLine holds in memory at once.
const storedLinesPage = 500

// eachStoredLine calls fn for every software line with its readings, in id order, from one read transaction (a consistent snapshot),
// a page of lines at a time. It only reads, so it runs on the selfcheck's read-only handle.
func eachStoredLine(ctx context.Context, db *sql.DB, fn func(storedLine)) error {
	return eachStoredLineBy(ctx, db, storedLinesPage, fn)
}

// eachStoredLineBy is eachStoredLine with pages of size lines.
func eachStoredLineBy(ctx context.Context, db *sql.DB, size int, fn func(storedLine)) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("inventory: check software lines: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	after := ""
	for {
		page, err := storedLinePage(ctx, tx, after, size)
		if err != nil || len(page) == 0 {
			return err
		}
		for _, l := range page {
			fn(l)
		}
		after = page[len(page)-1].id
	}
}

// storedLinePage reads the next page of at most size lines after id after, with their readings.
func storedLinePage(ctx context.Context, tx *sql.Tx, after string, size int) ([]storedLine, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, state, ifnull(not_installed_at, ''), source, ifnull(version, ''), ifnull(pkg_version, ''), differs <> 0,
		product_key, line FROM inv_software WHERE id > ? ORDER BY id LIMIT ?`, after, size)
	if err != nil {
		return nil, fmt.Errorf("inventory: check software lines: %w", err)
	}
	var page []storedLine
	at := map[string]int{}
	for rows.Next() {
		var l storedLine
		if err := rows.Scan(&l.id, &l.state, &l.marked, &l.source, &l.version, &l.pkg, &l.differs, &l.key, &l.line); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("inventory: check software lines: %w", err)
		}
		at[l.id] = len(page)
		page = append(page, l)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("inventory: check software lines: %w", err)
	}
	if len(page) == 0 {
		return nil, nil
	}
	ids := make([]string, len(page))
	for i, l := range page {
		ids[i] = l.id
	}
	list, err := json.Marshal(ids)
	if err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT `+readingCols+`, r.software_id FROM inv_software_reading r WHERE r.software_id IN (SELECT value FROM json_each(?))
		ORDER BY r.software_id, r.source, r.instance, r.addr_id`, string(list))
	if err != nil {
		return nil, fmt.Errorf("inventory: check software readings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		r, err := scanReading(rows, &id)
		if err != nil {
			return nil, fmt.Errorf("inventory: check software readings: %w", err)
		}
		page[at[id]].readings = append(page[at[id]].readings, r)
	}
	return page, rows.Err()
}
