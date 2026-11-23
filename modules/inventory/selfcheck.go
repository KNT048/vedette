package inventory

import "github.com/knt048/vedette/core/selfcheck"

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
	// A line's stored value is one of its readings, and no reading of a stronger source than that value's is ignored unless a
	// person's entry holds the line (the resolver's rules 1 to 3; the tests recompute the whole rule).
	selfcheck.Register(selfcheck.Invariant{
		Name: "inventory.line_value_is_the_resolvers",
		Query: `SELECT count(*) FROM inv_software s WHERE s.state <> 'removed' AND (NOT EXISTS (SELECT 1 FROM inv_software_reading r WHERE r.software_id = s.id
			AND r.source = s.source AND ifnull(r.version, '') = ifnull(s.version, '') AND ifnull(r.pkg_version, '') = ifnull(s.pkg_version, ''))
			OR (NOT EXISTS (SELECT 1 FROM inv_software_reading m WHERE m.software_id = s.id AND m.source = 'manual') AND EXISTS (SELECT 1 FROM inv_software_reading r
				WHERE r.software_id = s.id AND r.instance <> '` + instanceOSGuess + `' AND ` + rankSQL("r.source", "r.instance") + ` > (SELECT max(` + rankSQL("e.source", "e.instance") + `)
				FROM inv_software_reading e WHERE e.software_id = s.id AND e.source = s.source AND ifnull(e.version, '') = ifnull(s.version, '')
				AND ifnull(e.pkg_version, '') = ifnull(s.pkg_version, '')))))`,
	})
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

// The train rule of a line and the newest release among equal sources need the product catalogue and the version order, which live
// in Go: the fixture tests check them on every line (lines_fixture_test.go assertResolved).

// rankSQL is readingRank in SQL for a source and instance column (guesses aside).
func rankSQL(source, instance string) string {
	return `(CASE WHEN ` + source + ` = 'manual' THEN 7 WHEN ` + source + ` IN ('osquery', 'wazuh', 'box', 'agent') THEN 6 WHEN ` + source + ` = 'snmp' THEN 5
		WHEN ` + source + ` = 'passive' AND ` + instance + ` = '` + instanceOS + `' THEN 5 WHEN ` + source + ` IN ('nmap', 'scan') THEN 3 WHEN ` + source + ` = 'passive' THEN 2 ELSE 0 END)`
}
