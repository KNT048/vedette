package findings

import "github.com/knt048/vedette/core/selfcheck"

func init() {
	// findings keeps its own tables free of foreign keys to the device table, so nothing else stops a finding or a plan mark
	// from pointing at a device that no longer exists.
	selfcheck.Register(selfcheck.Invariant{
		Name:  "findings.finding_device_exists",
		Query: `SELECT count(*) FROM fnd_finding WHERE asset_id NOT IN (SELECT id FROM inv_asset)`,
	})
	selfcheck.Register(selfcheck.Invariant{
		Name:  "findings.plan_mark_device_exists",
		Query: `SELECT count(*) FROM fnd_plan_done WHERE asset_id NOT IN (SELECT id FROM inv_asset)`,
	})
}
