package inventory

import "github.com/knt048/vedette/core/selfcheck"

func init() {
	// A device's chosen reading of a field is one of that device's own observations.
	selfcheck.Register(selfcheck.Invariant{
		Name:  "inventory.chosen_observation_is_the_devices_own",
		Query: `SELECT count(*) FROM (SELECT a.id FROM inv_asset a WHERE a.kind_obs_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inv_observation o WHERE o.id = a.kind_obs_id AND o.asset_id = a.id) UNION ALL SELECT a.id FROM inv_asset a WHERE a.hostname_obs_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inv_observation o WHERE o.id = a.hostname_obs_id AND o.asset_id = a.id) UNION ALL SELECT a.id FROM inv_asset a WHERE a.mac_obs_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inv_observation o WHERE o.id = a.mac_obs_id AND o.asset_id = a.id) UNION ALL SELECT a.id FROM inv_asset a WHERE a.vendor_obs_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inv_observation o WHERE o.id = a.vendor_obs_id AND o.asset_id = a.id) UNION ALL SELECT a.id FROM inv_asset a WHERE a.model_obs_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inv_observation o WHERE o.id = a.model_obs_id AND o.asset_id = a.id) UNION ALL SELECT a.id FROM inv_asset a WHERE a.os_obs_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inv_observation o WHERE o.id = a.os_obs_id AND o.asset_id = a.id))`,
	})
}
