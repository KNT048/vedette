package exposure

import (
	"context"
	"database/sql"

	"github.com/knt048/vedette/core/selfcheck"
)

// The rules of the rows the scan writer keeps; each query counts the rows that break one.
func init() {
	// An open service is on an address of its target: the IP target itself, or an address of one of its names.
	selfcheck.Register(selfcheck.Invariant{
		Name: "exposure.open_service_on_an_address_of_its_target",
		Query: `SELECT count(*) FROM exp_service s WHERE s.state = 'open'
			AND NOT EXISTS (SELECT 1 FROM exp_address a WHERE a.target_id = s.target_id AND a.ip = s.ip)`,
	})
	// An issue about a service is about a service of its own target.
	selfcheck.Register(selfcheck.Invariant{
		Name:  "exposure.issue_on_a_service_of_its_target",
		Query: `SELECT count(*) FROM exp_issue i JOIN exp_service s ON s.id = i.service_id WHERE s.target_id <> i.target_id`,
	})
	// A target has at most one scan queued, waiting or running.
	selfcheck.Register(selfcheck.Invariant{
		Name: "exposure.one_active_scan_per_target",
		Query: `SELECT count(*) FROM (SELECT x.target_id FROM exp_scan x JOIN core_run r ON r.id = x.run_id
			WHERE r.status IN ('queued', 'waiting', 'running', 'stopping') GROUP BY x.target_id HAVING count(*) > 1)`,
	})
	// A name's address belongs to the same target as the name.
	selfcheck.Register(selfcheck.Invariant{
		Name:  "exposure.address_of_a_name_of_its_target",
		Query: `SELECT count(*) FROM exp_address a JOIN exp_host h ON h.id = a.host_id WHERE h.target_id <> a.target_id`,
	})
	// An issue a person handled says how, by whom and when; one that is not handled says none of it.
	selfcheck.Register(selfcheck.Invariant{
		Name: "exposure.handled_issue_says_how",
		Query: `SELECT count(*) FROM exp_issue WHERE (state = 'handled') <> (resolution IS NOT NULL AND resolved_by IS NOT NULL AND resolved_at IS NOT NULL)
			OR (state <> 'handled' AND (resolved_by IS NOT NULL OR resolved_at IS NOT NULL OR accepted_until IS NOT NULL))`,
	})
	// A domain target that is a name under another domain target sits under it in the tree (the other is among its ancestors).
	selfcheck.Register(selfcheck.Invariant{
		Name:  "exposure.subdomain_target_under_its_parent",
		Count: func(ctx context.Context, db *sql.DB) (int64, error) { return unplacedPairs(ctx, db) },
	})
	// No name is scanned by two enabled targets: a child scans its own names and its parent skips them.
	selfcheck.Register(selfcheck.Invariant{
		Name:  "exposure.name_scanned_by_one_target",
		Count: func(ctx context.Context, db *sql.DB) (int64, error) { return doubleScanned(ctx, db) },
	})
}
