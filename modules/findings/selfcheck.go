package findings

import (
	"slices"
	"strings"

	"github.com/knt048/vedette/core/selfcheck"
)

// The data invariants of the findings model (`vedette selfcheck`): each query counts the rows that break the rule.
var invariants = []selfcheck.Invariant{
	{ // open exactly when there is no resolution; every handled row says how, by whom and when
		Name: "findings.handled_complete",
		Query: `SELECT count(*) FROM fnd_finding WHERE (state = 'open') <> (resolution IS NULL)
			OR state = 'handled' AND (via IS NULL OR resolved_by IS NULL OR resolved_at IS NULL)`,
	},
	{ // patch credit for a version move names two different versions
		Name: "findings.version_moved_versions",
		Query: `SELECT count(*) FROM fnd_finding WHERE via = 'version_moved'
			AND (ifnull(from_version, '') = '' OR ifnull(to_version, '') = '' OR from_version = to_version)`,
	},
	{ // open findings total = the sum over devices = the sum over fixes
		Name: "findings.open_sums_agree",
		Query: `SELECT abs(t.n - (SELECT ifnull(sum(n), 0) FROM (SELECT count(*) AS n FROM fnd_finding WHERE state = 'open' GROUP BY asset_id)))
			+ abs(t.n - (SELECT ifnull(sum(n), 0) FROM (SELECT count(*) AS n FROM fnd_finding WHERE state = 'open' GROUP BY fix_key)))
			FROM (SELECT count(*) AS n FROM fnd_finding WHERE state = 'open') t`,
	},
	{ // every stored value of an open vocabulary is one the Go type knows
		Name: "findings.vocabulary",
		Query: `SELECT count(*) FROM fnd_finding WHERE basis NOT IN (` + quoted(DetectionBases) + `)
			OR ifnull(via, 'person') NOT IN (` + quoted(Vias) + `)
			OR fix_kind NOT IN (` + quoted([]FixKind{FixUpdate, FixDistroUpdate, FixOSUpdate, FixFeatureUpdate, FixNoneYet, FixUnknown}) + `)`,
	},
	{
		Name:  "findings.event_vocabulary",
		Query: `SELECT count(*) FROM fnd_finding_event WHERE kind NOT IN (` + quoted(EventKinds) + `)`,
	},
	{
		Name:  "findings.question_vocabulary",
		Query: `SELECT count(*) FROM fnd_question WHERE kind NOT IN (` + quoted(QuestionKinds) + `)`,
	},
}

// catalogueInvariants hold between the findings and feeds' catalogue: they read feeds' tables, so they run on a box's whole database.
var catalogueInvariants = []selfcheck.Invariant{
	{ // every finding's CVE is in the catalogue (the catalogue keeps a finding's CVE whatever its age)
		Name:  "findings.cve_in_catalogue",
		Query: `SELECT count(*) FROM fnd_finding f WHERE NOT EXISTS (SELECT 1 FROM feeds_cve c WHERE c.cve = f.cve)`,
	},
	{ // every catalogue CVE published before the window has an exploited-list entry, a qualifying signal or a finding
		Name: "findings.catalogue_retention",
		Query: `SELECT count(*) FROM feeds_cve c WHERE c.published < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-366 days')
			AND NOT EXISTS (SELECT 1 FROM feeds_kev k WHERE k.cve = c.cve)
			AND NOT EXISTS (SELECT 1 FROM feeds_signal s WHERE s.cve = c.cve AND s.qualifies = 1)
			AND NOT EXISTS (SELECT 1 FROM fnd_finding f WHERE f.cve = c.cve)`,
	},
	{ // range precedence: a finding the data detects through the CVE record's ranges has a CVE NVD gives no ranges for
		Name: "findings.range_precedence",
		Query: `SELECT count(*) FROM fnd_finding f WHERE f.detected = 1 AND f.range_origin IN ('cna', 'adp')
			AND EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = f.cve AND r.origin = 'nvd')`,
	},
}

func init() {
	for _, inv := range append(slices.Clone(invariants), catalogueInvariants...) {
		selfcheck.Register(inv)
	}
}

// quoted is a SQL list of the values ('a', 'b').
func quoted[T ~string](vs []T) string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = "'" + string(v) + "'"
	}
	return strings.Join(out, ", ")
}
