package findings

import (
	"strings"

	"github.com/knt048/vedette/core/selfcheck"
)

// The data invariants of the findings model (`vedette selfcheck`): each query counts the rows that break the rule.
var invariants = []selfcheck.Invariant{
	{ // D4: open exactly when there is no resolution; every handled row says how, by whom and when
		Name: "findings.handled_complete",
		Query: `SELECT count(*) FROM fnd_finding WHERE (state = 'open') <> (resolution IS NULL)
			OR state = 'handled' AND (via IS NULL OR resolved_by IS NULL OR resolved_at IS NULL)`,
	},
	{ // D5: patch credit for a version move names two different versions
		Name: "findings.version_moved_versions",
		Query: `SELECT count(*) FROM fnd_finding WHERE via = 'version_moved'
			AND (ifnull(from_version, '') = '' OR ifnull(to_version, '') = '' OR from_version = to_version)`,
	},
	{ // D7: open findings total = the sum over devices = the sum over fixes
		Name: "findings.open_sums_agree",
		Query: `SELECT abs(t.n - (SELECT ifnull(sum(n), 0) FROM (SELECT count(*) AS n FROM fnd_finding WHERE state = 'open' GROUP BY asset_id)))
			+ abs(t.n - (SELECT ifnull(sum(n), 0) FROM (SELECT count(*) AS n FROM fnd_finding WHERE state = 'open' GROUP BY fix_key)))
			FROM (SELECT count(*) AS n FROM fnd_finding WHERE state = 'open') t`,
	},
	{ // rule 6: every stored value of an open vocabulary is one the Go type knows
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

func init() {
	for _, inv := range invariants {
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
