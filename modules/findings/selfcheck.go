package findings

import (
	"context"
	"database/sql"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/productid"

	"github.com/knt048/vedette/core/selfcheck"
)

// The data invariants of the findings model (`vedette selfcheck`): each query counts the rows that break the rule.
var invariants = []selfcheck.Invariant{
	{ // open exactly when there is no resolution; every handled row says how, by whom and when
		Name: "findings.handled_complete",
		Query: `SELECT count(*) FROM fnd_finding WHERE (state = 'open') <> (resolution IS NULL)
			OR state = 'handled' AND (via IS NULL OR resolved_by IS NULL OR resolved_at IS NULL)`,
	},
	{ // open means detected: an open finding the latest match no longer detects would show the advice of a reading the device moved past
		Name:  "findings.open_is_detected",
		Query: `SELECT count(*) FROM fnd_finding WHERE state = 'open' AND detected = 0`,
	},
	{ // patch credit for a version move names two different versions
		Name: "findings.version_moved_versions",
		Query: `SELECT count(*) FROM fnd_finding WHERE via = 'version_moved'
			AND (ifnull(from_version, '') = '' OR ifnull(to_version, '') = '' OR from_version = to_version)`,
	},
	{ // the "By fix" group of a finding names its stored fix: fix_key is FixKey of the line's product and the stored fix kind, version
		// and channel when not public (a key clipped at its 400-byte limit is left out)
		Name: "findings.fix_key_names_stored_fix",
		Query: `SELECT count(*) FROM fnd_finding WHERE length(CAST(fix_key AS BLOB)) < 400
			AND substr(fix_key, -length(` + fixTailSQL + `)) <> ` + fixTailSQL,
	},
	{ // every stored value of an open vocabulary is one the Go type knows
		Name: "findings.vocabulary",
		Query: `SELECT count(*) FROM fnd_finding WHERE basis NOT IN (` + quoted(DetectionBases) + `)
			OR ifnull(via, 'person') NOT IN (` + quoted(Vias) + `)
			OR fix_kind NOT IN (` + quoted(knownFixKinds) + `)
			OR fix_channel NOT IN (` + quoted(FixChannels) + `)`,
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

// fixTailSQL is the end of a stored fix_key that names the row's fix (FixKey).
const fixTailSQL = `('|' || fix_kind || '|' || ifnull(fix_version, '') || CASE fix_channel WHEN 'public' THEN '' ELSE '|' || fix_channel END)`

// catalogueInvariants hold between the findings and feeds' catalogue (and inventory's software lines): they read other modules'
// tables, so they run on a box's whole database.
var catalogueInvariants = []selfcheck.Invariant{
	{ // a detected finding names a version its software line runs: the line's effective reading or one of its live readings (a
		// version or a package release), never a version of another line (a safe check's and a person's word name no version of theirs).
		// An ignored device writes nothing (POST-1; INV-30 lists its findings only under Ignored): its findings keep the version they
		// were matched on while its agent may still report newer ones, and unignoring it matches it again at once, so it is left out here.
		Name: "findings.matched_version_on_line",
		Query: `SELECT count(*) FROM fnd_finding f WHERE f.state = 'open' AND f.detected = 1 AND f.software_id IS NOT NULL
			AND ifnull(f.matched_version, '') <> '' AND f.basis NOT IN ('scan', 'person')
			AND NOT EXISTS (SELECT 1 FROM inv_asset a WHERE a.id = f.asset_id AND a.ignored_at IS NOT NULL)
			AND NOT EXISTS (SELECT 1 FROM inv_software s WHERE s.id = f.software_id AND f.matched_version IN (ifnull(s.version, ''), ifnull(s.pkg_version, '')))
			AND NOT EXISTS (SELECT 1 FROM inv_software_reading r WHERE r.software_id = f.software_id AND f.matched_version IN (ifnull(r.version, ''), ifnull(r.pkg_version, '')))`,
	},
	{ // a finding and a question name a software line of their own device: a split moved them with the line inside its write
		// (DeviceSplit, followLines as the safety net), a merge moved them with the device (DeviceMerged)
		Name: "findings.line_on_its_device",
		Query: `SELECT (SELECT count(*) FROM fnd_finding f JOIN inv_software s ON s.id = f.software_id WHERE s.asset_id <> f.asset_id)
			+ (SELECT count(*) FROM fnd_question q JOIN inv_software s ON s.id = q.software_id WHERE s.asset_id <> q.asset_id)`,
	},
	{ // every finding's CVE is in the catalogue (the catalogue keeps a finding's CVE whatever its age)
		Name:  "findings.cve_in_catalogue",
		Query: `SELECT count(*) FROM fnd_finding f WHERE NOT EXISTS (SELECT 1 FROM feeds_cve c WHERE c.cve = f.cve)`,
	},
	{ // every catalogue CVE published before the reporting window has an exploited-list entry, an exploited signal, a public exploit
		// that appeared inside the window (Exploit-DB's and a proof of concept's date; for another source the day the box first stored it,
		// once the box has held that source since before the window) or a finding, unless every age is reported (feeds window.go; a day
		// of slack for the prune of the pull job)
		Name: "findings.catalogue_retention",
		Query: `SELECT count(*) FROM feeds_cve c WHERE c.published < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-366 days')
			AND NOT EXISTS (SELECT 1 FROM core_setting w WHERE w.key = 'feeds.cve_window' AND json_extract(w.value, '$.every_age') = 1)
			AND NOT EXISTS (SELECT 1 FROM feeds_kev k WHERE k.cve = c.cve)
			AND NOT EXISTS (SELECT 1 FROM feeds_signal s WHERE s.cve = c.cve AND s.qualifies = 1 AND (s.kind = 'exploited'
				OR s.source IN ('exploit-db', 'poc-in-github') AND s.first_seen >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-366 days')
				OR s.source NOT IN ('exploit-db', 'poc-in-github') AND s.stored_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-366 days')
					AND (SELECT min(o.stored_at) FROM feeds_signal o WHERE o.source = s.source) < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-365 days')))
			AND NOT EXISTS (SELECT 1 FROM fnd_finding f WHERE f.cve = c.cve)`,
	},
	{ // range precedence: a finding the data detects through a CVE record's ranges rests on rows of that origin the catalogue holds for
		// its CVE, and never on an ADP's while NVD has ranges (the CNA's rows are read beside NVD's, an ADP's are not: feeds matchRows),
		// unless its line's product has a version scheme: the vendor's own rows decide its trains (vendorscheme.go). The product is
		// resolved as the matcher resolves it (productid.ResolveStored of the line), so a line named otherwise (nmap's "netscaler
		// gateway") counts too.
		Name:  "findings.range_precedence",
		Count: rangePrecedenceBreaks,
	},
}

// rangePrecedenceBreaks counts the detected findings that rest on a CVE record's ranges the catalogue does not hold for the CVE (no
// row of that origin), or on an ADP's while NVD has ranges for the CVE, leaving out those whose software line is a product with a
// version scheme (schemedSpans resolves it the same way).
func rangePrecedenceBreaks(ctx context.Context, db *sql.DB) (int64, error) {
	rows, err := db.QueryContext(ctx, `SELECT s.vendor, s.product, s.display, ifnull(s.cpe, ''), s.id IS NOT NULL FROM fnd_finding f
		LEFT JOIN inv_software s ON s.id = f.software_id
		WHERE f.detected = 1 AND f.range_origin IN ('cna', 'adp')
		AND (NOT EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = f.cve AND r.origin = f.range_origin)
			OR f.range_origin = 'adp' AND EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = f.cve AND r.origin = 'nvd'))`)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	var n int64
	for rows.Next() {
		var vendor, product, display, cpe sql.NullString
		var line bool
		if err := rows.Scan(&vendor, &product, &display, &cpe, &line); err != nil {
			return 0, err
		}
		if p, ok := productid.ResolveStored(vendor.String, product.String, display.String, cpe.String); line && ok && p.Scheme != "" {
			continue
		}
		n++
	}
	return n, rows.Err()
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
