package feeds

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// The Feeds page shows each feed's count with the note of its last pull. For most feeds the count says itself (entries of a list,
// indicators, scores). For the feeds below it does not: it can be 0 on a healthy box, or it counts something other than what the
// name suggests (CVEs with versions, package rows, Windows releases). Their note starts with what the feed holds, read from the
// stored data in the pull's last transaction, so every good pull says it: one that read nothing new (an unchanged file, no record
// due) too, which before left the row with a bare count.

// heldNotes says, for each built-in feed whose count needs words, what it holds now. TestHeldNotes_EveryBuiltinFeedIsDecided keeps
// every built-in feed decided: here, or in the test's list of feeds whose count says itself.
var heldNotes = map[string]func(context.Context, *sql.Tx) (string, error){
	"first-epss":        heldKEVScores,
	nvdFeedID:           heldNVD,
	cveOrgFeedID:        heldCVEOrg,
	ubuntuOSVFeedID:     heldDistro(ubuntuOSVFeedID),
	ubuntuVEXFeedID:     heldDistro(ubuntuVEXFeedID),
	debianTrackerFeedID: heldDistro(debianTrackerFeedID),
	alpineOSVFeedID:     heldDistro(alpineOSVFeedID),
	winRelFeedID:        heldWinRel,
}

// withHeld puts what feed id holds in front of the pull's own note; "" for a feed whose count says itself.
func withHeld(ctx context.Context, tx *sql.Tx, id, note string) (string, error) {
	f := heldNotes[id]
	if f == nil {
		return note, nil
	}
	held, err := f(ctx, tx)
	if err != nil {
		return "", fmt.Errorf("feeds: what %s holds: %w", id, err)
	}
	return strings.TrimSpace(held + " " + note), nil
}

// kevSet is the CVEs of the exploited lists (the CISA list, and VulnCheck KEV when its key is set), as SQL.
const kevSet = `SELECT cve FROM feeds_vuln WHERE source_id IN ('cisa-kev', 'vulncheck-kev')`

func counts(ctx context.Context, tx *sql.Tx, q string, args []any, into ...any) error {
	return tx.QueryRowContext(ctx, q, args...).Scan(into...)
}

// cves is "1 exploited CVE" or "41 exploited CVEs".
func cves(n int, what string) string {
	if n == 1 {
		return "1 " + what + " CVE"
	}
	return grouped(n) + " " + what + " CVEs"
}

func heldKEVScores(ctx context.Context, tx *sql.Tx) (string, error) {
	var kev, scored int
	if err := counts(ctx, tx, `SELECT count(*), count(epss) FROM feeds_vuln WHERE source_id = 'cisa-kev'`, nil, &kev, &scored); err != nil {
		return "", err
	}
	if kev == 0 {
		return "No score yet: the exploited CVEs are scored once the CISA list is on the box.", nil
	}
	return fmt.Sprintf("Scores of %s of the %s on the CISA list, today's and a week ago's.", grouped(scored), cves(kev, "exploited")), nil
}

func heldNVD(ctx context.Context, tx *sql.Tx) (string, error) {
	var all, ranged int
	if err := counts(ctx, tx, `SELECT count(*), count(*) FILTER (WHERE EXISTS (SELECT 1 FROM feeds_affected r WHERE r.cve = a.cve))
FROM feeds_affected_cve a WHERE a.source = 'nvd'`, nil, &all, &ranged); err != nil {
		return "", err
	}
	if all == 0 {
		return "", nil // not loaded yet: the row says so
	}
	return fmt.Sprintf("NVD records of %s; %s of them name affected versions.", cves(all, "exploited"), grouped(ranged)), nil
}

// heldCVEOrg: CVE.org is read only for the exploited CVEs NVD gives no affected versions for, so 0 is a healthy count when NVD has
// versions for every one, or when the records of the others name none Vedette can compare.
func heldCVEOrg(ctx context.Context, tx *sql.Tx) (string, error) {
	var gap, read, held int
	noNVD := `FROM (SELECT DISTINCT cve FROM feeds_vuln WHERE source_id IN ('cisa-kev', 'vulncheck-kev')) v
WHERE NOT EXISTS (SELECT 1 FROM feeds_affected_cve a WHERE a.cve = v.cve AND a.source = 'nvd' AND EXISTS (SELECT 1 FROM feeds_affected r WHERE r.cve = v.cve))`
	if err := counts(ctx, tx, `SELECT count(*), count(*) FILTER (WHERE EXISTS (SELECT 1 FROM feeds_cveorg_checked c WHERE c.cve = v.cve)) `+noNVD, nil, &gap, &read); err != nil {
		return "", err
	}
	if err := counts(ctx, tx, `SELECT count(*) FROM feeds_affected_cve WHERE source <> 'nvd'`, nil, &held); err != nil {
		return "", err
	}
	unread, none := max(gap-read, 0), max(read-held, 0)
	verb := "have"
	if gap == 1 {
		verb = "has"
	}
	switch {
	case gap == 0:
		return "Read only for exploited CVEs NVD gives no affected versions for, and NVD gives them for every one now.", nil
	case held == 0 && unread == 0:
		return fmt.Sprintf("%s %s no affected versions from NVD, and CVE.org gives none Vedette can compare for them either; each is asked again every 12 hours.",
			cves(gap, "exploited"), verb), nil
	}
	var parts []string
	switch {
	case held > 0 && none > 0:
		parts = append(parts, fmt.Sprintf("CVE.org gives versions Vedette can compare for %s of them, none for %s", grouped(held), grouped(none)))
	case held > 0:
		parts = append(parts, fmt.Sprintf("CVE.org gives versions Vedette can compare for %s of them", grouped(held)))
	case none > 0:
		parts = append(parts, fmt.Sprintf("CVE.org gives none Vedette can compare for %s", grouped(none)))
	}
	if unread > 0 {
		parts = append(parts, fmt.Sprintf("%s not read from CVE.org yet", grouped(unread)))
	}
	return fmt.Sprintf("%s %s no affected versions from NVD; %s.", cves(gap, "exploited"), verb, strings.Join(parts, ", ")), nil
}

// heldDistro: a distribution feed counts one row per package, release and CVE, not CVEs.
func heldDistro(id string) func(context.Context, *sql.Tx) (string, error) {
	return func(ctx context.Context, tx *sql.Tx) (string, error) {
		var rows, kev, other int
		if err := counts(ctx, tx, `SELECT count(*), count(DISTINCT CASE WHEN cve IN (`+kevSet+`) THEN cve END), count(DISTINCT CASE WHEN cve NOT IN (`+kevSet+`) THEN cve END)
FROM feeds_distro_fix WHERE source_id = ?`, []any{id}, &rows, &kev, &other); err != nil {
			return "", err
		}
		if rows == 0 {
			return "", nil
		}
		t := "Counts one record per package, release and CVE: " + cves(kev, "exploited")
		if other > 0 {
			t += fmt.Sprintf(" and %s of the packages your devices run", cves(other, "other"))
		}
		return t + ".", nil
	}
}

func heldWinRel(ctx context.Context, tx *sql.Tx) (string, error) {
	var rels, ups int
	var newest sql.NullString
	if err := counts(ctx, tx, `SELECT (SELECT count(*) FROM feeds_winrel), (SELECT count(*) FROM feeds_winrel_update), (SELECT max(day) FROM feeds_winrel_update)`, nil,
		&rels, &ups, &newest); err != nil {
		return "", err
	}
	if rels == 0 {
		return "", nil
	}
	what := "Windows releases"
	if rels == 1 {
		what = "Windows release"
	}
	t := fmt.Sprintf("%s %s on Microsoft's release information pages", grouped(rels), what)
	if d, err := time.Parse(time.DateOnly, newest.String); err == nil && ups > 0 {
		t += fmt.Sprintf(", with %s monthly updates, the newest of %s", grouped(ups), d.Format("2 Jan 2006"))
	}
	return t + ".", nil
}
