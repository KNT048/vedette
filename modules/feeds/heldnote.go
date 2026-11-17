package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/orgtime"
)

// The Feeds page shows each feed's count with a note. For most feeds the count says itself (entries of a list, indicators,
// scores). For the feeds below it does not: it can be 0 on a healthy box, or it counts something other than what the name
// suggests (CVEs with versions, package rows, Windows releases). Their note starts with what the feed holds, counted from the
// stored data when the row is read (Service.live), then the last pull's own sentence (rows rejected, records read). Counted when
// read, the sentence is right whenever the page is read: after an update, before the feed's next pull; and after another feed
// changed what it counts (the CISA list grew, NVD gave versions), which a sentence stored by the feed's own pull would miss.

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

// heldFrom names, for each feed of heldNotes, the feeds whose data its sentence counts. That data is written only by a pull of one
// of them (in the transaction that records the pull) or by an edit of one of them (a key removed), so their last_fetch and rev
// change with it: they key the sentence counted last (heldNow). TestHeldNotes_FollowTheData checks every feed.
var heldFrom = map[string][]string{
	"first-epss":        {"first-epss", kevFeedID},
	nvdFeedID:           {nvdFeedID},
	cveOrgFeedID:        {cveOrgFeedID, nvdFeedID, kevFeedID, vulnCheckFeedID},
	ubuntuOSVFeedID:     {ubuntuOSVFeedID, kevFeedID, vulnCheckFeedID},
	ubuntuVEXFeedID:     {ubuntuVEXFeedID, kevFeedID, vulnCheckFeedID},
	debianTrackerFeedID: {debianTrackerFeedID, kevFeedID, vulnCheckFeedID},
	alpineOSVFeedID:     {alpineOSVFeedID, kevFeedID, vulnCheckFeedID},
	winRelFeedID:        {winRelFeedID},
}

// heldCache keeps each feed's sentence with the key it was counted under: a distribution feed's count reads every row of the feed
// (about 0.1 s for 100,000 rows), and the list of feeds is read by Settings and by the findings page.
type heldCache struct {
	mu   sync.Mutex
	held map[string]heldEntry
}

type heldEntry struct{ key, note string }

// heldNow is what feed id holds now: "" for a feed whose count says itself, or when the count fails (logged; the row keeps its
// pull's own note). It is counted again once a feed of heldFrom[id] pulled or was edited.
func (s *Service) heldNow(ctx context.Context, id string) string {
	f := heldNotes[id]
	if f == nil {
		return ""
	}
	s.held.mu.Lock()
	defer s.held.mu.Unlock()
	note, err := func() (string, error) {
		tx, err := s.DB.Reader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return "", err
		}
		defer func() { _ = tx.Rollback() }()
		key, err := heldKey(ctx, tx, id)
		if err != nil {
			return "", err
		}
		if e, ok := s.held.held[id]; ok && e.key == key {
			return e.note, nil
		}
		note, err := f(ctx, tx)
		if err != nil {
			return "", err
		}
		if s.held.held == nil {
			s.held.held = map[string]heldEntry{}
		}
		s.held.held[id] = heldEntry{key, note}
		return note, nil
	}()
	if err != nil {
		if ctx.Err() == nil {
			s.Log.ErrorContext(ctx, "feeds: what the feed holds could not be counted", "feed", id, "error", err)
		}
		return ""
	}
	return note
}

// heldKey is the last pull and the edit count of each feed of heldFrom[id], read in the transaction that counts.
func heldKey(ctx context.Context, tx *sql.Tx, id string) (string, error) {
	from, err := json.Marshal(heldFrom[id])
	if err != nil {
		return "", fmt.Errorf("feeds: held key: %w", err)
	}
	var key sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT group_concat(k, ' ') FROM (SELECT id || '@' || coalesce(last_fetch, '') || '#' || rev AS k
FROM feeds_source WHERE id IN (SELECT value FROM json_each(?)) ORDER BY id)`, string(from)).Scan(&key); err != nil {
		return "", fmt.Errorf("feeds: held key: %w", err)
	}
	return key.String, nil
}

// withHeld puts what a feed holds in front of a note.
func withHeld(held, note string) string { return strings.TrimSpace(held + " " + note) }

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
	var kev, gap, read, held int
	if err := counts(ctx, tx, `SELECT count(*) FROM (`+kevSet+` LIMIT 1)`, nil, &kev); err != nil {
		return "", err
	}
	if kev == 0 { // a fresh box, or the CISA list not loaded yet: nothing to say about NVD
		return "Nothing to read yet: CVE.org is read for the exploited CVEs NVD gives no affected versions for, once the CISA list is on the box.", nil
	}
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
		if gap == 1 {
			return "1 exploited CVE has no affected versions from NVD, and CVE.org gives none Vedette can compare for it either; it is asked again every 12 hours.", nil
		}
		return fmt.Sprintf("%s have no affected versions from NVD, and CVE.org gives none Vedette can compare for them either; each is asked again every 12 hours.",
			cves(gap, "exploited")), nil
	}
	var parts []string
	switch {
	case held > 0 && none > 0:
		parts = append(parts, fmt.Sprintf("CVE.org gives versions Vedette can compare for %s of them, none for %s", grouped(held), grouped(none)))
	case held > 0 && gap == 1:
		parts = append(parts, "CVE.org gives versions Vedette can compare for it")
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

// heldDistro: a distribution feed counts one row per package, release and CVE, not CVEs. Grouped by CVE first, so the CISA list is
// looked up once per CVE, not once per row (half the time of counting DISTINCT twice over the rows).
func heldDistro(id string) func(context.Context, *sql.Tx) (string, error) {
	return func(ctx context.Context, tx *sql.Tx) (string, error) {
		var rows, all, kev int
		if err := counts(ctx, tx, `SELECT coalesce(sum(n), 0), count(*), coalesce(sum(kev), 0)
FROM (SELECT count(*) AS n, cve IN (`+kevSet+`) AS kev FROM feeds_distro_fix WHERE source_id = ? GROUP BY cve)`, []any{id}, &rows, &all, &kev); err != nil {
			return "", err
		}
		if rows == 0 {
			return "", nil
		}
		t := "Counts one record per package, release and CVE: " + cves(kev, "exploited")
		if other := all - kev; other > 0 {
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
		upd := "monthly updates"
		if ups == 1 {
			upd = "monthly update"
		}
		t += fmt.Sprintf(", with %s %s, the newest of %s", grouped(ups), upd, orgtime.CalendarDay(d))
	}
	return t + ".", nil
}
