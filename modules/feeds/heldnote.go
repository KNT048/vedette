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
	nvdFeedID:           heldNVD,
	cveOrgFeedID:        heldCVEOrg,
	ubuntuOSVFeedID:     heldDistro(ubuntuOSVFeedID),
	ubuntuVEXFeedID:     heldDistro(ubuntuVEXFeedID),
	debianTrackerFeedID: heldDistro(debianTrackerFeedID),
	alpineOSVFeedID:     heldDistro(alpineOSVFeedID),
	winRelFeedID:        heldWinRel,
	pocGitHubFeedID:     heldPoC,
	nodeLineFeedID:      func(ctx context.Context, tx *sql.Tx) (string, error) { return lineHeld(ctx, tx, nodeLineFeedID) },
	oracleLineFeedID:    func(ctx context.Context, tx *sql.Tx) (string, error) { return lineHeld(ctx, tx, oracleLineFeedID) },
	eolFeedID:           func(ctx context.Context, tx *sql.Tx) (string, error) { return supportHeld(ctx, tx, eolFeedID) },
}

// heldFrom names, for each feed of heldNotes, the feeds whose data its sentence counts. That data is written only by a pull of one
// of them (in the transaction that records the pull) or by an edit of one of them (a key removed), so their last_fetch and rev
// change with it: they key the sentence counted last (heldNow). TestHeldNotes_FollowTheData checks every feed.
var heldFrom = map[string][]string{
	nvdFeedID:           {nvdFeedID},
	cveOrgFeedID:        {cveOrgFeedID, nvdFeedID, recentFeedID, kevFeedID, vulnCheckFeedID},
	ubuntuOSVFeedID:     {ubuntuOSVFeedID, kevFeedID, vulnCheckFeedID},
	ubuntuVEXFeedID:     {ubuntuVEXFeedID, kevFeedID, vulnCheckFeedID},
	debianTrackerFeedID: {debianTrackerFeedID, kevFeedID, vulnCheckFeedID},
	alpineOSVFeedID:     {alpineOSVFeedID, kevFeedID, vulnCheckFeedID},
	winRelFeedID:        {winRelFeedID},
	pocGitHubFeedID:     {pocGitHubFeedID},
	nodeLineFeedID:      {nodeLineFeedID, nvdFeedID, recentFeedID, cveOrgFeedID}, // the catalogue's pruning drops statements of CVEs it no longer keeps
	oracleLineFeedID:    {oracleLineFeedID, nvdFeedID, recentFeedID, cveOrgFeedID},
	eolFeedID:           {eolFeedID},
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
const kevSet = `SELECT cve FROM feeds_kev WHERE source_id IN ('cisa-kev', 'vulncheck-kev')`

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

func heldNVD(ctx context.Context, tx *sql.Tx) (string, error) {
	var all, ranged int
	if err := counts(ctx, tx, `SELECT count(*), count(*) FILTER (WHERE EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = c.cve AND r.origin = 'nvd'))
FROM feeds_cve c WHERE c.nvd_at IS NOT NULL AND c.cve IN (`+kevSet+`)`, nil, &all, &ranged); err != nil {
		return "", err
	}
	if all == 0 {
		return "", nil // not loaded yet: the row says so
	}
	return fmt.Sprintf("NVD records of %s; %s of them name affected versions.", cves(all, "exploited"), grouped(ranged)), nil
}

// heldCVEOrg: the feed counts the catalogue CVEs whose CVE record was read; what matters is how many of those NVD gives no affected
// versions for get them from their record, for the catalogue and for the exploited CVEs.
func heldCVEOrg(ctx context.Context, tx *sql.Tx) (string, error) {
	var all, read, gap, held int
	if err := counts(ctx, tx, `SELECT count(*), count(*) FILTER (WHERE c.record_at IS NOT NULL),
count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = c.cve AND r.origin = 'nvd')),
count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = c.cve AND r.origin = 'nvd')
  AND EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = c.cve AND r.origin IN ('cna', 'adp') AND `+genericRowSQL+`))
FROM feeds_cve c`, nil, &all, &read, &gap, &held); err != nil {
		return "", err
	}
	var kevGap int
	if err := counts(ctx, tx, `SELECT count(*) FROM (SELECT DISTINCT cve FROM feeds_kev WHERE source_id IN ('cisa-kev', 'vulncheck-kev')) v
WHERE NOT EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = v.cve AND r.origin = 'nvd')`, nil, &kevGap); err != nil {
		return "", err
	}
	var parts []string
	if read == 0 {
		parts = append(parts, "No CVE record read yet: the CVE Program's records of the catalogue's CVEs load at the next check.")
	} else {
		parts = append(parts, fmt.Sprintf("%s of %s catalogue CVEs have their record read; %s without affected versions from NVD, %s of them with versions from the record.",
			grouped(read), grouped(all), grouped(gap), grouped(held)))
	}
	if kevGap > 0 {
		aff, _, nvd, err := kevRecordView(ctx, tx)
		if err != nil {
			return "", err
		}
		held := 0
		for cve := range aff {
			if !nvd[cve] {
				held++
			}
		}
		parts = append(parts, fmt.Sprintf("Exploited: %s without affected versions from NVD, %s of them with versions from the record.", grouped(kevGap), grouped(held)))
	}
	return strings.Join(parts, " "), nil
}

// heldDistro: a distribution feed counts one row per package, release and CVE, not CVEs. Grouped by CVE first, so the CISA list is
// looked up once per CVE, not once per row (half the time of counting DISTINCT twice over the rows).
func heldDistro(id string) func(context.Context, *sql.Tx) (string, error) {
	return func(ctx context.Context, tx *sql.Tx) (string, error) {
		var rows, all, kev int
		if err := counts(ctx, tx, `SELECT coalesce(sum(n), 0), count(*), coalesce(sum(kev), 0)
FROM (SELECT count(*) AS n, cve IN (`+kevSet+`) AS kev FROM (SELECT cve FROM feeds_distro_fix WHERE source_id = ?1
UNION ALL SELECT cve FROM feeds_distro_triage WHERE source_id = ?1) GROUP BY cve)`, []any{id}, &rows, &all, &kev); err != nil {
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
