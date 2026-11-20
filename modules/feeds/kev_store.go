package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/store"
)

// Exploited-list entries (feeds_kev). One CVE may be on several lists (the CISA catalog, VulnCheck KEV, custom feeds); every
// reader that shows one entry per CVE reads the owner entry: the CISA list's, else VulnCheck's, else the custom feed's (ownerOrder).

// The lists of feeds_kev.list.
const (
	ListCISA      = "cisa"
	ListVulnCheck = "vulncheck"
	listCustom    = "custom:" // + the custom feed's id
)

// nucleiFeedID is the built-in feed of nuclei-templates' CVE index: a public-exploit signal ("has a scan template").
const nucleiFeedID = "nuclei-templates"

// The signal kinds (feeds_signal.kind) this module writes now. Open vocabulary: decoders of other sources add kinds of their own.
const (
	SignalExploited     = "exploited"      // on an exploited list, or a vendor says it is exploited
	SignalPublicExploit = "public_exploit" // a public exploit or a scan template exists
)

// listOf is the list a feed's entries are stored under.
func listOf(sourceID string) string {
	switch sourceID {
	case kevFeedID:
		return ListCISA
	case vulnCheckFeedID:
		return ListVulnCheck
	}
	return listCustom + sourceID
}

// listRank orders the lists of one CVE: the CISA list first, then VulnCheck, then custom feeds.
func listRank(list string) int {
	switch list {
	case ListCISA:
		return 0
	case ListVulnCheck:
		return 1
	}
	return 2
}

// ownerOrder is listRank in SQL (k2 is the feeds_kev row ranked).
const ownerOrder = `CASE k2.list WHEN 'cisa' THEN 0 WHEN 'vulncheck' THEN 1 ELSE 2 END, k2.list`

// VulnRow is an exploited-list entry as the pages read it: the owner entry of its CVE, with the EPSS score of the CVE (today's and the
// one of a week before, when the box holds it) and whether nuclei has a template for it.
type VulnRow struct {
	Vuln
	EPSS        *float64
	EPSS7dAgo   *float64
	HasTemplate bool
	SourceID    string
}

// vulnSelect reads owner entries; the caller appends its WHERE conditions with "AND …" and its ORDER BY.
const vulnSelect = `SELECT k.cve, k.vendor, k.product, k.name, k.description, k.required_action, k.links, k.date_added, k.due_date, k.ransomware,
  e.epss, h.epss,
  EXISTS (SELECT 1 FROM feeds_signal s WHERE s.cve = k.cve AND s.kind = 'public_exploit' AND s.source = 'nuclei-templates'),
  k.source_id
FROM feeds_kev k
LEFT JOIN feeds_epss e ON e.cve = k.cve
LEFT JOIN feeds_epss_hist h ON h.cve = k.cve AND h.day = (SELECT date(score_date, '-7 days') FROM feeds_epss_baseline WHERE id = 1)
WHERE k.list = (SELECT k2.list FROM feeds_kev k2 WHERE k2.cve = k.cve ORDER BY ` + ownerOrder + ` LIMIT 1) `

func scanVuln(r scanner) (VulnRow, error) {
	var (
		v             VulnRow
		links         string
		due           *string
		ransom, hasTp int
	)
	err := r.Scan(&v.CVE, &v.Vendor, &v.Product, &v.Name, &v.Description, &v.RequiredAction, &links, &v.DateAdded, &due,
		&ransom, &v.EPSS, &v.EPSS7dAgo, &hasTp, &v.SourceID)
	if err != nil {
		return VulnRow{}, err
	}
	if err := json.Unmarshal([]byte(links), &v.Links); err != nil || v.Links == nil {
		v.Links = []string{}
	}
	if due != nil {
		v.DueDate = *due
	}
	v.Ransomware, v.HasTemplate = ransom != 0, hasTp != 0
	return v, nil
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// queryVulns reads owner entries; cond starts with "AND" (or is empty) and may end with ORDER BY / LIMIT.
func queryVulns(ctx context.Context, q queryer, cond string, args ...any) ([]VulnRow, error) {
	rows, err := q.QueryContext(ctx, vulnSelect+cond, args...)
	if err != nil {
		return nil, fmt.Errorf("feeds: read vulnerabilities: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []VulnRow{}
	for rows.Next() {
		v, err := scanVuln(rows)
		if err != nil {
			return nil, fmt.Errorf("feeds: read vulnerabilities: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// kevSources is the SQL condition of the exploited lists that make KEV events and findings: the CISA list and VulnCheck KEV.
const kevSources = `k.source_id IN ('cisa-kev', 'vulncheck-kev')`

// VulnByCVE returns the owner entry of one CVE (upper case).
func (s *Store) VulnByCVE(ctx context.Context, cve string) (VulnRow, bool, error) {
	rows, err := queryVulns(ctx, s.db.Reader(), `AND k.cve = ?`, cve)
	if err != nil || len(rows) == 0 {
		return VulnRow{}, false, err
	}
	return rows[0], true, nil
}

// VulnsByProductKey returns the entries of one product key (productid.Key), newest first.
func (s *Store) VulnsByProductKey(ctx context.Context, key string) ([]VulnRow, error) {
	all, err := queryVulns(ctx, s.db.Reader(), `ORDER BY k.date_added DESC, k.cve DESC`)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(all, func(v VulnRow) bool { return v.Key() != key }), nil
}

// HasTemplate reports whether nuclei has a template for the CVE (its public-exploit signal).
func (s *Store) HasTemplate(ctx context.Context, cve string) (bool, error) {
	var n int
	err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM feeds_signal WHERE cve = ? AND kind = 'public_exploit' AND source = 'nuclei-templates'`, cve).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("feeds: read template: %w", err)
	}
	return n > 0, nil
}

// Product is a vendor and product pair as KEV writes them.
type Product struct{ Vendor, Product string }

// Key is productid.Key of the pair.
func (p Product) Key() string { return productid.Key(p.Vendor, p.Product) }

// KevPairs lists every vendor and product pair of the exploited lists (CISA, VulnCheck), for the inventory catalog. A custom feed's
// products are not KEV entries.
func (s *Store) KevPairs(ctx context.Context) ([]Product, error) {
	all, err := queryVulns(ctx, s.db.Reader(), `AND `+kevSources)
	if err != nil {
		return nil, err
	}
	seen := map[Product]bool{}
	var out []Product
	for _, v := range all {
		if p := (Product{Vendor: v.Vendor, Product: v.Product}); !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	slices.SortStableFunc(out, func(a, b Product) int { return strings.Compare(a.Key(), b.Key()) })
	return out, nil
}

// vulnsNewestFirst returns the entries added on or after day (YYYY-MM-DD; "" for all), newest first.
func (s *Store) vulnsNewestFirst(ctx context.Context, day string) ([]VulnRow, error) {
	return queryVulns(ctx, s.db.Reader(), `AND k.date_added >= ? ORDER BY k.date_added DESC, k.cve DESC`, day)
}

// latest returns the newest entry added, nil when there is none.
func (s *Store) latest(ctx context.Context) (*VulnRow, error) {
	rows, err := queryVulns(ctx, s.db.Reader(), `ORDER BY k.date_added DESC, k.cve DESC LIMIT 1`)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

func sameVuln(a, b Vuln) bool {
	return a.Vendor == b.Vendor && a.Product == b.Product && a.Name == b.Name && a.Description == b.Description &&
		a.RequiredAction == b.RequiredAction && slices.Equal(a.Links, b.Links) && a.DateAdded == b.DateAdded &&
		a.DueDate == b.DueDate && a.Ransomware == b.Ransomware
}

// Bounds of one pull transaction: the context is checked every ctxEvery rows, and what is read is read once, before the loop.
const ctxEvery = 256

// Bounds of a stored vulnerability's vendor and product (characters): the matching key vendor|product must stay inside the CHECK of
// feeds_weekly_answer.key whatever a custom feed sends.
const (
	maxVendorProduct = 200
	maxProductKey    = 500
)

// clampDate turns a date a feed gives in the future into today, like the IOC path does for first_seen.
func clampDate(day, today string) string {
	if day > today { // YYYY-MM-DD compares as text
		return today
	}
	return day
}

// kevListURL is the address a CISA or VulnCheck signal row links to.
var kevListURL = map[string]string{
	kevFeedID:       "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
	vulnCheckFeedID: "https://vulncheck.com/kev",
}

// ensureCVE gives a CVE its catalogue row (only its id until NVD or the CVE record answers).
func ensureCVE(ctx context.Context, tx *sql.Tx, cve, stamp string) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve (cve, updated_at) VALUES (?, ?) ON CONFLICT(cve) DO NOTHING`, cve, stamp); err != nil {
		return fmt.Errorf("feeds: catalogue entry: %w", err)
	}
	return nil
}

// applyVulns writes the entries of one pull of a list inside tx. It returns the entries that are news (fresh) and the CVEs whose
// owner entry changed (updated):
//   - fresh: a CVE the CISA list names for the first time (whatever other list had it), or one VulnCheck names that no list had;
//     for a custom feed, its new rows (no event is made of them);
//   - updated: an entry of this list that changed, when this list owns the CVE.
//
// An entry with an empty DateAdded takes today's date when new and keeps its date when it exists; dates in the future become today.
// The CISA list and VulnCheck KEV also write their exploited signal row in the same transaction. With replace (custom feeds,
// VulnCheck) the list's entries that are no longer listed go, with their signals; the CISA list never drops an entry.
func applyVulns(ctx context.Context, tx *sql.Tx, now time.Time, source string, vulns []Vuln, replace bool) (fresh []VulnRow, updated []string, err error) {
	list := listOf(source)
	existing := map[string]Vuln{}
	lists := map[string]int{} // the best rank among the lists that have the CVE before this pull
	rows, err := tx.QueryContext(ctx, `SELECT cve, list, vendor, product, name, description, required_action, links, date_added, coalesce(due_date, ''), ransomware FROM feeds_kev`)
	if err != nil {
		return nil, nil, fmt.Errorf("feeds: read list entries: %w", err)
	}
	for rows.Next() {
		var (
			v      Vuln
			l, lk  string
			ransom int
		)
		if err := rows.Scan(&v.CVE, &l, &v.Vendor, &v.Product, &v.Name, &v.Description, &v.RequiredAction, &lk, &v.DateAdded, &v.DueDate, &ransom); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("feeds: read list entries: %w", err)
		}
		if r, ok := lists[v.CVE]; !ok || listRank(l) < r {
			lists[v.CVE] = listRank(l)
		}
		if l != list {
			continue
		}
		if err := json.Unmarshal([]byte(lk), &v.Links); err != nil || v.Links == nil {
			v.Links = []string{}
		}
		v.Ransomware = ransom != 0
		existing[v.CVE] = v
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, nil, fmt.Errorf("feeds: read list entries: %w", err)
	}
	signal := isKEVSource(source)
	stamp, today := store.FormatTS(now), now.UTC().Format(time.DateOnly)
	rank := listRank(list)
	listed := map[string]bool{}
	for i, v := range vulns {
		if i%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
		}
		listed[v.CVE] = true
		v.Links = cleanLinks(v.Links)
		if v.DateAdded != "" {
			v.DateAdded = clampDate(v.DateAdded, today)
		}
		old, found := existing[v.CVE]
		if v.DateAdded == "" {
			v.DateAdded = today
			if found {
				v.DateAdded = old.DateAdded
			}
		}
		if signal {
			if err := putSignal(ctx, tx, v.CVE, SignalExploited, source, v.DateAdded+"T00:00:00.000Z", stamp, true, kevListURL[source]); err != nil {
				return nil, nil, err
			}
		}
		if found && sameVuln(old, v) {
			continue
		}
		links, err := json.Marshal(append([]string{}, v.Links...))
		if err != nil {
			return nil, nil, fmt.Errorf("feeds: encode links: %w", err)
		}
		var due *string
		if v.DueDate != "" {
			due = &v.DueDate
		}
		if err := ensureCVE(ctx, tx, v.CVE, stamp); err != nil {
			return nil, nil, err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO feeds_kev (cve, list, source_id, vendor, product, name, description, required_action, links, date_added,
due_date, ransomware, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(cve, list) DO UPDATE SET source_id = excluded.source_id, vendor = excluded.vendor, product = excluded.product, name = excluded.name,
description = excluded.description, required_action = excluded.required_action, links = excluded.links, date_added = excluded.date_added,
due_date = excluded.due_date, ransomware = excluded.ransomware, updated_at = excluded.updated_at`,
			v.CVE, list, source, v.Vendor, v.Product, v.Name, v.Description, v.RequiredAction, string(links), v.DateAdded, due, boolInt(v.Ransomware), stamp)
		if err != nil {
			return nil, nil, fmt.Errorf("feeds: store list entry: %w", err)
		}
		best, had := lists[v.CVE]
		switch {
		case !found && (list == ListCISA || !had || rank < best):
			// the CISA list names it for the first time, or this list is the first to have it (VulnCheck taking over a custom feed's)
			fresh = append(fresh, VulnRow{Vuln: v, SourceID: source})
		case !found:
		case !had || rank <= best:
			updated = append(updated, v.CVE)
		}
		if !had || rank < best {
			lists[v.CVE] = rank
		}
	}
	if replace {
		for c := range existing {
			if listed[c] {
				continue
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_kev WHERE cve = ? AND list = ?`, c, list); err != nil {
				return nil, nil, fmt.Errorf("feeds: delete list entry: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_signal WHERE cve = ? AND kind = 'exploited' AND source = ?`, c, source); err != nil {
				return nil, nil, fmt.Errorf("feeds: delete signal: %w", err)
			}
		}
	}
	if err := fillTemplates(ctx, tx, fresh); err != nil {
		return nil, nil, err
	}
	return fresh, updated, nil
}

// fillTemplates sets HasTemplate of the rows from their nuclei signal.
func fillTemplates(ctx context.Context, tx *sql.Tx, rows []VulnRow) error {
	for i := range rows {
		var has bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM feeds_signal WHERE cve = ? AND kind = 'public_exploit' AND source = 'nuclei-templates')`,
			rows[i].CVE).Scan(&has); err != nil {
			return fmt.Errorf("feeds: read template: %w", err)
		}
		rows[i].HasTemplate = has
	}
	return nil
}

// putSignal records that source says cve is of kind: a new row is stored with first_seen; an existing one keeps the earlier
// first_seen and is seen again now.
func putSignal(ctx context.Context, tx *sql.Tx, cve, kind, source, firstSeen, stamp string, qualifies bool, url string) error {
	if firstSeen > stamp {
		firstSeen = stamp // a source that dates a signal in the future
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies, url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(cve, kind, source) DO UPDATE SET first_seen = min(first_seen, excluded.first_seen), last_seen = excluded.last_seen,
qualifies = excluded.qualifies, url = excluded.url`, cve, kind, source, firstSeen, stamp, stamp, boolInt(qualifies), url)
	if err != nil {
		return fmt.Errorf("feeds: store signal: %w", err)
	}
	return nil
}

func stringSet(ctx context.Context, q queryer, query string, args ...any) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("feeds: read set: %w", err)
	}
	out := map[string]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("feeds: read set: %w", err)
		}
		out[s] = true
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("feeds: read set: %w", err)
	}
	return out, nil
}

// templatesOfCISA is the CISA-list CVEs that have a nuclei template.
const templatesOfCISA = `SELECT s.cve FROM feeds_signal s WHERE s.kind = 'public_exploit' AND s.source = 'nuclei-templates'
AND EXISTS (SELECT 1 FROM feeds_kev k WHERE k.cve = s.cve AND k.list = 'cisa')`

// Template is one CVE of nuclei-templates' index, with the address of its template.
type Template struct{ CVE, URL string }

// applyTemplates replaces the public-exploit signals of nuclei-templates with the CVEs of one index (a CVE seen before keeps its
// first sighting); it returns the CISA-list CVEs whose "has a template" changed (a custom feed's CVE changing is no event).
func applyTemplates(ctx context.Context, tx *sql.Tx, now time.Time, tmpls []Template) ([]string, error) {
	before, err := stringSet(ctx, tx, templatesOfCISA)
	if err != nil {
		return nil, err
	}
	// a stamp no row of the source has, so "any other last_seen" means "not in this index" (as applyIOCs)
	stamp := store.FormatTS(now)
	for {
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM feeds_signal WHERE source = 'nuclei-templates' AND kind = 'public_exploit' AND last_seen = ? LIMIT 1`, stamp).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("feeds: check stamp: %w", err)
		}
		now = now.Add(time.Millisecond)
		stamp = store.FormatTS(now)
	}
	for i, t := range tmpls {
		if i%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		// nuclei templates are always a qualifying public exploit (a working check, reviewed by the project)
		if err := putSignal(ctx, tx, t.CVE, SignalPublicExploit, nucleiFeedID, stamp, stamp, true, t.URL); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_signal WHERE source = 'nuclei-templates' AND kind = 'public_exploit' AND last_seen <> ?`, stamp); err != nil {
		return nil, fmt.Errorf("feeds: drop templates: %w", err)
	}
	after, err := stringSet(ctx, tx, templatesOfCISA)
	if err != nil {
		return nil, err
	}
	var changed []string
	for c := range before {
		if !after[c] {
			changed = append(changed, c)
		}
	}
	for c := range after {
		if !before[c] {
			changed = append(changed, c)
		}
	}
	slices.Sort(changed)
	return changed, nil
}

// kevCVEs lists the CVEs of the CISA list.
func (s *Store) kevCVEs(ctx context.Context) ([]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT cve FROM feeds_kev WHERE list = 'cisa' ORDER BY cve`)
	if err != nil {
		return nil, fmt.Errorf("feeds: read cves: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("feeds: read cves: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
