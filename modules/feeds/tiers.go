package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// D-615: the day NVD published each KEV CVE (feeds_published), and D-613/D-616: what the tier feeds epss-all and nvd-recent
// hold, for the "Updates to plan" page and the CVE page of a CVE on no exploited list.

// applyPublished stores the days NVD published the CVEs of one nvd-kev pull (D-615). Rows are only added or corrected: a
// CVE an update did not return keeps its day. NVD's day replaces a day CVE.org gave (D-617).
func applyPublished(ctx context.Context, tx *sql.Tx, got map[string]string) error {
	if len(got) == 0 {
		return nil
	}
	st, err := tx.PrepareContext(ctx, `INSERT INTO feeds_published (cve, published, source) VALUES (?, ?, 'nvd') ON CONFLICT(cve) DO UPDATE SET published = excluded.published, source = 'nvd'`)
	if err != nil {
		return fmt.Errorf("feeds: published: %w", err)
	}
	defer func() { _ = st.Close() }()
	for _, cve := range slices.Sorted(maps.Keys(got)) {
		if _, err := st.ExecContext(ctx, cve, got[cve]); err != nil {
			return fmt.Errorf("feeds: published %s: %w", cve, err)
		}
	}
	return nil
}

// applyCVEOrgPublished stores the days CVE.org's records give for exploited CVEs NVD has given none for (D-615 (2), D-617): a row
// NVD wrote is never replaced, and a day CVE.org gave once stays (a CVE's published day does not change).
func applyCVEOrgPublished(ctx context.Context, tx *sql.Tx, got map[string]string) error {
	for _, cve := range slices.Sorted(maps.Keys(got)) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_published (cve, published, source) VALUES (?, ?, 'cve.org') ON CONFLICT(cve) DO NOTHING`, cve, got[cve]); err != nil {
			return fmt.Errorf("feeds: published %s: %w", cve, err)
		}
	}
	return nil
}

// publishedCount is how many CVEs have NVD's published day (CVE.org's do not count, D-617); 0 makes the next nvd-kev pull a full one.
func (s *Store) publishedCount(ctx context.Context) (int, error) {
	var n int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM feeds_published WHERE source = 'nvd'`).Scan(&n); err != nil {
		return 0, fmt.Errorf("feeds: count published: %w", err)
	}
	return n, nil
}

// KevPublished returns the day NVD published each CVE it answered for, else the day its CVE.org record gives (D-615, D-617). A CVE that is absent has no known day:
// findings then treats it as recent and never closes a finding on it for its age.
func (s *Store) KevPublished(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT cve, published FROM feeds_published`)
	if err != nil {
		return nil, fmt.Errorf("feeds: read published: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]time.Time{}
	for rows.Next() {
		var cve, day string
		if err := rows.Scan(&cve, &day); err != nil {
			return nil, fmt.Errorf("feeds: read published: %w", err)
		}
		if t, err := time.Parse(time.DateOnly, day); err == nil {
			out[cve] = t
		}
	}
	return out, rows.Err()
}

// PublishedOf returns the day NVD published each of these CVEs ("2017-03-14", D-615); a CVE NVD has not answered for is absent.
func (s *Store) PublishedOf(ctx context.Context, cves []string) (map[string]string, error) {
	out := make(map[string]string, len(cves))
	for _, c := range cves {
		d, err := s.publishedOf(ctx, c)
		if err != nil {
			return nil, err
		}
		if d != nil {
			out[c] = *d
		}
	}
	return out, nil
}

// publishedOf is the day NVD published one CVE ("2017-03-14"), nil when it has not answered for it.
func (s *Store) publishedOf(ctx context.Context, cve string) (*string, error) {
	var d string
	err := s.db.Reader().QueryRowContext(ctx, `SELECT published FROM feeds_published WHERE cve = ?`, cve).Scan(&d)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("feeds: read published: %w", err)
	}
	return &d, nil
}

// TierFeed is the state of one tier feed for the pages that read it.
type TierFeed string

// The states of a tier feed: off (an admin has not turned it on), loading (on, its first fill is not finished), ready.
const (
	TierOff     TierFeed = "off"
	TierLoading TierFeed = "loading"
	TierReady   TierFeed = "ready"
)

// TierStatus says what the tier data holds (D-613, D-616).
type TierStatus struct {
	EPSS, Recent TierFeed
	EPSSDate     time.Time // the day of the last good pull of epss-all (FIRST publishes one file a day); zero unless EPSS is ready
	RecentSince  time.Time // CVEs published on or after it are in nvd-recent's data; zero unless Recent is ready
}

// TierStatus reads the two feeds: epss-all is ready once it stored scores, nvd-recent once its first fill finished (its
// cursor left the fill mode) and it holds records.
func (s *Store) TierStatus(ctx context.Context, now time.Time) (TierStatus, error) {
	var out TierStatus
	epss, err := s.source(ctx, epssAllFeedID)
	if err != nil {
		return out, err
	}
	recent, err := s.source(ctx, recentFeedID)
	if err != nil {
		return out, err
	}
	var scores, records int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT (SELECT count(*) FROM feeds_epss), (SELECT count(*) FROM feeds_recent_cve)`).Scan(&scores, &records); err != nil {
		return out, fmt.Errorf("feeds: tier status: %w", err)
	}
	out.EPSS, out.Recent = TierOff, TierOff
	if epss.Enabled {
		out.EPSS = TierLoading
		if scores > 0 && epss.LastSuccess != nil {
			out.EPSS, out.EPSSDate = TierReady, epss.LastSuccess.UTC().Truncate(24*time.Hour)
		}
	}
	if recent.Enabled {
		out.Recent = TierLoading
		cur, err := s.recentCursor(ctx)
		if err != nil {
			return out, err
		}
		if cur != nil && !cur.fill() && records > 0 {
			out.Recent, out.RecentSince = TierReady, now.UTC().AddDate(0, 0, -recentDays).Truncate(24*time.Hour)
		}
	}
	return out, nil
}

// TierCVE is what the tier data says about one CVE (GET /feeds/cve/{id}/tier).
type TierCVE struct {
	CVE                     string
	Tier                    string // "likely", "recent", or "" (older than 12 months, or no published day in the data)
	Published, LastModified *time.Time
	NVDStatus, Severity     *string
	Score, EPSS, Percentile *float64
	EPSSDate                *time.Time
	Products                []string // "vendor product" of NVD's affected entries, at most 10
	Ranges                  bool     // NVD gives affected entries
}

// TierCVEOf reads one CVE from the tier data of the feeds that are on; found is false when neither holds it. Tier follows
// D-613 and D-615: EPSS ≥ EPSSLikely and published in the last 365 days is likely, published in the last 365 days is recent.
func (s *Store) TierCVEOf(ctx context.Context, cve string, now time.Time) (TierCVE, bool, error) {
	st, err := s.TierStatus(ctx, now)
	if err != nil {
		return TierCVE{}, false, err
	}
	out := TierCVE{CVE: cve, Products: []string{}}
	found := false
	db := s.db.Reader()
	if st.EPSS == TierReady {
		var e, p float64
		err := db.QueryRowContext(ctx, `SELECT epss, percentile FROM feeds_epss WHERE cve = ?`, cve).Scan(&e, &p)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return TierCVE{}, false, fmt.Errorf("feeds: tier epss: %w", err)
		default:
			d := st.EPSSDate
			out.EPSS, out.Percentile, out.EPSSDate, found = &e, &p, &d, true
		}
	}
	if st.Recent == TierReady {
		var pub, mod, status string
		var sev sql.NullString
		var score sql.NullFloat64
		err := db.QueryRowContext(ctx, `SELECT published, last_modified, status, severity, score FROM feeds_recent_cve WHERE cve = ?`, cve).Scan(&pub, &mod, &status, &sev, &score)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return TierCVE{}, false, fmt.Errorf("feeds: tier record: %w", err)
		default:
			p, e1 := parseTS(pub)
			m, e2 := parseTS(mod)
			if e1 == nil && e2 == nil && !p.Before(now.AddDate(0, 0, -recentDays)) {
				found = true
				out.Published, out.LastModified, out.NVDStatus = &p, &m, &status
				if sev.Valid {
					v := strings.ToLower(sev.String)
					out.Severity = &v
				}
				if score.Valid {
					out.Score = &score.Float64
				}
				out.Tier = "recent"
				if out.EPSS != nil && *out.EPSS >= EPSSLikely {
					out.Tier = "likely"
				}
				if out.Products, out.Ranges, err = s.recentProducts(ctx, cve); err != nil {
					return TierCVE{}, false, err
				}
			}
		}
	}
	return out, found, nil
}

// recentProducts lists the vendor and product of a CVE's NVD affected entries ("f5 nginx"), at most 10, sorted.
func (s *Store) recentProducts(ctx context.Context, cve string) ([]string, bool, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT DISTINCT cpe FROM feeds_recent_affected WHERE cve = ?`, cve)
	if err != nil {
		return nil, false, fmt.Errorf("feeds: tier products: %w", err)
	}
	defer func() { _ = rows.Close() }()
	seen := map[string]bool{}
	listed := false
	for rows.Next() {
		var cpe string
		if err := rows.Scan(&cpe); err != nil {
			return nil, false, fmt.Errorf("feeds: tier products: %w", err)
		}
		listed = true
		parts := strings.Split(cpe, ":") // cpe:2.3:part:vendor:product:…
		if len(parts) < 5 {
			continue
		}
		seen[strings.ReplaceAll(parts[3]+" "+parts[4], "_", " ")] = true
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("feeds: tier products: %w", err)
	}
	out := append([]string{}, slices.Sorted(maps.Keys(seen))...) // never nil: products is an array in the answer
	if len(out) > 10 {
		out = out[:10]
	}
	return out, listed, nil
}

// TierRecord is one CVE of the tier data as findings' plan reads it (D-617): NVD's record of the last 12 months with the affected
// entries the caller kept, and its EPSS score.
type TierRecord struct {
	CVE              string
	Tier             string // "likely" (EPSS ≥ EPSSLikely) or "recent"
	Published        time.Time
	Severity         string   // NVD's CVSS severity ("HIGH"), "" when none
	Score            *float64 // its base score
	EPSS, Percentile *float64 // nil when epss-all is not ready or has no score for the CVE
	Affected         []AffectedRow
}

// tierChunk is how many CPEs one read of TierRecords asks for.
const tierChunk = 500

// TierRecords reads the CVEs of nvd-recent published since now minus 365 days whose NVD affected entries name a CPE keep accepts,
// each with those entries only (D-617): the distinct CPEs are read from the index first (tens of thousands of short strings), then
// only the rows of the kept ones, so a pass holds the CVEs of the products the devices run, never the whole year. Nothing while
// nvd-recent is not ready (its first fill unfinished, or off); EPSS only while epss-all is ready.
func (s *Store) TierRecords(ctx context.Context, now time.Time, keep func(cpe string) bool) ([]TierRecord, error) {
	st, err := s.TierStatus(ctx, now)
	if err != nil || st.Recent != TierReady {
		return nil, err
	}
	db := s.db.Reader()
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT cpe FROM feeds_recent_affected`)
	if err != nil {
		return nil, fmt.Errorf("feeds: tier products: %w", err)
	}
	var want []string
	for rows.Next() {
		var cpe string
		if err := rows.Scan(&cpe); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("feeds: tier products: %w", err)
		}
		if keep(cpe) {
			want = append(want, cpe)
		}
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("feeds: tier products: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("feeds: tier products: %w", err)
	}
	cutoff := store.FormatTS(now.AddDate(0, 0, -recentDays))
	epssOn := st.EPSS == TierReady
	at := map[string]int{}
	var out []TierRecord
	for len(want) > 0 {
		n := min(len(want), tierChunk)
		part, err := json.Marshal(want[:n]) // one parameter: the CPEs as a JSON array (json_each), no SQL built from strings
		if err != nil {
			return nil, fmt.Errorf("feeds: tier records: %w", err)
		}
		want = want[n:]
		rs, err := db.QueryContext(ctx, `SELECT a.cve, a.cpe, a.start_incl, a.start_excl, a.end_incl, a.end_excl, r.published, r.severity, r.score, e.epss, e.percentile
FROM feeds_recent_affected a JOIN feeds_recent_cve r ON r.cve = a.cve LEFT JOIN feeds_epss e ON e.cve = a.cve
WHERE a.cpe IN (SELECT value FROM json_each(?)) AND r.published >= ? ORDER BY a.cve`, string(part), cutoff)
		if err != nil {
			return nil, fmt.Errorf("feeds: tier records: %w", err)
		}
		for rs.Next() {
			var (
				cve, pub string
				af       AffectedRow
				sev      sql.NullString
				score    sql.NullFloat64
				ep, pc   sql.NullFloat64
			)
			if err := rs.Scan(&cve, &af.CPE, &af.StartIncl, &af.StartExcl, &af.EndIncl, &af.EndExcl, &pub, &sev, &score, &ep, &pc); err != nil {
				_ = rs.Close()
				return nil, fmt.Errorf("feeds: tier records: %w", err)
			}
			i, ok := at[cve]
			if !ok {
				p, err := parseTS(pub)
				if err != nil {
					continue // the CHECK keeps this from happening; never a guessed day
				}
				r := TierRecord{CVE: cve, Tier: "recent", Published: p, Severity: sev.String}
				if score.Valid {
					r.Score = &score.Float64
				}
				if epssOn && ep.Valid && pc.Valid {
					e, q := ep.Float64, pc.Float64
					r.EPSS, r.Percentile = &e, &q
					if e >= EPSSLikely {
						r.Tier = "likely"
					}
				}
				i = len(out)
				at[cve] = i
				out = append(out, r)
			}
			out[i].Affected = append(out[i].Affected, af)
		}
		if err := rs.Close(); err != nil {
			return nil, fmt.Errorf("feeds: tier records: %w", err)
		}
		if err := rs.Err(); err != nil {
			return nil, fmt.Errorf("feeds: tier records: %w", err)
		}
	}
	return out, nil
}
