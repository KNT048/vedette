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

// What the tier feeds epss-all and nvd-recent hold, for the "Updates to plan" page and the CVE page of a CVE on no exploited list.

// TierFeed is the state of one tier feed for the pages that read it.
type TierFeed string

// The states of a tier feed: off (an admin has not turned it on), loading (on, its first fill is not finished), ready.
const (
	TierOff     TierFeed = "off"
	TierLoading TierFeed = "loading"
	TierReady   TierFeed = "ready"
)

// TierStatus says what the tier data holds.
type TierStatus struct {
	EPSS, Recent TierFeed
	EPSSDate     time.Time // FIRST's day of the stored scores (the file's score_date, 00:00 UTC); before a pull stored it, the UTC day of the last good pull; zero unless EPSS is ready
	RecentSince  time.Time // CVEs published on or after it are in nvd-recent's data; zero unless Recent is ready
}

// TierStatus reads the two feeds: epss-all is ready once it stored scores, nvd-recent once the fill of its window finished (its
// cursor left the fill mode) and the catalogue holds NVD records of the window.
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
	// Only "is there any row" is read, so ask for that: counting walks the whole table (400k scores, 100k CVEs).
	var hasScores, hasRecords bool
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM feeds_epss), EXISTS (SELECT 1 FROM feeds_cve WHERE nvd_at IS NOT NULL AND published >= ?)`,
		store.FormatTS(now.AddDate(0, 0, -recentDays))).Scan(&hasScores, &hasRecords); err != nil {
		return out, fmt.Errorf("feeds: tier status: %w", err)
	}
	out.EPSS, out.Recent = TierOff, TierOff
	if epss.Enabled {
		out.EPSS = TierLoading
		if hasScores && epss.LastSuccess != nil {
			out.EPSS, out.EPSSDate = TierReady, epss.LastSuccess.UTC().Truncate(24*time.Hour)
			// FIRST's own day of the scores, the day Settings › Feeds names too; a pull before the column kept none
			var day sql.NullString
			err := s.db.Reader().QueryRowContext(ctx, `SELECT score_date FROM feeds_epss_baseline WHERE id = 1`).Scan(&day)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return out, fmt.Errorf("feeds: tier status: %w", err)
			}
			if d, err := time.Parse(time.DateOnly, day.String); day.Valid && err == nil {
				out.EPSSDate = d
			}
		}
	}
	if recent.Enabled {
		out.Recent = TierLoading
		cur, err := s.recentCursor(ctx)
		if err != nil {
			return out, err
		}
		if cur != nil && !cur.fill() && hasRecords {
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
// EPSS ≥ EPSSLikely and published in the last 365 days is likely, published in the last 365 days is recent.
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
		err := db.QueryRowContext(ctx, `SELECT published, modified, nvd_status FROM feeds_cve WHERE cve = ? AND nvd_at IS NOT NULL AND nvd_status <> 'Rejected'`, cve).Scan(&pub, &mod, &status)
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
				scores, err := s.CVSSOf(ctx, []string{cve})
				if err != nil {
					return TierCVE{}, false, err
				}
				if c, ok := scores[cve]; ok {
					v, sc := strings.ToLower(Severity(c.Score, c.Version)), c.Score
					out.Severity, out.Score = &v, &sc
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
	if out.Published == nil { // not in the window (older, or the feed not ready): the day the catalogue holds
		d, err := s.publishedOf(ctx, cve)
		if err != nil {
			return TierCVE{}, false, err
		}
		if d != nil {
			if t, err := time.Parse(time.DateOnly, *d); err == nil {
				out.Published = &t
			}
		}
	}
	return out, found, nil
}

// recentProducts lists the vendor and product of a CVE's NVD affected entries ("f5 nginx"), at most 10, sorted.
func (s *Store) recentProducts(ctx context.Context, cve string) ([]string, bool, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT DISTINCT cpe FROM feeds_cve_range WHERE cve = ? AND origin = 'nvd'`, cve)
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

// TierRecord is one CVE of the tier data as findings' plan reads it: NVD's record of the last 12 months with the affected
// entries the caller kept, and its EPSS score.
type TierRecord struct {
	CVE              string
	Tier             string // "likely" (EPSS ≥ EPSSLikely) or "recent"
	Published        time.Time
	Severity         string   // NVD's CVSS severity ("HIGH"), "" when none
	Score            *float64 // its base score
	EPSS, Percentile *float64 // nil when epss-all is not ready or has no score for the CVE
	Affected         []AffectedRow
	// Distro is, for TierDistroRecords, the distributions' rows (fixed, not affected, open) of the packages asked for; nil for TierRecords.
	Distro []DistroFix
	// Platforms is, per entry, NVD's "running on" operating systems ("microsoft:windows"); empty for none.
	Platforms [][]string
}

// tierChunk is how many CPEs one read of TierRecords asks for.
const tierChunk = 500

// TierRecords reads the CVEs of nvd-recent published since now minus 365 days whose NVD affected entries name a CPE keep accepts,
// each with those entries only: the distinct CPEs are read from the index first (tens of thousands of short strings), then
// only the rows of the kept ones, so a pass holds the CVEs of the products the devices run, never the whole year. Nothing while
// nvd-recent is not ready (its first fill unfinished, or off); EPSS only while epss-all is ready.
func (s *Store) TierRecords(ctx context.Context, now time.Time, keep func(cpe string) bool) ([]TierRecord, error) {
	st, err := s.TierStatus(ctx, now)
	if err != nil || st.Recent != TierReady {
		return nil, err
	}
	db := s.db.Reader()
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT vendor, product, cpe FROM feeds_cve_range WHERE origin = 'nvd'`)
	if err != nil {
		return nil, fmt.Errorf("feeds: tier products: %w", err)
	}
	kept := map[string]bool{}
	pairs := map[[2]string]bool{}
	for rows.Next() {
		var vendor, product, cpe string
		if err := rows.Scan(&vendor, &product, &cpe); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("feeds: tier products: %w", err)
		}
		if keep(cpe) {
			kept[cpe] = true
			pairs[[2]string{vendor, product}] = true
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("feeds: tier products: %w", err)
	}
	want := slices.SortedFunc(maps.Keys(pairs), func(a, b [2]string) int {
		if c := strings.Compare(a[0], b[0]); c != 0 {
			return c
		}
		return strings.Compare(a[1], b[1])
	})
	cutoff := store.FormatTS(now.AddDate(0, 0, -recentDays))
	epssOn := st.EPSS == TierReady
	at := map[string]int{}
	var out []TierRecord
	var cves []string
	for len(want) > 0 {
		n := min(len(want), tierChunk)
		part, err := json.Marshal(want[:n]) // one parameter: the products as a JSON array (json_each), no SQL built from strings
		if err != nil {
			return nil, fmt.Errorf("feeds: tier records: %w", err)
		}
		want = want[n:]
		rs, err := db.QueryContext(ctx, `SELECT a.cve, a.cpe, a.start_incl, a.start_excl, a.end_incl, a.end_excl, a.platforms, r.published, e.epss, e.percentile
FROM json_each(?) j JOIN feeds_cve_range a ON a.vendor = json_extract(j.value, '$[0]') AND a.product = json_extract(j.value, '$[1]') AND a.origin = 'nvd'
JOIN feeds_cve r ON r.cve = a.cve LEFT JOIN feeds_epss e ON e.cve = a.cve
WHERE r.published >= ? AND r.nvd_status <> 'Rejected' ORDER BY a.cve, a.id`, string(part), cutoff)
		if err != nil {
			return nil, fmt.Errorf("feeds: tier records: %w", err)
		}
		for rs.Next() {
			var (
				cve, pub string
				af       AffectedRow
				ep, pc   sql.NullFloat64
				pl       sql.NullString
			)
			if err := rs.Scan(&cve, &af.CPE, &af.StartIncl, &af.StartExcl, &af.EndIncl, &af.EndExcl, &pl, &pub, &ep, &pc); err != nil {
				_ = rs.Close()
				return nil, fmt.Errorf("feeds: tier records: %w", err)
			}
			if !kept[af.CPE] {
				continue
			}
			i, ok := at[cve]
			if !ok {
				p, err := parseTS(pub)
				if err != nil {
					continue // the CHECK keeps this from happening; never a guessed day
				}
				r := TierRecord{CVE: cve, Tier: "recent", Published: p}
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
				cves = append(cves, cve)
			}
			plats := []string{}
			if pl.Valid && json.Unmarshal([]byte(pl.String), &plats) != nil {
				plats = []string{}
			}
			out[i].Affected = append(out[i].Affected, af)
			out[i].Platforms = append(out[i].Platforms, plats)
		}
		if err := errors.Join(rs.Err(), rs.Close()); err != nil {
			return nil, fmt.Errorf("feeds: tier records: %w", err)
		}
	}
	if err := s.withSeverity(ctx, out, cves); err != nil {
		return nil, err
	}
	slices.SortStableFunc(out, func(a, b TierRecord) int { return strings.Compare(a.CVE, b.CVE) })
	return out, nil
}

// withSeverity sets Severity and Score of the records from the catalogue's scores (PickCVSS): the same score the findings show.
func (s *Store) withSeverity(ctx context.Context, recs []TierRecord, cves []string) error {
	scores, err := s.CVSSOf(ctx, cves)
	if err != nil {
		return err
	}
	for i := range recs {
		if c, ok := scores[recs[i].CVE]; ok {
			sc := c.Score
			recs[i].Severity, recs[i].Score = Severity(c.Score, c.Version), &sc
		}
	}
	return nil
}

// tierCVEs lists the CVEs of nvd-recent published since now minus 365 days while it is ready (the distribution feeds keep
// their fixed rows for the devices' packages); nil otherwise. About 105,000 short strings on a test box (2026-11-15).
func (s *Store) tierCVEs(ctx context.Context, now time.Time) (map[string]bool, error) {
	st, err := s.TierStatus(ctx, now)
	if err != nil || st.Recent != TierReady {
		return nil, err
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT cve FROM feeds_cve WHERE published >= ? AND nvd_at IS NOT NULL AND nvd_status <> 'Rejected'`, store.FormatTS(now.AddDate(0, 0, -recentDays)))
	if err != nil {
		return nil, fmt.Errorf("feeds: tier cves: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("feeds: tier cves: %w", err)
		}
		out[c] = true
	}
	return out, rows.Err()
}

// hasTierCVEs says whether tierCVEs would list any CVE, without reading them.
func (s *Store) hasTierCVEs(ctx context.Context, now time.Time) (bool, error) {
	st, err := s.TierStatus(ctx, now)
	if err != nil || st.Recent != TierReady {
		return false, err
	}
	var has bool
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM feeds_cve WHERE published >= ? AND nvd_at IS NOT NULL AND nvd_status <> 'Rejected')`, store.FormatTS(now.AddDate(0, 0, -recentDays))).Scan(&has); err != nil {
		return false, fmt.Errorf("feeds: tier cves: %w", err)
	}
	return has, nil
}

// DistroPackage is a source package of one release as the distributions' security data names it ("ubuntu", "24.04", "openssl").
// Release "" asks for every release of the distribution (an Alpine device whose OS names no branch: findings picks the branch).
type DistroPackage struct{ Distro, Release, Package string }

// TierDistro is the distributions' data for "Updates to plan" (TierDistroRecords).
type TierDistro struct {
	// Records are the CVEs of nvd-recent published since now minus 365 days for which a distribution feed that is on has a row (fixed,
	// not affected or open) of one of the packages asked for, each with those rows only (Distro; no NVD entries), and EPSS while
	// epss-all is ready. CVEs of the CISA list are in the answer too: findings drops them (they are findings).
	Records []TierRecord
	// Covered holds the releases ("ubuntu/24.04"; "alpine/" for a package asked with no release) among the packages' for which a feed
	// that is on stored rows in a pull made with the tier want-set (distro_packages set): a device of another release is not compared
	// (loading or failing).
	Covered map[string]bool
	// Known holds the packages ("alpine/openssh") a feed that is on has any row of, for any CVE and release: a package the
	// distribution's data never names has no word from it at all, and findings compares it with NVD's upstream ranges instead.
	Known map[string]bool
	// Loading holds the distributions the plan still waits for (DistroPlanLoading): a feed it reads is on and has never completed a pull.
	Loading map[string]bool
}

// TierDistroRecords reads the distributions' data of pkgs for "Updates to plan" (TierDistro). Nothing but Loading while nvd-recent is
// not ready.
func (s *Store) TierDistroRecords(ctx context.Context, now time.Time, pkgs []DistroPackage) (TierDistro, error) {
	out := TierDistro{Covered: map[string]bool{}, Known: map[string]bool{}}
	var err error
	if out.Loading, err = s.DistroPlanLoading(ctx); err != nil {
		return out, err
	}
	st, err := s.TierStatus(ctx, now)
	if err != nil || st.Recent != TierReady || len(pkgs) == 0 {
		return out, err
	}
	byRel := map[[2]string][]string{}
	byDistro := map[string][]string{}
	for _, p := range pkgs {
		k := [2]string{p.Distro, p.Release}
		byRel[k] = append(byRel[k], p.Package)
		byDistro[p.Distro] = append(byDistro[p.Distro], p.Package)
	}
	db := s.db.Reader()
	cutoff := store.FormatTS(now.AddDate(0, 0, -recentDays))
	epssOn := st.EPSS == TierReady
	at := map[string]int{}
	seen := map[string]bool{} // cve/distro/release/package: a package asked under its release and with none is read once
	for _, d := range slices.Sorted(maps.Keys(byDistro)) {
		if err := eachChunk(byDistro[d], func(part string) error {
			rs, err := db.QueryContext(ctx, `SELECT DISTINCT d.package FROM feeds_distro_fix d JOIN feeds_source s ON s.id = d.source_id
WHERE s.enabled = 1 AND d.distro = ? AND d.package IN (SELECT value FROM json_each(?))`, d, part)
			if err != nil {
				return err
			}
			defer func() { _ = rs.Close() }()
			for rs.Next() {
				var p string
				if err := rs.Scan(&p); err != nil {
					return err
				}
				out.Known[d+"/"+p] = true
			}
			return rs.Err()
		}); err != nil {
			return out, fmt.Errorf("feeds: tier distro: %w", err)
		}
	}
	for _, rel := range slices.SortedFunc(maps.Keys(byRel), func(a, b [2]string) int { return strings.Compare(a[0]+"/"+a[1], b[0]+"/"+b[1]) }) {
		var has bool
		// covered only once a pull made with the tier want-set stored rows for the release (distro_packages set, review r1 #3 of
		// #808): the CISA list's rows alone would show its devices compared with nothing to plan while the feed loads or fails
		if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM feeds_distro_fix d JOIN feeds_source s ON s.id = d.source_id
WHERE s.enabled = 1 AND s.distro_packages IS NOT NULL AND d.distro = ? AND (? = '' OR d.release = ?))`, rel[0], rel[1], rel[1]).Scan(&has); err != nil {
			return out, fmt.Errorf("feeds: tier distro: %w", err)
		}
		if !has {
			continue
		}
		out.Covered[rel[0]+"/"+rel[1]] = true
		if err := eachChunk(byRel[rel], func(part string) error {
			rs, err := db.QueryContext(ctx, `SELECT d.cve, d.release, d.package, d.status, COALESCE(d.fixed_version, ''), d.pro, r.published, e.epss, e.percentile
FROM feeds_distro_fix d JOIN feeds_source s ON s.id = d.source_id JOIN feeds_cve r ON r.cve = d.cve LEFT JOIN feeds_epss e ON e.cve = d.cve
WHERE s.enabled = 1 AND d.distro = ? AND (? = '' OR d.release = ?) AND d.package IN (SELECT value FROM json_each(?)) AND r.published >= ?
AND r.nvd_at IS NOT NULL AND r.nvd_status <> 'Rejected'
ORDER BY d.cve, d.release, d.package, d.source_id`, rel[0], rel[1], rel[1], part, cutoff)
			if err != nil {
				return err
			}
			defer func() { _ = rs.Close() }()
			for rs.Next() {
				var (
					cve, release, pkg, status, fixed, pub string
					pro                                   bool
					ep, pc                                sql.NullFloat64
				)
				if err := rs.Scan(&cve, &release, &pkg, &status, &fixed, &pro, &pub, &ep, &pc); err != nil {
					return err
				}
				if k := cve + "/" + rel[0] + "/" + release + "/" + pkg + "/" + status + "/" + fixed; seen[k] {
					continue
				} else {
					seen[k] = true
				}
				i, ok := at[cve]
				if !ok {
					p, err := parseTS(pub)
					if err != nil {
						continue // the CHECK keeps this from happening; never a guessed day
					}
					r := TierRecord{CVE: cve, Tier: "recent", Published: p}
					if epssOn && ep.Valid && pc.Valid {
						e, q := ep.Float64, pc.Float64
						r.EPSS, r.Percentile = &e, &q
						if e >= EPSSLikely {
							r.Tier = "likely"
						}
					}
					i = len(out.Records)
					at[cve] = i
					out.Records = append(out.Records, r)
				}
				out.Records[i].Distro = append(out.Records[i].Distro, DistroFix{Distro: rel[0], Release: release, Package: pkg, CVE: cve, Status: status, Fixed: fixed, Pro: pro})
			}
			return rs.Err()
		}); err != nil {
			return out, fmt.Errorf("feeds: tier distro: %w", err)
		}
	}
	cves := make([]string, len(out.Records))
	for i, r := range out.Records {
		cves[i] = r.CVE
	}
	return out, s.withSeverity(ctx, out.Records, cves)
}

// eachChunk calls fn with the sorted, distinct names as JSON arrays of at most tierChunk names (one parameter for json_each: no SQL
// built from strings).
func eachChunk(names []string, fn func(part string) error) error {
	names = slices.Compact(slices.Sorted(slices.Values(names)))
	for len(names) > 0 {
		n := min(len(names), tierChunk)
		part, err := json.Marshal(names[:n])
		if err != nil {
			return err
		}
		names = names[n:]
		if err := fn(string(part)); err != nil {
			return err
		}
	}
	return nil
}
