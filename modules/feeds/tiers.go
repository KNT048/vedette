package feeds

import (
	"context"
	"database/sql"
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

// tierCVEs lists the catalogue's CVEs the match pass reads (the distribution feeds keep their rows of the devices' packages for these,
// DistroWant.Tier): the match pass's own set (the wiring's MatchSet: a CVE of the catalogue that OutsideWindow does not set aside),
// whether NVD has analysed it yet or not, so a pair the matcher reaches never lacks the distribution's word because the pull left its
// CVE out. ready is false while nvd-recent is not loaded: the set is then what the catalogue holds now (it never shrinks below what the
// match pass reads), and the pull keeps no record of the packages it kept them for, so the pull after the load runs in full
// (distroPartial). About 112,000 short strings on a test box (2026-11-28).
func (s *Store) tierCVEs(ctx context.Context, now time.Time) (map[string]bool, bool, error) {
	st, err := s.TierStatus(ctx, now)
	if err != nil {
		return nil, false, err
	}
	w, err := s.Window(ctx, now)
	if err != nil {
		return nil, false, err
	}
	rows, err := s.db.Reader().QueryContext(ctx, w.readSQL())
	if err != nil {
		return nil, false, fmt.Errorf("feeds: tier cves: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, false, fmt.Errorf("feeds: tier cves: %w", err)
		}
		out[c] = true
	}
	return out, st.Recent == TierReady, rows.Err()
}

// readSQL is the CVEs of the catalogue (feeds_cve: every CVE with ranges or on an exploited list has a row) the reporting window lets
// the match pass read: every one but those OutsideWindow sets aside (published before the window and kept by no exploited-list entry,
// exploited signal or recent public exploit; a CVE with no date counts as recent); every one while every age is reported.
func (w Window) readSQL() string {
	if w.EveryAge {
		return `SELECT cve FROM feeds_cve`
	}
	return `SELECT cve FROM feeds_cve WHERE published IS NULL OR published >= ` + w.since() + ` OR cve IN (` + w.keptSQL() + `)`
}

// hasTierCVEs says whether tierCVEs would list any CVE, without reading them.
func (s *Store) hasTierCVEs(ctx context.Context, now time.Time) (bool, error) {
	st, err := s.TierStatus(ctx, now)
	if err != nil || st.Recent != TierReady {
		return false, err
	}
	w, err := s.Window(ctx, now)
	if err != nil {
		return false, err
	}
	var has bool
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT EXISTS (`+w.readSQL()+`)`).Scan(&has); err != nil {
		return false, fmt.Errorf("feeds: tier cves: %w", err)
	}
	return has, nil
}
