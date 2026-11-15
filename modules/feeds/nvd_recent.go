package feeds

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The NVD records of every CVE published in the last 12 months (tier 3, D-613, D-614). Measured 2026-11-15 without a key:
// 104,135 CVEs in the 12 months (19,630 + 26,874 + 57,631 in three 120-day windows); a page of 2,000 records was 1.2 MB
// on the wire (gzip) and 10.4 MB of JSON, answered in 13 s; NVD changes about 1,700 records a day. The first fill is about
// 105 requests of RecentPageSize records (about 60 MB on the wire, about 25 minutes with nvdPause between requests),
// spread over pulls of at most pullBudget: each page is stored as it comes and feeds_recent_cursor says where the next
// pull goes on. After a good pull, a daily update asks only for the records NVD changed since one day before it.
// Nothing of the customer is in a request: only the date window and the record number it starts at.
const (
	recentFeedID = "nvd-recent"
	// RecentPageSize records per request: about 5 MB of JSON at the measured 5.2 KB a record.
	RecentPageSize = 1000
	// recentMaxBytes caps one answer (three times the measured average page).
	recentMaxBytes = 16_000_000
	// recentDays is how far back tier 3 goes (kien 2026-11-15: "mọi cve trong 12 tháng").
	recentDays = 365
	// recentWindow is NVD's largest date range for one query (120 days).
	recentWindow = 120 * 24 * time.Hour
	// recentIncrementalDays: an update asks for the changes since one day before the last good pull, which NVD's
	// 120-day limit allows up to this age; an older box fills again.
	recentIncrementalDays = 100
	// recentMaxStatus caps NVD's vulnStatus ("Awaiting Analysis", "Deferred", ...).
	recentMaxStatus = 40
)

// RecentCVE is one NVD record as tier 3 keeps it.
type RecentCVE struct {
	CVE                     string
	Published, LastModified time.Time
	Status                  string   // NVD's vulnStatus; "Rejected" records are dropped
	Severity                string   // CVSS base severity of the newest CVSS version NVD gives (NVD's own first), "" when none
	Score                   *float64 // its base score
	Affected                []AffectedRow
}

// RecentPage is one parsed answer.
type RecentPage struct {
	Total, Returned int
	Records         []RecentCVE
	Stats
}

// RecentPageURL builds one request: base?pubStartDate=…&pubEndDate=… (byPublished, the first fill) or
// lastModStartDate=…&lastModEndDate=… (an update), &resultsPerPage=RecentPageSize&startIndex=start.
func RecentPageURL(base string, byPublished bool, from, to time.Time, start int) (string, error) {
	if err := CheckURL(base); err != nil {
		return "", err
	}
	if strings.ContainsAny(base, "?#") {
		return "", fail(ErrInvalidURL, "The NVD address must not carry a query string.")
	}
	const layout = "2006-01-02T15:04:05.000Z"
	a, b := "lastModStartDate", "lastModEndDate"
	if byPublished {
		a, b = "pubStartDate", "pubEndDate"
	}
	return fmt.Sprintf("%s?%s=%s&%s=%s&resultsPerPage=%d&startIndex=%d", strings.TrimSpace(base), a, from.UTC().Format(layout), b, to.UTC().Format(layout), RecentPageSize, start), nil
}

type cvssEntry struct {
	Type     string `json:"type"`
	CVSSData struct {
		BaseScore    *float64 `json:"baseScore"`
		BaseSeverity string   `json:"baseSeverity"`
	} `json:"cvssData"`
}

type recentAnswer struct {
	TotalResults    *int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			VulnStatus   string `json:"vulnStatus"`
			Metrics      struct {
				V40 []cvssEntry `json:"cvssMetricV40"`
				V31 []cvssEntry `json:"cvssMetricV31"`
				V30 []cvssEntry `json:"cvssMetricV30"`
			} `json:"metrics"`
			Configurations []struct {
				Nodes []struct {
					Negate   bool `json:"negate"`
					CPEMatch []struct {
						Vulnerable bool   `json:"vulnerable"`
						Criteria   string `json:"criteria"`
						StartIncl  string `json:"versionStartIncluding"`
						StartExcl  string `json:"versionStartExcluding"`
						EndIncl    string `json:"versionEndIncluding"`
						EndExcl    string `json:"versionEndExcluding"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

var cvssSeverities = map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "NONE": true}

// nvdTime reads NVD's timestamps ("2026-08-01T03:16:25.307", UTC, sometimes with a Z).
func nvdTime(s string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02T15:04:05", strings.TrimSuffix(strings.TrimSpace(s), "Z"))
	return t.UTC(), err == nil
}

// severityOf picks the CVSS severity tier 3 shows: the newest CVSS version present, NVD's own score ("Primary") before
// the CNA's ("Secondary"). An unknown severity or a score outside 0..10 is ignored.
func severityOf(lists ...[]cvssEntry) (string, *float64) {
	for _, l := range lists {
		for _, want := range []string{"Primary", "Secondary"} {
			for _, e := range l {
				sev := strings.ToUpper(strings.TrimSpace(e.CVSSData.BaseSeverity))
				if e.Type != want || !cvssSeverities[sev] {
					continue
				}
				if sc := e.CVSSData.BaseScore; sc != nil && *sc >= 0 && *sc <= 10 {
					v := *sc
					return sev, &v
				}
				return sev, nil
			}
		}
	}
	return "", nil
}

// ParseNVDRecent reads one NVD CVE API 2.0 answer for tier 3. A record with a bad id or dates is rejected, as is one with
// an unusable vulnerable entry (the whole record, as ParseNVD does: never half a configuration). A damaged answer fails.
func ParseNVDRecent(data []byte) (RecentPage, error) {
	if len(data) > recentMaxBytes {
		return RecentPage{}, fail(ErrTooLarge, "The NVD answer is larger than %d MB; Vedette would skip it.", recentMaxBytes/1_000_000)
	}
	var a recentAnswer
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&a); err != nil || a.TotalResults == nil {
		return RecentPage{}, fail(ErrBadSample, "The NVD answer is not the CVE API 2.0 format.")
	}
	out := RecentPage{Total: *a.TotalResults, Returned: len(a.Vulnerabilities), Records: make([]RecentCVE, 0, len(a.Vulnerabilities))}
	tl := newTally()
	for i, v := range a.Vulnerabilities {
		row := i + 1
		id := strings.ToUpper(strings.TrimSpace(v.CVE.ID))
		pub, okP := nvdTime(v.CVE.Published)
		mod, okM := nvdTime(v.CVE.LastModified)
		status := strings.TrimSpace(v.CVE.VulnStatus)
		switch {
		case !cveRE.MatchString(id) || len(id) > 32:
			tl.reject(row, "id: %s is not a CVE ID", quoteVal(v.CVE.ID))
			continue
		case !okP || !okM:
			tl.reject(row, "%s: the dates are not NVD timestamps", id)
			continue
		case status == "" || len(status) > recentMaxStatus || !printableASCII(status):
			tl.reject(row, "%s: vulnStatus %s is not usable", id, quoteVal(status))
			continue
		}
		rec := RecentCVE{CVE: id, Published: pub, LastModified: mod, Status: status, Affected: []AffectedRow{}}
		rec.Severity, rec.Score = severityOf(v.CVE.Metrics.V40, v.CVE.Metrics.V31, v.CVE.Metrics.V30)
		bad := ""
	entries:
		for _, c := range v.CVE.Configurations {
			for _, n := range c.Nodes {
				if n.Negate {
					continue
				}
				for _, m := range n.CPEMatch {
					if !m.Vulnerable {
						continue
					}
					r := AffectedRow{CPE: m.Criteria, StartIncl: m.StartIncl, StartExcl: m.StartExcl, EndIncl: m.EndIncl, EndExcl: m.EndExcl}
					if bad = badAffected(r); bad != "" || len(rec.Affected) >= nvdMaxRowsPerCVE {
						if bad == "" {
							bad = "more than " + strconv.Itoa(nvdMaxRowsPerCVE) + " entries"
						}
						break entries
					}
					rec.Affected = append(rec.Affected, r)
				}
			}
		}
		if bad != "" {
			tl.reject(row, "%s: %s", id, bad)
			continue
		}
		tl.Accepted++
		out.Records = append(out.Records, rec)
	}
	out.Stats = tl.stats()
	return out, nil
}

// recentCursor is how far an unfinished pull got (feeds_recent_cursor).
type recentCursor struct {
	URL              string
	Fill             bool // the first fill (by published date), else an update (by NVD's change date)
	From, To, Until  time.Time
	NextIndex, Total int
}

func (s *Store) recentCursor(ctx context.Context) (*recentCursor, error) {
	var (
		c             recentCursor
		mode, f, t, u string
	)
	err := s.db.Reader().QueryRowContext(ctx, `SELECT url, mode, win_from, win_to, until, next_index, total FROM feeds_recent_cursor WHERE id = 1`).
		Scan(&c.URL, &mode, &f, &t, &u, &c.NextIndex, &c.Total)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("feeds: recent cursor: %w", err)
	}
	c.Fill = mode == "fill"
	var e1, e2, e3 error
	c.From, e1 = parseTS(f)
	c.To, e2 = parseTS(t)
	c.Until, e3 = parseTS(u)
	if err := errors.Join(e1, e2, e3); err != nil {
		return nil, nil // a row Vedette cannot read: start again
	}
	return &c, nil
}

func saveRecentCursor(ctx context.Context, tx *sql.Tx, c *recentCursor) error {
	if c == nil {
		_, err := tx.ExecContext(ctx, `DELETE FROM feeds_recent_cursor`)
		return err
	}
	mode := "update"
	if c.Fill {
		mode = "fill"
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO feeds_recent_cursor (id, url, mode, win_from, win_to, until, next_index, total) VALUES (1, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET url = excluded.url, mode = excluded.mode, win_from = excluded.win_from, win_to = excluded.win_to, until = excluded.until, next_index = excluded.next_index, total = excluded.total`,
		c.URL, mode, store.FormatTS(c.From), store.FormatTS(c.To), store.FormatTS(c.Until), c.NextIndex, c.Total)
	return err
}

// storeRecentPage writes one page and the cursor after it in one transaction: a record published before cutoff (an update
// can return old CVEs NVD changed) or that NVD rejected is dropped; the others replace their row and entries. A feed edited
// or turned off meanwhile writes nothing (stale).
func storeRecentPage(ctx context.Context, tx *sql.Tx, recs []RecentCVE, cutoff time.Time) error {
	del, err := tx.PrepareContext(ctx, `DELETE FROM feeds_recent_cve WHERE cve = ?`)
	if err != nil {
		return err
	}
	defer func() { _ = del.Close() }()
	up, err := tx.PrepareContext(ctx, `INSERT INTO feeds_recent_cve (cve, published, last_modified, status, severity, score) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(cve) DO UPDATE SET published = excluded.published, last_modified = excluded.last_modified, status = excluded.status, severity = excluded.severity, score = excluded.score`)
	if err != nil {
		return err
	}
	defer func() { _ = up.Close() }()
	wipe, err := tx.PrepareContext(ctx, `DELETE FROM feeds_recent_affected WHERE cve = ?`)
	if err != nil {
		return err
	}
	defer func() { _ = wipe.Close() }()
	ins, err := tx.PrepareContext(ctx, `INSERT INTO feeds_recent_affected (cve, cpe, start_incl, start_excl, end_incl, end_excl) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer func() { _ = ins.Close() }()
	for _, r := range recs {
		if r.Published.Before(cutoff) || strings.EqualFold(r.Status, "Rejected") {
			if _, err := del.ExecContext(ctx, r.CVE); err != nil {
				return err
			}
			continue
		}
		var sev any
		if r.Severity != "" {
			sev = r.Severity
		}
		if _, err := up.ExecContext(ctx, r.CVE, store.FormatTS(r.Published), store.FormatTS(r.LastModified), r.Status, sev, r.Score); err != nil {
			return err
		}
		if _, err := wipe.ExecContext(ctx, r.CVE); err != nil {
			return err
		}
		for _, a := range r.Affected {
			if _, err := ins.ExecContext(ctx, r.CVE, a.CPE, a.StartIncl, a.StartExcl, a.EndIncl, a.EndExcl); err != nil {
				return err
			}
		}
	}
	return nil
}

// recentText is the feed's progress line while a pull is unfinished.
func recentText(c *recentCursor, stored int, paused bool) string {
	verb := "Updating"
	if c.Fill {
		verb = "Loading"
	}
	t := fmt.Sprintf("%s the CVEs of the last 12 months from NVD: %s stored so far", verb, grouped(stored))
	if c.Fill {
		t += fmt.Sprintf(", published up to %s", c.From.Format("2 Jan 2006"))
	}
	t += "."
	if paused {
		t += " Vedette goes on at the next check (every 5 minutes)."
	}
	return t
}

func (s *Service) setRecentText(t string) {
	s.nvdMu.Lock()
	defer s.nvdMu.Unlock()
	s.recent = t
}

func (s *Store) recentCount(ctx context.Context) (all, ranged int, err error) {
	err = s.db.Reader().QueryRowContext(ctx, `SELECT count(*), (SELECT count(DISTINCT cve) FROM feeds_recent_affected) FROM feeds_recent_cve`).Scan(&all, &ranged)
	if err != nil {
		err = fmt.Errorf("feeds: count recent CVEs: %w", err)
	}
	return all, ranged, err
}

// buildRecent runs (or goes on with) the paged pull of nvd-recent. The first fill asks for the CVEs published in each
// 120-day window from recentDays ago to the start of the pull; after a good pull younger than recentIncrementalDays, an
// update asks for the records NVD changed since one day before it. Every page is stored as it comes with the cursor after
// it, so a pull that stops (its budget, NVD busy after every try, nvd-kev pulling) loses nothing and returns errNVDPaused;
// the next pull goes on. A pull that got no page at all is a failure of the feed (its back-off applies). When the last
// page is in, CVEs published before the 12 months go and the feed records its counts.
func (s *Service) buildRecent(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	now := s.now()
	cur, err := s.st.recentCursor(ctx)
	if err != nil {
		return p, err
	}
	if cur == nil || cur.URL != src.URL {
		have, _, err := s.st.recentCount(ctx)
		if err != nil {
			return p, err
		}
		if have > 0 && src.Status == "ok" && src.LastSuccess != nil && now.Sub(*src.LastSuccess) < recentIncrementalDays*24*time.Hour {
			cur = &recentCursor{URL: src.URL, From: src.LastSuccess.Add(-24 * time.Hour), To: now, Until: now}
		} else {
			from := now.AddDate(0, 0, -recentDays)
			cur = &recentCursor{URL: src.URL, Fill: true, From: from, To: minTime(from.Add(recentWindow), now), Until: now}
		}
	}
	run := &nvdRun{} // nvdPage's busy and retry fields; the progress line of this feed is s.recent
	pages, bytesRead := 0, 0
	var st Stats
	paused := func(why error) (pullPlan, error) {
		stored, _, _ := s.st.recentCount(ctx)
		s.setRecentText(recentText(cur, stored, true))
		if pages == 0 && !errors.Is(why, errNVDPaused) {
			if nvdRetryable(why) && ctx.Err() == nil {
				return p, &Error{Err: why, Detail: nvdBusy(why) + ", after every try. Vedette tries again later; the CVEs stored so far are kept."}
			}
			return p, why
		}
		s.Log.InfoContext(ctx, "the NVD pull of recent CVEs paused; it goes on later", "pages", pages, "error", why)
		return p, errNVDPaused
	}
	cutoff := now.AddDate(0, 0, -recentDays)
	for {
		if s.busy(nvdFeedID) { // one NVD pull at a time: NVD allows 5 requests in 30 s without a key
			return paused(errNVDPaused)
		}
		if pages > 0 {
			if err := s.sleep(ctx, nvdPause); err != nil {
				return paused(err)
			}
		}
		u, err := RecentPageURL(src.URL, cur.Fill, cur.From, cur.To, cur.NextIndex)
		if err != nil {
			return p, err
		}
		stored, _, _ := s.st.recentCount(ctx)
		s.setRecentText(recentText(cur, stored, false))
		resp, err := s.nvdPage(ctx, run, u, recentMaxBytes)
		if err != nil {
			return paused(err)
		}
		d, err := ParseNVDRecent(resp.Body)
		if err != nil {
			return paused(err)
		}
		if d.Returned == 0 && cur.NextIndex < d.Total {
			return paused(fail(ErrBadSample, "NVD answered an empty page at record %d of %d; Vedette kept the CVEs it had.", cur.NextIndex, d.Total))
		}
		next := *cur
		next.NextIndex += d.Returned
		next.Total = d.Total
		done := false
		if next.NextIndex >= d.Total {
			if next.Fill && next.To.Before(next.Until) {
				next.From, next.To, next.NextIndex, next.Total = next.To, minTime(next.To.Add(recentWindow), next.Until), 0, 0
			} else {
				done = true
			}
		}
		stale := false
		err = s.DB.Write(ctx, func(tx *sql.Tx) error {
			row, err := sourceTx(ctx, tx, src.ID)
			if err != nil {
				return err
			}
			if row.Rev != src.Rev || !row.Enabled {
				stale = true
				return nil
			}
			if err := storeRecentPage(ctx, tx, d.Records, cutoff); err != nil {
				return fmt.Errorf("feeds: store recent CVEs: %w", err)
			}
			if done {
				if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_recent_cve WHERE published < ?`, store.FormatTS(cutoff)); err != nil {
					return fmt.Errorf("feeds: prune recent CVEs: %w", err)
				}
				return saveRecentCursor(ctx, tx, nil)
			}
			return saveRecentCursor(ctx, tx, &next)
		})
		if err != nil {
			return p, err
		}
		if stale {
			s.setRecentText("")
			return p, ErrFeedDisabled // pullOne finds the row changed and writes nothing
		}
		pages++
		bytesRead += len(resp.Body)
		st.Accepted += d.Accepted
		st.Rejected += d.Rejected
		if len(st.Reasons) < 3 {
			st.Reasons = append(st.Reasons, d.Reasons...)
		}
		cur = &next
		if done {
			break
		}
	}
	s.setRecentText("")
	all, ranged, err := s.st.recentCount(ctx)
	if err != nil {
		return p, err
	}
	if len(st.Reasons) > 3 {
		st.Reasons = st.Reasons[:3]
	}
	p.out = outcome{OK: true, Bytes: bytesRead}
	p.out.fill(st, all)
	line := fmt.Sprintf("%s CVEs published since %s; NVD gives affected versions for %s of them.", grouped(all), cutoff.Format("2 Jan 2006"), grouped(ranged))
	p.out.Note = strings.TrimSpace(line + " " + p.out.Note)
	return p, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
