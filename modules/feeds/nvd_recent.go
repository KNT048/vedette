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
	// recentMaxStatus caps NVD's vulnStatus ("Awaiting Analysis", "Deferred", ...).
	recentMaxStatus = 40
	// recentSmallPage: a page that came back too large or unreadable is asked again with this many records.
	recentSmallPage = 250
	// recentMaxTotal bounds the records of one window (57,631 in the busiest 120 days measured): more is a broken answer.
	recentMaxTotal = 150_000
	// recentResumeStale: an update window that ended longer ago than this is asked again up to now (as nvd-kev's
	// nvdIncrementalStale), and a pull finished that late catches up at once.
	recentResumeStale = 12 * time.Hour
	// recentMaxSpan: the longest change window asked for; a longer gap fills again. NVD allows 120 days, but at ~1,700
	// changes a day an update over ~60 days asks for more records than a refill of 12 months (~105,000), and an
	// unfinished fill older than this starts over rather than finishing windows that have aged (review r2 #2, #3).
	recentMaxSpan = 60 * 24 * time.Hour
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
// lastModStartDate=…&lastModEndDate=… (an update), &resultsPerPage=size&startIndex=start.
func RecentPageURL(base string, byPublished bool, from, to time.Time, start, size int) (string, error) {
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
	return fmt.Sprintf("%s?%s=%s&%s=%s&resultsPerPage=%d&startIndex=%d", strings.TrimSpace(base), a, from.UTC().Format(layout), b, to.UTC().Format(layout), size, start), nil
}

type cvssEntry struct {
	Type     string `json:"type"`
	CVSSData struct {
		BaseScore    *float64 `json:"baseScore"`
		BaseSeverity string   `json:"baseSeverity"`
	} `json:"cvssData"`
}

// recentAnswer is one NVD answer; each record is decoded on its own (recentRecord), so one record of the wrong shape is rejected
// alone instead of failing the whole page (review r2 #9 of #802).
type recentAnswer struct {
	TotalResults    *int              `json:"totalResults"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
}

type recentRecord struct {
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
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&a); err != nil || a.TotalResults == nil || *a.TotalResults < 0 {
		return RecentPage{}, fail(ErrBadSample, "The NVD answer is not the CVE API 2.0 format.")
	}
	out := RecentPage{Total: *a.TotalResults, Returned: len(a.Vulnerabilities), Records: make([]RecentCVE, 0, len(a.Vulnerabilities))}
	tl := newTally()
	for i, raw := range a.Vulnerabilities {
		row := i + 1
		var v recentRecord
		if err := json.Unmarshal(raw, &v); err != nil {
			tl.reject(row, "the record is not an NVD CVE record")
			continue
		}
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

// Cursor modes of feeds_recent_cursor.
const (
	modeFill   = "fill"   // the first fill, by published date, window by window up to Until
	modeUpdate = "update" // the records NVD changed between From and To
	modeDone   = "done"   // nothing pending; the data is complete up to Until
)

// recentCursor is where nvd-recent stands (feeds_recent_cursor): an unfinished pull, or after a finished one the time
// its data is complete up to, where the next update starts (review r1 #2: a fill longer than a day leaves no gap).
type recentCursor struct {
	URL              string
	Mode             string
	From, To, Until  time.Time
	NextIndex, Total int
}

func (c *recentCursor) fill() bool { return c.Mode == modeFill }

func (s *Store) recentCursor(ctx context.Context) (*recentCursor, error) {
	var (
		c       recentCursor
		f, t, u string
	)
	err := s.db.Reader().QueryRowContext(ctx, `SELECT url, mode, win_from, win_to, until, next_index, total FROM feeds_recent_cursor WHERE id = 1`).
		Scan(&c.URL, &c.Mode, &f, &t, &u, &c.NextIndex, &c.Total)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("feeds: recent cursor: %w", err)
	}
	var e1, e2, e3 error
	c.From, e1 = parseTS(f)
	c.To, e2 = parseTS(t)
	c.Until, e3 = parseTS(u)
	if err := errors.Join(e1, e2, e3); err != nil {
		return nil, nil // a row Vedette cannot read: start again
	}
	return &c, nil
}

func saveRecentCursor(ctx context.Context, tx *sql.Tx, c recentCursor) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO feeds_recent_cursor (id, url, mode, win_from, win_to, until, next_index, total) VALUES (1, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET url = excluded.url, mode = excluded.mode, win_from = excluded.win_from, win_to = excluded.win_to, until = excluded.until, next_index = excluded.next_index, total = excluded.total`,
		c.URL, c.Mode, store.FormatTS(c.From), store.FormatTS(c.To), store.FormatTS(c.Until), c.NextIndex, c.Total)
	return err
}

// recentStart decides what a pull of nvd-recent does (review r1 #1, #2), whatever the feed's last status was:
//   - an unfinished fill goes on (its windows end at its own Until; the update after it starts there);
//   - an unfinished update goes on; if its window ended more than recentResumeStale ago, it asks again from its From to
//     now, so the next update, which starts one day before this one's end, leaves no gap;
//   - after a finished pull, an update from one day before the time the data is complete up to;
//   - a fill when there is no data, the address changed, or the gap is longer than NVD's window allows.
func recentStart(cur *recentCursor, url string, have int, now time.Time) recentCursor {
	fill := func() recentCursor {
		from := now.AddDate(0, 0, -recentDays)
		return recentCursor{URL: url, Mode: modeFill, From: from, To: minTime(from.Add(recentWindow), now), Until: now}
	}
	if cur == nil || cur.URL != url || have == 0 && cur.Mode != modeFill {
		return fill()
	}
	switch cur.Mode {
	case modeFill:
		if now.Sub(cur.Until) > recentMaxSpan {
			return fill()
		}
		return *cur
	case modeUpdate:
		c := *cur
		if now.Sub(c.To) > recentResumeStale {
			c.To, c.Until, c.NextIndex, c.Total = now, now, 0, 0
		}
		if c.To.Sub(c.From) > recentMaxSpan {
			return fill()
		}
		return c
	}
	from := cur.Until.Add(-24 * time.Hour)
	if now.Sub(from) > recentMaxSpan {
		return fill()
	}
	return recentCursor{URL: url, Mode: modeUpdate, From: from, To: now, Until: now}
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

// recentText is the feed's progress line while a pull is unfinished; busy is why NVD's last try failed and retryAt when
// that page is tried again (nvdPage), shown while the pull waits or pauses.
func recentText(c recentCursor, stored int, paused bool, busy string, retryAt, now time.Time) string {
	verb := "Updating"
	if c.fill() {
		verb = "Loading"
	}
	t := fmt.Sprintf("%s the CVEs of the last 12 months from NVD: %s stored so far", verb, grouped(stored))
	if c.fill() {
		t += fmt.Sprintf(", published up to %s", c.From.Format("2 Jan 2006"))
	}
	t += "."
	if busy != "" {
		t += " " + busy + "."
	}
	if wait := retryAt.Sub(now); busy != "" && wait > 0 {
		return t + " Vedette tries again in " + roughly(wait) + "."
	}
	if paused {
		t += " Vedette goes on at the next check (every 5 minutes)."
	}
	return t
}

// recentProgress is where an unfinished nvd-recent pull stands; live() writes its line from it, with run's busy reason and retry
// time as they are at that moment (nvdPage sets them under nvdMu).
type recentProgress struct {
	cur    recentCursor
	stored int
	paused bool
	run    *nvdRun
}

// setRecent records the pull's progress (nil: no pull unfinished) and when a paused pull goes on (zero: at the next check).
func (s *Service) setRecent(p *recentProgress, resumeAt time.Time) {
	s.nvdMu.Lock()
	defer s.nvdMu.Unlock()
	s.recent, s.recentAt = p, resumeAt
}

// recentResumeAt is when a paused nvd-recent pull goes on; zero when nothing holds it back.
func (s *Service) recentResumeAt() time.Time {
	s.nvdMu.Lock()
	defer s.nvdMu.Unlock()
	return s.recentAt
}

func (s *Store) recentCount(ctx context.Context) (all, ranged int, err error) {
	err = s.db.Reader().QueryRowContext(ctx, `SELECT count(*), (SELECT count(DISTINCT cve) FROM feeds_recent_affected) FROM feeds_recent_cve`).Scan(&all, &ranged)
	if err != nil {
		err = fmt.Errorf("feeds: count recent CVEs: %w", err)
	}
	return all, ranged, err
}

// buildRecent runs (or goes on with) the paged pull of nvd-recent (recentStart says what it asks for). Every page is
// stored as it comes with the cursor after it, so a pull that stops (its budget, NVD busy after every try, another NVD pull
// running or waiting out NVD) loses nothing and returns errNVDPaused; the next pull goes on. A pull that got no page at all
// is a failure of the feed (its error is shown, its back-off applies). When the last page is in, CVEs published before the
// 12 months go, the cursor says up to when the data is complete, and the feed records its counts.
func (s *Service) buildRecent(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	now := s.now()
	saved, err := s.st.recentCursor(ctx)
	if err != nil {
		return p, err
	}
	have, _, err := s.st.recentCount(ctx)
	if err != nil {
		return p, err
	}
	cur := recentStart(saved, src.URL, have, now)
	run := &nvdRun{} // nvdPage's busy reason and retry time, shown in the progress line (s.recent)
	pages, bytesRead, stored := 0, 0, have
	var st Stats
	progress := func(paused bool) *recentProgress {
		return &recentProgress{cur: cur, stored: stored, paused: paused, run: run}
	}
	stop := func(why error) (pullPlan, error) {
		if pages == 0 && !errors.Is(why, errNVDPaused) { // a failure: the feed shows its error, not a progress line (review r1 #4)
			s.setRecent(nil, time.Time{})
			if nvdRetryable(why) && ctx.Err() == nil {
				return p, &Error{Err: why, Detail: nvdBusy(why) + ", after every try. Vedette tries again later; the CVEs stored so far are kept."}
			}
			return p, why
		}
		s.nvdMu.Lock()
		resume := time.Time{}
		if run.busy != "" && run.retryAt.After(s.now()) {
			resume = run.retryAt
		}
		s.nvdMu.Unlock()
		s.setRecent(progress(true), resume)
		s.Log.InfoContext(ctx, "the NVD pull of recent CVEs paused; it goes on later", "pages", pages, "error", why)
		return p, errNVDPaused
	}
	cutoff := now.AddDate(0, 0, -recentDays)
	for {
		if s.busy(nvdFeedID) { // one NVD pull at a time (the request gate in nvdPage spaces the requests of both)
			return stop(errNVDPaused)
		}
		if at, paused := s.nvdResumeAt(); paused && s.now().Before(at) { // nvd-kev waits out NVD: so does this feed
			return stop(errNVDPaused)
		}
		s.setRecent(progress(false), time.Time{})
		var d RecentPage
		var body int
		for _, size := range []int{RecentPageSize, recentSmallPage} { // a page too large or unreadable is asked again smaller (review r1 #6)
			u, err := RecentPageURL(src.URL, cur.fill(), cur.From, cur.To, cur.NextIndex, size)
			if err != nil {
				return p, err
			}
			var resp *Response
			if resp, err = s.nvdPage(ctx, run, u, cur.NextIndex, recentMaxBytes); err == nil {
				s.nvdMu.Lock()
				run.busy, run.retryAt = "", time.Time{} // NVD answered: the line stops saying it was busy (review r2 #5 of #802)
				s.nvdMu.Unlock()
				body = len(resp.Body)
				d, err = ParseNVDRecent(resp.Body)
			}
			if err == nil || size == recentSmallPage || !errors.Is(err, ErrTooLarge) && !errors.Is(err, ErrBadSample) {
				if err != nil {
					return stop(err)
				}
				break
			}
		}
		if d.Total > recentMaxTotal && !cur.fill() { // NVD changed more than a refill would ask: fill instead (review r2 #2)
			s.Log.InfoContext(ctx, "NVD changed too many records for an update; filling the 12 months again", "changed", d.Total)
			cur = recentStart(nil, src.URL, 0, now)
			continue
		}
		if d.Total > recentMaxTotal {
			return stop(fail(ErrBadSample, "NVD answered %s records for one window, more than Vedette expects (%s); it kept the CVEs it had.", grouped(d.Total), grouped(recentMaxTotal)))
		}
		if d.Returned > RecentPageSize { // review r2 #10: more records than asked for is not NVD's answer
			return stop(fail(ErrBadSample, "NVD answered %d records for a page of %d; Vedette kept the CVEs it had.", d.Returned, RecentPageSize))
		}
		if d.Returned == 0 && cur.NextIndex < d.Total {
			return stop(fail(ErrBadSample, "NVD answered an empty page at record %d of %d; Vedette kept the CVEs it had.", cur.NextIndex, d.Total))
		}
		next := cur
		next.NextIndex += d.Returned
		next.Total = d.Total
		done := false
		if next.NextIndex >= d.Total {
			switch {
			case next.fill() && next.To.Before(next.Until):
				next.From, next.To, next.NextIndex, next.Total = next.To, minTime(next.To.Add(recentWindow), next.Until), 0, 0
			case now.Sub(next.Until) > recentResumeStale && now.Sub(next.Until.Add(-24*time.Hour)) <= recentMaxSpan:
				// a fill or update resumed late: catch up with NVD's changes since (a longer gap: done, and the next pull fills)
				next = recentCursor{URL: src.URL, Mode: modeUpdate, From: next.Until.Add(-24 * time.Hour), To: now, Until: now}
			default:
				done = true
				next = recentCursor{URL: src.URL, Mode: modeDone, From: next.Until, To: next.Until, Until: next.Until}
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
			}
			return saveRecentCursor(ctx, tx, next)
		})
		if err != nil {
			return p, err
		}
		if stale {
			s.setRecent(nil, time.Time{})
			return p, ErrFeedDisabled // pullOne finds the row changed and writes nothing
		}
		pages++
		bytesRead += body
		st.Accepted += d.Accepted
		st.Rejected += d.Rejected
		if len(st.Reasons) < 3 {
			st.Reasons = append(st.Reasons, d.Reasons...)
		}
		cur = next
		if done {
			break
		}
		if stored, _, err = s.st.recentCount(ctx); err != nil {
			return p, err
		}
	}
	s.setRecent(nil, time.Time{})
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
