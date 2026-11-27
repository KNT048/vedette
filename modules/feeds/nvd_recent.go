package feeds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/store"
)

// The catalogue pull of NVD records (nvd-recent): every CVE published in the window, then the records NVD changes, and, when many are
// missing, one pass over the whole NVD set for the older CVEs the retention rule keeps (an exploited-list entry, a signal of any age).
// Measured 2026-11-15 without a key: 104,135 CVEs in 12 months (19,630 + 26,874 + 57,631 in three 120-day windows); a page of 2,000
// records was 1.2 MB on the wire (gzip) and 10.4 MB of JSON, answered in 13 s; NVD changes about 1,700 records a day. The fill of the
// window is about 105 requests of RecentPageSize records (about 60 MB on the wire, about 25 minutes with nvdPause between requests),
// spread over pulls of at most pullBudget: each page is stored as it comes and feeds_nvd_cursor says where the next pull goes on.
// After a good pull, a daily update asks only for the records NVD changed since one day before it, and keeps those the retention rule
// keeps, whatever their age. Nothing of the customer is in a request: only the date window, the record number it starts at, or the
// id of a CVE a public list names.
const (
	recentFeedID = "nvd-recent"
	// RecentPageSize records per request: about 5 MB of JSON at the measured 5.2 KB a record.
	RecentPageSize = 1000
	// recentMaxBytes caps one answer (three times the measured average page).
	recentMaxBytes = 16_000_000
	// recentDays is the window of the fill: the catalogue's window.
	recentDays = windowDays
	// recentWindow is NVD's largest date range for one query (120 days).
	recentWindow = 120 * 24 * time.Hour
	// recentSmallPage: a page that came back too large or unreadable is asked again with this many records.
	recentSmallPage = 250
	// recentMaxTotal bounds the records of one window (57,631 in the busiest 120 days measured): more is a broken answer.
	recentMaxTotal = 150_000
	// recentResumeStale: an update window that ended longer ago than this is asked again up to now (as nvd-kev's
	// nvdIncrementalStale), and a pull finished that late catches up at once.
	recentResumeStale = 12 * time.Hour
	// recentMaxSpan: the longest change window asked for; a longer gap fills again. NVD allows 120 days, but at ~1,700
	// changes a day an update over ~60 days asks for more records than a refill of 12 months (~105,000), and an
	// unfinished fill older than this starts over rather than finishing windows that have aged.
	recentMaxSpan = 60 * 24 * time.Hour
	// walkPageSize records per request of the walk over the whole NVD set (NVD's largest page): about 165 requests for the whole set.
	walkPageSize = 2000
	// walkMaxBytes caps one page of the walk (three times the measured 10.4 MB of 2,000 records).
	walkMaxBytes = nvdMaxAnswer
	// walkMaxTotal bounds the records of the whole set (about 330,000 in 2026): more is a broken answer.
	walkMaxTotal = 1_500_000
	// walkMissing: a walk starts when at least this many kept CVEs have no NVD record (a new signal source loaded thousands of older
	// CVEs); fewer are asked for one by one (missingPerPull a pull).
	walkMissing = 300
	// walkAgain: a finished walk is not started again before this long, whatever is missing (some CVEs NVD has no record of).
	walkAgain = 7 * 24 * time.Hour
	// missingPerPull is the most CVEs one pull asks NVD for by id; missingAskAgain how long before the same one is asked again.
	missingPerPull  = 30
	missingAskAgain = 24 * time.Hour
)

// The selectors of feeds_nvd_cursor.
const (
	selectorRecent = "recent"
	selectorWalk   = "walk"
)

// Cursor modes of feeds_nvd_cursor.
const (
	modeFill   = "fill"   // the fill of the window, by published date, window by window up to Until
	modeWalk   = "walk"   // the walk over the whole NVD set, page by page
	modeUpdate = "update" // the records NVD changed between From and To
	modeDone   = "done"   // nothing pending; the data is complete up to Until
)

// recentCursor is where one selector of nvd-recent stands (feeds_nvd_cursor): an unfinished pull, or after a finished one the time
// its data is complete up to, where the next update starts (a fill longer than a day leaves no gap).
type recentCursor struct {
	URL              string
	Mode             string
	From, To, Until  time.Time
	NextIndex, Total int
}

func (c *recentCursor) fill() bool { return c.Mode == modeFill }

func (s *Store) recentCursor(ctx context.Context) (*recentCursor, error) {
	return s.nvdCursor(ctx, selectorRecent)
}

func (s *Store) nvdCursor(ctx context.Context, selector string) (*recentCursor, error) {
	var (
		c       recentCursor
		f, t, u string
	)
	err := s.db.Reader().QueryRowContext(ctx, `SELECT url, mode, win_from, win_to, until, next_index, total FROM feeds_nvd_cursor WHERE selector = ?`, selector).
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

func saveNVDCursor(ctx context.Context, tx *sql.Tx, selector string, c recentCursor) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO feeds_nvd_cursor (selector, url, mode, win_from, win_to, until, next_index, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(selector) DO UPDATE SET url = excluded.url, mode = excluded.mode, win_from = excluded.win_from, win_to = excluded.win_to, until = excluded.until, next_index = excluded.next_index, total = excluded.total`,
		selector, c.URL, c.Mode, store.FormatTS(c.From), store.FormatTS(c.To), store.FormatTS(c.Until), c.NextIndex, c.Total)
	return err
}

// recentComplete says the window of nvd-recent is complete for url: its last pull finished (mode done) at this address. Anything
// else (no cursor; an unfinished fill or update; another address) is a pull the feed still owes, due at the next check whatever its
// last success says. A done cursor with no CVE stored (only a source that answers nothing) waits for the feed's interval, so such a
// source is not asked every 5 minutes.
func recentComplete(cur *recentCursor, url string) bool {
	return cur != nil && cur.Mode == modeDone && cur.URL == url
}

// walkRunning says a walk over the whole NVD set is unfinished at url: the next check goes on with it.
func walkRunning(walk *recentCursor, url string) bool {
	return walk != nil && walk.Mode == modeWalk && walk.URL == url
}

// recentOwed says nvd-recent owes a pull at the next check, whatever its last success says: its window is not complete, or a walk is
// unfinished.
func (s *Store) recentOwed(ctx context.Context, url string) (bool, error) {
	cur, err := s.recentCursor(ctx)
	if err != nil {
		return false, err
	}
	walk, err := s.nvdCursor(ctx, selectorWalk)
	if err != nil {
		return false, err
	}
	now := time.Now()
	w, err := s.Window(ctx, now)
	if err != nil {
		return false, err
	}
	return !recentComplete(cur, url) || walkRunning(walk, url) || recentComplete(cur, url) && everyAgeOwed(w, walk, url, now), nil
}

// everyAgeOwed is true when an administrator switched on the CVEs of every age after the last pass over NVD's whole set began (or
// none ran): that pass stored only the older CVEs the window kept, so one more pass reads the whole set and stores every record. Not
// within everyAgeCooldown of the last pass's start: switching off and on again does not read the whole set twice in a day.
func everyAgeOwed(w Window, last *recentCursor, url string, now time.Time) bool {
	return w.EveryAge && (last == nil || last.URL != url || last.From.Before(w.Since) && now.Sub(last.From) >= everyAgeCooldown)
}

// everyAgeCooldown is the least time between two whole reads (NVD's set, the CVE Program's list) that the every-age switch starts.
const everyAgeCooldown = 24 * time.Hour

// recentIdleText is the progress line of nvd-recent while no pull is running and the data is not complete: where the
// next pull goes on, from the cursor; "" when the data is complete or cannot be read. next: the line says the next 5-minute
// check goes on (false during the back-off after a failure).
func (s *Service) recentIdleText(ctx context.Context, url string, next bool) string {
	cur, err := s.st.recentCursor(ctx)
	if err != nil {
		return ""
	}
	now := s.now()
	have, _, err := s.st.recentCount(ctx, now)
	if err != nil {
		return ""
	}
	if recentComplete(cur, url) {
		walk, err := s.st.nvdCursor(ctx, selectorWalk)
		if err != nil || !walkRunning(walk, url) {
			return ""
		}
		return walkText(*walk, next, "", time.Time{}, now)
	}
	return recentText(recentStart(cur, url, have, now), have, next, "", time.Time{}, now)
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

// recentText is the feed's progress line while a pull is unfinished; busy is why NVD's last try failed and retryAt when
// that page is tried again (nvdPage), shown while the pull waits or pauses.
func recentText(c recentCursor, stored int, paused bool, busy string, retryAt, now time.Time) string {
	verb := "Updating"
	if c.fill() {
		verb = "Loading"
	}
	t := fmt.Sprintf("%s the CVEs of the last 12 months from NVD: %s stored so far", verb, grouped(stored))
	if c.fill() {
		t += fmt.Sprintf(", published up to %s", orgtime.CalendarDay(c.From))
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

// walkText is the progress line of an unfinished walk over the whole NVD set.
func walkText(c recentCursor, paused bool, busy string, retryAt, now time.Time) string {
	t := "Reading the older CVEs the exploited lists and signals name from NVD's whole list"
	if c.Total > 0 {
		t += fmt.Sprintf(": record %s of %s", grouped(c.NextIndex), grouped(c.Total))
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
	walk   bool // cur is the walk's cursor
	stored int
	paused bool
	run    *nvdRun
}

// text is the progress line; called under nvdMu.
func (p *recentProgress) text(now time.Time) string {
	if p.walk {
		return walkText(p.cur, p.paused, p.run.busy, p.run.retryAt, now)
	}
	return recentText(p.cur, p.stored, p.paused, p.run.busy, p.run.retryAt, now)
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

// recentCount is how many catalogue CVEs were published inside the window (NVD did not reject them), and how many of those have NVD
// ranges.
func (s *Store) recentCount(ctx context.Context, now time.Time) (all, ranged int, err error) {
	err = s.db.Reader().QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = c.cve AND r.origin = 'nvd'))
FROM feeds_cve c WHERE c.published >= ? AND c.nvd_status <> 'Rejected'`, store.FormatTS(now.AddDate(0, 0, -recentDays))).Scan(&all, &ranged)
	if err != nil {
		err = fmt.Errorf("feeds: count recent CVEs: %w", err)
	}
	return all, ranged, err
}

// recentPull is one pull of nvd-recent as it goes: what it read, for the feed's outcome and the events.
type recentPull struct {
	src        sourceRow
	run        *nvdRun // nvdPage's busy reason and retry time, shown in the progress line (s.recent)
	pages      int
	bytes      int
	st         Stats
	kevChanged []string // exploited-list CVEs whose NVD ranges changed
	kevFirst   bool     // no exploited-list CVE had NVD's answer before this pull
	catalogue  bool     // a CVE on no exploited list was written
}

// storeNVDPage writes the records of one page the retention rule keeps and the cursor after it, in one transaction. A feed edited or
// turned off meanwhile writes nothing (stale).
func (s *Service) storeNVDPage(ctx context.Context, rp *recentPull, recs []NVDRecord, selector string, next recentCursor, now time.Time) (stale bool, err error) {
	pinned, err := s.pinned(ctx)
	if err != nil {
		return false, err
	}
	err = s.DB.Write(ctx, func(tx *sql.Tx) error {
		row, err := sourceTx(ctx, tx, rp.src.ID)
		if err != nil {
			return err
		}
		if row.Rev != rp.src.Rev || !row.Enabled {
			stale = true
			return nil
		}
		ret, err := retentionOf(ctx, tx, now, pinned)
		if err != nil {
			return err
		}
		w, err := writeNVDRecords(ctx, tx, recs, ret, now)
		if err != nil {
			return fmt.Errorf("feeds: store NVD records: %w", err)
		}
		rp.kevChanged = append(rp.kevChanged, w.KEVChanged...)
		rp.catalogue = rp.catalogue || w.Catalogue
		if selector == "" {
			return nil
		}
		return saveNVDCursor(ctx, tx, selector, next)
	})
	return stale, err
}

// buildRecent runs (or goes on with) the paged pull of nvd-recent (recentStart says what it asks for), then, once the window is
// complete, the catch-up of the older CVEs the retention rule keeps (catchUp). Every page is stored as it comes with the cursor after
// it, so a pull that stops (its budget, NVD busy after every try, another NVD pull running or waiting out NVD) loses nothing and
// returns errNVDPaused; the next pull goes on. A pull that got no page at all is a failure of the feed (its error is shown, its
// back-off applies). When the last page is in, the retention rule drops what aged out, the cursor says up to when the data is
// complete, and the feed records its counts.
func (s *Service) buildRecent(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	now := s.now()
	saved, err := s.st.recentCursor(ctx)
	if err != nil {
		return p, err
	}
	have, _, err := s.st.recentCount(ctx, now)
	if err != nil {
		return p, err
	}
	before, err := s.st.kevNVDCount(ctx)
	if err != nil {
		return p, err
	}
	rp := &recentPull{src: src, run: &nvdRun{}, kevFirst: before == 0}
	cur := recentStart(saved, src.URL, have, now)
	stored := have
	walking := false
	progress := func(paused bool) *recentProgress {
		return &recentProgress{cur: cur, walk: walking, stored: stored, paused: paused, run: rp.run}
	}
	stop := func(why error) (pullPlan, error) {
		if rp.pages == 0 && !errors.Is(why, errNVDPaused) { // a failure: the feed shows its error, not a progress line
			s.setRecent(nil, time.Time{})
			if nvdRetryable(why) && ctx.Err() == nil {
				return p, &Error{Err: why, Detail: nvdBusy(why) + ", after every try. Vedette tries again later; the CVEs stored so far are kept."}
			}
			return p, why
		}
		s.nvdMu.Lock()
		resume := time.Time{}
		if rp.run.busy != "" && rp.run.retryAt.After(s.now()) {
			resume = rp.run.retryAt
		}
		s.nvdMu.Unlock()
		s.setRecent(progress(true), resume)
		s.Log.InfoContext(ctx, "the NVD pull of the catalogue paused; it goes on later", "pages", rp.pages, "error", why)
		return p, errNVDPaused
	}
	waitTurn := func() bool { // one NVD pull at a time (the request gate in nvdPage spaces the requests of both)
		if s.busy(nvdFeedID) {
			return false
		}
		at, paused := s.nvdResumeAt() // nvd-kev waits out NVD: so does this feed
		return !paused || !s.now().Before(at)
	}
	if !recentComplete(saved, src.URL) || !rp.walkOrCatchUpOnly(ctx, s, now) {
		for done := false; !done; {
			if !waitTurn() {
				return stop(errNVDPaused)
			}
			s.setRecent(progress(false), time.Time{})
			var d NVDPage
			var body int
			for _, size := range []int{RecentPageSize, recentSmallPage} { // a page too large or unreadable is asked again smaller
				u, err := RecentPageURL(src.URL, cur.fill(), cur.From, cur.To, cur.NextIndex, size)
				if err != nil {
					return p, err
				}
				if body, d, err = s.nvdParsedPage(ctx, rp.run, u, cur.NextIndex, recentMaxBytes); err == nil || size == recentSmallPage ||
					!errors.Is(err, ErrTooLarge) && !errors.Is(err, ErrBadSample) {
					if err != nil {
						return stop(err)
					}
					break
				}
			}
			if d.Total > recentMaxTotal && !cur.fill() { // NVD changed more than a refill would ask: fill instead
				s.Log.InfoContext(ctx, "NVD changed too many records for an update; filling the window again", "changed", d.Total)
				cur = recentStart(nil, src.URL, 0, now)
				continue
			}
			if d.Total > recentMaxTotal {
				return stop(fail(ErrBadSample, "NVD answered %s records for one window, more than Vedette expects (%s); it kept the CVEs it had.", grouped(d.Total), grouped(recentMaxTotal)))
			}
			if d.Returned > RecentPageSize { // more records than asked for is not NVD's answer
				return stop(fail(ErrBadSample, "NVD answered %d records for a page of %d; Vedette kept the CVEs it had.", d.Returned, RecentPageSize))
			}
			if d.Returned == 0 && cur.NextIndex < d.Total {
				return stop(fail(ErrBadSample, "NVD answered an empty page at record %d of %d; Vedette kept the CVEs it had.", cur.NextIndex, d.Total))
			}
			next := cur
			next.NextIndex += d.Returned
			next.Total = d.Total
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
			stale, err := s.storeNVDPage(ctx, rp, d.Records, selectorRecent, next, now)
			if err != nil {
				return p, err
			}
			if stale {
				s.setRecent(nil, time.Time{})
				return p, ErrFeedDisabled // pullOne finds the row changed and writes nothing
			}
			rp.add(d, body)
			cur = next
			if stored, _, err = s.st.recentCount(ctx, now); err != nil {
				return p, err
			}
		}
	}
	// the window is complete: the older CVEs the retention rule keeps
	walking = true
	if err := s.catchUp(ctx, rp, now, waitTurn, func(c recentCursor) { cur = c; s.setRecent(progress(false), time.Time{}) }); err != nil {
		return stop(err)
	}
	s.setRecent(nil, time.Time{})
	pinned, err := s.pinned(ctx)
	if err != nil {
		return p, err
	}
	if err := s.DB.Write(ctx, func(tx *sql.Tx) error { return pruneCatalogue(ctx, tx, now, pinned) }); err != nil {
		return p, err
	}
	all, ranged, err := s.st.recentCount(ctx, now)
	if err != nil {
		return p, err
	}
	st := rp.st
	if len(st.Reasons) > 3 {
		st.Reasons = st.Reasons[:3]
	}
	p.out = outcome{OK: true, Bytes: rp.bytes}
	p.out.fill(st, all)
	line := fmt.Sprintf("%s CVEs published since %s; NVD gives affected versions for %s of them.", grouped(all), orgtime.CalendarDay(now.AddDate(0, 0, -recentDays)), grouped(ranged))
	if total, err := s.st.catalogueCount(ctx); err == nil && total > all {
		why := "exploited, with a public exploit of the last 12 months, or held by a finding"
		if w, err := s.st.Window(ctx, now); err == nil && w.EveryAge {
			why = "CVEs of every age are reported"
		}
		line += fmt.Sprintf(" The catalogue keeps %s older CVEs: %s.", grouped(total-all), why)
	}
	p.out.Note = strings.TrimSpace(line + " " + p.out.Note)
	p.kevRanges, p.kevRangesFirst, p.catalogueRanges = rp.kevChanged, rp.kevFirst, rp.catalogue
	return p, nil
}

// walkOrCatchUpOnly is true when the window is complete and current, so this pull only goes on with the catch-up of older CVEs (an
// unfinished walk, or CVEs to ask for by id).
func (rp *recentPull) walkOrCatchUpOnly(ctx context.Context, s *Service, now time.Time) bool {
	walk, err := s.st.nvdCursor(ctx, selectorWalk)
	return err == nil && walkRunning(walk, rp.src.URL) && rp.src.LastSuccess != nil && now.Sub(*rp.src.LastSuccess) < time.Duration(rp.src.IntervalHours)*time.Hour
}

func (rp *recentPull) add(d NVDPage, body int) {
	rp.pages++
	rp.bytes += body
	rp.st.Accepted += d.Accepted
	rp.st.Rejected += d.Rejected
	if len(rp.st.Reasons) < 3 {
		rp.st.Reasons = append(rp.st.Reasons, d.Reasons...)
	}
}

// nvdParsedPage fetches and parses one page.
func (s *Service) nvdParsedPage(ctx context.Context, run *nvdRun, u string, start int, maxBytes int64) (int, NVDPage, error) {
	resp, err := s.nvdPage(ctx, run, u, start, maxBytes)
	if err != nil {
		return 0, NVDPage{}, err
	}
	s.nvdMu.Lock()
	run.busy, run.retryAt = "", time.Time{} // NVD answered: the line stops saying it was busy
	s.nvdMu.Unlock()
	d, err := ParseNVD(resp.Body)
	return len(resp.Body), d, err
}

// catchUp gives the older CVEs the retention rule keeps their NVD record: when many have none (a new signal source loaded thousands of
// older CVEs), one walk over the whole NVD set, page by page (walkPageSize records, its own cursor, going on at the next check when
// the pull's budget ends); otherwise the few that have none are asked for by id (missing). Only CVEs a public list names are asked
// for by id: never one only a custom feed or the customer's own findings name.
func (s *Service) catchUp(ctx context.Context, rp *recentPull, now time.Time, waitTurn func() bool, show func(recentCursor)) error {
	url := rp.src.URL
	walk, err := s.st.nvdCursor(ctx, selectorWalk)
	if err != nil {
		return err
	}
	if !walkRunning(walk, url) {
		w, err := s.st.Window(ctx, now)
		if err != nil {
			return err
		}
		n, err := s.st.missingCount(ctx, w)
		if err != nil {
			return err
		}
		if !everyAgeOwed(w, walk, url, now) && (n < walkMissing || walk != nil && walk.URL == url && now.Sub(walk.Until) < walkAgain) {
			return s.askMissing(ctx, rp, now, waitTurn, missingPerPull, false)
		}
		walk = &recentCursor{URL: url, Mode: modeWalk, From: now, To: now, Until: now}
		s.Log.InfoContext(ctx, "reading NVD's whole list for the older CVEs the catalogue keeps", "missing", n)
	}
	cur := *walk
	for {
		if !waitTurn() {
			return errNVDPaused
		}
		show(cur)
		var (
			body int
			d    NVDPage
		)
		for _, size := range []int{walkPageSize, recentSmallPage} { // a page too large or unreadable is asked again smaller
			u, err := WalkPageURL(url, cur.NextIndex, size)
			if err != nil {
				return err
			}
			if body, d, err = s.nvdParsedPage(ctx, rp.run, u, cur.NextIndex, walkMaxBytes); err == nil || size == recentSmallPage ||
				!errors.Is(err, ErrTooLarge) && !errors.Is(err, ErrBadSample) {
				if err != nil {
					return err
				}
				break
			}
		}
		switch {
		case d.Total > walkMaxTotal:
			return fail(ErrBadSample, "NVD answered %s records for its whole list, more than Vedette expects (%s); it kept the CVEs it had.", grouped(d.Total), grouped(walkMaxTotal))
		case d.Returned > walkPageSize:
			return fail(ErrBadSample, "NVD answered %d records for a page of %d; Vedette kept the CVEs it had.", d.Returned, walkPageSize)
		case d.Returned == 0 && cur.NextIndex < d.Total:
			return fail(ErrBadSample, "NVD answered an empty page at record %d of %d; Vedette kept the CVEs it had.", cur.NextIndex, d.Total)
		}
		next := cur
		next.NextIndex += d.Returned
		next.Total = d.Total
		done := next.NextIndex >= d.Total
		if done {
			next.Mode = modeDone
		}
		stale, err := s.storeNVDPage(ctx, rp, d.Records, selectorWalk, next, now)
		if err != nil {
			return err
		}
		if stale {
			return ErrFeedDisabled
		}
		rp.add(d, body)
		cur = next
		if done {
			return nil
		}
	}
}

// askMissing asks NVD by id for the kept CVEs that have no NVD record yet (fetchMissing) and stores what NVD answers.
func (s *Service) askMissing(ctx context.Context, rp *recentPull, now time.Time, waitTurn func() bool, limit int, kevOnly bool) error {
	recs, body, err := s.fetchMissing(ctx, rp.run, rp.src.URL, now, waitTurn, limit, kevOnly, nil)
	if err != nil || len(recs) == 0 {
		return err
	}
	stale, err := s.storeNVDPage(ctx, rp, recs, "", recentCursor{}, now)
	if err != nil {
		return err
	}
	if stale {
		return ErrFeedDisabled
	}
	rp.add(NVDPage{Stats: Stats{Accepted: len(recs)}}, body)
	return nil
}

// fetchMissing asks NVD by id for the kept CVEs that have no NVD record yet (missingRecords), at most limit, each not asked again for
// missingAskAgain; have skips the CVEs the caller already holds a record of. kevOnly limits it to the exploited lists. A CVE NVD has no record of is skipped; NVD busy or failing ends the asking
// with what was read.
func (s *Service) fetchMissing(ctx context.Context, run *nvdRun, base string, now time.Time, waitTurn func() bool, limit int, kevOnly bool, have func(string) bool) ([]NVDRecord, int, error) {
	w, err := s.st.Window(ctx, now)
	if err != nil {
		return nil, 0, err
	}
	cves, err := s.st.missingRecords(ctx, w, kevOnly, 5000)
	if err != nil {
		return nil, 0, err
	}
	var (
		out   []NVDRecord
		bytes int
		asked int
	)
	for _, cve := range cves {
		if asked >= limit {
			break
		}
		if have != nil && have(cve) {
			continue
		}
		s.nvdMu.Lock()
		at, seen := s.nvdAsked[cve]
		s.nvdMu.Unlock()
		if seen && now.Sub(at) < missingAskAgain {
			continue
		}
		if !waitTurn() {
			break
		}
		asked++
		u, err := CVEIDURL(base, cve)
		if err != nil {
			return out, bytes, err
		}
		body, d, err := s.nvdParsedPage(ctx, run, u, 0, MaxBodyBytes)
		if err != nil && ctx.Err() != nil {
			return out, bytes, ctx.Err()
		}
		if err != nil && nvdRetryable(err) { // NVD busy or unreachable: this CVE and the rest at the next pull
			s.Log.InfoContext(ctx, "NVD did not answer for one CVE's record; it is asked again at the next pull", "cve", cve, "error", err)
			break
		}
		// NVD answered (with the record, without it, or with one Vedette refuses): not asked again for a while, and the next CVE goes on
		s.nvdMu.Lock()
		if s.nvdAsked == nil {
			s.nvdAsked = map[string]time.Time{}
		}
		s.nvdAsked[cve] = now
		s.nvdMu.Unlock()
		if err != nil {
			s.Log.InfoContext(ctx, "NVD's record of one CVE could not be used; it is asked again in a day", "cve", cve, "error", err)
			continue
		}
		bytes += body
		for _, r := range d.Records {
			if r.CVE == cve { // only the record asked for
				out = append(out, r)
			}
		}
	}
	return out, bytes, nil
}

// missingRecords lists the CVEs the retention rule keeps that a public list names (the CISA list, VulnCheck KEV, a signal the window
// keeps; kevOnly: the lists only) and that have no NVD record in the catalogue, newest ids first, at most limit.
func (s *Store) missingRecords(ctx context.Context, w Window, kevOnly bool, limit int) ([]string, error) {
	q := w.publicListedSQL()
	if kevOnly {
		q = missingKEVSQL
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT m.cve FROM (`+q+`) m LEFT JOIN feeds_cve c ON c.cve = m.cve WHERE c.nvd_at IS NULL
ORDER BY substr(m.cve, 5, 4) DESC, length(m.cve) DESC, m.cve DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("feeds: missing records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("feeds: missing records: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// publicSignalSources are the signal sources whose CVEs may be asked of NVD by id: public lists the box downloads whole. A source built
// from what the box itself sees (an IDS alert naming a CVE) is never one of them.
var publicSignalSources = []string{nucleiFeedID, metasploitFeedID, exploitDBFeedID, pocGitHubFeedID, msrcFeedID, ciscoFeedID, fortinetFeedID,
	chromeFeedID, androidFeedID, rapid7FeedID, gtiFeedID, appleClaimSource}

const missingKEVSQL = `SELECT cve FROM feeds_kev WHERE source_id IN ('cisa-kev', 'vulncheck-kev')`

// missingCount is how many kept CVEs a public list names have no NVD record (Window.publicListedSQL).
func (s *Store) missingCount(ctx context.Context, w Window) (int, error) {
	var n int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM (`+w.publicListedSQL()+`) m LEFT JOIN feeds_cve c ON c.cve = m.cve WHERE c.nvd_at IS NULL`).Scan(&n); err != nil {
		return 0, fmt.Errorf("feeds: missing records: %w", err)
	}
	return n, nil
}

// catalogueCount is how many CVEs the catalogue holds.
func (s *Store) catalogueCount(ctx context.Context) (int, error) {
	var n int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM feeds_cve`).Scan(&n); err != nil {
		return 0, fmt.Errorf("feeds: count catalogue: %w", err)
	}
	return n, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
