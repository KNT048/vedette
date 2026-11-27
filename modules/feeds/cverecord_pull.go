package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The pull of CVE records (feed cve-org, "CVE records"). Transport, measured 2026-11-20 from a 100 Mbit/s line:
//   - the whole list once: the CVE Program's daily archive (669 MB; 429,247 records; 61 s uncapped from that line), saved to a work file
//     and resumed where it stopped (Range, only while its size is the same), throttled to recordRate, then read entry by entry; only the
//     records the catalogue keeps are stored;
//   - then the changes: the repository's change log (deltaLog.json, 30 days of hourly changes, 1.9 MB compressed) says which records
//     changed since the box's data is complete; each day that is over is read from that day's end-of-day archive of changes (3 to 13 MB),
//     what it does not hold by its ID when every box keeps the CVE (recordKeep.askable), at most recordLeftPerPull a pull. About 10 to
//     20 MB a day, at most every recordDeltaEvery;
//   - by ID, every pull: the records of the CVEs an exploited list or a qualifying public signal names that the box has not read, or
//     that have no NVD ranges and were not read for recordRecheck (a new CISA entry has its vendor's versions at once);
//   - by ID, every pull once the whole list is read: the records still missing of the CVEs every box keeps (recordKeep.askable: named
//     by a public list or signal, or published inside the window) that entered the catalogue after the archives that would have
//     brought them (recordsBacklog), within recordIDBudget asks a pull;
//   - the whole list again, at most every recordOwnAgain, when a CVE only this box's own lists or signals keep has no record
//     (recordsOwn): such a CVE is never asked for by ID.
//
// Asking by ID would be about 110,000 requests for the catalogue and 2,000 to 7,000 a day for the changes: the archives are one
// request each. Nothing of the customer is in any request: the archives are the same for every box, and an ID is asked only when a
// public list or signal names it, never because a device or a finding does.
const (
	cveOrgFeedID = "cve-org"
	// recordsRepo is the feed's default address: the CVE Program's repository on GitHub.
	recordsRepo = "https://github.com/CVEProject/cvelistV5"
	// recordPerPull is the most records one pull asks for by ID for the lists and signals; recordRecheck how long before one without
	// NVD ranges is asked again.
	recordPerPull = 60
	recordRecheck = 12 * time.Hour
	// recordLeftPerPull is the most records of the change log one pull asks for by ID (what the day's archive does not hold).
	recordLeftPerPull = 400
	// recordIDBudget is the most records one pull asks for by ID in all (the lists and signals, the change log's leftovers, then the
	// backlog of recordsBacklog, which takes what the others left); recordBacklogBatch backlog records are written per transaction, so
	// a pull that stops loses at most one batch.
	recordIDBudget     = recordPerPull + recordLeftPerPull
	recordBacklogBatch = 100
	// recordDeltaEvery: the change log is read at most this often.
	recordDeltaEvery = 12 * time.Hour
	// recordArchiveKeep: the release files of a day stay published for about 4 days (the newest 100 hourly releases): data older than
	// this loads the whole list again (the days of changes it would need are gone), and an unfinished download older than this starts
	// over with a newer day.
	recordArchiveKeep = 3 * 24 * time.Hour
	// recordRescanUnread: when at least this many CVEs a list or signal names have no record (a new signal source named thousands of
	// older CVEs), the whole list is read again, at most every recordRescanAgain; fewer are asked for by ID.
	recordRescanUnread = 300
	recordRescanAgain  = 7 * 24 * time.Hour
	// recordOwnAgain: a CVE only this box's own lists or signals keep (a custom list, a box-built signal) is never asked for by ID, as
	// the ask would tell the source what this box watches; when one has no record, the whole list is read again early (recordsOwn),
	// at most this often. selectorRecordOwn is the row of feeds_nvd_cursor whose win_from is when the last such read started, so the
	// bound holds across restarts.
	recordOwnAgain    = 24 * time.Hour
	selectorRecordOwn = "cve_record_own"
	// recordArchiveMax bounds the daily archive (669 MB in 2026); recordLogMax the change log (31.7 MB uncompressed in 2026).
	recordArchiveMax = 3 << 30
	recordLogMax     = 256 << 20
	// recordRate bounds the archive download, in bytes a second (669 MB in about 3 minutes).
	recordRate = 4 << 20
	// recordBatch records are written per transaction.
	recordBatch = 500
	// recordReadReserve is the part of a pull's budget kept for reading the downloaded archive (about a minute measured).
	recordReadReserve = 4 * time.Minute
	// selectorRecord is the CVE records' row of feeds_nvd_cursor (where the paged pulls stand).
	selectorRecord = "cve_record"
	// recordReader is the revision of the reader that turns a record into ranges (recordRanges), stamped on the cursor's address
	// (recordCursorURL). Records are not stored whole, so a box whose records an older reader read reads the whole list again, once,
	// when this changes: "ranges-2" keeps the versions a vendor writes in its own notation (statedRows); "ranges-3" reads VMware's ESXi
	// versions written as words ("8.0 prior to ESXi80a-20842819", esxiTextRows); "ranges-4" keeps Juniper's fix per maintenance branch
	// ("22.3R2-S2, 22.3R3-S1") as one row per branch (branchFixes); "ranges-5" keeps, for a product with a version scheme, the ranges a
	// vendor states unaffected (unaffectedRows) and the rows of an entry limited to some models, with the models (statedRows); "ranges-6"
	// keeps a defaultStatus "unaffected" only from the vendor's own CNA (ownCNA); "ranges-7" leaves out a range inside one
	// letter-release branch alone ("1.1.1" before "1.1.1zk", letterBranch) instead of the product, so OpenSSL's numeric ranges beside
	// it are read; "ranges-8" reads the notations CNAs write inside the version fields (recordNotation): GitHub's comparators
	// ("= 8.9.6.1", ">= 2.0, < 2.3.1"), the product's name in front of a version ("openssl-1.1.0"), a fix per release train after
	// lessThan ("1.20.4,2.0.2,2.1.2"); "ranges-9" reads an entry limited to operating systems once per system (recordSystems)
	// instead of leaving the product's rows out, and keeps an entry's lone unaffected version above every affected row as the fix
	// of its line (lineFixOf); "ranges-10" reads a range written with a hyphen in "version" ("1.0-1.23") from the first release through
	// the second instead of as one release (hyphenRead).
	recordReader = "ranges-10"
	// recordRereadMark marks a cursor whose whole-list read replaces every stored record, a newer one too (recordsBulk).
	recordRereadMark = "-reread"
)

// recordCursorURL is the cursor's address for a feed address: the feed's, stamped with the reader's revision.
func recordCursorURL(feedURL string) string { return feedURL + "#" + recordReader }

// recordCursorFeed is the feed address of a cursor's address (without the reader's stamp).
func recordCursorFeed(cursorURL string) string {
	u, _, _ := strings.Cut(cursorURL, "#")
	return u
}

// recordPause is the wait between two records asked for by ID (a second, as the repository's raw files are a shared service);
// recordLeftPause between the change log's leftovers; recordRetryWaits the waits before the second and third try of a record the
// source answered busy. Vars for the tests (Service.wait replaces the real waits).
var (
	recordPause      = time.Second
	recordLeftPause  = 250 * time.Millisecond
	recordRetryWaits = []time.Duration{6 * time.Second, 30 * time.Second}
)

// recordHosts is the host GitHub serves a repository's release files from (a release download redirects there; measured 2026-11-20).
var recordHosts = []string{"release-assets.githubusercontent.com"}

// recordSource is where a feed address reads from: the record files, the release files and the hosts a release download may redirect
// to. The default address is GitHub's repository; any other address (a mirror) serves the same layout under itself.
type recordSource struct {
	records, releases string
	redirect          []string
}

func recordSourceOf(feedURL string) (recordSource, error) {
	if err := CheckURL(feedURL); err != nil {
		return recordSource{}, err
	}
	base := strings.TrimRight(strings.TrimSpace(feedURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.RawQuery != "" || u.Fragment != "" {
		return recordSource{}, fail(ErrInvalidURL, "The CVE records address must not carry a query string.")
	}
	src := recordSource{records: base + "/cves", releases: base + "/releases/download"}
	if strings.EqualFold(u.Host, "github.com") {
		src.records, src.redirect = "https://raw.githubusercontent.com"+u.EscapedPath()+"/main/cves", recordHosts
	}
	return src, nil
}

// archiveURL is a release file of day (UTC): the whole list as of that midnight (whole: the 23:00 release carries it), or every record
// changed that day (the end-of-day release, published about 00:40 the next day).
func (r recordSource) archiveURL(day time.Time, whole bool) string {
	d := day.UTC().Format(time.DateOnly)
	if whole {
		return r.releases + "/cve_" + d + "_2300Z/" + d + "_all_CVEs_at_midnight.zip.zip"
	}
	return r.releases + "/cve_" + d + "_at_end_of_day/" + d + "_delta_CVEs_at_end_of_day.zip"
}

// urgentOnlyKey marks a pull of the CVE records that follows a load of an exploited list: only the records asked for by ID (the
// list's new entries), so the list's alerts are not held back by a download.
type urgentOnlyKey struct{}

func urgentOnly(ctx context.Context) bool { b, _ := ctx.Value(urgentOnlyKey{}).(bool); return b }

// recordRun is one pull of the CVE records as it goes.
type recordRun struct {
	src        sourceRow
	from       recordSource
	byID       int // records read by ID
	asked      int // records asked for by ID (read or not)
	backlog    int // CVEs every box keeps still without a record after this pull (recordsBacklog)
	fromBulk   int // records read from the archives
	stored     int
	missing    int // records the source does not have (yet)
	tooLarge   int
	unreadable int
	bytes      int64
	kevChanged []string
	kevFirst   bool
	catalogue  bool // the matched rows of a CVE on no exploited list changed
	tl         *tally
	notes      []string
}

// buildCVERecords runs one pull: the records due by ID, then (unless the pull follows a list load) the whole list or its changes.
// Each part writes as it goes, in its own transactions, so a pull that stops loses nothing. A pull that read nothing because the source
// failed is a failure of the feed (its back-off applies); one that the box refused (its address) fails at once.
func (s *Service) buildCVERecords(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	from, err := recordSourceOf(src.URL)
	if err != nil {
		return p, err
	}
	now := s.now()
	run := &recordRun{src: src, from: from, kevFirst: true, tl: newTally()}
	errID := s.recordsByID(ctx, run, now)
	if refused(errID) || errors.Is(errID, ErrFeedDisabled) {
		return p, errID
	}
	var errBulk error
	if !urgentOnly(ctx) && errID == nil {
		errBulk = s.recordsBulk(ctx, run, now)
		if refused(errBulk) || errors.Is(errBulk, ErrFeedDisabled) || errors.Is(errBulk, errWorkFile) {
			return p, errBulk
		}
		if errors.Is(errBulk, errRecordsLater) {
			errBulk = nil // goes on at the next check: its note says so
		}
		if errBulk == nil {
			errBulk = s.recordsBacklog(ctx, run, now)
			if refused(errBulk) || errors.Is(errBulk, ErrFeedDisabled) {
				return p, errBulk
			}
		}
	}
	failed := errors.Join(errID, errBulk)
	if run.byID+run.fromBulk+run.missing+run.unreadable == 0 && run.bytes == 0 && failed != nil {
		if ctx.Err() == nil && nvdRetryable(failed) {
			return p, &Error{Err: failed, Detail: "The CVE Program's files (GitHub) were busy or did not answer, after every try. Vedette tries again later; the records read before are kept."}
		}
		return p, failed
	}
	total, err := recordCount(ctx, s.DB.Reader())
	if err != nil {
		return p, err
	}
	st := run.tl.stats()
	p.out = outcome{OK: true, Bytes: int(min(run.bytes, int64(^uint(0)>>1))), Records: total}
	p.out.Accepted, p.out.Rejected, p.out.Reasons = run.byID+run.fromBulk, st.Rejected, st.Reasons
	p.out.Note = run.note(failed)
	p.kevRanges, p.kevRangesFirst, p.catalogueRanges = run.kevChanged, run.kevFirst && len(run.kevChanged) > 0, run.catalogue
	return p, nil
}

// refused is an address the box refuses (the admin's address is wrong, or the box does not know its own yet): the pull fails.
func refused(err error) bool {
	return errors.Is(err, ErrRedirect) || errors.Is(err, ErrInvalidURL) || errors.Is(err, ErrBlockedAddress) || errors.Is(err, ErrBoxAddrsUnknown)
}

// note is the pull's own sentence: what it read, and what it left for later.
func (r *recordRun) note(failed error) string {
	var parts []string
	if r.fromBulk > 0 {
		parts = append(parts, fmt.Sprintf("read %s records from the CVE Program's archives", grouped(r.fromBulk)))
	}
	if r.byID > 0 {
		parts = append(parts, fmt.Sprintf("%s by their ID", grouped(r.byID)))
	}
	if r.missing > 0 {
		parts = append(parts, fmt.Sprintf("%s not published yet", grouped(r.missing)))
	}
	if r.unreadable+r.tooLarge > 0 {
		parts = append(parts, fmt.Sprintf("%s unreadable or too large", grouped(r.unreadable+r.tooLarge)))
	}
	t := ""
	if len(parts) > 0 {
		t = strings.ToUpper(parts[0][:1]) + parts[0][1:]
		if len(parts) > 1 {
			t += ", " + strings.Join(parts[1:], ", ")
		}
		t += "."
	}
	for _, n := range r.notes {
		t = strings.TrimSpace(t + " " + n)
	}
	if r.backlog > 0 {
		t = strings.TrimSpace(t + " " + fmt.Sprintf("%s CVEs of the catalogue still have no record: Vedette reads them by their ID, up to %s a pull.",
			grouped(r.backlog), grouped(recordIDBudget)))
	}
	if failed != nil && nvdRetryable(failed) {
		t = strings.TrimSpace(t + " The CVE Program's files stopped answering; Vedette goes on at the next check.")
	}
	return t
}

// errWorkFile is a failure to keep the daily archive on the box's disk: the pull fails with what to check, never as the source's fault.
var errWorkFile = errors.New("feeds: the CVE records work file")

// recordDiskMargin is the free space left over after the archive (the database and every other module share the disk); recordArchiveSize
// is the archive's size when the source has not said it yet (669 MB in 2026, with room to grow).
const (
	recordDiskMargin  = 512 << 20
	recordArchiveSize = 800 << 20
)

func diskError(err error) error {
	return &Error{Err: fmt.Errorf("%w: %w", errWorkFile, err), Detail: "Vedette could not write the CVE Program's whole list to this box's disk. Check the free disk space; the records read before are kept."}
}

// errRecordsLater ends a part of the pull that goes on at the next check (its budget is spent); not a failure.
var errRecordsLater = errors.New("feeds: the CVE records pull goes on later")

// ---- by ID ----

// recordsByID reads the records due by ID (Store.recordDue), one file each, recordPause apart. A record the source does not have (404),
// refuses (any other HTTP error that is not "busy") or that Vedette cannot read is counted, stamped (asked again after recordRecheck)
// and skipped, its stored data kept; a source that stays busy ends this part with what it read.
func (s *Service) recordsByID(ctx context.Context, run *recordRun, now time.Time) error {
	// Many listed CVEs without a record (a new signal source named thousands of older CVEs): those come from the next read of the
	// whole list (recordsBulk), not one file each; only the exploited lists' CVEs are still asked for by ID meanwhile.
	listed := publicListedSQL
	never, err := s.st.recordUnread(ctx)
	if err != nil {
		return err
	}
	if never >= recordRescanUnread {
		listed = missingKEVSQL
	}
	due, err := s.st.recordDueOf(ctx, listed, now, recordPerPull)
	if err != nil || len(due) == 0 {
		return err
	}
	recs, unread, err := s.recordsGet(ctx, run, due, recordPause)
	run.byID += len(recs)
	if werr := s.storeRecords(ctx, run, recs, unread, now); werr != nil {
		return werr
	}
	return err
}

// recordsBacklog reads by ID the records still missing of the CVEs every box keeps (Store.recordBacklog): a CVE that entered the
// catalogue, or a public list or signal, after the archive or the day's changes that would have brought its record (a new box whose
// signal indexes loaded after its first read of the whole list, an older CVE an exploit index names today, a CVE NVD published a while
// after the CVE Program). Only once the whole list is read with the current reader (before, the archive brings them all), with what
// the pull's recordIDBudget leaves, recordLeftPause apart, written recordBacklogBatch at a time so a pull that stops keeps what it
// read; it ends early, without failing, a minute before the pull's deadline. A record the source does not have is stamped like any
// by-ID ask (not asked again: the change log brings it once it is published).
func (s *Service) recordsBacklog(ctx context.Context, run *recordRun, now time.Time) error {
	cur, err := s.st.nvdCursor(ctx, selectorRecord)
	if err != nil || cur == nil || cur.Mode != modeDone || cur.URL != recordCursorURL(run.src.URL) {
		return err
	}
	cutoff := now.AddDate(0, 0, -windowDays)
	defer func() {
		if n, err := s.st.recordBacklogCount(ctx, cutoff); err == nil {
			run.backlog = n
		}
	}()
	limit := recordIDBudget - run.asked
	if limit <= 0 {
		return nil
	}
	due, err := s.st.recordBacklog(ctx, cutoff, limit)
	if err != nil || len(due) == 0 {
		return err
	}
	fctx := ctx
	if dl, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		fctx, cancel = context.WithDeadline(ctx, dl.Add(-time.Minute))
		defer cancel()
	}
	for i, chunk := range slices.Collect(slices.Chunk(due, recordBacklogBatch)) {
		if i > 0 {
			if err := s.sleep(fctx, recordLeftPause); err != nil {
				break
			}
		}
		recs, unread, gerr := s.recordsGet(fctx, run, chunk, recordLeftPause)
		run.byID += len(recs)
		if err := s.storeRecords(ctx, run, recs, unread, now); err != nil {
			return err
		}
		if gerr != nil {
			if fctx.Err() != nil && ctx.Err() == nil {
				return nil // the pull's time is nearly spent: the next pull goes on
			}
			return gerr
		}
	}
	if ctx.Err() == nil && fctx.Err() != nil {
		return nil
	}
	return ctx.Err()
}

// recordsGet asks for each record of cves by ID, pause apart. It returns the records read, the CVEs it could not read (to stamp), and
// why it stopped early (busy, refused address, the pull's end).
func (s *Service) recordsGet(ctx context.Context, run *recordRun, cves []string, pause time.Duration) (recs []CVERecord, unread []string, err error) {
	for i, cve := range cves {
		if i > 0 {
			if err := s.sleep(ctx, pause); err != nil {
				return recs, unread, err
			}
		}
		u, err := CVERecordURL(run.from.records, cve)
		if err != nil {
			return recs, unread, err
		}
		run.asked++
		resp, err := s.recordGet(ctx, u)
		var se *StatusError
		switch {
		case err == nil:
		case refused(err):
			return recs, unread, err
		case ctx.Err() != nil || nvdRetryable(err):
			return recs, unread, err
		case errors.As(err, &se) && se.Code == http.StatusNotFound:
			unread, run.missing = append(unread, cve), run.missing+1 // not published (yet): asked again after recordRecheck
			continue
		case errors.As(err, &se):
			unread = append(unread, cve) // this one file is refused (403, 410, 451…): the others go on
			run.tl.reject(i+1, "%s: HTTP %s", cve, strconv.Itoa(se.Code))
			continue
		default:
			unread, run.tooLarge = append(unread, cve), run.tooLarge+1
			continue
		}
		run.bytes += int64(len(resp.Body))
		rec, err := ParseCVERecord(resp.Body, cve)
		if err != nil { // a proxy page or a cut answer: the data stored before stays
			unread, run.unreadable = append(unread, cve), run.unreadable+1
			run.tl.reject(i+1, "%s: the record is not CVE JSON 5", cve)
			continue
		}
		recs = append(recs, rec)
	}
	return recs, unread, nil
}

// recordGet fetches one record, trying again after recordRetryWaits (or the source's Retry-After, at most 2 min) while it is busy.
func (s *Service) recordGet(ctx context.Context, u string) (*Response, error) {
	for try := 0; ; try++ {
		resp, err := s.get(ctx, Request{URL: u, MaxBytes: RecordMaxBytes})
		if err == nil || ctx.Err() != nil || !nvdRetryable(err) || try >= len(recordRetryWaits) {
			return resp, err
		}
		wait := recordRetryWaits[try]
		var se *StatusError
		if errors.As(err, &se) && se.RetryAfter > wait {
			wait = min(se.RetryAfter, 2*time.Minute)
		}
		if err := s.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// storeRecords writes records read (and stamps the CVEs that could not be read) in one transaction, unless the feed was edited or
// turned off meanwhile.
func (s *Service) storeRecords(ctx context.Context, run *recordRun, recs []CVERecord, unread []string, now time.Time) error {
	if len(recs)+len(unread) == 0 {
		return nil
	}
	pinned, err := s.pinned(ctx)
	if err != nil {
		return err
	}
	stale := false
	err = s.DB.Write(ctx, func(tx *sql.Tx) error {
		row, err := sourceTx(ctx, tx, run.src.ID)
		if err != nil {
			return err
		}
		if row.Rev != run.src.Rev || !row.Enabled {
			stale = true
			return nil
		}
		k, err := recordKeepOf(ctx, tx, now, pinned)
		if err != nil {
			return err
		}
		w, err := writeRecords(ctx, tx, recs, k, now)
		if err != nil {
			return err
		}
		ts := store.FormatTS(now)
		for _, cve := range unread {
			if err := ensureCVE(ctx, tx, cve, ts); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET record_at = ? WHERE cve = ?`, ts, cve); err != nil {
				return fmt.Errorf("feeds: CVE record %s: %w", cve, err)
			}
		}
		run.stored += w.Stored
		run.kevFirst = run.kevFirst && (len(w.KEVChanged) == 0 || w.KEVFirst)
		run.kevChanged = append(run.kevChanged, w.KEVChanged...)
		run.catalogue = run.catalogue || w.Catalogue
		return nil
	})
	if err == nil && stale {
		return ErrFeedDisabled
	}
	return err
}

// ---- the whole list and its changes ----

// recordsOwed says the CVE records owe a pull at the next check, whatever their last success says: the whole list is loading.
func (s *Store) recordsOwed(ctx context.Context, feedURL string) (bool, error) {
	cur, err := s.nvdCursor(ctx, selectorRecord)
	if err != nil {
		return false, err
	}
	return cur == nil || cur.Mode == modeFill || cur.URL != recordCursorURL(feedURL), nil
}

// recordsBulk loads the whole list when the box has none, its data is older than the change log reaches, its address changed, an older
// reader read the stored records (recordReader), many listed CVEs have no record, or a CVE only this box's own lists keep has none
// (recordsOwn); otherwise it reads the changes, at most every recordDeltaEvery. The read after a reader change replaces every stored record and goes back to the archive's midnight, so the
// changes since are read again through the change log; it is resumable like any read of the whole list.
func (s *Service) recordsBulk(ctx context.Context, run *recordRun, now time.Time) error {
	cur, err := s.st.nvdCursor(ctx, selectorRecord)
	if err != nil {
		return err
	}
	unread, err := s.st.recordUnread(ctx)
	if err != nil {
		return err
	}
	waiting, err := s.st.recordWaitingCount(ctx)
	if err != nil {
		return err
	}
	switch {
	case cur == nil || recordCursorFeed(cur.URL) != run.src.URL || now.Sub(cur.Until) > recordArchiveKeep:
		day := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
		return s.recordsWhole(ctx, run, recentCursor{URL: recordCursorURL(run.src.URL), Mode: modeFill, From: day, To: day, Until: day}, now)
	case cur.Mode == modeFill:
		c := *cur
		if now.Sub(c.From) > recordArchiveKeep { // that day's archive is gone: a newer one
			day := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
			c = recentCursor{URL: c.URL, Mode: modeFill, From: day, To: day, Until: day}
		}
		return s.recordsWhole(ctx, run, c, now)
	case cur.URL != recordCursorURL(run.src.URL): // an older reader read the stored records
		day := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
		run.notes = append(run.notes, "Vedette reads CVE records in a newer way: reading the whole list again.")
		return s.recordsWhole(ctx, run, recentCursor{URL: recordCursorURL(run.src.URL) + recordRereadMark, Mode: modeFill, From: day, To: day, Until: day}, now)
	case waiting > 0 && now.Sub(cur.From) >= recordRescanAgain:
		day := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
		run.notes = append(run.notes, fmt.Sprintf("%s changed records wait for a read of the whole list: reading it again.", grouped(waiting)))
		return s.recordsWhole(ctx, run, recentCursor{URL: recordCursorURL(run.src.URL), Mode: modeFill, From: day, To: day, Until: cur.Until}, now)
	case unread >= recordRescanUnread && now.Sub(cur.From) >= recordRescanAgain:
		day := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
		run.notes = append(run.notes, fmt.Sprintf("%s listed CVEs had no record: reading the whole list again.", grouped(unread)))
		return s.recordsWhole(ctx, run, recentCursor{URL: recordCursorURL(run.src.URL), Mode: modeFill, From: day, To: day, Until: cur.Until}, now)
	}
	if started, err := s.recordsOwn(ctx, run, *cur, now); started || err != nil {
		return err
	}
	if now.Sub(cur.To) >= recordDeltaEvery {
		return s.recordsChanges(ctx, run, *cur, now)
	}
	return nil
}

// recordsOwn starts a read of the whole list when a CVE only this box's own lists or signals keep has no record (Store.recordOwnUnread):
// such a CVE is never asked for by its ID, and without this its record would come only with the next read of the whole list for
// another reason, up to a week later or never. It starts only when the whole list is read (cur is done with the current reader: an
// unfinished read goes on as it is), when the archive it would read is newer than the one last read, and at most every recordOwnAgain
// (selectorRecordOwn, kept in the database). The read is the same as any other (recordsWhole: the archive's rate, the fetch log, the
// feed's back-off) and stamps afterwards the CVEs the list does not hold (stampNotInList), so a CVE the CVE Program never published
// starts no second one. started: this pull is that read.
func (s *Service) recordsOwn(ctx context.Context, run *recordRun, cur recentCursor, now time.Time) (started bool, err error) {
	day := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
	if cur.Mode != modeDone || cur.URL != recordCursorURL(run.src.URL) || !cur.From.Before(day) {
		return false, nil
	}
	last, err := s.st.nvdCursor(ctx, selectorRecordOwn)
	if err != nil {
		return false, err
	}
	if last != nil && !now.Before(last.From) && now.Sub(last.From) < recordOwnAgain {
		return false, nil
	}
	own, err := s.st.recordOwnUnread(ctx, now.AddDate(0, 0, -windowDays))
	if err != nil || own == 0 {
		return false, err
	}
	if err := s.saveRecordCursorAt(ctx, run, selectorRecordOwn, recentCursor{URL: recordCursorURL(run.src.URL), Mode: modeDone, From: now, To: now, Until: now}); err != nil {
		return false, err
	}
	run.notes = append(run.notes, fmt.Sprintf("%s CVEs kept only by this box's own lists or signals have no record: reading the whole list again (they are never asked for by their ID).", grouped(own)))
	return true, s.recordsWhole(ctx, run, recentCursor{URL: recordCursorURL(run.src.URL), Mode: modeFill, From: day, To: day, Until: cur.Until}, now)
}

// recordWorkDir is where the daily archive is kept while it downloads.
func (s *Service) recordWorkDir() string {
	d := s.DataDir
	if d == "" {
		d = os.TempDir()
	}
	return filepath.Join(d, "feeds-cve-records")
}

// recordsWhole downloads the daily archive of cur.From (resuming the bytes a pull before got), then reads it and stores the records
// the catalogue keeps. The cursor says how far the download is (next_index of total bytes); when the archive is read, the data is
// complete up to its midnight and the change log goes on from there. The file is deleted once read.
func (s *Service) recordsWhole(ctx context.Context, run *recordRun, cur recentCursor, now time.Time) error {
	dir := s.recordWorkDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return diskError(err)
	}
	name := cur.From.UTC().Format(time.DateOnly) + "_all.zip"
	path := filepath.Join(dir, name)
	if old, err := os.ReadDir(dir); err == nil { // a download of another day is of no use any more
		for _, e := range old {
			if e.Name() != name {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	done, err := s.downloadArchive(ctx, run, &cur, path)
	if errors.Is(err, errWorkFile) { // a full disk: the part downloaded goes, so it does not hold the space
		_ = os.Remove(path)
		cur.NextIndex, cur.Total = 0, 0
	}
	if serr := s.saveRecordCursor(ctx, run, cur); serr != nil {
		return serr
	}
	if err != nil || !done {
		if err == nil {
			err = errRecordsLater
			of := ""
			if cur.Total > 0 {
				of = fmt.Sprintf(" of %d", cur.Total>>20)
			}
			run.notes = append(run.notes, fmt.Sprintf("Downloading the CVE Program's whole list: %d%s MB; Vedette goes on at the next check.", cur.NextIndex>>20, of))
		}
		return err
	}
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < recordReadReserve/2 {
		run.notes = append(run.notes, "The CVE Program's whole list is downloaded; Vedette reads it at the next check.")
		return errRecordsLater
	}
	midnight := cur.From.UTC().Truncate(24 * time.Hour)
	if err := s.readArchive(ctx, run, path, midnight, now, strings.HasSuffix(cur.URL, recordRereadMark)); err != nil {
		if errors.Is(err, errArchive) { // a damaged file: download it again
			_ = os.Remove(path)
			cur.NextIndex, cur.Total = 0, 0
			_ = s.saveRecordCursor(ctx, run, cur)
		}
		return err
	}
	_ = os.Remove(path)
	until := midnight
	if cur.Until.After(until) { // a re-read of the whole list does not move back what the changes brought
		until = cur.Until
	}
	if err := s.stampNotInList(ctx, run, now); err != nil {
		return err
	}
	return s.saveRecordCursor(ctx, run, recentCursor{URL: recordCursorURL(run.src.URL), Mode: modeDone, From: midnight, To: time.Time{}, Until: until})
}

// stampNotInList stamps the kept CVEs a complete read of the whole list did not hold (an id the CVE Program never published, or one a
// list names wrongly), as a by-ID ask that found no record does: they no longer count as unread, so they neither hold back the by-ID
// asks nor start another read of the whole list a week later. Unless the feed was edited or turned off meanwhile.
func (s *Service) stampNotInList(ctx context.Context, run *recordRun, now time.Time) error {
	return s.DB.Write(ctx, func(tx *sql.Tx) error {
		row, err := sourceTx(ctx, tx, run.src.ID)
		if err != nil || row.Rev != run.src.Rev || !row.Enabled {
			return err
		}
		missing, err := stringSet(ctx, tx, `SELECT i.cve FROM (`+importantSQL+`) i LEFT JOIN feeds_cve c ON c.cve = i.cve WHERE c.record_at IS NULL`)
		if err != nil {
			return err
		}
		ts := store.FormatTS(now)
		for cve := range missing {
			if !cveRE.MatchString(cve) {
				continue
			}
			if err := ensureCVE(ctx, tx, cve, ts); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET record_at = ? WHERE cve = ?`, ts, cve); err != nil {
				return fmt.Errorf("feeds: CVE record %s: %w", cve, err)
			}
		}
		return nil
	})
}

// saveRecordCursor writes where the CVE records stand, unless the feed was edited or turned off meanwhile. The row is selectorRecord of
// feeds_nvd_cursor, the table of where each paged pull stands: fill (next_index of total bytes of the archive downloaded), done (until =
// the data is complete up to, win_to = the change log's last read, win_from = the day of the last whole list).
func (s *Service) saveRecordCursor(ctx context.Context, run *recordRun, c recentCursor) error {
	return s.saveRecordCursorAt(ctx, run, selectorRecord, c)
}

// saveRecordCursorAt writes the selector's row of feeds_nvd_cursor, unless the feed was edited or turned off meanwhile.
func (s *Service) saveRecordCursorAt(ctx context.Context, run *recordRun, selector string, c recentCursor) error {
	stale := false
	err := s.DB.Write(ctx, func(tx *sql.Tx) error {
		row, err := sourceTx(ctx, tx, run.src.ID)
		if err != nil {
			return err
		}
		if row.Rev != run.src.Rev || !row.Enabled {
			stale = true
			return nil
		}
		return saveNVDCursor(ctx, tx, selector, c)
	})
	if err == nil && stale {
		return ErrFeedDisabled
	}
	return err
}

// downloadArchive gets the rest of the daily archive into path (the file's size is where it goes on), at most recordRate bytes a second,
// until the pull's budget leaves only recordReadReserve. done: the file is whole.
func (s *Service) downloadArchive(ctx context.Context, run *recordRun, cur *recentCursor, path string) (done bool, err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // path is the module's own work file (recordWorkDir and a day's name)
	if err != nil {
		return false, diskError(err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = diskError(cerr)
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return false, diskError(err)
	}
	have := info.Size()
	total := int64(cur.Total)
	if total > 0 && have == total {
		cur.NextIndex = int(have)
		return true, nil
	}
	if total > 0 && have > total || total == 0 && have > 0 && cur.NextIndex == 0 {
		have = 0 // not this archive's bytes
	}
	if err := f.Truncate(have); err != nil {
		return false, diskError(err)
	}
	if _, err := f.Seek(have, io.SeekStart); err != nil {
		return false, diskError(err)
	}
	want := int64(recordArchiveSize)
	if total > 0 {
		want = total
	}
	freeOf := func(dir string) (int64, bool) { n, err := store.DiskFree(dir); return n, err == nil }
	if s.free != nil {
		freeOf = s.free
	}
	if free, ok := freeOf(filepath.Dir(path)); ok && free < want-have+recordDiskMargin {
		return false, &Error{Err: errWorkFile, Detail: fmt.Sprintf("Not enough free disk space to download the CVE Program's whole list: %s MB free, about %s MB needed. "+
			"Vedette tries again later; the records read before are kept.", grouped(int(free>>20)), grouped(int((want-have+recordDiskMargin)>>20)))}
	}
	var wantTotal int64
	if have > 0 {
		wantTotal = total
	}
	dctx := ctx
	if dl, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		dctx, cancel = context.WithDeadline(ctx, dl.Add(-recordReadReserve))
		defer cancel()
	}
	got := int64(0)
	resp, err := s.Fetcher.Fetch(dctx, Request{URL: run.from.archiveURL(cur.From, true), MaxBytes: recordArchiveMax, From: have, WantTotal: wantTotal,
		RedirectHosts: run.from.redirect, Stream: func(r io.Reader) error {
			n, err := s.throttledCopy(dctx, f, r)
			got = n
			return err
		}})
	cur.NextIndex = int(have + got)
	run.bytes += got
	switch {
	case resp != nil && resp.Partial && resp.Total > 0:
		cur.Total = int(resp.Total)
	case resp != nil && resp.Total > 0: // a whole answer: its size is the archive's
		cur.Total = int(resp.Total)
	}
	if errors.Is(err, ErrFileChanged) { // another file under the same name: start it over
		if terr := f.Truncate(0); terr != nil {
			return false, diskError(terr)
		}
		cur.NextIndex, cur.Total = 0, 0
		run.notes = append(run.notes, "The CVE Program's whole list changed during its download; Vedette downloads it again from the start.")
		return false, errRecordsLater
	}
	if err != nil {
		if dctx.Err() != nil && ctx.Err() == nil && got > 0 {
			return false, nil // the budget of this pull is spent: the next one goes on
		}
		return false, err
	}
	if cur.Total <= 0 { // the source did not say the size: the answer that ended is the whole file
		cur.Total = cur.NextIndex
	}
	return cur.NextIndex == cur.Total, nil
}

// throttledCopy copies r to w at most recordRate bytes a second.
func (s *Service) throttledCopy(ctx context.Context, w io.Writer, r io.Reader) (int64, error) {
	buf := make([]byte, 256<<10)
	var n int64
	start := s.now()
	for {
		k, err := r.Read(buf)
		if k > 0 {
			if _, werr := w.Write(buf[:k]); werr != nil {
				return n, diskError(werr)
			}
			n += int64(k)
			if ahead := time.Duration(float64(n)/recordRate*float64(time.Second)) - s.now().Sub(start); ahead > 50*time.Millisecond {
				if err := s.sleep(ctx, ahead); err != nil {
					return n, err
				}
			}
		}
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
}

// readArchive reads the daily archive at path and stores the records the catalogue keeps, recordBatch a transaction. A record of a CVE
// the catalogue does not hold is read only to learn whether it was published inside the window.
func (s *Service) readArchive(ctx context.Context, run *recordRun, path string, midnight, now time.Time, all bool) error {
	f, err := os.Open(path) //nolint:gosec // path is the module's own work file (recordWorkDir and a day's name)
	if err != nil {
		return diskError(err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return diskError(err)
	}
	pinned, err := s.pinned(ctx)
	if err != nil {
		return err
	}
	k, err := recordKeepOf(ctx, s.DB.Reader(), now, pinned)
	if err != nil {
		return err
	}
	// a record read after the archive's midnight (by ID, or from a later day's changes) is newer than the archive's: it stays, unless
	// the read replaces every record (all: an older reader read them; the changes since midnight are read again after it)
	newer := map[string]bool{}
	if !all {
		if newer, err = stringSet(ctx, s.DB.Reader(), `SELECT cve FROM feeds_cve WHERE record_at > ?`, store.FormatTS(midnight)); err != nil {
			return err
		}
	}
	var batch []CVERecord
	flush := func() error {
		err := s.storeRecords(ctx, run, batch, nil, now)
		batch = batch[:0]
		return err
	}
	n := 0
	err = walkDailyArchive(f, info.Size(), func(e archiveEntry, body func() ([]byte, error)) error {
		if n++; n%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if newer[e.CVE] {
			return nil
		}
		rec, ok, err := readArchived(e, body, k, run)
		if err != nil || !ok {
			return err
		}
		rec.asOf = midnight
		run.fromBulk++
		if batch = append(batch, rec); len(batch) >= recordBatch {
			return flush()
		}
		return nil
	})
	if err != nil {
		return err
	}
	return flush()
}

// readArchived reads one archived record the box keeps (ok); a record too large or unreadable is counted and skipped.
func readArchived(e archiveEntry, body func() ([]byte, error), k recordKeep, run *recordRun) (CVERecord, bool, error) {
	b, err := body()
	switch {
	case errors.Is(err, ErrTooLarge):
		run.tooLarge++
		return CVERecord{}, false, nil
	case err != nil:
		return CVERecord{}, false, err
	}
	if !k.have[e.CVE] {
		if pub, ok := recordPublished(b); !ok || pub.Before(k.cutoff) {
			return CVERecord{}, false, nil
		}
	}
	rec, err := ParseCVERecord(b, e.CVE)
	if err != nil {
		run.unreadable++
		return CVERecord{}, false, nil
	}
	return rec, k.keeps(rec), nil
}

// recordPublished reads only the cveMetadata of a record (it comes first): the day a published record was published.
func recordPublished(b []byte) (time.Time, bool) {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return time.Time{}, false
	}
	for i := 0; i < 8 && dec.More(); i++ {
		key, err := dec.Token()
		if err != nil {
			return time.Time{}, false
		}
		if key != "cveMetadata" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return time.Time{}, false
			}
			continue
		}
		var m struct {
			State     string `json:"state"`
			Published string `json:"datePublished"`
		}
		if err := dec.Decode(&m); err != nil || m.State != RecordPublished {
			return time.Time{}, false
		}
		t := recordTime(m.Published)
		return t, !t.IsZero()
	}
	return time.Time{}, false
}

// deltaChange is one change the change log lists: a record new or updated at a time, logged at fetch.
type deltaChange struct {
	fetch   time.Time
	cve     string
	updated time.Time
	isNew   bool
}

// parseDeltaLog reads the change log (deltaLog.json: a list of hourly entries, each with its fetchTime and the records new and updated
// in it), oldest first. oldest is the first entry's time.
func parseDeltaLog(b []byte) (changes []deltaChange, oldest time.Time, err error) {
	var log []struct {
		FetchTime string `json:"fetchTime"`
		New       []struct {
			CVE     string `json:"cveId"`
			Updated string `json:"dateUpdated"`
		} `json:"new"`
		Updated []struct {
			CVE     string `json:"cveId"`
			Updated string `json:"dateUpdated"`
		} `json:"updated"`
	}
	if err := json.Unmarshal(b, &log); err != nil {
		return nil, time.Time{}, fail(ErrBadSample, "The CVE Program's change log is not the list Vedette reads.")
	}
	if len(log) > 100_000 {
		return nil, time.Time{}, fail(ErrBadSample, "The CVE Program's change log has more than 100,000 entries.")
	}
	for _, e := range log {
		ft := recordTime(e.FetchTime)
		if ft.IsZero() {
			return nil, time.Time{}, fail(ErrBadSample, "The CVE Program's change log has an entry without its time.")
		}
		if oldest.IsZero() || ft.Before(oldest) {
			oldest = ft
		}
		for i, list := range [][]struct {
			CVE     string `json:"cveId"`
			Updated string `json:"dateUpdated"`
		}{e.New, e.Updated} {
			for _, c := range list {
				if !cveRE.MatchString(c.CVE) || len(c.CVE) > 32 {
					continue
				}
				changes = append(changes, deltaChange{fetch: ft, cve: c.CVE, updated: recordTime(c.Updated), isNew: i == 0})
			}
		}
	}
	if len(changes) > 5_000_000 {
		return nil, time.Time{}, fail(ErrBadSample, "The CVE Program's change log lists more than 5,000,000 changes.")
	}
	slices.SortStableFunc(changes, func(a, b deltaChange) int { return a.fetch.Compare(b.fetch) })
	return changes, oldest, nil
}

// recordsChanges reads the change log and brings the records the box keeps up to date: each day that is over from that day's archive
// of changes, what it does not hold by ID (recordLeftPerPull at most, a day's leftovers first; today's only when they are few, else
// the day's archive brings them tomorrow). The cursor moves to the last change before the first one still missing; a change log that
// no longer reaches the cursor loads the whole list again.
func (s *Service) recordsChanges(ctx context.Context, run *recordRun, cur recentCursor, now time.Time) error {
	resp, err := s.Fetcher.Fetch(ctx, Request{URL: run.from.records + "/deltaLog.json", MaxBytes: recordLogMax})
	if err != nil {
		return err
	}
	run.bytes += int64(len(resp.Body))
	changes, oldest, err := parseDeltaLog(resp.Body)
	if err != nil {
		return err
	}
	cur.To = now
	if cur.Until.Before(oldest) { // the log does not reach back to the data: load the whole list again
		run.notes = append(run.notes, "The CVE Program's change log no longer reaches back to this box's data: loading the whole list again.")
		day := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
		return s.saveRecordCursor(ctx, run, recentCursor{URL: recordCursorURL(run.src.URL), Mode: modeFill, From: day, To: day, Until: cur.Until})
	}
	pinned, err := s.pinned(ctx)
	if err != nil {
		return err
	}
	k, err := recordKeepOf(ctx, s.DB.Reader(), now, pinned)
	if err != nil {
		return err
	}
	pending := slices.DeleteFunc(changes, func(c deltaChange) bool { return !c.fetch.After(cur.Until) })
	need := map[string]time.Time{} // the newest change of each record the box keeps
	for _, c := range pending {
		if k.have[c.cve] || c.isNew {
			if t, ok := need[c.cve]; !ok || c.updated.After(t) {
				need[c.cve] = c.updated
			}
		}
	}
	today := now.UTC().Truncate(24 * time.Hour)
	covered := map[string]time.Time{} // records stored, with the time the record says it was updated
	var days []time.Time
	for _, c := range pending {
		if d := c.fetch.UTC().Truncate(24 * time.Hour); d.Before(today) && !slices.ContainsFunc(days, d.Equal) {
			days = append(days, d)
		}
	}
	gone := false         // the archive of an earlier day is not there any more
	notYet := time.Time{} // yesterday, when its end-of-day archive is not published yet: its changes wait like today's
	yesterday := today.AddDate(0, 0, -1)
	for _, d := range days {
		if err := s.readChangeArchive(ctx, run, d, need, covered, k, now); err != nil {
			if !errors.Is(err, errRecordsLater) {
				return err
			}
			if d.Equal(yesterday) {
				notYet = d
			} else {
				gone = true
			}
		}
	}
	// a change counts as stored once the box read the CVE's current record after it was logged (by ID, or from an archive that holds
	// it: an archive's older copy is never stored), in this pull or an earlier one
	readAt, err := s.st.recordReadAt(ctx, slices.Collect(maps.Keys(need)))
	if err != nil {
		return err
	}
	lastFetch := map[string]time.Time{}
	for _, c := range pending {
		lastFetch[c.cve] = c.fetch
	}
	done := func(cve string) bool {
		t, ok := need[cve]
		return !ok || isCovered(covered, cve, t) || !readAt[cve].IsZero() && !readAt[cve].Before(lastFetch[cve])
	}
	isNew := map[string]bool{}
	for _, c := range pending {
		isNew[c.cve] = isNew[c.cve] || c.isNew
	}
	// What the archives did not hold is asked for by ID only when every box would ask the same: a new CVE, one published inside the
	// window, or one a public source names (recordKeep.askable). Any other record (a CVE only this box keeps, for a finding) is never
	// asked for by ID: today's wait for tomorrow's archive; a past day's (its archive gone) is marked waiting (recordWaiting) and read
	// with the next whole list, which a waiting record brings about at most once a week.
	var left, waits []string
	var todayLeft, closedLeft int
	for _, c := range pending {
		if done(c.cve) || slices.Contains(left, c.cve) || slices.Contains(waits, c.cve) {
			continue
		}
		day := lastChange(pending, c.cve).UTC().Truncate(24 * time.Hour)
		closed := day.Before(today) && !day.Equal(notYet)
		if !isNew[c.cve] && !k.askable[c.cve] {
			if closed {
				covered[c.cve] = need[c.cve] // passed over now; marked waiting, read with the next whole list
				waits = append(waits, c.cve)
			}
			continue
		}
		if closed {
			closedLeft++
		} else {
			todayLeft++
		}
		left = append(left, c.cve)
	}
	if gone && closedLeft > recordLeftPerPull { // whole days are missing: the whole list, not thousands of single requests
		run.notes = append(run.notes, "The CVE Program's files of changed records no longer reach back to this box's data: loading the whole list again.")
		day := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
		return s.saveRecordCursor(ctx, run, recentCursor{URL: recordCursorURL(run.src.URL), Mode: modeFill, From: day, To: day, Until: cur.Until})
	}
	if len(waits) > 0 {
		if err := s.markRecordsWaiting(ctx, run, waits); err != nil {
			return err
		}
		run.notes = append(run.notes, fmt.Sprintf("%s changed records of CVEs no public list names wait for the next read of the whole list (at most once a week).", grouped(len(waits))))
	}
	if todayLeft > recordLeftPerPull { // today's changes come with tomorrow's archive (and yesterday's with its own, still to come)
		left = slices.DeleteFunc(left, func(cve string) bool {
			d := lastChange(pending, cve).UTC().Truncate(24 * time.Hour)
			return !d.Before(today) || d.Equal(notYet)
		})
	}
	if len(left) > recordLeftPerPull {
		left = left[:recordLeftPerPull]
	}
	recs, unread, gerr := s.recordsGet(ctx, run, left, recordLeftPause)
	run.byID += len(recs)
	if err := s.storeRecords(ctx, run, recs, unread, now); err != nil { // the unread are stamped too: not asked again for these changes
		return err
	}
	for _, r := range recs {
		covered[r.CVE] = now // the current record: newer than every change logged
	}
	for _, cve := range unread {
		covered[cve] = now // not published or unreadable: not asked again for these changes
	}
	until := cur.Until
	for i := 0; i < len(pending); { // the cursor moves over each logged hour whose records are all stored, up to the first one missing
		j := i
		for j < len(pending) && pending[j].fetch.Equal(pending[i].fetch) {
			j++
		}
		if slices.ContainsFunc(pending[i:j], func(c deltaChange) bool { return !done(c.cve) }) {
			break
		}
		until, i = pending[i].fetch, j
	}
	if serr := s.saveRecordCursor(ctx, run, recentCursor{URL: recordCursorURL(run.src.URL), Mode: modeDone, From: cur.From, To: cur.To, Until: until}); serr != nil {
		return serr
	}
	return gerr
}

// lastChange is the time of the last logged change of cve.
func lastChange(changes []deltaChange, cve string) time.Time {
	var t time.Time
	for _, c := range changes {
		if c.cve == cve && c.fetch.After(t) {
			t = c.fetch
		}
	}
	return t
}

// isCovered says the record stored for cve is at least as new as the change logged (a zero time: any record read).
func isCovered(covered map[string]time.Time, cve string, want time.Time) bool {
	got, ok := covered[cve]
	return ok && !got.Before(want)
}

// readChangeArchive reads the archive of changes of day and stores the records of need it holds; errRecordsLater when that day has no
// archive (any more).
func (s *Service) readChangeArchive(ctx context.Context, run *recordRun, day time.Time, need, covered map[string]time.Time, k recordKeep, now time.Time) error {
	resp, err := s.Fetcher.Fetch(ctx, Request{URL: run.from.archiveURL(day, false), MaxBytes: deltaMaxBytes, RedirectHosts: run.from.redirect})
	var se *StatusError
	if errors.As(err, &se) && se.Code == http.StatusNotFound {
		return errRecordsLater
	}
	if err != nil {
		return err
	}
	run.bytes += int64(len(resp.Body))
	var batch []CVERecord
	err = walkDeltaArchive(resp.Body, func(e archiveEntry, body func() ([]byte, error)) error {
		if _, ok := need[e.CVE]; !ok {
			return nil
		}
		rec, ok, err := readArchived(e, body, k, run)
		if err != nil {
			return err
		}
		if !ok {
			covered[e.CVE] = now // read: the box does not keep it
			return nil
		}
		if !rec.Updated.IsZero() && rec.Updated.Before(need[e.CVE]) {
			return nil // the archive's copy is older than the change logged: not stored, so its read time never claims the change
		}
		covered[e.CVE] = need[e.CVE]
		rec.asOf = day.AddDate(0, 0, 1) // the end of that day
		batch = append(batch, rec)
		run.fromBulk++
		return nil
	})
	if err != nil {
		return err
	}
	for chunk := range slices.Chunk(batch, recordBatch) {
		if err := s.storeRecords(ctx, run, chunk, nil, now); err != nil {
			return err
		}
	}
	return nil
}
