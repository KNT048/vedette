package feeds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The pull of CVE.org affected versions: the CVE records of the CISA KEV CVEs NVD gave no usable ranges, one
// small file each, politely (cveOrgPause apart, cveOrgMaxPerPull at most, each CVE read again only after cveOrgRecheck).
const (
	cveOrgFeedID     = "cve-org"
	cveOrgMaxPerPull = 60
	cveOrgRecheck    = 12 * time.Hour
)

// cveOrgPause is the wait between two records; cveOrgRetryWaits the waits before the second and third try of a record
// the source answered busy (429, 5xx) or not at all. Vars for the tests (Service.wait replaces the real waits).
var (
	cveOrgPause      = time.Second
	cveOrgRetryWaits = []time.Duration{6 * time.Second, 30 * time.Second}
)

// kevTodo is a CISA KEV entry whose CVE.org record is due.
type kevTodo struct{ CVE, Vendor, Product string }

// cveOrgTodo lists the CISA KEV CVEs without NVD ranges (none stored, or NVD's answer has no vulnerable entry) whose
// record was not read since before: never read first, then the longest ago, newest KEV entries first.
func (s *Store) cveOrgTodo(ctx context.Context, before time.Time, limit int) ([]kevTodo, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT k.cve, k.vendor, k.product FROM feeds_kev k JOIN feeds_cve c ON c.cve = k.cve
WHERE k.source_id IN ('cisa-kev', 'vulncheck-kev')
  AND k.list = (SELECT k2.list FROM feeds_kev k2 WHERE k2.cve = k.cve AND k2.source_id IN ('cisa-kev', 'vulncheck-kev') ORDER BY `+ownerOrder+` LIMIT 1)
  AND NOT EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = k.cve AND r.origin = 'nvd')
  AND (c.record_at IS NULL OR c.record_at < ?)
ORDER BY c.record_at IS NOT NULL, c.record_at, k.date_added DESC, k.cve
LIMIT ?`, store.FormatTS(before), limit)
	if err != nil {
		return nil, fmt.Errorf("feeds: CVE.org to do: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []kevTodo
	for rows.Next() {
		var k kevTodo
		if err := rows.Scan(&k.CVE, &k.Vendor, &k.Product); err != nil {
			return nil, fmt.Errorf("feeds: CVE.org to do: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// buildCVEOrg reads the due records (cveOrgTodo) under src.URL (CVEOrgRecordURL). Each CVE stands alone: a record the
// source does not have (404), refuses (any other HTTP error that is not "busy") or that Vedette cannot read is counted,
// stamped (asked again after cveOrgRecheck) and skipped, and its stored ranges stay; an address the box refuses ends the
// pull as a failure; a source that stays busy after
// cveOrgRetryWaits ends the pull with what it has, and the next pull goes on with the CVEs left. A pull that read no
// record at all because the source failed is a failure of the feed (its back-off applies).
func (s *Service) buildCVEOrg(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	now := s.now()
	todo, err := s.st.cveOrgTodo(ctx, now.Add(-cveOrgRecheck), cveOrgMaxPerPull)
	if err != nil {
		return p, err
	}
	got, checked, unread, counts, days := map[string]CVEOrgResult{}, []string{}, []string{}, map[string]int{}, map[string]string{}
	tl, bytes := newTally(), 0
	var stopped error
loop:
	for i, k := range todo {
		if i > 0 {
			if err := s.sleep(ctx, cveOrgPause); err != nil {
				stopped = err
				break
			}
		}
		u, err := CVEOrgRecordURL(src.URL, k.CVE)
		if err != nil {
			return p, err
		}
		resp, err := s.cveOrgGet(ctx, u)
		var se *StatusError
		switch {
		case err == nil:
		case errors.Is(err, ErrRedirect) || errors.Is(err, ErrInvalidURL) || errors.Is(err, ErrBlockedAddress) || errors.Is(err, ErrBoxAddrsUnknown):
			return p, err // the address itself is refused: the admin's address is wrong, or the box does not know its own yet
		case ctx.Err() != nil || nvdRetryable(err):
			stopped = err
			break loop
		case errors.As(err, &se) && se.Code == http.StatusNotFound:
			unread = append(unread, k.CVE) // not on CVE.org's list (yet): asked again after cveOrgRecheck
			counts["missing"]++
			continue
		case errors.As(err, &se):
			unread = append(unread, k.CVE) // this one file is refused (403, 410, 451…): the others go on (review M4)
			tl.reject(i+1, "%s: HTTP %s", k.CVE, strconv.Itoa(se.Code))
			continue
		default:
			unread = append(unread, k.CVE) // too large, or an answer Vedette cannot read
			tl.reject(i+1, "%s: the record could not be read", k.CVE)
			continue
		}
		bytes += len(resp.Body)
		res, err := ParseCVERecord(resp.Body, k.CVE, k.Vendor, k.Product)
		if err != nil { // a proxy page or a cut answer: the ranges stored before stay (review L1)
			unread = append(unread, k.CVE)
			tl.reject(i+1, "%s: the record is not CVE JSON 5", k.CVE)
			continue
		}
		checked = append(checked, k.CVE)
		tl.Accepted++
		counts[res.Outcome]++
		if res.Published != "" {
			days[k.CVE] = res.Published
		}
		if res.Outcome == CVEOrgRanges {
			got[k.CVE] = res
		}
	}
	if len(checked)+len(unread) == 0 && stopped != nil {
		if ctx.Err() == nil {
			return p, &Error{Err: stopped, Detail: "CVE.org (GitHub) was busy or did not answer, after every try. Vedette tries again later; the versions loaded before are kept."}
		}
		return p, stopped
	}
	p.out = outcome{OK: true, Bytes: bytes}
	p.cveOrg, p.cveOrgChecked, p.cveOrgUnread, p.cveOrgDays, p.hasCVEOrg = got, checked, unread, days, true
	st := tl.stats()
	p.out.Accepted, p.out.Rejected, p.out.Reasons = st.Accepted, st.Rejected, st.Reasons
	if n := len(checked) + len(unread); n > 0 {
		p.out.Note = cveOrgNote(n, counts, st.Rejected, stopped != nil)
	}
	return p, nil
}

// cveOrgGet fetches one record, trying again after cveOrgRetryWaits (or the source's Retry-After, at most 2 min) while
// it is busy or slow.
func (s *Service) cveOrgGet(ctx context.Context, u string) (*Response, error) {
	for try := 0; ; try++ {
		resp, err := s.get(ctx, Request{URL: u, MaxBytes: CVEOrgMaxBytes})
		if err == nil || ctx.Err() != nil || !nvdRetryable(err) || try >= len(cveOrgRetryWaits) {
			return resp, err
		}
		wait := cveOrgRetryWaits[try]
		var se *StatusError
		if errors.As(err, &se) && se.RetryAfter > wait {
			wait = min(se.RetryAfter, 2*time.Minute)
		}
		if err := s.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// cveOrgNote is the feed's status line after a pull that read records: what they gave, in the words of the page.
func cveOrgNote(n int, c map[string]int, rejected int, stopped bool) string {
	t := fmt.Sprintf("Read %s CVE.org records of exploited CVEs NVD has no versions for: %s with affected versions from their CNA", grouped(n), grouped(c[CVEOrgRanges]))
	if c[CVEOrgNoMatch] > 0 {
		t += fmt.Sprintf(", %s naming other products than CISA's entry", grouped(c[CVEOrgNoMatch]))
	}
	if k := c[CVEOrgNoVersions] + c[CVEOrgUnusable] + c[CVEOrgRejected]; k > 0 {
		t += fmt.Sprintf(", %s without versions Vedette can compare", grouped(k))
	}
	if c["missing"] > 0 {
		t += fmt.Sprintf(", %s not on CVE.org yet", grouped(c["missing"]))
	}
	if rejected > 0 {
		t += fmt.Sprintf(", %s unreadable", grouped(rejected))
	}
	t += "."
	if stopped {
		t += " CVE.org (GitHub) stopped answering; Vedette reads the rest at the next pull."
	}
	return t
}

// applyCVEOrg stores the ranges a CVE.org pull found (origin cna, each with its entry's defaultStatus): a CVE that has
// NVD rows by now keeps the CNA rows aside (NVD's win when read); a CVE whose record no longer gives ranges loses the CNA ones it had.
// Every CVE read (checked) or not readable this time (unread: its stored ranges stay) is stamped (feeds_cve.record_at), and the CNA
// rows of CVEs no exploited list names any more go. It returns the CVEs whose ranges changed, whether all of them were read for the
// first time (backlog: matched quietly, a new CISA entry alerts through its own new_kev event), and how many CVEs have CNA ranges.
func applyCVEOrg(ctx context.Context, tx *sql.Tx, got map[string]CVEOrgResult, checked, unread []string, now time.Time) (changed []string, first bool, total int, err error) {
	ts := store.FormatTS(now)
	first = true
	stamp := func(cve string) (bool, error) {
		var seen bool
		err := tx.QueryRowContext(ctx, `SELECT record_at IS NOT NULL FROM feeds_cve WHERE cve = ?`, cve).Scan(&seen)
		if errors.Is(err, sql.ErrNoRows) {
			if err := ensureCVE(ctx, tx, cve, ts); err != nil {
				return false, err
			}
		} else if err != nil {
			return false, fmt.Errorf("feeds: CVE.org: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET record_at = ? WHERE cve = ?`, ts, cve); err != nil {
			return false, fmt.Errorf("feeds: CVE.org: %w", err)
		}
		return seen, nil
	}
	for _, cve := range unread {
		if _, err := stamp(cve); err != nil {
			return nil, false, 0, err
		}
	}
	for _, cve := range slices.Sorted(slices.Values(checked)) {
		seen, err := stamp(cve)
		if err != nil {
			return nil, false, 0, err
		}
		have, err := readRanges(ctx, tx, `WHERE r.cve = ?`, cve)
		if err != nil {
			return nil, false, 0, err
		}
		if slices.ContainsFunc(have, func(r Range) bool { return r.Origin == OriginNVD }) {
			continue // NVD has ranges now: they win
		}
		res, ok := got[cve]
		if ok && len(have) == len(res.Rows) && !slices.ContainsFunc(have, func(r Range) bool { return r.Origin != OriginCNA }) &&
			slices.EqualFunc(have, res.Rows, func(h Range, r AffectedRow) bool { return h.AffectedRow() == r }) &&
			!slices.ContainsFunc(have, func(h Range) bool { return h.DefaultStatus != res.defaultOf(slices.Index(res.Rows, h.AffectedRow())) }) {
			continue
		}
		if !ok && len(have) == 0 {
			continue
		}
		changed, first = append(changed, cve), first && !seen
		if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_cve_range WHERE cve = ? AND origin = 'cna'`, cve); err != nil {
			return nil, false, 0, fmt.Errorf("feeds: CVE.org: %w", err)
		}
		for i, r := range res.Rows {
			part, vendor, product := cpeParts(r.CPE)
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, default_status)
VALUES (?, 'cna', ?, ?, ?, ?, ?, ?, ?, ?, ?)`, cve, part, clipBytes(vendor), clipBytes(product), r.CPE, r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl, res.defaultOf(i)); err != nil {
				return nil, false, 0, fmt.Errorf("feeds: CVE.org: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET updated_at = ? WHERE cve = ?`, ts, cve); err != nil {
			return nil, false, 0, fmt.Errorf("feeds: CVE.org: %w", err)
		}
	}
	if err := pruneOrphanRanges(ctx, tx); err != nil {
		return nil, false, 0, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(DISTINCT r.cve) FROM feeds_cve_range r WHERE r.origin = 'cna'
AND NOT EXISTS (SELECT 1 FROM feeds_cve_range n WHERE n.cve = r.cve AND n.origin = 'nvd')`).Scan(&total); err != nil {
		return nil, false, 0, fmt.Errorf("feeds: CVE.org: %w", err)
	}
	return changed, first && len(changed) > 0, total, nil
}

// pruneOrphanRanges deletes the CNA ranges of CVEs no exploited-list source lists any more (a VulnCheck entry that went), so they are
// not counted or matched; NVD's rows are left alone.
func pruneOrphanRanges(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_cve_range WHERE origin = 'cna'
AND cve NOT IN (SELECT cve FROM feeds_kev WHERE source_id IN ('cisa-kev', 'vulncheck-kev'))`); err != nil {
		return fmt.Errorf("feeds: prune CVE.org ranges: %w", err)
	}
	return nil
}

// applyCVEOrgPublished stores the days CVE.org's records give for CVEs NVD has given none for: NVD's day is never replaced, and a day
// CVE.org gave once stays (a CVE's published day does not change).
func applyCVEOrgPublished(ctx context.Context, tx *sql.Tx, got map[string]string) error {
	for _, cve := range slices.Sorted(maps.Keys(got)) {
		if _, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET published = ? WHERE cve = ? AND published IS NULL`, got[cve]+"T00:00:00.000Z", cve); err != nil {
			return fmt.Errorf("feeds: published %s: %w", cve, err)
		}
	}
	return nil
}
