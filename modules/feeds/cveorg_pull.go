package feeds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The pull of CVE.org affected versions (D-556): the CVE records of the CISA KEV CVEs NVD gave no usable ranges, one
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
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT v.cve, v.vendor, v.product FROM feeds_vuln v
LEFT JOIN feeds_cveorg_checked c ON c.cve = v.cve
WHERE v.source_id = 'cisa-kev'
  AND NOT EXISTS (SELECT 1 FROM feeds_affected_cve a WHERE a.cve = v.cve AND a.source = 'nvd' AND EXISTS (SELECT 1 FROM feeds_affected r WHERE r.cve = v.cve))
  AND (c.checked_at IS NULL OR c.checked_at < ?)
ORDER BY c.checked_at IS NOT NULL, c.checked_at, v.date_added DESC, v.cve
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
// source does not have (404) or that Vedette refuses is counted and skipped; a source that stays busy after
// cveOrgRetryWaits ends the pull with what it has, and the next pull goes on with the CVEs left. A pull that read no
// record at all because the source failed is a failure of the feed (its back-off applies).
func (s *Service) buildCVEOrg(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	now := s.now()
	todo, err := s.st.cveOrgTodo(ctx, now.Add(-cveOrgRecheck), cveOrgMaxPerPull)
	if err != nil {
		return p, err
	}
	got, checked, counts := map[string][]AffectedRow{}, []string{}, map[string]int{}
	tl, bytes := newTally(), 0
	var stopped error
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
		case errors.As(err, &se) && se.Code == http.StatusNotFound:
			checked = append(checked, k.CVE) // not on CVE.org's list (yet): asked again after cveOrgRecheck
			counts["missing"]++
			continue
		case errors.Is(err, ErrTooLarge):
			checked = append(checked, k.CVE)
			tl.reject(i+1, "%s: the record is too large", k.CVE)
			continue
		case err != nil && (ctx.Err() != nil || nvdRetryable(err)):
			stopped = err
		case err != nil:
			return p, err // a refused address or redirect: the admin's address is wrong
		}
		if stopped != nil {
			break
		}
		bytes += len(resp.Body)
		checked = append(checked, k.CVE)
		res, err := ParseCVERecord(resp.Body, k.CVE, k.Vendor, k.Product)
		if err != nil {
			tl.reject(i+1, "%s: the record is not CVE JSON 5", k.CVE)
			continue
		}
		tl.Accepted++
		counts[res.Outcome]++
		if res.Outcome == CVEOrgRanges {
			got[k.CVE] = res.Rows
		}
	}
	if len(checked) == 0 && stopped != nil {
		if ctx.Err() == nil {
			return p, &Error{Err: stopped, Detail: "CVE.org (GitHub) was busy or did not answer, after every try. Vedette tries again later; the versions loaded before are kept."}
		}
		return p, stopped
	}
	p.out = outcome{OK: true, Bytes: bytes}
	p.cveOrg, p.cveOrgChecked, p.hasCVEOrg = got, checked, true
	st := tl.stats()
	p.out.Accepted, p.out.Rejected, p.out.Reasons = st.Accepted, st.Rejected, st.Reasons
	if len(checked) > 0 {
		p.out.Note = cveOrgNote(len(checked), counts, st.Rejected, stopped != nil)
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
	t := fmt.Sprintf("Read %s CVE.org records of exploited CVEs NVD has no versions for: %s with the vendor's affected versions", grouped(n), grouped(c[CVEOrgRanges]))
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

// applyCVEOrg stores the ranges a CVE.org pull found (D-556): NVD's ranges win, so a CVE that has NVD rows by now is left
// alone; a CVE whose record no longer gives ranges loses the CVE.org ones it had. Every checked CVE is stamped, and the
// stamps of CVEs CISA no longer lists go. It returns the CVEs whose ranges changed and how many CVEs have CVE.org ranges.
func applyCVEOrg(ctx context.Context, tx *sql.Tx, got map[string][]AffectedRow, checked []string, now time.Time) (changed []string, total int, err error) {
	ts := store.FormatTS(now)
	checked = slices.Sorted(slices.Values(checked))
	for _, cve := range checked {
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cveorg_checked (cve, checked_at) VALUES (?, ?) ON CONFLICT(cve) DO UPDATE SET checked_at = excluded.checked_at`, cve, ts); err != nil {
			return nil, 0, fmt.Errorf("feeds: CVE.org: %w", err)
		}
		src, err := affectedSource(ctx, tx, cve)
		if err != nil {
			return nil, 0, err
		}
		if src == rangesNVD {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM feeds_affected WHERE cve = ?`, cve).Scan(&n); err != nil {
				return nil, 0, fmt.Errorf("feeds: CVE.org: %w", err)
			}
			if n > 0 {
				continue // NVD has ranges now: they win
			}
		}
		rows := got[cve]
		if len(rows) == 0 {
			if src == rangesCVEOrg {
				if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_affected_cve WHERE cve = ?`, cve); err != nil { // its rows go with it (ON DELETE CASCADE)
					return nil, 0, fmt.Errorf("feeds: CVE.org: %w", err)
				}
				changed = append(changed, cve)
			}
			continue
		}
		same, err := sameAffected(ctx, tx, cve, rangesCVEOrg, rows)
		if err != nil {
			return nil, 0, err
		}
		if same {
			continue
		}
		changed = append(changed, cve)
		if err := putAffected(ctx, tx, cve, rangesCVEOrg, rows, ts); err != nil {
			return nil, 0, err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_cveorg_checked WHERE cve NOT IN (SELECT cve FROM feeds_vuln WHERE source_id = 'cisa-kev')`); err != nil {
		return nil, 0, fmt.Errorf("feeds: CVE.org: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM feeds_affected_cve WHERE source = 'cve.org'`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("feeds: CVE.org: %w", err)
	}
	return changed, total, nil
}
