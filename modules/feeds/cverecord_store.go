package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/store"
)

// What a CVE record writes into the catalogue. The record reader is the one writer of feeds_cve.record_at, title, solution, workaround
// and the ssvc columns and of the cna and adp rows of feeds_cve_range. It writes the description and the published day only while NVD
// has given none (NVD's English description wins as soon as NVD answers), the weaknesses (cwe) while NVD has not answered or listed none,
// and the references (feeds_cve_ref) while NVD has tagged none (nvdRefs): NVD's record carries the CNA's and CISA's weaknesses and
// references, tagged by an analyst. CVSS scores stay NVD's: NVD's record carries the CNA's and CISA's scores too.

// importantSQL is the CVEs the box holds for a reason of its own (with the pinned CVEs the caller adds): an exploited-list entry (a
// custom list's too) or a qualifying signal. Only its public part (publicListedSQL) is ever asked for by ID. References do not depend
// on it: every CVE the catalogue holds keeps them, and they go with the CVE (feeds_cve_ref cascades from feeds_cve).
const importantSQL = keepSetSQL

// recordKeep says which records the box stores.
type recordKeep struct {
	have map[string]bool // in the catalogue, or kept whatever their age (an exploited-list entry, a qualifying signal, a pin)
	// askable are the kept CVEs whose record may be asked for by ID because every box asks the same: one a public source names
	// (publicListedSQL), or one published inside the window. Never a CVE kept only for a finding or a custom list.
	askable map[string]bool
	cutoff  time.Time // a CVE published since is kept (the catalogue's window)
}

// recordKeepOf reads the keep sets.
func recordKeepOf(ctx context.Context, q queryer, now time.Time, pinned []string) (recordKeep, error) {
	have, err := stringSet(ctx, q, `SELECT cve FROM feeds_cve UNION `+keepSetSQL)
	if err != nil {
		return recordKeep{}, err
	}
	for _, c := range pinned {
		have[c] = true
	}
	cutoff := now.AddDate(0, 0, -windowDays)
	ask, err := stringSet(ctx, q, publicListedSQL+` UNION SELECT cve FROM feeds_cve WHERE published >= ?`, store.FormatTS(cutoff))
	if err != nil {
		return recordKeep{}, err
	}
	return recordKeep{have: have, askable: ask, cutoff: cutoff}, nil
}

// keeps says whether a record read is stored: its CVE is in the catalogue or kept, or it was published inside the window.
func (k recordKeep) keeps(r CVERecord) bool {
	return k.have[r.CVE] || r.State == RecordPublished && !r.Published.IsZero() && !r.Published.Before(k.cutoff)
}

// recordWrite is what writeRecords did.
type recordWrite struct {
	Stored     int      // records written
	KEVChanged []string // exploited-list CVEs whose record ranges changed (findings matches them again)
	KEVFirst   bool     // every one of them was read for the first time
	Catalogue  bool     // the rows a matcher reads of a CVE on no exploited list changed: findings' match pass reads them again
}

// recordStmts are the prepared statements of one writeRecords call.
type recordStmts struct {
	ensure, update, readAt, delRanges, insRange, delRefs, nvdRefs, insRef *sql.Stmt
}

func prepareRecordStmts(ctx context.Context, tx *sql.Tx) (*recordStmts, error) {
	var s recordStmts
	var err error
	for _, p := range []struct {
		st *(*sql.Stmt)
		q  string
	}{
		{&s.ensure, `INSERT INTO feeds_cve (cve, updated_at) VALUES (?, ?) ON CONFLICT(cve) DO NOTHING`},
		{&s.update, `UPDATE feeds_cve SET record_at = ?, title = ?, cwe = CASE WHEN nvd_at IS NULL OR cwe = '[]' THEN ? ELSE cwe END, solution = ?, workaround = ?, ssvc_exploitation = ?, ssvc_automatable = ?,
ssvc_impact = ?, description = CASE WHEN nvd_at IS NULL OR description = '' THEN ? ELSE description END, published = coalesce(published, ?)
WHERE cve = ?`},
		{&s.readAt, `SELECT record_at IS NOT NULL, EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = feeds_cve.cve AND r.origin = 'nvd') FROM feeds_cve WHERE cve = ?`},
		{&s.delRanges, `DELETE FROM feeds_cve_range WHERE cve = ? AND origin IN ('cna', 'adp')`},
		{&s.insRange, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, fixed, version_type, default_status)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`},
		{&s.delRefs, `DELETE FROM feeds_cve_ref WHERE cve = ? AND (? OR NOT EXISTS (SELECT 1 FROM feeds_cve_ref n WHERE n.cve = feeds_cve_ref.cve AND n.source = 'nvd'))`},
		{&s.nvdRefs, `SELECT EXISTS (SELECT 1 FROM feeds_cve_ref WHERE cve = ? AND source = 'nvd')`},
		{&s.insRef, `INSERT INTO feeds_cve_ref (cve, url, tags, source) VALUES (?, ?, ?, ?)`},
	} {
		if *p.st, err = tx.PrepareContext(ctx, p.q); err != nil {
			s.close()
			return nil, fmt.Errorf("feeds: CVE records: %w", err)
		}
	}
	return &s, nil
}

func (s *recordStmts) close() {
	for _, st := range []*sql.Stmt{s.ensure, s.update, s.readAt, s.delRanges, s.insRange, s.delRefs, s.nvdRefs, s.insRef} {
		if st != nil {
			_ = st.Close()
		}
	}
}

// writeRecords writes the records the keep rule keeps (recordKeep.keeps), each whole: its catalogue row's record columns, its record
// ranges (cna and adp, replacing the ones it had) and its references (every CVE the catalogue holds keeps them). A rejected record of a CVE the catalogue
// holds drops its record ranges and references (NVD's status and the retention rule decide whether the CVE stays). Every CVE written
// is stamped read (record_at).
func writeRecords(ctx context.Context, tx *sql.Tx, recs []CVERecord, k recordKeep, now time.Time) (recordWrite, error) {
	out := recordWrite{KEVFirst: true}
	if len(recs) == 0 {
		return out, nil
	}
	ts := store.FormatTS(now)
	kev, err := stringSet(ctx, tx, `SELECT cve FROM feeds_kev WHERE source_id IN ('cisa-kev', 'vulncheck-kev')`)
	if err != nil {
		return out, err
	}
	st, err := prepareRecordStmts(ctx, tx)
	if err != nil {
		return out, err
	}
	defer st.close()
	added := map[string]bool{} // CVEs whose description gains Apple's claim in this write (appleNoteAdded)
	for i, r := range recs {
		if i%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return out, err
			}
		}
		if r.State == RecordRejected {
			if !k.have[r.CVE] {
				continue
			}
		} else if !k.keeps(r) {
			continue
		}
		if _, err := st.ensure.ExecContext(ctx, r.CVE, ts); err != nil {
			return out, fmt.Errorf("feeds: CVE record %s: %w", r.CVE, err)
		}
		var seen, hasNVD bool
		if err := st.readAt.QueryRowContext(ctx, r.CVE).Scan(&seen, &hasNVD); err != nil {
			return out, fmt.Errorf("feeds: CVE record %s: %w", r.CVE, err)
		}
		cwe, err := json.Marshal(append([]string{}, r.CWE...))
		if err != nil {
			return out, err
		}
		var published any
		if !r.Published.IsZero() {
			published = store.FormatTS(r.Published)
		}
		readAt := ts
		if !r.asOf.IsZero() && r.asOf.Before(now) {
			readAt = store.FormatTS(r.asOf)
		}
		if err := appleNoteAdded(ctx, tx, r.CVE, r.Description, added); err != nil {
			return out, err
		}
		if _, err := st.update.ExecContext(ctx, readAt, r.Title, string(cwe), r.Solution, r.Workaround, nullWord(r.SSVC.Exploitation),
			nullWord(r.SSVC.Automatable), nullWord(r.SSVC.Impact), r.Description, published, r.CVE); err != nil {
			return out, fmt.Errorf("feeds: CVE record %s: %w", r.CVE, err)
		}
		changed, matched, err := replaceRecordRanges(ctx, tx, st, r)
		if err != nil {
			return out, err
		}
		if changed {
			if _, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET updated_at = ? WHERE cve = ?`, ts, r.CVE); err != nil {
				return out, fmt.Errorf("feeds: CVE record %s: %w", r.CVE, err)
			}
			if kev[r.CVE] && !hasNVD && matched { // only rows the matcher reads are news for findings
				out.KEVChanged, out.KEVFirst = append(out.KEVChanged, r.CVE), out.KEVFirst && !seen
			}
			out.Catalogue = out.Catalogue || !kev[r.CVE] && matched
		}
		// a rejected record drops every reference; otherwise NVD's tagged references, once there, stand (nvdRefs)
		if _, err := st.delRefs.ExecContext(ctx, r.CVE, r.State == RecordRejected); err != nil {
			return out, fmt.Errorf("feeds: CVE record %s: %w", r.CVE, err)
		}
		var nvdHas bool
		if err := st.nvdRefs.QueryRowContext(ctx, r.CVE).Scan(&nvdHas); err != nil {
			return out, fmt.Errorf("feeds: CVE record %s: %w", r.CVE, err)
		}
		if r.State == RecordPublished && !nvdHas {
			for _, ref := range r.Refs {
				tags, err := json.Marshal(ref.Tags)
				if err != nil {
					return out, err
				}
				if _, err := st.insRef.ExecContext(ctx, r.CVE, ref.URL, string(tags), ref.Source); err != nil {
					return out, fmt.Errorf("feeds: CVE record %s: %w", r.CVE, err)
				}
			}
		}
		out.Stored++
	}
	out.KEVFirst = out.KEVFirst && len(out.KEVChanged) > 0
	if err := applyAppleClaims(ctx, tx, now, added); err != nil { // the descriptions written may carry Apple's word on exploitation
		return out, err
	}
	return out, nil
}

// nullWord is a stored word, NULL for none.
func nullWord(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// replaceRecordRanges replaces the record ranges of r's CVE when they differ from the stored ones, and says whether they did and
// whether the rows a matcher reads did (Range.Generic, or a product's version scheme: SchemeProduct; the other rows kept in a
// vendor's notation are display-only).
func replaceRecordRanges(ctx context.Context, tx *sql.Tx, st *recordStmts, r CVERecord) (changed, matched bool, err error) {
	have, err := readRanges(ctx, tx, `WHERE r.cve = ? AND r.origin IN ('cna', 'adp')`, r.CVE)
	if err != nil {
		return false, false, err
	}
	want := r.Ranges
	if r.State == RecordRejected {
		want = nil
	}
	same := func(have, want []Range) bool {
		return len(have) == len(want) && !slices.ContainsFunc(want, func(w Range) bool {
			return !slices.ContainsFunc(have, func(h Range) bool { return sameRecordRange(h, w) })
		})
	}
	if same(have, want) {
		return false, false, nil
	}
	read := func(rs []Range) []Range { // the rows a matcher reads: generic ones, and those a product's version scheme reads
		return slices.DeleteFunc(slices.Clone(rs), func(x Range) bool { return !x.Generic() && !SchemeProduct(x) })
	}
	matched = !same(read(have), read(want))
	if _, err := st.delRanges.ExecContext(ctx, r.CVE); err != nil {
		return false, false, fmt.Errorf("feeds: CVE record %s: %w", r.CVE, err)
	}
	for _, w := range want {
		if _, err := st.insRange.ExecContext(ctx, r.CVE, w.Origin, w.Part, clipBytes(w.Vendor), clipBytes(w.Product), w.CPE, w.StartIncl, w.StartExcl,
			w.EndIncl, w.EndExcl, w.Fixed, w.VersionType, w.DefaultStatus); err != nil {
			return false, false, fmt.Errorf("feeds: CVE record %s: %w", r.CVE, err)
		}
	}
	return true, matched, nil
}

// sameRecordRange compares two record ranges of one CVE on every stored column.
func sameRecordRange(a, b Range) bool {
	return a.Origin == b.Origin && a.Part == b.Part && a.Vendor == clipBytes(b.Vendor) && a.Product == clipBytes(b.Product) && a.CPE == b.CPE &&
		sameSpan(a, b) && a.DefaultStatus == b.DefaultStatus
}

// ---- the exploited lists' view, as findings reads it today (KevAffected, RangesFromCVEOrg) ----

// recordSkipVendors are the vendors whose NVD rows findings reads with a comparator of its own: the CNA's versions of their products
// without a version scheme, written another way, would reach the generic comparison and could close an affected device. Juniper:
// Junos releases "21.4R3-S5" of its other products; Microsoft: Office editions and Windows builds. Their record ranges are stored,
// and left out of the generic views. A product with a version scheme needs no entry (recordSkipped leaves its record rows to the
// scheme): Citrix left this list when NetScaler's builds ("13.1-49.13") got theirs.
var recordSkipVendors = map[string]bool{"juniper": true, "microsoft": true}

// kevRecordView is, for each exploited-list CVE without NVD ranges, the record ranges of the product its owner entry names (the CNA's
// rows keyed RecordProductKey of the entry's vendor and product), as the matcher's CPE entries: CPE
// "cpe:2.3:*:<vendor>:<product>:<version or *>:…" with the entry's own names (never a guessed NVD name), an exact version written in
// the CPE. source is rangesCVEOrg for a complete list (every row says affected or unaffected) and rangesCVEOrgPartial otherwise. A
// CVE whose entry names several products ("Multiple Products"), a vendor of recordSkipVendors or a product with a version scheme
// (recordSkipped) has none.
func kevRecordView(ctx context.Context, q queryer) (map[string][]AffectedRow, map[string]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT k.cve, k.vendor, k.product FROM feeds_kev k
WHERE k.source_id IN ('cisa-kev', 'vulncheck-kev')
  AND k.list = (SELECT k2.list FROM feeds_kev k2 WHERE k2.cve = k.cve AND k2.source_id IN ('cisa-kev', 'vulncheck-kev') ORDER BY `+ownerOrder+` LIMIT 1)
  AND NOT EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = k.cve AND r.origin = 'nvd')
  AND EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = k.cve AND r.origin = 'cna' AND `+genericRowSQL+`)`)
	if err != nil {
		return nil, nil, fmt.Errorf("feeds: read record ranges: %w", err)
	}
	type owner struct{ vendor, product string }
	owners := map[string]owner{}
	for rows.Next() {
		var cve string
		var o owner
		if err := rows.Scan(&cve, &o.vendor, &o.product); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("feeds: read record ranges: %w", err)
		}
		owners[cve] = o
	}
	if err := rows.Close(); err != nil {
		return nil, nil, fmt.Errorf("feeds: read record ranges: %w", err)
	}
	aff, src := map[string][]AffectedRow{}, map[string]string{}
	if len(owners) == 0 {
		return aff, src, nil
	}
	cves := slices.Sorted(mapsKeys(boolKeys(owners)))
	for chunk := range slices.Chunk(cves, 500) {
		part, err := json.Marshal(chunk)
		if err != nil {
			return nil, nil, err
		}
		got, err := readRanges(ctx, q, `WHERE r.origin = 'cna' AND `+genericRowSQL+` AND r.cve IN (SELECT value FROM json_each(?))`, string(part))
		if err != nil {
			return nil, nil, err
		}
		for _, per := range groupByCVE(got) {
			cve := per[0].CVE
			if rows, source := KEVRecordRows(per, owners[cve].vendor, owners[cve].product); len(rows) > 0 {
				aff[cve], src[cve] = rows, source
			}
		}
	}
	return aff, src, nil
}

// KEVRecordRows is the view of kevRecordView for one CVE: of its record ranges, the CNA's rows of the product an exploited-list entry
// names (vendor, product), as the matcher's CPE entries, with "cve.org" for a complete list or "cve.org-partial"; none for a vendor of
// recordSkipVendors or a "Multiple Products" entry.
func KEVRecordRows(ranges []Range, vendor, product string) ([]AffectedRow, string) {
	k := RecordProductKey(vendor, product)
	cpeVendor, cpeProduct := productid.Norm(vendor), productid.Norm(product)
	if k.Vendor == "" || k.Product == "" || cpeProduct == "multipleproducts" || recordSkipVendors[k.Vendor] {
		return nil, ""
	}
	var rows []AffectedRow
	complete := true
	for _, r := range CutCatchAll(ranges) { // a record's "every later version" row stops at the trains it names fixes for
		if r.Origin != OriginCNA || r.Vendor != k.Vendor || r.Product != k.Product || r.Part != "" || !r.Generic() || recordSkipped(r) {
			continue
		}
		rows = append(rows, kevRecordRow(r, cpeVendor, cpeProduct))
		complete = complete && (r.DefaultStatus == DefaultAffected || r.DefaultStatus == DefaultUnaffected)
	}
	switch {
	case len(rows) == 0:
		return nil, ""
	case complete:
		return rows, rangesCVEOrg
	}
	return rows, rangesCVEOrgPartial
}

// kevRecordRow is a record range as the matcher's CPE entry: an exact version ([v, v]) in the CPE, a range beside a CPE of any version.
func kevRecordRow(r Range, vendor, product string) AffectedRow {
	cpe := func(version string) string {
		return "cpe:2.3:*:" + vendor + ":" + product + ":" + version + ":*:*:*:*:*:*:*"
	}
	if r.StartIncl != "" && r.StartIncl == r.EndIncl && r.StartExcl == "" && r.EndExcl == "" {
		return AffectedRow{CPE: cpe(cpeEscape(r.StartIncl))}
	}
	return AffectedRow{CPE: cpe("*"), StartIncl: r.StartIncl, StartExcl: r.StartExcl, EndIncl: r.EndIncl, EndExcl: r.EndExcl}
}

// ---- counts ----

// recordDue lists the CVEs whose record is asked for by its ID this pull, at most limit: only CVEs a public source names
// (publicListedSQL: never a custom list's, a box-built signal's or a finding's CVE), whose record was never read, or, without NVD
// ranges, not read since recordRecheck before now when the CVE is on an exploited list or published inside the window (an older
// signalled CVE without ranges, often Deferred or Rejected by NVD, is not asked again and again: the change log brings its changes).
// Never read first, then the longest ago.
func (s *Store) recordDue(ctx context.Context, now time.Time, limit int) ([]string, error) {
	return s.recordDueOf(ctx, publicListedSQL, now, limit)
}

// recordDueOf is recordDue over the CVEs of listed (a SELECT of one cve column, never one a box builds from its own data).
func (s *Store) recordDueOf(ctx context.Context, listed string, now time.Time, limit int) ([]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT i.cve FROM (`+listed+`) i LEFT JOIN feeds_cve c ON c.cve = i.cve
WHERE c.record_at IS NULL
   OR (c.record_at < ? AND NOT EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = i.cve AND r.origin = 'nvd')
       AND (i.cve IN (`+missingKEVSQL+`) OR c.published >= ?))
ORDER BY c.record_at IS NOT NULL, c.record_at, i.cve DESC
LIMIT ?`, store.FormatTS(now.Add(-recordRecheck)), store.FormatTS(now.AddDate(0, 0, -windowDays)), limit)
	if err != nil {
		return nil, fmt.Errorf("feeds: CVE records due: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("feeds: CVE records due: %w", err)
		}
		if cveRE.MatchString(c) {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

// recordBacklogSQL is the CVEs every box keeps whose record was never read: those a public list or signal names (publicListedSQL)
// and the catalogue's CVEs published since the window's start (the first argument). A stamped record (read, not published, waiting)
// is not one of them; a CVE only a custom list, a box-built signal or a finding keeps never is.
var recordBacklogSQL = `SELECT i.cve FROM (` + publicListedSQL + ` UNION SELECT cve FROM feeds_cve WHERE published >= ? AND record_at IS NULL) i
LEFT JOIN feeds_cve c ON c.cve = i.cve WHERE c.record_at IS NULL`

// recordBacklog lists at most limit CVEs of recordBacklogSQL: the exploited lists' first, then the newest IDs (a new CVE before an
// older one an exploit index names).
func (s *Store) recordBacklog(ctx context.Context, cutoff time.Time, limit int) ([]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT b.cve FROM (`+recordBacklogSQL+`) b
ORDER BY b.cve IN (`+missingKEVSQL+`) DESC, substr(b.cve, 5, 4) DESC, length(b.cve) DESC, b.cve DESC LIMIT ?`, store.FormatTS(cutoff), limit)
	if err != nil {
		return nil, fmt.Errorf("feeds: CVE records missing: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("feeds: CVE records missing: %w", err)
		}
		if cveRE.MatchString(c) {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

// recordBacklogCount is how many CVEs recordBacklogSQL holds.
func (s *Store) recordBacklogCount(ctx context.Context, cutoff time.Time) (int, error) {
	var n int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM (`+recordBacklogSQL+`)`, store.FormatTS(cutoff)).Scan(&n); err != nil {
		return 0, fmt.Errorf("feeds: CVE records missing: %w", err)
	}
	return n, nil
}

// recordUnread counts the CVEs a public list or signal names (publicListedSQL, as the NVD twin missingCount) whose record was never
// read: many of them (a new signal source that names thousands of older CVEs) are read from the daily archive, not one by one.
func (s *Store) recordUnread(ctx context.Context) (int, error) {
	var n int
	err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM (`+publicListedSQL+`) i LEFT JOIN feeds_cve c ON c.cve = i.cve WHERE c.record_at IS NULL`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("feeds: CVE records unread: %w", err)
	}
	return n, nil
}

// recordWaiting is the record_at of a CVE whose record changed in a day's last hour that no archive of changes held, and that is never
// asked for by ID (only this box keeps it): the stored record is older than the source's; the next read of the whole list replaces it.
// A real read time is never this one.
const recordWaiting = "1970-01-01T00:00:00.000Z"

// markRecordsWaiting marks these CVEs' records waiting (recordWaiting), unless the feed was edited or turned off meanwhile.
func (s *Service) markRecordsWaiting(ctx context.Context, run *recordRun, cves []string) error {
	part, err := json.Marshal(cves)
	if err != nil {
		return err
	}
	return s.DB.Write(ctx, func(tx *sql.Tx) error {
		row, err := sourceTx(ctx, tx, run.src.ID)
		if err != nil || row.Rev != run.src.Rev || !row.Enabled {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET record_at = ? WHERE cve IN (SELECT value FROM json_each(?))`, recordWaiting, string(part)); err != nil {
			return fmt.Errorf("feeds: CVE records waiting: %w", err)
		}
		return nil
	})
}

// recordWaitingCount is how many records wait for the next read of the whole list.
func (s *Store) recordWaitingCount(ctx context.Context) (int, error) {
	var n int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM feeds_cve WHERE record_at = ?`, recordWaiting).Scan(&n); err != nil {
		return 0, fmt.Errorf("feeds: CVE records waiting: %w", err)
	}
	return n, nil
}

// recordReadAt is when the record of each of these CVEs was last read (absent: never; a waiting record reads as never).
func (s *Store) recordReadAt(ctx context.Context, cves []string) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	for chunk := range slices.Chunk(cves, 500) {
		part, err := json.Marshal(chunk)
		if err != nil {
			return nil, err
		}
		rows, err := s.db.Reader().QueryContext(ctx, `SELECT cve, record_at FROM feeds_cve WHERE record_at IS NOT NULL AND record_at <> ? AND cve IN (SELECT value FROM json_each(?))`,
			recordWaiting, string(part))
		if err != nil {
			return nil, fmt.Errorf("feeds: CVE records read: %w", err)
		}
		for rows.Next() {
			var cve, at string
			if err := rows.Scan(&cve, &at); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("feeds: CVE records read: %w", err)
			}
			if t, err := parseTS(at); err == nil {
				out[cve] = t
			}
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return nil, fmt.Errorf("feeds: CVE records read: %w", err)
		}
	}
	return out, nil
}

// recordCount is how many catalogue CVEs have their record read.
func recordCount(ctx context.Context, q interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}) (int, error) {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM feeds_cve WHERE record_at IS NOT NULL`).Scan(&n); err != nil {
		return 0, fmt.Errorf("feeds: count CVE records: %w", err)
	}
	return n, nil
}
