package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/store"
)

// What a CVE record writes into the catalogue. The record reader is the one writer of feeds_cve.record_at, title, cwe, solution,
// workaround and the ssvc columns, of the cna and adp rows of feeds_cve_range and of feeds_cve_ref. It writes the description and the
// published day only while NVD has given none (NVD's English description wins as soon as NVD answers). CVSS scores stay NVD's: NVD's
// record carries the CNA's and CISA's scores too.

// importantSQL is the CVEs whose references the catalogue keeps (with the pinned CVEs the caller adds): an exploited-list entry or a
// qualifying signal. The same set, without the pinned ones, is the only set ever asked for by its ID.
const importantSQL = keepSetSQL

// recordKeep says which records the box stores.
type recordKeep struct {
	have      map[string]bool // in the catalogue, or kept whatever their age (an exploited-list entry, a qualifying signal, a pin)
	important map[string]bool // the references of these are kept: an exploited-list entry, a qualifying signal, a pin
	cutoff    time.Time       // a CVE published since is kept (the catalogue's window)
}

// recordKeepOf reads the keep sets.
func recordKeepOf(ctx context.Context, q queryer, now time.Time, pinned []string) (recordKeep, error) {
	have, err := stringSet(ctx, q, `SELECT cve FROM feeds_cve UNION `+keepSetSQL)
	if err != nil {
		return recordKeep{}, err
	}
	imp, err := stringSet(ctx, q, importantSQL)
	if err != nil {
		return recordKeep{}, err
	}
	for _, c := range pinned {
		have[c], imp[c] = true, true
	}
	return recordKeep{have: have, important: imp, cutoff: now.AddDate(0, 0, -windowDays)}, nil
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
}

// recordStmts are the prepared statements of one writeRecords call.
type recordStmts struct {
	ensure, update, readAt, delRanges, insRange, delRefs, insRef *sql.Stmt
}

func prepareRecordStmts(ctx context.Context, tx *sql.Tx) (*recordStmts, error) {
	var s recordStmts
	var err error
	for _, p := range []struct {
		st *(*sql.Stmt)
		q  string
	}{
		{&s.ensure, `INSERT INTO feeds_cve (cve, updated_at) VALUES (?, ?) ON CONFLICT(cve) DO NOTHING`},
		{&s.update, `UPDATE feeds_cve SET record_at = ?, title = ?, cwe = ?, solution = ?, workaround = ?, ssvc_exploitation = ?, ssvc_automatable = ?,
ssvc_impact = ?, description = CASE WHEN nvd_at IS NULL OR description = '' THEN ? ELSE description END, published = coalesce(published, ?)
WHERE cve = ?`},
		{&s.readAt, `SELECT record_at IS NOT NULL, EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = feeds_cve.cve AND r.origin = 'nvd') FROM feeds_cve WHERE cve = ?`},
		{&s.delRanges, `DELETE FROM feeds_cve_range WHERE cve = ? AND origin IN ('cna', 'adp')`},
		{&s.insRange, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, fixed, version_type, default_status)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`},
		{&s.delRefs, `DELETE FROM feeds_cve_ref WHERE cve = ?`},
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
	for _, st := range []*sql.Stmt{s.ensure, s.update, s.readAt, s.delRanges, s.insRange, s.delRefs, s.insRef} {
		if st != nil {
			_ = st.Close()
		}
	}
}

// writeRecords writes the records the keep rule keeps (recordKeep.keeps), each whole: its catalogue row's record columns, its record
// ranges (cna and adp, replacing the ones it had) and, for an important CVE, its references. A rejected record of a CVE the catalogue
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
		if _, err := st.update.ExecContext(ctx, ts, r.Title, string(cwe), r.Solution, r.Workaround, nullWord(r.SSVC.Exploitation),
			nullWord(r.SSVC.Automatable), nullWord(r.SSVC.Impact), r.Description, published, r.CVE); err != nil {
			return out, fmt.Errorf("feeds: CVE record %s: %w", r.CVE, err)
		}
		changed, err := replaceRecordRanges(ctx, tx, st, r)
		if err != nil {
			return out, err
		}
		if changed {
			if _, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET updated_at = ? WHERE cve = ?`, ts, r.CVE); err != nil {
				return out, fmt.Errorf("feeds: CVE record %s: %w", r.CVE, err)
			}
			if kev[r.CVE] && !hasNVD {
				out.KEVChanged, out.KEVFirst = append(out.KEVChanged, r.CVE), out.KEVFirst && !seen
			}
		}
		if _, err := st.delRefs.ExecContext(ctx, r.CVE); err != nil {
			return out, fmt.Errorf("feeds: CVE record %s: %w", r.CVE, err)
		}
		if k.important[r.CVE] && r.State == RecordPublished {
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
	return out, nil
}

// nullWord is a stored word, NULL for none.
func nullWord(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// replaceRecordRanges replaces the record ranges of r's CVE when they differ from the stored ones, and says whether they did.
func replaceRecordRanges(ctx context.Context, tx *sql.Tx, st *recordStmts, r CVERecord) (bool, error) {
	have, err := readRanges(ctx, tx, `WHERE r.cve = ? AND r.origin IN ('cna', 'adp')`, r.CVE)
	if err != nil {
		return false, err
	}
	want := r.Ranges
	if r.State == RecordRejected {
		want = nil
	}
	if len(have) == len(want) && !slices.ContainsFunc(want, func(w Range) bool {
		return !slices.ContainsFunc(have, func(h Range) bool { return sameRecordRange(h, w) })
	}) {
		return false, nil
	}
	if _, err := st.delRanges.ExecContext(ctx, r.CVE); err != nil {
		return false, fmt.Errorf("feeds: CVE record %s: %w", r.CVE, err)
	}
	for _, w := range want {
		if _, err := st.insRange.ExecContext(ctx, r.CVE, w.Origin, w.Part, clipBytes(w.Vendor), clipBytes(w.Product), w.CPE, w.StartIncl, w.StartExcl,
			w.EndIncl, w.EndExcl, w.Fixed, w.VersionType, w.DefaultStatus); err != nil {
			return false, fmt.Errorf("feeds: CVE record %s: %w", r.CVE, err)
		}
	}
	return true, nil
}

// sameRecordRange compares two record ranges of one CVE on every stored column.
func sameRecordRange(a, b Range) bool {
	return a.Origin == b.Origin && a.Part == b.Part && a.Vendor == clipBytes(b.Vendor) && a.Product == clipBytes(b.Product) && a.CPE == b.CPE &&
		sameSpan(a, b) && a.DefaultStatus == b.DefaultStatus
}

// pruneRecordRefs drops the references of CVEs that are no longer important (no list entry, no qualifying signal, no pin).
func pruneRecordRefs(ctx context.Context, tx *sql.Tx, pinned []string) error {
	pins, err := json.Marshal(append([]string{}, pinned...))
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_cve_ref WHERE cve NOT IN (`+importantSQL+`) AND cve NOT IN (SELECT value FROM json_each(?))`, string(pins)); err != nil {
		return fmt.Errorf("feeds: prune CVE references: %w", err)
	}
	return nil
}

// ---- the exploited lists' view, as findings reads it today (KevAffected, RangesFromCVEOrg) ----

// recordSkipVendors are the vendors whose NVD rows findings reads with a comparator of its own: the CNA's versions written another
// way would reach the generic one and could close an affected device. Juniper: Junos "21.4R3-S5"; Microsoft: Office editions and
// Windows builds; Citrix: builds written "13.1-49.13" or "13.1.49.13". Their record ranges are stored, and left out of this view.
var recordSkipVendors = map[string]bool{"juniper": true, "microsoft": true, "citrix": true}

// kevRecordView is, for each exploited-list CVE without NVD ranges, the record ranges of the product its owner entry names (the CNA's
// rows keyed RecordProductKey of the entry's vendor and product), as the matcher's CPE entries: CPE
// "cpe:2.3:*:<vendor>:<product>:<version or *>:…" with the entry's own names (never a guessed NVD name), an exact version written in
// the CPE. source is rangesCVEOrg for a complete list (every row says affected or unaffected) and rangesCVEOrgPartial otherwise. A
// CVE whose entry names several products ("Multiple Products") or a vendor of recordSkipVendors has none.
func kevRecordView(ctx context.Context, q queryer) (map[string][]AffectedRow, map[string]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT k.cve, k.vendor, k.product FROM feeds_kev k
WHERE k.source_id IN ('cisa-kev', 'vulncheck-kev')
  AND k.list = (SELECT k2.list FROM feeds_kev k2 WHERE k2.cve = k.cve AND k2.source_id IN ('cisa-kev', 'vulncheck-kev') ORDER BY `+ownerOrder+` LIMIT 1)
  AND NOT EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = k.cve AND r.origin = 'nvd')
  AND EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = k.cve AND r.origin = 'cna')`)
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
		got, err := readRanges(ctx, q, `WHERE r.origin = 'cna' AND r.cve IN (SELECT value FROM json_each(?))`, string(part))
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
	for _, r := range ranges {
		if r.Origin != OriginCNA || r.Vendor != k.Vendor || r.Product != k.Product || r.Part != "" {
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

// recordDue lists the CVEs whose record is asked for by its ID this pull, at most limit: only CVEs a public list or a qualifying
// public signal names (never a pin: a finding's CVE is never asked for by its ID), whose record was never read, or, without NVD
// ranges, not read since before. Never read first, then the longest ago.
func (s *Store) recordDue(ctx context.Context, before time.Time, limit int) ([]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT i.cve FROM (`+importantSQL+`) i LEFT JOIN feeds_cve c ON c.cve = i.cve
WHERE c.record_at IS NULL
   OR (c.record_at < ? AND NOT EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = i.cve AND r.origin = 'nvd'))
ORDER BY c.record_at IS NOT NULL, c.record_at, i.cve DESC
LIMIT ?`, store.FormatTS(before), limit)
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

// recordUnread counts the CVEs a public list or signal names whose record was never read: many of them (a new signal source that
// names thousands of older CVEs) are read from the daily archive, not one by one.
func (s *Store) recordUnread(ctx context.Context) (int, error) {
	var n int
	err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM (`+importantSQL+`) i LEFT JOIN feeds_cve c ON c.cve = i.cve WHERE c.record_at IS NULL`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("feeds: CVE records unread: %w", err)
	}
	return n, nil
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
