package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/versionscheme"
)

// The vulnerability catalogue: one row per CVE (feeds_cve) with its scores (feeds_cve_metric) and affected versions
// (feeds_cve_range), whichever pull brought it. Which CVEs it holds is the retention rule (retained, pruneCatalogue), not a table.

// windowDays is the catalogue's window: every CVE published in the last windowDays days is kept.
const windowDays = 365

// The origins of a range (feeds_cve_range.origin).
const (
	OriginNVD = "nvd"
	OriginCNA = "cna" // the CNA's affected[] list of the CVE record
	OriginADP = "adp" // an Authorized Data Publisher's (CISA) list of the CVE record
)

// epssHistKeep is how many days of EPSS scores feeds_epss_hist keeps (the "rising" display compares with a week before).
const epssHistKeep = 8

// keepSetSQL is the CVEs the retention rule keeps whatever their age: an exploited-list entry or a qualifying signal of any kind.
// Pinned CVEs (an open finding) are added by the caller.
const keepSetSQL = `SELECT cve FROM feeds_kev UNION SELECT cve FROM feeds_signal WHERE qualifies = 1`

// retention decides which NVD records a pull stores: those published inside the window and those of the keep set.
type retention struct {
	cutoff time.Time
	keep   map[string]bool
	all    bool // every record (tests that write NVD answers directly)
}

// retentionOf reads the keep set inside tx (one read per page: a list entry or signal stored meanwhile counts from the next page).
func retentionOf(ctx context.Context, tx *sql.Tx, now time.Time, pinned []string) (retention, error) {
	keep, err := stringSet(ctx, tx, keepSetSQL)
	if err != nil {
		return retention{}, err
	}
	for _, c := range pinned {
		keep[c] = true
	}
	return retention{cutoff: now.AddDate(0, 0, -windowDays), keep: keep}, nil
}

func (r retention) keeps(rec NVDRecord) bool {
	return r.all || r.keep[rec.CVE] || !rec.Published.Before(r.cutoff) && !strings.EqualFold(rec.Status, "Rejected")
}

// nvdWrite is what writeNVDRecords did.
type nvdWrite struct {
	Stored     int      // records written
	KEVChanged []string // CVEs of the exploited lists whose NVD ranges changed (findings matches them again)
	Catalogue  bool     // the NVD ranges of a CVE on no exploited list changed: findings' match pass reads them again
}

// writeNVDRecords writes the NVD records the retention rule keeps into the catalogue, each record whole: its row (dates, NVD's status,
// description), its scores and its NVD ranges replace what the catalogue had (the CVE record's own rows stay; reads prefer NVD's when
// there are any). NVD's weaknesses replace the CVE's when NVD lists any (they carry the CNA's and CISA's too); NVD's references replace
// the CVE's, for every CVE it stores, once NVD has tagged them (nvdRefs). A record NVD rejected keeps only its
// status, so the retention rule drops it unless a list, a signal or a finding holds it. A record older than the stored one (NVD's lastModified) is skipped: a pull that collected its pages over several checks
// never puts back what a later pull already replaced.
func writeNVDRecords(ctx context.Context, tx *sql.Tx, recs []NVDRecord, ret retention, now time.Time) (nvdWrite, error) {
	var out nvdWrite
	stamp := store.FormatTS(now)
	kev, err := stringSet(ctx, tx, `SELECT cve FROM feeds_kev WHERE source_id IN ('cisa-kev', 'vulncheck-kev')`)
	if err != nil {
		return out, err
	}
	storedMod, err := tx.PrepareContext(ctx, `SELECT modified FROM feeds_cve WHERE cve = ? AND modified IS NOT NULL`)
	if err != nil {
		return out, fmt.Errorf("feeds: catalogue: %w", err)
	}
	defer func() { _ = storedMod.Close() }()
	upCVE, err := tx.PrepareContext(ctx, `INSERT INTO feeds_cve (cve, published, modified, nvd_status, nvd_at, description, cwe, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(cve) DO UPDATE SET published = coalesce(excluded.published, published), modified = coalesce(excluded.modified, modified), nvd_status = excluded.nvd_status, nvd_at = excluded.nvd_at,
description = excluded.description, cwe = CASE WHEN excluded.cwe = '[]' THEN cwe ELSE excluded.cwe END, updated_at = excluded.updated_at`)
	if err != nil {
		return out, fmt.Errorf("feeds: catalogue: %w", err)
	}
	defer func() { _ = upCVE.Close() }()
	delMetric, err := tx.PrepareContext(ctx, `DELETE FROM feeds_cve_metric WHERE cve = ?`)
	if err != nil {
		return out, fmt.Errorf("feeds: catalogue: %w", err)
	}
	defer func() { _ = delMetric.Close() }()
	insMetric, err := tx.PrepareContext(ctx, `INSERT INTO feeds_cve_metric (cve, source, version, score, vector) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return out, fmt.Errorf("feeds: catalogue: %w", err)
	}
	defer func() { _ = insMetric.Close() }()
	delRange, err := tx.PrepareContext(ctx, `DELETE FROM feeds_cve_range WHERE cve = ? AND origin = 'nvd'`)
	if err != nil {
		return out, fmt.Errorf("feeds: catalogue: %w", err)
	}
	defer func() { _ = delRange.Close() }()
	insRange, err := tx.PrepareContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, platforms)
VALUES (?, 'nvd', ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return out, fmt.Errorf("feeds: catalogue: %w", err)
	}
	defer func() { _ = insRange.Close() }()
	delRef, err := tx.PrepareContext(ctx, `DELETE FROM feeds_cve_ref WHERE cve = ?`)
	if err != nil {
		return out, fmt.Errorf("feeds: catalogue: %w", err)
	}
	defer func() { _ = delRef.Close() }()
	insRef, err := tx.PrepareContext(ctx, `INSERT INTO feeds_cve_ref (cve, url, tags, source) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return out, fmt.Errorf("feeds: catalogue: %w", err)
	}
	defer func() { _ = insRef.Close() }()
	added := map[string]bool{} // CVEs whose description gains Apple's claim in this write (appleNoteAdded)
	for i, r := range recs {
		if i%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return out, err
			}
		}
		rejected := strings.EqualFold(r.Status, "Rejected")
		if !ret.keeps(r) {
			if !rejected {
				continue
			}
			var n int // a rejected record of a CVE the catalogue holds: its status says so, and the retention rule takes it out
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM feeds_cve WHERE cve = ?`, r.CVE).Scan(&n); err != nil {
				return out, fmt.Errorf("feeds: catalogue: %w", err)
			}
			if n == 0 {
				continue
			}
		}
		if !r.LastModified.IsZero() {
			var mod string
			err := storedMod.QueryRowContext(ctx, r.CVE).Scan(&mod)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return out, fmt.Errorf("feeds: catalogue: %w", err)
			}
			if t, perr := parseTS(mod); err == nil && perr == nil && r.LastModified.Before(t) {
				continue // the catalogue holds a newer record of this CVE
			}
		}
		if !kev[r.CVE] && !out.Catalogue { // a catalogue CVE's ranges: one change is enough to say so
			same, err := sameNVDRanges(ctx, tx, r)
			if err != nil {
				return out, err
			}
			out.Catalogue = !same
		}
		if kev[r.CVE] {
			same, err := sameNVDRanges(ctx, tx, r)
			if err != nil {
				return out, err
			}
			var known bool
			if err := tx.QueryRowContext(ctx, `SELECT nvd_at IS NOT NULL FROM feeds_cve WHERE cve = ?`, r.CVE).Scan(&known); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return out, fmt.Errorf("feeds: catalogue: %w", err)
			}
			if !same || !known {
				out.KEVChanged = append(out.KEVChanged, r.CVE)
			}
		}
		cwe, err := json.Marshal(append([]string{}, r.CWE...))
		if err != nil {
			return out, err
		}
		if err := appleNoteAdded(ctx, tx, r.CVE, r.Description, added); err != nil {
			return out, err
		}
		if _, err := upCVE.ExecContext(ctx, r.CVE, tsOrNull(r.Published), tsOrNull(r.LastModified), r.Status, stamp, r.Description, string(cwe), stamp); err != nil {
			return out, fmt.Errorf("feeds: catalogue %s: %w", r.CVE, err)
		}
		if _, err := delMetric.ExecContext(ctx, r.CVE); err != nil {
			return out, fmt.Errorf("feeds: catalogue %s: %w", r.CVE, err)
		}
		if _, err := delRange.ExecContext(ctx, r.CVE); err != nil {
			return out, fmt.Errorf("feeds: catalogue %s: %w", r.CVE, err)
		}
		out.Stored++
		if rejected {
			continue
		}
		for _, m := range r.Metrics {
			if _, err := insMetric.ExecContext(ctx, r.CVE, m.Source, m.Version, m.Score, m.Vector); err != nil {
				return out, fmt.Errorf("feeds: catalogue %s: %w", r.CVE, err)
			}
		}
		if r.Tagged() {
			if err := nvdRefs(ctx, delRef, insRef, r); err != nil {
				return out, err
			}
		}
		for j, a := range r.Affected {
			plats := []string{}
			if j < len(r.Platforms) && r.Platforms[j] != nil {
				plats = r.Platforms[j]
			}
			pj, err := json.Marshal(plats)
			if err != nil {
				return out, err
			}
			part, vendor, product := cpeParts(a.CPE)
			if _, err := insRange.ExecContext(ctx, r.CVE, part, clipBytes(vendor), clipBytes(product), a.CPE,
				a.StartIncl, a.StartExcl, a.EndIncl, a.EndExcl, string(pj)); err != nil {
				return out, fmt.Errorf("feeds: catalogue %s: %w", r.CVE, err)
			}
		}
	}
	if err := applyAppleClaims(ctx, tx, now, added); err != nil { // the descriptions written may carry Apple's word on exploitation
		return out, err
	}
	return out, nil
}

// nvdRefs replaces the references of r's CVE by NVD's, which NVD has tagged: one vocabulary of tags (nvdTag), source "nvd". NVD
// lists the CNA's and the ADPs' references too, with an analyst's tags; while NVD has tagged none, the CVE record's stand
// (writeRecords), and once NVD has, the record's never replace them. One rule, so the stored references do not depend on which pull
// came first.
func nvdRefs(ctx context.Context, del, ins *sql.Stmt, r NVDRecord) error {
	if _, err := del.ExecContext(ctx, r.CVE); err != nil {
		return fmt.Errorf("feeds: catalogue %s: %w", r.CVE, err)
	}
	for _, ref := range r.Refs {
		tags, err := json.Marshal(ref.Tags)
		if err != nil {
			return err
		}
		if _, err := ins.ExecContext(ctx, r.CVE, ref.URL, string(tags), RefsNVD); err != nil {
			return fmt.Errorf("feeds: catalogue %s: %w", r.CVE, err)
		}
	}
	return nil
}

// tsOrNull is t as stored, NULL for the zero time (a record always has both dates; a test's record may not).
func tsOrNull(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return store.FormatTS(t)
}

// clipBytes cuts s to at most maxVendorProduct bytes at a rune boundary (a CPE vendor or product kept in a range row).
func clipBytes(s string) string {
	n := maxVendorProduct
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// sameNVDRanges reports whether the stored NVD ranges of r's CVE are exactly r's (a CVE NVD did not change is not news).
func sameNVDRanges(ctx context.Context, tx *sql.Tx, r NVDRecord) (bool, error) {
	have, err := readRanges(ctx, tx, `WHERE r.cve = ? AND r.origin = 'nvd'`, r.CVE)
	if err != nil {
		return false, err
	}
	if len(have) != len(r.Affected) {
		return false, nil
	}
	for i, h := range have {
		if h.AffectedRow() != r.Affected[i] {
			return false, nil
		}
	}
	return true, nil
}

// pruneCatalogue applies the retention rule: a CVE stays while it was published inside the window (and NVD did not reject it), or
// is on an exploited list, or has a qualifying signal of any kind and any age, or an open finding pins it. Nothing ages out from under
// an open finding. It also drops the EPSS history older than epssHistKeep days and of CVEs no list or signal names.
func pruneCatalogue(ctx context.Context, tx *sql.Tx, now time.Time, pinned []string) error {
	pins, err := json.Marshal(append([]string{}, pinned...))
	if err != nil {
		return fmt.Errorf("feeds: prune catalogue: %w", err)
	}
	cutoff := store.FormatTS(now.AddDate(0, 0, -windowDays))
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_cve WHERE (published IS NULL OR published < ? OR nvd_status = 'Rejected')
AND NOT EXISTS (SELECT 1 FROM feeds_kev k WHERE k.cve = feeds_cve.cve)
AND NOT EXISTS (SELECT 1 FROM feeds_signal s WHERE s.cve = feeds_cve.cve AND s.qualifies = 1)
AND cve NOT IN (SELECT value FROM json_each(?))`, cutoff, string(pins)); err != nil {
		return fmt.Errorf("feeds: prune catalogue: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_epss_hist WHERE day < ? OR cve NOT IN (SELECT cve FROM feeds_kev UNION SELECT cve FROM feeds_signal)`,
		now.UTC().AddDate(0, 0, -epssHistKeep).Format(time.DateOnly)); err != nil {
		return fmt.Errorf("feeds: prune EPSS history: %w", err)
	}
	return nil
}

// Range is one affected-versions row of the catalogue.
type Range struct {
	CVE, Origin                            string
	Part, Vendor, Product, CPE             string
	StartIncl, StartExcl, EndIncl, EndExcl string
	Fixed, VersionType                     string
	// DefaultStatus is the CVE record entry's defaultStatus of a CNA or ADP row (DefaultAffected, DefaultUnaffected, DefaultUnknown);
	// "" for NVD's rows.
	DefaultStatus string
	Platforms     []string // NVD's "running on" operating systems ("microsoft:windows"); empty for none
}

// AffectedRow is the range as the matcher's CPE entry.
func (r Range) AffectedRow() AffectedRow {
	return AffectedRow{CPE: r.CPE, StartIncl: r.StartIncl, StartExcl: r.StartExcl, EndIncl: r.EndIncl, EndExcl: r.EndExcl}
}

const rangeCols = `r.cve, r.origin, r.part, r.vendor, r.product, r.cpe, r.start_incl, r.start_excl, r.end_incl, r.end_excl, r.fixed, r.version_type, r.default_status, r.platforms`

func readRanges(ctx context.Context, q queryer, where string, args ...any) ([]Range, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+rangeCols+` FROM feeds_cve_range r `+where+` ORDER BY r.cve, r.id`, args...)
	if err != nil {
		return nil, fmt.Errorf("feeds: read ranges: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Range
	for rows.Next() {
		var (
			r  Range
			pl sql.NullString
		)
		if err := rows.Scan(&r.CVE, &r.Origin, &r.Part, &r.Vendor, &r.Product, &r.CPE, &r.StartIncl, &r.StartExcl, &r.EndIncl, &r.EndExcl, &r.Fixed, &r.VersionType, &r.DefaultStatus, &pl); err != nil {
			return nil, fmt.Errorf("feeds: read ranges: %w", err)
		}
		r.Platforms = []string{}
		if pl.Valid && json.Unmarshal([]byte(pl.String), &r.Platforms) != nil {
			r.Platforms = []string{}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// rangeOrigin is the precedence of one CVE's ranges, applied when they are read: NVD's rows when NVD gives any, else the CVE record's
// (origin cna or adp) that the generic comparison reads (Range.Generic; a row kept in a vendor's notation never counts here, its
// product's version scheme reads it: RangeSpan). It returns the rows that count.
func rangeOrigin(rows []Range) []Range {
	rows = slices.DeleteFunc(rows, func(r Range) bool { return !r.Generic() })
	if slices.ContainsFunc(rows, func(r Range) bool { return r.Origin == OriginNVD }) {
		return slices.DeleteFunc(rows, func(r Range) bool { return r.Origin != OriginNVD })
	}
	return rows
}

// ProductKey names a product as the catalogue's ranges do: CPE vendor and product, lower case ("apache", "http_server").
type ProductKey struct{ Vendor, Product string }

// Ranges returns the ranges of every catalogue CVE that names one of these products, with the precedence of rangeOrigin applied per
// CVE (a CVE NVD gives ranges for counts only NVD's, also when NVD names other products). Sorted by CVE, then as stored.
func (s *Store) Ranges(ctx context.Context, keys []ProductKey) ([]Range, error) {
	cves := map[string]bool{}
	for chunk := range slices.Chunk(keys, 400) {
		pairs := make([][2]string, len(chunk))
		for i, k := range chunk {
			pairs[i] = [2]string{strings.ToLower(k.Vendor), strings.ToLower(k.Product)}
		}
		part, err := json.Marshal(pairs)
		if err != nil {
			return nil, fmt.Errorf("feeds: ranges: %w", err)
		}
		got, err := stringSet(ctx, s.db.Reader(), `SELECT DISTINCT r.cve FROM json_each(?) j
JOIN feeds_cve_range r ON r.vendor = json_extract(j.value, '$[0]') AND r.product = json_extract(j.value, '$[1]')`, string(part))
		if err != nil {
			return nil, err
		}
		for c := range got {
			cves[c] = true
		}
	}
	want := map[ProductKey]bool{}
	for _, k := range keys {
		want[ProductKey{strings.ToLower(k.Vendor), strings.ToLower(k.Product)}] = true
	}
	var out []Range
	for chunk := range slices.Chunk(slices.Sorted(mapsKeys(cves)), 400) {
		part, err := json.Marshal(chunk)
		if err != nil {
			return nil, fmt.Errorf("feeds: ranges: %w", err)
		}
		rows, err := readRanges(ctx, s.db.Reader(), `WHERE r.cve IN (SELECT value FROM json_each(?))`, string(part))
		if err != nil {
			return nil, err
		}
		for _, per := range groupByCVE(rows) {
			for _, r := range rangeOrigin(per) {
				if want[ProductKey{r.Vendor, r.Product}] {
					out = append(out, r)
				}
			}
		}
	}
	return out, nil
}

// RangeProduct is a product a catalogue range names: a CPE's vendor and product, or, Record set, a CVE record's product key (no CPE).
type RangeProduct struct {
	Vendor, Product string
	Record          bool
}

// RangeProducts is every product a catalogue range names, each once: the match pass keeps those its devices run and reads only their
// ranges (Ranges). One walk of the (vendor, product, cpe) index.
func (s *Store) RangeProducts(ctx context.Context) ([]RangeProduct, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT DISTINCT vendor, product, cpe = '' FROM feeds_cve_range`)
	if err != nil {
		return nil, fmt.Errorf("feeds: range products: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []RangeProduct
	for rows.Next() {
		var k RangeProduct
		if err := rows.Scan(&k.Vendor, &k.Product, &k.Record); err != nil {
			return nil, fmt.Errorf("feeds: range products: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// MatchName is the vendor and product a range names, as the matcher compares them with a device's software: a CPE's own names; for a
// CVE record's product key (record), the product the catalogue knows by that name (core/productid ByRangeName), by its NVD name
// when it has one, else by its own normalised name; a record key the catalogue does not know stays as it is. So a record that names
// "Palo Alto Networks" "PAN-OS" reaches the device NVD's paloaltonetworks:pan-os names.
func MatchName(vendor, product string, record bool) (string, string) {
	if !record {
		return vendor, product
	}
	p, ok := productid.ByRangeName("", vendor, product)
	if !ok {
		return vendor, product
	}
	for _, c := range p.CPEs {
		if !c.Prefix && c.Vendor != "" && c.Product != "" {
			return c.Vendor, c.Product
		}
	}
	return productid.Norm(p.Vendor), productid.Norm(p.Product)
}

// RangesOf returns the ranges of these CVEs with the precedence of rangeOrigin applied per CVE, sorted by CVE, then as stored. A CVE
// the catalogue does not hold, or holds without ranges, is absent.
func (s *Store) RangesOf(ctx context.Context, cves []string) ([]Range, error) {
	var out []Range
	for chunk := range slices.Chunk(cves, 400) {
		part, err := json.Marshal(chunk)
		if err != nil {
			return nil, fmt.Errorf("feeds: ranges: %w", err)
		}
		rows, err := readRanges(ctx, s.db.Reader(), `WHERE r.cve IN (SELECT value FROM json_each(?))`, string(part))
		if err != nil {
			return nil, err
		}
		for _, per := range groupByCVE(rows) {
			out = append(out, rangeOrigin(per)...)
		}
	}
	return out, nil
}

// SchemeRangesOf returns the ranges of these CVEs a product's version scheme reads (RangeScheme): the rows kept in their vendor's
// notation (Range.Generic false), the CVE records' rows of a product that has a scheme (SchemeProduct: the vendor's own word, read per
// release train, never by the generic comparison), and for a product whose vendor states its releases in the description (Described)
// the rows the description gives (describedRows, statedUnaffected). Sorted by CVE, then as stored.
func (s *Store) SchemeRangesOf(ctx context.Context, cves []string) ([]Range, error) {
	var out, worded []Range // worded: record rows of a Described product, whose description may say more
	nvdNamed, err := json.Marshal(nvdNotationCPEs())
	if err != nil {
		return nil, fmt.Errorf("feeds: vendor ranges: %w", err)
	}
	for chunk := range slices.Chunk(cves, 400) {
		part, err := json.Marshal(chunk)
		if err != nil {
			return nil, fmt.Errorf("feeds: vendor ranges: %w", err)
		}
		rows, err := readRanges(ctx, s.db.Reader(), `WHERE r.cve IN (SELECT value FROM json_each(?)) AND (NOT (`+genericRowSQL+`) OR r.origin <> 'nvd'
OR r.part || ':' || r.vendor || ':' || r.product IN (SELECT value FROM json_each(?)))`, string(part), string(nvdNamed))
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if !r.Generic() || SchemeProduct(r) {
				out = append(out, r)
			}
			if r.Origin != OriginNVD && describedProduct(r) {
				worded = append(worded, r)
			}
		}
	}
	if len(worded) == 0 {
		return out, nil
	}
	desc, err := s.descriptionsOf(ctx, worded)
	if err != nil {
		return nil, err
	}
	var fixes map[string]lineFixes // read once, when a row states no version
	stated := map[string]bool{}    // CVE and product whose stated lines are added
	for _, r := range worded {
		if recordBounded(r) {
			if k := r.CVE + "|" + r.Part + ":" + r.Vendor + ":" + r.Product; !stated[k] {
				stated[k] = true
				out = append(out, statedUnaffected(r, desc[r.CVE])...)
			}
			continue
		}
		if fixes == nil {
			if fixes, err = s.describedFixes(ctx); err != nil {
				return nil, err
			}
		}
		var patched []versionscheme.Version
		if p, ok := productid.ByRangeName(r.Part, r.Vendor, r.Product); ok {
			patched = fixes[p.Key].patchedWith(r.CVE)
		}
		out = append(out, describedRows(r, desc[r.CVE], patched)...)
	}
	slices.SortStableFunc(out, func(a, b Range) int { return strings.Compare(a.CVE, b.CVE) })
	return out, nil
}

// descriptionsOf is the description of each CVE of rows.
func (s *Store) descriptionsOf(ctx context.Context, rows []Range) (map[string]string, error) {
	cves := make([]string, 0, len(rows))
	for _, r := range rows {
		cves = append(cves, r.CVE)
	}
	part, err := json.Marshal(slices.Compact(slices.Sorted(slices.Values(cves))))
	if err != nil {
		return nil, fmt.Errorf("feeds: descriptions: %w", err)
	}
	q, err := s.db.Reader().QueryContext(ctx, `SELECT cve, description FROM feeds_cve WHERE cve IN (SELECT value FROM json_each(?))`, string(part))
	if err != nil {
		return nil, fmt.Errorf("feeds: descriptions: %w", err)
	}
	defer func() { _ = q.Close() }()
	out := map[string]string{}
	for q.Next() {
		var c, d string
		if err := q.Scan(&c, &d); err != nil {
			return nil, fmt.Errorf("feeds: descriptions: %w", err)
		}
		out[c] = d
	}
	return out, q.Err()
}

// SchemeCVEs returns the CVEs whose CVE record rows (origin cna or adp) name one of these products: a CVE a vendor states in its own
// notation reaches the match pass before NVD analyses it (Ranges returns only the rows the generic comparison reads). Sorted.
func (s *Store) SchemeCVEs(ctx context.Context, keys []ProductKey) ([]string, error) {
	cves := map[string]bool{}
	for chunk := range slices.Chunk(keys, 400) {
		pairs := make([][2]string, len(chunk))
		for i, k := range chunk {
			pairs[i] = [2]string{strings.ToLower(k.Vendor), strings.ToLower(k.Product)}
		}
		part, err := json.Marshal(pairs)
		if err != nil {
			return nil, fmt.Errorf("feeds: scheme CVEs: %w", err)
		}
		got, err := stringSet(ctx, s.db.Reader(), `SELECT DISTINCT r.cve FROM json_each(?) j
JOIN feeds_cve_range r ON r.vendor = json_extract(j.value, '$[0]') AND r.product = json_extract(j.value, '$[1]') WHERE r.origin <> 'nvd'`, string(part))
		if err != nil {
			return nil, err
		}
		for c := range got {
			cves[c] = true
		}
	}
	return slices.Sorted(mapsKeys(cves)), nil
}

// SchemeProduct says the range names a product whose versions the product catalogue declares a version scheme for (core/productid
// ByRangeName, field "scheme"): its CVE record rows are read through that scheme only (RangeScheme).
func SchemeProduct(r Range) bool {
	p, ok := productid.ByRangeName(r.Part, r.Vendor, r.Product)
	return ok && p.Scheme != ""
}

// nvdNotationCPEs is "part:vendor:product" of every NVD name of a product whose scheme NVD writes in the vendor's notation
// (versionscheme NVDNotation: DSM's "7.2.1-69057-6"): NVD's rows of these products are read in the scheme too (SchemeRangesOf), beside
// the generic comparison.
var nvdNotationCPEs = sync.OnceValue(func() []string {
	out := []string{}
	for _, p := range productid.Products() {
		if s, ok := versionscheme.Lookup(p.Scheme); !ok || !s.NVDNotation {
			continue
		}
		for _, c := range p.CPEs {
			if !c.Prefix {
				out = append(out, c.Base())
			}
		}
	}
	return out
})

// recordSkipped says a CVE record row is left out of the generic comparison's views (MatchRow, KEVRecordRows): its product has a
// version scheme that reads it (a row with a bound: one without says no version a scheme could place, recordBounded), or its vendor is
// one whose versions findings compares with rules of its own (recordSkipVendors).
func recordSkipped(r Range) bool {
	return r.Origin != OriginNVD && (recordSkipVendors[r.Vendor] || SchemeProduct(r) && recordBounded(r))
}

// recordBounded says a CVE record row states a version: a bound or a fixed release. A row of a product with no version at all (Synology's
// records name "DiskStation Manager (DSM)" with only "affected") is no range a scheme can read: the generic comparison keeps it, and it
// asks for the version as before.
func recordBounded(r Range) bool {
	return r.StartIncl != "" || r.StartExcl != "" || r.EndIncl != "" || r.EndExcl != "" || r.Fixed != ""
}

// MatchRow is the range as the matcher's CPE entry: NVD's and a record's CPE as stated, a record's product without a CPE as
// "cpe:2.3:*:<vendor>:<product>:…" of the name the catalogue knows it by (MatchName, kevRecordRow). ok is false for a record row the
// generic comparison does not read (recordSkipped: a product with a version scheme, a vendor whose versions findings compares with
// rules of its own).
func (r Range) MatchRow() (AffectedRow, bool) {
	if recordSkipped(r) {
		return AffectedRow{}, false
	}
	if r.CPE == "" {
		if r.Vendor == "" || r.Product == "" {
			return AffectedRow{}, false
		}
		v, p := MatchName(r.Vendor, r.Product, true)
		return kevRecordRow(r, cpeEscape(v), cpeEscape(p)), true
	}
	return r.AffectedRow(), true
}

// groupByCVE splits rows sorted by CVE into one slice per CVE.
func groupByCVE(rows []Range) [][]Range {
	var out [][]Range
	for i := 0; i < len(rows); {
		j := i + 1
		for j < len(rows) && rows[j].CVE == rows[i].CVE {
			j++
		}
		out = append(out, rows[i:j:j])
		i = j
	}
	return out
}

func mapsKeys(m map[string]bool) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// Signal is one feeds_signal row: why a CVE is urgent, from which source, since when.
type Signal struct {
	CVE, Kind, Source             string
	FirstSeen, StoredAt, LastSeen time.Time
	Qualifies                     bool
	URL                           string
	Detail                        json.RawMessage // small, for display; nil when none
}

// Signals returns the signal rows of these CVEs, each CVE's sorted by first sighting.
func (s *Store) Signals(ctx context.Context, cves []string) (map[string][]Signal, error) {
	out := map[string][]Signal{}
	for chunk := range slices.Chunk(cves, 500) {
		part, err := json.Marshal(chunk)
		if err != nil {
			return nil, fmt.Errorf("feeds: signals: %w", err)
		}
		rows, err := s.db.Reader().QueryContext(ctx, `SELECT cve, kind, source, first_seen, stored_at, last_seen, qualifies, url, detail FROM feeds_signal
WHERE cve IN (SELECT value FROM json_each(?)) ORDER BY cve, first_seen, kind, source`, string(part))
		if err != nil {
			return nil, fmt.Errorf("feeds: signals: %w", err)
		}
		for rows.Next() {
			var (
				g          Signal
				fs, sa, ls string
				detail     sql.NullString
			)
			if err := rows.Scan(&g.CVE, &g.Kind, &g.Source, &fs, &sa, &ls, &g.Qualifies, &g.URL, &detail); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("feeds: signals: %w", err)
			}
			var e1, e2, e3 error
			g.FirstSeen, e1 = parseTS(fs)
			g.StoredAt, e2 = parseTS(sa)
			g.LastSeen, e3 = parseTS(ls)
			if err := errors.Join(e1, e2, e3); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("feeds: signals: %w", err)
			}
			if detail.Valid {
				g.Detail = json.RawMessage(detail.String)
			}
			out[g.CVE] = append(out[g.CVE], g)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return nil, fmt.Errorf("feeds: signals: %w", err)
		}
	}
	return out, nil
}

// CatalogueEntry is one CVE of the catalogue as the matcher and the pages read it.
type CatalogueEntry struct {
	CVE                 string
	Published, Modified *time.Time
	NVDStatus           string     // "" until NVD answered
	NVDAt, RecordAt     *time.Time // when NVD answered, when the CVE record was read; nil: never
	Title, Description  string
	CVSS                *CVSS // PickCVSS of the stored scores; nil when none
	Severity            string
	EPSS, Percentile    *float64
	// RangesFrom is the origin of the ranges that count (rangeOrigin): OriginNVD, OriginCNA, OriginADP, or "" when none;
	// RangesComplete says, for the CVE record's rows, whether they make a complete list: every row's entry says
	// affected or unaffected for the versions it does not list.
	RangesFrom     string
	RangesComplete bool
}

// Catalogue returns the catalogue entries of these CVEs; a CVE the catalogue does not hold is absent.
func (s *Store) Catalogue(ctx context.Context, cves []string) (map[string]CatalogueEntry, error) {
	out := map[string]CatalogueEntry{}
	db := s.db.Reader()
	for chunk := range slices.Chunk(cves, 500) {
		part, err := json.Marshal(chunk)
		if err != nil {
			return nil, fmt.Errorf("feeds: catalogue: %w", err)
		}
		rows, err := db.QueryContext(ctx, `SELECT c.cve, c.published, c.modified, c.nvd_status, c.nvd_at, c.record_at, c.title, c.description, e.epss, e.percentile,
(SELECT CASE WHEN EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = c.cve AND r.origin = 'nvd') THEN 'nvd'
             ELSE (SELECT min(r.origin) FROM feeds_cve_range r WHERE r.cve = c.cve AND `+genericRowSQL+`) END),
NOT EXISTS (SELECT 1 FROM feeds_cve_range r WHERE r.cve = c.cve AND r.origin <> 'nvd' AND `+genericRowSQL+` AND r.default_status NOT IN ('affected', 'unaffected'))
FROM feeds_cve c LEFT JOIN feeds_epss e ON e.cve = c.cve WHERE c.cve IN (SELECT value FROM json_each(?))`, string(part))
		if err != nil {
			return nil, fmt.Errorf("feeds: catalogue: %w", err)
		}
		for rows.Next() {
			var (
				e                                 CatalogueEntry
				pub, mod, status, nvdAt, recordAt sql.NullString
				origin                            sql.NullString
			)
			var complete bool
			if err := rows.Scan(&e.CVE, &pub, &mod, &status, &nvdAt, &recordAt, &e.Title, &e.Description, &e.EPSS, &e.Percentile, &origin, &complete); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("feeds: catalogue: %w", err)
			}
			e.Published, e.Modified, e.NVDAt, e.RecordAt = optTime(pub), optTime(mod), optTime(nvdAt), optTime(recordAt)
			e.NVDStatus, e.RangesFrom = status.String, origin.String
			e.RangesComplete = complete && e.RangesFrom != "" && e.RangesFrom != OriginNVD
			out[e.CVE] = e
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return nil, fmt.Errorf("feeds: catalogue: %w", err)
		}
	}
	scores, err := s.metricsOf(ctx, slices.Collect(mapsKeys(boolKeys(out))))
	if err != nil {
		return nil, err
	}
	for cve, ms := range scores {
		if c, ok := PickCVSS(ms); ok {
			e := out[cve]
			e.CVSS, e.Severity = &c, Severity(c.Score, c.Version)
			out[cve] = e
		}
	}
	return out, nil
}

func boolKeys[V any](m map[string]V) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func optTime(s sql.NullString) *time.Time {
	if !s.Valid {
		return nil
	}
	t, err := parseTS(s.String)
	if err != nil {
		return nil
	}
	return &t
}

// metricsOf reads the stored scores of these CVEs.
func (s *Store) metricsOf(ctx context.Context, cves []string) (map[string][]Metric, error) {
	out := map[string][]Metric{}
	for chunk := range slices.Chunk(cves, 500) {
		part, err := json.Marshal(chunk) // one parameter: the CVEs as a JSON array (json_each), no SQL built from strings
		if err != nil {
			return nil, fmt.Errorf("feeds: cvss: %w", err)
		}
		rows, err := s.db.Reader().QueryContext(ctx, `SELECT cve, source, version, score, vector FROM feeds_cve_metric WHERE cve IN (SELECT value FROM json_each(?))`, string(part))
		if err != nil {
			return nil, fmt.Errorf("feeds: cvss: %w", err)
		}
		for rows.Next() {
			var cve string
			var m Metric
			if err := rows.Scan(&cve, &m.Source, &m.Version, &m.Score, &m.Vector); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("feeds: cvss: %w", err)
			}
			out[cve] = append(out[cve], m)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return nil, fmt.Errorf("feeds: cvss: %w", err)
		}
	}
	return out, nil
}

// CVSSOf returns the CVSS base score of each of these CVEs that has one (PickCVSS of the catalogue's scores), with its version, source
// and vector. A CVE without a score is absent: the pages say "No CVSS score", never 0. The source is "nvd" or "cna" as the findings
// API names it: CISA's ADP, another scorer than NVD, reads as "cna" there.
func (s *Store) CVSSOf(ctx context.Context, cves []string) (map[string]CVSS, error) {
	scores, err := s.metricsOf(ctx, cves)
	if err != nil {
		return nil, err
	}
	out := make(map[string]CVSS, len(scores))
	for cve, ms := range scores {
		if c, ok := PickCVSS(ms); ok {
			if c.Source == MetricADP {
				c.Source = MetricCNA
			}
			out[cve] = c
		}
	}
	return out, nil
}

// KevAffected returns the affected entries of the exploited lists' CVEs, for findings: NVD's when NVD gives any, else those of the
// CNA's CVE record for the product the list's entry names (kevRecordView; RangesFromCVEOrg names them). A CVE NVD has not answered for and the record gave nothing for is absent; one NVD
// answered for without a vulnerable entry is present with an empty list.
func (s *Store) KevAffected(ctx context.Context) (map[string][]AffectedRow, error) {
	db := s.db.Reader()
	rows, err := readRanges(ctx, db, `WHERE r.origin = 'nvd' AND r.cve IN (SELECT cve FROM feeds_kev WHERE source_id IN ('cisa-kev', 'vulncheck-kev'))`)
	if err != nil {
		return nil, err
	}
	out := map[string][]AffectedRow{}
	for _, r := range rows {
		out[r.CVE] = append(out[r.CVE], r.AffectedRow())
	}
	fromRecord, _, err := kevRecordView(ctx, db) // only CVEs without NVD ranges
	if err != nil {
		return nil, err
	}
	for cve, rs := range fromRecord {
		out[cve] = rs
	}
	answered, err := stringSet(ctx, db, `SELECT c.cve FROM feeds_cve c WHERE c.nvd_at IS NOT NULL AND c.nvd_status <> 'Rejected'
AND c.cve IN (SELECT cve FROM feeds_kev WHERE source_id IN ('cisa-kev', 'vulncheck-kev'))`)
	if err != nil {
		return nil, err
	}
	for cve := range answered {
		if _, ok := out[cve]; !ok {
			out[cve] = []AffectedRow{}
		}
	}
	return out, nil
}

// The sources RangesFromCVEOrg names, as findings reads them.
const (
	rangesCVEOrg        = "cve.org"
	rangesCVEOrgPartial = "cve.org-partial"
)

// RangesFromCVEOrg returns the exploited-list CVEs whose affected versions (KevAffected) come from the CNA's CVE record, not from NVD,
// with their source as findings names it: "cve.org" (a complete list: every row says affected or unaffected) or "cve.org-partial"
// (findings may raise a match on it, never close one). kevRecordView decides both.
func (s *Store) RangesFromCVEOrg(ctx context.Context) (map[string]string, error) {
	_, src, err := kevRecordView(ctx, s.db.Reader())
	return src, err
}

// matchStampFeeds are the feeds whose pulls may change what the match pass reads: the exploited lists, the catalogue's records, the
// distributions' data, EPSS, the scan templates, the public-exploit indexes and the vendors' exploitation claims (their signals
// change no match yet, but the urgency read of the findings keys on the same stamp).
const matchStampFeeds = `'alpine-osv', 'cisa-kev', 'cisco-psirt', 'cve-org', 'debian-tracker', 'epss-all', 'exploit-db', 'fortinet-psirt', 'metasploit',
'msrc', 'nuclei-templates', 'nvd-kev', 'nvd-recent', 'poc-in-github', 'ubuntu-osv', 'ubuntu-vex', 'vulncheck-kev'`

// MatchStamp changes whenever what KevVulns, KevAffected and DistroFixes return may have changed: the last pull time and
// rev (turned on or off) of the feeds that write them (each written in the pull's own transaction), and the count and newest change
// of the exploited-list entries and of their catalogue rows. findings (through cmd/vedette) keeps one read of the list per stamp,
// instead of reading the ranges once per device.
func (s *Store) MatchStamp(ctx context.Context) (string, error) {
	var stamp sql.NullString
	err := s.db.Reader().QueryRowContext(ctx, `SELECT (SELECT group_concat(id || '=' || COALESCE(last_fetch, '') || '/' || rev, ',') FROM
(SELECT id, last_fetch, rev FROM feeds_source WHERE id IN (`+matchStampFeeds+`) ORDER BY id))
|| ';' || (SELECT count(*) || '/' || COALESCE(max(updated_at), '') FROM feeds_kev WHERE source_id IN ('cisa-kev', 'vulncheck-kev'))
|| ';' || (SELECT count(*) || '/' || COALESCE(max(c.updated_at), '') FROM feeds_cve c WHERE c.cve IN (SELECT cve FROM feeds_kev))`).Scan(&stamp)
	if err != nil {
		return "", fmt.Errorf("feeds: match stamp: %w", err)
	}
	return stamp.String, nil
}

// kevNVDCount is how many CVEs of the exploited lists NVD answered for.
func (s *Store) kevNVDCount(ctx context.Context) (int, error) {
	var n int
	if err := s.db.Reader().QueryRowContext(ctx, kevNVDCountSQL).Scan(&n); err != nil {
		return 0, fmt.Errorf("feeds: count NVD answers: %w", err)
	}
	return n, nil
}

func kevNVDCountTx(ctx context.Context, tx *sql.Tx) (int, error) {
	var n int
	if err := tx.QueryRowContext(ctx, kevNVDCountSQL).Scan(&n); err != nil {
		return 0, fmt.Errorf("feeds: count NVD answers: %w", err)
	}
	return n, nil
}

const kevNVDCountSQL = `SELECT count(*) FROM feeds_cve WHERE nvd_at IS NOT NULL AND cve IN (SELECT cve FROM feeds_kev WHERE source_id IN ('cisa-kev', 'vulncheck-kev'))`

// KevPublished returns the day each CVE of the exploited lists was published (NVD's, else the CVE record's). A CVE that is absent has
// no known day: findings then treats it as recent and never closes a finding on it for its age.
func (s *Store) KevPublished(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT cve, published FROM feeds_cve WHERE published IS NOT NULL AND cve IN (SELECT cve FROM feeds_kev)`)
	if err != nil {
		return nil, fmt.Errorf("feeds: read published: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]time.Time{}
	for rows.Next() {
		var cve, ts string
		if err := rows.Scan(&cve, &ts); err != nil {
			return nil, fmt.Errorf("feeds: read published: %w", err)
		}
		if t, err := parseTS(ts); err == nil {
			out[cve] = t.UTC().Truncate(24 * time.Hour)
		}
	}
	return out, rows.Err()
}

// publishedChunk is the most CVEs of one PublishedOf query.
const publishedChunk = 500

// PublishedOf returns the day each of these CVEs was published ("2017-03-14"); a CVE with no known day is absent. One query per
// publishedChunk CVEs (the CVEs as one JSON array parameter, json_each), not one per CVE.
func (s *Store) PublishedOf(ctx context.Context, cves []string) (map[string]string, error) {
	out := make(map[string]string, len(cves))
	for chunk := range slices.Chunk(cves, publishedChunk) {
		part, err := json.Marshal(chunk)
		if err != nil {
			return nil, fmt.Errorf("feeds: read published: %w", err)
		}
		rows, err := s.db.Reader().QueryContext(ctx, `SELECT c.cve, c.published FROM json_each(?) j JOIN feeds_cve c ON c.cve = j.value WHERE c.published IS NOT NULL`, string(part))
		if err != nil {
			return nil, fmt.Errorf("feeds: read published: %w", err)
		}
		for rows.Next() {
			var c, ts string
			if err := rows.Scan(&c, &ts); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("feeds: read published: %w", err)
			}
			if len(ts) >= 10 {
				out[c] = ts[:10]
			}
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return nil, fmt.Errorf("feeds: read published: %w", err)
		}
	}
	return out, nil
}

// publishedOf is the day one CVE was published ("2017-03-14"), nil when the catalogue has none.
func (s *Store) publishedOf(ctx context.Context, cve string) (*string, error) {
	got, err := s.PublishedOf(ctx, []string{cve})
	if err != nil {
		return nil, err
	}
	if d, ok := got[cve]; ok {
		return &d, nil
	}
	return nil, nil
}
