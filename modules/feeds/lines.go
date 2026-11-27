package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/core/productid"
)

// Line sources. A vendor that states per release line whether a CVE affects the line (Node.js's security working group: "22.x"
// vulnerable, "^22.23.4" patched) is read into feeds_line_cve (the source speaks about the CVE for the product) and feeds_line_status
// (one row per line it lists). How the vendor's data reads, and what a line it does not list means, is data
// (content/catalog/line-sources.json), never code. A source of line support only (endoflife.date) fills feeds_line_support: when a
// line was released and until when its vendor assesses it; it never decides a CVE. Findings reads all three through LineData.

const (
	nodeLineFeedID = "nodejs-security-wg" // Node.js security working group, vuln/core/index.json
	eolFeedID      = "endoflife-date"     // endoflife.date API v1, products/full: line support only

	// DecoderNodeLines and DecoderEOL are the decoders of the two sources.
	DecoderNodeLines Decoder = "nodejs-security-wg"
	DecoderEOL       Decoder = "endoflife-date"

	nodeLineNotice = "MIT, Node.js security working group (nodejs/security-wg). Facts only: CVE ids and the affected and patched release lines."
	eolNotice      = "MIT, endoflife.date. Facts only: release lines and their support dates; never a CVE verdict."

	// lineStaleAfter is how far past its interval a line source may be before its conventions say nothing (LineCover.Stale): an
	// explicit row stays valid, "not listed means not affected" needs a fresh statement.
	lineStaleAfter = 24 * time.Hour
)

// Conventions of line-sources.json: what a listed row states (Listed) and what a line the source does not list means (Absent).
const (
	ListedSemverRange           = "semver_range"
	AbsentUnaffectedIfSupported = "unaffected_if_supported"
	AbsentUnknown               = "unknown"
)

// LineSourceDef is one row of line-sources.json's sources.
type LineSourceDef struct {
	Source   string   `json:"source"`
	Products []string `json:"products"`
	Listed   string   `json:"listed"`
	Absent   string   `json:"absent"`
	Ref      string   `json:"ref"`
}

type lineSourcesFile struct {
	About   string          `json:"_about"`
	Sources []LineSourceDef `json:"sources"`
	Support []struct {
		Source   string            `json:"source"`
		Products map[string]string `json:"products"` // catalogue id -> the product's name at the source
	} `json:"support"`
}

// lineCatalogue is line-sources.json read and checked: the line sources by feed id with their products' keys, and the support
// sources' names of each product.
type lineCatalogue struct {
	sources map[string]LineSourceDef
	keys    map[string][]string          // source -> the catalogue keys of its products
	support map[string]map[string]string // source -> name at the source -> catalogue key
}

var lineCat = sync.OnceValues(func() (lineCatalogue, error) { return parseLineSources(catalogdata.LineSources) })

// parseLineSources reads line-sources.json: every source is a built-in feed with a known convention and catalogue products.
func parseLineSources(b []byte) (lineCatalogue, error) {
	var f lineSourcesFile
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return lineCatalogue{}, fmt.Errorf("feeds: line-sources.json: %w", err)
	}
	c := lineCatalogue{sources: map[string]LineSourceDef{}, keys: map[string][]string{}, support: map[string]map[string]string{}}
	key := func(id string) (string, error) {
		p, ok := productid.ByID(id)
		if !ok {
			return "", fmt.Errorf("feeds: line-sources.json: %q is not a catalogue product", id)
		}
		return p.Key, nil
	}
	for _, s := range f.Sources {
		if _, ok := BuiltinByID(s.Source); !ok || len(s.Products) == 0 || s.Listed != ListedSemverRange ||
			s.Absent != AbsentUnaffectedIfSupported && s.Absent != AbsentUnknown {
			return lineCatalogue{}, fmt.Errorf("feeds: line-sources.json: source %q: unknown feed, no product or unknown convention", s.Source)
		}
		for _, id := range s.Products {
			k, err := key(id)
			if err != nil {
				return lineCatalogue{}, err
			}
			c.keys[s.Source] = append(c.keys[s.Source], k)
		}
		c.sources[s.Source] = s
	}
	for _, s := range f.Support {
		if _, ok := BuiltinByID(s.Source); !ok {
			return lineCatalogue{}, fmt.Errorf("feeds: line-sources.json: support source %q is not a built-in feed", s.Source)
		}
		c.support[s.Source] = map[string]string{}
		for id, name := range s.Products {
			k, err := key(id)
			if err != nil {
				return lineCatalogue{}, err
			}
			c.support[s.Source][name] = k
		}
	}
	return c, nil
}

// lineStatement is one CVE a line source speaks about for one product, with its rows.
type lineStatement struct {
	CVE, Product, Ref string
	Rows              []lineRow
}

// lineRow is one release line of a statement (feeds_line_status).
type lineRow struct {
	Line, Status                    string
	Introduced, LastAffected, Fixed string
	Explicit                        bool
	Platforms                       []string
}

// lineSupport is one release line of a product (feeds_line_support).
type lineSupport struct {
	Product, Line                      string
	Released, AssessedUntil, EOL, Last string // YYYY-MM-DD; "" for none
}

var (
	nodeCVERE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
	// a comparator of a Node.js semver range: an operator and a version of three numbers, or a whole line ("22.x")
	semverCmpRE  = regexp.MustCompile(`^(\^|>=|<=|<)?v?([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,6})$`)
	semverLineRE = regexp.MustCompile(`^v?([0-9]{1,4})\.(?:x|\*)$`)
	dayRE        = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

// nodeClause is one "||" part of a Node.js range, read for the release line it is on.
type nodeClause struct{ line, lo, hiIncl, hiExcl string }

// parseNodeClause reads one part of a vulnerable or patched range: "22.x", "^22.23.4", ">=4.0.0 <4.8.4", "8.5.0", "<=6.9.1". Every
// comparator must be on one release line (the major number); anything else is unreadable (ok false), so the entry is not used.
func parseNodeClause(s string) (nodeClause, bool) {
	var c nodeClause
	fields := strings.Fields(strings.NewReplacer(">= ", ">=", "<= ", "<=", "< ", "<", "^ ", "^").Replace(strings.TrimSpace(s)))
	if len(fields) == 0 || len(fields) > 2 {
		return c, false
	}
	if m := semverLineRE.FindStringSubmatch(fields[0]); m != nil && len(fields) == 1 {
		return nodeClause{line: trimZeros(m[1])}, true
	}
	for _, f := range fields {
		m := semverCmpRE.FindStringSubmatch(f)
		if m == nil {
			return c, false
		}
		line, v := trimZeros(m[2]), trimZeros(m[2])+"."+trimZeros(m[3])+"."+trimZeros(m[4])
		if c.line != "" && c.line != line {
			return c, false
		}
		c.line = line
		switch m[1] {
		case "", "^", ">=":
			if c.lo != "" {
				return c, false
			}
			c.lo = v
			if m[1] == "" { // one exact release
				c.hiIncl = v
			}
		case "<=":
			c.hiIncl = v
		case "<":
			c.hiExcl = v
		}
	}
	return c, true
}

func trimZeros(s string) string {
	if t := strings.TrimLeft(s, "0"); t != "" {
		return t
	}
	return "0"
}

// nodeEntry is one entry of Node.js's vuln/core/index.json.
type nodeEntry struct {
	CVE          []string `json:"cve"`
	Vulnerable   string   `json:"vulnerable"`
	Patched      string   `json:"patched"`
	Ref          string   `json:"ref"`
	Environments []string `json:"affectedEnvironments"`
}

// ParseNodeLines reads the Node.js security working group's index (vuln/core/index.json) into one statement per CVE for product:
// one affected row per release line its vulnerable range names, from the start the range gives (none: the whole line), up to the
// release its patched range gives for that line (none: no fix yet). An entry limited to some platforms keeps its lines listed with
// the platforms, so they are never read as "not listed". It fails closed: an entry whose ranges do not read, name one line twice,
// or disagree is dropped and counted by reason, never stored in part.
func ParseNodeLines(body []byte, product string) ([]lineStatement, Stats, error) {
	var idx map[string]json.RawMessage
	if err := json.Unmarshal(body, &idx); err != nil {
		return nil, Stats{}, fail(ErrBadSample, "The Node.js vulnerability index is not the JSON object Vedette reads.")
	}
	t := newTally()
	byCVE := map[string]lineStatement{}
	keys := slices.Sorted(maps.Keys(idx))
	for i, k := range keys {
		var e nodeEntry
		if err := json.Unmarshal(idx[k], &e); err != nil {
			t.reject(i+1, "entry %s: not an object Vedette reads", k)
			continue
		}
		st, reason := nodeStatement(e)
		if reason != "" {
			t.reject(i+1, "entry %s: "+reason, k)
			continue
		}
		for _, cve := range e.CVE {
			if !nodeCVERE.MatchString(cve) {
				continue
			}
			if _, dup := byCVE[cve]; dup { // the index repeats an entry now and then: the first one stands
				continue
			}
			s := st
			s.CVE, s.Product = cve, product
			byCVE[cve] = s
		}
		t.Accepted++
	}
	out := make([]lineStatement, 0, len(byCVE))
	for _, c := range slices.Sorted(maps.Keys(byCVE)) {
		out = append(out, byCVE[c])
	}
	return out, t.stats(), nil
}

// nodeStatement is the rows of one entry, or the reason it is not read.
func nodeStatement(e nodeEntry) (lineStatement, string) {
	if len(e.CVE) == 0 {
		return lineStatement{}, "no CVE id"
	}
	fixes := map[string]string{}
	for p := range strings.SplitSeq(e.Patched, "||") {
		if strings.TrimSpace(p) == "" {
			continue
		}
		c, ok := parseNodeClause(p)
		if !ok || c.lo == "" || c.hiIncl != "" || fixes[c.line] != "" {
			return lineStatement{}, "a patched range Vedette does not read"
		}
		fixes[c.line] = c.lo
	}
	var platforms []string
	if !slices.Contains(e.Environments, "all") {
		if len(e.Environments) == 0 {
			return lineStatement{}, "no platform"
		}
		platforms = slices.Sorted(slices.Values(e.Environments))
	}
	var st lineStatement
	seen := map[string]bool{}
	for v := range strings.SplitSeq(e.Vulnerable, "||") {
		c, ok := parseNodeClause(v)
		if !ok || seen[c.line] {
			return lineStatement{}, "a vulnerable range Vedette does not read"
		}
		seen[c.line] = true
		fix := fixes[c.line]
		if c.hiExcl != "" && fix != "" && c.hiExcl != fix {
			return lineStatement{}, "the vulnerable and patched ranges disagree"
		}
		row := lineRow{Line: c.line, Status: "affected", Introduced: c.lo, LastAffected: c.hiIncl, Fixed: cmpOrStr(c.hiExcl, fix), Explicit: true, Platforms: platforms}
		st.Rows = append(st.Rows, row)
	}
	if ref := strings.TrimSpace(e.Ref); strings.HasPrefix(ref, "https://") && len(ref) <= 500 {
		st.Ref = ref
	}
	return st, ""
}

func cmpOrStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// eolFile is endoflife.date's API v1 products/full answer, the fields read.
type eolFile struct {
	Result []struct {
		Name     string `json:"name"`
		Releases []struct {
			Name        string  `json:"name"`
			ReleaseDate string  `json:"releaseDate"`
			IsEol       bool    `json:"isEol"`
			EolFrom     *string `json:"eolFrom"`
			Latest      *struct {
				Date string `json:"date"`
			} `json:"latest"`
		} `json:"releases"`
	} `json:"result"`
}

// ParseEOL reads endoflife.date's products/full for the catalogue products names maps (the name at endoflife.date -> catalogue key):
// per release line its release day and end of security support (assessed_until and eol: the day the vendor stops assessing the line),
// and the day of its latest release. A line that is past its end with no day given, or has no release day, is not stored: its
// support is unknown.
func ParseEOL(body []byte, names map[string]string) ([]lineSupport, Stats, error) {
	var f eolFile
	if err := json.Unmarshal(body, &f); err != nil || len(f.Result) == 0 {
		return nil, Stats{}, fail(ErrBadSample, "The endoflife.date answer is not the product list Vedette reads.")
	}
	t := newTally()
	var out []lineSupport
	for _, p := range f.Result {
		key, ok := names[p.Name]
		if !ok {
			continue
		}
		for _, r := range p.Releases {
			ls := lineSupport{Product: key, Line: strings.TrimSpace(r.Name), Released: r.ReleaseDate}
			if r.EolFrom != nil {
				ls.AssessedUntil, ls.EOL = *r.EolFrom, *r.EolFrom
			}
			if r.Latest != nil && dayRE.MatchString(r.Latest.Date) {
				ls.Last = r.Latest.Date
			}
			switch {
			case ls.Line == "" || len(ls.Line) > 40 || !dayRE.MatchString(ls.Released):
				t.reject(0, "%s: a release line with no name or release day", p.Name)
			case ls.EOL != "" && !dayRE.MatchString(ls.EOL), r.IsEol && ls.EOL == "":
				t.reject(0, "%s: a release line past its end with no day", p.Name)
			default:
				t.Accepted++
				out = append(out, ls)
			}
		}
	}
	return out, t.stats(), nil
}

// buildLines pulls a line source (Node.js's index) or the support source (endoflife.date). The whole file every time (145 kB and
// 3 MB, once a day): the stored rows keep only the catalogue's CVEs (INV-34), so a CVE that entered it since is read at the next pull.
func (s *Service) buildLines(ctx context.Context, src sourceRow, p pullPlan, dec Decoder) (pullPlan, error) {
	cat, err := lineCat()
	if err != nil {
		return p, err
	}
	resp, err := s.get(ctx, Request{URL: src.URL})
	if err != nil {
		return p, err
	}
	p.out = outcome{OK: true, Bytes: len(resp.Body), ETag: resp.ETag, LastModif: resp.LastModified}
	var st Stats
	if dec == DecoderEOL {
		p.support, st, err = ParseEOL(resp.Body, cat.support[src.ID])
		if err == nil && len(p.support) == 0 {
			err = fail(ErrBadSample, "endoflife.date lists none of the products Vedette reads its support for; the stored support was kept.")
		}
		if err != nil {
			return p, err
		}
		p.hasSupport = true
		p.out.fill(st, len(p.support))
		return p, nil
	}
	for _, key := range cat.keys[src.ID] {
		var sts []lineStatement
		if sts, st, err = ParseNodeLines(resp.Body, key); err != nil {
			return p, err
		}
		p.lines = append(p.lines, sts...)
	}
	if err := accepted(st); err != nil {
		return p, err
	}
	p.hasLines = true
	p.out.fill(st, st.Accepted)
	return p, nil
}

// applyLines replaces what a line source states with stmts, keeping only the catalogue's CVEs (INV-34). A statement that did not
// change keeps the day it was first stated, so an unchanged index changes nothing for findings. changed: the CVEs whose rows changed.
func applyLines(ctx context.Context, tx *sql.Tx, now time.Time, sourceID string, stmts []lineStatement) (changed []string, err error) {
	old, days, err := lineSigs(ctx, tx, sourceID)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_line_cve WHERE source_id = ?`, sourceID); err != nil { // its rows go with it
		return nil, fmt.Errorf("feeds: clear line rows: %w", err)
	}
	for _, st := range stmts {
		day := now.UTC().Format(time.DateOnly)
		if d, ok := days[st.Product+"|"+st.CVE]; ok {
			day = d
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO feeds_line_cve (source_id, product, cve, stated_at, ref)
SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM feeds_cve WHERE cve = ?)`, sourceID, st.Product, st.CVE, day, st.Ref, st.CVE)
		if err != nil {
			return nil, fmt.Errorf("feeds: write line rows: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 { // not a catalogue CVE
			continue
		}
		for _, r := range st.Rows {
			var plat any
			if len(r.Platforms) > 0 {
				b, _ := json.Marshal(r.Platforms)
				plat = string(b)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_line_status (source_id, product, cve, line, status, introduced, last_affected, fixed,
explicit, platforms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, sourceID, st.Product, st.CVE, r.Line, r.Status, r.Introduced, r.LastAffected, r.Fixed,
				boolInt(r.Explicit), plat); err != nil {
				return nil, fmt.Errorf("feeds: write line rows: %w", err)
			}
		}
	}
	now2, _, err := lineSigs(ctx, tx, sourceID)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for id := range now2 {
		if old[id] != now2[id] {
			set[id[strings.Index(id, "|CVE-")+1:]] = true
		}
	}
	for id := range old {
		if _, ok := now2[id]; !ok {
			set[id[strings.Index(id, "|CVE-")+1:]] = true
		}
	}
	return slices.Sorted(maps.Keys(set)), nil
}

// lineSigs is, per product|cve a line source states, its ref and rows as one text, and the day it was stated.
func lineSigs(ctx context.Context, tx *sql.Tx, sourceID string) (sigs, days map[string]string, err error) {
	rows, err := tx.QueryContext(ctx, `SELECT c.product || '|' || c.cve, c.stated_at, c.ref || ifnull((SELECT json_group_array(json_array(line, status,
introduced, last_affected, fixed, explicit, ifnull(platforms, ''))) FROM (SELECT * FROM feeds_line_status s WHERE s.source_id = c.source_id
AND s.product = c.product AND s.cve = c.cve ORDER BY line)), '') FROM feeds_line_cve c WHERE c.source_id = ?`, sourceID)
	if err != nil {
		return nil, nil, fmt.Errorf("feeds: read line rows: %w", err)
	}
	defer func() { _ = rows.Close() }()
	sigs, days = map[string]string{}, map[string]string{}
	for rows.Next() {
		var id, day, sig string
		if err := rows.Scan(&id, &day, &sig); err != nil {
			return nil, nil, fmt.Errorf("feeds: read line rows: %w", err)
		}
		sigs[id], days[id] = sig, day
	}
	return sigs, days, rows.Err()
}

// applySupport replaces the line support a source states; changed says whether any row changed.
func applySupport(ctx context.Context, tx *sql.Tx, sourceID string, rows []lineSupport) (changed bool, err error) {
	sig := func() (string, error) {
		var s sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT group_concat(product || '|' || line || '|' || released || '|' || ifnull(assessed_until, '') || '|' ||
ifnull(eol, '') || '|' || ifnull(last_release, ''), ';') FROM (SELECT * FROM feeds_line_support WHERE source_id = ? ORDER BY product, line)`, sourceID).Scan(&s)
		return s.String, err
	}
	before, err := sig()
	if err != nil {
		return false, fmt.Errorf("feeds: read line support: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_line_support WHERE source_id = ?`, sourceID); err != nil {
		return false, fmt.Errorf("feeds: clear line support: %w", err)
	}
	for _, r := range rows {
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO feeds_line_support (product, line, source_id, released, assessed_until, eol, last_release)
VALUES (?, ?, ?, ?, ?, ?, ?)`, r.Product, r.Line, sourceID, r.Released, nullStr(r.AssessedUntil), nullStr(r.EOL), nullStr(r.Last)); err != nil {
			return false, fmt.Errorf("feeds: write line support: %w", err)
		}
	}
	after, err := sig()
	if err != nil {
		return false, fmt.Errorf("feeds: read line support: %w", err)
	}
	return before != after, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// LineRow is one release line a line source states for a CVE (feeds_line_status), for findings.
type LineRow struct {
	Source, Product, CVE, Line, Status string
	Introduced, LastAffected, Fixed    string
	Explicit                           bool
	Platforms                          []string
}

// LineCover says a line source speaks about a CVE for a product (feeds_line_cve): a line it does not list is read by its convention
// (Absent), only while the source is fresh (Stale false) and its statement is not older than the CVE (StatedAt).
type LineCover struct {
	Source, Product, CVE, Ref string
	StatedAt                  time.Time
	Absent                    string
	Stale                     bool
}

// LineSupport is one release line of a product with when its vendor assessed it (feeds_line_support); zero times for none.
type LineSupport struct {
	Source, Product, Line              string
	Released, AssessedUntil, EOL, Last time.Time
}

// LineData is what the line sources that are on say about cves: their rows, their covers, and the support of every line of the
// products they cover. A source switched off says nothing.
func (s *Store) LineData(ctx context.Context, cves []string, now time.Time) ([]LineRow, []LineCover, []LineSupport, error) {
	if len(cves) == 0 {
		return nil, nil, nil, nil
	}
	cat, err := lineCat()
	if err != nil {
		return nil, nil, nil, err
	}
	srcs, err := s.sources(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	on, stale := map[string]bool{}, map[string]bool{}
	for _, r := range srcs {
		if !r.Builtin || !r.Enabled {
			continue
		}
		on[r.ID] = true
		stale[r.ID] = r.LastSuccess == nil || r.LastSuccess.After(now) || now.Sub(*r.LastSuccess) > interval(r.IntervalHours)+lineStaleAfter
	}
	list, _ := json.Marshal(cves)
	rdr := s.db.Reader()
	var covers []LineCover
	q, err := rdr.QueryContext(ctx, `SELECT source_id, product, cve, stated_at, ref FROM feeds_line_cve WHERE cve IN (SELECT value FROM json_each(?))
ORDER BY cve, source_id, product`, string(list))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("feeds: read line covers: %w", err)
	}
	products := map[string]bool{}
	for q.Next() {
		var c LineCover
		var day string
		if err := q.Scan(&c.Source, &c.Product, &c.CVE, &day, &c.Ref); err != nil {
			_ = q.Close()
			return nil, nil, nil, fmt.Errorf("feeds: read line covers: %w", err)
		}
		if !on[c.Source] {
			continue
		}
		c.StatedAt, _ = time.Parse(time.DateOnly, day)
		c.Absent, c.Stale = cat.sources[c.Source].Absent, stale[c.Source]
		if c.Absent == "" {
			c.Absent = AbsentUnknown
		}
		covers = append(covers, c)
		products[c.Product] = true
	}
	_ = q.Close()
	if err := q.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("feeds: read line covers: %w", err)
	}
	var rowsOut []LineRow
	q, err = rdr.QueryContext(ctx, `SELECT source_id, product, cve, line, status, introduced, last_affected, fixed, explicit, ifnull(platforms, '')
FROM feeds_line_status WHERE cve IN (SELECT value FROM json_each(?)) ORDER BY cve, source_id, product, line`, string(list))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("feeds: read line rows: %w", err)
	}
	for q.Next() {
		var r LineRow
		var plat string
		if err := q.Scan(&r.Source, &r.Product, &r.CVE, &r.Line, &r.Status, &r.Introduced, &r.LastAffected, &r.Fixed, &r.Explicit, &plat); err != nil {
			_ = q.Close()
			return nil, nil, nil, fmt.Errorf("feeds: read line rows: %w", err)
		}
		if plat != "" {
			_ = json.Unmarshal([]byte(plat), &r.Platforms)
		}
		if on[r.Source] {
			rowsOut = append(rowsOut, r)
		}
	}
	_ = q.Close()
	if err := q.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("feeds: read line rows: %w", err)
	}
	var support []LineSupport
	if len(products) > 0 {
		ps, _ := json.Marshal(slices.Sorted(maps.Keys(products)))
		q, err = rdr.QueryContext(ctx, `SELECT source_id, product, line, released, ifnull(assessed_until, ''), ifnull(eol, ''), ifnull(last_release, '')
FROM feeds_line_support WHERE product IN (SELECT value FROM json_each(?)) ORDER BY product, line, source_id`, string(ps))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("feeds: read line support: %w", err)
		}
		for q.Next() {
			var l LineSupport
			var rel, until, eol, last string
			if err := q.Scan(&l.Source, &l.Product, &l.Line, &rel, &until, &eol, &last); err != nil {
				_ = q.Close()
				return nil, nil, nil, fmt.Errorf("feeds: read line support: %w", err)
			}
			if !on[l.Source] {
				continue
			}
			l.Released, _ = time.Parse(time.DateOnly, rel)
			l.AssessedUntil, _ = time.Parse(time.DateOnly, until)
			l.EOL, _ = time.Parse(time.DateOnly, eol)
			l.Last, _ = time.Parse(time.DateOnly, last)
			support = append(support, l)
		}
		_ = q.Close()
		if err := q.Err(); err != nil {
			return nil, nil, nil, fmt.Errorf("feeds: read line support: %w", err)
		}
	}
	return rowsOut, covers, support, nil
}

// LineProducts is the catalogue keys of every product a line source speaks for (line-sources.json), sorted.
func LineProducts() []string {
	cat, err := lineCat()
	if err != nil {
		return nil
	}
	var out []string
	for _, ks := range cat.keys {
		out = append(out, ks...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// LineCVEs is the CVEs a line source that is on states rows for, of the given catalogue product keys: the match set compares them
// even before NVD or the CVE record name the product with a range.
func (s *Store) LineCVEs(ctx context.Context, products []string) ([]string, error) {
	if len(products) == 0 {
		return nil, nil
	}
	ps, _ := json.Marshal(products)
	q, err := s.db.Reader().QueryContext(ctx, `SELECT DISTINCT c.cve FROM feeds_line_cve c JOIN feeds_source s ON s.id = c.source_id AND s.enabled = 1
WHERE c.product IN (SELECT value FROM json_each(?)) ORDER BY c.cve`, string(ps))
	if err != nil {
		return nil, fmt.Errorf("feeds: line CVEs: %w", err)
	}
	defer func() { _ = q.Close() }()
	var out []string
	for q.Next() {
		var c string
		if err := q.Scan(&c); err != nil {
			return nil, fmt.Errorf("feeds: line CVEs: %w", err)
		}
		out = append(out, c)
	}
	return out, q.Err()
}

// lineHeld is the held note of a line source: how many catalogue CVEs it speaks about, for which products.
func lineHeld(ctx context.Context, tx *sql.Tx, id string) (string, error) {
	var n, lines int
	if err := tx.QueryRowContext(ctx, `SELECT count(*), (SELECT count(*) FROM feeds_line_status WHERE source_id = ?) FROM feeds_line_cve WHERE source_id = ?`, id, id).Scan(&n, &lines); err != nil {
		return "", err
	}
	return fmt.Sprintf("Per release line, %s catalogue CVEs (%s line statements).", grouped(n), grouped(lines)), nil
}

// supportHeld is the held note of a support source: how many release lines it gives the support of.
func supportHeld(ctx context.Context, tx *sql.Tx, id string) (string, error) {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM feeds_line_support WHERE source_id = ?`, id).Scan(&n); err != nil {
		return "", err
	}
	return fmt.Sprintf("Support dates of %s release lines; used only to tell which lines a vendor still assesses, never as a CVE verdict.", grouped(n)), nil
}

// pruneLines drops the line statements of CVEs the catalogue no longer keeps (INV-34).
func pruneLines(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_line_cve WHERE cve NOT IN (SELECT cve FROM feeds_cve)`); err != nil {
		return fmt.Errorf("feeds: prune line rows: %w", err)
	}
	return nil
}
