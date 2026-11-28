package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// Vendor statements read by the AI, per release line. Where the box's own readers decide nothing, the AI reads the pages the box
// fetched and answers what the vendor states for the product's release line: affected, fixed (in a release), not affected, or unsure,
// with the sentence it relied on. The box keeps that answer only as far as it can check it: the quote must be in the page text the box
// fetched, word for word, and a version bound is kept only when the quote names it. The reading is stored once per (CVE, product,
// release line, CVE record, page text) and applied by every match to every device and version on that line:
//
//   - affected (the version inside the stated bounds, or the line named as affected): a finding, range origin ai_read, labelled as read
//     by AI from the page's host, which a person can reject in one click;
//   - not affected (past the stated fix on the same line, or the line named as not affected): settled only when the page is the vendor's
//     own; an exploited CVE waits for a person; a third-party page settles nothing;
//   - anything else decides nothing and the CVE stays possible, with its cause.
//
// A fix release becomes the finding's fix only when the quote names it.

// The statuses of a reading (fnd_line_statement.status).
const (
	StatementAffected    = "affected"
	StatementFixed       = "fixed"
	StatementNotAffected = "not_affected"
	StatementUnsure      = "unsure"
)

// The bases of a reading (fnd_line_statement.basis): stated, the text states it for this product and every version of the quote follows
// this product's own name (namedWithThisProduct); unpaired, the text states it but a version of the quote does not follow this product's
// name, so it opens a finding, gives no fix, and a "not affected" is an AI proposal a person confirms; inferred, the AI inferred it from
// another product's release line of the same record (ProposeVerdict.InferredFrom): it only opens, never a fix, never "not affected".
const (
	BasisStated   = "stated"
	BasisUnpaired = "unpaired"
	BasisInferred = "inferred"
)

// RangeAIRead is the range origin of a finding the AI's reading of the vendor's statement opened (fnd_finding.range_origin).
const RangeAIRead = "ai_read"

// statementRecheck is how old a reading may get before the box fetches its page again (no tokens: the AI is asked again only when the
// page text changed) and before an unsure reading is asked again.
const statementRecheck = 30 * 24 * time.Hour

// LineStatement is one row of fnd_line_statement: the AI's reading of the vendor's statement for one release line.
type LineStatement struct {
	Key, CVE, Product, Line   string
	StatedLine                string // the release line as the AI wrote it ("8.6"); used only when the quote names it
	RecordHash, PageHash      string
	Status                    string
	Basis                     string // BasisStated, BasisUnpaired or BasisInferred ("" reads as stated)
	Introduced, FixedIn, Last string // each "" unless the quote or the cited page names it
	Reason, Quote, URL, Host  string // Host "" when the quote is from the CVE record
	VendorPage, QuoteFound    bool
	Model, Profile, Activity  string
	AskedBy                   string
	AskedAt, SeenAt           time.Time
	RejectedBy                string
	RejectedAt                time.Time
	// Research is the research behind the reading (fnd_line_research, P-12); nil for a reading of the pages the box fetched.
	Research *LineResearch
}

func statementKey(cve, product, line, record, page string) string {
	return hashHex("ls1\x1f" + cve + "\x1f" + product + "\x1f" + line + "\x1f" + record + "\x1f" + page)
}

// identity is the key a reading is stored under: its line, the CVE record and the cited page (statementKey), and what it states (its
// status, bounds and basis, and whether the box found its quote). Two different answers read from the same record and page are two readings, so a newer answer never
// overwrites the older one that opened a finding (lineStore decides which older ones stay); the same answer again is the same reading,
// which keeps a person's rejection.
func (st LineStatement) identity() string {
	return hashHex("ls2\x1f" + statementKey(st.CVE, st.Product, st.Line, st.RecordHash, st.PageHash) + "\x1f" + st.Status + "\x1f" + st.Introduced + "\x1f" +
		st.FixedIn + "\x1f" + st.Last + "\x1f" + cmpNonEmpty(st.Basis, BasisStated) + "\x1f" + strconv.FormatBool(st.QuoteFound))
}

// recordHash is the identity of a CVE record's stamp (Vuln.Stamp) as a reading is keyed by it, and of what the reading reads of the
// record: rec2 is the whole record (the description, the solution and every product's rows), so each line read from the description and
// the line's own rows alone is read once more (the old reading applies until then, P-3).
func recordHash(stamp string) string { return hashHex("rec2\x1f" + stamp) }

// pageHash is the identity of a page's text as the box fetched it.
func pageHash(text string) string { return hashHex("page1\x1f" + text) }

const statementColumns = `statement_key, cve, product_key, line, stated_line, record_hash, page_hash, status, ifnull(introduced, ''), ifnull(fixed_in, ''),
	ifnull(last_affected, ''), reason, quote, url, host, vendor_page, quote_found, model, profile, ifnull(activity_id, ''), asked_by, asked_at, seen_at,
	ifnull(rejected_by, ''), ifnull(rejected_at, ''), basis, ` + researchColumn

func scanStatement(sc scanner) (LineStatement, error) {
	var st LineStatement
	var asked, seen, rejAt, research string
	if err := sc.Scan(&st.Key, &st.CVE, &st.Product, &st.Line, &st.StatedLine, &st.RecordHash, &st.PageHash, &st.Status, &st.Introduced, &st.FixedIn,
		&st.Last, &st.Reason, &st.Quote, &st.URL, &st.Host, &st.VendorPage, &st.QuoteFound, &st.Model, &st.Profile, &st.Activity, &st.AskedBy, &asked, &seen,
		&st.RejectedBy, &rejAt, &st.Basis, &research); err != nil {
		return LineStatement{}, err
	}
	st.Research = parseResearch(research)
	var err error
	if st.AskedAt, err = parseTS(asked); err != nil {
		return LineStatement{}, err
	}
	if st.SeenAt, err = parseTS(seen); err != nil {
		return LineStatement{}, err
	}
	if rejAt != "" {
		if st.RejectedAt, err = parseTS(rejAt); err != nil {
			return LineStatement{}, err
		}
	}
	return st, nil
}

// statementsOf reads every reading of the CVEs, newest first.
func statementsOf(ctx context.Context, q querier, cves []string) ([]LineStatement, error) {
	if len(cves) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(cves)
	if err != nil {
		return nil, err
	}
	rows, err := q.QueryContext(ctx, `SELECT `+statementColumns+` FROM fnd_line_statement WHERE cve IN (SELECT value FROM json_each(?))
		ORDER BY asked_at DESC, rowid DESC`, string(b))
	if err != nil {
		return nil, fmt.Errorf("findings: reading the AI's readings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []LineStatement
	for rows.Next() {
		st, err := scanStatement(rows)
		if err != nil {
			return nil, fmt.Errorf("findings: reading the AI's readings: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// storeStatement stores a reading: the older readings of the same CVE, product and line go (a reading a person rejected stays, so the
// same page is never applied again); the same reading asked again (an unsure one after statementRecheck) replaces the row unless a
// person rejected it.
func storeStatement(ctx context.Context, tx *sql.Tx, st LineStatement) error {
	if !checkKeyRE.MatchString(st.Key) {
		return fmt.Errorf("findings: bad reading key %q", st.Key)
	}
	if st.Basis != "" && st.Basis != BasisStated && st.Basis != BasisUnpaired && st.Basis != BasisInferred {
		return fmt.Errorf("findings: bad reading basis %q", st.Basis)
	}
	line, err := statementsWhere(ctx, tx, `cve = ? AND product_key = ? AND line = ?`, st.CVE, clipBytes(st.Product, 300), clipBytes(st.Line, 200))
	if err != nil {
		return err
	}
	for _, k := range lineStore(line, st) {
		if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_line_statement WHERE statement_key = ?`, k); err != nil {
			return fmt.Errorf("findings: replacing a reading: %w", err)
		}
	}
	at := store.FormatTS(st.AskedAt)
	_, err = tx.ExecContext(ctx, `INSERT INTO fnd_line_statement (statement_key, cve, product_key, line, stated_line, record_hash, page_hash, status, introduced,
		fixed_in, last_affected, reason, quote, url, host, vendor_page, quote_found, model, profile, activity_id, asked_by, asked_at, seen_at, basis, rejected_by, rejected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
		ON CONFLICT (statement_key) DO UPDATE SET status = excluded.status, introduced = excluded.introduced, fixed_in = excluded.fixed_in,
			last_affected = excluded.last_affected, stated_line = excluded.stated_line, reason = excluded.reason, quote = excluded.quote,
			url = excluded.url, host = excluded.host, vendor_page = excluded.vendor_page, quote_found = excluded.quote_found, model = excluded.model,
			profile = excluded.profile, activity_id = excluded.activity_id, asked_by = excluded.asked_by, asked_at = excluded.asked_at,
			seen_at = excluded.seen_at, basis = excluded.basis
		WHERE fnd_line_statement.rejected_by IS NULL`,
		st.Key, st.CVE, clipBytes(st.Product, 300), clipBytes(st.Line, 200), clipBytes(st.StatedLine, 200), st.RecordHash, st.PageHash, st.Status,
		nullString(clipBytes(st.Introduced, 100)), nullString(clipBytes(st.FixedIn, 100)), nullString(clipBytes(st.Last, 100)), clipBytes(st.Reason, 600),
		clipBytes(st.Quote, 400), clipBytes(st.URL, 2000), clipBytes(st.Host, 255), st.VendorPage, st.QuoteFound, clipBytes(cmpNonEmpty(st.Model, "unknown"), 80),
		clipBytes(cmpNonEmpty(st.Profile, "unknown"), 160), nullString(st.Activity), st.AskedBy, at, at, cmpNonEmpty(st.Basis, BasisStated))
	if err != nil {
		return fmt.Errorf("findings: storing a reading: %w", err)
	}
	return nil
}

// touchStatement records that a fetch found a reading's page unchanged.
func touchStatement(ctx context.Context, tx *sql.Tx, key string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE fnd_line_statement SET seen_at = ? WHERE statement_key = ?`, store.FormatTS(now), key); err != nil {
		return fmt.Errorf("findings: touching a reading: %w", err)
	}
	return nil
}

// lineReading is what the stored readings say for one question: the reading that applies (nil when none) and the newest one a person
// rejected (nil when none).
type lineReading struct {
	applied  *LineStatement
	rejected *LineStatement
	// held is an older reading of the line that called the version affected while the newer applied one does not: the AI never closes
	// its own finding, so the finding stands on it until a person confirms the newer answer (P-12).
	held *LineStatement
}

// newest is the newest of the two.
func (r lineReading) newest() *LineStatement {
	switch {
	case r.applied == nil:
		return r.rejected
	case r.rejected == nil || r.applied.AskedAt.After(r.rejected.AskedAt):
		return r.applied
	}
	return r.rejected
}

// readingFor picks the readings that speak for id from sts (newest first): the reading of id's own line; else, the newest reading of
// another key whose release line, as the quote names it, contains id's version ("8.6" for 8.6.5).
func readingFor(sts []LineStatement, cve string, id CheckID) lineReading {
	var r lineReading
	view := make([]*LineStatement, len(sts)) // each reading as the resolution sees it: rejected by a person, or covered by one's rejection
	says := lineSays(sts, cve, id)
	for i := range sts {
		view[i] = &sts[i]
		if sts[i].RejectedBy == "" {
			if by := coveredBy(sts, says, i); by != nil {
				c := sts[i]
				c.RejectedBy, c.RejectedAt = by.RejectedBy, by.RejectedAt
				view[i] = &c
			}
		}
	}
	for _, st := range view {
		if st.CVE != cve || st.Product != id.Product {
			continue
		}
		own := st.Line == id.Line
		if !own && !st.coversLine(id) {
			continue
		}
		switch {
		case st.RejectedBy != "":
			if own && r.rejected == nil {
				r.rejected = st
			}
		case r.applied == nil || own && r.applied.Line != id.Line:
			r.applied = st
		}
	}
	if a := r.applied; a != nil && r.rejected != nil && a.Line != id.Line && !a.AskedAt.After(r.rejected.AskedAt) {
		r.applied = nil // a person rejected the reading of this very line since: another line's older reading does not stand in for it
	}
	if a := r.applied; a != nil && a.Line == id.Line && a.verdictFor(id) != VerdictAffected {
		older := false // newest first: only a reading stored before the applied one
		for _, st := range view {
			if st == a {
				older = true
				continue
			}
			if older && st.CVE == cve && st.Product == id.Product && st.Line == id.Line && st.RejectedBy == "" && st.verdictFor(id) == VerdictAffected {
				r.held = st
				break
			}
		}
	}
	return r
}

// says is what a reading says for id's version whatever a person did about it: VerdictAffected, VerdictNotAffected or "" (verdictFor of a
// rejected reading is "").
func (st LineStatement) says(id CheckID) string {
	st.RejectedBy = ""
	return st.verdictFor(id)
}

// lineSays is what each reading of id's own line says for its version ("" for a reading of another CVE, product or line).
func lineSays(sts []LineStatement, cve string, id CheckID) []string {
	out := make([]string, len(sts))
	for i, st := range sts {
		if st.CVE == cve && st.Product == id.Product && st.Line == id.Line {
			out[i] = st.says(id)
		}
	}
	return out
}

// coveredBy is the person's rejection that covers reading sts[i] for a version (nil when none; says is what each reading says for it), so one rejection is enough (P-12):
// a rejected reading of the same line that says the same for the version, and either was stored after it (sts is newest first: an
// older reading must not hold a finding open after the person said no to a newer one) or was read from the same CVE record and cited page
// (its text, or for a page only the AI's tools read, its address: the same answer again is not asked twice). Decided per version: a
// "fixed" reading calls one version affected and another not, so a rejection never covers a reading that says the opposite for the
// version, and a newer reading from a changed record or page is a new statement.
func coveredBy(sts []LineStatement, says []string, i int) *LineStatement {
	n := &sts[i]
	v := says[i]
	if v == "" {
		return nil
	}
	byURL := n.Research != nil && (n.Research.QuoteCheck == QuoteTool || n.Research.QuoteCheck == QuoteLive)
	for j := range sts {
		r := &sts[j]
		if j == i || r.RejectedBy == "" || r.CVE != n.CVE || r.Product != n.Product || r.Line != n.Line || says[j] != v {
			continue
		}
		if j < i || r.RecordHash == n.RecordHash && r.URL == n.URL && (r.PageHash == n.PageHash || byURL) {
			return r
		}
	}
	return nil
}

// coversLine says the reading's release line, as its quote names it, contains id's version: "8.6" contains 8.6.5, never 8.60.
func (st LineStatement) coversLine(id CheckID) bool {
	l := st.StatedLine
	if l == "" || !namesToken(st.Quote, l) {
		return false
	}
	return l == id.Line || dottedPrefix(l, id.Version)
}

// dottedPrefix says version is line or starts with line followed by a separator.
func dottedPrefix(line, version string) bool {
	if line == "" || !strings.HasPrefix(version, line) {
		return false
	}
	if len(version) == len(line) {
		return true
	}
	c := version[len(line)]
	return c == '.' || c == '-' || c == '_' || c == ' ' || c == 'R' || c == 'r'
}

// namesToken says text names tok as a whole version ("7.4.10" does not name 7.4.1; a sentence's last period may follow it).
func namesToken(text, tok string) bool {
	if tok == "" {
		return false
	}
	t, k := strings.ToLower(text), strings.ToLower(tok)
	word := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' }
	for i := 0; i <= len(t)-len(k); {
		j := strings.Index(t[i:], k)
		if j < 0 {
			return false
		}
		j += i
		end := j + len(k)
		before := j == 0 || !word(t[j-1]) && t[j-1] != '.'
		after := end == len(t) || !word(t[end]) && t[end] != '.' || t[end] == '.' && (end+1 == len(t) || !word(t[end+1]))
		if before && after {
			return true
		}
		i = j + 1
	}
	return false
}

// reBefore is a bound written as "before X", "prior to X" or "earlier than X" (all versions before X).
var reBefore = regexp.MustCompile(`(?i)\b(?:before|prior to|earlier than)\s+(?:version\s+|v)?([0-9][0-9A-Za-z.\-_]*[0-9A-Za-z])`)

// verdictFor is what the reading says for id's version: VerdictAffected, VerdictNotAffected, or "" when it decides nothing for it.
// A reading whose quote was not found in the page decides nothing; a rejected one decides nothing.
func (st LineStatement) verdictFor(id CheckID) string {
	if !st.QuoteFound || st.RejectedBy != "" {
		return ""
	}
	if st.Basis == BasisInferred && st.Status != StatementAffected && st.Status != StatementNotAffected {
		return "" // an inference from another product's line opens, or proposes "not affected" to a person; it states no fix
	}
	scheme := productScheme(id.Product)
	names := namesToken(st.Quote, id.Version) || namesToken(st.Quote, id.Line) || st.coversLine(id)
	bounded := st.Introduced != "" || st.FixedIn != "" || st.Last != ""
	inside := func() bool {
		r := textRange{start: st.Introduced, end: st.FixedIn, quote: st.Quote}
		if r.end == "" {
			r.end, r.endIncl = st.Last, true
		}
		if r.end == "" {
			return false
		}
		v, _, ok := judgeTextRanges([]textRange{r}, id.Version, id.Build, scheme)
		return ok && v == VerdictAffected
	}
	switch st.Status {
	case StatementAffected:
		if !bounded {
			if x := st.quotedFix(id); x != "" {
				if before, ok := versionBefore(id, x); ok && !before {
					return "" // "before X" and the version is X or later: the sentence does not call it affected
				}
			}
			if names || st.Basis == BasisInferred && st.namedByRelease(id) {
				return VerdictAffected // the vendor names the line or the version as affected; an inference names a release of the line the version is before
			}
			return ""
		}
		if inside() {
			return VerdictAffected
		}
		return ""
	case StatementFixed:
		if inside() {
			return VerdictAffected
		}
		if st.pastFix(id) {
			return VerdictNotAffected
		}
		return ""
	case StatementNotAffected:
		if names {
			return VerdictNotAffected
		}
	}
	return ""
}

// pastFix says id's version is at or past the stated fix (or past the last affected release) on the same line: the vendor's own scheme
// says so for its train, or the quote states the line, or a bound "before X" names the fix.
func (st LineStatement) pastFix(id CheckID) bool {
	quoted := func(b string) string { // a bound read from the page beside the quote may open a finding, never settle one
		if namesToken(st.Quote, b) {
			return b
		}
		return ""
	}
	end, incl := quoted(st.FixedIn), false
	if end == "" {
		end, incl = quoted(st.Last), true
	}
	if end == "" {
		return false
	}
	if scheme := productScheme(id.Product); scheme != nil {
		r := textRange{start: quoted(st.Introduced), end: end, endIncl: incl, quote: st.Quote}
		v, _, ok := judgeTextRanges([]textRange{r}, id.Version, id.Build, scheme)
		return ok && v == VerdictNotAffected
	}
	if id.Build != "" {
		return false
	}
	c, ok := CompareVersions(id.Version, end)
	if !ok || c < 0 || incl && c == 0 {
		return false
	}
	if st.coversLine(id) && dottedPrefix(st.StatedLine, end) {
		return true
	}
	if !onFixTrain(end, id.Version) {
		return false // "7.14 before 7.14.5 and 7.15 before 7.15.3": a fix on another train says nothing about this version
	}
	for _, m := range reBefore.FindAllStringSubmatch(st.Quote, -1) {
		if strings.EqualFold(strings.TrimRight(m[1], "."), end) {
			return true // "all versions before X": the vendor's whole list ends at X
		}
	}
	return false
}

// onFixTrain says version is on the train of the release fix: it starts with all parts of fix but the last ("3.4.7", and the hotfix
// "3.4.0.2", on the train of "3.4.0"; "2.450" on that of "2.442"): a release before which every version is affected is on the version's
// own train. 3.4.1 is not on the train of 3.3.5, nor 121.0.1 on that of 120.0.1.
func onFixTrain(fix, version string) bool {
	i := strings.LastIndexAny(fix, ".-_")
	return i > 0 && dottedPrefix(strings.ToLower(fix[:i]), strings.ToLower(version))
}

// reVersionToken is a dotted version as a sentence writes it ("115.42", "7.2.1"; never a lone number).
var reVersionToken = regexp.MustCompile(`[0-9]+(?:\.[0-9]+)+`)

// reLowerBound is a release written as the start of a range: "from X" (X affected) or "after X" (X not), as the record's rows and
// sentences write it.
var reLowerBound = regexp.MustCompile(`(?i)\b(from|after)\s+(?:version\s+|v)?$`)

// namedByRelease says the quote names the reading's stated line through releases of it only ("Browser ESR 115.42" names line 115), and
// id's version is on that line and before every such release: the record states line N of another product fixed in release N.x, so
// N.y of this product's line before it carried the flaw. A release that starts a range ("from 115.1.0 before 115.42.0") is a lower
// bound: the version is at or past it ("after": past it). A version at or past a named release, before a range's start, or off the
// line, is not named. Only an inferred reading (BasisInferred) speaks for a version this way.
func (st LineStatement) namedByRelease(id CheckID) bool {
	l := st.StatedLine
	if l == "" || !dottedPrefix(l, id.Version) || namesToken(st.Quote, l) {
		return false
	}
	n := 0
	for _, at := range reVersionToken.FindAllStringIndex(st.Quote, -1) {
		tok := st.Quote[at[0]:at[1]]
		if tok == l || !dottedPrefix(l, tok) || !namesToken(st.Quote, tok) {
			continue
		}
		before, ok := versionBefore(id, tok)
		if !ok {
			return false
		}
		if m := reLowerBound.FindStringSubmatch(st.Quote[:at[0]]); m != nil {
			if strings.EqualFold(m[1], "after") {
				if atMost, ok := versionAtMost(id, tok); !ok || atMost {
					return false
				}
			} else if before {
				return false
			}
			continue
		}
		if !before {
			return false
		}
		n++
	}
	return n > 0
}

// fix is the fix a finding the reading opened says for id: the stated fixed release, kept only when the quote names it; else the
// release a "before X" of the quote names on id's own train, when id is before it; none for a reading inferred from another product's
// line (BasisInferred) or one whose quote does not pair its versions with this product's name (BasisUnpaired).
func (st LineStatement) fix(id CheckID) Fix {
	if st.Basis != BasisStated && st.Basis != "" {
		return Fix{Kind: FixUnknown} // a release the quote does not pair with this product's own name may be another product's
	}
	if st.FixedIn != "" && namesToken(st.Quote, st.FixedIn) {
		return Fix{Kind: FixUpdate, Version: st.FixedIn}
	}
	if x := st.quotedFix(id); x != "" {
		if before, ok := versionBefore(id, x); ok && before {
			return Fix{Kind: FixUpdate, Version: x}
		}
	}
	return Fix{Kind: FixUnknown}
}

// quotedFix is the release a "before X" of the quote names on id's own train (onFixTrain), "" when none: the fix the vendor's sentence
// states ("DSM 7.2.1 versions before 7.2.1-69057-6"), whether or not the AI wrote it as fixed_in.
func (st LineStatement) quotedFix(id CheckID) string {
	for _, m := range reBefore.FindAllStringSubmatch(st.Quote, -1) {
		if x := strings.TrimRight(m[1], "."); onFixTrain(x, id.Version) {
			return x
		}
	}
	return ""
}

// versionBefore says id's version is before release x, by the product's scheme or the generic order; ok false when they do not compare.
func versionBefore(id CheckID, x string) (before, ok bool) {
	if scheme := productScheme(id.Product); scheme != nil {
		v, _, ok := judgeTextRanges([]textRange{{end: x}}, id.Version, id.Build, scheme)
		return v == VerdictAffected, ok
	}
	if id.Build != "" {
		return false, false
	}
	c, ok := CompareVersions(id.Version, x)
	return c < 0, ok
}

// versionAtMost says id's version is at or before release x (ok false when the two cannot be ordered): "after x" excludes x however
// the text writes it ("115.1" is "115.1.0").
func versionAtMost(id CheckID, x string) (atMost, ok bool) {
	if scheme := productScheme(id.Product); scheme != nil {
		v, _, ok := judgeTextRanges([]textRange{{end: x, endIncl: true}}, id.Version, id.Build, scheme)
		return v == VerdictAffected, ok
	}
	if id.Build != "" {
		return false, false
	}
	c, ok := CompareVersions(id.Version, x)
	return c <= 0, ok
}

// asCheck is the reading as the lists show a check of a possible CVE: decided by the AI, the verdict it gives this version (unsure when
// it decides nothing here, or when a "not affected" comes from a page that is not the vendor's), the quote and its page.
func (st LineStatement) asCheck(id CheckID) Check {
	verdict := st.verdictFor(id)
	if verdict == "" {
		verdict = VerdictUnsure
	}
	c := Check{Key: st.Key, CVE: st.CVE, ID: id, DecidedBy: DecidedAI, Verdict: verdict, Reason: cleanOr(st.Reason, "The AI read the vendor's statement."),
		Quote: st.Quote, Model: st.Model, Profile: st.Profile, ActivityID: st.Activity, CheckedBy: st.AskedBy, CheckedAt: st.AskedAt,
		RejectedBy: st.RejectedBy, RejectedAt: st.RejectedAt, Sources: []CheckSource{}, Reading: &st}
	if st.URL != "" {
		c.Sources = []CheckSource{{URL: st.URL, Status: "ok", Cited: st.QuoteFound}}
	}
	if verdict != VerdictUnsure {
		c.Confidence = ConfidenceConfident
	}
	return c
}

// readingsFor is what the stored readings say for each question with a check identity, by the question's key.
func readingsFor(ctx context.Context, q querier, qs []Question) (map[string]lineReading, error) {
	var cves []string
	for _, x := range qs {
		if x.CheckKey != "" && x.Detail.Check != nil && !slices.Contains(cves, x.CVE) {
			cves = append(cves, x.CVE)
		}
	}
	sts, err := statementsOf(ctx, q, cves)
	if err != nil || len(sts) == 0 {
		return map[string]lineReading{}, err
	}
	out := map[string]lineReading{}
	for _, x := range qs {
		if x.CheckKey == "" || x.Detail.Check == nil {
			continue
		}
		if r := readingFor(sts, x.CVE, *x.Detail.Check); r.applied != nil || r.rejected != nil {
			out[x.CheckKey] = r
		}
	}
	return out, nil
}

// due says the line of id should be read again: no reading yet, the CVE record changed since the newest one, an unsure reading older
// than statementRecheck, or a page not fetched for statementRecheck (the fetch costs no tokens; the AI is asked only when it changed).
func (r lineReading) due(id CheckID, now time.Time) bool {
	last := r.newest()
	if last == nil {
		return true
	}
	if id.Record != "" && last.RecordHash != id.Record && last.Line == id.Line {
		return true
	}
	if last.Line == id.Line && last.toResearch() {
		return true
	}
	if last.RejectedBy == "" && last.Status == StatementUnsure && last.Research == nil && now.Sub(last.AskedAt) >= statementRecheck {
		return true
	}
	return now.Sub(last.SeenAt) >= statementRecheck
}

// aboutCVE says a page's text is about cve: it names the CVE, or it names an advisory the CVE's own record references (the id in the
// reference's address: FG-IR-24-015 for .../psirt/FG-IR-24-015, Synology-SA-26:01 for .../Synology_SA_26_01). A page that names neither
// (a product's release notes, a list of every advisory) may state ranges of another flaw, so the AI's reading of it decides nothing.
func aboutCVE(text, cve string, refs []RefLink) bool {
	if names, _ := cveMentions(text, cve); names {
		return true
	}
	ids := map[string]bool{}
	for _, r := range refs {
		for _, id := range advisoryIDsOf(r.URL) {
			ids[id] = true
		}
	}
	if len(ids) == 0 {
		return false
	}
	for _, tok := range reIDToken.FindAllString(text, -1) {
		if ids[normID(tok)] {
			return true
		}
	}
	return false
}

// reIDToken is a run of letters and digits joined by "-", "_" or ":", as an advisory id is written (FG-IR-24-015, Synology-SA-26:01).
var reIDToken = regexp.MustCompile(`[A-Za-z0-9]+(?:[-_:][A-Za-z0-9]+)*`)

// normID is an advisory id compared without case or separators: Synology_SA_26_01 and Synology-SA-26:01 are the same advisory.
func normID(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 'a' - 'A'
		}
		return -1
	}, s)
}

// advisoryIDsOf is the advisory ids a reference's address carries (normID): each part of its path or query value that is one id token,
// without a file extension, with at least two letters and two digits ("FG-IR-24-015", "cisco-sa-ssh-x9F2", "VMSA-2024-0001.html"); a
// version ("7.4.3"), a year or a word ("advisories") is no id.
func advisoryIDsOf(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	parts := strings.Split(u.Path, "/")
	for _, vs := range u.Query() {
		parts = append(parts, vs...)
	}
	var out []string
	for _, p := range parts {
		if i := strings.LastIndexByte(p, '.'); i > 0 && slices.Contains([]string{"html", "htm", "txt", "pdf", "asp", "aspx", "php", "jsp", "json", "xml"}, strings.ToLower(p[i+1:])) {
			p = p[:i]
		}
		if len(p) < 5 || len(p) > 80 || reIDToken.FindString(p) != p {
			continue
		}
		letters, digits := 0, 0
		for _, r := range p {
			switch {
			case r >= '0' && r <= '9':
				digits++
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
				letters++
			}
		}
		if letters >= 2 && digits >= 2 {
			out = append(out, normID(p))
		}
	}
	return out
}

// hostOf is the host of a page address, "" when none.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// aiReadNote is the evidence of a finding the AI's reading opened: where it was read and the sentence.
func aiReadNote(q Question, st LineStatement) string {
	where := "the CVE record"
	if st.Host != "" {
		where = st.Host
	}
	note := fmt.Sprintf("Read by AI from %s: the vendor's statement lists %s %s as affected by %s", where, clean(q.Detail.Software), clean(q.Detail.Version), q.CVE)
	if st.Basis == BasisInferred {
		note = fmt.Sprintf("Read by AI from %s: the statement names release line %s of %s, not %s %s itself; the AI infers that the same line of %s carried "+
			"the flaw (%s)", where, clean(st.StatedLine), q.CVE, clean(q.Detail.Software), clean(q.Detail.Version), clean(q.Detail.Software), oneLine(st.Reason, 200))
	}
	if st.Quote != "" {
		note += ": \"" + oneLine(st.Quote, 300) + "\""
	}
	if st.URL != "" {
		note += " (" + st.URL + ")"
	}
	return clipBytes(note+". A person can reject this reading.", 1000)
}

// statusSide is the side a reading's status takes: affected (affected, or fixed in a release: it may open a finding), not_affected, or ""
// for unsure.
func statusSide(status string) string {
	switch status {
	case StatementAffected, StatementFixed:
		return StatementAffected
	case StatementNotAffected:
		return StatementNotAffected
	}
	return ""
}

// statementsWhere is the readings matching the condition on fnd_line_statement.
func statementsWhere(ctx context.Context, q querier, where string, args ...any) ([]LineStatement, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+statementColumns+` FROM fnd_line_statement WHERE `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("findings: reading the line's readings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []LineStatement
	for rows.Next() {
		st, err := scanStatement(rows)
		if err != nil {
			return nil, fmt.Errorf("findings: reading the line's readings: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// ---- the life cycle of a line's AI readings (P-6, P-12), in pure functions: storing, a person's rejection and the outcome. Every rule
// that decides whether an AI reading opens, holds or hides a finding is here; TestReadingLifeCycle_Matrix drives them through every
// sequence of events up to length 4 and checks the invariants after each step; a person's rejection is resolved per version in
// readingFor (coveredBy). ----

// lineStore is what storing reading st does to the line's readings (every one, rejected ones included, newest first): the keys deleted
// before st is written. A newer reading keeps the older ones that called the line affected with a found quote (the finding they opened
// stays until a person confirms the newer answer: lineReading.held), also behind a newer "affected" whose bounds may leave a version
// out; only a newer one stating the same status and bounds with a quote the box found replaces them. Rejected readings stay: a person's
// rejection covers the readings that say the same (coveredBy).
func lineStore(line []LineStatement, st LineStatement) (drop []string) {
	for _, o := range line {
		keep := o.RejectedBy != "" || o.Key == st.Key || statusSide(o.Status) == StatementAffected && o.QuoteFound &&
			(!st.QuoteFound || o.Status != st.Status || o.FixedIn != st.FixedIn || o.Last != st.Last || o.Introduced != st.Introduced)
		if !keep {
			drop = append(drop, o.Key)
		}
	}
	return drop
}

// lineOutcome is what the line's readings decide for the version id: the reading a finding stands on (nil when none), and whether the
// newest reading no longer calls it affected, so the question waits for a person in Review AI answers beside that finding (review).
func lineOutcome(r lineReading, id CheckID) (by *LineStatement, review bool) {
	if r.applied != nil && r.applied.verdictFor(id) == VerdictAffected {
		return r.applied, false
	}
	if r.held != nil {
		return r.held, true
	}
	return nil, false
}

// toResearch says the reading is one the previous reader made from the record's first references (no research behind it) that decides
// nothing: unsure, or its quote was not found. The research engine researches such a line once, by itself (P-12); a previous reading
// that decides is kept, and a line with a research reading is researched again only when the record or a cited page changes (an unsure
// research is not asked again by age alone).
func (st LineStatement) toResearch() bool {
	return st.Research == nil && st.RejectedBy == "" && (st.Status == StatementUnsure || !st.QuoteFound)
}
