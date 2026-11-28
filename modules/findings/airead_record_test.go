package findings

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

// The AI reads like a careful person, evidence-bound: the whole CVE record (every product's rows, not only the line's own), the record
// alone when no page can be read, an inference the record itself supports (another product's release line), and a bound stated on the
// cited page beside the quote. A synthetic product the catalogue does not know: Quillfeather Mail, whose record names the vendor's
// browser lines.

const (
	cveQuill = "CVE-2026-991001"
	// quillFixed names line 115 of the browser only: the mail client's 115 line is in no row and no sentence of the record.
	quillFixed  = "This vulnerability was fixed in Quillfeather Browser 157, Quillfeather Browser ESR 115.42, Quillfeather Mail 157 and Quillfeather Mail 140.17."
	quillRowESR = "quillfeather browser (edition esr): affected from 115.1.0 before 115.42.0 [nvd]"
)

// quillWorld is one workstation running Quillfeather Mail at version, whose CVE's NVD row names the product with no version (so the
// match asks), the CVE on no exploited list, and a record with no reference page the box may read.
func quillWorld(t *testing.T, version string) (*env, *fakeChecker) {
	t.Helper()
	return quillWorldOf(t, "Mail", version)
}

// quillWorldOf is quillWorld with the vendor's product of that name ("Mail" or "Browser") on the workstation.
func quillWorldOf(t *testing.T, product, version string) (*env, *fakeChecker) {
	t.Helper()
	e := newEnv(t)
	sw := Software{ID: "s-quill", Display: "Quillfeather " + product, Vendor: "Quillfeather", Product: product, Version: version, Source: "agent"}
	a := Asset{ID: "pc-01", Name: "pc-01", OS: "Microsoft Windows 11 Pro", Software: []Software{sw}}
	e.inv.assets = map[string]AssetView{"pc-01": {ID: "pc-01", Hostname: ptr("pc-01"), IP: "192.0.2.10", Kind: "workstation", Approved: true}}
	e.inv.match = map[string]Asset{"pc-01": a}
	e.feeds.vulns = []Vuln{{CVE: cveQuill, NVDAnswered: true, Origin: RangeNVD, Affected: []Affected{{CPE: "cpe:2.3:a:quillfeather:" + strings.ToLower(product) + ":-:*:*:*:*:*:*:*"}}}}
	e.feeds.unlisted = map[string]bool{cveQuill: true}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	fc := &fakeChecker{budget: ReadBudget{Auto: true}, pages: map[string][]FetchedPage{},
		verdicts: map[string]ProposeVerdict{cveQuill + "|" + version: {Status: StatementUnsure, Reason: "The record names no row of this line."}},
		records: map[string]CVERecordText{cveQuill: {Description: "Use-after-free in the layout engine. " + quillFixed, Rows: []RecordRow{
			{Vendor: "quillfeather", Product: "browser", Text: quillRowESR},
			{Vendor: "quillfeather", Product: "mail", Text: "quillfeather mail: affected before 157.0 [nvd]"},
		}}}}
	e.svc.SetChecker(fc)
	return e, fc
}

func quillItem(t *testing.T, e *env) PossibleItem {
	t.Helper()
	items, err := e.svc.possibleItems(t.Context(), "pc-01")
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.CVE == cveQuill {
			return it
		}
	}
	return PossibleItem{}
}

func quillFindings(t *testing.T, e *env) int {
	t.Helper()
	return e.count(`SELECT count(*) FROM fnd_finding WHERE cve = '` + cveQuill + `' AND range_origin = 'ai_read' AND state = 'open' AND detected = 1`)
}

// With no reference page to read, the AI still reads the record: its description and the rows of every product it names, the line's
// own first; the reading cites the record.
func TestLineReading_TheRecordAloneIsReadWhenNoPageIs(t *testing.T) {
	t.Parallel()
	e, fc := quillWorld(t, "115.9.0")
	if it := quillItem(t, e); !it.Checkable() {
		t.Fatalf("the CVE is not checkable: %+v", it)
	}
	runCheck(t, e)
	if len(fc.sent) != 1 {
		t.Fatalf("%d AI calls, want one on the record alone", len(fc.sent))
	}
	req := fc.sent[0]
	if len(req.Pages) != 0 || !strings.Contains(req.Description, quillFixed) {
		t.Errorf("request pages %d, description %q: want the record alone", len(req.Pages), req.Description)
	}
	if len(req.Rows) != 2 || !strings.HasPrefix(req.Rows[0], "quillfeather mail") || req.Rows[1] != quillRowESR {
		t.Errorf("rows %q: want the line's own product first, then every other product's", req.Rows)
	}
	if n := e.count(`SELECT count(*) FROM fnd_line_statement WHERE cve = '` + cveQuill + `' AND url = ''`); n != 1 {
		t.Errorf("%d readings of the record stored, want 1", n)
	}
	if n := e.count(`SELECT count(*) FROM fnd_possible_check WHERE cve = '` + cveQuill + `'`); n != 0 {
		t.Errorf("%d structured checks stored beside the reading of the record", n)
	}
	// the record unchanged: not asked again
	runCheck(t, e)
	if len(fc.sent) != 1 {
		t.Errorf("the unchanged record was read again (%d calls)", len(fc.sent))
	}
}

// A check stored before the AI read the record ("no page could be read") is read again, now from the record.
func TestLineReading_ACheckThatReadNoPageIsReadAgainFromTheRecord(t *testing.T) {
	t.Parallel()
	e, fc := quillWorld(t, "115.9.0")
	q := quillItem(t, e).Question
	c := Check{Key: q.CheckKey, CVE: cveQuill, ID: *q.Detail.Check, DecidedBy: DecidedStructured, Verdict: VerdictUnsure, Sources: []CheckSource{},
		Reason: "The CVE record lists no reference page the box can read.", Undecided: &Undecided{Reason: UndecidedNoReference}, CheckedBy: "ana@example.com", CheckedAt: e.svc.now()}
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error { return insertCheck(t.Context(), tx, c) }); err != nil {
		t.Fatal(err)
	}
	if !quillItem(t, e).Checkable() {
		t.Fatal("a check that read no page is not checkable again")
	}
	runCheck(t, e)
	if len(fc.sent) != 1 {
		t.Errorf("%d AI calls, want the record read once", len(fc.sent))
	}
	if it := quillItem(t, e); it.Check == nil || it.Check.Reading == nil {
		t.Errorf("the item shows %+v, want the reading of the record", it.Check)
	}
}

// The record states line 115 of another of its products fixed in 115.42 and nothing for the mail client's 115 line: the AI may infer
// that line 115 of the mail client carried the flaw. That opens a finding only (rejectable, labelled an inference), never with the other
// product's release as its fix, never for a version at or past the named release, and an inference never settles "not affected".
func TestLineReading_AnInferenceFromAnotherProductsLineOnlyOpens(t *testing.T) {
	t.Parallel()
	infer := ProposeVerdict{Status: StatementAffected, Line: "115", FixedIn: "115.42", InferredFrom: "Quillfeather Browser ESR", Quote: quillFixed, Source: 0,
		Reason: "Browser ESR 115 is fixed in 115.42; the mail client's 115 line shares the engine and has no fix in the record."}
	for _, tc := range []struct {
		name    string
		version string
		edit    func(v *ProposeVerdict)
		finding bool
		rows    []RecordRow // more rows of the record
	}{
		{name: "affected from another product's line", version: "115.9.0", finding: true},
		{name: "a version past the named release", version: "115.50.0"},
		{name: "a version off the line", version: "116.1.0"},
		{name: "the quote names no release of the line", version: "115.9.0", edit: func(v *ProposeVerdict) {
			v.Quote = "Use-after-free in the layout engine."
		}},
		{name: "not affected from an inference", version: "157.2.0", edit: func(v *ProposeVerdict) {
			v.Status, v.Line, v.FixedIn = StatementNotAffected, "157", ""
		}},
		{name: "fixed from an inference", version: "115.50.0", edit: func(v *ProposeVerdict) { v.Status = StatementFixed }},
		{name: "the record has a row of this product on the line", version: "115.9.0", rows: []RecordRow{
			{Vendor: "Quillfeather", Product: "Mail", Text: "Quillfeather Mail (edition esr): affected from 115.0 before 115.6 [cna]"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, fc := quillWorld(t, tc.version)
			r := fc.records[cveQuill]
			r.Rows = append(r.Rows, tc.rows...)
			fc.records[cveQuill] = r
			v := infer
			if tc.edit != nil {
				tc.edit(&v)
			}
			fc.verdicts[cveQuill+"|"+tc.version] = v
			runCheck(t, e)
			if got := quillFindings(t, e) == 1; got != tc.finding {
				t.Fatalf("finding %v, want %v", got, tc.finding)
			}
			var fixed, status string
			if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT ifnull(fixed_in, ''), status FROM fnd_line_statement WHERE cve = ?`, cveQuill).
				Scan(&fixed, &status); err != nil {
				t.Fatal(err)
			}
			if fixed != "" {
				t.Errorf("the other product's release %q was kept as a bound of this one", fixed)
			}
			if tc.finding {
				var kind, evidence string
				if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT fix_kind, evidence FROM fnd_finding WHERE cve = ?`, cveQuill).Scan(&kind, &evidence); err != nil {
					t.Fatal(err)
				}
				if kind != string(FixUnknown) || !strings.Contains(evidence, "infers") || !strings.Contains(evidence, "Inferred from Quillfeather Browser ESR") {
					t.Errorf("fix %s, evidence %s: want no fix and the inference named", kind, evidence)
				}
				return
			}
			if it := quillItem(t, e); it.State == PossibleSettled {
				t.Errorf("an inference settled the CVE: %+v", it.Check)
			}
			if (tc.edit != nil && v.Status != StatementAffected && v.Status != StatementNotAffected || tc.rows != nil) && status != StatementUnsure {
				t.Errorf("an inference read %s was kept as %s, want unsure", v.Status, status)
			}
		})
	}
}

// A bound the AI gives that the quote does not name, but the cited page states as its own sentence ("present-in" and "fixed-in" lines
// of a project's tracker), places the version inside the affected releases: a finding. It never settles a version past it, nor becomes
// the fix.
func TestLineReading_ABoundOnTheCitedPageOpensButNeverSettles(t *testing.T) {
	t.Parallel()
	const page = "Summary: signature check accepts an overlarge S value. CVE-2026-991001\npresent-in: 0.68\nfixed-in: 2026-05-20 (0.84)"
	v := ProposeVerdict{Status: StatementAffected, Introduced: "0.68", FixedIn: "0.84", Line: "", Quote: "present-in: 0.68", Source: 1,
		Reason: "Present in 0.68, fixed in 0.84."}
	for _, tc := range []struct {
		version string
		finding bool
	}{{"0.80", true}, {"0.85", false}} {
		t.Run(tc.version, func(t *testing.T) {
			t.Parallel()
			e, fc := quillWorld(t, tc.version)
			url := "https://www.example.org/~maker/mail/wishlist/overlarge-s.html"
			fc.pages[cveQuill] = []FetchedPage{{URL: url, Status: "ok", Text: page}}
			fc.tags = map[string][]string{url: {"third-party-advisory"}}
			fc.verdicts[cveQuill+"|"+tc.version] = v
			runCheck(t, e)
			if got := quillFindings(t, e) == 1; got != tc.finding {
				t.Fatalf("finding %v, want %v", got, tc.finding)
			}
			if tc.finding {
				if n := e.count(`SELECT count(*) FROM fnd_finding WHERE cve = '` + cveQuill + `' AND fix_kind = 'unknown'`); n != 1 {
					t.Error("a fix release the quote does not name became the fix")
				}
				return
			}
			if it := quillItem(t, e); it.State == PossibleSettled {
				t.Error("a bound the quote does not name settled a version past it")
			}
		})
	}
}

// Only a reference tagged vendor-advisory or a page on the vendor's own host is the vendor's page: a third-party site whose path names
// the vendor and a model (/<vendor>/<model>/), a person's home page about the product, or a code host's project path is not, however
// the path reads (a vendor page lets the box settle "not affected").
func TestMarkVendorPages_OnlyTheVendorsTagOrHost(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw  string
		tag  string
		want bool
	}{
		{"https://vulns.example.org/quillfeather/mail-x9/overflow.html", "third-party-advisory", false},
		{"https://www.example.org/~maker/mail/wishlist/overlarge-s.html", "third-party-advisory", false},
		{"https://code.example.net/quillfeather/mail/security/advisories/1", "", false},
		{"https://www.quillfeather.com/security/QF-2026-01", "", true},
		{"https://advisories.example.net/QF-2026-01", "vendor-advisory", true},
	} {
		pages := []FetchedPage{{URL: tc.raw, Status: "ok"}}
		var tags []string
		if tc.tag != "" {
			tags = []string{tc.tag}
		}
		markVendorPages(pages, []RefLink{{URL: tc.raw, Tags: tags}}, "quillfeather|mail")
		if pages[0].Vendor != tc.want {
			t.Errorf("%s: vendor %v, want %v", tc.raw, pages[0].Vendor, tc.want)
		}
	}
}

// A sentence that names several products of the record pairs each release with the product named just before it: a bound the answer
// gives for this product that the sentence pairs with another product ("fixed in Browser ESR 115.42 and Mail 140.17" read for the mail
// client's line 115) is the other product's, so the reading is an inference (no bound, no fix, opens only); for the browser's line 115
// the same sentence states its bound, but names another product's release too, so it opens with no fix.
func TestLineReading_ABoundPairedWithAnotherProductIsAnInference(t *testing.T) {
	t.Parallel()
	const both = "This flaw was fixed in Quillfeather Browser ESR 115.42 and Quillfeather Mail 140.17."
	for _, tc := range []struct {
		product, version string
		basis, fixed     string // stored
		fix              string // the opened finding's fix ("" none opened)
	}{
		{"Mail", "115.9.0", BasisInferred, "", ""},
		// the sentence pairs 115.42 with the browser, but 140.17 with the mail client: not every release follows the browser's name, so
		// the reading opens with no fix (it may give none, nor settle anything)
		{"Browser", "115.9.0", BasisUnpaired, "115.42", "-"},
	} {
		t.Run(tc.product, func(t *testing.T) {
			t.Parallel()
			e, fc := quillWorldOf(t, tc.product, tc.version)
			r := fc.records[cveQuill]
			r.Description = "Use-after-free in the layout engine. " + both
			fc.records[cveQuill] = r
			fc.verdicts[cveQuill+"|"+tc.version] = ProposeVerdict{Status: StatementFixed, FixedIn: "115.42", Line: "115", Quote: both, Source: 0,
				Reason: "Fixed in 115.42."}
			runCheck(t, e)
			var basis, fixed string
			if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT basis, ifnull(fixed_in, '') FROM fnd_line_statement WHERE cve = ?`, cveQuill).
				Scan(&basis, &fixed); err != nil {
				t.Fatal(err)
			}
			if basis != tc.basis || fixed != tc.fixed {
				t.Errorf("stored basis %s fixed_in %q, want %s %q", basis, fixed, tc.basis, tc.fixed)
			}
			var fix string
			if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT ifnull(max(ifnull(fix_version, '-')), '') FROM fnd_finding WHERE cve = ? AND range_origin = 'ai_read'`,
				cveQuill).Scan(&fix); err != nil {
				t.Fatal(err)
			}
			if fix != tc.fix {
				t.Errorf("opened finding's fix %q, want %q", fix, tc.fix)
			}
		})
	}
}

// A line whose edition is known and whose release line the record's rows do not list waits for the reading, not for a person's
// attribute: it is checkable, and its cause is the reading's.
func TestCheckable_AnUnlistedLineIsRead(t *testing.T) {
	t.Parallel()
	q := Question{Kind: QuestionNotComparable, CVE: cveQuill, SoftwareID: "s-quill", Detail: QuestionDetail{Version: "115.9.0", Attribute: AttrUnlistedLine,
		Undecided: &Undecided{Reason: UndecidedAttribute}}}
	if !checkable(q) {
		t.Error("an unlisted release line is not checkable")
	}
	for _, attr := range []string{AttrEdition, AttrArchitecture, AttrPlatform} {
		x := q
		x.Detail.Attribute = attr
		if checkable(x) {
			t.Errorf("a line waiting for its %s is checkable", attr)
		}
	}
	q.CheckKey, q.Detail.Check = strings.Repeat("a", 64), &CheckID{Product: "quillfeather|mail", Line: "115.9.0", Version: "115.9.0"}
	if c := PossibleCause(PossibleItem{Question: q, CVE: cveQuill, State: PossibleOpen}, ReadState{Ready: true, Auto: true}); c != CauseNeedsReading {
		t.Errorf("cause %q, want %s", c, CauseNeedsReading)
	}
	q.CheckKey, q.Detail.Check = "", nil
	q.Detail.Attribute = AttrEdition
	if c := PossibleCause(PossibleItem{Question: q, CVE: cveQuill, State: PossibleOpen}, ReadState{Ready: true}); c != CauseVersionNeeded {
		t.Errorf("an edition to state: cause %q, want %s", c, CauseVersionNeeded)
	}
}

// An answer that quotes another product's row of the record is that product's statement, whatever the answer says of its basis: read
// as an inference (no bound, no fix of the other product's releases), even when the answer leaves "inferred_from" empty.
func TestLineReading_AQuoteOfAnotherProductsRowIsAnInference(t *testing.T) {
	t.Parallel()
	e, fc := quillWorld(t, "115.9.0")
	fc.verdicts[cveQuill+"|115.9.0"] = ProposeVerdict{Status: StatementAffected, Line: "115", Introduced: "115.1.0", FixedIn: "115.42.0", Quote: quillRowESR,
		Source: 0, Reason: "Line 115 is affected before 115.42.0."}
	runCheck(t, e)
	var basis, fixed string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT basis, ifnull(fixed_in, '') FROM fnd_line_statement WHERE cve = ?`, cveQuill).
		Scan(&basis, &fixed); err != nil {
		t.Fatal(err)
	}
	if basis != BasisInferred || fixed != "" {
		t.Errorf("basis %q, fixed_in %q: want an inference with no bound of the other product", basis, fixed)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE cve = '` + cveQuill + `' AND fix_kind <> 'unknown'`); n != 0 {
		t.Errorf("%d findings carry the other product's release as their fix", n)
	}
}

// A release the quote pairs with another product of the record is never this product's bound, fix or "not affected", however the
// sentence names the products: a longer name that contains this one ("Mail Server" read for Mail), written with a dash or as one
// word, with the vendor in the row's product, a quote that names the other product only, a release named for both products, and the
// version itself said "not affected" of the other product. A sentence that pairs the release with this product (or names no
// product) still states it, and a row of this product's edition ("browser esr") is this product's.
func TestLineReading_AReleaseTheQuotePairsWithAnotherProductIsAnInference(t *testing.T) {
	t.Parallel()
	rows := func(products ...string) CVERecordText {
		var r CVERecordText
		for _, p := range products {
			r.Rows = append(r.Rows, RecordRow{Vendor: "quillfeather", Product: p, Text: "quillfeather " + p + ": affected [cna]"})
		}
		return r
	}
	fixed := func(quote string) ProposeVerdict {
		return ProposeVerdict{Status: StatementFixed, FixedIn: "2.3", Line: "2", Quote: quote}
	}
	for _, tc := range []struct {
		name, product string
		rec           CVERecordText
		v             ProposeVerdict
		inferred      bool
	}{
		{"a longer name holding this one", "mail", rows("mail", "mail_server"), fixed("Fixed in Quillfeather Mail Server 2.3."), true},
		{"both named, the release the other's", "mail", rows("mail", "mail_server"), fixed("Quillfeather Mail 1.9 and Quillfeather Mail Server 2.3 fix it."), true},
		{"the other's name with a dash", "mail", rows("mail", "mail_server"), fixed("Mail 1.9 and Mail-Server 2.3 fix it."), true},
		{"the other's name as one word", "mail", rows("mail", "mail_server"), fixed("Mail 1.9 and MailServer 2.3 fix it."), true},
		{"the vendor in the other's product", "mail", rows("mail", "quillfeather_mail_server"), fixed("Quillfeather Mail 1.9 and Quillfeather Mail Server 2.3 fix it."), true},
		{"the other product named only", "browser", rows("browser", "mail"), fixed("Quillfeather Mail before 2.3 is affected."), true},
		{"one release named for both", "browser", rows("browser", "mail"), fixed("Quillfeather Browser 2.3 is affected and Quillfeather Mail 2.3 is fixed."), true},
		{"the version not affected of the other", "browser", rows("browser", "mail"),
			ProposeVerdict{Status: StatementNotAffected, Line: "2", Quote: "Quillfeather Browser 1.0 is affected; Quillfeather Mail 2.2 is not affected."}, true},
		{"this product's own release", "browser", rows("browser", "mail"), fixed("Fixed in Quillfeather Browser 1.9 and 2.3, and Quillfeather Mail 3.1."), false},
		{"this product's edition", "browser", rows("browser_esr", "mail"), fixed("Fixed in Quillfeather Browser ESR 2.3 and Quillfeather Mail 3.1."), false},
		{"no product named", "browser", rows("browser", "mail"), fixed("Versions before 2.3 are affected."), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			id := CheckID{Product: "quillfeather|" + tc.product, Line: "2", Version: "2.2"}
			v := tc.v
			v.InferredFrom = unpairedBound(tc.rec, id, v)
			st := readingOfAnswer("CVE-2026-991002", id, v, nil, v.Quote, nil, ProposeAnswer{}, "admin", time.Now())
			st.VendorPage = true
			verdict, fix := st.verdictFor(id), st.fix(id)
			if tc.inferred {
				if st.Basis != BasisInferred || fix.Kind != FixUnknown || verdict == VerdictNotAffected && !st.asCheck(id).Proposal() {
					t.Errorf("basis %s, verdict %q, fix %+v: want an inference (no fix, not affected only as a proposal)", st.Basis, verdict, fix)
				}
				return
			}
			if st.Basis != BasisStated || fix.Version != "2.3" {
				t.Errorf("basis %s, fix %+v: want the stated fix 2.3", st.Basis, fix)
			}
		})
	}
}

// An AI reading's "not affected" is always a proposal for a person; whether every version of its quote follows this product's own name
// (the record's or the catalogue's, only spaces or its own edition word between) says only whether it is stated or unpaired, which
// decides whether it may give a fix.
func TestLineReading_OnlyAVersionNamedWithThisProductIsStated(t *testing.T) {
	t.Parallel()
	const url = "https://www.quillfeather.com/security/QF-2026-01"
	for _, tc := range []struct {
		name, quote string
		basis       string
	}{
		{"another product's name before the version", "Quillfeather Mail Server 115.42 is not affected.", BasisUnpaired},
		{"this product's name before the version", "Quillfeather Mail 115.42 is not affected.", BasisStated},
		{"this product's edition word between", "Quillfeather Mail ESR 115.42 is not affected.", BasisStated},
		{"no name before the version", "Release 115.42 is not affected.", BasisUnpaired},
		{"two versions, one not named with this product", "Quillfeather Mail 115.42 and 115.43 are not affected.", BasisUnpaired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, fc := quillWorld(t, "115.42")
			r := fc.records[cveQuill]
			r.Rows = append(r.Rows, RecordRow{Vendor: "quillfeather", Product: "mail", Edition: "esr", Text: "quillfeather mail (edition esr): affected from 140.0 before 140.17.0 [nvd]"})
			fc.records[cveQuill] = r
			fc.pages[cveQuill] = []FetchedPage{{URL: url, Status: "ok", Text: cveQuill + ". " + tc.quote}}
			fc.verdicts[cveQuill+"|115.42"] = ProposeVerdict{Status: StatementNotAffected, Line: "115.42", Quote: tc.quote, Source: 1, Reason: "Not affected."}
			runCheck(t, e)
			it := quillItem(t, e)
			if it.State != PossibleProposal || it.Check == nil || it.Check.Verdict != VerdictNotAffected || PossibleCause(it, e.svc.ReadState(t.Context())) != CauseNeedsPerson {
				t.Fatalf("state %s (check %+v), want the AI's not affected as a proposal for a person", it.State, it.Check)
			}
			if b := it.Check.Reading.Basis; b != tc.basis {
				t.Errorf("basis %s, want %s", b, tc.basis)
			}
		})
	}
}

// A fix the quote states is the finding's fix only when the release follows this product's own name; otherwise the finding opens with
// no fix.
func TestLineStatement_AFixOnlyFromAReleaseNamedWithThisProduct(t *testing.T) {
	t.Parallel()
	id := CheckID{Product: "quillfeather|mail", Line: "115.9.0", Version: "115.9.0"}
	st := LineStatement{Status: StatementFixed, Basis: BasisUnpaired, FixedIn: "115.42", StatedLine: "115", Quote: "Fixed in 115.42.", QuoteFound: true}
	if got := st.verdictFor(id); got != VerdictAffected {
		t.Errorf("unpaired fixed: %q, want affected (opens)", got)
	}
	if f := st.fix(id); f.Kind != FixUnknown {
		t.Errorf("unpaired reading's fix %+v, want none", f)
	}
	st.Basis = BasisStated
	if f := st.fix(id); f.Version != "115.42" {
		t.Errorf("stated reading's fix %+v, want 115.42", f)
	}
}

// Every version-like token of the quote counts, not only a dotted one: a whole number, a wildcard line, a train with a letter, a date or a
// "v" release that does not follow this product's own name keeps the reading from settling or fixing. A CVE id is not a version, and a
// number inside this product's own name ("Server 2019") is part of the name.
func TestNamedWithThisProduct_EveryVersionLikeToken(t *testing.T) {
	t.Parallel()
	names, editions := []string{"mail", "server 2019"}, []string{"esr"}
	for _, tc := range []struct {
		quote string
		want  bool
	}{
		{"Quillfeather Mail 140.17 is fixed; Quillfeather Reader 116 is not affected.", false},
		{"Quillfeather Mail 140.17 is fixed; Quillfeather Reader 115.x is not affected.", false},
		{"Quillfeather Mail 21.4 is fixed in R2-S3.", false},
		{"Quillfeather Mail 140.17, released 2026-01-15, fixes it.", false},
		{"Quillfeather Mail 140.17 fixes it; v116.0 is not affected.", false},
		{"Quillfeather Mail 8.6.5 and Reader 8.6.5p1 fix it.", false},
		{"Quillfeather Mail 140.17 fixes 3 issues.", false},
		{"Quillfeather Mail 115.42.0.1 fixes CVE-2026-991001.", true},
		{"Quillfeather Mail ESR 115.42 is not affected.", true},
		{"Quillfeather Mail 21.4R2-S3 is not affected.", true},
		{"Quillfeather Mail 8.6.5p1 fixes it.", true},
		{"Quillfeather Mail v115.42 is not affected.", true},
		{"Quillfeather Server 2019 10.0.17763.5329 fixes it.", true},
		{"QUILLFEATHER MAIL 140.17 is not affected.", true},
		{"Quillfeather Mails 140.17 are not affected.", false},
		{"Quillfeather Mail: 140.17 is not affected.", false},
	} {
		if got := namedWithThisProduct(tc.quote, names, editions, []string{"quillfeather"}); got != tc.want {
			t.Errorf("%q: %v, want %v", tc.quote, got, tc.want)
		}
	}
}

// End to end: a vendor page's "not affected" for a whole-number line of a product the record does not list is no settling of this one.
func TestLineReading_AWholeNumberReleaseOfAnotherProductDoesNotSettle(t *testing.T) {
	t.Parallel()
	const url = "https://www.quillfeather.com/security/QF-2026-02"
	quote := "Quillfeather Mail 140.17 is affected; Quillfeather Reader 115 is not affected."
	e, fc := quillWorld(t, "115.42")
	fc.pages[cveQuill] = []FetchedPage{{URL: url, Status: "ok", Text: cveQuill + ". " + quote}}
	fc.verdicts[cveQuill+"|115.42"] = ProposeVerdict{Status: StatementNotAffected, Line: "115", Quote: quote, Source: 1, Reason: "Not affected."}
	runCheck(t, e)
	it := quillItem(t, e)
	if it.State == PossibleSettled {
		t.Fatalf("settled by another product's release (check %+v), want a proposal for a person", it.Check)
	}
}

// A name of this product counts only when the word before it is the vendor's name, the sentence's start, punctuation or a lower-case word:
// a capitalised other word makes it another product's name ("Thunder Mail 2.3" is no release of Mail).
func TestNamedWithThisProduct_TheWordBeforeTheName(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		quote string
		want  bool
	}{
		{"Thunder Mail 2.3 is not affected.", false},
		{"Exchange Mail 2.3 fixes it.", false},
		{"Quillfeather Mail 2.3 fixes it.", true},
		{"Mail 2.3 fixes it.", true},
		{"Upgrade the Mail 2.3 release.", true},
		{"Fixed (Mail 2.3).", true},
	} {
		if got := namedWithThisProduct(tc.quote, []string{"mail"}, nil, []string{"quillfeather"}); got != tc.want {
			t.Errorf("%q: %v, want %v", tc.quote, got, tc.want)
		}
	}
}

// An AI reading never settles "not affected" by itself, whatever its page and basis: even a stated reading of the vendor's own page
// for a CVE on no exploited list is an AI proposal a person confirms or rejects; confirming it answers the question not affected.
func TestLineReading_AnAIReadingNeverSettlesNotAffected(t *testing.T) {
	t.Parallel()
	const url = "https://www.quillfeather.com/security/QF-2026-03"
	const quote = "Quillfeather Mail 115.42 is not affected."
	e, fc := quillWorld(t, "115.42")
	fc.pages[cveQuill] = []FetchedPage{{URL: url, Status: "ok", Text: cveQuill + ". " + quote}}
	fc.verdicts[cveQuill+"|115.42"] = ProposeVerdict{Status: StatementNotAffected, Line: "115.42", Quote: quote, Source: 1, Reason: "Not affected."}
	runCheck(t, e)
	it := quillItem(t, e)
	if it.State != PossibleProposal || it.Check == nil || it.Check.Verdict != VerdictNotAffected || it.Check.Reading == nil ||
		it.Check.Reading.Basis != BasisStated || !it.Check.Reading.VendorPage {
		t.Fatalf("state %s, check %+v: want a proposal of the stated vendor reading", it.State, it.Check)
	}
	if _, err := e.svc.ConfirmProposal(t.Context(), it.Question.ID, "ana@example.com", false); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE id = '` + it.Question.ID + `' AND answer = 'not_affected'`); n != 1 {
		t.Error("confirming the proposal did not answer the question not affected")
	}
}

// An inference from another product's row that states a range of line N ("from 115.1.0 before 115.42.0") speaks for a version of
// this product inside that range: the start of the range is a lower bound, not a release the version must be before. A version
// before the start, or past the end, is not named.
func TestLineReading_AnInferenceFromARangeOfTheOtherProductsLine(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		version string
		finding bool
	}{
		{"115.9.0", true},
		{"115.1.0", true},
		{"115.0.5", false},
		{"115.42.0", false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			t.Parallel()
			e, fc := quillWorld(t, tc.version)
			fc.verdicts[cveQuill+"|"+tc.version] = ProposeVerdict{Status: StatementAffected, Line: "115", InferredFrom: "quillfeather browser (edition esr)",
				Quote: quillRowESR, Source: 0, Reason: "The browser's ESR 115 line is affected; the mail client's 115 line has no row."}
			runCheck(t, e)
			if got := quillFindings(t, e) == 1; got != tc.finding {
				t.Fatalf("finding %v, want %v", got, tc.finding)
			}
		})
	}
}

// An answer that quotes a row of this product about another build (an edition the item is not, or "edition not" the item's) reads
// another build's statement: it is an inference like a quote of another product's row. A row of the item's own edition, a row of no
// edition beside none, and any row while the item's edition is unknown are this product's own.
func TestOtherProductsRow_ARowOfAnotherBuildOfThisProduct(t *testing.T) {
	t.Parallel()
	plain := "quillfeather mail (edition not esr): affected before 157.0 [nvd]"
	own := "quillfeather mail (edition esr): affected from 140.0 before 140.17.0 [nvd]"
	pro := "quillfeather mail (edition pro): affected before 3.2 [nvd]"
	rec := CVERecordText{Description: "Use-after-free in the layout engine.", Rows: []RecordRow{
		{Vendor: "quillfeather", Product: "mail", NotEditions: []string{"esr"}, Text: plain},
		{Vendor: "quillfeather", Product: "mail", Edition: "esr", Text: own},
		{Vendor: "quillfeather", Product: "mail", Edition: "pro", Text: pro},
		{Vendor: "quillfeather", Product: "browser", Edition: "esr", Text: quillRowESR},
	}}
	for _, tc := range []struct {
		quote, edition, want string
	}{
		{plain, "esr", "quillfeather mail (edition not esr)"},
		{pro, "esr", "quillfeather mail (edition pro)"},
		{own, "esr", ""},
		{plain, "", ""},
		{pro, "", ""},
		{quillRowESR, "esr", "quillfeather browser"},
		{quillRowESR, "", "quillfeather browser"},
	} {
		if got := otherProductsRow(rec, "quillfeather|mail", tc.quote, tc.edition); got != tc.want {
			t.Errorf("%q (edition %q): %q, want %q", tc.quote, tc.edition, got, tc.want)
		}
	}
}

// "after X" excludes X however the record writes it: a version equal to X with more or fewer zero components ("115.1" and "115.1.0")
// is not past it, while one past it on the line is.
func TestNamedByRelease_AfterExcludesTheSameReleaseWrittenOtherwise(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		quote, version string
		want           bool
	}{
		{"quillfeather browser 115.x: affected after 115.1 before 115.42.0", "115.1.0", false},
		{"quillfeather browser 115.x: affected after 115.1.0 before 115.42.0", "115.1", false},
		{"quillfeather browser 115.x: affected after 115.1.0 before 115.42.0", "115.1.0", false},
		{"quillfeather browser 115.x: affected after 115.1 before 115.42.0", "115.1.1", true},
		{"quillfeather browser 115.x: affected from 115.1 before 115.42.0", "115.1.0", true},
	} {
		st := LineStatement{StatedLine: "115", Quote: tc.quote, Basis: BasisInferred, Status: StatementAffected}
		if got := st.namedByRelease(CheckID{Product: "quillfeather|mail", Line: tc.version, Version: tc.version}); got != tc.want {
			t.Errorf("%q at %s: named %v, want %v", tc.quote, tc.version, got, tc.want)
		}
	}
}
