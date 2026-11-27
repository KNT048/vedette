package findings

import (
	"database/sql"
	"strings"
	"testing"
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
	e := newEnv(t)
	sw := Software{ID: "s-quill", Display: "Quillfeather Mail", Vendor: "Quillfeather", Product: "Mail", Version: version, Source: "agent"}
	a := Asset{ID: "pc-01", Name: "pc-01", OS: "Microsoft Windows 11 Pro", Software: []Software{sw}}
	e.inv.assets = map[string]AssetView{"pc-01": {ID: "pc-01", Hostname: ptr("pc-01"), IP: "192.0.2.10", Kind: "workstation", Approved: true}}
	e.inv.match = map[string]Asset{"pc-01": a}
	e.feeds.vulns = []Vuln{{CVE: cveQuill, NVDAnswered: true, Origin: RangeNVD, Affected: []Affected{{CPE: "cpe:2.3:a:quillfeather:mail:-:*:*:*:*:*:*:*"}}}}
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
		settled bool
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, fc := quillWorld(t, tc.version)
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
			if tc.edit != nil && v.Status != StatementAffected && status != StatementUnsure {
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

// The project's own site is the vendor's for "not affected": a page whose path starts with the product's or vendor's name, or a
// person's home and then that name, where the record's reference points. Another path on such a host is not.
func TestMarkVendorPages_TheProjectsOwnSite(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]bool{
		"https://www.example.org/~maker/mail/wishlist/overlarge-s.html": true,
		"https://code.example.net/quillfeather/mail/security/advisories/1": true,
		"https://code.example.net/someone/mail-poc":                       false,
		"https://www.example.org/~maker/other/mail.html":                  false,
		"https://www.example.org/mail":                                    false,
		"https://news.example.com/news/quillfeather/mail-flaw":            false,
	} {
		pages := []FetchedPage{{URL: raw, Status: "ok"}}
		markVendorPages(pages, []RefLink{{URL: raw, Tags: []string{"third-party-advisory"}}}, "quillfeather|mail")
		if pages[0].Vendor != want {
			t.Errorf("%s: vendor %v, want %v", raw, pages[0].Vendor, want)
		}
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
