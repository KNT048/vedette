package findings

import (
	"errors"
	"strings"
	"testing"
)

// The research of a synthetic product the catalogue does not know (Quillfeather Mail, quillWorld): the vendor's page the AI's tools
// read is not one of the record's references the box fetched.
const (
	quillSA       = "https://quillfeather.example/security/qsa-2026-17"
	quillSAText   = "Quillfeather Security Advisory QSA-2026-17 (CVE-2026-991001). Quillfeather Mail 115.0 through 115.11 is affected; the 115 line is fixed in Quillfeather Mail 115.12."
	quillAffected = "Quillfeather Mail 115.0 through 115.11 is affected"
)

func quillResearch(status, quoteCheck, quote, text string) ResearchAnswer {
	return ResearchAnswer{Verdict: ProposeVerdict{Status: status, Line: "115", Introduced: "115.0", FixedIn: "115.12", Quote: quote, Reason: "The vendor's advisory states it."}, Confidence: "high",
		Basis: BasisStated, URL: quillSA, QuoteCheck: quoteCheck, QuotedText: text, Mode: "balanced", Layer: "quick", Model: "quick-model", Profile: "Quick",
		ActivityID: "act-9", TokensIn: 30000, TokensOut: 900,
		Steps: []ResearchStep{{Layer: "quick", Model: "quick-model", Profile: "Quick", Web: "provider", TokensIn: 30000, TokensOut: 900, Searches: 2,
			Pages: []string{quillSA}, Verdict: status, Confidence: "high", QuoteCheck: quoteCheck}}}
}

// An AI "not affected" never closes anything: the CVE stays possible as a proposal a person decides in the review queue, its question
// unanswered, nothing in Answered and no finding.
func TestResearch_NotAffectedNeverClosesARow(t *testing.T) {
	t.Parallel()
	e, fc := quillWorld(t, "115.12.0")
	fc.answers = map[string]ResearchAnswer{cveQuill + "|115.12.0": quillResearch(StatementNotAffected, QuoteTool, "the 115 line is fixed in Quillfeather Mail 115.12", quillSAText)}
	runCheck(t, e)
	it := quillItem(t, e)
	if it.CVE != cveQuill || it.State != PossibleProposal || it.Check == nil || it.Check.Verdict != VerdictNotAffected {
		t.Fatalf("item %+v: want a not-affected proposal", it)
	}
	if PossibleCause(it, e.svc.ReadState(t.Context())) != CauseNeedsPerson {
		t.Errorf("cause %q, want needs_person", PossibleCause(it, e.svc.ReadState(t.Context())))
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE cve = '` + cveQuill + `' AND answer IS NOT NULL`); n != 0 {
		t.Error("the AI's not affected answered the question")
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE cve = '` + cveQuill + `'`); n != 0 {
		t.Error("a finding was written")
	}
	rev, err := e.svc.Review(t.Context(), ReviewFilter{}, Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	if rev.Total != 1 || rev.Items[0].CVE != cveQuill || rev.Items[0].Check == nil || rev.Items[0].Check.Reading == nil || rev.Items[0].Check.Reading.Research == nil {
		t.Fatalf("review queue %+v", rev)
	}
	r := rev.Items[0].Check.Reading.Research
	if r.QuoteCheck != QuoteTool || r.Tokens != 30900 || r.Layer != "quick" || len(r.Detail.Steps) != 1 || r.Detail.Steps[0].Searches != 2 {
		t.Errorf("research %+v", r)
	}
}

// "Affected" opens a finding (range origin ai_read) only with a quote the box found; the same answer with a quote found nowhere
// decides nothing.
func TestResearch_AffectedOpensOnlyWithACheckedQuote(t *testing.T) {
	t.Parallel()
	e, fc := quillWorld(t, "115.9.0")
	fc.answers = map[string]ResearchAnswer{cveQuill + "|115.9.0": quillResearch(StatementAffected, QuoteNotFound, quillAffected, "")}
	runCheck(t, e)
	if quillFindings(t, e) != 0 {
		t.Fatal("an affected answer whose quote the box did not find opened a finding")
	}
	if it := quillItem(t, e); it.CVE != cveQuill {
		t.Fatal("the CVE is no longer possible")
	}
	e2, fc2 := quillWorld(t, "115.9.0")
	fc2.answers = map[string]ResearchAnswer{cveQuill + "|115.9.0": quillResearch(StatementAffected, QuoteTool, quillAffected, quillSAText)}
	runCheck(t, e2)
	if quillFindings(t, e2) != 1 {
		t.Fatal("an affected answer with a checked quote opened no finding")
	}
	var host string
	var found bool
	if err := e2.db.Reader().QueryRowContext(t.Context(), `SELECT host, quote_found FROM fnd_line_statement WHERE cve = ?`, cveQuill).Scan(&host, &found); err != nil {
		t.Fatal(err)
	}
	if host != "quillfeather.example" || !found {
		t.Errorf("reading host %q quote found %v", host, found)
	}
	if n := e2.count(`SELECT count(*) FROM fnd_line_research r JOIN fnd_line_statement s USING (statement_key) WHERE s.cve = '` + cveQuill + `' AND r.quote_check = 'tool' AND r.tokens = 30900`); n != 1 {
		t.Errorf("%d research rows", n)
	}
}

// One research per (CVE, product, line), shared by every device and version on the line.
func TestResearch_OneResearchPerLineSharedByDevices(t *testing.T) {
	t.Parallel()
	e, fc := quillWorld(t, "115.9.0")
	a := e.inv.match["pc-01"]
	a.ID, a.Name = "pc-02", "pc-02"
	e.inv.match["pc-02"] = a
	v := e.inv.assets["pc-01"]
	v.ID, v.Hostname, v.IP = "pc-02", ptr("pc-02"), "192.0.2.11"
	e.inv.assets["pc-02"] = v
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	fc.answers = map[string]ResearchAnswer{cveQuill + "|115.9.0": quillResearch(StatementAffected, QuoteTool, quillAffected, quillSAText)}
	runCheck(t, e)
	if len(fc.research) != 1 {
		t.Fatalf("%d researches, want one for the line", len(fc.research))
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE cve = '` + cveQuill + `' AND range_origin = 'ai_read' AND state = 'open'`); n != 2 {
		t.Errorf("%d findings, want one per device", n)
	}
	req := fc.research[0]
	if req.Digest == "" || !strings.Contains(req.Digest, cveQuill) || len(req.Platforms) != 1 || req.Platforms[0] != "workstation" {
		t.Errorf("request digest %q platforms %v", req.Digest, req.Platforms)
	}
	for _, leak := range []string{"pc-01", "pc-02", "192.0.2."} {
		if strings.Contains(req.Digest+strings.Join(req.Platforms, " ")+req.Item.Product, leak) {
			t.Errorf("the research carries %q", leak)
		}
	}
}

// A reading survives a re-read of the CVE record while its quote is still on the cited page (the box fetches it, no tokens), and
// only then: the quote gone from the page, the line is researched again.
func TestResearch_SurvivesARecordReReadOnlyWithItsQuote(t *testing.T) {
	t.Parallel()
	e, fc := quillWorld(t, "115.9.0")
	fc.answers = map[string]ResearchAnswer{cveQuill + "|115.9.0": quillResearch(StatementAffected, QuoteTool, quillAffected, quillSAText)}
	fc.pages["elsewhere"] = []FetchedPage{{URL: quillSA, Status: "ok", Text: "<p>" + quillSAText + "</p>"}} // fetchable, not a reference
	runCheck(t, e)
	if quillFindings(t, e) != 1 || len(fc.research) != 1 {
		t.Fatalf("findings %d researches %d", quillFindings(t, e), len(fc.research))
	}
	restamp := func(stamp string) {
		e.feeds.vulns[0].Stamp = stamp
		if _, err := e.svc.Reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	restamp("reader update")
	runCheck(t, e)
	if len(fc.research) != 1 {
		t.Errorf("a record re-read with the quote on the page researched again (%d)", len(fc.research))
	}
	if quillFindings(t, e) != 1 {
		t.Error("the record re-read dropped the finding")
	}
	it := quillItem(t, e)
	if it.CVE == cveQuill && it.Checkable() {
		t.Error("the line is still due after the reading was kept")
	}
	var rec string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT record_hash FROM fnd_line_statement WHERE cve = ?`, cveQuill).Scan(&rec); err != nil {
		t.Fatal(err)
	}
	if rec != recordHash("reader update") {
		t.Errorf("record identity not moved: %s", rec)
	}
	fc.pages["elsewhere"][0].Text = "Quillfeather Security Advisory QSA-2026-17 has moved."
	restamp("another update")
	runCheck(t, e)
	if len(fc.research) != 2 {
		t.Errorf("the quote left the page and the line was not researched again (%d)", len(fc.research))
	}
}

// Bulk confirmation of the review queue: an exploited CVE's "not affected" is confirmed only when the request names its CVE; a row
// that does not wait (unknown, already answered) is skipped; a confirmed row answers its question not affected.
func TestReview_BulkConfirmExcludesExploitedUnlessNamed(t *testing.T) {
	t.Parallel()
	e, _ := possibleWorld(t)
	runCheck(t, e)
	rev, err := e.svc.Review(t.Context(), ReviewFilter{}, Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	if rev.Total != 1 || rev.Exploited != 1 || rev.Items[0].CVE != "CVE-2026-82002" || !rev.Items[0].Exploited {
		t.Fatalf("review %+v: want the exploited 82002", rev)
	}
	id := rev.Items[0].ID
	got, err := e.svc.ConfirmReview(t.Context(), []string{id, "q-unknown"}, nil, "ana@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Confirmed != 0 || len(got.Skipped) != 2 || got.Skipped[0].Reason != "exploited" || got.Skipped[1].Reason != "not_waiting" {
		t.Fatalf("without naming it: %+v", got)
	}
	if got, err = e.svc.ConfirmReview(t.Context(), []string{id}, []string{"CVE-2026-99999"}, "ana@example.com"); err != nil || got.Confirmed != 0 {
		t.Fatalf("naming another CVE: %+v %v", got, err)
	}
	if got, err = e.svc.ConfirmReview(t.Context(), []string{id}, []string{"CVE-2026-82002"}, "ana@example.com"); err != nil || got.Confirmed != 1 {
		t.Fatalf("naming it: %+v %v", got, err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE id = '` + id + `' AND answer = 'not_affected'`); n != 1 {
		t.Error("the confirmed answer did not answer the question")
	}
	if got, err = e.svc.ConfirmReview(t.Context(), []string{id}, []string{"CVE-2026-82002"}, "ana@example.com"); err != nil || got.Confirmed != 0 || got.Skipped[0].Reason != "not_waiting" {
		t.Errorf("confirming twice: %+v %v", got, err)
	}
	if _, err := e.svc.ConfirmReview(t.Context(), nil, nil, "ana@example.com"); err == nil {
		t.Error("an empty confirmation was accepted")
	}
}

// A row whose CVE is on no exploited list is confirmed in bulk without naming it.
func TestReview_BulkConfirmOfANotExploitedAnswer(t *testing.T) {
	t.Parallel()
	e, fc := quillWorld(t, "115.12.0")
	fc.answers = map[string]ResearchAnswer{cveQuill + "|115.12.0": quillResearch(StatementNotAffected, QuoteTool, "the 115 line is fixed in Quillfeather Mail 115.12", quillSAText)}
	runCheck(t, e)
	rev, err := e.svc.Review(t.Context(), ReviewFilter{Confidence: "high", Quote: "checked"}, Page{Limit: PageMax})
	if err != nil || rev.Total != 1 || rev.Exploited != 0 {
		t.Fatalf("review %+v %v", rev, err)
	}
	if low, _ := e.svc.Review(t.Context(), ReviewFilter{Confidence: "low"}, Page{Limit: PageMax}); low.Total != 0 {
		t.Error("the confidence filter kept a high-confidence answer")
	}
	if got, err := e.svc.ConfirmReview(t.Context(), []string{rev.Items[0].ID}, nil, "ana@example.com"); err != nil || got.Confirmed != 1 {
		t.Fatalf("confirm: %+v %v", got, err)
	}
}

// "Research deeper" researches the line again now, whatever was read before, and marks the request so the strong layer answers.
func TestResearch_DeeperResearchesTheLineAgain(t *testing.T) {
	t.Parallel()
	e, fc := quillWorld(t, "115.9.0")
	runCheck(t, e) // unsure: researched once
	if len(fc.research) != 1 {
		t.Fatalf("%d researches", len(fc.research))
	}
	it := quillItem(t, e)
	fc.answers = map[string]ResearchAnswer{cveQuill + "|115.9.0": quillResearch(StatementAffected, QuoteTool, quillAffected, quillSAText)}
	u, err := e.svc.deeperUnit(t.Context(), it.Question.ID) // what StartResearchDeeper runs in the background, run here to its end
	if err != nil {
		t.Fatal(err)
	}
	e.svc.check.run = &CheckRun{Running: true}
	e.svc.runPossibleCheck(t.Context(), []checkUnit{*u}, "ana@example.com")
	if len(fc.research) != 2 || !fc.research[1].Deeper {
		t.Fatalf("researches %d, deeper %v", len(fc.research), len(fc.research) == 2 && fc.research[1].Deeper)
	}
	if quillFindings(t, e) != 1 {
		t.Error("the deeper answer was not applied")
	}
	if _, err := e.svc.StartResearchDeeper(t.Context(), "q-none", "ana@example.com"); !errors.Is(err, ErrNotResearchable) {
		t.Errorf("an unknown row: %v", err)
	}
}
