package findings

import (
	"database/sql"
	"encoding/json"
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
	// the other way: a newer "affected" with a checked quote opens at once
	aff := quillResearch(StatementAffected, QuoteTool, "Quillfeather Mail 115.12.0 is affected", quillSAText+" Quillfeather Mail 115.12.0 is affected.")
	aff.Verdict.FixedIn, aff.Verdict.Introduced = "", ""
	fc.answers[cveQuill+"|115.12.0"] = aff
	u, err := e.svc.deeperUnit(t.Context(), it.Question.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.check.run = &CheckRun{Running: true}
	e.svc.runPossibleCheck(t.Context(), []checkUnit{*u}, "ana@example.com")
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE cve = '` + cveQuill + `' AND range_origin = 'ai_read' AND state = 'open'`); n != 1 {
		t.Errorf("a newer affected answer opened %d findings, want 1", n)
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

// The AI never closes anything, its own findings included: a newer research that says "not affected" for a line whose older reading
// opened a finding leaves the finding open and waits in Review AI answers; only a person's confirmation closes it. The other way, a
// newer "affected" with a checked quote opens at once.
func TestResearch_AnAIFindingStaysOpenWhenTheAINowSaysNotAffected(t *testing.T) {
	t.Parallel()
	e, fc := quillWorld(t, "115.9.0")
	fc.answers = map[string]ResearchAnswer{cveQuill + "|115.9.0": quillResearch(StatementAffected, QuoteTool, quillAffected, quillSAText)}
	fc.pages["elsewhere"] = []FetchedPage{{URL: quillSA, Status: "ok", Text: quillSAText}}
	runCheck(t, e)
	if quillFindings(t, e) != 1 {
		t.Fatal("the affected research opened no finding")
	}
	// the record is read again and the quote has left the page: researched again, and the AI now says not affected
	notAffected := quillResearch(StatementNotAffected, QuoteTool, "Quillfeather Mail 115.9.0 is not affected by this issue", "QSA-2026-17 (CVE-2026-991001): Quillfeather Mail 115.9.0 is not affected by this issue.")
	notAffected.Verdict.Introduced, notAffected.Verdict.FixedIn = "", ""
	fc.answers[cveQuill+"|115.9.0"] = notAffected
	fc.pages["elsewhere"][0].Text = "QSA-2026-17 was revised."
	e.feeds.vulns[0].Stamp = "revised"
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	runCheck(t, e)
	if len(fc.research) != 2 {
		t.Fatalf("%d researches, want the line researched again", len(fc.research))
	}
	if quillFindings(t, e) != 1 {
		t.Fatal("the AI's newer not-affected answer closed the finding its older reading opened")
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if quillFindings(t, e) != 1 {
		t.Fatal("the next match closed the AI's finding")
	}
	if in, err := e.svc.Input(t.Context(), "", "", Page{Limit: PageMax}); err != nil || strings.Contains(fmtJSON(t, in), cveQuill) {
		t.Errorf("the review item is in Needs your input too (%v)", err)
	}
	rev, err := e.svc.Review(t.Context(), ReviewFilter{}, Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	if rev.Total != 1 || rev.Items[0].CVE != cveQuill || rev.Items[0].Finding == nil || rev.Items[0].Check == nil || rev.Items[0].Check.Verdict != VerdictNotAffected {
		t.Fatalf("review %+v: want the not-affected answer beside the open finding", rev)
	}
	got, err := e.svc.ConfirmReview(t.Context(), []string{rev.Items[0].ID}, nil, "ana@example.com")
	if err != nil || got.Confirmed != 1 {
		t.Fatalf("confirm %+v %v", got, err)
	}
	if quillFindings(t, e) != 0 {
		t.Error("a person's confirmation did not close the finding")
	}
	if rev, _ = e.svc.Review(t.Context(), ReviewFilter{}, Page{Limit: PageMax}); rev.Total != 0 {
		t.Errorf("review after confirming: %d rows", rev.Total)
	}
}

// Questions that the distribution's data or the device's own version decides are never sent to the AI, even with a check key kept
// from before.
func TestResearch_DistroPendingQuestionsAreNeverResearched(t *testing.T) {
	t.Parallel()
	for _, reason := range []string{DistroNotListed, DistroOtherPackages, UndecidedNetworkVersion, UndecidedPackage} {
		t.Run(reason, func(t *testing.T) {
			t.Parallel()
			e, fc := quillWorld(t, "115.9.0")
			if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
				_, err := tx.ExecContext(t.Context(), `UPDATE fnd_question SET detail = json_set(detail, '$.undecided', json_object('reason', ?)) WHERE cve = ?`, reason, cveQuill)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			it := quillItem(t, e)
			if it.Question.CheckKey == "" {
				t.Fatal("the fixture's question has no check key")
			}
			runCheck(t, e)
			if len(fc.research) != 0 {
				t.Errorf("%d researches of a %s question", len(fc.research), reason)
			}
			if _, err := e.svc.deeperUnit(t.Context(), it.Question.ID); !errors.Is(err, ErrNotResearchable) {
				t.Errorf("Research deeper of a %s question: %v", reason, err)
			}
		})
	}
}

func fmtJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The AI never closes its own finding with a newer "affected" either: one whose quote the box did not find decides nothing, and one
// whose bounds leave the installed version out says, for that version, what "not affected" says. Neither ends the finding the older
// reading opened.
func TestResearch_ANewerAffectedAnswerDoesNotCloseTheAIFinding(t *testing.T) {
	t.Parallel()
	unchecked := quillResearch(StatementAffected, QuoteNotFound, "Quillfeather Mail 115.9.0 is affected and fixed in 115.13", "")
	unchecked.Verdict.Introduced, unchecked.Verdict.FixedIn = "", "115.13"
	outside := quillResearch(StatementAffected, QuoteTool, "Quillfeather Mail 115.10 through 115.11 is affected", "QSA-2026-17 (CVE-2026-991001): Quillfeather Mail 115.10 through 115.11 is affected.")
	outside.Verdict.Introduced, outside.Verdict.FixedIn, outside.Verdict.LastAffected = "115.10", "", "115.11"
	for name, newer := range map[string]ResearchAnswer{"unchecked quote": unchecked, "bounds leave the version out": outside} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e, fc := quillWorld(t, "115.9.0")
			fc.answers = map[string]ResearchAnswer{cveQuill + "|115.9.0": quillResearch(StatementAffected, QuoteTool, quillAffected, quillSAText)}
			fc.pages["elsewhere"] = []FetchedPage{{URL: quillSA, Status: "ok", Text: quillSAText}}
			runCheck(t, e)
			if quillFindings(t, e) != 1 {
				t.Fatal("the affected research opened no finding")
			}
			fc.answers[cveQuill+"|115.9.0"] = newer
			fc.pages["elsewhere"][0].Text = "QSA-2026-17 was revised."
			e.feeds.vulns[0].Stamp = "revised"
			if _, err := e.svc.Reconcile(t.Context()); err != nil {
				t.Fatal(err)
			}
			runCheck(t, e)
			if len(fc.research) != 2 {
				t.Fatalf("%d researches, want the line researched again", len(fc.research))
			}
			if _, err := e.svc.Reconcile(t.Context()); err != nil {
				t.Fatal(err)
			}
			if quillFindings(t, e) != 1 {
				t.Fatal("the AI's newer affected answer closed the finding its older reading opened")
			}
		})
	}
}

// Bulk confirmation reads the exploited lists inside the transaction that answers: a CVE that becomes exploited between the queue's read
// and the confirmation is not confirmed without being named.
func TestReview_ExploitedIsReadInsideTheConfirmation(t *testing.T) {
	t.Parallel()
	e, fc := quillWorld(t, "115.12.0")
	fc.answers = map[string]ResearchAnswer{cveQuill + "|115.12.0": quillResearch(StatementNotAffected, QuoteTool, "the 115 line is fixed in Quillfeather Mail 115.12", quillSAText)}
	runCheck(t, e)
	rev, err := e.svc.Review(t.Context(), ReviewFilter{}, Page{Limit: PageMax})
	if err != nil || rev.Total != 1 || rev.Exploited != 0 {
		t.Fatalf("review %+v %v", rev, err)
	}
	reads := 0
	e.feeds.vulnsErr = func() error { // the CVE joins an exploited list right after the first read of the confirmation
		if reads++; reads > 1 {
			delete(e.feeds.unlisted, cveQuill)
		}
		return nil
	}
	got, err := e.svc.ConfirmReview(t.Context(), []string{rev.Items[0].ID}, nil, "ana@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Confirmed != 0 || len(got.Skipped) != 1 || got.Skipped[0].Reason != "exploited" {
		t.Fatalf("a CVE exploited by the time of the write: %+v", got)
	}
	if got, err = e.svc.ConfirmReview(t.Context(), []string{rev.Items[0].ID}, []string{cveQuill}, "ana@example.com"); err != nil || got.Confirmed != 1 {
		t.Fatalf("named: %+v %v", got, err)
	}
}

// A quote the box found only in its own digest of the CVE record is the record's sentence, never the page the AI cited: the reading
// names no host and is not the vendor's page.
func TestResearch_ADigestQuoteIsTheRecordsNotTheCitedPage(t *testing.T) {
	t.Parallel()
	e, fc := quillWorld(t, "115.9.0")
	digest := "CVE-2026-991001\nRow: " + quillRowESR
	a := quillResearch(StatementAffected, QuoteDigest, quillRowESR, digest)
	fc.answers = map[string]ResearchAnswer{cveQuill + "|115.9.0": a}
	runCheck(t, e)
	var host, url string
	var vendor bool
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT host, url, vendor_page FROM fnd_line_statement WHERE cve = ?`, cveQuill).Scan(&host, &url, &vendor); err != nil {
		t.Fatal(err)
	}
	if host != "" || url != "" || vendor {
		t.Errorf("a digest quote credited to %q (%q, vendor page %v), want the CVE record", host, url, vendor)
	}
}

// A person rejects an AI reading once: the rejection covers the line's older readings of the same verdict (one of them may hold the
// finding open), and a new research of the same verdict from the same record and cited page is stored already rejected.
func TestResearch_OneRejectCoversTheSameVerdict(t *testing.T) {
	t.Parallel()
	e, fc := quillWorld(t, "115.9.0")
	fc.answers = map[string]ResearchAnswer{cveQuill + "|115.9.0": quillResearch(StatementAffected, QuoteTool, quillAffected, quillSAText)}
	fc.pages["elsewhere"] = []FetchedPage{{URL: quillSA, Status: "ok", Text: quillSAText}}
	runCheck(t, e)
	outside := quillResearch(StatementAffected, QuoteTool, "Quillfeather Mail 115.10 through 115.11 is affected", "QSA-2026-17 (CVE-2026-991001): Quillfeather Mail 115.10 through 115.11 is affected.")
	outside.Verdict.Introduced, outside.Verdict.FixedIn, outside.Verdict.LastAffected = "115.10", "", "115.11"
	fc.answers[cveQuill+"|115.9.0"] = outside
	fc.pages["elsewhere"][0].Text = "QSA-2026-17 was revised."
	e.feeds.vulns[0].Stamp = "revised"
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	runCheck(t, e)
	if quillFindings(t, e) != 1 || len(fc.research) != 2 {
		t.Fatalf("findings %d researches %d: want the finding held by the older reading", quillFindings(t, e), len(fc.research))
	}
	var newest string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT statement_key FROM fnd_line_statement WHERE cve = ? ORDER BY rowid DESC LIMIT 1`, cveQuill).Scan(&newest); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RejectProposal(t.Context(), newest, "ana@example.com"); err != nil {
		t.Fatal(err)
	}
	if quillFindings(t, e) != 0 {
		t.Fatal("one rejection left the finding open on an older reading of the same verdict")
	}
	// researched again now (same record, same cited page) with the same verdict: already rejected, nothing opens
	fc.answers[cveQuill+"|115.9.0"] = quillResearch(StatementAffected, QuoteTool, quillAffected, quillSAText)
	it := quillItem(t, e)
	u, err := e.svc.deeperUnit(t.Context(), it.Question.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.check.run = &CheckRun{Running: true}
	e.svc.runPossibleCheck(t.Context(), []checkUnit{*u}, "ana@example.com")
	if len(fc.research) != 3 {
		t.Fatalf("%d researches", len(fc.research))
	}
	if quillFindings(t, e) != 0 {
		t.Error("the same rejected verdict from the same record and page opened the finding again")
	}
	// a changed record is a new statement: no longer covered
	e.feeds.vulns[0].Stamp = "revised again"
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	u, err = e.svc.deeperUnit(t.Context(), it.Question.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.check.run = &CheckRun{Running: true}
	e.svc.runPossibleCheck(t.Context(), []checkUnit{*u}, "ana@example.com")
	if quillFindings(t, e) != 1 {
		t.Error("an answer on a changed record was held by an older rejection")
	}
}
