package findings

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The DSM line 7.2.1 as the vendor's page states it in words the box's own reader does not parse (so the AI reads it).
const dsmFixedText = "CVE-2026-82002 concerns Synology DiskStation Manager (DSM). DSM 7.2.1 is affected; the fix is in DSM 7.2.1-69057-6 and later."

// lineWorld is possibleWorld with 82002's page stating the fix of DSM 7.2.1 and the AI reading it as fixed in 7.2.1-69057-6.
func lineWorld(t *testing.T) (*env, *fakeChecker) {
	t.Helper()
	e, fc := possibleWorld(t)
	fc.pages["CVE-2026-82002"] = []FetchedPage{{URL: dsmPageURL + "#82002", Status: "ok", Text: dsmFixedText}}
	fc.verdicts["CVE-2026-82002|7.2.1-69057-5"] = ProposeVerdict{Status: StatementFixed, FixedIn: "7.2.1-69057-6", Line: "7.2.1", Reason: "Fixed in 7.2.1-69057-6.",
		Quote: "DSM 7.2.1 is affected; the fix is in DSM 7.2.1-69057-6 and later.", Source: 1}
	return e, fc
}

func aiReadFindings(t *testing.T, e *env, device string) int {
	t.Helper()
	return e.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = '` + device + `' AND cve = 'CVE-2026-82002' AND range_origin = 'ai_read' AND state = 'open' AND detected = 1`)
}

func possibleCauseOf(t *testing.T, e *env, cve string) string {
	t.Helper()
	return PossibleCause(possibleByCVE(t, e)[cve], e.svc.ReadState(t.Context()))
}

// A quote the box does not find word for word in the page it fetched decides nothing: no finding, the CVE stays possible (ai_unsure).
func TestLineReading_QuoteNotInThePageDecidesNothing(t *testing.T) {
	t.Parallel()
	e, fc := lineWorld(t)
	v := fc.verdicts["CVE-2026-82002|7.2.1-69057-5"]
	v.Quote = "DSM 7.2.1 versions before 7.2.1-69057-6 are affected."
	fc.verdicts["CVE-2026-82002|7.2.1-69057-5"] = v
	runCheck(t, e)
	if n := aiReadFindings(t, e, "nas-01"); n != 0 {
		t.Errorf("%d findings from a quote that is not in the page", n)
	}
	if n := e.count(`SELECT count(*) FROM fnd_line_statement WHERE cve = 'CVE-2026-82002' AND quote_found = 0`); n != 1 {
		t.Errorf("the reading is not stored with its quote marked not found")
	}
	if c := possibleCauseOf(t, e, "CVE-2026-82002"); c != CauseAIUnsure {
		t.Errorf("cause %q, want %s", c, CauseAIUnsure)
	}
}

// A verified "affected" opens a finding by itself (range origin ai_read), labelled with the page's host, its fix the release the quote
// names; a person rejects it in one click: the finding closes on every device of the line, one audit row, the CVE is possible again
// (needs_person) and the same page is not read again.
func TestLineReading_AffectedOpensAFindingAPersonCanReject(t *testing.T) {
	t.Parallel()
	e, fc := lineWorld(t)
	runCheck(t, e)
	if n := aiReadFindings(t, e, "nas-01"); n != 1 {
		t.Fatalf("%d open ai_read findings on nas-01, want 1", n)
	}
	var id, fixVersion, evidence string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT id, ifnull(fix_version, ''), evidence FROM fnd_finding WHERE cve = 'CVE-2026-82002' AND range_origin = 'ai_read'`).
		Scan(&id, &fixVersion, &evidence); err != nil {
		t.Fatal(err)
	}
	if fixVersion != "7.2.1-69057-6" || !strings.Contains(evidence, "Read by AI from www.synology.com") {
		t.Errorf("fix %q, evidence %s: want the quoted fix and the label", fixVersion, evidence)
	}
	v, err := e.svc.View(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	c := v.JSON().AICheck
	if c == nil || c.Reading == nil || c.Reading.Host == nil || *c.Reading.Host != "www.synology.com" || !c.Reading.QuoteFound {
		t.Fatalf("view ai_check %+v: want the reading with its host", c)
	}
	if _, err := e.svc.Possible(t.Context(), PossibleFilter{}, Page{Limit: PageMax}); err != nil {
		t.Fatal(err)
	}
	calls := len(fc.sent)
	if err := e.svc.RejectProposal(t.Context(), c.Key, "ana@example.com"); err != nil {
		t.Fatal(err)
	}
	if n := aiReadFindings(t, e, "nas-01"); n != 0 {
		t.Error("the rejected reading's finding is still detected")
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.ai_reading_rejected' AND target = '` + c.Key + `'`); n != 1 {
		t.Error("the rejection is not audited")
	}
	it, ok := possibleByCVE(t, e)["CVE-2026-82002"]
	if !ok || PossibleCause(it, e.svc.ReadState(t.Context())) != CauseNeedsPerson || it.Checkable() {
		t.Errorf("after the rejection: listed %v, item %+v; want possible, needs_person, not read again", ok, it)
	}
	runCheck(t, e)
	for _, req := range fc.sent[calls:] {
		if req.CVE == "CVE-2026-82002" {
			t.Error("the AI was asked again about the page a person rejected")
		}
	}
	if n := aiReadFindings(t, e, "nas-01"); n != 0 {
		t.Error("the rejected reading was applied again")
	}
	// a page changed by its next fetch is read again; the rejected reading stays stored next to the new one
	e.advance(31 * 24 * time.Hour)
	fc.pages["CVE-2026-82002"][0].Text = dsmFixedText + " Updated advisory."
	calls = len(fc.sent)
	runCheck(t, e)
	if !slices.ContainsFunc(fc.sent[calls:], func(r ProposeRequest) bool { return r.CVE == "CVE-2026-82002" }) {
		t.Fatal("the changed page was not read again")
	}
	if n := e.count(`SELECT count(*) FROM fnd_line_statement WHERE cve = 'CVE-2026-82002' AND rejected_by IS NOT NULL`); n != 1 {
		t.Errorf("%d rejected readings kept after a new reading of the line, want 1", n)
	}
}

// A bound the AI gives that its quote does not name decides nothing: a "fixed" whose release is not in the quote settles no version
// past it, even on the vendor's page for a CVE on no exploited list.
func TestLineReading_ABoundNotInTheQuoteSettlesNothing(t *testing.T) {
	t.Parallel()
	e, fc := lineWorld(t)
	e.feeds.unlisted = map[string]bool{"CVE-2026-82002": true}
	fc.tags = map[string][]string{dsmPageURL + "#82002": {"vendor-advisory"}}
	v := fc.verdicts["CVE-2026-82002|7.2.1-69057-5"]
	v.FixedIn = "7.2.1-69057-4" // not in the quote: the device would be past it
	fc.verdicts["CVE-2026-82002|7.2.1-69057-5"] = v
	runCheck(t, e)
	it := possibleByCVE(t, e)["CVE-2026-82002"]
	if it.State == PossibleSettled {
		t.Error("a fix release the quote does not name settled the CVE")
	}
	if n := e.count(`SELECT count(*) FROM fnd_line_statement WHERE cve = 'CVE-2026-82002' AND fixed_in IS NOT NULL`); n != 0 {
		t.Error("a bound the quote does not name was stored")
	}
}

// A reading speaks for its own release line and for the versions of the line its quote names, never for another line.
func TestLineStatement_ReadingForKeepsToItsLine(t *testing.T) {
	t.Parallel()
	sts := []LineStatement{{CVE: "CVE-2026-1", Product: "acme|widget", Line: "7.14.2", StatedLine: "7.14", Status: StatementFixed, FixedIn: "7.14.5",
		Quote: "Widget 7.14 is fixed in 7.14.5.", QuoteFound: true}}
	if r := readingFor(sts, "CVE-2026-1", CheckID{Product: "acme|widget", Line: "7.14.3", Version: "7.14.3"}); r.applied == nil {
		t.Error("a reading of 7.14 does not speak for 7.14.3")
	}
	for _, id := range []CheckID{{Product: "acme|widget", Line: "7.15.1", Version: "7.15.1"}, {Product: "acme|widget", Line: "7.1.4", Version: "7.1.4"},
		{Product: "acme|gadget", Line: "7.14.3", Version: "7.14.3"}} {
		if r := readingFor(sts, "CVE-2026-1", id); r.applied != nil {
			t.Errorf("a reading of 7.14 speaks for %s %s", id.Product, id.Version)
		}
	}
}

// A fix the AI gives that the quote does not name never becomes the finding's fix.
func TestLineReading_AFixNotInTheQuoteIsNoFix(t *testing.T) {
	t.Parallel()
	e, fc := lineWorld(t)
	fc.verdicts["CVE-2026-82002|7.2.1-69057-5"] = ProposeVerdict{Status: StatementAffected, FixedIn: "7.2.1-69057-9", Line: "7.2.1", Quote: "DSM 7.2.1 is affected", Source: 1}
	runCheck(t, e)
	if n := aiReadFindings(t, e, "nas-01"); n != 1 {
		t.Fatalf("%d findings, want the line named affected to open one", n)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE cve = 'CVE-2026-82002' AND fix_kind = 'unknown' AND fix_version IS NULL`); n != 1 {
		t.Error("a fix release the quote does not name became the fix")
	}
}

// An AI reading never settles "not affected" by itself: from the vendor's page or another one, on an exploited CVE or not, it is a
// proposal a person confirms or rejects (needs_person); an exploited CVE's is never offered in bulk.
func TestLineReading_NotAffectedOnlyFromTheVendorAndNeverAloneForAnExploitedCVE(t *testing.T) {
	t.Parallel()
	notAffected := ProposeVerdict{Status: StatementNotAffected, Line: "7.2", Quote: "DSM 7.2 is not affected by this issue", Source: 1}
	for _, tc := range []struct {
		name      string
		tags      []string
		exploited bool
		state     string
		cause     string
	}{
		{"third party", []string{"third-party-advisory"}, false, PossibleProposal, CauseNeedsPerson},
		{"vendor, not exploited", []string{"vendor-advisory"}, false, PossibleProposal, CauseNeedsPerson},
		{"vendor, exploited", []string{"vendor-advisory"}, true, PossibleProposal, CauseNeedsPerson},
	} {
		e, fc := possibleWorld(t)
		const blog = "https://blog.example.org/dsm"
		fc.pages["CVE-2026-82002"] = []FetchedPage{{URL: blog, Status: "ok", Text: "CVE-2026-82002. Synology DiskStation Manager (DSM). DSM 7.2 is not affected by this issue, which only concerns the new photo service."}}
		fc.tags = map[string][]string{blog: tc.tags}
		fc.verdicts["CVE-2026-82002|7.2.1-69057-5"] = notAffected
		if !tc.exploited {
			e.feeds.unlisted = map[string]bool{"CVE-2026-82002": true}
		}
		runCheck(t, e)
		it := possibleByCVE(t, e)["CVE-2026-82002"]
		if it.State != tc.state || PossibleCause(it, e.svc.ReadState(t.Context())) != tc.cause {
			t.Errorf("%s: state %s cause %q, want %s %q", tc.name, it.State, PossibleCause(it, e.svc.ReadState(t.Context())), tc.state, tc.cause)
		}
		if tc.exploited && it.Bulk() {
			t.Errorf("%s: an exploited CVE read not affected is offered for bulk confirmation", tc.name)
		}
	}
}

// One reading of a release line applies to every device and version on that line: a second device on DSM 7.2.1 with another release
// gets its finding from the stored reading at its match, without another AI call.
func TestLineReading_AppliesToASecondDeviceOnTheSameLine(t *testing.T) {
	t.Parallel()
	e, fc := lineWorld(t)
	runCheck(t, e)
	calls := len(fc.sent)
	twin := e.inv.match["nas-01"]
	twin.ID, twin.Name = "nas-02", "nas-02"
	twin.Software = slices.Clone(twin.Software)
	twin.Software[0].ID, twin.Software[0].Version = "s-nas-2", "7.2.1-69057-3"
	e.inv.match[twin.ID] = twin
	e.inv.assets[twin.ID] = AssetView{ID: twin.ID, Name: twin.ID, Hostname: ptr(twin.ID), IP: "192.0.2.91", Kind: "server", Approved: true}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := aiReadFindings(t, e, "nas-02"); n != 1 {
		t.Errorf("%d ai_read findings on the second device of the line, want 1", n)
	}
	runCheck(t, e)
	for _, req := range fc.sent[calls:] {
		if req.CVE == "CVE-2026-82002" {
			t.Error("the AI was asked again about a line it read")
		}
	}
}

// A reading stored by a check of one device applies at once to the other devices on the same line: they are matched again with it,
// so none of them shows the reading as a proposal waiting for a person.
func TestLineReading_ACheckOfOneDeviceAppliesToTheLineAtOnce(t *testing.T) {
	t.Parallel()
	e, _ := lineWorld(t)
	twin := e.inv.match["nas-01"]
	twin.ID, twin.Name = "nas-02", "nas-02"
	twin.Software = slices.Clone(twin.Software)
	twin.Software[0].ID, twin.Software[0].Version = "s-nas-2", "7.2.1-69057-3"
	e.inv.match[twin.ID] = twin
	e.inv.assets[twin.ID] = AssetView{ID: twin.ID, Name: twin.ID, Hostname: ptr(twin.ID), IP: "192.0.2.91", Kind: "server", Approved: true}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	items, err := e.svc.possibleItems(t.Context(), "nas-01")
	if err != nil {
		t.Fatal(err)
	}
	e.svc.check.run = &CheckRun{Running: true}
	e.svc.runPossibleCheck(t.Context(), e.svc.unitsToCheck(t.Context(), items), "ana@example.com")
	if n := aiReadFindings(t, e, "nas-01"); n != 1 {
		t.Fatalf("%d ai_read findings on the checked device, want 1", n)
	}
	if n := aiReadFindings(t, e, "nas-02"); n != 1 {
		t.Errorf("%d ai_read findings on the other device of the line right after the check, want 1", n)
	}
}

// A re-read of the CVE record keeps the reading while its quote is still on its page (its record identity moves on, no tokens; the
// quote leaving the page: TestResearch_SurvivesARecordReReadOnlyWithItsQuote); a page unchanged after 30 days is fetched (no tokens) and
// not asked again; a changed page is asked again. Only the newest reading of the line is kept.
func TestLineReading_ReadAgainWhenTheRecordOrThePageChanges(t *testing.T) {
	t.Parallel()
	e, fc := lineWorld(t)
	runCheck(t, e)
	asked := func(from int) bool {
		return slices.ContainsFunc(fc.sent[from:], func(r ProposeRequest) bool { return r.CVE == "CVE-2026-82002" })
	}
	// 31 days, the same page: fetched, not asked; the finding stays
	e.advance(31 * 24 * time.Hour)
	if !possibleItemDue(t, e) {
		t.Fatal("a reading 31 days old is not due for a fetch")
	}
	calls := len(fc.sent)
	runCheck(t, e)
	if asked(calls) || possibleItemDue(t, e) || aiReadFindings(t, e, "nas-01") != 1 {
		t.Errorf("an unchanged page: asked %v, still due %v; want a fetch only", asked(calls), possibleItemDue(t, e))
	}
	// the record changes: due again, but the quote is still on the page: kept, not asked, its record identity moved on
	restamp := func(stamp string) {
		for i := range e.feeds.vulns {
			if e.feeds.vulns[i].CVE == "CVE-2026-82002" {
				e.feeds.vulns[i].Stamp = stamp
			}
		}
		if _, err := e.svc.Reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	restamp("changed")
	if aiReadFindings(t, e, "nas-01") != 1 || !possibleItemDue(t, e) {
		t.Fatal("a record change dropped the finding or is not due")
	}
	calls = len(fc.sent)
	runCheck(t, e)
	if asked(calls) || possibleItemDue(t, e) || aiReadFindings(t, e, "nas-01") != 1 {
		t.Errorf("a record re-read with the quote still on the page: asked %v, still due %v; want the reading kept", asked(calls), possibleItemDue(t, e))
	}

	// 31 days, a changed page: asked again
	e.advance(31 * 24 * time.Hour)
	fc.pages["CVE-2026-82002"][0].Text = dsmFixedText + " Updated advisory."
	if !possibleItemDue(t, e) {
		t.Fatal("a reading 31 days old is not due after the record's reading")
	}
	calls = len(fc.sent)
	runCheck(t, e)
	if !asked(calls) {
		t.Error("the AI was not asked again after the page changed")
	}
	if n := e.count(`SELECT count(*) FROM fnd_line_statement WHERE cve = 'CVE-2026-82002'`); n != 1 {
		t.Errorf("%d readings kept, want the newest only", n)
	}
}

// possibleItemDue says the reading behind nas-01's finding of 82002 is due again, as the match notes it.
func possibleItemDue(t *testing.T, e *env) bool {
	t.Helper()
	e.svc.stamps.drop("nas-01")
	if _, err := e.svc.OnMatchChanged(t.Context(), "nas-01"); err != nil {
		t.Fatal(err)
	}
	e.svc.check.mu.Lock()
	defer e.svc.check.mu.Unlock()
	for _, u := range e.svc.check.due {
		if u.cve == "CVE-2026-82002" {
			return true
		}
	}
	return false
}

// The cause names what holds a CVE: no AI set up (needs_reading), the reading's budget used up (ai_budget).
func TestLineReading_CauseWithoutAIAndWithTheBudgetUsedUp(t *testing.T) {
	t.Parallel()
	e, fc := lineWorld(t)
	fc.ready = errors.New("no AI profile")
	if c := possibleCauseOf(t, e, "CVE-2026-82002"); c != CauseNeedsReading {
		t.Errorf("no AI: cause %q, want %s", c, CauseNeedsReading)
	}
	fc.ready = nil
	fc.budget = ReadBudget{Auto: true, Reached: true}
	if c := possibleCauseOf(t, e, "CVE-2026-82002"); c != CauseAIBudget {
		t.Errorf("budget used up: cause %q, want %s", c, CauseAIBudget)
	}
	if e.svc.AutoRead(t.Context()) {
		t.Error("the automatic reading started with its budget used up")
	}
	list, err := e.svc.Possible(t.Context(), PossibleFilter{}, Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	if list.Counts.Causes[CauseAIBudget] == 0 {
		t.Errorf("counts by cause %v: no ai_budget", list.Counts.Causes)
	}
}

// Every possible row carries one cause of the closed list, with no AI set up: the residue of the fixture names each.
func TestPossibleCause_EveryPossibleRowHasOne(t *testing.T) {
	t.Parallel()
	e, _ := residueWorld(t)
	items, err := e.svc.possibleItems(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]int{}
	for _, it := range items {
		c := PossibleCause(it, e.svc.ReadState(t.Context()))
		if it.State == PossibleSettled {
			continue
		}
		if !slices.Contains(PossibleCauses, c) {
			t.Errorf("%s on %s (%s, %+v): cause %q, want one of the list", it.CVE, it.Question.AssetID, it.Question.Kind, it.Question.Detail.Undecided, c)
		}
		by[c]++
	}
	t.Logf("possible CVEs by cause: %v", by)
	if by[CauseNeedsReading] == 0 {
		t.Error("with no AI, no row needs reading")
	}
}

// The automatic reading runs after a match pass only while the AI settings have it on, and reads what is due.
func TestAutoRead_RunsOnlyWhenSwitchedOn(t *testing.T) {
	t.Parallel()
	e, fc := lineWorld(t)
	fc.budget = ReadBudget{Auto: false}
	if e.svc.AutoRead(t.Context()) {
		t.Fatal("the automatic reading started while switched off")
	}
	fc.budget = ReadBudget{Auto: true}
	if !e.svc.AutoRead(t.Context()) {
		t.Fatal("the automatic reading did not start")
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		run, _ := e.svc.CheckStatus(t.Context())
		if run != nil && !run.Running {
			if run.By != SystemUser || run.Readings == 0 {
				t.Errorf("run %+v: want the system's run with a reading", run)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the automatic reading did not finish")
		}
		runtime.Gosched()
	}
	if aiReadFindings(t, e, "nas-01") != 1 {
		t.Error("the automatic reading's affected line opened no finding")
	}
}

// What a reading says for one version, from the stated bounds and the quote alone.
func TestLineStatement_VerdictFor(t *testing.T) {
	t.Parallel()
	id := CheckID{Product: "acme|widget", Line: "3.4.1", Version: "3.4.1"}
	for _, tc := range []struct {
		name string
		st   LineStatement
		want string
	}{
		{"inside the stated fix", LineStatement{Status: StatementFixed, FixedIn: "3.4.5", Quote: "Fixed in 3.4.5.", QuoteFound: true}, VerdictAffected},
		{"before X, past it", LineStatement{Status: StatementFixed, FixedIn: "3.4.0", Quote: "All versions before 3.4.0 are affected.", QuoteFound: true}, VerdictNotAffected},
		{"before X of another train", LineStatement{Status: StatementFixed, FixedIn: "3.3.5", Quote: "Widget 3.3 before 3.3.5 and 3.4 before 3.4.3 are affected.",
			QuoteFound: true}, ""},
		{"past a fix of no named line", LineStatement{Status: StatementFixed, FixedIn: "3.4.0", Quote: "Upgrade to 3.4.0.", QuoteFound: true}, ""},
		{"past the fix on the stated line", LineStatement{Status: StatementFixed, FixedIn: "3.4.0", StatedLine: "3.4", Quote: "Release 3.4 is fixed in 3.4.0.", QuoteFound: true}, VerdictNotAffected},
		{"line named not affected", LineStatement{Status: StatementNotAffected, StatedLine: "3.4", Quote: "Widget 3.4 is not affected.", QuoteFound: true}, VerdictNotAffected},
		{"another line named not affected", LineStatement{Status: StatementNotAffected, StatedLine: "3.5", Quote: "Widget 3.5 is not affected.", QuoteFound: true}, ""},
		{"stated line not in the quote", LineStatement{Status: StatementNotAffected, StatedLine: "3.4", Quote: "This release is not affected.", QuoteFound: true}, ""},
		{"quote not found", LineStatement{Status: StatementAffected, StatedLine: "3.4", Quote: "Widget 3.4 is affected.", QuoteFound: false}, ""},
		{"affected range ends before the version", LineStatement{Status: StatementAffected, Introduced: "3.0", Last: "3.3.9", Quote: "3.0 through 3.3.9", QuoteFound: true}, ""},
		{"unsure", LineStatement{Status: StatementUnsure, Quote: "Widget 3.4.1", QuoteFound: true}, ""},
		{"inferred, the line named by a later release of it", LineStatement{Status: StatementAffected, Basis: BasisInferred, StatedLine: "3",
			Quote: "Fixed in Gadget 3.9 and Widget 4.2.", QuoteFound: true}, VerdictAffected},
		{"inferred, the line named by an earlier release of it", LineStatement{Status: StatementAffected, Basis: BasisInferred, StatedLine: "3",
			Quote: "Fixed in Gadget 3.2 and Widget 4.2.", QuoteFound: true}, ""},
		{"inferred, a release of another line", LineStatement{Status: StatementAffected, Basis: BasisInferred, StatedLine: "3", Quote: "Fixed in Gadget 4.9.",
			QuoteFound: true}, ""},
		{"a fix the quote does not name settles nothing", LineStatement{Status: StatementFixed, FixedIn: "3.4.0", StatedLine: "3.4",
			Quote: "Release 3.4 is affected.", QuoteFound: true}, ""},
	} {
		if got := tc.st.verdictFor(id); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if !dottedPrefix("8.6", "8.6.5") || dottedPrefix("8.6", "8.60") || dottedPrefix("1", "10.2") {
		t.Error("dottedPrefix")
	}
	// a hotfix of the fixed release is past the fix too: 3.4.1.2 is on the train of 3.4.1 (its first parts are 3.4)
	hotfix := CheckID{Product: "acme|widget", Line: "3.4.1.2", Version: "3.4.1.2"}
	if got := (LineStatement{Status: StatementFixed, FixedIn: "3.4.1", Quote: "All versions before 3.4.1 are affected.", QuoteFound: true}).verdictFor(hotfix); got != VerdictNotAffected {
		t.Errorf("a hotfix past the fix: %q, want %q", got, VerdictNotAffected)
	}
}

// A reading decides only from a page about this CVE: one that names the CVE, or names an advisory the CVE record itself references
// (Synology-SA-26:01 for a reference .../Synology_SA_26_01). A vendor's page that names neither (a release note, the product's page of
// every advisory) decides nothing either way: the CVE stays possible, ai_unsure.
func TestLineReading_APageThatNamesNeitherTheCVENorItsAdvisoryDecidesNothing(t *testing.T) {
	t.Parallel()
	const fixed = "Synology DiskStation Manager (DSM). DSM 7.2.1 is affected; the fix is in DSM 7.2.1-69057-6 and later."
	notAffected := ProposeVerdict{Status: StatementNotAffected, Line: "7.2.1", Quote: "DSM 7.2.1 is not affected.", Source: 1}
	for _, tc := range []struct {
		name    string
		text    string
		verdict *ProposeVerdict // nil: the fix of lineWorld
		finding int
		state   string
		cause   string
	}{
		{"affected, the CVE named", dsmFixedText, nil, 1, "", ""},
		{"affected, the referenced advisory named", "Synology-SA-26:01 " + fixed, nil, 1, "", ""},
		{"affected, neither named", fixed, nil, 0, PossibleOpen, CauseAIUnsure},
		{"affected, another advisory named", "Synology-SA-25:09 " + fixed, nil, 0, PossibleOpen, CauseAIUnsure},
		{"affected, another CVE named", "CVE-2026-82001. " + fixed, nil, 0, PossibleOpen, CauseAIUnsure},
		{"not affected, the CVE named", "CVE-2026-82002. Synology DiskStation Manager (DSM). DSM 7.2.1 is not affected.", &notAffected, 0, PossibleProposal, CauseNeedsPerson},
		{"not affected, neither named", "Synology DiskStation Manager (DSM). DSM 7.2.1 is not affected.", &notAffected, 0, PossibleOpen, CauseAIUnsure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, fc := lineWorld(t)
			e.feeds.unlisted = map[string]bool{"CVE-2026-82002": true}
			fc.pages["CVE-2026-82002"][0].Text = tc.text
			if tc.verdict != nil {
				fc.verdicts["CVE-2026-82002|7.2.1-69057-5"] = *tc.verdict
			}
			runCheck(t, e)
			if n := aiReadFindings(t, e, "nas-01"); n != tc.finding {
				t.Errorf("%d findings, want %d", n, tc.finding)
			}
			if tc.state == "" {
				return
			}
			it := possibleByCVE(t, e)["CVE-2026-82002"]
			if c := PossibleCause(it, e.svc.ReadState(t.Context())); it.State != tc.state || c != tc.cause {
				t.Errorf("state %s cause %q, want %s %q", it.State, c, tc.state, tc.cause)
			}
		})
	}
}

// The advisory ids a reference's address carries: one id token per path part or query value, with letters and digits; a version, a
// year, a word or a file name is none.
func TestAboutCVE_AdvisoryIDsOfAReference(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string][]string{
		"https://www.fortiguard.com/psirt/FG-IR-24-015":                        {"fgir24015"},
		"https://www.vmware.com/security/advisories/VMSA-2024-0001.html":       {"vmsa20240001"},
		"https://kb.example.com/article?id=SA44312":                            {"sa44312"},
		"https://docs.example.com/fortios/7.4.3/release-notes/2024/index.html": nil,
		"https://example.com/security/advisories":                              nil,
	} {
		if got := advisoryIDsOf(raw); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", raw, got, want)
		}
	}
	refs := []RefLink{{URL: "https://www.fortiguard.com/psirt/FG-IR-24-015"}}
	if !aboutCVE("Advisory FG-IR-24-015: FortiOS 7.4 before 7.4.3.", "CVE-2024-1", refs) || aboutCVE("Advisory FG-IR-24-0150: FortiOS 7.4.", "CVE-2024-1", refs) {
		t.Error("aboutCVE does not match the referenced advisory id as a whole token")
	}
}

// A fix release the quote states ("before X" on the version's own train) is the finding's fix even when the AI gave no fixed_in, but only
// from a reading whose every release follows the product's own name (basis stated): "DSM 7.2.1 versions before 7.2.1-69057-6" names
// no product before 7.2.1-69057-6, so the finding opens with no fix. A version at or past that X is not inside what the sentence calls
// affected, so the reading opens no finding for it.
func TestLineReading_TheQuotedFixIsTheFix(t *testing.T) {
	t.Parallel()
	const quote = "DSM 7.2.1 versions before 7.2.1-69057-6 are affected."
	affected := ProposeVerdict{Status: StatementAffected, Line: "7.2.1", Quote: quote, Source: 1}
	e, fc := lineWorld(t)
	fc.pages["CVE-2026-82002"][0].Text = "CVE-2026-82002: " + quote // names DSM only: the box's own reader leaves it to the AI
	fc.verdicts["CVE-2026-82002|7.2.1-69057-5"] = affected
	runCheck(t, e)
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE cve = 'CVE-2026-82002' AND range_origin = 'ai_read' AND fix_kind = 'unknown'`); n != 1 {
		t.Errorf("%d findings opened with no fix, want 1", n)
	}
	id := CheckID{Product: "synology|diskstation manager", Line: "7.2.1", Version: "7.2.1-69057-5"}
	st := LineStatement{Status: StatementAffected, Basis: BasisStated, StatedLine: "7.2.1", Quote: quote, QuoteFound: true}
	if f := st.fix(id); f.Version != "7.2.1-69057-6" {
		t.Errorf("a stated reading's quoted fix %+v, want 7.2.1-69057-6", f)
	}
	past := CheckID{Product: "synology|diskstation manager", Line: "7.2.1", Version: "7.2.1-69057-7"}
	if v := st.verdictFor(past); v != "" {
		t.Errorf("a version past the quoted fix: %q, want nothing decided", v)
	}
}

// autoReadToEnd starts the automatic reading and waits for its run to finish.
func autoReadToEnd(t *testing.T, e *env) CheckRun {
	t.Helper()
	if !e.svc.AutoRead(t.Context()) {
		t.Fatal("the automatic reading did not start")
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if run, _ := e.svc.CheckStatus(t.Context()); run != nil && !run.Running {
			return *run
		}
		if time.Now().After(deadline) {
			t.Fatal("the automatic reading did not finish")
		}
		runtime.Gosched()
	}
}

func sentFor(fc *fakeChecker, cve string) int {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	n := 0
	for _, r := range fc.sent {
		if r.CVE == cve {
			n++
		}
	}
	return n
}

// One item whose call is refused (a hook stopped its text, the answer was unusable) does not stop the reading: the next CVE is read in
// the same run, the refused one is left by the automatic reading until its retry time (it is not first again at the next run), and a
// person's check reads it at once. On a real box one reference page refused by a hook stopped every hourly run at the same CVE.
func TestAutoRead_ARefusedItemDoesNotStopTheNext(t *testing.T) {
	t.Parallel()
	e, fc := possibleWorld(t)
	fc.pages["CVE-2026-82003"] = []FetchedPage{{URL: dsmPageURL + "#82003", Status: "ok", Text: "CVE-2026-82003 concerns Synology DiskStation Manager (DSM) 7.2; see the release notes."}}
	fc.refuse = map[string]error{"CVE-2026-82002": &ItemRefused{Reason: "The AI was not asked: a hook stopped the data sent with it.", RetryAfter: 24 * time.Hour}}
	run := autoReadToEnd(t, e)
	if run.Stopped != nil || run.Failed == 0 || run.Readings == 0 {
		t.Fatalf("run %+v: want it to go past the refused item, read the next and count the refused one", run)
	}
	if sentFor(fc, "CVE-2026-82002") != 1 || sentFor(fc, "CVE-2026-82003") != 1 {
		t.Fatalf("calls: 82002 %d, 82003 %d; want one each", sentFor(fc, "CVE-2026-82002"), sentFor(fc, "CVE-2026-82003"))
	}
	// the next automatic run leaves the refused item until its retry time: nothing else is due, so no run starts
	if e.svc.AutoRead(t.Context()) {
		autoReadToEnd(t, e)
	}
	if n := sentFor(fc, "CVE-2026-82002"); n != 1 {
		t.Errorf("the refused item was asked %d times, want it left until its retry time", n)
	}
	// a person's check reads it at once, and an answer clears the hold
	fc.refuse = nil
	runCheck(t, e)
	if n := sentFor(fc, "CVE-2026-82002"); n != 2 {
		t.Errorf("a person's check did not read the refused item (%d calls)", n)
	}
	if len(e.svc.check.held) != 0 {
		t.Errorf("held after an answer: %v", e.svc.check.held)
	}
}

// A held item says on its row until when the automatic reading leaves it and why, as a label of a closed list (never the provider's
// words); an answer clears it.
func TestPossible_AHeldItemSaysUntilWhenAndWhy(t *testing.T) {
	t.Parallel()
	e, fc := possibleWorld(t)
	fc.pages["CVE-2026-82003"] = []FetchedPage{{URL: dsmPageURL + "#82003", Status: "ok", Text: "CVE-2026-82003 concerns Synology DiskStation Manager (DSM) 7.2; see the release notes."}}
	fc.refuse = map[string]error{"CVE-2026-82002": &ItemRefused{Reason: "The AI answered, but not in the format Vedette needs (HTTP 502 from upstream).", RetryAfter: 24 * time.Hour, Systemic: true}}
	autoReadToEnd(t, e)
	heldOf := func() map[string]*HeldJS {
		list, err := e.svc.Possible(t.Context(), PossibleFilter{}, Page{Limit: PageMax})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]*HeldJS{}
		for _, r := range list.Items {
			out[r.CVE] = r.Held
		}
		return out
	}
	held := heldOf()
	h := held["CVE-2026-82002"]
	if h == nil || h.Reason != HeldAnswerUnusable || h.Until != store.FormatTS(e.svc.now().Add(24*time.Hour)) {
		t.Fatalf("held %+v, want answer_unusable until a day from now", h)
	}
	if held["CVE-2026-82003"] != nil {
		t.Errorf("a CVE that was read is held: %+v", held["CVE-2026-82003"])
	}
	// the line says when the automatic reading reads it again: while that reading cannot run (switched off, today's reads used up, no
	// profile), it would promise a reading that does not come, so the row keeps its cause's own sentence instead
	for _, c := range []struct {
		name   string
		budget ReadBudget
		ready  error
	}{{"switched off", ReadBudget{}, nil}, {"reads used up", ReadBudget{Auto: true, Reached: true}, nil},
		{"no profile", ReadBudget{Auto: true}, errors.New("no profile for explaining findings")}} {
		fc.budget, fc.ready = c.budget, c.ready
		if h := heldOf()["CVE-2026-82002"]; h != nil {
			t.Errorf("%s: the row still says the automatic reading reads it again: %+v", c.name, h)
		}
	}
	fc.budget, fc.ready = ReadBudget{Auto: true}, nil
	fc.refuse = nil
	runCheck(t, e)
	if h := heldOf()["CVE-2026-82002"]; h != nil {
		t.Errorf("still held after an answer: %+v", h)
	}
}

// A call that fails for a reason Propose does not name (the provider answered an error) is that item's failure too, left for the next
// run; only aiFailStreak such failures in a row stop the run, since the AI then answers nothing at all.
func TestPossibleCheck_TheAIFailingInARowStopsTheRun(t *testing.T) {
	t.Parallel()
	e, fc := possibleWorld(t)
	var units []checkUnit
	fc.refuse = map[string]error{}
	for i := range 5 {
		cve := fmt.Sprintf("CVE-2026-9100%d", i)
		fc.pages[cve] = []FetchedPage{{URL: dsmPageURL + "#" + cve, Status: "ok", Text: cve + " concerns Synology DiskStation Manager (DSM) 7.2."}}
		fc.refuse[cve] = errors.New("the AI provider returned an error (HTTP 500)")
		units = append(units, checkUnit{key: "k-" + cve, cve: cve, id: CheckID{Product: "synology|diskstation_manager", Line: "7.2.1", Version: "7.2.1-69057-5", Record: "r"},
			devs: []string{"nas-01"}})
	}
	e.svc.check.run = &CheckRun{Running: true}
	e.svc.runPossibleCheck(t.Context(), units, SystemUser)
	run := *e.svc.check.run
	if run.Stopped == nil || !strings.Contains(*run.Stopped, "in a row") || len(fc.sent) != aiFailStreak {
		t.Fatalf("run %+v after %d calls: want it stopped after %d failures in a row", run, len(fc.sent), aiFailStreak)
	}
	if h, ok := e.svc.check.held["k-CVE-2026-91000"]; !ok || h.reason == "" || !h.until.After(e.svc.now()) {
		t.Errorf("the failed item is not held with its reason and retry time: %+v", h)
	}
}

// An answer the box cannot use (outside the schema, cut off) is held per item like a hook's refusal, but several in a row mean the
// provider cannot do the reading at all: aiFailStreak of them stop the run, so a model that cannot answer in the schema does not spend
// every read left of the day in one run. A hook's refusal is about the item's text and never stops it.
func TestPossibleCheck_UnusableAnswersInARowStopTheRun(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name     string
		systemic bool
		calls    int
	}{{"unusable answers", true, aiFailStreak}, {"hook refusals", false, 5}} {
		t.Run(c.name, func(t *testing.T) {
			e, fc := possibleWorld(t)
			var units []checkUnit
			fc.refuse = map[string]error{}
			for i := range 5 {
				cve := fmt.Sprintf("CVE-2026-9120%d", i)
				fc.pages[cve] = []FetchedPage{{URL: dsmPageURL + "#" + cve, Status: "ok", Text: cve + " concerns Synology DiskStation Manager (DSM) 7.2."}}
				fc.refuse[cve] = &ItemRefused{Reason: "The AI answered, but not in the format Vedette needs.", RetryAfter: 24 * time.Hour, Systemic: c.systemic}
				units = append(units, checkUnit{key: "k-" + cve, cve: cve, id: CheckID{Product: "synology|diskstation_manager", Line: "7.2.1", Version: "7.2.1-69057-5", Record: "r"},
					devs: []string{"nas-01"}})
			}
			e.svc.check.run = &CheckRun{Running: true}
			e.svc.runPossibleCheck(t.Context(), units, SystemUser)
			run := *e.svc.check.run
			if len(fc.sent) != c.calls || (run.Stopped != nil) != c.systemic {
				t.Fatalf("run %+v after %d calls: want %d calls, stopped %v", run, len(fc.sent), c.calls, c.systemic)
			}
			if h, ok := e.svc.check.held["k-CVE-2026-91200"]; !ok || h.until.Before(e.svc.now().Add(24*time.Hour)) {
				t.Errorf("the refused item is not held for a day: %+v", h)
			}
		})
	}
}

// The streak counts calls, not CVEs: a CVE with more release lines than one call carries (possibleCheckItems a call) makes several calls,
// and when the AI answers none of them the run stops after aiFailStreak calls, not after every call of that CVE.
func TestPossibleCheck_TheAIFailingInARowStopsWithinOneCVE(t *testing.T) {
	t.Parallel()
	e, fc := possibleWorld(t)
	const cve = "CVE-2026-91100"
	fc.pages[cve] = []FetchedPage{{URL: dsmPageURL + "#" + cve, Status: "ok", Text: cve + " concerns Synology DiskStation Manager (DSM)."}}
	fc.refuse = map[string]error{cve: errors.New("the AI provider returned an error (HTTP 500)")}
	var units []checkUnit
	for i := range (aiFailStreak + 2) * possibleCheckItems {
		line := fmt.Sprintf("7.%d", i)
		units = append(units, checkUnit{key: "k-" + line, cve: cve, id: CheckID{Product: "synology|diskstation_manager", Line: line, Version: line + ".1-69057-5", Record: "r"},
			devs: []string{"nas-01"}})
	}
	e.svc.check.run = &CheckRun{Running: true}
	e.svc.runPossibleCheck(t.Context(), units, SystemUser)
	run := *e.svc.check.run
	if run.Stopped == nil || !strings.Contains(*run.Stopped, "in a row") || len(fc.sent) != aiFailStreak {
		t.Fatalf("run %+v after %d calls: want it stopped after %d failures in a row", run, len(fc.sent), aiFailStreak)
	}
	if run.Failed != len(units) {
		t.Errorf("failed %d of %d units: every unit the stop left is not checked", run.Failed, len(units))
	}
}

// A reading the AI inferred from another product's release line (basis inferred) is decided from that basis, not from its quote: it
// never gives a fix, even when its quote states "before X" on the version's own train, and its "not affected" is a proposal a person
// confirms, never settled.
func TestLineStatement_AnInferredReadingIsNeverAFix(t *testing.T) {
	t.Parallel()
	id := CheckID{Product: "acme|mail", Line: "115.9.0", Version: "115.9.0"}
	st := LineStatement{Status: StatementAffected, Basis: BasisInferred, StatedLine: "115", Quote: "Acme Browser ESR 115 versions before 115.42 are affected.", QuoteFound: true}
	if got := st.verdictFor(id); got != VerdictAffected {
		t.Errorf("inferred affected: %q, want %q", got, VerdictAffected)
	}
	if f := st.fix(id); f.Kind != FixUnknown {
		t.Errorf("inferred reading's fix %+v, want none", f)
	}
	stated := st
	stated.Basis = BasisStated
	if f := stated.fix(id); f.Kind != FixUpdate || f.Version != "115.42" {
		t.Errorf("the same quote stated for this product: fix %+v, want 115.42", f)
	}
	na := LineStatement{Status: StatementNotAffected, Basis: BasisInferred, StatedLine: "115", Quote: "Acme Mail 115 is not affected.", QuoteFound: true, VendorPage: true}
	if c := na.asCheck(id); c.Verdict != VerdictNotAffected || !c.Proposal() || c.Settled() {
		t.Errorf("inferred not affected: %+v, want a proposal for a person, never settled", c)
	}
	fixed := LineStatement{Status: StatementFixed, Basis: BasisInferred, FixedIn: "115.2", StatedLine: "115", Quote: "Release 115 is fixed in 115.2.", QuoteFound: true, VendorPage: true}
	if got := fixed.verdictFor(id); got != "" {
		t.Errorf("inferred fixed: %q, want nothing", got)
	}
	// a stated reading names its line only through its own words: a release of the line in the quote is no naming of it
	if got := (LineStatement{Status: StatementAffected, StatedLine: "115", Quote: "Fixed in 115.42.", QuoteFound: true}).verdictFor(id); got != "" {
		t.Errorf("stated, the line named by a release only: %q, want nothing", got)
	}
}
