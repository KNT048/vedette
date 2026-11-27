package findings

import (
	"errors"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
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

// "Not affected" read from a page that is not the vendor's settles nothing: the CVE stays possible (vendor_silent). From the vendor's
// page it settles a CVE on no exploited list, and an exploited one waits for a person (needs_person, never in bulk).
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
		{"third party", []string{"third-party-advisory"}, false, PossibleOpen, CauseVendorSilent},
		{"vendor, not exploited", []string{"vendor-advisory"}, false, PossibleSettled, ""},
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

// A reading is read again when the CVE record changes (the reading keeps applying until then); a page unchanged after 30 days is
// fetched (no tokens) and not asked again; a changed page is asked again. Only the newest reading of the line is kept.
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
	// the record changes: due again, asked again; the finding stands meanwhile
	for i := range e.feeds.vulns {
		if e.feeds.vulns[i].CVE == "CVE-2026-82002" {
			e.feeds.vulns[i].Stamp = "changed"
		}
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if aiReadFindings(t, e, "nas-01") != 1 || !possibleItemDue(t, e) {
		t.Fatal("a record change dropped the finding or is not due")
	}
	calls = len(fc.sent)
	runCheck(t, e)
	if !asked(calls) {
		t.Error("the AI was not asked again after the record changed")
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
		{"not affected, the CVE named", "CVE-2026-82002. Synology DiskStation Manager (DSM). DSM 7.2.1 is not affected.", &notAffected, 0, PossibleSettled, ""},
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

// A fix release the quote states ("before X" on the version's own train) is the finding's fix even when the AI gave no fixed_in; a
// version at or past that X is not inside what the sentence calls affected, so the reading opens no finding for it.
func TestLineReading_TheQuotedFixIsTheFix(t *testing.T) {
	t.Parallel()
	const quote = "DSM 7.2.1 versions before 7.2.1-69057-6 are affected."
	affected := ProposeVerdict{Status: StatementAffected, Line: "7.2.1", Quote: quote, Source: 1}
	e, fc := lineWorld(t)
	fc.pages["CVE-2026-82002"][0].Text = "CVE-2026-82002: " + quote // names DSM only: the box's own reader leaves it to the AI
	fc.verdicts["CVE-2026-82002|7.2.1-69057-5"] = affected
	runCheck(t, e)
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE cve = 'CVE-2026-82002' AND range_origin = 'ai_read' AND fix_kind = 'update' AND fix_version = '7.2.1-69057-6'`); n != 1 {
		t.Errorf("%d findings with the quoted fix 7.2.1-69057-6, want 1", n)
	}
	past := CheckID{Product: "synology|diskstation manager", Line: "7.2.1", Version: "7.2.1-69057-7"}
	st := LineStatement{Status: StatementAffected, StatedLine: "7.2.1", Quote: quote, QuoteFound: true}
	if v := st.verdictFor(past); v != "" {
		t.Errorf("a version past the quoted fix: %q, want nothing decided", v)
	}
}
