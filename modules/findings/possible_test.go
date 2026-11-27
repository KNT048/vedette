package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeChecker is a PossibleChecker that serves fixed pages and fixed AI verdicts, and records what each AI call was sent.
type fakeChecker struct {
	mu       sync.Mutex
	ready    error
	pages    map[string][]FetchedPage  // by CVE
	verdicts map[string]ProposeVerdict // by CVE + "|" + version: what the AI answers
	stop     *CheckStop
	sent     []ProposeRequest
	tags     map[string][]string // a reference's tags by its address; unset: vendor-advisory (the catalogue's words)
	budget   ReadBudget
}

func (f *fakeChecker) Ready(context.Context) error { return f.ready }

func (f *fakeChecker) Budget(context.Context) ReadBudget { return f.budget }

func (f *fakeChecker) Record(_ context.Context, cve string) (CVERecordText, error) {
	var refs []RefLink
	for _, p := range f.pages[cve] {
		tags, ok := f.tags[p.URL]
		if !ok {
			tags = []string{"vendor-advisory"}
		}
		refs = append(refs, RefLink{URL: p.URL, Tags: tags})
	}
	return CVERecordText{Description: "A flaw in Synology DiskStation Manager.", Refs: refs}, nil
}

func (f *fakeChecker) Fetch(_ context.Context, urls []string) []FetchedPage {
	var out []FetchedPage
	for _, ps := range f.pages {
		for _, p := range ps {
			if slices.Contains(urls, p.URL) {
				out = append(out, p)
			}
		}
	}
	return out
}

func (f *fakeChecker) Propose(_ context.Context, _ string, req ProposeRequest) (ProposeAnswer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, req)
	if f.stop != nil {
		return ProposeAnswer{}, f.stop
	}
	ans := ProposeAnswer{Model: "test-model", Profile: "test", ActivityID: "act-1"}
	for _, it := range req.Items {
		v, ok := f.verdicts[req.CVE+"|"+it.Version]
		if !ok {
			continue
		}
		v.Index = it.Index
		ans.Verdicts = append(ans.Verdicts, v)
	}
	return ans, nil
}

const dsmPageURL = "https://www.synology.com/en-global/security/advisory/Synology_SA_26_01"

// possibleWorld is residueWorld (nas-01 runs DSM 7.2.1-69057-5; CVE-2026-82001..82003 name fixes only on newer DSM lines) with a
// checker: the vendor's advisory states 82001's range for 7.2.1 in words the box reads; 82002's page names DSM without a range the box
// reads, and the AI proposes "not affected" quoting it; 82003's AI answer is unsure.
func possibleWorld(t *testing.T) (*env, *fakeChecker) {
	t.Helper()
	e, _ := residueWorld(t)
	fc := &fakeChecker{
		budget: ReadBudget{Auto: true},
		pages: map[string][]FetchedPage{
			"CVE-2026-82001": {{URL: dsmPageURL + "#82001", Status: "ok", Text: "CVE-2026-82001. Affected products: Synology DiskStation Manager (DSM).\n7.2.1 versions before 7.2.1-69057-6 are affected. Upgrade to 7.2.1-69057-6 or above."}},
			"CVE-2026-82002": {{URL: dsmPageURL + "#82002", Status: "ok", Text: "CVE-2026-82002. Synology DiskStation Manager (DSM). DSM 7.2 is not affected by this issue, which only concerns the new photo service."}},
			"CVE-2026-82003": {{URL: dsmPageURL + "#82003", Status: "failed", Note: "the site answered 403"}},
		},
		verdicts: map[string]ProposeVerdict{
			"CVE-2026-82002|7.2.1-69057-5": {Status: StatementNotAffected, Line: "7.2", Reason: "DSM 7.2 is not affected.", Quote: "DSM 7.2 is not affected by this issue", Source: 1},
			"CVE-2026-82003|7.2.1-69057-5": {Status: StatementUnsure, Reason: "The advisory could not be read."},
		},
	}
	e.svc.SetChecker(fc)
	return e, fc
}

// runCheck runs one check of every checkable possible CVE to its end (the background run, called in the test's goroutine).
func runCheck(t *testing.T, e *env) CheckRun {
	t.Helper()
	items, err := e.svc.possibleItems(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	e.svc.check.run = &CheckRun{Running: true}
	e.svc.runPossibleCheck(t.Context(), e.svc.unitsToCheck(t.Context(), items), "ana@example.com")
	return *e.svc.check.run
}

func possibleByCVE(t *testing.T, e *env) map[string]PossibleItem {
	t.Helper()
	items, err := e.svc.possibleItems(t.Context(), "nas-01")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]PossibleItem{}
	for _, it := range items {
		out[it.CVE] = it
	}
	return out
}

// Every possible CVE says machine-readably why it is undecided, from the closed list; the counts of the list and of Home agree.
func TestPossible_Count_EveryPossibleCVEHasAReason(t *testing.T) {
	t.Parallel()
	e, _ := residueWorld(t)
	items, err := e.svc.possibleItems(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		t.Fatal("the fixture has no possible CVE")
	}
	by := map[string]int{}
	for _, it := range items {
		u := it.Question.Detail.Undecided
		if u == nil || !slices.Contains(UndecidedReasons, u.Reason) {
			t.Errorf("%s on %s (%s): undecided %+v, want a reason of the list", it.CVE, it.Question.AssetID, it.Question.Kind, u)
			continue
		}
		by[u.Reason]++
	}
	t.Logf("possible CVEs by undecided reason: %v", by)
	list, err := e.svc.Possible(t.Context(), PossibleFilter{}, Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	if list.Counts.Possible != len(items) || list.Total != len(items) {
		t.Errorf("list counts %+v total %d, want %d possible", list.Counts, list.Total, len(items))
	}
	b, err := json.Marshal(list)
	if err != nil || !strings.Contains(string(b), `"undecided":{"reason":`) {
		t.Errorf("the API does not carry the undecided reason: %v", err)
	}
}

// A finding of the same device, CVE and line always wins: the question is not listed as possible (no double count, never hidden).
func TestPossible_NeverHidesOrDoublesAFinding(t *testing.T) {
	t.Parallel()
	e, _ := residueWorld(t)
	before := possibleByCVE(t, e)
	if _, ok := before["CVE-2026-82001"]; !ok {
		t.Fatal("CVE-2026-82001 is not possible on nas-01")
	}
	e.exec(`INSERT INTO fnd_finding (id, asset_id, cve, software_id, detected, basis, verified, range_origin, fix_kind, fix_key, state, urgency, urgency_at, first_seen, last_seen, updated_at)
		VALUES ('f-x', 'nas-01', 'CVE-2026-82001', 's-nas', 1, 'statement', 'no', 'person', 'unknown', 'k', 'open', 5, '2026-11-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z')`)
	after := possibleByCVE(t, e)
	if _, ok := after["CVE-2026-82001"]; ok {
		t.Error("CVE-2026-82001 is listed possible beside its finding")
	}
	if len(after) != len(before)-1 {
		t.Errorf("%d possible after, %d before: only the CVE with a finding leaves", len(after), len(before))
	}
}

// The app decides first: a vendor's advisory the box reads decides without AI (and the match applies it: a finding with the advisory as
// its range origin); only what it leaves goes to the AI, in one call per CVE, as readings of the release line. A CVE whose page could
// not be read is not sent to the AI and is not stored (not checked). A second check sends nothing: every key was checked.
func TestPossibleCheck_AppFirstThenAIProposalsOnce(t *testing.T) {
	t.Parallel()
	e, fc := possibleWorld(t)
	run := runCheck(t, e)
	if run.Advisory != 1 || run.Readings != 1 || run.Failed != 1 || run.Stopped != nil {
		t.Errorf("run %+v: want 1 decided from the advisory, 1 reading, 1 not checked", run)
	}
	for _, req := range fc.sent {
		if req.CVE == "CVE-2026-82001" {
			t.Error("the AI was asked about the CVE the vendor's advisory decided")
		}
	}
	rows := map[string]Check{}
	cs, err := checksOf(t.Context(), e.db.Reader(), allKeys(t, e))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		rows[c.CVE] = c
	}
	if c := rows["CVE-2026-82001"]; c.DecidedBy != DecidedAdvisory || c.Verdict != VerdictAffected || !strings.Contains(c.Quote, "before 7.2.1-69057-6") {
		t.Errorf("82001 check %+v: want decided by the advisory, affected, quoting the range", c)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'nas-01' AND cve = 'CVE-2026-82001' AND range_origin = 'advisory' AND state = 'open'`); n != 1 {
		t.Error("the match did not turn the advisory's verdict into a finding")
	}
	if c := possibleByCVE(t, e)["CVE-2026-82002"].Check; c == nil || c.Reading == nil || c.DecidedBy != DecidedAI || c.Verdict != VerdictNotAffected ||
		!c.Reading.QuoteFound || !c.Reading.VendorPage || c.Model == "" {
		t.Errorf("82002 check %+v: want the AI's reading of the vendor's page, not affected, its quote found", c)
	}
	if c, ok := rows["CVE-2026-82003"]; ok {
		t.Errorf("82003 check %+v: want none (its page could not be read)", c)
	}
	p := possibleByCVE(t, e)
	if p["CVE-2026-82002"].State != PossibleProposal || p["CVE-2026-82003"].State != PossibleOpen {
		t.Errorf("states 82002 %s, 82003 %s: want proposal and possible", p["CVE-2026-82002"].State, p["CVE-2026-82003"].State)
	}
	calls := len(fc.sent)
	runCheck(t, e) // the CVEs of the other devices the fake AI did not answer are asked again; nas-01's are not
	for _, req := range fc.sent[calls:] {
		if strings.HasPrefix(req.CVE, "CVE-2026-8200") {
			t.Errorf("a second check asked the AI about %s again", req.CVE)
		}
	}
}

func allKeys(t *testing.T, e *env) []string {
	t.Helper()
	var keys []string
	rows, err := e.db.Reader().QueryContext(t.Context(), `SELECT check_key FROM fnd_possible_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}
	return keys
}

// What the AI is sent carries no device data: no device name, address or id, only the CVE, the product, the version and public text.
func TestPossibleCheck_SendsNoDeviceData(t *testing.T) {
	t.Parallel()
	e, fc := possibleWorld(t)
	runCheck(t, e)
	if len(fc.sent) == 0 {
		t.Fatal("no AI call")
	}
	b, err := json.Marshal(fc.sent)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"nas-01", "192.0.2.", "s-nas"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("the AI request carries %q: %s", leak, b)
		}
	}
}

// A proposal waits for a person: confirming "not affected" answers the question (listed under Answered); an exploited CVE proposed not
// affected is never confirmed in bulk; rejecting makes the CVE possible again and the key is not checked again.
func TestPossibleCheck_ProposalsAreConfirmedOrRejectedByAPerson(t *testing.T) {
	t.Parallel()
	e, _ := possibleWorld(t)
	runCheck(t, e)
	p := possibleByCVE(t, e)
	prop := p["CVE-2026-82002"]
	if prop.Bulk() {
		t.Error("an exploited CVE proposed not affected is offered for bulk confirmation")
	}
	if n, err := e.svc.ConfirmProposals(t.Context(), "", VerdictNotAffected, ConfidenceLikely, "ana@example.com", true); err != nil || n != 0 {
		t.Errorf("bulk confirm of exploited not-affected proposals: %d, %v; want 0", n, err)
	}
	if err := e.svc.RejectProposal(t.Context(), prop.Check.Key, "ana@example.com"); err != nil {
		t.Fatal(err)
	}
	if st := possibleByCVE(t, e)["CVE-2026-82002"].State; st != PossibleOpen {
		t.Errorf("after a rejection the CVE is %s, want possible", st)
	}
	if possibleByCVE(t, e)["CVE-2026-82002"].Checkable() {
		t.Error("a rejected proposal's evidence is offered for a new check")
	}
	// a proposal confirmed: the question is answered not affected
	e2, _ := possibleWorld(t)
	runCheck(t, e2)
	q := possibleByCVE(t, e2)["CVE-2026-82002"].Question
	if _, err := e2.svc.ConfirmProposal(t.Context(), q.ID, "ana@example.com", false); err != nil {
		t.Fatal(err)
	}
	if n := e2.count(`SELECT count(*) FROM fnd_question WHERE id = '` + q.ID + `' AND answer = 'not_affected' AND answered_by = 'ana@example.com'`); n != 1 {
		t.Error("the confirmed proposal did not answer the question")
	}
	if _, ok := possibleByCVE(t, e2)["CVE-2026-82002"]; ok {
		t.Error("the confirmed CVE is still possible")
	}
}

// The check identity follows the evidence: a changed CVE record gives a new key, so the CVE is checkable again; the same evidence on
// another device is the same key (checked once for both).
func TestPossibleCheck_KeyFollowsTheEvidence(t *testing.T) {
	t.Parallel()
	e, _ := possibleWorld(t)
	runCheck(t, e)
	old := possibleByCVE(t, e)["CVE-2026-82003"].Question.CheckKey
	for i := range e.feeds.vulns {
		if e.feeds.vulns[i].CVE == "CVE-2026-82003" {
			e.feeds.vulns[i].Stamp = "2026-11-27T00:00:00.000Z|changed"
		}
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	it := possibleByCVE(t, e)["CVE-2026-82003"]
	if it.Question.CheckKey == old || !it.Checkable() {
		t.Errorf("after a record change: key changed %v, checkable %v; want a new key, checkable", it.Question.CheckKey != old, it.Checkable())
	}
}

// A budget reached (or the AI unavailable) stops the check: what was decided stays, the rest is not stored and stays checkable.
func TestPossibleCheck_AStopKeepsWhatWasDecided(t *testing.T) {
	t.Parallel()
	e, fc := possibleWorld(t)
	fc.stop = &CheckStop{Reason: "This month's AI budget is used up."}
	run := runCheck(t, e)
	if run.Stopped == nil || !strings.Contains(*run.Stopped, "budget") {
		t.Errorf("run %+v: want stopped by the budget", run)
	}
	if n := e.count(`SELECT count(*) FROM fnd_possible_check WHERE decided_by = 'ai'`); n != 0 {
		t.Errorf("%d AI checks stored by a check the budget stopped", n)
	}
	p := possibleByCVE(t, e)
	if !p["CVE-2026-82002"].Checkable() || !p["CVE-2026-82003"].Checkable() {
		t.Error("CVEs the AI never answered are not checkable again")
	}
}

// The quote guard: the AI's quote must be in the page word for word; with a range of the version's line it is confident, else likely.
func TestQuoteChecks(t *testing.T) {
	t.Parallel()
	id := CheckID{Version: "15.1R7.9", Line: "15.1"}
	page := "Junos OS: 15.1 versions before 15.1R7-S13 are affected. Other releases are not."
	if !quoteFound("15.1 versions  before 15.1R7-S13", page) || quoteFound("15.1 versions before 15.1R8", page) {
		t.Error("quoteFound does not compare word for word")
	}
	if !quoteNamesRange("15.1 versions before 15.1R7-S13 are affected", id) || quoteNamesRange("Other releases are not affected", id) {
		t.Error("quoteNamesRange")
	}
	if got := textRanges(page); len(got) != 1 || got[0].line != "15.1" || got[0].end != "15.1R7-S13" {
		t.Errorf("textRanges %+v", got)
	}
}

// An exploited CVE never vanishes: every (device, line, CVE) the box knows of is a finding, a possible CVE (settled ones included) or an
// answered question, before a check and after it, and after a person confirms what it proposed.
func TestPossibleCheck_Count_ExploitedNeverVanish(t *testing.T) {
	t.Parallel()
	e, _ := possibleWorld(t)
	known := func() map[string]bool {
		t.Helper()
		out := map[string]bool{}
		rows, err := e.db.Reader().QueryContext(t.Context(), `SELECT asset_id, cve, ifnull(software_id, '') FROM fnd_finding
			UNION SELECT asset_id, cve, ifnull(software_id, '') FROM fnd_question WHERE answer IS NOT NULL AND cve IS NOT NULL`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var a, c, s string
			if err := rows.Scan(&a, &c, &s); err != nil {
				t.Fatal(err)
			}
			out[a+"|"+c+"|"+s] = true
		}
		items, err := e.svc.possibleItems(t.Context(), "")
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			out[it.Question.AssetID+"|"+it.CVE+"|"+it.Question.SoftwareID] = true
		}
		return out
	}
	before := known()
	runCheck(t, e)
	for _, it := range possibleByCVE(t, e) {
		if it.State == PossibleProposal {
			if _, err := e.svc.ConfirmProposal(t.Context(), it.Question.ID, "ana@example.com", true); err != nil {
				t.Fatal(err)
			}
		}
	}
	after := known()
	for k := range before {
		if !after[k] {
			t.Errorf("%s vanished", k)
		}
	}
}

// The product an AI call names is the catalogue's product, never the software name as the device or a person wrote it (a manual entry
// or an agent's display name may carry the device's own name).
func TestPossibleCheck_SendsTheCatalogueProductNotTheDisplayName(t *testing.T) {
	t.Parallel()
	e, fc := possibleWorld(t)
	a := e.inv.match["nas-01"]
	a.Software[0].Display = "DSM on nas-01 in the accounts office"
	e.inv.match["nas-01"] = a
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	runCheck(t, e)
	if len(fc.sent) == 0 {
		t.Fatal("no AI call")
	}
	b, err := json.Marshal(fc.sent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "accounts office") || strings.Contains(string(b), "nas-01") {
		t.Errorf("the AI request carries the software's display name: %s", b)
	}
}

// The check identity carries the whole release the device states: two ESXi 8.0 hosts on different updates (builds) never share a check,
// a proposal or a rejection; two on the same build do.
func TestPossibleCheck_KeyCarriesTheStatedBuild(t *testing.T) {
	t.Parallel()
	e, _ := possibleWorld(t)
	keys := func() map[string]string {
		t.Helper()
		items, err := e.svc.possibleItems(t.Context(), "")
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, it := range items {
			if it.CVE == "CVE-2026-81002" {
				out[it.Question.AssetID] = it.Question.CheckKey
			}
		}
		return out
	}
	k := keys()
	if k["esx-01"] == "" || k["esx-01"] != k["esx-02"] {
		t.Fatalf("same build: keys %v, want one shared key", k)
	}
	e.inv.match["esx-02"] = esxiStated("esx-02", "8.0", "update_1", "21495797")
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if k = keys(); k["esx-02"] == "" || k["esx-01"] == k["esx-02"] {
		t.Errorf("8.0 Update 3 and 8.0 Update 1 share the check key %v", k)
	}
}

// The references are read in the order of their tags as the catalogue stores them (the CVE record's words, which NVD's tags are
// stored in too: vendor-advisory, patch, third-party-advisory), and one tagged exploit is never read.
func TestChooseRefs_ReadsTheCatalogueTagWords(t *testing.T) {
	t.Parallel()
	refs := []RefLink{
		{URL: "https://lists.example.net/msg"},
		{URL: "https://blog.example.org/post", Tags: []string{"third-party-advisory"}},
		{URL: "https://poc.example.com/x", Tags: []string{"exploit"}},
		{URL: "https://advisories.example.com/a1", Tags: []string{"vendor-advisory"}},
	}
	got := chooseRefs(refs, "synology|diskstation manager")
	want := []string{"https://advisories.example.com/a1", "https://blog.example.org/post", "https://lists.example.net/msg"}
	if !slices.Equal(got, want) {
		t.Errorf("chooseRefs = %v, want %v", got, want)
	}
}

// "Not affected" is settled only from the vendor's own advisory (a reference tagged vendor-advisory, or a page on the vendor's own
// host): a third party's page that seems to place the version past the fix leaves the CVE to the AI. "Affected" from any page stands.
func TestPossibleCheck_NotAffectedOnlyFromTheVendorsAdvisory(t *testing.T) {
	t.Parallel()
	const blog = "https://blog.example.org/dsm-flaw"
	fixed := "CVE-2026-82003 in Synology DiskStation Manager: 7.2.1 versions before 7.2.1-69057-2 are affected."
	for _, tc := range []struct {
		name, text string
		tags       []string
		want       string // the stored check's decided_by and verdict
	}{
		{"third party, fixed", fixed, []string{"third-party-advisory"}, "ai"},
		{"vendor-tagged, fixed", fixed, []string{"vendor-advisory"}, "advisory not_affected"},
		{"third party, affected", "CVE-2026-82003 in Synology DiskStation Manager: 7.2.1 versions before 7.2.1-69057-9 are affected.",
			[]string{"third-party-advisory"}, "advisory affected"},
	} {
		e, fc := possibleWorld(t)
		fc.pages["CVE-2026-82003"] = []FetchedPage{{URL: blog, Status: "ok", Text: tc.text}}
		fc.tags = map[string][]string{blog: tc.tags}
		runCheck(t, e)
		var by, verdict string
		if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT decided_by, verdict FROM fnd_possible_check WHERE cve = 'CVE-2026-82003'
			UNION ALL SELECT 'ai', status FROM fnd_line_statement WHERE cve = 'CVE-2026-82003'`).Scan(&by, &verdict); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := by + " " + verdict; !strings.HasPrefix(got, tc.want) {
			t.Errorf("%s: check %q, want %q", tc.name, got, tc.want)
		}
	}
}

// When no reference page could be read, the AI is not asked (it would see the record alone) and nothing is stored: the next check
// tries the pages again, which costs fetches only. A CVE with no reference the box may read is not sent to the AI either; it is
// stored undecided (no_reference_page) until its record changes.
func TestPossibleCheck_NoPageReadNoAICall(t *testing.T) {
	t.Parallel()
	e, fc := possibleWorld(t)
	run := runCheck(t, e)
	for _, req := range fc.sent {
		if len(fc.pages[req.CVE]) == 0 || req.CVE == "CVE-2026-82003" {
			t.Errorf("the AI was asked about %s, whose pages were not read", req.CVE)
		}
	}
	if n := e.count(`SELECT count(*) FROM fnd_possible_check WHERE cve = 'CVE-2026-82003'`); n != 0 {
		t.Errorf("%d checks stored for a CVE whose page could not be read", n)
	}
	if run.Failed == 0 {
		t.Errorf("run %+v: the CVE whose page could not be read is not counted as not checked", run)
	}
	if !possibleByCVE(t, e)["CVE-2026-82003"].Checkable() {
		t.Error("a CVE whose page could not be read is not checkable again")
	}
	rows, err := e.db.Reader().QueryContext(t.Context(), `SELECT cve, decided_by, verdict, detail FROM fnd_possible_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	noRefs := 0
	for rows.Next() {
		var cve, by, verdict, detail string
		if err := rows.Scan(&cve, &by, &verdict, &detail); err != nil {
			t.Fatal(err)
		}
		if len(fc.pages[cve]) > 0 {
			continue
		}
		noRefs++
		if by != DecidedStructured || verdict != VerdictUnsure || !strings.Contains(detail, UndecidedNoReference) {
			t.Errorf("%s (no reference): check %s %s %s, want structured unsure %s", cve, by, verdict, detail, UndecidedNoReference)
		}
	}
	if noRefs == 0 {
		t.Error("the fixture has no possible CVE without a reference")
	}
}

// A change of the CVE record alone never closes a finding a check decided, nor drops a proposal: the last verdict for the same CVE,
// product, release line and release keeps applying until a check on the new evidence replaces it (the CVE is checkable again).
func TestPossibleCheck_ARecordChangeKeepsTheLastVerdict(t *testing.T) {
	t.Parallel()
	e, fc := possibleWorld(t)
	runCheck(t, e)
	const open = `SELECT count(*) FROM fnd_finding WHERE asset_id = 'nas-01' AND cve = 'CVE-2026-82001' AND range_origin = 'advisory' AND state = 'open'`
	if e.count(open) != 1 {
		t.Fatal("the advisory did not decide CVE-2026-82001")
	}
	for i := range e.feeds.vulns {
		if c := e.feeds.vulns[i].CVE; c == "CVE-2026-82001" || c == "CVE-2026-82002" {
			e.feeds.vulns[i].Stamp = "a new reference"
		}
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if e.count(open) != 1 {
		t.Error("a change of the CVE record closed the finding the vendor's advisory decided")
	}
	it := possibleByCVE(t, e)["CVE-2026-82002"]
	if it.State != PossibleProposal || it.Check == nil || !it.Checkable() {
		t.Fatalf("82002 after a record change: state %s, check %v, checkable %v; want the proposal kept and checkable", it.State, it.Check != nil, it.Checkable())
	}
	calls := len(fc.sent)
	runCheck(t, e)
	asked := false
	for _, req := range fc.sent[calls:] {
		asked = asked || req.CVE == "CVE-2026-82002"
	}
	if !asked {
		t.Error("the check on the new evidence did not ask about CVE-2026-82002 again")
	}
	it = possibleByCVE(t, e)["CVE-2026-82002"]
	if it.Check == nil || it.Check.Reading == nil || it.Check.Reading.RecordHash != it.Question.Detail.Check.Record || it.Checkable() {
		t.Errorf("82002 after the new check: check %+v; want the reading of the new record, not checkable", it.Check)
	}
	if n := e.count(`SELECT count(*) FROM fnd_line_statement WHERE cve = 'CVE-2026-82002'`); n != 1 {
		t.Errorf("%d readings of 82002 kept, want only the newest", n)
	}
	if e.count(open) != 1 {
		t.Error("the new check closed the finding")
	}
}

// Confirming proposals in bulk fails closed: when the exploited list cannot be read, nothing is confirmed (an exploited CVE proposed
// not affected is confirmed one by one only).
func TestConfirmProposals_FailClosedWhenTheExploitedListCannotBeRead(t *testing.T) {
	t.Parallel()
	e, _ := possibleWorld(t)
	e.feeds.unlisted = map[string]bool{"CVE-2026-82002": true}
	seedProposal(t, e, "CVE-2026-82002", VerdictNotAffected)
	it := possibleByCVE(t, e)["CVE-2026-82002"]
	if !it.Bulk() {
		t.Fatalf("82002 (on no exploited list) is not offered in bulk: %+v", it)
	}
	reads := 0
	e.feeds.vulnsErr = func() error {
		reads++
		if reads > 1 {
			return errors.New("the catalogue is locked")
		}
		return nil
	}
	n, err := e.svc.ConfirmProposals(t.Context(), "", VerdictNotAffected, ConfidenceLikely, "ana@example.com", true)
	if err == nil || n != 0 {
		t.Errorf("bulk confirm with the exploited list unreadable: %d confirmed, error %v; want none and an error", n, err)
	}
	if c := e.count(`SELECT count(*) FROM fnd_question WHERE id = '` + it.Question.ID + `' AND answer IS NOT NULL`); c != 0 {
		t.Error("the proposal was confirmed while the exploited list could not be read")
	}
}

// Confirming "affected" on a CVE of no exploited list records the finding from the CVE's catalogue entry (its fixes and urgency), as
// the next match does: the match does not have to rebuild it.
func TestConfirmProposal_AffectedOnACatalogueCVEUsesItsRecord(t *testing.T) {
	t.Parallel()
	e, fc := possibleWorld(t)
	e.feeds.unlisted = map[string]bool{"CVE-2026-82002": true}
	_ = fc
	seedProposal(t, e, "CVE-2026-82002", VerdictAffected)
	it := possibleByCVE(t, e)["CVE-2026-82002"]
	if it.State != PossibleProposal {
		t.Fatalf("82002: %s, want a proposal", it.State)
	}
	id, err := e.svc.ConfirmProposal(t.Context(), it.Question.ID, "ana@example.com", true)
	if err != nil || id == "" {
		t.Fatalf("confirm: %q, %v", id, err)
	}
	read := func() string {
		t.Helper()
		var s string
		if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT fix_kind || '|' || fix_key || '|' || urgency || '|' || ifnull(fix_version, '') FROM fnd_finding WHERE id = ?`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	confirmed := read()
	t.Logf("confirmed: %s", confirmed)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if matched := read(); matched != confirmed {
		t.Errorf("the confirmed finding %q differs from what the match makes of it %q", confirmed, matched)
	}
}

// A reference that answers with a script-rendered portal's shell (no CVE id, no product: "Loading", "CSS Error", "Refresh") is not a
// page read: when every reference is such a page, the AI is not called and the CVE is stored undecided (fetch_failed), since fetching
// again gives the same shell until the record changes. A page that failed for a moment still stores nothing.
func TestPossibleCheck_AScriptShellIsNotARead(t *testing.T) {
	t.Parallel()
	e, fc := possibleWorld(t)
	shell := "Example Community\n\nLoading\n\n× Sorry to interrupt\nCSS Error\n\nRefresh"
	fc.pages["CVE-2026-82003"] = []FetchedPage{{URL: "https://portal.example.com/A72300", Status: "ok", Text: shell}}
	runCheck(t, e)
	for _, req := range fc.sent {
		if req.CVE == "CVE-2026-82003" {
			t.Error("the AI was asked about a CVE whose only page is a script shell")
		}
	}
	cs, err := checksOf(t.Context(), e.db.Reader(), allKeys(t, e))
	if err != nil {
		t.Fatal(err)
	}
	var got *Check
	for _, c := range cs {
		if c.CVE == "CVE-2026-82003" {
			got = &c
		}
	}
	if got == nil || got.DecidedBy != DecidedStructured || got.Verdict != VerdictUnsure || got.Undecided == nil || got.Undecided.Reason != UndecidedFetchFailed {
		t.Fatalf("82003 check %+v: want structured, unsure, fetch_failed", got)
	}
	if len(got.Sources) != 1 || got.Sources[0].Status == "ok" {
		t.Errorf("82003 sources %+v: want the shell listed as not read", got.Sources)
	}
}

// seedProposal stores an AI proposal of one version as checks made before readings of release lines were stored (fnd_possible_check,
// decided by ai, likely), for the device nas-01's question about cve.
func seedProposal(t *testing.T, e *env, cve, verdict string) {
	t.Helper()
	q := possibleByCVE(t, e)[cve].Question
	if q.CheckKey == "" || q.Detail.Check == nil {
		t.Fatalf("%s has no check identity on nas-01", cve)
	}
	c := Check{Key: q.CheckKey, CVE: cve, ID: *q.Detail.Check, DecidedBy: DecidedAI, Verdict: verdict, Confidence: ConfidenceLikely, Reason: "The page says so.",
		Quote: "DSM 7.2 is not affected by this issue", Sources: []CheckSource{{URL: dsmPageURL, Status: "ok", Cited: true}}, Model: "test-model",
		Profile: "test", CheckedBy: "ana@example.com", CheckedAt: e.svc.now()}
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error { return insertCheck(t.Context(), tx, c) }); err != nil {
		t.Fatal(err)
	}
}
