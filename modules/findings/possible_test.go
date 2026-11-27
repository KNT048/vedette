package findings

import (
	"context"
	"encoding/json"
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
}

func (f *fakeChecker) Ready(context.Context) error { return f.ready }

func (f *fakeChecker) Record(_ context.Context, cve string) (CVERecordText, error) {
	var refs []RefLink
	for _, p := range f.pages[cve] {
		refs = append(refs, RefLink{URL: p.URL, Tags: []string{"Vendor Advisory"}})
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
		pages: map[string][]FetchedPage{
			"CVE-2026-82001": {{URL: dsmPageURL + "#82001", Status: "ok", Text: "CVE-2026-82001. Affected products: Synology DiskStation Manager (DSM).\n7.2.1 versions before 7.2.1-69057-6 are affected. Upgrade to 7.2.1-69057-6 or above."}},
			"CVE-2026-82002": {{URL: dsmPageURL + "#82002", Status: "ok", Text: "Synology DiskStation Manager (DSM). DSM 7.2 is not affected by this issue, which only concerns the new photo service."}},
			"CVE-2026-82003": {{URL: dsmPageURL + "#82003", Status: "failed", Note: "the site answered 403"}},
		},
		verdicts: map[string]ProposeVerdict{
			"CVE-2026-82002|7.2.1-69057-5": {Verdict: VerdictNotAffected, Reason: "DSM 7.2 is not affected.", Quote: "DSM 7.2 is not affected by this issue", Source: 1},
			"CVE-2026-82003|7.2.1-69057-5": {Verdict: VerdictUnsure, Reason: "The advisory could not be read."},
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
	e.svc.runPossibleCheck(t.Context(), checkUnits(items), "ana@example.com")
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
// its range origin); only what it leaves goes to the AI, in one call per CVE, as proposals; an unsure answer keeps the CVE possible
// with a reason. A second check sends nothing: every key was checked.
func TestPossibleCheck_AppFirstThenAIProposalsOnce(t *testing.T) {
	t.Parallel()
	e, fc := possibleWorld(t)
	run := runCheck(t, e)
	if run.Advisory != 1 || run.Proposals != 1 || run.Undecided != 1 || run.Stopped != nil {
		t.Errorf("run %+v: want 1 decided from the advisory, 1 proposal, 1 undecided", run)
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
	if c := rows["CVE-2026-82002"]; c.DecidedBy != DecidedAI || c.Verdict != VerdictNotAffected || c.Confidence != ConfidenceLikely || c.Model == "" {
		t.Errorf("82002 check %+v: want an AI proposal, not affected, likely (the quote names no 7.2.1 range)", c)
	}
	if c := rows["CVE-2026-82003"]; c.Verdict != VerdictUnsure || c.Undecided == nil || c.Undecided.Reason != UndecidedFetchFailed {
		t.Errorf("82003 check %+v: want unsure with fetch_failed (its page could not be read)", c)
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
	if err := e.svc.RejectProposal(t.Context(), prop.Question.CheckKey, "ana@example.com"); err != nil {
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
