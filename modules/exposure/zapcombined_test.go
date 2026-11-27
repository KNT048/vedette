package exposure

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	corerun "github.com/knt048/vedette/core/run"
)

// INV-24: a page whose active scan the run takes anyway runs its passive and active scans in one ZAP run (CombinedWebScanner), against
// a fake ZAP. No real scan, no real sleep.

// combinedWeb is an activeWeb that runs both scans of a page in one run.
type combinedWeb struct {
	*activeWeb
	pages      []string     // the pages of each one-run call
	targets    []ScanTarget // the target of each one-run call
	rowsAt     []int        // probe-log rows at each one-run call
	activeErr  error        // the active part ended without its report
	noCombined bool         // an older host: every one-run call is refused
	refusals   int
	hookC      func()
	clock      func() time.Time
	hangFirst  bool        // the first one-run call never answers: the step's own wait for the page runs out
	startedAt  []time.Time // the run's clock at each one-run call
}

// combinedRules are the active rules the fake host says it ran (its report's 10036 is a passive rule: the passive pass read it).
var combinedRules = []string{"40012", "40018", "40019", "40020", "40021", "40022", "40027"}

func (c *combinedWeb) Combined(ctx context.Context, st ScanTarget, p WebPage) (WebScan, WebScan, error, error) {
	if c.noCombined {
		c.refusals++
		return WebScan{}, WebScan{}, nil, ErrNoCombined
	}
	if c.clock != nil {
		c.startedAt = append(c.startedAt, c.clock())
	}
	if c.hangFirst && len(c.pages) == 0 {
		c.pages = append(c.pages, p.URL)
		<-ctx.Done()
		return WebScan{}, WebScan{}, nil, ctx.Err()
	}
	if c.hookC != nil {
		c.hookC()
	}
	c.pages, c.targets, c.rowsAt = append(c.pages, p.URL), append(c.targets, st), append(c.rowsAt, len(c.log.rows))
	passive := WebScan{Report: c.report(p.URL)}
	if c.activeErr != nil {
		return passive, WebScan{}, c.activeErr, nil
	}
	return passive, WebScan{Report: c.active(p.URL), Rules: combinedRules, DisruptiveRules: zapTestDisruptiveRules}, nil, nil
}

func (e *env) wireCombined(active func(string) []byte) *combinedWeb {
	w := &combinedWeb{activeWeb: e.wireActive(active), clock: e.clock.Now}
	e.svc.cfg.Web = w
	return w
}

// A person's deep scan: one ZAP run per page for both scans, never Baseline then Active; one probe-log row per page before its run;
// the passive and the active results kept apart as before (the active report's passive alert is the passive pass's, not counted
// twice), and the two steps of the run page end as they did.
func TestWebCombined_OneZAPRunPerPage(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireCombined(xssReport)
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	s, err := e.svc.Scan(e.ctx(), "admin@acme.example", id)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.pages) != 3 || len(w.asked) != 0 || len(w.calls) != 0 {
		t.Fatalf("one-run calls %q, baseline %q, active %q", w.pages, w.asked, w.urls)
	}
	for i, n := range w.rowsAt {
		if n != i+1 || !strings.HasPrefix(w.log.rows[i].Tool, "ZAP passive and active scan in one run") || w.log.rows[i].URL != w.pages[i] {
			t.Fatalf("probe log at the calls %v: %+v", w.rowsAt, w.log.rows)
		}
	}
	for _, tg := range w.targets {
		if !tg.Mode.Full || !tg.Mode.Disruptive {
			t.Fatalf("the one-run target: %+v", tg)
		}
	}
	passive, active := 0, 0
	for _, r := range s.WebFindings {
		switch {
		case r.PluginID == "10036" && r.Pass == "":
			passive++
		case r.PluginID == "40012" && r.Pass == passActive:
			active++
		default:
			t.Fatalf("row %+v", r)
		}
	}
	if passive != 3 || active != 3 {
		t.Fatalf("%d passive rows, %d active rows: %+v", passive, active, s.WebFindings)
	}
	if st, note := e.runStep(stepNameZAP); st.Status != corerun.Done || !strings.Contains(note, "3") {
		t.Fatalf("the passive step: %s %q", st.Status, note)
	}
	if st, note := e.runStep(stepNameZAPAct); st.Status != corerun.Done || note != "ZAP attacked 3 of 3 pages with the disruptive rules on the box's own IP, 3 alerts." {
		t.Fatalf("the active step: %s %q", st.Status, note)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'zap' AND key LIKE '40012@%' AND state = 'open' AND json_extract(detail, '$.zap.pass') = 'active'`); n != 3 {
		t.Fatalf("%d active issues", n)
	}
}

// The active part of the run ended without its report (the host's time ran out): the passive results stand, the page is read, and
// the active step says the page's active results are not known.
func TestWebCombined_PassiveStandsWhenTheActivePartEnds(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireCombined(xssReport)
	w.activeErr = ErrActiveTimedOut
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	s, err := e.svc.Scan(e.ctx(), "admin@acme.example", id)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.pages) != 3 || len(w.calls) != 0 || len(s.WebFindings) != 3 {
		t.Fatalf("calls %q active %q findings %+v", w.pages, w.urls, s.WebFindings)
	}
	for _, r := range s.WebFindings {
		if r.PluginID != "10036" || r.Pass != "" {
			t.Fatalf("row %+v", r)
		}
	}
	if !lineWith(notChecked(s), notActiveHostSlow) {
		t.Fatalf("not checked %q", notChecked(s))
	}
	if st, _ := e.runStep(stepNameZAP); st.Status != corerun.Done {
		t.Fatalf("the passive step: %s", st.Status)
	}
	if st, note := e.runStep(stepNameZAPAct); st.Status != corerun.Failed || note != "ZAP attacked none of 3 pages." {
		t.Fatalf("the active step: %s %q", st.Status, note)
	}
}

// Only a page the active pass would take anyway gets one run: a scheduled scan and a scan without the testing terms run the baseline
// alone, as before.
func TestWebCombined_OnlyWhenTheActiveScanRuns(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireCombined(emptyReport)
	e.scanIP(Content{}) // no terms: the surface scan
	if len(w.pages) != 0 || len(w.asked) != 3 {
		t.Fatalf("without the terms: %d one-run calls, %d baseline", len(w.pages), len(w.asked))
	}
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), SystemUser, id); err != nil {
		t.Fatal(err)
	}
	if len(w.pages) != 0 || len(w.asked) != 6 || len(w.calls) != 0 {
		t.Fatalf("scheduled: %d one-run calls, %d baseline, %d active", len(w.pages), len(w.asked), len(w.calls))
	}
}

// An older host refuses the one run before anything starts: the step runs the baseline then the active scan as before, from the first
// page on, and asks the host for one run only once.
func TestWebCombined_AnOlderHostRunsBothOneAfterTheOther(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireCombined(xssReport)
	w.noCombined = true
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	s, err := e.svc.Scan(e.ctx(), "admin@acme.example", id)
	if err != nil {
		t.Fatal(err)
	}
	if w.refusals != 1 || len(w.asked) != 3 || len(w.calls) != 3 {
		t.Fatalf("refusals %d, baseline %q, active %q", w.refusals, w.asked, w.urls)
	}
	if len(s.WebFindings) != 6 {
		t.Fatalf("rows: %+v", s.WebFindings)
	}
	if st, note := e.runStep(stepNameZAPAct); st.Status != corerun.Done || !strings.HasPrefix(note, "ZAP attacked 3 of 3 pages") {
		t.Fatalf("the active step: %s %q", st.Status, note)
	}
}

// The active pass's time (60 minutes) counts from the first page attacked with its passive scan: a page that no longer fits gets its
// baseline only, and the active pass says it was not attacked.
func TestWebCombined_TheRunLimitCountsFromTheFirstPage(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireCombined(xssReport)
	w.hookC = func() { e.advance(25 * time.Minute) }
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	s, err := e.svc.Scan(e.ctx(), "admin@acme.example", id)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.pages) != 2 || len(w.asked) != 1 || len(w.calls) != 0 { // at 0 and 25 minutes; at 50 a page of 21 more does not fit in 60
		t.Fatalf("one-run %q, baseline %q, active %q", w.pages, w.asked, w.urls)
	}
	if !lineWith(notChecked(s), "1 page not attacked: the active pass of one scan takes at most 60 minutes") {
		t.Fatalf("not checked %q", notChecked(s))
	}
	if st, note := e.runStep(stepNameZAPAct); st.Status != corerun.Partial || !strings.HasSuffix(note, "1 page not attacked.") {
		t.Fatalf("the active step: %s %q", st.Status, note)
	}
}

// A page whose one run the step gave up on (its wait ran out) is a "Not checked" line of that page only: the pages after it still run,
// as after a baseline that ran out of time.
func TestWebCombined_APageOutOfTimeLeavesTheNextPagesRunning(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t)
		w := e.wireCombined(xssReport)
		w.hangFirst = true
		id := e.committedIP(ipA).ID
		e.acceptTerms(id, true)
		s, err := e.svc.Scan(e.ctx(), "admin@acme.example", id)
		if err != nil {
			t.Fatal(err)
		}
		if len(w.pages) != 3 {
			t.Fatalf("one-run calls %q: the pages after the one out of time were dropped", w.pages)
		}
		if !lineWith(notChecked(s), notWebSlowAhead) || len(s.WebPages) != 2 {
			t.Fatalf("pages %q, not checked %q", s.WebPages, notChecked(s))
		}
	})
}

// A page starts in one run only while that whole run (CombinedScanTimeout, the passive part included) still fits in the active
// pass's 60 minutes; a page that no longer fits gets its baseline, and its active scan alone when that still fits.
func TestWebCombined_OneRunStartsOnlyWhenItFits(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireCombined(xssReport)
	w.hookC = func() { e.advance(37 * time.Minute) } // 37 + 21 fits in 60, 37 + 25 does not
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	for _, at := range w.startedAt {
		if at.Sub(w.startedAt[0])+CombinedScanTimeout > ActiveRunLimit {
			t.Fatalf("a one run started at %s after the first, past the active pass's %s: starts %v", at.Sub(w.startedAt[0]), ActiveRunLimit, w.startedAt)
		}
	}
	if len(w.pages) != 1 || len(w.asked) != 2 || len(w.calls) != 2 {
		t.Fatalf("one-run %q, baseline %q, active %q", w.pages, w.asked, w.urls)
	}
}

// A technology is left out only on the page where this run positively identified a product that never runs on it: never on a guess,
// never on another page.
func TestWebCombined_TechnologyOnlyWhenIdentified(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireCombined(emptyReport)
	svcs := webServices()
	for i := range svcs {
		if svcs[i].Port == 443 {
			svcs[i].Product = "GitLab"
		}
	}
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Services: svcs, Ports: 98}}
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if len(w.pages) != 3 {
		t.Fatalf("one-run calls %q", w.pages)
	}
	left := 0
	for i, tg := range w.targets {
		want := []string(nil)
		if w.pages[i] == "https://"+ipA+"/" {
			want, left = []string{"HypersonicSQL", "Microsoft SQL Server", "Oracle"}, left+1
		}
		if !slices.Equal(tg.NoTech, want) {
			t.Fatalf("%s: technologies left out %q, want %q", w.pages[i], tg.NoTech, want)
		}
		if row := w.log.rows[i]; (want != nil) != strings.Contains(row.Tool, "left out") {
			t.Fatalf("%s: probe row %q", w.pages[i], row.Tool)
		}
	}
	if left != 1 {
		t.Fatalf("the identified page was not scanned: %q", w.pages)
	}
}

func TestWebTechAbsent(t *testing.T) {
	t.Parallel()
	page := WebPage{URL: "https://203.0.113.7:10443/", Host: "203.0.113.7", IP: netip.MustParseAddr("203.0.113.7"), Port: 10443}
	gitlab := []string{"HypersonicSQL", "Microsoft SQL Server", "Oracle"}
	for name, tc := range map[string]struct {
		c    Content
		want []string
	}{
		"nothing identified":          {Content{}, nil},
		"nuclei matched":              {Content{Templates: []TemplateRow{{IP: "203.0.113.7", Port: 10443, Template: "gitlab-detect", Outcome: OutcomeMatched}}}, gitlab},
		"nuclei did not match":        {Content{Templates: []TemplateRow{{IP: "203.0.113.7", Port: 10443, Template: "gitlab-detect", Outcome: OutcomeNoMatch}}}, nil},
		"another port":                {Content{Templates: []TemplateRow{{IP: "203.0.113.7", Port: 443, Template: "gitlab-detect", Outcome: OutcomeMatched}}}, nil},
		"another address":             {Content{Templates: []TemplateRow{{IP: "203.0.113.8", Port: 10443, Template: "gitlab-detect", Outcome: OutcomeMatched}}}, nil},
		"nmap named it from a probe":  {Content{Services: []ServiceRow{{IP: "203.0.113.7", Port: 10443, Name: "https", Product: "GitLab", Method: "probed"}}}, gitlab},
		"nmap by the port only":       {Content{Services: []ServiceRow{{IP: "203.0.113.7", Port: 10443, Name: "https", Product: "GitLab", Method: "table"}}}, nil},
		"a title is not an identity":  {Content{Ports: []PortRow{{IP: "203.0.113.7", Port: 10443, Title: "Sign in · GitLab"}}}, nil},
		"another product of the port": {Content{Services: []ServiceRow{{IP: "203.0.113.7", Port: 10443, Name: "https", Product: "nginx", Method: "probed"}}}, nil},
	} {
		got := webTechAbsent(tc.c, page)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
		if slices.Contains(got, "MySQL") || slices.Contains(got, "PostgreSQL") {
			t.Errorf("%s: a database GitLab ran on is left out: %q", name, got)
		}
	}
}
