package exposure

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/oas"
)

// INV-24, the active web scan: when it runs, with which rules, and how its results are kept, against a fake ZAP.

// activeWeb is a fakeWeb that runs the active scan too: active returns its report, each call is recorded with its target, and hook runs
// at the start of each call.
type activeWeb struct {
	*fakeWeb
	active  func(page string) []byte
	cut     bool
	calls   []ScanTarget
	urls    []string
	hook    func()
	logRows []int // rows in the probe log at each active call
}

func (a *activeWeb) Active(_ context.Context, st ScanTarget, p WebPage) (WebScan, error) {
	if a.hook != nil {
		a.hook()
	}
	a.calls, a.urls = append(a.calls, st), append(a.urls, p.URL)
	a.logRows = append(a.logRows, len(a.log.rows))
	return WebScan{Report: a.active(p.URL), CutShort: a.cut, DisruptiveRules: zapTestDisruptiveRules}, nil
}

// zapTestDisruptiveRules are the rules the host names as run only with the disruptive rules (ZapActiveResult.DisruptiveRules).
var zapTestDisruptiveRules = []string{"7", "20015", "30001", "30002", "40014", "40016", "40017", "40018", "40044", "90026", "90034"}

func xssReport(page string) []byte {
	return []byte(fmt.Sprintf(`{"site":[{"@name":%q,"alerts":[{"pluginid":"40012","alert":"Cross Site Scripting (Reflected)","riskcode":"3","confidence":"2","cweid":"79","instances":[{"uri":%q}]},`+
		`{"pluginid":"10036","alert":"Server Leaks Version","riskcode":"1","confidence":"3","cweid":"200","instances":[{"uri":%q}]}]}]}`, strings.TrimSuffix(page, "/"), page+"search", page))
}

func emptyReport(page string) []byte {
	return []byte(fmt.Sprintf(`{"site":[{"@name":%q,"alerts":[]}]}`, strings.TrimSuffix(page, "/")))
}

// wireActive gives the service a web scanner that runs both passes.
func (e *env) wireActive(active func(string) []byte) *activeWeb {
	w := &activeWeb{fakeWeb: &fakeWeb{report: cleanReport}, active: active}
	l := &webLog{}
	w.log = l
	e.svc.cfg.Web, e.svc.cfg.Probes = w, l
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Services: webServices(), Ports: 98}}
	e.svc.SetRunner(&fakeRunner{content: Content{}})
	return w
}

func lineWith(lines []string, part string) bool {
	return slices.ContainsFunc(lines, func(s string) bool { return strings.Contains(s, part) })
}

func (e *env) webSteps(id string) []WebStep {
	e.t.Helper()
	scans, err := e.svc.Scans(e.ctx(), id)
	if err != nil || len(scans) == 0 {
		e.t.Fatalf("scans: %v %v", scans, err)
	}
	return scans[0].WebSteps
}

// Only a person's scan of a target whose testing terms are accepted runs the active scan, after the passive one, on the pages the
// passive scan read; each page is in the probe log before ZAP attacks it. A scan without the terms has no active pass.
func TestZapActive_OnlyInAPersonsScanNow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireActive(emptyReport)
	s := e.scanIP(Content{}) // no terms: the surface scan
	if len(w.calls) != 0 || len(w.asked) != 3 {
		t.Fatalf("without the terms: %d active calls, %d passive", len(w.calls), len(w.asked))
	}
	if lineWith(notChecked(s), "Active web") {
		t.Fatalf("a surface scan speaks of the active scan: %q", notChecked(s))
	}
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(w.urls, w.asked[3:]) {
		t.Fatalf("active on %q, passive on %q", w.urls, w.asked[3:])
	}
	for i, n := range w.logRows {
		if n != 6+i+1 { // 3 + 3 passive rows, then this page's active row
			t.Fatalf("probe log rows at the active calls: %v", w.logRows)
		}
	}
	if !strings.HasPrefix(w.log.rows[len(w.log.rows)-1].Tool, "ZAP active scan") {
		t.Fatalf("probe row: %+v", w.log.rows[len(w.log.rows)-1])
	}
	steps := e.webSteps(id)
	if len(steps) != 2 || steps[0].Step != WebStepPassive || steps[1] != (WebStep{Step: WebStepActive, State: WebDone, PagesDone: 3, PagesTotal: 3, Disruptive: true}) {
		t.Fatalf("web steps: %+v", steps)
	}
}

// A scan the box runs by itself keeps the passive baseline only, and says so in one plain line on the scan and on the run's web
// steps, so a scheduled run does not look incomplete.
func TestZapActive_ScheduledScanIsPassiveOnly(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireActive(emptyReport)
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	s, err := e.svc.Scan(e.ctx(), SystemUser, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.calls) != 0 || len(w.asked) != 3 {
		t.Fatalf("scheduled: %d active calls, %d passive", len(w.calls), len(w.asked))
	}
	if !slices.Contains(notChecked(s), notActiveScheduled) || notActiveScheduled != "Active web checks run when a person presses Scan now; scheduled scans read the pages without attacking them." {
		t.Fatalf("not checked: %q", notChecked(s))
	}
	steps := e.webSteps(id)
	if len(steps) != 2 || steps[0].Note != notActiveScheduled || steps[0].State != WebDone || steps[1].State != WebSkipped || steps[1].Note != notActiveScheduled {
		t.Fatalf("web steps: %+v", steps)
	}
}

// The disruptive rules go only to the box's own proven IP, in a person's scan whose mode allows the disruptive checks: not behind
// carrier-grade NAT, and not on an acceptance without them.
func TestZapActive_DisruptiveRulesOnlyOnAProvenOwnIP(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireActive(emptyReport)
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	gw := &fakeGateway{g: GatewayDevice{IP: netip.MustParseAddr("192.0.2.1")}}
	e.svc.cfg.Gateway = gw
	scan := func() []bool {
		w.calls = nil
		e.advance(ScanEvery)
		if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", id); err != nil {
			t.Fatal(err)
		}
		var out []bool
		for _, c := range w.calls {
			if !c.Mode.Full {
				t.Fatalf("not deep: %+v", c)
			}
			out = append(out, c.Mode.Disruptive)
		}
		return out
	}
	if got := scan(); !slices.Equal(got, []bool{true, true, true}) {
		t.Fatalf("own IP: %v", got)
	}
	gw.g = GatewayDevice{IP: netip.MustParseAddr("100.64.0.1")}
	if got := scan(); !slices.Equal(got, []bool{false, false, false}) {
		t.Fatalf("behind carrier-grade NAT: %v", got)
	}
	gw.g = GatewayDevice{IP: netip.MustParseAddr("192.0.2.1")}
	e.acceptTerms(id, false) // an older acceptance without the disruptive checks
	if got := scan(); !slices.Equal(got, []bool{false, false, false}) {
		t.Fatalf("terms without the disruptive checks: %v", got)
	}
}

// A domain's pages on a CDN or hosting address get the active scan without the disruptive rules, and the scan says so.
func TestZapActive_CDNAddressGetsActiveWithoutDisruptive(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireActive(emptyReport)
	dom := e.committedDomain()
	e.acceptTerms(dom.ID, true)
	e.svc.SetRunner(&fakeRunner{content: Content{
		Hosts: []HostRow{{Name: "acme.example", IP: ipA}, {Name: "www.acme.example", IP: ipA}},
		Ports: []PortRow{{ipA, 443, "https", "", "", 0, false, "", nil, "", "", "", nil, true}},
	}})
	s, err := e.svc.Scan(e.ctx(), "admin@acme.example", dom.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.calls) != 2 {
		t.Fatalf("active calls: %q (passive %q), not checked %q", w.urls, w.asked, notChecked(s))
	}
	for _, c := range w.calls {
		if !c.Mode.Full || c.Mode.Disruptive {
			t.Fatalf("a domain's page: %+v", c.Mode)
		}
	}
	if !lineWith(notChecked(s), "ran without its disruptive rules") {
		t.Fatalf("not checked: %q", notChecked(s))
	}
}

// An alert both passes report is one row and one issue; an alert of the active scan is an issue with ZAP's risk, confidence and pass,
// apart from the exploited CVEs; a scheduled scan (passive only) never closes it, and a person's scan whose active pass no longer
// reports it does.
func TestZapActive_NoDoubleCount(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireActive(xssReport) // its 10036 is the passive baseline's alert too (cleanReport)
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	s, err := e.svc.Scan(e.ctx(), "admin@acme.example", id)
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, r := range s.WebFindings {
		count[r.PluginID+"@"+r.Site]++
	}
	for k, n := range count {
		if n != 1 {
			t.Fatalf("%s is %d rows", k, n)
		}
	}
	if len(s.WebFindings) != 6 || len(s.Vulns) != 0 { // 3 pages: 10036 once each (passive), 40012 once each (active)
		t.Fatalf("rows: %+v", s.WebFindings)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'zap' AND key LIKE '10036@%'`); n != 3 {
		t.Fatalf("%d issues of 10036, want one per page", n)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'zap' AND key LIKE '40012@%' AND state = 'open'
		AND json_extract(detail, '$.zap.pass') = 'active' AND json_extract(detail, '$.zap.risk') = 'high' AND json_extract(detail, '$.zap.confidence') = 'medium'`); n != 3 {
		t.Fatalf("%d open active issues with ZAP's rating", n)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'zap' AND key LIKE '10036@%' AND json_extract(detail, '$.zap.pass') = 'passive'`); n != 3 {
		t.Fatalf("%d passive issues", n)
	}
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), SystemUser, id); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE key LIKE '40012@%' AND state = 'open'`); n != 3 {
		t.Fatalf("a scheduled scan closed %d active issues", 3-n)
	}
	w.active = emptyReport
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE key LIKE '40012@%' AND state = 'gone'`); n != 3 {
		t.Fatalf("%d active issues gone after the active scan no longer found them", n)
	}
}

// A page cut short at the active scan's time limit keeps what it found and says so; the run's time for the active pass bounds how many
// pages it attacks, and says which were left.
func TestZapActive_CutShortAndTheRunLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireActive(xssReport)
	w.cut = true
	w.hook = func() { e.advance(25 * time.Minute) }
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	s, err := e.svc.Scan(e.ctx(), "admin@acme.example", id)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.calls) != 2 { // starts at 0 and 25 minutes; at 50 minutes a page of 21 more does not fit in 60
		t.Fatalf("active calls: %q", w.urls)
	}
	n := 0
	for _, r := range s.WebFindings {
		if r.PluginID == "40012" {
			n++
		}
	}
	if n != 2 || !lineWith(notChecked(s), notActiveCut) || !lineWith(notChecked(s), "1 page not attacked: the active pass of one scan takes at most 60 minutes") {
		t.Fatalf("findings %d, not checked %q", n, notChecked(s))
	}
	steps := e.webSteps(id)
	if a := steps[1]; a.State != WebPartial || !a.CutShort || a.PagesDone != 2 || a.PagesTotal != 3 || a.Alerts != 4 {
		t.Fatalf("active step: %+v", a)
	}
}

// A page whose active scan was cut short at its time limit did not run every rule, so an active alert it no longer reports is not
// "gone": only an active scan that finished on the page closes it.
func TestZapActive_ACutShortPageClosesNoActiveIssue(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireActive(xssReport)
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE key LIKE '40012@%' AND state = 'open'`); n != 3 {
		t.Fatalf("%d open active issues, want 3", n)
	}
	w.active, w.cut = emptyReport, true
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE key LIKE '40012@%' AND state = 'open'`); n != 3 {
		t.Fatalf("a cut-short active scan closed %d active issues", 3-n)
	}
	w.cut = false
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE key LIKE '40012@%' AND state = 'gone'`); n != 3 {
		t.Fatalf("%d active issues gone after a finished active scan no longer found them, want 3", n)
	}
}

// persistentXSSReport is an active report with an alert of a disruptive rule (40014, persistent XSS) and one of a rule every active
// pass runs (40012, reflected XSS).
func persistentXSSReport(page string) []byte {
	return []byte(fmt.Sprintf(`{"site":[{"@name":%q,"alerts":[{"pluginid":"40014","alert":"Cross Site Scripting (Persistent)","riskcode":"3","confidence":"2","cweid":"79","instances":[{"uri":%q}]},`+
		`{"pluginid":"40012","alert":"Cross Site Scripting (Reflected)","riskcode":"3","confidence":"2","cweid":"79","instances":[{"uri":%q}]}]}]}`, strings.TrimSuffix(page, "/"), page+"guestbook", page+"search"))
}

// An active issue is closed only by a later active pass that ran the rule that found it: a pass without the disruptive rules never
// closes an issue of a disruptive rule (it stays open, its rating kept), while it does close one of a rule it ran itself; a later
// pass with the disruptive rules that no longer finds it closes it.
func TestZapActive_APassWithoutTheDisruptiveRulesClosesNoIssueOfThem(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireActive(persistentXSSReport)
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	gw := &fakeGateway{g: GatewayDevice{IP: netip.MustParseAddr("192.0.2.1")}}
	e.svc.cfg.Gateway = gw
	open := func(plugin string) int {
		return e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'zap' AND key LIKE '` + plugin + `@%' AND state = 'open'`)
	}
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if open("40014") != 3 || open("40012") != 3 {
		t.Fatalf("after the disruptive pass: %d open 40014, %d open 40012", open("40014"), open("40012"))
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE key LIKE '40014@%' AND json_extract(detail, '$.zap.disruptive') = 1`); n != 3 {
		t.Fatalf("%d issues of 40014 say a disruptive rule found them", n)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE key LIKE '40012@%' AND coalesce(json_extract(detail, '$.zap.disruptive'), 0) = 0`); n != 3 {
		t.Fatalf("%d issues of 40012 say a rule of every pass found them", n)
	}
	// The API carries it (Issue.detail.zap.disruptive).
	issues, err := e.svc.Issues(e.ctx(), id)
	if err != nil {
		t.Fatal(err)
	}
	out, err := into[oas.ExposureGetExposureTreeIDIssuesOK](items[IssueView]{issues})
	if err != nil {
		t.Fatalf("the issues do not fit the API: %v", err)
	}
	flagged := 0
	for _, it := range out.Items {
		if z, ok := it.Detail.Zap.Get(); ok && z.Disruptive.Or(false) {
			flagged++
		}
	}
	if flagged != 3 {
		t.Fatalf("%d issues say detail.zap.disruptive in the API, want 3", flagged)
	}
	// The gateway moved behind carrier-grade NAT: the next person's scan runs the active pass without the disruptive rules.
	gw.g = GatewayDevice{IP: netip.MustParseAddr("100.64.0.1")}
	w.active = emptyReport
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if c := w.calls[len(w.calls)-1]; c.Mode.Disruptive {
		t.Fatal("the pass behind carrier-grade NAT ran the disruptive rules")
	}
	if open("40014") != 3 {
		t.Fatalf("a pass without the disruptive rules closed %d issues of a disruptive rule", 3-open("40014"))
	}
	if open("40012") != 0 {
		t.Fatalf("a pass that ran the rule did not close %d issues it no longer found", open("40012"))
	}
	// Back on the box's own line: a pass with the disruptive rules that no longer finds them closes them.
	gw.g = GatewayDevice{IP: netip.MustParseAddr("192.0.2.1")}
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE key LIKE '40014@%' AND state = 'gone'`); n != 3 {
		t.Fatalf("%d issues of 40014 gone after a disruptive pass no longer found them, want 3", n)
	}
}
