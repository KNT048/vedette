package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// zap.active with passive: the page's passive and active scans in one ZAP run (one start, one spider), against the fake podman and
// nft of zap_test.go. No real scan, no real sleep.

// planJobs are the job types of a plan, in order.
func planJobs(plan string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`(?m)^  - type: (\S+)$`).FindAllStringSubmatch(plan, -1) {
		out = append(out, m[1])
	}
	return out
}

// planJob is the text of the n-th job of type typ (0-based) up to the next job.
func planJob(t *testing.T, plan, typ string, n int) string {
	t.Helper()
	parts := strings.Split(plan, "\n  - type: ")
	seen := 0
	for _, p := range parts[1:] {
		if strings.HasPrefix(p, typ+"\n") {
			if seen == n {
				return p
			}
			seen++
		}
	}
	t.Fatalf("no job %s #%d in %s", typ, n, plan)
	return ""
}

func skipPage(t *testing.T) zapPage {
	t.Helper()
	p := zapActivePage(t, api.ZapKindIP)
	p.skip = []string{"/Admin", "/users/sign_in"}
	return p
}

// One run does both passes in this order: the passive rules on (as the baseline's), one spider, the wait for the passive rules,
// their report, then the active scan and its report. The page's one context keeps the web paths to skip (in any case), and the
// gentle speed is one thread for the spider and the active scan.
func TestZapCombined_OnePlanSpiderPassiveThenActive(t *testing.T) {
	t.Parallel()
	for _, gentle := range []bool{false, true} {
		p := skipPage(t)
		plan := zapPlanActive(p, zapActiveOpts{passive: true, gentle: gentle})
		want := []string{"passiveScan-config", "spider", "passiveScan-wait", "report", "activeScan", "report"}
		if got := planJobs(plan); !slices.Equal(got, want) {
			t.Fatalf("jobs %q, want %q", got, want)
		}
		pcfg := planJob(t, plan, "passiveScan-config", 0)
		if strings.Contains(pcfg, "disableAllRules") || !strings.Contains(pcfg, "maxAlertsPerRule: 10") || !strings.Contains(pcfg, "scanOnlyInScope: true") {
			t.Fatalf("the passive rules must stay on, as the baseline's: %s", pcfg)
		}
		if r := planJob(t, plan, "report", 0); !strings.Contains(r, `reportFile: "passive.json"`) {
			t.Fatalf("the first report is the passive one: %s", r)
		}
		if r := planJob(t, plan, "report", 1); !strings.Contains(r, `reportFile: "out.json"`) {
			t.Fatalf("the last report is the active one: %s", r)
		}
		if strings.Count(plan, "- name: ") != 1 || strings.Contains(plan, "technology") || strings.Count(plan, "context: page") != 2 {
			t.Fatalf("one context, every technology, for the spider and the active scan: %s", plan)
		}
		for _, prefix := range p.skip {
			ex := zapQuote(zapExcludeRE(p.url, prefix))
			if !strings.Contains(plan, "        - "+ex) || !strings.HasPrefix(zapExcludeRE(p.url, prefix), "(?i)^") {
				t.Fatalf("the path to skip %s is not excluded in any case: %s", prefix, plan)
			}
		}
		threads := "2"
		if gentle {
			threads = "1"
		}
		if !strings.Contains(planJob(t, plan, "spider", 0), "threadCount: "+threads+"\n") || !strings.Contains(planJob(t, plan, "activeScan", 0), "threadPerHost: "+threads+"\n") {
			t.Fatalf("gentle %v: threads: %s", gentle, plan)
		}
		// the rules, the spider and the bounds are the active plan's own: only the passive part differs
		active := zapPlanActive(p, zapActiveOpts{gentle: gentle})
		if !maps2Equal(planRules(t, plan), planRules(t, active)) || planJob(t, plan, "spider", 0) != planJob(t, active, "spider", 0) ||
			planJob(t, plan, "activeScan", 0) != planJob(t, active, "activeScan", 0) {
			t.Fatalf("the active part differs from the active plan:\n%s\n---\n%s", plan, active)
		}
	}
	// without passive the plan is the active plan as before: passive rules off, no wait, one report
	if got := planJobs(zapPlanActive(skipPage(t), zapActiveOpts{})); !slices.Equal(got, []string{"passiveScan-config", "spider", "activeScan", "report"}) {
		t.Fatalf("the active plan changed: %q", got)
	}
}

func maps2Equal(a, b map[int]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Technologies leave rules out only when core names them: the active scan then runs in a second context of the same URL, include and
// excludes, whose technology leaves them out; the spider and the passive rules keep the page's context with every technology. The
// rules that skip or narrow are named in the result's skipped rules. Without technologies: no technology line, no rule skipped.
func TestZapCombined_TechnologyOnlyWhenNamed(t *testing.T) {
	t.Parallel()
	p := skipPage(t)
	none := zapActiveOpts{passive: true}
	if plan := zapPlanActive(p, none); strings.Contains(plan, "technology") || strings.Contains(plan, "context: active") {
		t.Fatalf("no technology named, none left out: %s", plan)
	}
	if got := zapSkippedRules(p, none); slices.ContainsFunc(got, func(id int) bool { return id >= 40018 && id <= 40027 }) {
		t.Fatalf("no technology named, no SQL injection rule skipped: %v", got)
	}
	o := zapActiveOpts{passive: true, tech: []string{"HypersonicSQL", "Microsoft SQL Server", "Oracle"}}
	plan := zapPlanActive(p, o)
	if strings.Count(plan, "- name: ") != 2 || !strings.Contains(plan, "    - name: active\n") || strings.Count(plan, "excludePaths:") != 2 {
		t.Fatalf("a second context with the same excludes: %s", plan)
	}
	if !strings.Contains(plan, "      technology:\n        exclude:\n          - \"HypersonicSQL\"\n          - \"Microsoft SQL Server\"\n          - \"Oracle\"\n") || strings.Count(plan, "technology:") != 1 {
		t.Fatalf("the technologies left out: %s", plan)
	}
	if !strings.Contains(planJob(t, plan, "spider", 0), "context: page\n") || !strings.Contains(planJob(t, plan, "activeScan", 0), "context: active\n") {
		t.Fatalf("the spider keeps every technology, the active scan leaves them out: %s", plan)
	}
	got := zapSkippedRules(p, o)
	for _, id := range []int{40018, 40020, 40021, 40027} {
		if !slices.Contains(got, id) {
			t.Errorf("rule %d is not named as left out or narrowed: %v", id, got)
		}
	}
	for _, id := range []int{40019, 40022} {
		if slices.Contains(got, id) {
			t.Errorf("rule %d (a database not left out) is named: %v", id, got)
		}
	}
	// a run without passive never takes technologies (the plan is the active plan as before)
	if plan := zapPlanActive(p, zapActiveOpts{tech: o.tech}); strings.Contains(plan, "technology") {
		t.Fatalf("technology without passive: %s", plan)
	}
}

// Every technology the API takes turns off a rule of the host's rule split that runs on every page.
func TestZapTechRulesCoverTheAPI(t *testing.T) {
	t.Parallel()
	var keys []string
	for k, id := range zapTechRules {
		keys = append(keys, k)
		i := slices.IndexFunc(zapActiveRules, func(r zapRule) bool { return r.id == id })
		if i < 0 || zapActiveRules[i].class != zapRuleOn {
			t.Errorf("%s: rule %d is not a rule that runs on every page", k, id)
		}
	}
	slices.Sort(keys)
	if !slices.Equal(keys, api.ZapTechs) {
		t.Fatalf("the technologies of the rules %q, of the API %q", keys, api.ZapTechs)
	}
}

// The args: technologies only with passive, each a name of the API's list, once.
func TestZapCombined_Args(t *testing.T) {
	t.Parallel()
	base := api.ZapActiveArgs{ZapBaselineArgs: api.ZapBaselineArgs{URL: "https://" + zapTestIP + ":8443/", Host: zapTestIP, IP: zapTestIP, Port: 8443, Kind: api.ZapKindIP}}
	ok := base
	ok.Passive, ok.TechExclude = true, []string{"Oracle", "Microsoft SQL Server"}
	if _, err := zapActiveArgs(ok); err != nil {
		t.Fatal(err)
	}
	passive := base
	passive.Passive = true
	if _, err := zapActiveArgs(passive); err != nil {
		t.Fatal(err)
	}
	for name, tech := range map[string][]string{"unknown": {"SQLite"}, "twice": {"Oracle", "Oracle"}, "a pattern": {"Db.*"}, "case": {"oracle"}} {
		a := base
		a.Passive, a.TechExclude = true, tech
		if _, err := zapActiveArgs(a); err == nil {
			t.Errorf("%s: %q accepted", name, tech)
		}
	}
	noPassive := base
	noPassive.TechExclude = []string{"Oracle"}
	if _, err := zapActiveArgs(noPassive); err == nil {
		t.Error("technologies without passive accepted")
	}
}

// One podman run for both passes: the result names both reports (each kept as the host keeps a report), the rules the active part
// ran, and the plan is the combined one.
func TestZapCombined_OneRunBothReports(t *testing.T) {
	t.Parallel()
	w := newZapWorld(t, Deps{})
	w.passive, w.report = []byte(`{"site":[{"passive":1}]}`), []byte(`{"site":[{"active":1}]}`)
	got, err := w.o.zapRun(t.Context(), nolog, zapActivePage(t, api.ZapKindIP), zapPass{active: true, passive: true, tech: []string{"Oracle"}})
	if err != nil {
		t.Fatal(err)
	}
	res := got.(api.ZapActiveResult)
	if w.runs != 1 || strings.Count(strings.Join(w.Calls(), "\n"), "podman run") != 1 {
		t.Fatalf("%d podman runs for one page: %q", w.runs, w.Calls())
	}
	if res.PassiveReportID == "" || res.ReportID == "" || res.PassiveReportID == res.ReportID || res.ActiveFailed != "" || res.CutShort {
		t.Fatalf("%+v", res)
	}
	for id, want := range map[string][]byte{res.PassiveReportID: w.passive, res.ReportID: w.report} {
		b, err := os.ReadFile(filepath.Join(w.o.zapDir(), id+".json")) //nolint:gosec // the test's own state folder
		if err != nil || string(b) != string(want) {
			t.Fatalf("report %s: %q %v", id, b, err)
		}
	}
	if !slices.Equal(res.Rules, zapPlanRules(zapActivePage(t, api.ZapKindIP), zapActiveOpts{})) || len(res.Rules) == 0 || !slices.Contains(res.SkippedRules, 40021) {
		t.Fatalf("rules %v, skipped %v", res.Rules, res.SkippedRules)
	}
	if got := planJobs(w.plan); !slices.Contains(got, "passiveScan-wait") || !strings.Contains(w.plan, "context: active") {
		t.Fatalf("the run's plan: %s", w.plan)
	}
	w.cleanedUp(t)
}

// The passive report is kept when the active part ends without its report: ZAP killed (out of memory), the active report missing,
// the host's page limit reached. A stopped run, or a run whose passive report is missing although ZAP ended well, is an error.
func TestZapCombined_PassiveStandsWhenActiveEnds(t *testing.T) {
	t.Parallel()
	page := zapActivePage(t, api.ZapKindIP)
	pass := zapPass{active: true, passive: true}
	for name, tc := range map[string]struct {
		code   int
		active []byte
		want   string
	}{
		"killed":         {137, nil, api.CodeZapFailed},
		"no report":      {0, nil, api.CodeZapFailed},
		"report too big": {0, make([]byte, api.MaxZapReport+1), api.CodeZapReportTooLarge},
	} {
		w := newZapWorld(t, Deps{})
		w.passive, w.report, w.runCode = []byte(`{"site":[]}`), tc.active, tc.code
		got, err := w.o.zapRun(t.Context(), nolog, page, pass)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		res := got.(api.ZapActiveResult)
		if res.PassiveReportID == "" || res.ReportID != "" || res.ActiveFailed != tc.want || !res.CutShort || len(res.Rules) == 0 {
			t.Fatalf("%s: %+v", name, res)
		}
		w.cleanedUp(t)
	}
	synctest.Test(t, func(t *testing.T) {
		w := newZapWorld(t, Deps{})
		w.passive, w.runGate, w.leaveCtr = []byte(`{"site":[]}`), make(chan struct{}), true // the active scan never ends by itself
		got, err := w.o.zapRun(context.Background(), nolog, zapActivePage(t, api.ZapKindIP), pass)
		if err != nil {
			t.Fatal(err)
		}
		if res := got.(api.ZapActiveResult); res.PassiveReportID == "" || res.ActiveFailed != api.CodeZapTimedOut || !res.CutShort {
			t.Fatalf("%+v", res)
		}
		w.cleanedUp(t)
	})
	w := newZapWorld(t, Deps{})
	w.passive = nil
	_, err := w.o.zapRun(t.Context(), nolog, page, pass)
	var f *server.Failure
	if !errors.As(err, &f) || f.Code != api.CodeZapFailed {
		t.Fatalf("no passive report: %v", err)
	}
	if zapCombinedPageLimit < zapActivePageLimit+zapPassiveWaitMinutes*60e9 || zapActiveTimeout <= zapCombinedPageLimit {
		t.Fatal("the combined page's limit does not hold the passive wait, or the command's timeout does not hold the page's limit")
	}
}
