package ops

import (
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// The deep-scan settings of a target, as zap.baseline and zap.active take them: rule classes turned off (no_dos, no_change), web
// paths to skip (skip_paths) and the gentle speed. Each only narrows what the run does; the host builds every pattern itself from
// validated prefixes, and the grant and gateway checks of the disruptive rules stay exactly as they are.

// The rules of the split that request fixed file names (not a page the spider found): ZAP does not apply the context's excludes to
// them, so a run with paths to skip leaves them out.
var zapFixedPathRules = []int{10045, 40028, 40029, 40032, 40034, 40035, 40042}

// The disruptive rules per class: denial of service, and the checks that may change data (with the ones that make the server fetch
// something elsewhere).
var (
	zapDoSRules    = []int{20015, 30001, 30002, 40044}
	zapChangeRules = []int{7, 40014, 40016, 40017, 90026, 90034}
)

type narrowResult struct {
	Refused string `json:"disruptive_refused"`
	Skipped []int  `json:"skipped_rules"`
	Cut     bool   `json:"cut_short"`
}

// activeWith runs zap.active on the box's own IP with the disruptive rules and a person's grant, plus extra wire args.
func (a *zapAuthz) activeWith(extra map[string]any) (narrowResult, string) {
	a.t.Helper()
	args := map[string]any{"url": "https://" + zapTestIP + ":8443/", "host": zapTestIP, "ip": zapTestIP, "port": 8443, "kind": "ip",
		"disruptive": true, "grant": a.mustGrant(zapTestIP)}
	for k, v := range extra {
		args[k] = v
	}
	run, err := a.call("zap.active", args, zapPerson)
	if err != nil || run.Status != api.StatusSucceeded {
		a.t.Fatalf("zap.active %v: %+v %v", extra, run, err)
	}
	var r narrowResult
	if err := json.Unmarshal(run.Result, &r); err != nil {
		a.t.Fatal(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return r, a.plan
}

func TestZapArgs_SkipPaths(t *testing.T) {
	t.Parallel()
	page := func(paths ...string) api.ZapBaselineArgs {
		return api.ZapBaselineArgs{URL: "https://" + zapTestIP + ":8443/", Host: zapTestIP, IP: zapTestIP, Port: 8443, Kind: api.ZapKindIP, SkipPaths: paths}
	}
	p, err := zapArgs(page("/admin", "/api/v1/delete", "/a-b_c.d~e%20f!&',;=:@"))
	if err != nil || len(p.skip) != 3 {
		t.Fatalf("valid paths refused: %v", err)
	}
	many := make([]string, api.ZapMaxSkipPaths+1)
	for i := range many {
		many[i] = "/p" + strconv.Itoa(i)
	}
	for name, paths := range map[string][]string{
		"no leading slash":   {"admin"},
		"the page itself":    {"/"},
		"a pattern":          {"/admin.*"},
		"a regex anchor":     {"/admin$"},
		"a query":            {"/a?b=1"},
		"a fragment":         {"/a#b"},
		"a space":            {"/a b"},
		"a backslash":        {`/a\b`},
		"a parenthesis":      {"/a(b)"},
		"a control":          {"/a\nb"},
		"a non-ASCII letter": {"/ä"},
		"a repeat":           {"/a", "/a"},
		"too long":           {"/" + strings.Repeat("a", api.ZapMaxSkipPathLen)},
		"too many":           many,
	} {
		_, err := zapArgs(page(paths...))
		var ae *server.ArgsError
		if !errors.As(err, &ae) || ae.Details[0].Field != "args.skip_paths" {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := zapActiveArgs(api.ZapActiveArgs{ZapBaselineArgs: page(paths...)}); err == nil {
			t.Errorf("%s: zap.active took it", name)
		}
	}
}

// A class turned off leaves each of its rules out of the plan, and the result names the rules this page did not run because of the
// settings (core then closes no issue of theirs with this page). Denial of service off keeps the checks that may change data, and
// the reverse; data change off also keeps form posting off and SQL Injection at strength low. Both off is the plan without the
// disruptive rules.
func TestZapActive_ClassesOffLeaveTheirRules(t *testing.T) {
	t.Parallel()
	a := newZapAuthz(t, routeLAN)
	r, plan := a.activeWith(map[string]any{"no_dos": true})
	rules := planRules(t, plan)
	for _, id := range zapDoSRules {
		if _, on := rules[id]; on {
			t.Errorf("denial of service off: rule %d runs", id)
		}
		if !slices.Contains(r.Skipped, id) {
			t.Errorf("denial of service off: rule %d is not in skipped_rules %v", id, r.Skipped)
		}
	}
	for _, id := range zapChangeRules {
		if _, on := rules[id]; !on {
			t.Errorf("denial of service off took rule %d of data change", id)
		}
	}
	if rules[zapSQLi] != "medium" || !strings.Contains(plan, "postForm: true") || r.Refused != "" || r.Cut {
		t.Fatalf("denial of service off changed the rest: SQLi %q, refused %q, cut %v", rules[zapSQLi], r.Refused, r.Cut)
	}

	r, plan = a.activeWith(map[string]any{"no_change": true})
	rules = planRules(t, plan)
	for _, id := range zapChangeRules {
		if _, on := rules[id]; on {
			t.Errorf("data change off: rule %d runs", id)
		}
		if !slices.Contains(r.Skipped, id) {
			t.Errorf("data change off: rule %d is not in skipped_rules %v", id, r.Skipped)
		}
	}
	for _, id := range zapDoSRules {
		if _, on := rules[id]; !on {
			t.Errorf("data change off took rule %d of denial of service", id)
		}
	}
	if rules[zapSQLi] != "low" || strings.Contains(plan, "postForm: true") || !slices.Contains(r.Skipped, zapSQLi) {
		t.Fatalf("data change off: SQLi %q, forms posted %v, skipped %v", rules[zapSQLi], strings.Contains(plan, "postForm: true"), r.Skipped)
	}

	_, plan = a.activeWith(map[string]any{"no_dos": true, "no_change": true})
	if plan != zapActivePlan(zapActivePage(t, api.ZapKindIP), false) {
		t.Error("both classes off is not the plan without the disruptive rules")
	}
	// the settings narrow; they never stand in for the grant: without one the page runs without the disruptive rules, as before
	run, err := a.call("zap.active", map[string]any{"url": "https://" + zapTestIP + ":8443/", "host": zapTestIP, "ip": zapTestIP, "port": 8443,
		"kind": "ip", "disruptive": true, "no_dos": true}, zapPerson)
	var nr narrowResult
	if err != nil || json.Unmarshal(run.Result, &nr) != nil || nr.Refused != api.ZapRefusedGrantMissing {
		t.Fatalf("no grant with a class off: %+v %v", run, err)
	}
	// without the disruptive rules a class off changes nothing and skips nothing
	p := zapActivePage(t, api.ZapKindIP)
	if zapPlanActive(p, zapActiveOpts{noDoS: true, noChange: true}) != zapActivePlan(p, false) || len(zapSkippedRules(p, zapActiveOpts{noDoS: true, noChange: true})) != 0 {
		t.Error("a class off changed a run without the disruptive rules")
	}
}

// Web paths to skip: the active plan's context excludes each one (anchored to the page's origin, the prefix as written, any case,
// built by the host from the validated prefix), so neither the spider nor the active scan requests a URL under it. The rules that
// request fixed file names are left out (ZAP sends them without asking the context), and named in skipped_rules.
func TestZapActive_SkipPathsAreExcluded(t *testing.T) {
	t.Parallel()
	a := newZapAuthz(t, routeLAN)
	r, plan := a.activeWith(map[string]any{"skip_paths": []string{"/admin", "/robots.txt", "/a.b"}})
	ex := planExcludes(t, plan)
	if len(ex) != 3 {
		t.Fatalf("excludePaths %q", ex)
	}
	origin := "https://" + zapTestIP + ":8443"
	for url, want := range map[string]bool{
		origin + "/admin": true, origin + "/admin/users?id=1": true, origin + "/ADMIN/x": true, origin + "/administrator": true,
		origin + "/robots.txt": true, origin + "/a.b/c": true,
		origin + "/": false, origin + "/public/admin": false, origin + "/axb": false, origin + "/x/robots.txt": false,
		"https://" + zapTestIP + ":9443/admin": false,
	} {
		hit := false
		for _, e := range ex {
			if regexp.MustCompile(e).MatchString(url) {
				hit = true
			}
		}
		if hit != want {
			t.Errorf("%s excluded %v, want %v (%q)", url, hit, want, ex)
		}
	}
	rules := planRules(t, plan)
	for _, id := range zapFixedPathRules {
		if _, on := rules[id]; on {
			t.Errorf("paths skipped: rule %d requests fixed file names, and runs", id)
		}
		if !slices.Contains(r.Skipped, id) {
			t.Errorf("paths skipped: rule %d not in skipped_rules %v", id, r.Skipped)
		}
	}
	if _, on := rules[40012]; !on {
		t.Error("paths skipped took a rule that scans the pages the spider found")
	}
	if !strings.Contains(plan, "parseRobotsTxt: false") {
		t.Error("/robots.txt is skipped, but the spider reads it")
	}
	// no path to skip: the plan of before, no exclude, no rule skipped
	r, plan = a.activeWith(nil)
	if strings.Contains(plan, "excludePaths") || len(r.Skipped) != 0 || plan != zapActivePlan(zapActivePage(t, api.ZapKindIP), true) {
		t.Fatalf("without paths to skip the plan changed: skipped %v", r.Skipped)
	}
}

// The passive pass of a page with paths to skip runs as an Automation Framework plan the host writes (zap-baseline.py has no
// exclude): the same context with the excludes, a spider of one minute on one thread that handles no form, the passive rules, and
// the same report. Without paths to skip it is zap-baseline.py exactly as before.
func TestZapBaseline_SkipPathsRunThePassivePlan(t *testing.T) {
	t.Parallel()
	a := newZapAuthz(t, routeLAN)
	page := map[string]any{"url": "https://" + zapTestIP + ":8443/", "host": zapTestIP, "ip": zapTestIP, "port": 8443, "kind": "ip"}
	run, err := a.call("zap.baseline", page, zapPerson)
	a.mu.Lock()
	argv := slices.Clone(a.runArgv)
	a.mu.Unlock()
	if err != nil || run.Status != api.StatusSucceeded || !slices.Contains(argv, "zap-baseline.py") || slices.Contains(argv, "-autorun") {
		t.Fatalf("no path to skip: %+v %v %q", run, err, argv)
	}
	page["skip_paths"] = []string{"/delete"}
	run, err = a.call("zap.baseline", page, zapPerson)
	if err != nil || run.Status != api.StatusSucceeded {
		t.Fatalf("paths to skip: %+v %v", run, err)
	}
	a.mu.Lock()
	argv = slices.Clone(a.runArgv)
	plan := a.plan
	a.mu.Unlock()
	if slices.Contains(argv, "zap-baseline.py") || !slices.Contains(argv, "-autorun") {
		t.Fatalf("the passive pass with paths to skip ran %q", argv)
	}
	ex := planExcludes(t, plan)
	if len(ex) != 1 || !regexp.MustCompile(ex[0]).MatchString("https://"+zapTestIP+":8443/delete?id=3") {
		t.Fatalf("excludePaths %q", ex)
	}
	for _, want := range []string{"type: spider", "maxDuration: 1", "threadCount: 1", "processForm: false", "postForm: false", "type: passiveScan-wait",
		"scanOnlyInScope: true", "template: traditional-json", "context: page"} {
		if !strings.Contains(plan, want+"\n") {
			t.Errorf("the passive plan has no %q:\n%s", want, plan)
		}
	}
	if strings.Contains(plan, "activeScan") || strings.Contains(plan, "disableAllRules: true") {
		t.Fatalf("the passive plan runs the active scan or turns the passive rules off:\n%s", plan)
	}
	var res api.ZapBaselineResult
	if err := json.Unmarshal(run.Result, &res); err != nil || res.ReportID == "" {
		t.Fatalf("result %s %v", run.Result, err)
	}
}

// Gentle: the active scan and its spider run on one thread with 500 ms between requests. Fixed in the host, never a number of core's.
func TestZapActive_Gentle(t *testing.T) {
	t.Parallel()
	a := newZapAuthz(t, routeLAN)
	_, plan := a.activeWith(map[string]any{"gentle": true})
	for _, want := range []string{"threadPerHost: 1", "delayInMs: 500", "threadCount: 1"} {
		if !strings.Contains(plan, "      "+want+"\n") {
			t.Errorf("gentle plan has no %q", want)
		}
	}
	for _, not := range []string{"threadPerHost: 2", "delayInMs: 100", "threadCount: 2"} {
		if strings.Contains(plan, not) {
			t.Errorf("gentle plan still has %q", not)
		}
	}
	if zapGentleThreads != 1 || zapGentleDelayMs < 5*zapDelayMs {
		t.Fatal("gentle is not one thread and at least five times the delay")
	}
}

// planExcludes reads the excludePaths of the plan's context, as ZAP would (a YAML double-quoted scalar is a JSON string), turned into
// Go regular expressions (ZAP's Java patterns use the same syntax for what the host writes).
func planExcludes(t *testing.T, plan string) []string {
	t.Helper()
	i := strings.Index(plan, "      excludePaths:\n")
	if i < 0 {
		return nil
	}
	var out []string
	for _, l := range strings.Split(plan[i+len("      excludePaths:\n"):], "\n") {
		v, ok := strings.CutPrefix(l, "        - ")
		if !ok {
			break
		}
		var s string
		if err := json.Unmarshal([]byte(v), &s); err != nil {
			t.Fatalf("exclude %q: %v", v, err)
		}
		out = append(out, s)
	}
	return out
}
