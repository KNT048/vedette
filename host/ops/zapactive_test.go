package ops

import (
	"bufio"
	"context"
	"errors"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// zap.active: the plan the host writes, the rule split, the bounds, and the stop, against the fake podman and nft of zap_test.go.

func zapActivePage(t *testing.T, kind string) zapPage {
	t.Helper()
	a := api.ZapActiveArgs{ZapBaselineArgs: api.ZapBaselineArgs{URL: "https://" + zapTestIP + ":8443/", Host: zapTestIP, IP: zapTestIP, Port: 8443, Kind: api.ZapKindIP}}
	if kind == api.ZapKindDomain {
		a.ZapBaselineArgs = api.ZapBaselineArgs{URL: "https://www.example.com/", Host: "www.example.com", IP: zapTestIP, Port: 443, Kind: api.ZapKindDomain, Domain: "example.com", TXTToken: zapTestTok}
	}
	p, err := zapActiveArgs(a)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// planRules reads the rules of the plan's policy: id -> strength.
func planRules(t *testing.T, plan string) map[int]string {
	t.Helper()
	out := map[int]string{}
	m := regexp.MustCompile(`(?m)^        - id: (\d+)\n          strength: (\w+)\n          threshold: medium$`).FindAllStringSubmatch(plan, -1)
	for _, x := range m {
		id, _ := strconv.Atoi(x[1])
		out[id] = x[2]
	}
	if strings.Count(plan, "- id: ") != len(out) {
		t.Fatalf("a rule of the plan is not on, at a strength: %s", plan)
	}
	return out
}

// The plan keeps ZAP to the page's own origin: one context whose one include path is the scheme, host and port, anchored at both ends;
// the spider and the active scan both run in that context. The network fence is the page's address and port only, as for the baseline.
func TestZapActive_NeverAnotherHost(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		page      zapPage
		in, notIn []string
	}{
		{zapActivePage(t, api.ZapKindDomain), []string{"https://www.example.com/", "https://www.example.com", "https://www.example.com:443/login", "https://www.example.com/a?b=c", "https://www.example.com?x=1"},
			[]string{"https://example.com/", "http://www.example.com/", "https://www.example.com:8443/", "https://www.example.com.evil.example/", "https://www.example.com@evil.example/",
				"https://evil.example/https://www.example.com/", "https://wwwxexample.com/", "https://www.example.comx/", "https://" + zapTestIP + "/"}},
		{zapActivePage(t, api.ZapKindIP), []string{"https://" + zapTestIP + ":8443/", "https://" + zapTestIP + ":8443/x/y"},
			[]string{"https://" + zapTestIP + "/", "https://" + zapTestIP + ":84430/", "http://" + zapTestIP + ":8443/", "https://93x184.216.34:8443/", "https://1.1.1.1:8443/"}},
	} {
		plan := zapActivePlan(tc.page, true)
		inc := regexp.MustCompile(`(?m)^      includePaths:\n        - "(.*)"$`).FindStringSubmatch(plan)
		if inc == nil || strings.Count(plan, "includePaths") != 1 || strings.Contains(plan, "excludePaths") {
			t.Fatalf("one include path: %s", plan)
		}
		re := regexp.MustCompile(strings.ReplaceAll(inc[1], `\\`, `\`))
		if !strings.HasPrefix(re.String(), "^") || !strings.HasSuffix(re.String(), "$") {
			t.Fatalf("the include path is not anchored: %s", re)
		}
		for _, u := range tc.in {
			if !re.MatchString(u) {
				t.Errorf("%s: %s is out of scope", re, u)
			}
		}
		for _, u := range tc.notIn {
			if re.MatchString(u) {
				t.Errorf("%s: %s is in scope", re, u)
			}
		}
		if strings.Count(plan, "context: page") != 2 || strings.Count(plan, "- name: ") != 1 || strings.Count(plan, "http") != 3 {
			t.Fatalf("the spider and the active scan must run in the page's one context, on its one URL: %s", plan)
		}
	}
	// The run: the same fence as the baseline (the page's address and port), the active container, the plan in the work folder.
	w := newZapWorld(t, Deps{})
	w.report = cleanZapReport()
	if _, err := w.o.zapRun(t.Context(), nolog, zapActivePage(t, api.ZapKindDomain), zapPass{active: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.plan, `"https://www.example.com/"`) || slices.Index(w.runArgv, "--add-host") < 0 || w.runArgv[slices.Index(w.runArgv, "--add-host")+1] != "www.example.com:"+zapTestIP {
		t.Fatalf("plan %s, argv %q", w.plan, w.runArgv)
	}
	calls := w.Calls()
	if slices.Index(calls, "nft -f -") > slices.Index(calls, "podman run") {
		t.Fatalf("ZAP ran before its fence: %q", calls)
	}
	w.cleanedUp(t)
	// The validator takes the active run's argv, and nothing else of that shape.
	validate := validatePodmanIn("/var/lib/vedette-host")
	got := zapActivePage(t, api.ZapKindDomain).activeArgv("/var/lib/vedette-host/zap/wrk")
	if err := validate(got); err != nil {
		t.Fatalf("the validator refuses the active run: %v", err)
	}
	set := func(a []string, i int, v string) []string { a = slices.Clone(a); a[i] = v; return a }
	at := func(s string) int { return slices.Index(got, s) }
	for name, bad := range map[string][]string{
		"another network":    set(got, at("--network")+1, "host"),
		"a private add-host": set(got, at("--add-host")+1, "www.example.com:10.0.0.1"),
		"another plan":       set(got, len(got)-1, "/zap/wrk/other.yaml"),
		"another image":      set(got, at(zapImage), "docker.io/library/debian:latest"),
		"no memory cap":      set(got, at("--memory=2g"), "--memory=64g"),
		"another work dir":   set(got, at("--volume")+1, "/etc:/zap/wrk:rw,nosuid,nodev,noexec"),
		"an API port":        append(slices.Clone(got), "-port", "8080"),
		"the daemon":         set(got, at("-cmd"), "-daemon"),
	} {
		if validate(bad) == nil {
			t.Errorf("%s: the validator accepts %q", name, bad)
		}
	}
}

// The disruptive rules (denial of service, data changing, the hosting provider's metadata) and form posting are in the plan only with
// Disruptive; SQL Injection runs at strength low without it (no OR 1=1); the rules that are always off never run. The host takes
// Disruptive only for the box's own IP: a domain page or a typed IP is refused.
func TestZapActive_DisruptiveRulesOnlyOnAProvenOwnIP(t *testing.T) {
	t.Parallel()
	p := zapActivePage(t, api.ZapKindIP)
	gentle, rough := zapActivePlan(p, false), zapActivePlan(p, true)
	g, r := planRules(t, gentle), planRules(t, rough)
	for _, rule := range zapActiveRules {
		_, inG := g[rule.id]
		_, inR := r[rule.id]
		switch rule.class {
		case zapRuleOn:
			if !inG || !inR {
				t.Errorf("rule %d (%s) does not run on every page", rule.id, rule.why)
			}
		case zapRuleDisruptive:
			if inG || !inR {
				t.Errorf("disruptive rule %d (%s): without %v, with %v", rule.id, rule.why, inG, inR)
			}
		case zapRuleOff:
			if inG || inR {
				t.Errorf("rule %d (%s) runs", rule.id, rule.why)
			}
		}
	}
	for _, id := range []int{30001, 30002, 40044, 20015, 40014, 40016, 40017, 90026, 90034} {
		if _, on := g[id]; on {
			t.Errorf("disruptive rule %d is on without Disruptive", id)
		}
	}
	if g[zapSQLi] != "low" || r[zapSQLi] != "medium" {
		t.Fatalf("SQL Injection: %q without, %q with", g[zapSQLi], r[zapSQLi])
	}
	if !strings.Contains(gentle, "postForm: false") || !strings.Contains(rough, "postForm: true") || !strings.Contains(gentle, `defaultThreshold: "off"`) {
		t.Fatal("forms are posted only with Disruptive, and every rule not named is off")
	}
	base := api.ZapBaselineArgs{URL: "https://www.example.com/", Host: "www.example.com", IP: zapTestIP, Port: 443, Kind: api.ZapKindDomain, Domain: "example.com", TXTToken: zapTestTok}
	typed := api.ZapBaselineArgs{URL: "http://" + typedTestIP + "/", Host: typedTestIP, IP: typedTestIP, Port: 80, Kind: api.ZapKindIP, TXTToken: domainfence.Token(zapTestKey, typedTestIP),
		Typed: &api.ExposureTyped{Method: domainfence.MethodFile}}
	if _, err := zapActiveArgs(api.ZapActiveArgs{ZapBaselineArgs: typed}); err != nil {
		t.Fatalf("a typed IP without the disruptive rules: %v", err)
	}
	for name, a := range map[string]api.ZapBaselineArgs{"a domain page": base, "a typed IP": typed} {
		_, err := zapActiveArgs(api.ZapActiveArgs{ZapBaselineArgs: a, Disruptive: true})
		var ae *server.ArgsError
		if !errors.As(err, &ae) || ae.Details[0].Field != "args.disruptive" {
			t.Errorf("%s with the disruptive rules: %v", name, err)
		}
	}
	w := newZapWorld(t, Deps{})
	w.report = cleanZapReport()
	if _, err := w.o.zapRun(t.Context(), nolog, zapActivePage(t, api.ZapKindIP), zapPass{active: true}); err != nil {
		t.Fatal(err)
	}
	if _, on := planRules(t, w.plan)[30001]; on {
		t.Fatal("the run without Disruptive wrote a plan with the disruptive rules")
	}
}

// Every rule of the pinned image is classified, and only those: an image update must come with the table read again.
func TestZapActiveRulesCoverTheImage(t *testing.T) {
	t.Parallel()
	f, err := os.Open("testdata/zap-2.17.0-active-rules.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var image []int
	header := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := sc.Text(); strings.HasPrefix(l, "#") {
			header += l
		} else if l != "" {
			id, err := strconv.Atoi(strings.SplitN(l, "\t", 2)[0])
			if err != nil {
				t.Fatal(err)
			}
			image = append(image, id)
		}
	}
	if !strings.Contains(header, zapImage) {
		t.Fatalf("the rule list is of another image than %s: classify the new image's rules", zapImage)
	}
	var table []int
	for _, r := range zapActiveRules {
		table = append(table, r.id)
	}
	slices.Sort(image)
	if !slices.Equal(table, image) {
		t.Fatalf("table %v\nimage %v", table, image)
	}
}

// The bounds: the plan's own caps (spider time, depth and children; the active scan's time per rule and per page, its threads and
// delay), the container's memory, swap and pid caps, and the host's limit of the page, which ends a run that outlives it: the
// container is removed and the fence deleted, and the run says it timed out.
func TestZapActive_Bounds(t *testing.T) {
	t.Parallel()
	plan := zapActivePlan(zapActivePage(t, api.ZapKindIP), true)
	for _, want := range []string{"maxDuration: 2", "maxDepth: 5", "maxChildren: 20", "threadCount: 2", "maxRuleDurationInMins: 2", "maxScanDurationInMins: 12",
		"threadPerHost: 2", "delayInMs: 100", "maxAlertsPerRule: 10", "disableAllRules: true"} {
		if !strings.Contains(plan, "      "+want+"\n") {
			t.Errorf("the plan has no %q", want)
		}
	}
	argv := zapActivePage(t, api.ZapKindIP).activeArgv("/w")
	for _, want := range []string{"--memory=2g", "--memory-swap=2g", "--pids-limit=512", "-Xmx1g", "--read-only", "-silent"} {
		if !slices.Contains(argv, want) {
			t.Errorf("the run has no %s", want)
		}
	}
	if zapActivePageLimit < (zapSpiderMinutes+zapActiveMinutes+2)*60e9 || zapActiveTimeout <= zapActivePageLimit {
		t.Fatal("the page's limit does not hold the plan's own caps, or the command's timeout does not hold the page's limit")
	}
	synctest.Test(t, func(t *testing.T) {
		w := newZapWorld(t, Deps{})
		w.runGate, w.leaveCtr = make(chan struct{}), true // ZAP never ends by itself
		_, err := w.o.zapRun(context.Background(), nolog, zapActivePage(t, api.ZapKindIP), zapPass{active: true})
		var f *server.Failure
		if !errors.As(err, &f) || f.Code != api.CodeZapTimedOut || !strings.Contains(f.Message, "20 minutes") {
			t.Fatalf("%v, want zap_timed_out after 20 minutes", err)
		}
		w.cleanedUp(t)
	})
}

// A stopped run stops ZAP: zap.stop cancels the run that runs, waits until its container is removed and proven gone and its fence
// deleted, and the run ends zap_stopped. With no run, zap.stop says nothing was stopped.
func TestZapActive_StopKillsZAP(t *testing.T) {
	t.Parallel()
	w := newZapWorld(t, Deps{})
	if res, err := w.o.zapStopRun(t.Context(), nolog); err != nil || res.(api.ZapStopResult).Stopped {
		t.Fatalf("no run: %+v %v", res, err)
	}
	w.runGate, w.runStarted, w.leaveCtr = make(chan struct{}), make(chan struct{}, 1), true
	done := make(chan error, 1)
	go func() {
		_, err := w.o.zapRun(context.Background(), nolog, zapActivePage(t, api.ZapKindIP), zapPass{active: true})
		done <- err
	}()
	<-w.runStarted
	res, err := w.o.zapStopRun(t.Context(), nolog)
	if err != nil || !res.(api.ZapStopResult).Stopped {
		t.Fatalf("stop: %+v %v", res, err)
	}
	w.cleanedUp(t) // before zap.stop answered
	err = <-done
	var f *server.Failure
	if !errors.As(err, &f) || f.Code != api.CodeZapStopped {
		t.Fatalf("the stopped run: %v", err)
	}
}

// A run that reached the active scan's own time cap keeps its report and says it was cut short; one that ended in time does not
// (ZAP's own output, recorded from the pinned image).
func TestZapActive_ACutShortRunKeepsWhatItFound(t *testing.T) {
	t.Parallel()
	cut, err := os.ReadFile("testdata/zap-af-active-cut.out")
	if err != nil {
		t.Fatal(err)
	}
	done, err := os.ReadFile("testdata/zap-af-active-done.out")
	if err != nil {
		t.Fatal(err)
	}
	// the recorded cut run had a cap of 1 minute: put it at the cap of the plan
	cut = []byte(strings.Replace(string(cut), "time taken: 00:01:00", "time taken: 00:12:00", 1))
	if !zapCutShort(cut) || zapCutShort(done) || !zapCutShort([]byte("Job activeScan started\n")) || !zapCutShort([]byte("Job activeScan terminated\n")) {
		t.Fatal("cut short is read wrongly")
	}
	w := newZapWorld(t, Deps{})
	w.report, w.runOut = cleanZapReport(), cut
	res, err := w.o.zapRun(t.Context(), nolog, zapActivePage(t, api.ZapKindIP), zapPass{active: true})
	if err != nil {
		t.Fatal(err)
	}
	r := res.(api.ZapActiveResult)
	if !r.CutShort || r.Size != int64(len(w.report)) {
		t.Fatalf("result %+v", r)
	}
	w.cleanedUp(t)
}

func cleanZapReport() []byte { return []byte(`{"site":[]}`) }
