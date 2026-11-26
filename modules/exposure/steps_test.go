package exposure

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// stepsProbeLog is a probe log with the template, web and Greenbone faces (a deep scan logs all three).
type stepsProbeLog struct {
	*gbLog
	web *webLog
}

func (l stepsProbeLog) RecordWebProbe(ctx context.Context, p WebProbe) error {
	return l.web.RecordWebProbe(ctx, p)
}

// stepsEnv is a deep scan of ipA with every engine step wired: service identification finds a web server on 80 with an exploited CVE
// (nuclei runs its templates there), ZAP scans http://ipA/ (one alert), and OpenVAS, turned on, checks the open ports (4 results).
func stepsEnv(t *testing.T) *env {
	t.Helper()
	e, h := gbEnv(t)
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Ports: 98, Services: []ServiceRow{
		{IP: ipA, Port: 80, Name: "http", Product: "Apache httpd", Version: "2.4.49", CPE: "cpe:/a:apache:http_server:2.4.49"}}}}
	e.svc.cfg.Matcher = &fakeMatcher{m: Matches{Compared: 1, Listed: 1500, Vulns: []VulnRow{
		{IP: ipA, Port: 80, CVE: "CVE-2021-41773", Name: "Path traversal", Basis: "version", Summary: "In range."}}}}
	e.svc.cfg.Templates = &fakeTemplates{log: &fakeProbeLog{}, results: []TemplateResult{{Port: 80, Template: "CVE-2021-41773", CVE: "CVE-2021-41773", Outcome: OutcomeMatched}}}
	e.svc.cfg.Web = &fakeWeb{report: cleanReport}
	e.svc.cfg.Probes = stepsProbeLog{gbLog: h.gvm.log, web: &webLog{}}
	e.enable()
	h.gvm.with(func(g *fakeGVM) { g.states = []string{"Requested", "Running", "Done"} })
	return e
}

func (e *env) engineRuns() map[string]EngineRun {
	e.t.Helper()
	runs, err := e.svc.EngineRuns(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	return runs
}

// INV-30 (#861): a deep scan in which nuclei, ZAP and OpenVAS all ran gives each engine its last run: the run, the target, when the
// step ended, ok, and what it found. Before any scan there is none.
func TestContract_INV30_ADeepRunGivesEachStepItsLastRun(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t)
	if runs := e.engineRuns(); len(runs) != 0 {
		t.Fatalf("before any scan: %+v", runs)
	}
	s := e.scanIP(gbOpen())
	if s.GreenboneRun.State != GBRunDone || len(s.WebFindings) != 1 || len(s.Greenbone) != 4 {
		t.Fatalf("the scan did not run every step: run %+v, web %d, greenbone %d", s.GreenboneRun, len(s.WebFindings), len(s.Greenbone))
	}
	runs := e.engineRuns()
	want := map[string]string{
		StepNuclei:  "External scan of " + ipA + ": deep templates ran, 1 matched",
		StepZAP:     "External scan of " + ipA + ": ZAP scanned 1 page, 1 alert",
		StepOpenVAS: "External scan of " + ipA + ": OpenVAS found 4 results",
	}
	at := store.FormatTS(t0)
	for engine, text := range want {
		r, ok := runs[engine]
		if !ok || r.Outcome != StepOK || r.Text != text || r.Target != ipA || r.At != at || !strings.HasPrefix(r.RunID, "run") || r.RunID != runs[StepZAP].RunID {
			t.Errorf("%s: %+v (ok %v), want ok %q at %s", engine, r, ok, text, at)
		}
	}
}

// INV-30: a later run that skipped OpenVAS (turned off) leaves the OpenVAS card on the earlier run; ZAP and nuclei, which ran again,
// move to the new one. The second scan of the day replaces the snapshot, never the step's row.
func TestContract_INV30_ARunThatSkippedAStepLeavesItsEarlierRun(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t)
	e.scanIP(gbOpen())
	first := e.engineRuns()
	if _, err := e.svc.SetGreenbone(e.ctx(), "admin@acme.example", false); err != nil {
		t.Fatal(err)
	}
	e.advance(ScanEvery)
	e.svc.SetRunner(&fakeRunner{content: gbOpen()})
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", e.detectedID(ipA)); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM core_run_step WHERE name = ? AND status <> 'skipped'`, stepNameOpenVAS); n != 1 {
		t.Fatalf("%d OpenVAS steps that ran; the second scan did not run it", n)
	}
	if n := e.count(`SELECT count(*) FROM core_run_step WHERE name = ? AND status = 'skipped' AND note = ?`, stepNameOpenVAS, notGBOff); n != 1 { // the run page says why
		t.Fatalf("%d skipped OpenVAS steps saying it is off", n)
	}
	second := e.engineRuns()
	if second[StepOpenVAS] != first[StepOpenVAS] {
		t.Fatalf("openvas moved: %+v -> %+v", first[StepOpenVAS], second[StepOpenVAS])
	}
	later := store.FormatTS(t0.Add(ScanEvery))
	for _, engine := range []string{StepZAP, StepNuclei} {
		if r := second[engine]; r.RunID == first[engine].RunID || r.At != later || r.Outcome != StepOK {
			t.Errorf("%s: %+v, was %+v", engine, r, first[engine])
		}
	}
}

// INV-30: a run in which no step ran (no web port, no service with an exploited CVE, OpenVAS off) stores no engine run.
func TestContract_INV30_ARunWithNoStepStoresNone(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.Web = &fakeWeb{report: cleanReport}
	e.scanIP(Content{})
	if runs := e.engineRuns(); len(runs) != 0 {
		t.Fatalf("runs = %+v", runs)
	}
}

// INV-30: how the calls of a step make its outcome: all answered ok, some failed partial, none answered failed, a page ZAP found empty
// is answered but not scanned, only skipped calls (unavailable, skipped page) no run. A run that ends while a step is in a call, or
// between two of its calls before the run is past it, makes it stopped (a Stop) or failed (the box's error, a panic); a step the run
// is past keeps its outcome. A step is stored once; one the run is not past waits for the end of the run.
func TestStepLogOutcomes(t *testing.T) {
	t.Parallel()
	at := t0.Add(time.Minute)
	const open = -1 // begun, never ended
	for _, tc := range []struct {
		name   string
		engine string
		deep   bool
		calls  []int
		closed bool
		end    int
		want   string
		text   string
	}{
		{"ok", StepZAP, false, []int{callRan, callRan}, true, runEnded, StepOK, "ZAP scanned 2 pages, 2 alerts"},
		{"partial", StepZAP, false, []int{callRan, callFailed}, true, runEnded, StepPartial, "ZAP scanned 1 of 2 pages, 1 alert"},
		{"failed", StepZAP, false, []int{callFailed}, true, runEnded, StepFailed, "ZAP could not scan 1 page"},
		{"an empty page is not scanned", StepZAP, false, []int{callRan, callEmpty}, true, runEnded, StepOK, "ZAP scanned 1 of 2 pages, 1 alert"},
		{"only empty pages", StepZAP, false, []int{callEmpty, callEmpty}, true, runEnded, StepOK, "ZAP found no page to scan at 2 web ports"},
		{"skipped (unavailable)", StepZAP, false, []int{callSkipped}, true, runEnded, "", ""},
		{"stopped in a call", StepZAP, false, []int{callRan, open}, false, runStopped, StepStopped, "stopped while ZAP ran"},
		{"stopped between two calls", StepNuclei, false, []int{callRan}, false, runStopped, StepStopped, "stopped while the templates ran"},
		{"stopped after the step", StepNuclei, false, []int{callRan}, true, runStopped, StepOK, "safe templates ran, 1 matched"},
		{"panic in a call", StepZAP, false, []int{open}, false, runPanicked, StepFailed, "the scan stopped because of an error on the box while ZAP ran"},
		{"panic between two calls", StepNuclei, true, []int{callRan}, false, runPanicked, StepFailed, "the scan stopped because of an error on the box while the templates ran"},
		{"deep", StepNuclei, true, []int{callRan}, true, runEnded, StepOK, "deep templates ran, 1 matched"},
		{"deep partial", StepNuclei, true, []int{callRan, callFailed}, true, runEnded, StepPartial, "deep templates ran on 1 of 2 addresses, 1 matched"},
		{"skipped templates (module off)", StepNuclei, false, []int{callSkipped}, false, runEnded, "", ""},
	} {
		l := &stepLog{}
		for _, c := range tc.calls {
			l.begin(tc.engine, tc.deep)
			if c != open {
				l.end(tc.engine, c, map[bool]int{true: 1}[c == callRan], t0)
			}
		}
		if tc.closed {
			l.close(tc.engine)
		}
		if !tc.closed {
			if rows := l.rows("sr-1", ipA, t0, runOn, ""); len(rows) != 0 {
				t.Errorf("%s: stored before the run is past it: %+v", tc.name, rows)
			}
		}
		rows := l.rows("sr-1", ipA, at, tc.end, "")
		if tc.want == "" {
			if len(rows) != 0 {
				t.Errorf("%s: %+v", tc.name, rows)
			}
			continue
		}
		wantAt := t0
		if tc.want == StepStopped || (tc.want == StepFailed && tc.end == runPanicked) {
			wantAt = at // cut by the end of the run
		}
		if len(rows) != 1 || rows[0].Engine != tc.engine || rows[0].Outcome != tc.want || rows[0].Text != "External scan of "+ipA+": "+tc.text || rows[0].At != store.FormatTS(wantAt) {
			t.Errorf("%s: %+v", tc.name, rows)
		}
		if again := l.rows("sr-1", ipA, at, tc.end, ""); len(again) != 0 {
			t.Errorf("%s: stored twice: %+v", tc.name, again)
		}
	}
	var none *stepLog // a step called outside a run
	none.begin(StepNuclei, false)
	none.end(StepNuclei, callRan, 0, at)
	none.close(StepNuclei)
	if none.rows("sr-1", ipA, at, runEnded, "") != nil {
		t.Fatal("a nil log stored a run")
	}
}

// #863 r1 M1: nuclei or ZAP unavailable in a later run (the scan container down, the module off, ZAP not running) did not run: the
// earlier good run stays on its card.
func TestContract_INV30_AnUnavailableEngineIsNotARun(t *testing.T) {
	t.Parallel()
	for _, engine := range []string{StepNuclei, StepZAP} {
		t.Run(engine, func(t *testing.T) {
			t.Parallel()
			e := stepsEnv(t)
			e.scanIP(gbOpen())
			first := e.engineRuns()
			un := &Unavailable{Reason: "the scan container is not available"}
			if engine == StepZAP {
				e.svc.cfg.Web = &fakeWeb{report: cleanReport, err: un}
			} else {
				e.svc.cfg.Templates = &fakeTemplates{log: &fakeProbeLog{}, err: un}
			}
			e.advance(ScanEvery)
			if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", e.detectedID(ipA)); err != nil {
				t.Fatal(err)
			}
			second := e.engineRuns()
			if second[engine] != first[engine] || second[StepOpenVAS].RunID == first[StepOpenVAS].RunID {
				t.Fatalf("%s: %+v -> %+v (openvas %+v -> %+v)", engine, first[engine], second[engine], first[StepOpenVAS], second[StepOpenVAS])
			}
		})
	}
}

// #863 r1 L4: deleting or ignoring a target removes its engine runs, so Settings › Scanning no longer names it.
func TestContract_INV30_ADeletedTargetLeavesNoEngineRun(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t)
	e.scanIP(gbOpen())
	if len(e.engineRuns()) != 3 {
		t.Fatalf("runs = %+v", e.engineRuns())
	}
	if err := e.svc.Remove(e.ctx(), "admin@acme.example", e.detectedID(ipA), true); err != nil {
		t.Fatal(err)
	}
	if runs := e.engineRuns(); len(runs) != 0 {
		t.Fatalf("after the target was ignored: %+v", runs)
	}
}
