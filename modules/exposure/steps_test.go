package exposure

import (
	"context"
	"database/sql"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
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
		StepNuclei:  "External scan of " + ipA + ": safe templates ran, 1 matched",
		StepZAP:     "External scan of " + ipA + ": ZAP scanned 1 page, 1 alert",
		StepOpenVAS: "External scan of " + ipA + ": OpenVAS found 4 results",
	}
	at := store.FormatTS(t0)
	for engine, text := range want {
		r, ok := runs[engine]
		if !ok || r.Outcome != StepOK || r.Text != text || r.Target != ipA || r.At != at || !strings.HasPrefix(r.RunID, "sr") || r.RunID != runs[StepZAP].RunID {
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
	if n := e.count(`SELECT count(*) FROM exp_snapshot WHERE json_extract(greenbone_run, '$.state') = 'not_run'`); n != 1 {
		t.Fatalf("the second scan's snapshot: %d with OpenVAS not run", n)
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

// INV-30: how the calls of a step make its outcome: all answered ok, some failed partial, none answered failed, a call the stop cut
// stopped, only skipped calls no run; a step is stored once, and one still running waits for the end of the run.
func TestStepLogOutcomes(t *testing.T) {
	t.Parallel()
	at := t0.Add(time.Minute)
	for _, tc := range []struct {
		name  string
		calls []int // callRan, callFailed, callSkipped; -1: begun, never ended
		want  string
		text  string
	}{
		{"ok", []int{callRan, callRan}, StepOK, "ZAP scanned 2 pages, 2 alerts"},
		{"partial", []int{callRan, callFailed}, StepPartial, "ZAP scanned 1 of 2 pages, 1 alert"},
		{"failed", []int{callFailed}, StepFailed, "ZAP could not scan 1 page"},
		{"stopped", []int{callRan, -1}, StepStopped, "stopped while ZAP ran"},
		{"skipped", []int{callSkipped}, "", ""},
	} {
		l := &stepLog{}
		for _, c := range tc.calls {
			l.begin(StepZAP)
			if c >= 0 {
				l.end(StepZAP, c, map[bool]int{true: 1}[c == callRan], at)
			}
		}
		if tc.want == StepStopped {
			if rows := l.rows("sr-1", ipA, t0, false); len(rows) != 0 {
				t.Errorf("%s: stored while it runs: %+v", tc.name, rows)
			}
		}
		rows := l.rows("sr-1", ipA, at, true)
		if tc.want == "" {
			if len(rows) != 0 {
				t.Errorf("%s: %+v", tc.name, rows)
			}
			continue
		}
		if len(rows) != 1 || rows[0].Outcome != tc.want || rows[0].Text != "External scan of "+ipA+": "+tc.text || rows[0].At != store.FormatTS(at) {
			t.Errorf("%s: %+v", tc.name, rows)
		}
		if again := l.rows("sr-1", ipA, at, true); len(again) != 0 {
			t.Errorf("%s: stored twice: %+v", tc.name, again)
		}
	}
	var none *stepLog // a step called outside a run
	none.begin(StepNuclei)
	none.end(StepNuclei, callRan, 0, at)
	if none.rows("sr-1", ipA, at, true) != nil {
		t.Fatal("a nil log stored a run")
	}
}

// Migration 0012 takes the scans stored before it: the newest snapshot in which each step ran, its outcome from the snapshot's lines
// and OpenVAS state. A snapshot where a step did not run (OpenVAS not_run, no web check, templates not needed) is not one.
func TestMigration0012TakesTheEarlierScans(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	before := fstest.MapFS{}
	if err := fs.WalkDir(Migrations, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), "0012") || d.Name() > "0012" {
			return err
		}
		b, err := fs.ReadFile(Migrations, p)
		before[p] = &fstest.MapFile{Data: b}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "exposure", before); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if err := db.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO exp_target (id, kind, value, token, created_at) VALUES ('xt-1', 'ip', '203.0.113.10', '', '2026-11-01T00:00:00.000Z')`)
	snap := func(id, date, checks, notChecked, web, gb, gbRun string) {
		exec(`INSERT INTO exp_snapshot (id, target_id, date, scanned_at, hosts, ports, admin_panels, certs, counts, checks, not_checked, web_findings, greenbone, greenbone_run)
			VALUES (?, 'xt-1', ?, ?, '[]', '[]', '[]', '[]', '{}', ?, ?, ?, ?, ?)`, id, date, date+"T06:00:00.000Z", checks, notChecked, web, gb, gbRun)
	}
	// 15 Nov: every step ran (OpenVAS done with 3 results, ZAP with 4 alerts and one page that failed). 16 Nov: OpenVAS off, no web
	// port, no template needed.
	snap("sn-15", "2026-11-15", `[{"kind":"templates","at":"2026-11-15T06:05:00.000Z","text":"Safe templates for exploited vulnerabilities: 1 job"},
		{"kind":"web","at":"2026-11-15T06:10:00.000Z","text":"Passive web scan"},{"kind":"greenbone","at":"2026-11-15T07:30:00.000Z","text":"OpenVAS scanned"}]`,
		`[{"kind":"web","text":"https://203.0.113.10/: Passive web scan (ZAP) failed, so the page was not checked. The box log has the error."}]`,
		`[{},{},{},{}]`, `[{},{},{}]`, `{"state":"done","started_at":"2026-11-15T06:12:00.000Z","addresses":[]}`)
	snap("sn-16", "2026-11-16", `[{"kind":"templates","at":"2026-11-16T06:05:00.000Z","text":"Safe templates for exploited vulnerabilities: none needed, no identified service matched an exploited CVE."}]`,
		`[{"kind":"greenbone","text":"OpenVAS is off."},{"kind":"web","text":"Passive web scan (ZAP): no web port was identified, so no page was scanned."}]`,
		`[]`, `[]`, `{"state":"not_run","started_at":null,"addresses":[]}`)
	if err := store.Migrate(ctx, db, "exposure", Migrations); err != nil {
		t.Fatal(err)
	}
	runs, err := (&Service{cfg: Config{DB: db}}).EngineRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]EngineRun{
		StepNuclei:  {Engine: StepNuclei, RunID: "sn-15", Target: "203.0.113.10", At: "2026-11-15T06:05:00.000Z", Outcome: StepOK, Text: "External scan of 203.0.113.10: safe templates ran"},
		StepZAP:     {Engine: StepZAP, RunID: "sn-15", Target: "203.0.113.10", At: "2026-11-15T06:10:00.000Z", Outcome: StepPartial, Text: "External scan of 203.0.113.10: ZAP found 4 alerts"},
		StepOpenVAS: {Engine: StepOpenVAS, RunID: "sn-15", Target: "203.0.113.10", At: "2026-11-15T07:30:00.000Z", Outcome: StepOK, Text: "External scan of 203.0.113.10: OpenVAS found 3 results"},
	}
	if len(runs) != len(want) {
		t.Fatalf("runs = %+v", runs)
	}
	for engine, w := range want {
		if runs[engine] != w {
			t.Errorf("%s = %+v, want %+v", engine, runs[engine], w)
		}
	}
}
