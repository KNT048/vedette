package findings

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// manyQuill is quillWorld with n CVEs of Quillfeather Mail 115.9.0 on the workstation, each its own release line to research, in CVE
// order (no CVSS score sets another order).
func manyQuill(t *testing.T, n int) (*env, *fakeChecker, []string) {
	t.Helper()
	e := newEnv(t)
	sw := Software{ID: "s-quill", Display: "Quillfeather Mail", Vendor: "Quillfeather", Product: "Mail", Version: "115.9.0", Source: "agent"}
	e.inv.assets = map[string]AssetView{"pc-01": {ID: "pc-01", Hostname: ptr("pc-01"), IP: "192.0.2.10", Kind: "workstation", Approved: true}}
	e.inv.match = map[string]Asset{"pc-01": {ID: "pc-01", Name: "pc-01", OS: "Microsoft Windows 11 Pro", Software: []Software{sw}}}
	e.feeds.vulns, e.feeds.unlisted = nil, map[string]bool{}
	fc := &fakeChecker{budget: ReadBudget{Auto: true}, pages: map[string][]FetchedPage{}, records: map[string]CVERecordText{}}
	var cves []string
	for i := 1; i <= n; i++ {
		cve := fmt.Sprintf("CVE-2026-99200%d", i)
		cves = append(cves, cve)
		e.feeds.vulns = append(e.feeds.vulns, Vuln{CVE: cve, NVDAnswered: true, Origin: RangeNVD, Affected: []Affected{{CPE: "cpe:2.3:a:quillfeather:mail:-:*:*:*:*:*:*:*"}}})
		e.feeds.unlisted[cve] = true
		fc.records[cve] = CVERecordText{Description: "A flaw in Quillfeather Mail.", Rows: []RecordRow{{Vendor: "quillfeather", Product: "mail", Text: "quillfeather mail: affected before 157.0 [nvd]"}}}
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.svc.SetChecker(fc)
	return e, fc, cves
}

func researchedCVEs(fc *fakeChecker) []string {
	var out []string
	for _, r := range fc.research {
		out = append(out, r.CVE)
	}
	return out
}

// A run that reaches its time window stops between two lines, never during a call: what it researched is stored, the lines left are
// neither failed nor held, and the next run starts with them (the lines whose reading is oldest, never read first) instead of walking the
// lines it read already. The run's state counts the lines with an answer out of all the lines of its CVEs, across runs.
func TestResearch_ARunStopsBetweenLinesAndTheNextGoesOn(t *testing.T) {
	t.Parallel()
	e, fc, cves := manyQuill(t, 5)
	fc.tick = func(ctx context.Context) {
		if ctx.Err() != nil {
			t.Error("a research call was made on an ended context")
		}
		*e.clock = e.clock.Add(possibleCheckWindow/2 + time.Minute) // two calls use up the window
	}
	run := runCheck(t, e)
	if got := researchedCVEs(fc); !slices.Equal(got, cves[:2]) {
		t.Fatalf("first run researched %v, want %v", got, cves[:2])
	}
	if run.Running || run.Stopped == nil || !strings.Contains(*run.Stopped, "next run") || run.Failed != 0 {
		t.Errorf("first run %+v: want a clean stop, nothing failed", run)
	}
	if run.LinesTotal != 5 || run.LinesDone != 2 {
		t.Errorf("first run lines %d of %d, want 2 of 5", run.LinesDone, run.LinesTotal)
	}
	if h := e.svc.heldKeys(e.svc.now()); len(h) != 0 {
		t.Errorf("lines the window left are held: %v", h)
	}
	if n := e.count(`SELECT count(*) FROM fnd_line_statement`); n != 2 {
		t.Errorf("%d readings stored, want 2", n)
	}

	fc.research, fc.recorded = nil, nil
	run = runCheck(t, e)
	if len(fc.recorded) == 0 || fc.recorded[0] != cves[2] {
		t.Errorf("second run read the records in the order %v, want %s first", fc.recorded, cves[2])
	}
	if got := researchedCVEs(fc); !slices.Equal(got, cves[2:4]) {
		t.Errorf("second run researched %v, want %v", got, cves[2:4])
	}
	if run.LinesTotal != 5 || run.LinesDone != 4 {
		t.Errorf("second run lines %d of %d, want 4 of 5", run.LinesDone, run.LinesTotal)
	}

	fc.research = nil
	run = runCheck(t, e)
	if got := researchedCVEs(fc); !slices.Equal(got, cves[4:]) {
		t.Errorf("third run researched %v, want %v", got, cves[4:])
	}
	if run.Stopped != nil || run.LinesDone != 5 || run.LinesTotal != 5 {
		t.Errorf("third run %+v: want the end, 5 of 5 lines", run)
	}
}

// A line whose call timed out is not done: nothing is stored, its error is kept with a retry time, the run goes on with the next line,
// and the automatic reading researches it again once that time has passed.
func TestResearch_ATimedOutLineIsRetriedAtTheNextRun(t *testing.T) {
	t.Parallel()
	e, fc, cves := manyQuill(t, 2)
	timeout := errors.New("the AI provider did not answer Research CVEs in time")
	fc.refuse = map[string]error{cves[0]: timeout}
	run := autoRun(t, e)
	if run.Failed != 1 || run.Readings != 1 || run.LinesDone != 1 || run.LinesTotal != 2 || run.Stopped != nil {
		t.Errorf("run %+v: want the timed-out line failed, the other read", run)
	}
	if n := e.count(`SELECT count(*) FROM fnd_line_statement WHERE cve = '` + cves[0] + `'`); n != 0 {
		t.Error("the timed-out line has a reading")
	}
	e.svc.check.mu.Lock()
	var why string
	for _, h := range e.svc.check.held {
		why = h.reason
	}
	e.svc.check.mu.Unlock()
	if !strings.Contains(why, "in time") {
		t.Errorf("the line's error %q is not kept", why)
	}
	if e.svc.AutoRead(t.Context()) {
		t.Error("the automatic reading asked again before the retry time")
	}
	fc.refuse, fc.research = nil, nil
	*e.clock = e.clock.Add(possibleRetry + time.Minute)
	run = autoRun(t, e)
	if got := researchedCVEs(fc); !slices.Equal(got, cves[:1]) || run.LinesDone != 2 {
		t.Errorf("the next run researched %v (lines %d of %d), want %s again", got, run.LinesDone, run.LinesTotal, cves[0])
	}
}

// autoRun starts the automatic reading and returns its state once it ended.
func autoRun(t *testing.T, e *env) CheckRun {
	t.Helper()
	if !e.svc.AutoRead(t.Context()) {
		t.Fatal("the automatic reading did not start")
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		run, _ := e.svc.CheckStatus(t.Context())
		if run != nil && !run.Running {
			return *run
		}
		if time.Now().After(deadline) {
			t.Fatal("the automatic reading did not finish")
		}
		runtime.Gosched()
	}
}
