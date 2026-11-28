package findings

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
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
	fc.mu.Lock()
	defer fc.mu.Unlock()
	var out []string
	for _, r := range fc.research {
		out = append(out, r.CVE)
	}
	return out
}

// startWorker runs the research worker until the returned stop is called (which waits for it to return).
func startWorker(t *testing.T, e *env) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		_ = e.svc.ResearchWorker(ctx)
		close(done)
	}()
	return func() {
		cancel()
		<-done
	}
}

func checkRun(t *testing.T, e *env) CheckRun {
	t.Helper()
	run, _ := e.svc.CheckStatus(t.Context())
	if run == nil {
		t.Fatal("no check ran")
	}
	return *run
}

func possibleOf(t *testing.T, e *env, cve string) PossibleItem {
	t.Helper()
	items, err := e.svc.possibleItems(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.CVE == cve {
			return it
		}
	}
	t.Fatalf("%s is not possible", cve)
	return PossibleItem{}
}

// The worker researches every due line as soon as it starts, two CVEs at a time, with no hourly tick: the queue is empty before any
// time passes, and the check's state counts every line answered.
func TestResearchWorker_DrainsTheQueueWithoutTicks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, fc, cves := manyQuill(t, 5)
		start := time.Now()
		stop := startWorker(t, e)
		defer stop()
		synctest.Wait()
		got := researchedCVEs(fc)
		slices.Sort(got)
		if !slices.Equal(got, cves) {
			t.Fatalf("researched %v, want each of %v once", got, cves)
		}
		if waited := time.Since(start); waited != 0 {
			t.Errorf("the queue took %v of the clock to drain, want none", waited)
		}
		if run := checkRun(t, e); run.Running || run.LinesDone != 5 || run.LinesTotal != 5 || run.Readings != 5 || run.Stopped != nil {
			t.Errorf("run %+v: want 5 of 5 lines answered", run)
		}
		<-time.After(3 * time.Hour) // synctest time: the worker rests without asking again
		synctest.Wait()
		if n := len(researchedCVEs(fc)); n != 5 {
			t.Errorf("%d calls after resting, want 5", n)
		}
	})
}

// The research share used up stops the worker after the calls in flight: no new line starts, the reason is in the check's state, the
// possible CVEs show the cause ai_budget, and a wake does not start it again.
func TestResearchWorker_StopsAtTheBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, fc, cves := manyQuill(t, 5)
		fc.stop = &CheckStop{Reason: "The research share of this month's AI budget is used up."}
		stop := startWorker(t, e)
		defer stop()
		synctest.Wait()
		calls := len(researchedCVEs(fc))
		if calls == 0 || calls > researchParallel {
			t.Fatalf("%d calls, want at most the %d in flight", calls, researchParallel)
		}
		run := checkRun(t, e)
		if run.Running || run.Stopped == nil || !strings.Contains(*run.Stopped, "research share") {
			t.Errorf("run %+v: want stopped by the budget", run)
		}
		fc.mu.Lock()
		fc.budget.ResearchReached = true
		fc.mu.Unlock()
		e.svc.wakeResearch()
		<-time.After(2 * time.Hour) // synctest time
		synctest.Wait()
		if n := len(researchedCVEs(fc)); n != calls {
			t.Errorf("%d calls after the stop, want %d", n, calls)
		}
		if c := PossibleCause(possibleOf(t, e, cves[4]), e.svc.ReadState(t.Context())); c != CauseAIBudget {
			t.Errorf("cause %q, want ai_budget", c)
		}
	})
}

// Shutting down while a call runs starts no new call, keeps every answer stored, and leaves the cut line due (not failed, not held):
// a new worker researches it.
func TestResearchWorker_ShutdownKeepsTheQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, fc, cves := manyQuill(t, 4)
		fc.tick = func(ctx context.Context, req ResearchRequest) error {
			if req.CVE == cves[1] {
				<-ctx.Done()
				return ctx.Err()
			}
			return nil
		}
		stop := startWorker(t, e)
		synctest.Wait() // every other line answered beside the long call
		if n := len(researchedCVEs(fc)); n != 4 {
			t.Fatalf("%d calls before the shutdown, want 4 (one still running)", n)
		}
		stop()
		if n := len(researchedCVEs(fc)); n != 4 {
			t.Errorf("%d calls after the shutdown, want no new one", n)
		}
		if n := e.count(`SELECT count(*) FROM fnd_line_statement`); n != 3 {
			t.Errorf("%d readings stored, want the 3 answered", n)
		}
		if n := e.count(`SELECT count(*) FROM fnd_line_statement WHERE cve = '` + cves[1] + `'`); n != 0 {
			t.Error("the cut line has a reading")
		}
		if h := e.svc.heldKeys(e.svc.now()); len(h) != 0 {
			t.Errorf("the cut line is held: %v", h)
		}
		fc.mu.Lock()
		fc.tick, fc.research = nil, nil
		fc.mu.Unlock()
		stop = startWorker(t, e)
		defer stop()
		synctest.Wait()
		if got := researchedCVEs(fc); !slices.Equal(got, cves[1:2]) {
			t.Errorf("the next worker researched %v, want %s", got, cves[1])
		}
	})
}

// One line is never asked twice at once: a person's "Research deeper" of a line being researched is not queued again, two requests in a
// row make one call, and no two calls of one CVE run together, whatever is due beside them.
func TestResearchWorker_OneCallPerLineUnderConcurrency(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, fc, cves := manyQuill(t, 4)
		release := make(chan struct{})
		var mu sync.Mutex
		running, most, perCVE, mostPerCVE := 0, 0, map[string]int{}, 0
		fc.tick = func(_ context.Context, req ResearchRequest) error {
			mu.Lock()
			running++
			perCVE[req.CVE]++
			most, mostPerCVE = max(most, running), max(mostPerCVE, perCVE[req.CVE])
			mu.Unlock()
			if req.CVE == cves[0] && !req.Deeper {
				<-release
			}
			mu.Lock()
			running--
			perCVE[req.CVE]--
			mu.Unlock()
			return nil
		}
		stop := startWorker(t, e)
		defer stop()
		synctest.Wait() // cves[0] is being researched; the others went on beside it
		q := possibleOf(t, e, cves[0]).Question.ID
		for range 2 {
			if _, err := e.svc.StartResearchDeeper(t.Context(), q, "ana@example.com"); err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()
		close(release)
		synctest.Wait()
		count := func() (n int) {
			for _, c := range researchedCVEs(fc) {
				if c == cves[0] {
					n++
				}
			}
			return n
		}
		if n := count(); n != 1 {
			t.Errorf("%d calls for %s while it was being researched, want 1", n, cves[0])
		}
		for range 2 { // not in flight now: two requests in a row are one call
			if _, err := e.svc.StartResearchDeeper(t.Context(), q, "ana@example.com"); err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()
		if n := count(); n != 2 {
			t.Errorf("%d calls for %s after two requests in a row, want 2", n, cves[0])
		}
		if most > researchParallel || mostPerCVE != 1 {
			t.Errorf("%d calls at once (%d of one CVE), want at most %d and 1", most, mostPerCVE, researchParallel)
		}
		if got := len(researchedCVEs(fc)); got != 5 {
			t.Errorf("%d calls in all, want 5", got)
		}
	})
}

// A line whose call timed out is not done: nothing is stored, its error is kept, the others go on, and it is asked again after 1 h, then
// 6 h, with no call in between.
func TestResearchWorker_ATimedOutLineBacksOff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, fc, cves := manyQuill(t, 2)
		fc.refuse = map[string]error{cves[0]: errors.New("the AI provider did not answer Research CVEs in time")}
		stop := startWorker(t, e)
		defer stop()
		synctest.Wait()
		if run := checkRun(t, e); run.Failed != 1 || run.Readings != 1 || run.LinesDone != 1 || run.LinesTotal != 2 || run.Stopped != nil {
			t.Errorf("run %+v: want the timed-out line failed, the other read", run)
		}
		if n := e.count(`SELECT count(*) FROM fnd_line_statement WHERE cve = '` + cves[0] + `'`); n != 0 {
			t.Error("the timed-out line has a reading")
		}
		held := func() heldItem {
			e.svc.check.mu.Lock()
			defer e.svc.check.mu.Unlock()
			for _, h := range e.svc.check.held {
				return h
			}
			return heldItem{}
		}
		if h := held(); !strings.Contains(h.reason, "in time") || h.until.Sub(e.svc.now()) != time.Hour {
			t.Errorf("held %+v: want the error kept and 1 h", h)
		}
		*e.clock = e.clock.Add(30 * time.Minute)
		e.svc.wakeResearch()
		synctest.Wait()
		if n := len(researchedCVEs(fc)); n != 2 {
			t.Errorf("%d calls before the retry time, want 2", n)
		}
		*e.clock = e.clock.Add(31 * time.Minute)
		e.svc.wakeResearch()
		synctest.Wait()
		if n := len(researchedCVEs(fc)); n != 3 {
			t.Fatalf("%d calls after 1 h, want 3", n)
		}
		if h := held(); h.until.Sub(e.svc.now()) != 6*time.Hour {
			t.Errorf("second wait %v, want 6 h", h.until.Sub(e.svc.now()))
		}
		fc.mu.Lock()
		fc.refuse = nil
		fc.mu.Unlock()
		*e.clock = e.clock.Add(6*time.Hour + time.Minute)
		e.svc.wakeResearch()
		synctest.Wait()
		if n := e.count(`SELECT count(*) FROM fnd_line_statement WHERE cve = '` + cves[0] + `'`); n != 1 {
			t.Error("the line was not read after its retry time")
		}
	})
}
