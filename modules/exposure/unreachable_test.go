package exposure

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// A scan that got no answer from anything while the box itself could not reach the Internet is incomplete: it does not read
// "Done, 0 open services", it says why, and the target keeps the results of its last complete scan.

func (e *env) openServices(id string) int {
	e.t.Helper()
	return e.count(`SELECT count(*) FROM exp_service WHERE target_id = ? AND state = 'open'`, id)
}

// serviceRows is the target's service rows as one string: a scan that touched them (closed one, or counted a miss) changes it.
func (e *env) serviceRows(id string) string {
	e.t.Helper()
	var s string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT coalesce(group_concat(r, ','), '') FROM (SELECT ip || ':' || port || ':' || state || ':' ||
		last_seen || ':' || coalesce(last_run_id, '') AS r FROM exp_service WHERE target_id = ? ORDER BY ip, port)`, id).Scan(&s); err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *env) runStatus(id string) (status, msg string) {
	e.t.Helper()
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT status, coalesce(error, '') FROM core_run WHERE id = ?`, id).Scan(&status, &msg); err != nil {
		e.t.Fatal(err)
	}
	return status, msg
}

func (e *env) newestRun(id string) string {
	e.t.Helper()
	var run string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT x.run_id FROM exp_scan x JOIN core_run r ON r.id = x.run_id WHERE x.target_id = ?
		ORDER BY r.queued_at DESC, r.rowid DESC LIMIT 1`, id).Scan(&run); err != nil {
		e.t.Fatal(err)
	}
	return run
}

func TestContract_AScanThatReachedNothingWhileTheBoxWasOfflineIsIncomplete(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	a := e.committedIP(ipA)
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", a.ID); err != nil {
		t.Fatal(err)
	}
	before, rows := e.openServices(a.ID), e.serviceRows(a.ID)
	if before == 0 {
		t.Fatal("the first scan wrote no service")
	}
	e.advance(ScanEvery)
	e.light(ipA)            // the box's last check saw its IP moments ago
	run.content = Content{} // then every connection fails
	e.prober.offline()      // and the box reaches no public service either
	_, err := e.svc.Scan(e.ctx(), "operator@acme.example", a.ID)
	wantAPI(t, err, 502, "unreachable")
	if !strings.Contains(err.Error(), "could not reach "+ipA) {
		t.Fatalf("the reason: %v", err)
	}
	if got := e.serviceRows(a.ID); got != rows {
		t.Fatalf("the last result was overwritten: %s, had %s", got, rows)
	}
	st, msg := e.runStatus(e.newestRun(a.ID))
	if st != "failed" || !strings.Contains(msg, "could not reach") || !strings.Contains(msg, "incomplete") {
		t.Fatalf("the run: %s %q", st, msg)
	}
	// the box is online again and the target answers nothing at all: that result is real, and it is written
	e.prober.set(ipA)
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", a.ID); err != nil {
		t.Fatalf("an online scan that found nothing open: %v", err)
	}
	if st, _ := e.runStatus(e.newestRun(a.ID)); st != "done" {
		t.Fatalf("an online scan that found nothing open ended %s", st)
	}
}

// The class: every way a scan's results are written treats "could not reach anything" as incomplete.
func TestClass_EveryScanResultWriterKeepsTheLastResultWhenNothingWasReached(t *testing.T) {
	t.Parallel()
	type writer struct {
		name string
		scan func(e *env, id string) error
		make func(e *env) string
	}
	ipTarget := func(e *env) string { return e.committedIP(ipA).ID }
	domainTarget := func(e *env) string { return e.committedDomain().ID }
	scanNow := func(e *env, id string) error {
		_, err := e.svc.Scan(e.ctx(), "operator@acme.example", id)
		return err
	}
	boxRun := func(e *env, id string) error { // a scan the box runs by itself (its schedule): the same run, by the system
		e.acceptTerms(id, false)
		tg, err := loadTarget(e.ctx(), e.db.Reader(), id)
		if err != nil {
			return err
		}
		runID, _, err := e.svc.queueScan(e.ctx(), SystemUser, tg)
		if err != nil {
			return err
		}
		e.waitScan(runID)
		if st, msg := e.runStatus(runID); st != "done" {
			return errors.New(msg)
		}
		return nil
	}
	writers := []writer{
		{"Scan now of an IP", scanNow, ipTarget},
		{"Scan now of a domain", scanNow, domainTarget},
		{"scheduled scan of an IP", boxRun, ipTarget},
		{"scheduled scan of a domain", boxRun, domainTarget},
	}
	overwrote := 0
	for _, w := range writers {
		e := newEnv(t)
		run := &fakeRunner{content: sampleContent()}
		e.svc.SetRunner(run)
		id := w.make(e)
		if err := w.scan(e, id); err != nil {
			t.Fatalf("%s: first scan: %v", w.name, err)
		}
		before := e.serviceRows(id)
		e.advance(ScanEvery + time.Minute)
		e.light(ipA) // the box's last check saw its IP moments ago; then the network goes
		run.content = Content{}
		e.prober.offline()
		err := w.scan(e, id)
		if got := e.serviceRows(id); got != before || err == nil {
			overwrote++
			t.Errorf("%s: the scan ended as done (error %v), service rows %s -> %s", w.name, err, before, got)
		}
	}
	t.Logf("writers that overwrote the last result with an unreachable scan: %d of %d", overwrote, len(writers))
}
