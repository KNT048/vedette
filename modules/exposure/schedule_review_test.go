package exposure

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"testing"
	"time"
)

// hookSafety runs hook once, on the first read of the shared safety block.
type hookSafety struct {
	once sync.Once
	hook func()
}

func (h *hookSafety) ScanSafety(context.Context) (Safety, error) {
	h.once.Do(h.hook)
	return Safety{}, nil
}

// INV-36: terms withdrawn while the checks before a scheduled scan run (here: while the shared safety block is read) are seen when the
// run is registered: no scan starts, in the basic scope or any other, and the target says why.
func TestContract_INV36_TermsWithdrawnDuringTheChecksStopTheStart(t *testing.T) {
	t.Parallel()
	e, _, _ := schedEnv(t)
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	v := e.termsDomain()
	e.svc.cfg.Safety = &hookSafety{hook: func() {
		if _, err := e.svc.RevokeTerms(context.Background(), "admin@acme.example", v.ID); err != nil {
			t.Error(err)
		}
	}}
	e.tick()
	if v = e.target(v.ID); run.calls != 0 || e.svc.CurrentScan() != nil || str(v.Schedule.Note) != "Not scanned on schedule: the testing terms are not accepted" {
		t.Fatalf("%d scans, current %+v, schedule %+v", run.calls, e.svc.CurrentScan(), v.Schedule)
	}
}

// INV-36: a scheduled scan never runs the disruptive checks, even when they are accepted (its mode and ModeNow while it runs), and
// withdrawing the terms stops it; the target then says why it was not scanned.
func TestContract_INV36_ScheduledScanIsNeverDisruptiveAndStopsWithTheTerms(t *testing.T) {
	t.Parallel()
	e, _, _ := schedEnv(t)
	r := &waitRunner{fakeRunner: fakeRunner{content: sampleContent()}, in: make(chan struct{}), hold: make(chan struct{})}
	e.svc.SetRunner(r)
	v := e.committedDomain()
	e.acceptTerms(v.ID, true) // with the disruptive tick
	e.tick()
	<-r.in
	e.svc.runMu.Lock()
	mode := e.svc.run.mode
	e.svc.runMu.Unlock()
	now, err := e.svc.ModeNow(e.ctx(), SystemUser, v.ID)
	if err != nil || !mode.Full || mode.Disruptive || !now.Full || now.Disruptive {
		t.Fatalf("run mode %+v, ModeNow %+v %v", mode, now, err)
	}
	if _, err := e.svc.RevokeTerms(e.ctx(), "admin@acme.example", v.ID); err != nil {
		t.Fatal(err)
	}
	if got := e.waitBoxRun(); got.Status != RunStopped {
		t.Fatalf("run after the terms were withdrawn = %+v", got)
	}
	if v = e.target(v.ID); v.Schedule.NextAt != nil || !strings.HasPrefix(str(v.Schedule.Note), "Not scanned on schedule: ") {
		t.Fatalf("schedule = %+v", v.Schedule)
	}
	e.tick()
	if v = e.target(v.ID); str(v.Schedule.Note) != "Not scanned on schedule: the testing terms are not accepted" {
		t.Fatalf("schedule after a tick = %+v", v.Schedule)
	}
}

// INV-36: a scheduled scan taken out of the queue skips its period (the next tick does not queue it again) and the target says who
// removed it; a schedule turned off while its scan waits drops that scan.
func TestContract_INV36_RemovedOrTurnedOffScheduledScanDoesNotComeBack(t *testing.T) {
	t.Parallel()
	e, w, _ := schedEnv(t)
	w.w.From, w.w.To = "00:00", "00:00"
	r := &waitRunner{fakeRunner: fakeRunner{content: sampleContent()}, in: make(chan struct{}), hold: make(chan struct{})}
	e.svc.SetRunner(r)
	busy := e.detect(ipA)[0] // a Scan now that holds the slot
	if _, err := e.commit(busy.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE exp_target SET scan_every = 'off' WHERE id = ?`, busy.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	v := e.termsDomain()
	if _, err := e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, busy.ID, ""); err != nil {
		t.Fatal(err)
	}
	<-r.in
	e.tick()
	if !e.svc.inQueue(v.ID) {
		t.Fatal("the due target was not queued")
	}
	if err := e.svc.Unqueue(e.ctx(), "operator@acme.example", v.ID); err != nil {
		t.Fatal(err)
	}
	e.advance(time.Minute)
	e.tick()
	if e.svc.inQueue(v.ID) {
		t.Fatal("the removed scheduled scan came back at the next tick")
	}
	v = e.target(v.ID)
	if str(v.Schedule.Note) != "Not scanned on schedule: the scheduled scan was removed from the queue by operator@acme.example" || str(v.Schedule.NextAt) < "2026-11-16" {
		t.Fatalf("schedule = %+v", v.Schedule)
	}
	// L1: queued again a week later, then its schedule is turned off behind its back (no drop): it does not run
	e.advance(7 * 24 * time.Hour)
	e.tick()
	if !e.svc.inQueue(v.ID) {
		t.Fatal("not queued a period later")
	}
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE exp_target SET scan_every = 'off' WHERE id = ?`, v.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.svc.SetRunner(&fakeRunner{content: sampleContent()})
	close(r.hold)
	e.waitBoxRun()
	if e.svc.inQueue(v.ID) || e.count(`SELECT count(*) FROM exp_snapshot WHERE target_id = ?`, v.ID) != 0 {
		t.Fatalf("a scan whose schedule was turned off ran: queued %v, %d snapshots, run %+v", e.svc.inQueue(v.ID), e.count(`SELECT count(*) FROM exp_snapshot WHERE target_id = ?`, v.ID), e.svc.CurrentScan())
	}
}

// INV-36: a scheduled scan that started and failed says so, with the real reason, and the schedule tries again after
// ScheduleFailRetry, not at the next tick (no cooldown answer is stored as its reason).
func TestContract_INV36_FailedScheduledScanSaysWhyAndRetriesWithinTheHour(t *testing.T) {
	t.Parallel()
	e, w, _ := schedEnv(t)
	w.w.From, w.w.To = "00:00", "00:00"
	run := &fakeRunner{err: ErrCTDown}
	e.svc.SetRunner(run)
	v := e.termsDomain()
	e.tick()
	e.waitBoxRun()
	v = e.target(v.ID)
	if run.calls != 1 || !strings.HasPrefix(str(v.Schedule.Note), "Not scanned on schedule: the scheduled scan failed: The certificate-transparency search (crt.sh) did not answer") {
		t.Fatalf("%d scans, schedule %+v", run.calls, v.Schedule)
	}
	e.advance(15 * time.Minute)
	e.tick()
	if run.calls != 1 {
		t.Fatal("tried again before ScheduleFailRetry")
	}
	run.err, run.content = nil, sampleContent()
	e.advance(ScheduleFailRetry)
	e.tick()
	if e.waitBoxRun(); run.calls != 2 {
		t.Fatalf("after the retry time: %d scans", run.calls)
	}
	if v = e.target(v.ID); v.Schedule.Note != nil {
		t.Fatalf("a scan that ran still has a note: %+v", v.Schedule)
	}
}

// INV-36: before anything ran since the box started, GET /exposure/scan shows the scans that wait.
func TestContract_INV36_CurrentScanShowsTheQueueBeforeAnyRun(t *testing.T) {
	t.Parallel()
	e, _, _ := schedEnv(t)
	e.svc.spawn = func(func()) {} // the first queued scan's checks do not start
	v := e.termsDomain()
	e.tick()
	cur := e.svc.CurrentScan()
	if cur == nil || cur.Status != RunQueued || cur.TargetID != v.ID || !cur.Scheduled || len(cur.Queue) != 1 || !cur.Queue[0].Starting {
		t.Fatalf("current = %+v", cur)
	}
}

// INV-36: a domain whose names move to other addresses (a CDN, a load balancer) is not news; a port newly open on a name is.
func TestSchedule_DomainAddressRotationIsNotNews(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	prev := Snapshot{StartedAt: "2026-11-02T10:00:00.000Z"}
	prev.Hosts = []HostRow{{Name: "www.acme.example", IP: ipA}}
	prev.Ports = []PortRow{{IP: ipA, Port: 443, Service: "https"}}
	now := Snapshot{ID: "sn-2", StartedAt: "2026-11-09T10:00:00.000Z"}
	now.Hosts = []HostRow{{Name: "www.acme.example", IP: ipB}}
	now.Ports = []PortRow{{IP: ipB, Port: 443, Service: "https"}}
	if cs := e.svc.changes(e.ctx(), prev, now, t0, true); len(cs) != 0 {
		t.Fatalf("a moved address alerted: %+v", cs)
	}
	if cs := e.svc.changes(e.ctx(), prev, now, t0, false); len(cs) != 1 {
		t.Fatalf("an IP target's new address:port is new: %+v", cs)
	}
	now.Ports = append(now.Ports, PortRow{IP: ipB, Port: 8443, Service: "https-alt"})
	cs := e.svc.changes(e.ctx(), prev, now, t0, true)
	if len(cs) != 1 || !strings.Contains(cs[0].line, ipB+":8443") {
		t.Fatalf("a new port on the name: %+v", cs)
	}
	// admin pages: the same page on the moved address is not news; another page on the same name and port is
	now.Ports = now.Ports[:1]
	prev.AdminPanels = []AdminRow{{URL: "https://" + ipA + "/wp-admin/", Product: "WordPress", IP: ipA, Port: 443, Risk: "warn"}}
	now.AdminPanels = []AdminRow{{URL: "https://" + ipB + "/wp-admin/", Product: "WordPress", IP: ipB, Port: 443, Risk: "warn"}}
	if cs := e.svc.changes(e.ctx(), prev, now, t0, true); len(cs) != 0 {
		t.Fatalf("a moved admin page alerted: %+v", cs)
	}
	now.AdminPanels = append(now.AdminPanels, AdminRow{URL: "https://" + ipB + "/phpmyadmin/", Product: "phpMyAdmin", IP: ipB, Port: 443, Risk: "danger"})
	if cs := e.svc.changes(e.ctx(), prev, now, t0, true); len(cs) != 1 || !strings.Contains(cs[0].line, "/phpmyadmin/") {
		t.Fatalf("a new page on a known name and port: %+v", cs)
	}
}
