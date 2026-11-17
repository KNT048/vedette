package exposure

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// stoppedScan runs a deep scan of ipA whose OpenVAS step stop interrupts (cancelRun for a person's Stop, Close for a shutdown, …) at
// its first poll, and returns the target and the snapshot as the page reads it.
func stoppedScan(t *testing.T, e *env, h *fakeGB, stop func()) (string, Snapshot) {
	t.Helper()
	e.enable()
	e.svc.gb().poll = time.Millisecond
	once := false
	h.gvm.with(func(g *fakeGVM) {
		g.states = []string{"Running"}
		g.onPoll = func() {
			if !once {
				once = true
				stop()
			}
		}
	})
	ips := e.detect(ipA)
	if _, err := e.commit(ips[0].ID); err != nil {
		t.Fatal(err)
	}
	e.acceptTerms(ips[0].ID, false)
	e.svc.SetRunner(&fakeRunner{content: gbOpen()})
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID); err == nil {
		t.Fatal("a stopped run reads as done")
	}
	run := e.svc.CurrentScan()
	snap, err := e.svc.SnapshotOf(e.ctx(), ips[0].ID, run.StartedAt[:10])
	if err != nil {
		t.Fatal(err)
	}
	return ips[0].ID, snap
}

// Every way an OpenVAS step can be stopped stores why and when: a person's Stop (who), the module switched off, a shutdown of
// Vedette (an update), the testing terms withdrawn. The line says why without a time (the page shows ended_at in the viewer's zone),
// the scan's end is that moment, and Settings › Scanning's OpenVAS card says why too.
func TestContract_INV25_AStopSaysWhyAndWhen(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		stop   func(e *env)
		reason string
		by     string
		line   string
	}{
		{"a person's Stop", func(e *env) { e.svc.cancelRun("operator@acme.example") }, StopPerson, "operator@acme.example", "operator@acme.example pressed Stop"},
		{"the module switched off", func(e *env) { e.svc.ModuleSwitched(false) }, StopModule, "", "the External exposure module was switched off"},
		{"a shutdown of Vedette", func(e *env) { go e.svc.Close() }, StopShutdown, "", "Vedette shut down: an update, a restart or a stop of the service"},
		{"the terms withdrawn", func(e *env) {
			go func() { _, _ = e.svc.RevokeTerms(e.ctx(), "owner@acme.example", e.ipTarget()) }()
		}, StopTerms, "owner@acme.example", "the testing terms of this target were withdrawn or lowered by owner@acme.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, h := gbEnv(t)
			var at string
			_, snap := stoppedScan(t, e, h, func() { at = store.FormatTS(e.clock.Now()); tc.stop(e) })
			r := snap.GreenboneRun
			if r.State != GBRunStopped || r.Stop == nil || r.Stop.Reason != tc.reason || (tc.by == "") != (r.Stop.By == nil) || (r.Stop.By != nil && *r.Stop.By != tc.by) {
				t.Fatalf("run %+v, stop %+v", r, r.Stop)
			}
			if r.EndedAt == nil || *r.EndedAt < at || snap.FinishedAt == nil || *snap.FinishedAt != *r.EndedAt || snap.StartedAt > snap.ScannedAt {
				t.Fatalf("ended %v, finished %v, started %s (stop at %s)", r.EndedAt, snap.FinishedAt, snap.StartedAt, at)
			}
			want := "OpenVAS was stopped before it finished (" + tc.line + "), so its results are not shown. The results of the other checks above are kept."
			if !slices.Contains(notChecked(snap), want) {
				t.Fatalf("not checked %q, want %q", notChecked(snap), want)
			}
			runs, err := e.svc.EngineRuns(e.ctx())
			if err != nil {
				t.Fatal(err)
			}
			if c := runs[StepOpenVAS]; c.Outcome != StepStopped || !strings.HasSuffix(c.Text, "stopped while OpenVAS ran ("+tc.line+")") {
				t.Fatalf("OpenVAS card %+v", c)
			}
		})
	}
}

// A step cut in nuclei or ZAP by a shutdown says so on its card: stopped, with why.
func TestContract_INV30_ACutStepSaysWhy(t *testing.T) {
	t.Parallel()
	l := &stepLog{}
	l.begin(StepNuclei, false)
	rows := l.rows("sr-1", ipA, t0, runStopped, stopWhy(&GreenboneStop{Reason: StopShutdown}))
	if len(rows) != 1 || rows[0].Outcome != StepStopped ||
		rows[0].Text != "External scan of "+ipA+": stopped while the templates ran (Vedette shut down: an update, a restart or a stop of the service)" {
		t.Fatalf("rows %+v", rows)
	}
}

// OpenVAS runs again on its own for the newest scan whose step was stopped: the same snapshot gets its outcome (the other results
// stay as they were), its state says it ran again, the scan's end moves to the new end, and the attempt is audited.
func TestContract_INV25_OpenVASAgainReplacesTheStoppedStep(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	id, stopped := stoppedScan(t, e, h, func() { e.svc.cancelRun("admin@acme.example") })
	h.gvm.with(func(g *fakeGVM) { g.states, g.onPoll = []string{"Running", "Done"}, nil })
	e.advance(ScanEvery + time.Minute)
	run, err := e.svc.StartOpenVAS(e.ctx(), Actor{Email: "operator@acme.example"}, id)
	if err != nil {
		t.Fatal(err)
	}
	if !run.OpenVASOnly || run.Status != RunRunning {
		t.Fatalf("run %+v", run)
	}
	e.svc.runMu.Lock()
	done := e.svc.run.done
	e.svc.runMu.Unlock()
	<-done
	end := e.svc.CurrentScan()
	if end.Status != RunDone || end.SnapshotID == nil || *end.SnapshotID != stopped.ID {
		t.Fatalf("end %+v (error %+v)", end, end.Error)
	}
	got, err := e.svc.SnapshotOf(e.ctx(), id, stopped.Date)
	if err != nil {
		t.Fatal(err)
	}
	r := got.GreenboneRun
	if r.State != GBRunDone || !r.Again || r.Stop != nil || r.StartedAt == nil || *r.StartedAt <= *stopped.GreenboneRun.StartedAt || len(got.Greenbone) == 0 {
		t.Fatalf("run %+v, rows %d", r, len(got.Greenbone))
	}
	if got.StartedAt != stopped.StartedAt || got.FinishedAt == nil || *got.FinishedAt != *r.EndedAt || len(got.Ports) != len(stopped.Ports) {
		t.Fatalf("started %s (was %s), finished %v, ports %d", got.StartedAt, stopped.StartedAt, got.FinishedAt, len(got.Ports))
	}
	if slices.ContainsFunc(notChecked(got), func(l string) bool { return strings.Contains(l, "was stopped") || l == gbPending }) {
		t.Fatalf("the stopped line was kept: %q", notChecked(got))
	}
	var rows []string
	for _, a := range e.audits() {
		if a.User == "operator@acme.example" && (a.Action == "exposure.scan" || a.Action == "exposure.greenbone_scan") {
			rows = append(rows, a.Action+" "+a.Detail)
		}
	}
	if len(rows) != 2 || rows[0] != "exposure.scan OpenVAS again, on TCP ports 22, 443 the scan of "+stopped.Date+" found open" || !strings.HasPrefix(rows[1], "exposure.greenbone_scan ") {
		t.Fatalf("audit %q", rows)
	}
	// it finished: there is nothing left to run again
	e.advance(ScanEvery + time.Minute)
	if _, err := e.svc.StartOpenVAS(e.ctx(), Actor{Email: "operator@acme.example"}, id); !errors.Is(err, ErrNothingAgain) {
		t.Fatalf("again after done: %v", err)
	}
}

// OpenVAS again is refused, and audited, when it cannot help: a domain (its deep scan finds the addresses), a scan whose OpenVAS step
// did not start, OpenVAS not ready; and it shares the box's one scan slot and the 10 minutes between two scans of a target.
func TestContract_INV25_OpenVASAgainRefusals(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	id, _ := stoppedScan(t, e, h, func() { e.svc.cancelRun("admin@acme.example") })
	if _, err := e.svc.StartOpenVAS(e.ctx(), Actor{Email: "operator@acme.example"}, id); !isCode(err, "rate_limited") {
		t.Fatalf("within 10 minutes: %v", err)
	}
	e.advance(ScanEvery + time.Minute)
	if _, err := e.svc.SetGreenbone(e.ctx(), "admin@acme.example", false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.StartOpenVAS(e.ctx(), Actor{Email: "operator@acme.example"}, id); !isCode(err, "scanner_unavailable") || !strings.Contains(err.Error(), "OpenVAS cannot run now. Optional deep scan with OpenVAS is off.") {
		t.Fatalf("OpenVAS off: %v", err)
	}
	if !slices.ContainsFunc(e.audits(), func(a auditRow) bool {
		return a.Action == "exposure.scan" && strings.HasPrefix(a.Detail, "OpenVAS again: not done: scanner_unavailable")
	}) {
		t.Fatalf("the refusal is not audited: %+v", e.audits())
	}
	// a domain
	d := e.committedDomain()
	if _, err := e.svc.StartOpenVAS(e.ctx(), Actor{Email: "operator@acme.example"}, d.ID); !errors.Is(err, ErrAgainDomain) {
		t.Fatalf("domain: %v", err)
	}
}

// A scan whose OpenVAS step did not run has nothing to run again.
func TestContract_INV25_OpenVASAgainNeedsAStepThatStarted(t *testing.T) {
	t.Parallel()
	e, _ := gbEnv(t)
	s := e.scanIP(Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https"}}}) // OpenVAS off: not_run
	if s.GreenboneRun.State != GBRunNotRun || s.FinishedAt == nil || *s.FinishedAt != s.ScannedAt {
		t.Fatalf("run %+v, finished %v", s.GreenboneRun, s.FinishedAt)
	}
	e.advance(ScanEvery + time.Minute)
	if _, err := e.svc.StartOpenVAS(e.ctx(), Actor{Email: "operator@acme.example"}, e.ipTarget()); !errors.Is(err, ErrNothingAgain) {
		t.Fatalf("not run: %v", err)
	}
}

// A snapshot's day is a day of the organization's time zone: two scans of one local day are one snapshot, never two that read
// as the same day while another of that day was replaced.
func TestContract_SnapshotDayIsTheOrganizationsDay(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ict := time.FixedZone("ICT", 7*3600)
	e.svc.cfg.Zone = func(context.Context) *time.Location { return ict }
	e.clock.mu.Lock()
	e.clock.now = time.Date(2026, 11, 16, 23, 25, 0, 0, time.UTC) // 06:25 on 17 Nov in ICT
	e.clock.mu.Unlock()
	first := e.scanIP(Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https"}}})
	if first.Date != "2026-11-17" {
		t.Fatalf("day %s", first.Date)
	}
	e.svc.cfg.Zone = func(context.Context) *time.Location { return nil } // no answer: Location
	if got := e.svc.loc(); got != time.UTC {
		t.Fatalf("fallback %v", got)
	}
}

func isCode(err error, code string) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == code
}

// Migration 0013 gives the scans stored before it a start and an end: the start is when the results were stored; the end is the OpenVAS
// check line's time, the store time when OpenVAS did not run, and for the newest scan of a target the target's last_scan_at (which was
// set at the end). last_scan_at then becomes the newest scan's start.
func TestMigration0013GivesEarlierScansTheirTimes(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	before := fstest.MapFS{}
	if err := fs.WalkDir(Migrations, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() >= "0013" {
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
	exec(`INSERT INTO exp_target (id, kind, value, token, created_at, last_scan_at) VALUES ('xt-1', 'ip', '203.0.113.10', '', '2026-11-01T00:00:00.000Z', '2026-11-17T15:43:00.000Z')`)
	snap := func(id, date, scanned, checks, notChecked, gbRun string) {
		exec(`INSERT INTO exp_snapshot (id, target_id, date, scanned_at, hosts, ports, admin_panels, certs, counts, checks, not_checked, greenbone_run)
			VALUES (?, 'xt-1', ?, ?, '[]', '[]', '[]', '[]', '{}', ?, ?, ?)`, id, date, scanned, checks, notChecked, gbRun)
	}
	// 15 Nov: OpenVAS done, its check line at 07:30. 16 Nov: OpenVAS off. 17 Nov (newest): OpenVAS stopped by a shutdown at 15:43.
	snap("sn-15", "2026-11-15", "2026-11-15T06:00:00.000Z", `[{"kind":"greenbone","at":"2026-11-15T07:30:00.000Z","text":"OpenVAS scanned"}]`, `[]`, `{"state":"done"}`)
	snap("sn-16", "2026-11-16", "2026-11-16T06:00:00.000Z", `[]`, `[{"kind":"greenbone","text":"OpenVAS is off."}]`, `{"state":"not_run"}`)
	snap("sn-17", "2026-11-17", "2026-11-17T14:29:00.000Z", `[]`, `[{"kind":"greenbone","text":"`+notGBStopped+`"}]`, `{"state":"stopped"}`)
	// A second target whose OpenVAS step a power loss cut: the old start-up stored it as stopped and never wrote an end, so its
	// last_scan_at is still the store time. Its end is not known: NULL, never "finished when it started".
	exec(`INSERT INTO exp_target (id, kind, value, token, created_at, last_scan_at) VALUES ('xt-2', 'ip', '203.0.113.20', '', '2026-11-01T00:00:00.000Z', '2026-11-17T14:29:00.000Z')`)
	exec(`INSERT INTO exp_snapshot (id, target_id, date, scanned_at, hosts, ports, admin_panels, certs, counts, checks, not_checked, greenbone_run)
		VALUES ('sn-cut', 'xt-2', '2026-11-17', '2026-11-17T14:29:00.000Z', '[]', '[]', '[]', '[]', '{}', '[]', ?, '{"state":"stopped"}')`,
		`[{"kind":"greenbone","text":"`+notGBCutOff+`"}]`)
	if err := store.Migrate(ctx, db, "exposure", Migrations); err != nil {
		t.Fatal(err)
	}
	metas, err := listSnapshotMetas(ctx, db.Reader(), "xt-1")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{
		"sn-15": {"2026-11-15T06:00:00.000Z", "2026-11-15T07:30:00.000Z"},
		"sn-16": {"2026-11-16T06:00:00.000Z", "2026-11-16T06:00:00.000Z"},
		"sn-17": {"2026-11-17T14:29:00.000Z", "2026-11-17T15:43:00.000Z"},
	}
	for _, m := range metas {
		if m.FinishedAt == nil || m.StartedAt != want[m.ID][0] || *m.FinishedAt != want[m.ID][1] {
			t.Errorf("%s: started %s, finished %v, want %v", m.ID, m.StartedAt, m.FinishedAt, want[m.ID])
		}
	}
	var last string
	if err := db.Reader().QueryRowContext(ctx, `SELECT last_scan_at FROM exp_target WHERE id = 'xt-1'`).Scan(&last); err != nil || last != "2026-11-17T14:29:00.000Z" {
		t.Fatalf("last_scan_at %q, %v", last, err)
	}
	// the newest stopped step gets that end as its own stop time
	newest, ok, err := loadSnapshot(ctx, db.Reader(), "xt-1", "2026-11-17")
	if err != nil || !ok || newest.GreenboneRun.EndedAt == nil || *newest.GreenboneRun.EndedAt != "2026-11-17T15:43:00.000Z" {
		t.Fatalf("stopped step %+v, %v", newest.GreenboneRun, err)
	}
	cut, err := listSnapshotMetas(ctx, db.Reader(), "xt-2")
	if err != nil || len(cut) != 1 || cut[0].FinishedAt != nil || cut[0].StartedAt != "2026-11-17T14:29:00.000Z" {
		t.Fatalf("cut by a power loss: %+v, %v", cut, err)
	}
	cutSnap, _, err := loadSnapshot(ctx, db.Reader(), "xt-2", "2026-11-17")
	if err != nil || cutSnap.GreenboneRun.EndedAt != nil {
		t.Fatalf("cut step %+v, %v", cutSnap.GreenboneRun, err)
	}
}

// clockRunner is a port scan that takes d on the test clock, like a real one takes minutes.
type clockRunner struct {
	fakeRunner
	clock *fakeClock
	d     time.Duration
}

func (r *clockRunner) Scan(ctx context.Context, st ScanTarget) (Content, error) {
	r.clock.Advance(r.d)
	return r.fakeRunner.Scan(ctx, st)
}

// A new scan is named by the moment it started, before its port scan: never later than the time of any of its own steps, and its day
// (one snapshot per day) is the day it started, also when its steps end after midnight.
func TestContract_INV34_AScanStartsBeforeItsSteps(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ict := time.FixedZone("ICT", 7*3600)
	e.svc.cfg.Zone = func(context.Context) *time.Location { return ict }
	e.clock.mu.Lock()
	e.clock.now = time.Date(2026, 11, 17, 16, 50, 0, 0, time.UTC) // 23:50 on 17 Nov in ICT
	e.clock.mu.Unlock()
	ips := e.detect(ipA)
	if _, err := e.commit(ips[0].ID); err != nil {
		t.Fatal(err)
	}
	start := store.FormatTS(e.clock.Now())
	e.svc.SetRunner(&clockRunner{fakeRunner: fakeRunner{content: Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https"}}}}, clock: e.clock, d: 30 * time.Minute})
	done, err := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.Date != "2026-11-17" || done.StartedAt != start || done.ScannedAt <= start {
		t.Fatalf("day %s, started %s (pressed %s), stored %s", done.Date, done.StartedAt, start, done.ScannedAt)
	}
	snap, err := e.svc.SnapshotOf(e.ctx(), ips[0].ID, done.Date)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Checks) == 0 {
		t.Fatal("no step recorded a time")
	}
	for _, c := range snap.Checks {
		if c.At < snap.StartedAt {
			t.Errorf("step %s at %s is before the scan's start %s", c.Kind, c.At, snap.StartedAt)
		}
	}
	tg, err := e.svc.Target(e.ctx(), ips[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if tg.LastScanAt == nil || *tg.LastScanAt != start {
		t.Fatalf("last scanned %v, want %s", tg.LastScanAt, start)
	}
}

// Migration 0014 gives a scan stored before 0013 its real start: 0013 named it by its store time, when the steps before OpenVAS had
// all ended (21:29 for a scan whose port scan ended at 21:01). Its start becomes the earliest time one of its steps recorded; a scan
// stored since 0013 keeps its own start, and "Last scanned" follows the newest scan's start.
func TestMigration0014NamesEarlierScansByTheirFirstStep(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	before := fstest.MapFS{}
	if err := fs.WalkDir(Migrations, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() >= "0014" {
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
	exec(`INSERT INTO exp_target (id, kind, value, token, created_at, last_scan_at) VALUES ('xt-1', 'ip', '203.0.113.10', '', '2026-11-01T00:00:00.000Z', '2026-11-17T14:29:30.000Z')`)
	snap := func(id, date, scanned, started, checks string) {
		exec(`INSERT INTO exp_snapshot (id, target_id, date, scanned_at, started_at, hosts, ports, admin_panels, certs, counts, checks, not_checked, greenbone_run)
			VALUES (?, 'xt-1', ?, ?, ?, '[]', '[]', '[]', '[]', '{}', ?, '[]', '{"state":"stopped"}')`, id, date, scanned, started, checks)
	}
	line := func(kind, at string) string {
		return `{"kind":"` + kind + `","at":"` + at + `","text":"` + kind + ` step"}`
	}
	// The steps of a scan in the order they run, each line stamped when its step ended; 0013 took the store time (after "web") as the start.
	steps := []string{line("ports", "2026-11-17T14:01:10.000Z"), line("services", "2026-11-17T14:27:40.000Z"), line("templates", "2026-11-17T14:28:50.000Z"),
		line("web", "2026-11-17T14:29:20.000Z"), line("cve", "2026-11-17T14:29:25.000Z")}
	snap("sn-17", "2026-11-17", "2026-11-17T14:29:30.000Z", "2026-11-17T14:29:30.000Z", "["+strings.Join(steps, ",")+"]")
	// An earlier scan whose lines are out of order, with one element that is not a line and one time that is not a timestamp.
	snap("sn-16", "2026-11-16", "2026-11-15T23:24:00.000Z", "2026-11-15T23:24:00.000Z",
		`[`+line("web", "2026-11-15T23:23:00.000Z")+`,"text",{"kind":"ports","at":"yesterday","text":"x"},`+line("ports", "2026-11-15T23:02:00.000Z")+`]`)
	// No line at all: the store time is the only time it has.
	snap("sn-15", "2026-11-15", "2026-11-14T22:00:00.000Z", "2026-11-14T22:00:00.000Z", `[]`)
	// Stored since 0013: its start is real and earlier than its lines; it is left as it is.
	snap("sn-14", "2026-11-14", "2026-11-13T22:30:00.000Z", "2026-11-13T22:00:00.000Z", "["+line("ports", "2026-11-13T22:10:00.000Z")+"]")
	if err := store.Migrate(ctx, db, "exposure", Migrations); err != nil {
		t.Fatal(err)
	}
	metas, err := listSnapshotMetas(ctx, db.Reader(), "xt-1")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"sn-17": "2026-11-17T14:01:10.000Z", "sn-16": "2026-11-15T23:02:00.000Z", "sn-15": "2026-11-14T22:00:00.000Z", "sn-14": "2026-11-13T22:00:00.000Z"}
	for _, m := range metas {
		if m.StartedAt != want[m.ID] {
			t.Errorf("%s: started %s, want %s", m.ID, m.StartedAt, want[m.ID])
		}
	}
	// What each step recorded and which one the start came from (the evidence of the class: the store time was after every step)
	s, _, err := loadSnapshot(ctx, db.Reader(), "xt-1", "2026-11-17")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range s.Checks {
		from := ""
		if c.At == s.StartedAt {
			from = " <- start"
		}
		t.Logf("%-9s %s%s", c.Kind, c.At, from)
		if c.At < s.StartedAt {
			t.Errorf("step %s at %s is before the start %s", c.Kind, c.At, s.StartedAt)
		}
	}
	t.Logf("stored    %s (the start 0013 gave it)", s.ScannedAt)
	var last string
	if err := db.Reader().QueryRowContext(ctx, `SELECT last_scan_at FROM exp_target WHERE id = 'xt-1'`).Scan(&last); err != nil || last != "2026-11-17T14:01:10.000Z" {
		t.Fatalf("last_scan_at %q, %v", last, err)
	}
}

// A stopped OpenVAS step stored before the reason was kept gets the reason its line proves, from the exact lines older versions
// stored: a waiting line, or the line start-up stored in its place, means Vedette was not running when the step ended (StopRestart),
// and the page reads the line of that reason; the line a running Vedette stored for a Stop, a shutdown, the module switched off or the
// terms withdrawn alike proves none (no reason: the page says it was not recorded), and its stop time is kept.
func TestContract_INV34_OlderStopLinesGiveTheReasonTheyProve(t *testing.T) {
	t.Parallel()
	const (
		stopped     = "OpenVAS was stopped before it finished, so its results are not shown. The results of the other checks above are kept."
		stoppedSome = "OpenVAS was stopped before it had scanned every address; the results of the addresses it finished are shown. The results of the other checks above are kept."
		cut         = "OpenVAS was stopped before it finished (the box restarted or the scan was stopped), so its results are not shown. The results of the other checks above are kept."
		waiting     = "OpenVAS is scanning and runs for up to 90 minutes; its results are added here when it finishes. If none appear, it was stopped before it finished (a stop or a restart of the box)."
		waitingOld  = "OpenVAS started at 14 Nov 2026, 18:16 and runs for up to 90 minutes; its results are added here when it finishes."
		restarted   = "OpenVAS was stopped before it finished (Vedette restarted), so its results are not shown. The results of the other checks above are kept."
		addr        = "8.8.4.4 (www.acme.example): "
	)
	for _, tc := range []struct {
		name, run, line, reason, read string
	}{
		{"a Stop, a shutdown, the module or the terms", `{"state":"stopped","ended_at":"2026-11-17T15:43:00.000Z"}`, stopped, "", stopped},
		{"the same for a domain that kept some rows", `{"state":"stopped"}`, stoppedSome, "", stoppedSome},
		{"cut, as start-up stored it", `{"state":"stopped"}`, cut, StopRestart, restarted},
		{"cut, on an address of a domain", `{"state":"stopped"}`, addr + cut, StopRestart, addr + restarted},
		{"cut, older than the state column", `{}`, waitingOld, StopRestart, restarted},
		{"cut, the waiting line left stopped", `{"state":"stopped"}`, waiting, StopRestart, restarted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			s := e.scanIP(Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https"}}})
			if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
				_, err := tx.ExecContext(e.ctx(), `UPDATE exp_snapshot SET greenbone_run = ?, not_checked = ? WHERE id = ?`,
					tc.run, `[{"kind":"greenbone","text":"`+tc.line+`"}]`, s.ID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			got, err := e.svc.SnapshotOf(e.ctx(), e.ipTarget(), s.Date)
			if err != nil {
				t.Fatal(err)
			}
			r := got.GreenboneRun
			if r.State != GBRunStopped || (tc.reason == "") != (r.Stop == nil) || (r.Stop != nil && (r.Stop.Reason != tc.reason || r.Stop.By != nil)) {
				t.Fatalf("run %+v, stop %+v", r, r.Stop)
			}
			if !slices.Contains(notChecked(got), tc.read) {
				t.Fatalf("not checked %q, want %q", notChecked(got), tc.read)
			}
			if strings.Contains(tc.run, "ended_at") && (r.EndedAt == nil || *r.EndedAt != "2026-11-17T15:43:00.000Z") {
				t.Fatalf("the stop time was lost: %+v", r)
			}
		})
	}
}
