package run_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
)

const coreMigrations = "../../modules/core/migrations/sqlite"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// box is a database and what a process of the box would build on it.
type box struct {
	t     *testing.T
	db    *store.DB
	clock *clock
}

func newBox(t *testing.T) *box {
	t.Helper()
	return &box{t: t, db: storetest.NewMigrated(t, "core", coreMigrations), clock: &clock{t: time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC)}}
}

// gate is a module switch board.
type gate struct {
	mu  sync.Mutex
	off map[string]bool
}

func (g *gate) Enabled(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.off[id]
}

func (g *gate) set(id string, on bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.off == nil {
		g.off = map[string]bool{}
	}
	g.off[id] = !on
}

// process is one start of the box: a Manager with the test kinds registered. ended receives the id of every run whose end
// was recorded.
type process struct {
	*run.Manager
	ended chan string
	seen  map[string]bool // ends received while waiting for another run
}

func (b *box) process(g *gate, kinds ...run.Kind) *process {
	b.t.Helper()
	cfg := run.Config{DB: b.db, Audit: audit.New(b.clock.Now), Clock: b.clock.Now}
	if g != nil {
		cfg.Gate = g
	}
	m, err := run.New(cfg)
	if err != nil {
		b.t.Fatal(err)
	}
	p := &process{Manager: m, ended: make(chan string, 64), seen: map[string]bool{}}
	run.OnEnded(m, func(id string) { p.ended <- id })
	for _, k := range kinds {
		if err := m.Register(k); err != nil {
			b.t.Fatal(err)
		}
	}
	return p
}

func (p *process) start(t *testing.T) {
	t.Helper()
	if err := p.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
}

// waitEnded waits until the end of run id is recorded.
func (p *process) waitEnded(t *testing.T, id string) {
	t.Helper()
	for !p.seen[id] {
		select {
		case got := <-p.ended:
			p.seen[got] = true
		case <-t.Context().Done():
			t.Fatalf("run %s never ended", id)
		}
	}
	delete(p.seen, id)
}

func (b *box) get(p *process, id string) run.Detail {
	b.t.Helper()
	d, err := p.Get(b.t.Context(), id)
	if err != nil {
		b.t.Fatalf("get %s: %v", id, err)
	}
	return d
}

// invariantsHold runs every invariant query and fails on a count other than 0.
func (b *box) invariantsHold() {
	b.t.Helper()
	for _, inv := range run.Invariants {
		var n int
		if err := b.db.Reader().QueryRowContext(b.t.Context(), inv.Query).Scan(&n); err != nil {
			b.t.Fatalf("%s: %v", inv.Name, err)
		}
		if n != 0 {
			b.t.Errorf("%s (%s): %d rows break it", inv.Name, inv.Rule, n)
		}
	}
}

func (b *box) logText(p *process, id string) string {
	b.t.Helper()
	var lines []string
	for _, l := range b.get(p, id).Log {
		lines = append(lines, l.Text)
	}
	return strings.Join(lines, " | ")
}

// gated is a kind whose runs announce they started and end when the test says, or when they are stopped.
type gated struct {
	started chan *run.Exec
	release chan run.Result
}

func newGated() *gated {
	return &gated{started: make(chan *run.Exec, 16), release: make(chan run.Result, 16)}
}

func (g *gated) kind(module, name, lane string, resumable bool) run.Kind {
	return run.Kind{Module: module, Name: name, Lane: lane, Resumable: resumable, Run: func(ctx context.Context, x *run.Exec) (run.Result, error) {
		g.started <- x
		select {
		case r := <-g.release:
			return r, nil
		case <-ctx.Done():
			return run.Result{Status: run.Partial}, nil
		}
	}}
}

func (g *gated) waitStarted(t *testing.T) *run.Exec {
	t.Helper()
	select {
	case x := <-g.started:
		return x
	case <-t.Context().Done():
		t.Fatal("no run started")
		return nil
	}
}

func spec(module, kind, title string) run.Spec {
	return run.Spec{Module: module, Kind: kind, Title: title, Trigger: run.Manual, RequestedBy: "ann@example.com"}
}

func create(t *testing.T, p *process, s run.Spec) string {
	t.Helper()
	id, err := p.Create(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// The database itself refuses a second live run in a lane: the partial unique index, not the dispatcher's bookkeeping.
func TestOneLiveRunPerLaneIsHeldByTheDatabase(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	insert := func(id, lane string, st run.Status) error {
		return b.db.Write(t.Context(), func(tx *sql.Tx) error {
			_, err := tx.ExecContext(t.Context(), `INSERT INTO core_run (id, module, kind, lane, title, trigger, requested_by, status, queued_at, updated_at)
				VALUES (?, 'sensor-active', 'lan_sweep', ?, 'LAN sweep', 'manual', 'system', ?, '2026-03-02T10:00:00.000Z', '2026-03-02T10:00:00.000Z')`, id, lane, string(st))
			return err
		})
	}
	for _, c := range []struct {
		id, lane string
		st       run.Status
		refused  bool
	}{
		{"run-1", "nmap", run.Running, false},
		{"run-2", "nmap", run.Running, true},  // the lane is held
		{"run-3", "nmap", run.Stopping, true}, // stopping holds it too
		{"run-4", "nmap", run.Queued, false},  // the queue is not limited
		{"run-5", "nmap", run.Waiting, false},
		{"run-6", "nuclei", run.Running, false}, // another lane
	} {
		err := insert(c.id, c.lane, c.st)
		if got := store.IsUniqueViolation(err); got != c.refused {
			t.Errorf("%s in lane %s as %s: refused = %v (%v), want %v", c.id, c.lane, c.st, got, err, c.refused)
		}
	}
	// Moving a queued run to running while another runs is refused the same way.
	err := b.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE core_run SET status = 'running' WHERE id = 'run-4'`)
		return err
	})
	if !store.IsUniqueViolation(err) {
		t.Errorf("a second running row in lane nmap by UPDATE: %v, want a unique violation", err)
	}
}

// Runs of one lane go one after the other, oldest first; another lane runs beside them.
func TestTheQueueStartsOneRunPerLaneOldestFirst(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	nmap, nuclei := newGated(), newGated()
	p := b.process(nil, nmap.kind("sensor-active", "lan_sweep", "nmap", false), nuclei.kind("scan", "vuln_check", "nuclei", false))
	first := create(t, p, spec("sensor-active", "lan_sweep", "LAN sweep of 192.0.2.0/24"))
	b.clock.Advance(time.Second)
	second := create(t, p, spec("sensor-active", "lan_sweep", "LAN sweep of 198.51.100.0/24"))
	other := create(t, p, spec("scan", "vuln_check", "Vulnerability checks"))
	p.start(t)

	x1 := nmap.waitStarted(t)
	if x1.ID() != first {
		t.Fatalf("lane nmap started %s, want the oldest %s", x1.ID(), first)
	}
	if x := nuclei.waitStarted(t); x.ID() != other {
		t.Fatalf("lane nuclei started %s, want %s", x.ID(), other)
	}
	if got := b.get(p, second); got.Status != run.Queued {
		t.Fatalf("second run of a busy lane = %s, want queued", got.Status)
	}
	b.invariantsHold()

	nmap.release <- run.Result{}
	p.waitEnded(t, first)
	if x := nmap.waitStarted(t); x.ID() != second {
		t.Fatalf("after the first ended, lane nmap started %s, want %s", x.ID(), second)
	}
	d := b.get(p, first)
	if d.Status != run.Done || d.EndedAt == nil || d.StartedAt == nil || d.CanStop || d.CanResume {
		t.Errorf("first run = %+v, want done with its times and no buttons", d.Run)
	}
	nmap.release <- run.Result{Status: run.Failed, Error: "nmap is not available"}
	nuclei.release <- run.Result{Status: run.Partial, Error: "2 of 3 devices answered"}
	p.waitEnded(t, second)
	p.waitEnded(t, other)
	if d := b.get(p, second); d.Status != run.Failed || d.Error == nil || *d.Error != "nmap is not available" {
		t.Errorf("second run = %s %v, want failed with the error", d.Status, d.Error)
	}
	if d := b.get(p, other); d.Status != run.Partial || !strings.Contains(b.logText(p, other), "Partly done: 2 of 3 devices answered") {
		t.Errorf("other run = %s, log %q", d.Status, b.logText(p, other))
	}
	b.invariantsHold()
}

// sweep is a resumable kind with one step per range: it works through the steps that are not done, and on the second range
// it blocks until it is stopped (or released), so the test can restart the box in the middle.
type sweep struct {
	halfway chan string
	release chan struct{}
	resumed chan bool
}

func (s *sweep) kind(resumable bool) run.Kind {
	return run.Kind{Module: "sensor-active", Name: "lan_sweep", Lane: "nmap", Resumable: resumable, Run: func(ctx context.Context, x *run.Exec) (run.Result, error) {
		d, err := x.Run(ctx)
		if err != nil {
			return run.Result{}, err
		}
		s.resumed <- x.Resumed
		for _, st := range d.Steps {
			if st.Status == run.Done {
				continue // the cursor: a resumed sweep does not sweep a range again
			}
			if err := x.StartStep(ctx, st.Seq); err != nil {
				return run.Result{}, err
			}
			if st.Seq == 2 {
				_ = x.Progress(ctx, st.Seq, 3, st.Total)
				s.halfway <- x.ID()
				select {
				case <-s.release:
				case <-ctx.Done():
					return run.Result{Status: run.Partial}, nil
				}
			}
			if err := x.AddItem(ctx, run.Item{SubjectKind: "device", SubjectID: "a-" + fmt.Sprint(st.Seq), Label: "192.0.2." + fmt.Sprint(st.Seq), Outcome: "found"}); err != nil {
				return run.Result{}, err
			}
			if err := x.Progress(ctx, st.Seq, st.Total, st.Total); err != nil {
				return run.Result{}, err
			}
			if err := x.EndStep(ctx, st.Seq, run.Done, ""); err != nil {
				return run.Result{}, err
			}
		}
		return run.Result{}, nil
	}}
}

func newSweep() *sweep {
	return &sweep{halfway: make(chan string, 4), release: make(chan struct{}, 4), resumed: make(chan bool, 4)}
}

func sweepSpec() run.Spec {
	s := spec("sensor-active", "lan_sweep", "LAN sweep of 192.0.2.0/24, 198.51.100.0/24")
	s.Steps = []run.StepPlan{{Name: "192.0.2.0/24", Total: 256}, {Name: "198.51.100.0/24", Total: 256}}
	return s
}

// A restart keeps every run: a queued run stays queued, a running one is recorded as stopped by the restart, and a resumable
// one is queued again and continues from its cursor; a run a person was stopping ends stopped with the person's reason.
func TestARestartKeepsQueuedRunsStopsRunningOnesAndResumesTheResumable(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	sw, checks, snmp := newSweep(), newGated(), newGated()
	kinds := func(s *sweep) []run.Kind {
		return []run.Kind{s.kind(true), checks.kind("sensor-active", "device_check", "checks", false), snmp.kind("sensor-active", "snmp_read", "snmp", false)}
	}

	// The first process: a sweep halfway through its second range, a device check running, an SNMP read being stopped, and a
	// device check queued behind the running one.
	p1 := b.process(nil, kinds(sw)...)
	sweepID := create(t, p1, sweepSpec())
	checkID := create(t, p1, spec("sensor-active", "device_check", "Check 192.0.2.20"))
	snmpID := create(t, p1, spec("sensor-active", "snmp_read", "SNMP read"))
	b.clock.Advance(time.Second)
	queuedID := create(t, p1, spec("sensor-active", "device_check", "Check 192.0.2.21"))
	if err := p1.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if <-sw.resumed {
		t.Fatal("a fresh run says it was resumed")
	}
	<-sw.halfway
	checks.waitStarted(t)
	snmp.waitStarted(t)
	// The SNMP read is being stopped when the box goes down: hold the executor so it stays stopping.
	if err := b.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE core_run SET status = 'stopping', stop_reason = 'Stopped by ann@example.com' WHERE id = ?`, snmpID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	p1.Close() // the box stops: the rows are left as they are, as after a crash

	for id, want := range map[string]run.Status{sweepID: run.Running, checkID: run.Running, snmpID: run.Stopping, queuedID: run.Queued} {
		if got := b.get(p1, id).Status; got != want {
			t.Fatalf("after the stop, %s = %s, want %s", id, got, want)
		}
	}

	// The next start.
	b.clock.Advance(time.Minute)
	sw2 := newSweep()
	p2 := b.process(nil, kinds(sw2)...)
	if err := p2.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	if d := b.get(p2, queuedID); d.Status != run.Queued {
		t.Errorf("queued run after the restart = %s, want queued", d.Status)
	}
	if d := b.get(p2, checkID); d.Status != run.Stopped || d.StopReason == nil || *d.StopReason != run.RestartReason || d.EndedAt == nil || d.CanResume {
		t.Errorf("running device check after the restart = %+v, want stopped: %s, not resumable", d.Run, run.RestartReason)
	}
	if d := b.get(p2, snmpID); d.Status != run.Stopped || d.StopReason == nil || *d.StopReason != "Stopped by ann@example.com" {
		t.Errorf("stopping SNMP read after the restart = %s %v, want stopped with the person's reason", d.Status, d.StopReason)
	}
	d := b.get(p2, sweepID)
	if d.Status != run.Queued || d.EndedAt != nil || d.StopReason != nil {
		t.Errorf("resumable sweep after the restart = %+v, want queued again", d.Run)
	}
	if lt := b.logText(p2, sweepID); !strings.Contains(lt, "Stopped: "+run.RestartReason) || !strings.Contains(lt, "Queued again") {
		t.Errorf("sweep log = %q, want the restart and the requeue", lt)
	}
	if d.Steps[0].Status != run.Done || d.Steps[1].Status != run.Queued || d.Done != 256+3 || d.Total != 512 {
		t.Errorf("sweep cursor = %+v, %d of %d; want range 1 done, range 2 queued, 259 of 512", d.Steps, d.Done, d.Total)
	}
	var live int
	if err := b.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM core_run WHERE status IN ('running', 'stopping')`).Scan(&live); err != nil || live != 0 {
		t.Errorf("runs running or stopping after recovery = %d (%v), want 0", live, err)
	}
	b.invariantsHold()

	// Started, the sweep continues from its second range and the queued check runs.
	p2.start(t)
	if !<-sw2.resumed {
		t.Error("the requeued sweep does not say it was resumed")
	}
	<-sw2.halfway
	sw2.release <- struct{}{}
	p2.waitEnded(t, sweepID)
	d = b.get(p2, sweepID)
	if d.Status != run.Done || d.Done != 512 || d.ItemsTotal != 2 {
		t.Errorf("resumed sweep = %s, %d of %d, %d items; want done 512 of 512 with one item per range", d.Status, d.Done, d.Total, d.ItemsTotal)
	}
	if x := checks.waitStarted(t); x.ID() != queuedID {
		t.Errorf("the check lane started %s, want the queued check %s", x.ID(), queuedID)
	}
	checks.release <- run.Result{}
	p2.waitEnded(t, queuedID)
	b.invariantsHold()
}

// Stop and Resume as a person uses them: a running run goes stopping then stopped, its steps keep the cursor, Resume queues
// it again; both are audited; an ended run cannot be stopped and a done one cannot be resumed.
func TestStopAndResume(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	sw := newSweep()
	p := b.process(nil, sw.kind(true))
	id := create(t, p, sweepSpec())
	p.start(t)
	<-sw.resumed
	<-sw.halfway
	if err := p.Stop(t.Context(), id, "ann@example.com", ""); err != nil {
		t.Fatal(err)
	}
	p.waitEnded(t, id)
	d := b.get(p, id)
	if d.Status != run.Stopped || d.StopReason == nil || *d.StopReason != "Stopped by ann@example.com" || !d.CanResume || d.CanStop {
		t.Fatalf("stopped sweep = %+v, want stopped by ann, resumable", d.Run)
	}
	if d.Steps[1].Status != run.Stopped {
		t.Errorf("the step that was running = %s, want stopped", d.Steps[1].Status)
	}
	if err := p.Stop(t.Context(), id, "ann@example.com", ""); !errors.Is(err, run.ErrEnded) {
		t.Errorf("stop of a stopped run = %v, want ErrEnded", err)
	}
	if err := p.Resume(t.Context(), id, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	if !<-sw.resumed {
		t.Error("resumed run does not say so")
	}
	<-sw.halfway
	sw.release <- struct{}{}
	p.waitEnded(t, id)
	if d := b.get(p, id); d.Status != run.Done || d.CanResume {
		t.Errorf("resumed sweep = %s (can resume %v), want done", d.Status, d.CanResume)
	}
	if err := p.Resume(t.Context(), id, "bob@example.com"); !errors.Is(err, run.ErrNotResumable) {
		t.Errorf("resume of a done run = %v, want ErrNotResumable", err)
	}
	if _, err := p.Get(t.Context(), "run-nope"); !errors.Is(err, run.ErrNotFound) {
		t.Errorf("get of an unknown run = %v, want ErrNotFound", err)
	}
	rows, err := audit.Find(t.Context(), b.db.Reader(), []string{"scanning.run_stop", "scanning.run_resume"}, id, "0", "9", 10)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, r := range rows {
		actions = append(actions, r.User+" "+r.Action)
	}
	slices.Sort(actions)
	if want := []string{"ann@example.com scanning.run_stop", "bob@example.com scanning.run_resume"}; !slices.Equal(actions, want) {
		t.Errorf("audit = %v, want %v", actions, want)
	}
	b.invariantsHold()
}

// A queued run is stopped at once, and a run under it with it; a run of a kind that cannot go on is not resumable.
func TestStoppingAQueuedRunAndItsChildren(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	busy := newGated()
	p := b.process(nil, busy.kind("exposure", "exposure_scan", "exposure", false), busy.kind("exposure", "zap", "zap", false))
	parent := create(t, p, spec("exposure", "exposure_scan", "Scan of www.example.com"))
	cs := spec("exposure", "zap", "ZAP passive scan")
	cs.ParentID = parent
	child := create(t, p, cs)
	// Not started: both stay queued, and the stop of the parent stops the child.
	if err := p.Stop(t.Context(), parent, run.System, "The target was removed"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{parent, child} {
		d := b.get(p, id)
		if d.Status != run.Stopped || d.StopReason == nil || *d.StopReason != "The target was removed" || d.CanResume {
			t.Errorf("%s = %+v, want stopped with the reason, not resumable", id, d.Run)
		}
	}
	if d := b.get(p, parent); len(d.Children) != 1 || d.Children[0].ID != child {
		t.Errorf("children of the parent = %+v", d.Children)
	}
	b.invariantsHold()
}

// A run that waits frees its lane and says what it waits for; a resume queues it again.
func TestAWaitingRunFreesItsLaneUntilResumed(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	g := newGated()
	p := b.process(nil, g.kind("sensor-active", "lan_sweep", "nmap", true))
	first := create(t, p, spec("sensor-active", "lan_sweep", "LAN sweep of 10.0.0.0/16"))
	b.clock.Advance(time.Second)
	second := create(t, p, spec("sensor-active", "lan_sweep", "LAN sweep of 10.1.0.0/16"))
	p.start(t)
	g.waitStarted(t)
	g.release <- run.Result{Status: run.Waiting, WaitingFor: "the scan window (opens 23:00)"}
	p.waitEnded(t, first)
	d := b.get(p, first)
	if d.Status != run.Waiting || d.WaitingFor == nil || *d.WaitingFor != "the scan window (opens 23:00)" || d.EndedAt != nil || !d.CanResume || !d.CanStop {
		t.Fatalf("waiting run = %+v", d.Run)
	}
	if x := g.waitStarted(t); x.ID() != second {
		t.Fatalf("the free lane started %s, want %s", x.ID(), second)
	}
	g.release <- run.Result{}
	p.waitEnded(t, second)
	if err := p.Resume(t.Context(), first, run.System); err != nil {
		t.Fatal(err)
	}
	if x := g.waitStarted(t); x.ID() != first || !x.Resumed {
		t.Fatalf("resume started %s (resumed %v), want %s resumed", x.ID(), x.Resumed, first)
	}
	g.release <- run.Result{}
	p.waitEnded(t, first)
	if d := b.get(p, first); d.Status != run.Done || d.WaitingFor != nil {
		t.Errorf("resumed waiting run = %s waiting for %v", d.Status, d.WaitingFor)
	}
	b.invariantsHold()
}

// A module that is off starts none of its runs; turning it off stops the ones it has; turning it on starts the queue.
func TestTheModuleSwitch(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	g := &gate{}
	g.set("scan", false)
	k := newGated()
	p := b.process(g, k.kind("scan", "vuln_check", "nuclei", false))
	id := create(t, p, spec("scan", "vuln_check", "Vulnerability checks"))
	p.start(t)
	if err := p.Recover(t.Context()); err != nil { // a write round trip: the dispatcher had its chance
		t.Fatal(err)
	}
	if d := b.get(p, id); d.Status != run.Queued {
		t.Fatalf("run of an off module = %s, want queued", d.Status)
	}
	g.set("scan", true)
	p.ModuleChanged("scan", true)
	k.waitStarted(t)
	g.set("scan", false)
	p.ModuleChanged("scan", false)
	p.waitEnded(t, id)
	if d := b.get(p, id); d.Status != run.Stopped || d.StopReason == nil || *d.StopReason != run.ModuleOffReason {
		t.Errorf("run of a module turned off = %s %v", d.Status, d.StopReason)
	}
	b.invariantsHold()
}

// An error or a panic of the work makes the run failed with words for the run page.
func TestFailuresAreRecorded(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	p := b.process(nil,
		run.Kind{Module: "scan", Name: "boom", Lane: "a", Run: func(context.Context, *run.Exec) (run.Result, error) { panic("boom") }},
		run.Kind{Module: "scan", Name: "err", Lane: "b", Run: func(context.Context, *run.Exec) (run.Result, error) {
			return run.Result{}, errors.New("the scanner did not answer")
		}},
	)
	boom := create(t, p, spec("scan", "boom", "Boom"))
	bad := create(t, p, spec("scan", "err", "Err"))
	p.start(t)
	p.waitEnded(t, boom)
	p.waitEnded(t, bad)
	if d := b.get(p, boom); d.Status != run.Failed || d.Error == nil || *d.Error != "the run stopped on an internal error" {
		t.Errorf("panicking run = %s %v", d.Status, d.Error)
	}
	if d := b.get(p, bad); d.Status != run.Failed || d.Error == nil || *d.Error != "the scanner did not answer" {
		t.Errorf("failing run = %s %v", d.Status, d.Error)
	}
	if _, err := p.Create(t.Context(), spec("scan", "nope", "x")); !errors.Is(err, run.ErrUnknownKind) {
		t.Errorf("create of an unknown kind = %v", err)
	}
	b.invariantsHold()
}

// The log keeps the newest MaxLogLines of a run; Prune drops log lines past KeepLog and runs past KeepRuns; List pages,
// filters and searches.
func TestLogCapRetentionAndList(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	var x *run.Exec
	hold := make(chan struct{})
	got := make(chan struct{})
	p := b.process(nil, run.Kind{Module: "scan", Name: "talk", Lane: "talk", Run: func(_ context.Context, e *run.Exec) (run.Result, error) {
		x = e
		close(got)
		<-hold
		return run.Result{}, nil
	}}, run.Kind{Module: "scan", Name: "quiet", Lane: "quiet", Run: func(context.Context, *run.Exec) (run.Result, error) { return run.Result{}, nil }})
	s := spec("scan", "talk", "Talkative run")
	s.Subject = &run.Subject{Kind: "device", ID: "a-printer", Label: "Office printer"}
	talk := create(t, p, s)
	old := create(t, p, spec("scan", "quiet", "Old quiet run"))
	p.start(t)
	<-got
	p.waitEnded(t, old)
	// A full log, written in one go, then five lines more through the run.
	if err := b.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i + 1 < ?)
			INSERT INTO core_run_log (run_id, ts, level, text) SELECT ?, '2026-03-02T10:00:00.000Z', 'info', 'line ' || i FROM n`, run.MaxLogLines, talk)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for i := run.MaxLogLines; i < run.MaxLogLines+5; i++ {
		if err := x.Log(t.Context(), run.Info, fmt.Sprintf("line %d", i)); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := b.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM core_run_log WHERE run_id = ?`, talk).Scan(&n); err != nil || n != run.MaxLogLines {
		t.Errorf("log lines kept = %d (%v), want %d", n, err, run.MaxLogLines)
	}
	d := b.get(p, talk)
	if len(d.Log) != run.DetailLog || d.Log[len(d.Log)-1].Text != fmt.Sprintf("line %d", run.MaxLogLines+4) {
		t.Errorf("log tail = %d lines ending %q", len(d.Log), d.Log[len(d.Log)-1].Text)
	}
	close(hold)
	p.waitEnded(t, talk)

	// List: newest first, by subject, by search.
	all, total, err := p.List(t.Context(), run.Filter{})
	if err != nil || total != 2 || len(all) != 2 {
		t.Fatalf("list = %d of %d (%v)", len(all), total, err)
	}
	if mine, n, _ := p.List(t.Context(), run.Filter{SubjectKind: "device", SubjectID: "a-printer"}); n != 1 || mine[0].ID != talk || mine[0].Subject.Label != "Office printer" {
		t.Errorf("list by device = %+v", mine)
	}
	if found, n, _ := p.List(t.Context(), run.Filter{Q: "PRINTER"}); n != 1 || found[0].ID != talk {
		t.Errorf("search printer = %d", n)
	}
	if found, n, _ := p.List(t.Context(), run.Filter{Q: "100%_"}); n != 0 || len(found) != 0 {
		t.Errorf("search with wildcards = %d", n)
	}
	if page, n, _ := p.List(t.Context(), run.Filter{Limit: 1, Offset: 1}); n != 2 || len(page) != 1 {
		t.Errorf("page 2 of 1 = %d of %d", len(page), n)
	}

	// Retention.
	b.clock.Advance(run.KeepLog + time.Hour)
	runs, lines, err := p.Prune(t.Context())
	if err != nil || runs != 0 || lines < run.MaxLogLines {
		t.Errorf("prune after 30 days = %d runs, %d lines (%v); want the log only", runs, lines, err)
	}
	b.clock.Advance(run.KeepRuns)
	if runs, _, err := p.Prune(t.Context()); err != nil || runs != 2 {
		t.Errorf("prune after 400 days = %d runs (%v), want 2", runs, err)
	}
	b.invariantsHold()
}

// The invariant queries find what they are about: a run that ended without an end time, two live runs in one lane (only
// possible with the index gone), a run whose totals are not its steps'.
func TestTheInvariantsCountBrokenRows(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	exec := func(q string) {
		t.Helper()
		if err := b.db.Write(t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), q); return err }); err != nil {
			t.Fatal(err)
		}
	}
	const cols = `INSERT INTO core_run (id, module, kind, lane, title, trigger, requested_by, status, waiting_for, ended_at, total, done, queued_at, updated_at) VALUES `
	const ts = `'2026-03-02T10:00:00.000Z'`
	exec(`DROP INDEX core_run_live`)
	exec(cols + `('r1', 'scan', 'k', 'l', 't', 'manual', 'system', 'running', NULL, NULL, 0, 0, ` + ts + `, ` + ts + `),
		('r2', 'scan', 'k', 'l', 't', 'manual', 'system', 'stopping', NULL, NULL, 0, 0, ` + ts + `, ` + ts + `),
		('r3', 'scan', 'k', 'm', 't', 'manual', 'system', 'done', NULL, NULL, 0, 0, ` + ts + `, ` + ts + `),
		('r4', 'scan', 'k', 'm', 't', 'manual', 'system', 'queued', 'x', NULL, 5, 0, ` + ts + `, ` + ts + `),
		('r5', 'scan', 'k', 'm', 't', 'manual', 'system', 'paused', NULL, NULL, 0, 0, ` + ts + `, ` + ts + `)`)
	exec(`INSERT INTO core_run_step (run_id, seq, name, status, total, done) VALUES ('r4', 1, 's', 'queued', 4, 0)`)
	want := map[string]int{
		"runs.one_live_per_lane":              1,
		"runs.ended_have_ended_at":            1,
		"runs.waiting_for_only_while_waiting": 1,
		"runs.known_status":                   1,
		"runs.progress_is_the_sum_of_steps":   1,
	}
	for _, inv := range run.Invariants {
		var n int
		if err := b.db.Reader().QueryRowContext(t.Context(), inv.Query).Scan(&n); err != nil {
			t.Fatalf("%s: %v", inv.Name, err)
		}
		if n != want[inv.Name] {
			t.Errorf("%s = %d, want %d", inv.Name, n, want[inv.Name])
		}
		delete(want, inv.Name)
	}
	if len(want) != 0 {
		t.Errorf("invariants not registered: %v", want)
	}
}

// An off quickly followed by an on stops nothing: the stops read the switch again, off the goroutine that published the change.
func TestAModuleTurnedBackOnKeepsItsRuns(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	g := &gate{}
	p := b.process(g, newGated().kind("scan", "vuln_check", "nuclei", false))
	id := create(t, p, spec("scan", "vuln_check", "Vulnerability checks"))
	p.ModuleChanged("scan", false) // the off, published while the switch already reads on again
	p.Close()                      // waits for the stops of the module
	if d := b.get(p, id); d.Status != run.Queued {
		t.Errorf("run of a module turned off then on = %s %v, want queued", d.Status, d.StopReason)
	}
}

// A running run whose kind gives way (Kind.GiveWay) is told when a run of another kind is queued behind it, after that run is
// committed (a check the holder makes then sees it), never for a run of its own kind or one whose module is off.
func TestTheHolderIsToldToGiveWayAfterTheQueuedRunIsCommitted(t *testing.T) {
	t.Parallel()
	b := newBox(t)
	g := newGated()
	told := make(chan string, 16)
	var seen []string
	weekly := g.kind("sensor-active", "all_ports", "nmap", false)
	weekly.GiveWay = func(ctx context.Context, id string) {
		var n int // the run behind it is committed: a read outside any transaction sees it
		if err := b.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM core_run WHERE status = 'queued' AND kind = 'device_check'`).Scan(&n); err != nil || n == 0 {
			told <- "told before a check was queued and committed"
			return
		}
		told <- id
	}
	gt := &gate{}
	p := b.process(gt, weekly, g.kind("sensor-active", "device_check", "nmap", false), g.kind("scan", "vuln_identify", "nmap", false))
	p.start(t)
	holder := create(t, p, spec("sensor-active", "all_ports", "Scan of every port of printer"))
	g.waitStarted(t)
	create(t, p, spec("sensor-active", "all_ports", "Scan of every port of router")) // its own kind: it waits its turn
	gt.set("scan", false)
	create(t, p, spec("scan", "vuln_identify", "Identification")) // its module is off: it does not start, so nothing gives way to it
	if err := b.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := p.CreateTx(t.Context(), tx, spec("sensor-active", "device_check", "Check of printer"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-told:
		seen = append(seen, got)
	case <-t.Context().Done():
		t.Fatal("the holder was never told to give way")
	}
	if seen[0] != holder {
		t.Fatalf("told %q, want the holder %s", seen[0], holder)
	}
	g.release <- run.Result{Status: run.Partial, Error: "It gave way to other work"}
	p.waitEnded(t, holder)
}
