package exposure

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// waitRunner starts, says so on in, and then waits until its context ends (a stop) or hold is closed.
type waitRunner struct {
	fakeRunner
	in, hold chan struct{}
}

func (r *waitRunner) Scan(ctx context.Context, t ScanTarget) (Content, error) {
	close(r.in)
	select {
	case <-ctx.Done():
		return Content{}, ctx.Err()
	case <-r.hold:
	}
	return r.fakeRunner.Scan(ctx, t)
}

func scanReady(t *testing.T, e *env) TargetView {
	t.Helper()
	v := e.addVerifiedDomain()
	v, err := e.commit(v.ID)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// INV-18: Scan now answers at once with the run while the scan goes on; Stop ends it, nothing is saved, and the attempt is audited.
func TestScanRun_StartReturnsAtOnceAndStopSavesNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := &waitRunner{fakeRunner: fakeRunner{content: sampleContent()}, in: make(chan struct{}), hold: make(chan struct{})}
	e.svc.SetRunner(r)
	v := scanReady(t, e)

	if e.svc.CurrentScan() != nil {
		t.Fatal("a run before any scan")
	}
	run, err := e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != RunRunning || run.TargetID != v.ID || run.By != "operator@acme.example" || run.SnapshotID != nil {
		t.Fatalf("started run = %+v", run)
	}
	<-r.in
	if cur := e.svc.CurrentScan(); cur == nil || cur.ID != run.ID || cur.Status != RunRunning || cur.Phase != PhaseProbing {
		t.Fatalf("current = %+v", cur)
	}
	if _, err := e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, ""); !errors.Is(err, ErrScanBusy) {
		t.Fatalf("a second scan while one runs: %v", err)
	}
	got, ok := e.svc.StopScan(e.ctx(), "operator@acme.example")
	if !ok || got.Status != RunStopped || got.SnapshotID != nil || got.FinishedAt == nil {
		t.Fatalf("stopped = %+v %v", got, ok)
	}
	if _, ok := e.svc.StopScan(e.ctx(), "operator@acme.example"); ok {
		t.Fatal("stop with nothing running")
	}
	if snaps, _ := e.svc.Snapshots(e.ctx(), v.ID); len(snaps) != 0 {
		t.Fatalf("a stopped scan saved %d snapshots", len(snaps))
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'exposure.scan' AND detail = 'stopped by operator@acme.example'`); n != 1 {
		t.Fatalf("%d audit rows for the stop, want 1", n)
	}
}

// A run that ends with an error says why, in the code and text the synchronous scan answered, and saves nothing.
func TestScanRun_FailureShowsTheErrorAndSavesNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.SetRunner(&fakeRunner{err: ErrCTDown})
	v := scanReady(t, e)
	run, err := e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	e.svc.runMu.Lock()
	cur := e.svc.run
	e.svc.runMu.Unlock()
	<-cur.done
	got := e.svc.CurrentScan()
	if got.ID != run.ID || got.Status != RunFailed || got.Error == nil || got.Error.Code != "unreachable" || !strings.Contains(got.Error.Message, "crt.sh") || got.SnapshotID != nil {
		t.Fatalf("failed run = %+v", got)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'exposure.scan' AND detail LIKE 'not done: unreachable:%'`); n != 1 {
		t.Fatalf("%d audit rows, want 1", n)
	}
}

type panicRunner struct{}

func (panicRunner) Scan(context.Context, ScanTarget) (Content, error) { panic("bad banner") }

// A panic in the runner (it parses untrusted data) ends the run as failed; it does not take the box down or leave it busy for ever.
func TestScanRun_RunnerPanicEndsTheRun(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.SetRunner(panicRunner{})
	v := scanReady(t, e)
	if _, err := e.svc.ScanNow(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, ""); err == nil {
		t.Fatal("a panicking scan reported success")
	}
	got := e.svc.CurrentScan()
	if got.Status != RunFailed || got.Error == nil || got.Error.Code != "internal" {
		t.Fatalf("run = %+v", got)
	}
	e.advance(ScanEvery)
	e.svc.SetRunner(&fakeRunner{content: sampleContent()})
	if _, err := e.svc.ScanNow(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, ""); err != nil {
		t.Fatalf("the box stayed busy: %v", err)
	}
}

// SYS-5: switching the module off stops the run, and a scan whose gate was still running cannot start afterwards; on again, it can.
func TestScanRun_ModuleSwitchOffStopsAndRefuses(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := &waitRunner{fakeRunner: fakeRunner{content: sampleContent()}, in: make(chan struct{}), hold: make(chan struct{})}
	e.svc.SetRunner(r)
	v := scanReady(t, e)
	if _, err := e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, ""); err != nil {
		t.Fatal(err)
	}
	<-r.in
	e.svc.ModuleSwitched(false)
	e.svc.runMu.Lock()
	run := e.svc.run
	e.svc.runMu.Unlock()
	<-run.done
	if got := e.svc.CurrentScan(); got.Status != RunStopped {
		t.Fatalf("run after the switch-off = %+v", got)
	}
	e.advance(ScanEvery)
	_, err := e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, "")
	wantAPI(t, err, 409, "module_off")
	e.svc.ModuleSwitched(true)
	e.svc.SetRunner(&fakeRunner{content: sampleContent()})
	if _, err := e.svc.ScanNow(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, ""); err != nil {
		t.Fatal(err)
	}
}

// Shutting down ends the run with its audit row before the database closes (LEGAL §3), and nothing starts after it.
func TestScanRun_CloseEndsTheRunWithItsAuditRow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := &waitRunner{fakeRunner: fakeRunner{content: sampleContent()}, in: make(chan struct{}), hold: make(chan struct{})}
	e.svc.SetRunner(r)
	v := scanReady(t, e)
	if _, err := e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, ""); err != nil {
		t.Fatal(err)
	}
	<-r.in
	e.svc.Close()
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'exposure.scan' AND detail = 'stopped by the box (shutting down)'`); n != 1 {
		t.Fatalf("%d audit rows, want 1", n)
	}
	_, err := e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, "")
	wantAPI(t, err, 409, "module_off")
}
