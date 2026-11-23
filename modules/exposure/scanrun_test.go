package exposure

import (
	"context"
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

// Scan now answers at once with the queued run while the scan goes on; Stop ends it, nothing is written, and the attempt is audited.
func TestScanRun_StartReturnsAtOnceAndStopSavesNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := &waitRunner{fakeRunner: fakeRunner{content: sampleContent()}, in: make(chan struct{}), hold: make(chan struct{})}
	e.svc.SetRunner(r)
	v := scanReady(t, e)

	if e.svc.CurrentScan(e.ctx()) != nil {
		t.Fatal("a run before any scan")
	}
	run, err := e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if (run.Status != RunQueued && run.Status != RunRunning) || run.TargetID != v.ID || run.By != "operator@acme.example" {
		t.Fatalf("started run = %+v", run)
	}
	<-r.in
	if cur := e.svc.CurrentScan(e.ctx()); cur == nil || cur.ID != run.ID || cur.Status != RunRunning || cur.Phase != PhaseProbing {
		t.Fatalf("current = %+v", cur)
	}
	_, err = e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, "")
	wantAPI(t, err, 409, "busy")
	if _, ok := e.svc.StopScan(e.ctx(), "operator@acme.example"); !ok {
		t.Fatal("nothing to stop")
	}
	e.waitScan(run.ID)
	if got := e.svc.CurrentScan(e.ctx()); got == nil || got.Status != RunStopped || got.FinishedAt == nil {
		t.Fatalf("stopped = %+v", got)
	}
	if _, ok := e.svc.StopScan(e.ctx(), "operator@acme.example"); ok {
		t.Fatal("stop with nothing running")
	}
	if n := e.count(`SELECT count(*) FROM exp_service`) + e.count(`SELECT count(*) FROM exp_host`); n != 0 {
		t.Fatalf("a stopped scan wrote %d rows", n)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'exposure.scan' AND detail = 'stopped by operator@acme.example'`); n != 1 {
		t.Fatalf("%d audit rows for the stop, want 1", n)
	}
}

// A run that ends with an error says why and writes nothing.
func TestScanRun_FailureShowsTheErrorAndSavesNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.SetRunner(&fakeRunner{err: ErrCTDown})
	v := scanReady(t, e)
	run, err := e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	e.waitScan(run.ID)
	got := e.svc.CurrentScan(e.ctx())
	if got.ID != run.ID || got.Status != RunFailed || got.Error == nil || !strings.Contains(got.Error.Message, "crt.sh") {
		t.Fatalf("failed run = %+v", got)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'exposure.scan' AND detail LIKE 'not done: unreachable:%'`); n != 1 {
		t.Fatalf("%d audit rows, want 1", n)
	}
	if n := e.count(`SELECT count(*) FROM exp_host`); n != 0 {
		t.Fatalf("a failed scan wrote %d names", n)
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
	if got := e.svc.CurrentScan(e.ctx()); got.Status != RunFailed || got.Error == nil {
		t.Fatalf("run = %+v", got)
	}
	e.advance(ScanEvery)
	e.svc.SetRunner(&fakeRunner{content: sampleContent()})
	if _, err := e.svc.ScanNow(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, ""); err != nil {
		t.Fatalf("the box stayed busy: %v", err)
	}
}

// SYS-5: switching the module off stops the run and refuses new ones; on again, a scan runs.
func TestScanRun_ModuleSwitchOffStopsAndRefuses(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := &waitRunner{fakeRunner: fakeRunner{content: sampleContent()}, in: make(chan struct{}), hold: make(chan struct{})}
	e.svc.SetRunner(r)
	v := scanReady(t, e)
	run, err := e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	<-r.in
	e.svc.ModuleSwitched(false)
	e.runs.ModuleChanged(ModuleID, false)
	e.waitScan(run.ID)
	if got := e.svc.CurrentScan(e.ctx()); got.Status != RunStopped {
		t.Fatalf("run after the switch-off = %+v", got)
	}
	e.advance(ScanEvery)
	_, err = e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, "")
	wantAPI(t, err, 409, "module_off")
	e.svc.ModuleSwitched(true)
	e.runs.ModuleChanged(ModuleID, true)
	e.svc.SetRunner(&fakeRunner{content: sampleContent()})
	if _, err := e.svc.ScanNow(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, ""); err != nil {
		t.Fatal(err)
	}
}

// Shutting down ends the run with its audit row before the database closes (LEGAL §3), and nothing is queued after it.
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
	e.runs.Close() // the box closes the run manager: the run ends, and the next start records it as stopped by the restart
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'exposure.scan' AND detail = 'stopped by the box (shutting down)'`); n != 1 {
		t.Fatalf("%d audit rows, want 1", n)
	}
	_, err := e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, v.ID, "")
	wantAPI(t, err, 409, "module_off")
}

// A scan that waits in the queue is checked again when it starts: the ownership record removed meanwhile refuses it, and nothing of it
// reaches the runner. Consent and ownership are checked right before anything is sent, never only when the scan was asked.
func TestScanRun_AQueuedScanIsCheckedAgainWhenItStarts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	run := &blockingRunner{fakeRunner: fakeRunner{content: sampleContent()}, hold: make(chan struct{}), in: make(chan struct{})}
	e.svc.SetRunner(run)
	ip := e.detect(ipA)[0]
	if _, err := e.commit(ip.ID); err != nil {
		t.Fatal(err)
	}
	first, err := e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, ip.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	<-run.in
	dom := e.committedDomain()
	queued, err := e.svc.StartScan(e.ctx(), Actor{Email: "operator@acme.example"}, dom.ID, "")
	if err != nil || queued.Status != RunQueued {
		t.Fatalf("queued: %+v %v", queued, err)
	}
	e.dns.put("acme.example") // the TXT record is removed while the scan waits
	close(run.hold)
	e.waitScan(first.ID)
	e.waitScan(queued.ID)
	got, ok, err := e.svc.runOf(e.ctx(), queued.ID)
	if err != nil || !ok || got.Status != RunFailed || got.Error == nil || !strings.Contains(got.Error.Message, "TXT record") {
		t.Fatalf("the queued scan: %+v %v", got, err)
	}
	if run.calls != 1 {
		t.Fatalf("the runner was called %d times, want 1 (the first scan only)", run.calls)
	}
}
