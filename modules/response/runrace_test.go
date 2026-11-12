package response_test

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/response"
)

// The window between the reads of runItem and the step being sent (INV-9, INV-19). hookDir is a directory with a one-shot hook that
// runs inside DevicesOfKind: runItem calls it (through the never-touch list) after it read the request and the settings and before it
// claims the item, so the hook runs in exactly that window.
type hookDir struct {
	*fakeDirectory
	mu   sync.Mutex
	hook func()
}

func newHookDir() *hookDir {
	return &hookDir{fakeDirectory: &fakeDirectory{devices: map[string]response.DeviceInfo{}, findings: map[string]response.FindingInfo{}}}
}

func (d *hookDir) arm(f func()) { d.mu.Lock(); d.hook = f; d.mu.Unlock() }

func (d *hookDir) DevicesOfKind(ctx context.Context, kinds ...string) ([]response.DeviceInfo, error) {
	d.mu.Lock()
	h := d.hook
	d.hook = nil
	d.mu.Unlock()
	if h != nil {
		h()
	}
	return d.fakeDirectory.DevicesOfKind(ctx, kinds...)
}

// runsSent counts the device steps of phase "run" that reached the executor.
func runsSent(e *env) int {
	n := 0
	for _, p := range e.exec.phases() {
		if p == "run" {
			n++
		}
	}
	return n
}

// banEnv is a firewall ban rule with one pending request, on an environment whose directory has the hook.
func banEnv(t *testing.T, opts ...func(*response.Config)) (*env, *hookDir, string) {
	t.Helper()
	rd := newHookDir()
	e := newEnv(t, append([]func(*response.Config){func(c *response.Config) { c.Directory = rd }}, opts...)...)
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	return e, rd, e.only().ID
}

func resultOf(it response.RequestItem) string {
	if it.Result == nil {
		return ""
	}
	return *it.Result
}

// INV-19: an item that waited so long that the sweep failed it as "did not start" is not sent afterwards. The claim of the item is a
// compare-and-set: it fails when the item is no longer pending, and runItem then sends nothing. The record and the device agree.
func TestContract_INV19_SweepRacingTheRunNeverLeavesASentStepRecordedAsNotStarted(t *testing.T) {
	e, rd, id := banEnv(t)
	rd.arm(func() {
		e.clock.Advance(11 * time.Minute) // the item waited behind other steps
		if err := e.svc.SweepStuckForTest(context.Background()); err != nil {
			t.Error(err)
		}
	})
	got, err := e.svc.Approve(e.ctx(), oper, id, nil, "")
	e.must(err)
	it := got.Items[0]
	if n := runsSent(e); n != 0 {
		t.Fatalf("%d step(s) sent for an item recorded %s %q", n, it.Status, resultOf(it))
	}
	if it.Status != response.ItemFailed || !strings.Contains(resultOf(it), "did not start") || got.Status != response.StatusFailed {
		t.Fatalf("item %s %q, request %s", it.Status, resultOf(it), got.Status)
	}
	if e.logHas("approved", "Running:") {
		t.Fatal("a Running line for a step that was not sent")
	}
}

// slowExec runs a hook while the step is "in flight" and then answers like the fake executor.
type slowExec struct {
	*fakeExecutor
	inFlight func()
}

func (s *slowExec) Execute(ctx context.Context, st response.DeviceStep) (response.DeviceResult, error) {
	if st.Phase == "run" && s.inFlight != nil {
		f := s.inFlight
		s.inFlight = nil
		f()
	}
	return s.fakeExecutor.Execute(ctx, st)
}

// INV-19: a step that took longer than the sweep allows is recorded "State unknown" by the sweep; when the step then returns, its real
// result replaces that text and the correction is logged (the record says what the device did, not what the sweep feared).
func TestContract_INV19_RealResultReplacesTheSweepsStateUnknown(t *testing.T) {
	var se *slowExec
	e, _, id := banEnv(t, func(c *response.Config) {
		se = &slowExec{fakeExecutor: &fakeExecutor{}}
		c.Executor = se
	})
	se.inFlight = func() {
		e.clock.Advance(5 * time.Minute)
		if err := e.svc.SweepStuckForTest(context.Background()); err != nil {
			t.Error(err)
		}
		if got := e.only(); !strings.Contains(resultOf(got.Items[0]), "State unknown") {
			t.Errorf("the sweep did not record state unknown: %q", resultOf(got.Items[0]))
		}
	}
	got, err := e.svc.Approve(e.ctx(), oper, id, nil, "")
	e.must(err)
	it := got.Items[0]
	if it.Status != response.ItemExecuted || got.Status != response.StatusExecuted || strings.Contains(resultOf(it), "State unknown") || it.RemoveAt == nil {
		t.Fatalf("item %s %q, request %s, remove_at %v", it.Status, resultOf(it), got.Status, it.RemoveAt)
	}
	if !e.logHas("executed", "Correction of the earlier") || !e.logHas("failed", "State unknown") {
		t.Fatal("the correction is not in the log next to the sweep's line")
	}
	if _, err := e.svc.Rollback(e.ctx(), oper, id); err != nil { // an executed item can be undone
		t.Fatal(err)
	}
	if r, err := e.svc.VerifyLog(e.ctx()); err != nil || !r.OK {
		t.Fatalf("verify = %+v, %v", r, err)
	}
}

// INV-9 (M-B): the execution switch, the breaker and the maintenance window are read again inside the transaction that claims the
// item. A stop, a switch-off or a window that commits after runItem read the settings (here: inside the inventory read) still stops
// the step that was about to be sent.
func TestContract_INV9_ClosedGateAfterTheReadsStopsTheStep(t *testing.T) {
	cases := []struct {
		name string
		do   func(e *env)
		code string
	}{
		{"emergency stop", func(e *env) {
			if _, err := e.svc.EmergencyStop(context.Background(), oper); err != nil {
				t.Error(err)
			}
		}, "execution_off"},
		{"execution switched off", func(e *env) {
			if _, err := e.svc.SetExecution(context.Background(), admin, false, ""); err != nil {
				t.Error(err)
			}
		}, "execution_off"},
		{"maintenance window", func(e *env) {
			e.saveSettings(func(in *response.SettingsInput) {
				in.Maintenance = []response.Window{{ID: "w1", Name: "Patch night", Start: e.at(-time.Hour), End: e.at(time.Hour)}}
			})
		}, "maintenance"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, rd, id := banEnv(t)
			rd.arm(func() { c.do(e) })
			got, err := e.svc.Approve(e.ctx(), oper, id, nil, "")
			e.must(err)
			it := got.Items[0]
			if n := runsSent(e); n != 0 {
				t.Fatalf("%d step(s) sent after the gate closed", n)
			}
			if it.Status != response.ItemFailed || !e.logHas("refused", c.code) || e.logHas("approved", "Running:") {
				t.Fatalf("item %s %q; refused %s: %v", it.Status, resultOf(it), c.code, e.logHas("refused", c.code))
			}
		})
	}
}

// INV-9, INV-12 (M-B): a box action goes through the same claim: with the breaker open it adds nothing to the block list.
func TestContract_INV9_BoxActionIsStoppedByTheBreakerAfterTheReads(t *testing.T) {
	rd := newHookDir()
	e := newEnv(t, func(c *response.Config) { c.Directory = rd })
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	id := e.only().ID
	rd.arm(func() {
		if _, err := e.svc.EmergencyStop(context.Background(), oper); err != nil {
			t.Error(err)
		}
	})
	got, err := e.svc.Approve(e.ctx(), oper, id, nil, "")
	e.must(err)
	if got.Items[0].Status != response.ItemFailed || !e.logHas("refused", "circuit_open") || e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 {
		t.Fatalf("item %s %q, block entries %d", got.Items[0].Status, resultOf(got.Items[0]), e.count(`SELECT COUNT(*) FROM resp_block_entries`))
	}
}

// hangExec is an executor that ignores its context until released (a broken one: the Executor contract says it must not).
type hangExec struct {
	release chan struct{}
	started chan struct{}
	mu      sync.Mutex
	calls   int
}

func (h *hangExec) Execute(_ context.Context, s response.DeviceStep) (response.DeviceResult, error) {
	if s.Phase != "run" { // the read before the run answers (D-356); only the write hangs
		return response.DeviceResult{Status: response.StepOK, Detail: "read"}, nil
	}
	h.mu.Lock()
	h.calls++
	h.mu.Unlock()
	select {
	case h.started <- struct{}{}:
	default:
	}
	<-h.release
	return response.DeviceResult{Status: response.StepOK, Detail: "late"}, nil
}

// INV-19 (L6): runItem stops waiting at the item's deadline even when the executor does not: the item is recorded "State unknown",
// the approver gets an answer and the device-step lock is released, so the next item (here: a second request) is not stuck behind it.
func TestContract_INV19_ExecutorThatIgnoresItsContextCannotHoldTheRun(t *testing.T) {
	h := &hangExec{release: make(chan struct{}), started: make(chan struct{}, 4)}
	t.Cleanup(func() { close(h.release) })
	e := newEnv(t, func(c *response.Config) { c.Executor = h })
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}, nil)
	e.svc.SetStepLimitForTest(100 * time.Millisecond)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	e.fire(e.iocEvent("e2", "198.51.100.8"))
	reqs := e.actions()
	if len(reqs) != 2 {
		t.Fatalf("%d requests", len(reqs))
	}
	for i, r := range reqs {
		done := make(chan struct{})
		var got response.ActionRequest
		var err error
		go func() { got, err = e.svc.Approve(context.Background(), oper, r.ID, nil, ""); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("request %d: Approve is still waiting for the executor", i+1)
		}
		e.must(err)
		it := got.Items[0]
		if it.Status != response.ItemFailed || !strings.Contains(resultOf(it), "State unknown") || got.Status != response.StatusFailed {
			t.Fatalf("request %d: item %s %q, request %s", i+1, it.Status, resultOf(it), got.Status)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.calls != 2 {
		t.Fatalf("%d executor calls, want 2", h.calls)
	}
}

func itoaTest(i int) string { return strconv.Itoa(i) }
