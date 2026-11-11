package scan

import (
	"encoding/json"
	"testing"
	"time"
)

// M2: a worker that does not stop keeps the engine busy: the run shows stopped within 5 s, but no new run starts
// until the engine has returned (POST-2, FORBID-3).
func TestReview_M2_NoNewRunWhileTheEngineIsBusy(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	started := r.eng.blockRuns()
	release := make(chan struct{})
	r.eng.mu.Lock()
	r.eng.stubborn = release
	r.eng.mu.Unlock()
	v := r.start("a-web01")
	<-started
	t0 := time.Now()
	if _, err := r.svc.StopRun(r.ctx(), "it@acme.example", v.ID); err != nil {
		t.Fatal(err)
	}
	r.wait()
	if d := time.Since(t0); d > 5*time.Second || r.run(v.ID).Status != "stopped" {
		t.Fatalf("stopped after %s: %+v", d, r.run(v.ID))
	}
	_, err := r.svc.StartRun(r.ctx(), "it@acme.example", []string{"a-web01"})
	wantAPI(t, err, 409, "already_running")
	close(release)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	timeout := time.After(5 * time.Second)
	for r.svc.engineBusy() {
		select {
		case <-tick.C:
		case <-timeout:
			t.Fatal("the engine stayed busy after the worker returned")
		}
	}
	r.eng.mu.Lock()
	r.eng.stubborn, r.eng.blocked = nil, false
	r.eng.mu.Unlock()
	if _, err := r.svc.StartRun(r.ctx(), "it@acme.example", []string{"a-web01"}); err != nil {
		t.Fatalf("after the engine returned: %v", err)
	}
	r.wait()
}

// D-261 (4): GET /scans/runs says engine_busy while the engine has not returned from a run that already shows stopped,
// so the GUI locks Scan now instead of offering a click that gets 409 already_running.
func TestReview_M2_RunsViewSaysEngineBusyAfterStop(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	h := NewScanHandlers(r.svc)
	busy := func() bool {
		t.Helper()
		out, err := h.ScanGetScansRuns(r.ctx())
		if err != nil {
			t.Fatal(err)
		}
		b, err := out.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			EngineBusy *bool `json:"engine_busy"`
		}
		if err := json.Unmarshal(b, &v); err != nil || v.EngineBusy == nil {
			t.Fatalf("no engine_busy in %s (%v)", b, err)
		}
		return *v.EngineBusy
	}
	if busy() {
		t.Fatal("busy with nothing running")
	}
	started := r.eng.blockRuns()
	release := make(chan struct{})
	r.eng.mu.Lock()
	r.eng.stubborn = release
	r.eng.mu.Unlock()
	v := r.start("a-web01")
	<-started
	if _, err := r.svc.StopRun(r.ctx(), "it@acme.example", v.ID); err != nil {
		t.Fatal(err)
	}
	r.wait()
	if r.run(v.ID).Status != "stopped" || !busy() {
		t.Fatal("the run is stopped but the view does not say the engine is busy")
	}
	close(release)
	for deadline := time.Now().Add(5 * time.Second); r.svc.engineBusy(); {
		if time.Now().After(deadline) {
			t.Fatal("the engine stayed busy after the worker returned")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if busy() {
		t.Fatal("still busy after the engine returned")
	}
}
