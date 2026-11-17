package exposure

import (
	"testing"
	"time"
)

// Switching the External exposure module off stops an enabled Greenbone (Down, its data kept) and
// switching it on starts it again; a Greenbone that is off is left alone both ways. GreenboneAtStart is the box's start-up call.
func TestContract_INV25_TheModuleSwitchStopsAndStartsGreenbone(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.svc.ModuleSwitched(false) // off while Greenbone is off: nothing
	e.svc.ModuleSwitched(true)
	e.svc.gb().upWG.Wait()
	h.with(func(h *fakeGB) {
		if h.ups != 0 || h.downs != 0 {
			t.Fatalf("ups %d downs %d with Greenbone off", h.ups, h.downs)
		}
	})
	e.enable()
	e.svc.ModuleSwitched(false)
	e.svc.gb().upWG.Wait()
	h.with(func(h *fakeGB) {
		if h.ups != 1 || h.downs != 1 {
			t.Fatalf("after the module off: ups %d downs %d, want 1 and 1", h.ups, h.downs)
		}
	})
	if !e.svc.GreenboneEnabled(e.ctx()) {
		t.Fatal("the module switch turned the setting off")
	}
	e.svc.ModuleSwitched(true)
	e.svc.gb().upWG.Wait()
	e.svc.GreenboneAtStart(e.ctx()) // the box's start-up call: Up again (it is idempotent at the host)
	e.svc.gb().upWG.Wait()
	h.with(func(h *fakeGB) {
		if h.ups != 3 || h.downs != 1 {
			t.Fatalf("after the module on and a start-up: ups %d downs %d, want 3 and 1", h.ups, h.downs)
		}
	})
}

// kf-scan item 6: at a box restart the host answered greenbone.up with 429 rate_limited and OpenVAS stayed "could not be started". An
// Up the host refuses for now (HostBusy) is sent again after a wait until it runs; another failure is still an error at once.
func TestGreenboneUpAtStartIsRetriedWhileTheHostIsBusy(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	e.svc.gb().upRetry = time.Millisecond
	h.with(func(h *fakeGB) {
		h.ups = 0
		h.upErrs = []error{&HostBusy{Reason: "rate_limited", RetryAfter: time.Minute}, &HostBusy{Reason: "busy"}}
	})
	g := e.svc.gb()
	g.mu.Lock()
	g.upAt = time.Time{} // a restarted box: nothing started yet
	g.mu.Unlock()
	e.svc.GreenboneAtStart(e.ctx())
	g.upWG.Wait()
	h.with(func(h *fakeGB) {
		if h.ups != 3 {
			t.Fatalf("ups %d, want 3 (two refused for now, then started)", h.ups)
		}
	})
	g.mu.Lock()
	upErr, started := g.upErr, !g.upAt.IsZero()
	g.mu.Unlock()
	if upErr != "" || !started {
		t.Fatalf("after the retries: error %q, started %v", upErr, started)
	}
	// turned off while it waits: the retries stop
	e.svc.gb().upRetry = time.Hour
	h.with(func(h *fakeGB) { h.ups, h.upErrs = 0, []error{&HostBusy{Reason: "rate_limited"}} })
	g.mu.Lock()
	g.upAt = time.Time{}
	g.mu.Unlock()
	e.svc.GreenboneAtStart(e.ctx())
	if _, err := e.svc.SetGreenbone(e.ctx(), "admin@acme.example", false); err != nil {
		t.Fatal(err)
	}
	g.upWG.Wait()
	h.with(func(h *fakeGB) {
		if h.ups != 1 {
			t.Fatalf("ups %d after the turn-off, want 1", h.ups)
		}
	})
}

// The host's Retry-After lengthens the wait, never past five minutes.
func TestGreenboneUpWaitCapsTheHostsHint(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ backoff, hint, want time.Duration }{
		{15 * time.Second, 0, 15 * time.Second},
		{15 * time.Second, time.Minute, time.Minute},
		{15 * time.Second, 24 * time.Hour, 5 * time.Minute},
		{5 * time.Minute, 0, 5 * time.Minute},
	} {
		if got := upWait(c.backoff, c.hint); got != c.want {
			t.Errorf("upWait(%s, %s) = %s, want %s", c.backoff, c.hint, got, c.want)
		}
	}
}
