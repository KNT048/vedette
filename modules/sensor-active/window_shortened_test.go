package sensoractive_test

import (
	"errors"
	"testing"
	"time"

	sa "github.com/knt048/vedette/modules/sensor-active"
)

// A window SHORTENED while a run is in progress (the person moves "to" earlier, but the
// current time is still inside the new window): the run's deadline came from the OLD end, so without a reaction
// nmap goes on past the new end (INV-3: "only inside the window"). SettingsChanged stops a run whose deadline is
// later than the new end; the stop is ErrStopped (not an attempt). The fake nmap sleeps 30 s; the new window ends
// ~5 s after the change.
func TestWindowShortenedMidRunStopsAtTheNewEnd(t *testing.T) {
	t.Parallel()
	for name, device := range map[string]bool{"sweep": false, "device scan": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, fakeOpts{slowFrom: 1})
			e.base, e.t0 = local(9, 2, 0).Add(55*time.Second), time.Now() // Monday 02:00:55, window 01:00-05:00
			done := make(chan error, 1)
			go func() {
				if device {
					done <- e.svc.ScanDevice(e.ctx(), "a-web", "discovered")
					return
				}
				_, err := e.svc.DiscoverRanges(e.ctx())
				done <- err
			}()
			waitFor(t, "the fake nmap to start", func() bool { return len(e.nm.calls(t)) > 0 })
			changed := time.Now()
			e.inv.set(func(s *sa.Settings) { s.To = "02:01" }) // the window now ends at 02:01:00, ~5 s from now
			if err := e.svc.SettingsChanged(e.ctx()); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if took := time.Since(changed); took > 12*time.Second {
					t.Errorf("the run ended %s after the change (err = %v); the new window ended ~5 s after it", took.Round(time.Second), err)
				}
				if !errors.Is(err, sa.ErrStopped) {
					t.Errorf("err = %v, want ErrStopped", err)
				}
			case <-time.After(15 * time.Second):
				t.Errorf("nmap still running 15 s after the change, ~10 s past the new end of the window (02:01:00)")
				if err := <-done; err != nil { // only waits: the fake nmap must finish before the database closes
					t.Logf("late end: %v", err)
				}
			}
		})
	}
}
