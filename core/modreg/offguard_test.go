package modreg_test

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/knt048/vedette/core/modreg"
)

type flag struct{ on atomic.Bool }

func (f *flag) Enabled(string) bool { return f.on.Load() }

var backoff = []time.Duration{10 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute}

func advance(d time.Duration) {
	<-time.After(d)
	synctest.Wait()
}

// D-189: a module that is off at start gets its teardown at once, retried on the backoff until it succeeds, then left alone.
func TestOffGuardRetriesUntilTheTeardownSucceeds(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		g := modreg.NewOffGuard(ctx, &flag{}, slog.New(slog.DiscardHandler), backoff)
		var calls atomic.Int32
		g.Add("x", func(context.Context) error {
			if calls.Add(1) < 5 {
				return errors.New("host busy")
			}
			return nil
		})
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatalf("first attempt: %d calls", calls.Load())
		}
		advance(10 * time.Second) // 1st wait
		advance(30 * time.Second) // 2nd
		advance(2 * time.Minute)  // 3rd
		if calls.Load() != 4 {
			t.Fatalf("after 10 s, 30 s, 2 min: %d calls, want 4", calls.Load())
		}
		advance(9 * time.Minute)
		if calls.Load() != 4 {
			t.Fatalf("the fourth wait is 10 min, not shorter: %d calls", calls.Load())
		}
		advance(time.Minute)
		if calls.Load() != 5 {
			t.Fatalf("5th attempt: %d calls", calls.Load())
		}
		advance(time.Hour)
		if calls.Load() != 5 {
			t.Fatalf("kept calling after success: %d", calls.Load())
		}
		g.Wait()
	})
}

func TestOffGuardLeavesAModuleThatIsOn(t *testing.T) {
	t.Parallel()
	f := &flag{}
	f.on.Store(true)
	g := modreg.NewOffGuard(t.Context(), f, slog.New(slog.DiscardHandler), backoff)
	var calls atomic.Int32
	g.Add("x", func(context.Context) error { calls.Add(1); return nil })
	g.Wait()
	if calls.Load() != 0 {
		t.Fatal("a module that is on was torn down")
	}
}

// Switching off starts the teardown; switching on again cancels a teardown that is still failing.
func TestOffGuardFollowsSwitches(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f := &flag{}
		f.on.Store(true)
		g := modreg.NewOffGuard(ctx, f, slog.New(slog.DiscardHandler), backoff)
		var calls atomic.Int32
		g.Add("x", func(context.Context) error { calls.Add(1); return errors.New("never") })
		synctest.Wait()
		if calls.Load() != 0 {
			t.Fatal("torn down while on")
		}
		f.on.Store(false)
		g.ModuleChanged("x", false)
		synctest.Wait()
		advance(10 * time.Second)
		if calls.Load() != 2 {
			t.Fatalf("after switch-off and one wait: %d calls, want 2", calls.Load())
		}
		f.on.Store(true)
		g.ModuleChanged("x", true)
		g.Wait()
		advance(time.Hour)
		if calls.Load() != 2 {
			t.Fatalf("kept retrying after the module was turned on: %d", calls.Load())
		}
	})
}

func TestOffGuardStopsWithItsContext(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		g := modreg.NewOffGuard(ctx, &flag{}, slog.New(slog.DiscardHandler), []time.Duration{time.Hour})
		var calls atomic.Int32
		g.Add("x", func(context.Context) error { calls.Add(1); return errors.New("never") })
		synctest.Wait()
		cancel()
		g.Wait() // returns: the hour-long wait was cut
		if calls.Load() != 1 {
			t.Fatalf("%d calls", calls.Load())
		}
	})
}
