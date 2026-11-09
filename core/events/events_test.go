package events_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
)

func newBus(t *testing.T, opts ...events.Option) (*events.Bus, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return events.NewBus(slog.New(slog.NewTextHandler(&buf, nil)), opts...), &buf
}

func TestNames(t *testing.T) {
	t.Parallel()
	for _, n := range []string{"core.module.enabled", "findings.finding.status_changed", "auth-oidc.login.failed", "scan.finding.confirmed", "core.os.install_finished"} {
		if !events.ValidName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range []string{"", "core", "core.module", "core.module.enabled.now", "Core.module.enabled", "core.module.", ".module.enabled", "core.mod ule.enabled", "core.module.1st", "core..enabled", "core.module.en-abled", "-core.module.enabled"} {
		if events.ValidName(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
	b, _ := newBus(t)
	if err := b.Publish(t.Context(), events.Event{Name: "bad"}); !errors.Is(err, events.ErrInvalid) {
		t.Errorf("Publish(bad name) = %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Error("Subscribe with a malformed name did not panic")
		}
	}()
	b.Subscribe("bad", func(context.Context, events.Event) error { return nil })
}

func TestPublishDeliversInOrderToMatchingNamesOnly(t *testing.T) {
	t.Parallel()
	b, _ := newBus(t)
	var got []string
	rec := func(tag string) events.Handler {
		return func(_ context.Context, e events.Event) error {
			got = append(got, tag+":"+e.Name+":"+e.Data.(string))
			return nil
		}
	}
	b.Subscribe("core.module.enabled", rec("a"))
	b.Subscribe("core.module.disabled", rec("other"))
	b.Subscribe("core.module.enabled", rec("b"))
	if err := b.Publish(t.Context(), events.Event{Name: "core.module.enabled", Data: "feeds"}); err != nil {
		t.Fatal(err)
	}
	want := "a:core.module.enabled:feeds,b:core.module.enabled:feeds"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %v, want %s", got, want)
	}
	if err := b.Publish(t.Context(), events.Event{Name: "core.module.unwatched"}); err != nil {
		t.Fatal(err) // no subscriber is fine
	}
}

func TestUnsubscribe(t *testing.T) {
	t.Parallel()
	b, _ := newBus(t)
	n := 0
	un := b.Subscribe("a.b.c", func(context.Context, events.Event) error { n++; return nil })
	_ = b.Publish(t.Context(), events.Event{Name: "a.b.c"})
	un()
	un() // idempotent
	_ = b.Publish(t.Context(), events.Event{Name: "a.b.c"})
	if n != 1 {
		t.Fatalf("handler ran %d times, want 1", n)
	}
}

func TestHandlerMayUnsubscribeItselfAndOthers(t *testing.T) {
	t.Parallel()
	b, _ := newBus(t)
	var order []string
	var unA, unB func()
	unA = b.Subscribe("a.b.c", func(context.Context, events.Event) error { order = append(order, "a"); unA(); unB(); return nil })
	unB = b.Subscribe("a.b.c", func(context.Context, events.Event) error { order = append(order, "b"); return nil })
	_ = b.Publish(t.Context(), events.Event{Name: "a.b.c"})
	_ = b.Publish(t.Context(), events.Event{Name: "a.b.c"})
	// The first publish uses a snapshot: b still runs once. The second finds neither.
	if strings.Join(order, "") != "ab" {
		t.Fatalf("order = %v", order)
	}
}

func TestFailingAndPanickingHandlersDoNotBreakThePublisher(t *testing.T) {
	t.Parallel()
	b, logs := newBus(t)
	ran := 0
	b.Subscribe("a.b.c", func(context.Context, events.Event) error { return errors.New("handler error with details") })
	b.Subscribe("a.b.c", func(context.Context, events.Event) error { panic("kaboom") })
	b.Subscribe("a.b.c", func(context.Context, events.Event) error { ran++; return nil })
	if err := b.Publish(t.Context(), events.Event{Name: "a.b.c"}); err != nil {
		t.Fatalf("Publish returned %v; handler failures must not reach the publisher", err)
	}
	if ran != 1 {
		t.Fatalf("later handler ran %d times", ran)
	}
	out := logs.String()
	for _, want := range []string{"event handler failed", "handler error with details", "event handler panicked", "kaboom"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
}

func TestHandlerGetsATimeoutContext(t *testing.T) {
	t.Parallel()
	b, logs := newBus(t, events.WithTimeout(20*time.Millisecond))
	b.Subscribe("a.b.c", func(ctx context.Context, _ events.Event) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("handler context has no deadline")
		}
		<-ctx.Done() // a well-behaved slow handler returns when the deadline passes
		return ctx.Err()
	})
	start := time.Now()
	_ = b.Publish(t.Context(), events.Event{Name: "a.b.c"})
	if time.Since(start) > 5*time.Second {
		t.Fatal("Publish did not return after the handler timeout")
	}
	if !strings.Contains(logs.String(), "deadline exceeded") {
		t.Errorf("timeout not logged:\n%s", logs.String())
	}
}

func TestPublisherCancellationReachesHandlers(t *testing.T) {
	t.Parallel()
	b, _ := newBus(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	seen := false
	b.Subscribe("a.b.c", func(ctx context.Context, _ events.Event) error { seen = ctx.Err() != nil; return nil })
	_ = b.Publish(ctx, events.Event{Name: "a.b.c"})
	if !seen {
		t.Fatal("handler context was not cancelled with the publisher's")
	}
}

func TestOutboxFlushesInOrderAndEmpties(t *testing.T) {
	t.Parallel()
	b, logs := newBus(t)
	var got []string
	b.Subscribe("a.b.one", func(_ context.Context, e events.Event) error { got = append(got, e.Name); return nil })
	b.Subscribe("a.b.two", func(_ context.Context, e events.Event) error { got = append(got, e.Name); return nil })
	var o events.Outbox
	o.Add(events.Event{Name: "a.b.one"})
	o.Add(events.Event{Name: "not a name"})
	o.Add(events.Event{Name: "a.b.two"})
	if o.Len() != 3 {
		t.Fatalf("Len = %d", o.Len())
	}
	b.Flush(t.Context(), &o)
	if strings.Join(got, ",") != "a.b.one,a.b.two" || o.Len() != 0 {
		t.Fatalf("got %v, outbox len %d", got, o.Len())
	}
	if !strings.Contains(logs.String(), "event dropped") {
		t.Errorf("malformed event not logged:\n%s", logs.String())
	}
	b.Flush(t.Context(), &o) // nothing left: no second delivery
	if len(got) != 2 {
		t.Fatalf("flushed twice: %v", got)
	}
}

// The change was already committed when Flush runs, so a client that hung up must not stop the handlers
// that react to it (a dropped event is never replayed).
func TestFlushDeliversEvenWhenTheRequestWasCancelled(t *testing.T) {
	t.Parallel()
	b, _ := newBus(t, events.WithTimeout(time.Second))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var cancelled, hasDeadline bool
	b.Subscribe("a.b.c", func(ctx context.Context, _ events.Event) error {
		cancelled = ctx.Err() != nil
		_, hasDeadline = ctx.Deadline()
		return nil
	})
	var o events.Outbox
	o.Add(events.Event{Name: "a.b.c"})
	b.Flush(ctx, &o)
	if cancelled || !hasDeadline {
		t.Fatalf("handler context cancelled=%v hasDeadline=%v, want false and true", cancelled, hasDeadline)
	}
}

func TestConcurrentSubscribeAndPublish(t *testing.T) {
	t.Parallel()
	b, _ := newBus(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	n := 0
	for range 20 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			un := b.Subscribe("a.b.c", func(context.Context, events.Event) error { mu.Lock(); n++; mu.Unlock(); return nil })
			defer un()
		}()
		go func() {
			defer wg.Done()
			_ = b.Publish(t.Context(), events.Event{Name: "a.b.c"})
		}()
	}
	wg.Wait()
}
