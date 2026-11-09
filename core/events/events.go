// Package events is the in-process event bus modules use to tell each other that something happened
// (feeds.source.fetched, findings.finding.created, core.module.enabled, ...). Names are
// "<module>.<object>.<verb>". There is no global bus: main builds one Bus and hands it to the modules.
//
// Delivery rules:
//   - Publish after the transaction commits, never inside it: a rolled-back change must not be announced.
//     Collect events in an Outbox while the transaction runs and Flush it once Write returned nil.
//   - Handlers run synchronously in subscription order, each under a recover wrapper and a timeout context.
//     A handler that fails, panics or times out is logged and skipped; it never fails the publisher and
//     never stops the other handlers. A handler that ignores its context cannot be interrupted, so it
//     holds the publisher: keep handlers short and hand slow work to a job.
//   - Events are not persisted. A subscriber that must not miss anything reconciles from the database
//     (a job), using the event only as a hint to do it sooner.
package events

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"time"
)

// DefaultTimeout bounds one handler call.
const DefaultTimeout = 5 * time.Second

// ErrInvalid is wrapped by Publish when the event name is malformed.
var ErrInvalid = errors.New("events: invalid event")

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}\.[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$`)

// Event is something that happened. Data is whatever the publishing module documents in its CONTRACT
// (a struct of that module); subscribers type-assert it. Do not put secrets in it: events reach logs.
type Event struct {
	Name string
	Data any
}

// Handler receives an event. ctx carries the handler timeout; honour it.
type Handler func(ctx context.Context, e Event) error

// Option configures a Bus.
type Option func(*Bus)

// WithTimeout sets the per-handler timeout (default DefaultTimeout). d <= 0 is ignored.
func WithTimeout(d time.Duration) Option {
	return func(b *Bus) {
		if d > 0 {
			b.timeout = d
		}
	}
}

type subscription struct {
	id uint64
	fn Handler
}

// Bus delivers events to the handlers subscribed to their name.
type Bus struct {
	log     *slog.Logger
	timeout time.Duration

	mu   sync.RWMutex
	next uint64
	subs map[string][]subscription
}

// NewBus returns an empty bus. log must not be nil.
func NewBus(log *slog.Logger, opts ...Option) *Bus {
	if log == nil {
		panic("events: NewBus: nil logger")
	}
	b := &Bus{log: log, timeout: DefaultTimeout, subs: map[string][]subscription{}}
	for _, o := range opts {
		o(b)
	}
	return b
}

// ValidName reports whether name is a well-formed event name.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// Subscribe registers fn for events called name and returns a function that removes it (safe to call
// more than once, and from inside a handler). A malformed name or nil handler is a programming error and panics.
func (b *Bus) Subscribe(name string, fn Handler) (unsubscribe func()) {
	if !ValidName(name) {
		panic(fmt.Sprintf("events: Subscribe: malformed event name %q", name))
	}
	if fn == nil {
		panic("events: Subscribe: nil handler")
	}
	b.mu.Lock()
	b.next++
	id := b.next
	b.subs[name] = append(b.subs[name], subscription{id: id, fn: fn})
	b.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			cur := b.subs[name]
			kept := make([]subscription, 0, len(cur))
			for _, s := range cur {
				if s.id != id {
					kept = append(kept, s)
				}
			}
			if len(kept) == 0 {
				delete(b.subs, name)
			} else {
				b.subs[name] = kept
			}
		})
	}
}

// Publish delivers e to every handler subscribed to e.Name, in subscription order, and returns when
// all have finished. The only error is a malformed name; handler failures are logged.
func (b *Bus) Publish(ctx context.Context, e Event) error {
	if !ValidName(e.Name) {
		return fmt.Errorf("%w: name %q is not <module>.<object>.<verb>", ErrInvalid, e.Name)
	}
	b.mu.RLock()
	handlers := append([]subscription(nil), b.subs[e.Name]...) // snapshot: handlers may (un)subscribe
	b.mu.RUnlock()
	for _, s := range handlers {
		b.call(ctx, s.fn, e)
	}
	return nil
}

func (b *Bus) call(ctx context.Context, fn Handler, e Event) {
	hctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	defer func() {
		if p := recover(); p != nil {
			b.log.ErrorContext(ctx, "event handler panicked", "event", e.Name, "panic", fmt.Sprint(p))
		}
	}()
	if err := fn(hctx, e); err != nil {
		b.log.WarnContext(ctx, "event handler failed", "event", e.Name, "error", err)
	}
}

// Outbox collects the events of one transaction so they can be published after it commits.
// It is not safe for concurrent use; a transaction function runs on one goroutine.
type Outbox struct{ pending []Event }

// Add queues e. Name errors surface at Flush, so a typo cannot abort the business change.
func (o *Outbox) Add(e Event) { o.pending = append(o.pending, e) }

// Len returns the number of queued events.
func (o *Outbox) Len() int { return len(o.pending) }

// Flush publishes the queued events in order and empties the outbox. Call it after store.DB.Write
// returned nil; when Write failed, drop the outbox. A malformed event is logged and skipped.
func (b *Bus) Flush(ctx context.Context, o *Outbox) {
	pending := o.pending
	o.pending = nil
	for _, e := range pending {
		if err := b.Publish(ctx, e); err != nil {
			b.log.ErrorContext(ctx, "event dropped", "error", err)
		}
	}
}
