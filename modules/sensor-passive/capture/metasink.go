package capture

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
)

// MetadataPoster is the part of the sensor link that carries SPAN metadata to core; *sensorlink.Client implements it.
type MetadataPoster interface {
	PostMetadata(ctx context.Context, req *sensorlink.MetadataRequest) error
}

// The bounds of LinkMetadata.
const (
	// metaRepeat is how long an item that was delivered is not sent again: a device that keeps asking for the same name, or keeps
	// a flow to the same address, is matched once in this time (core keeps one hit per device and destination a day anyway). A
	// destination that a feed starts to list is matched at the device's next contact after this time.
	metaRepeat = 10 * time.Minute
	// metaPostEvery is the least time between two metadata requests: two per five seconds, a small part of the passive role's
	// request rate (sensorlink.RatePerSecond), so the observations and the heartbeat always find room.
	metaPostEvery = 5 * time.Second / sensorlink.MetadataPostsPerFlush
	// maxMetaPending is how many items wait for delivery; past it new items are dropped and counted.
	maxMetaPending = 10 * sensorlink.MaxMetadataItems
	// maxMetaSent is how many delivered items are remembered for metaRepeat; past it the oldest are forgotten.
	maxMetaSent = 50_000
	// maxMetaTries is how many times a batch core answers store_busy for is offered before it is dropped: that answer can be about
	// the batch (its matching could not be stored or finished), and a batch that never goes through must not hold up the rest.
	maxMetaTries = 5
)

type metaKey struct{ kind, src, dest string }

// LinkMetadata is the MetadataSink of the sensor binary: it reduces what the Engine extracted to what core's bad-address
// matching needs (which LAN address asked for which name, or opened a flow to which public address), keeps each of these once,
// and posts them to core over the sensor link from its own goroutine (Run), never from the capture loop: a slow core never holds
// up the reading of packets. Requests are paced by time (metaPostEvery) and wait as long as core's Retry-After asks, so the
// mirror port never takes the request budget the observations and the heartbeat need. Nothing else of a packet leaves the
// sensor: no port, no counter, no resolver address. What core cannot take now waits in a bounded queue.
type LinkMetadata struct {
	post  MetadataPoster
	clock func() time.Time
	wake  chan struct{}

	mu      sync.Mutex
	pending []sensorlink.MetadataItem
	queued  map[metaKey]bool
	sent    map[metaKey]time.Time
	lost    int   // items dropped since the last Metadata call (queue full, refused by core): Metadata reports them
	lastErr error // why the last of them were dropped
	tries   int   // store_busy answers in a row for the batch at the head of the queue
}

// NewLinkMetadata returns the sink that posts through p once Run is started. clock nil means time.Now.
func NewLinkMetadata(p MetadataPoster, clock func() time.Time) *LinkMetadata {
	if clock == nil {
		clock = time.Now
	}
	return &LinkMetadata{post: p, clock: clock, wake: make(chan struct{}, 1), queued: map[metaKey]bool{}, sent: map[metaKey]time.Time{}}
}

// Pending says how many items wait for delivery.
func (l *LinkMetadata) Pending() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.pending)
}

// errMetaLost says that metadata items were dropped.
var errMetaLost = errors.New("capture: metadata items dropped")

// Metadata implements MetadataSink: it queues the items (never waits for the network) and wakes Run. It returns an error when items
// were dropped since its last call (the queue was full, or core refused a batch for good); the Runner counts and logs it.
func (l *LinkMetadata) Metadata(_ context.Context, _ uint64, items []MetaItem) error {
	l.mu.Lock()
	now := l.clock()
	l.forget(now)
	for _, it := range items {
		w, ok := wireMeta(it)
		if !ok {
			continue
		}
		k := metaKey{w.Kind, w.Src, w.Dest}
		if l.queued[k] {
			continue
		}
		if at, ok := l.sent[k]; ok && now.Sub(at) < metaRepeat {
			continue
		}
		if len(l.pending) >= maxMetaPending {
			l.lost++
			l.lastErr = errors.New("the queue is full")
			continue
		}
		l.queued[k] = true
		l.pending = append(l.pending, w)
	}
	lost, why := l.lost, l.lastErr
	l.lost, l.lastErr = 0, nil
	l.mu.Unlock()
	select {
	case l.wake <- struct{}{}:
	default:
	}
	if lost > 0 {
		return fmt.Errorf("%w: %d (%w)", errMetaLost, lost, why)
	}
	return nil
}

// Run posts the queue until ctx ends: one batch of at most sensorlink.MaxMetadataItems at a time, metaPostEvery apart at least,
// longer when core asks (Retry-After) or cannot be reached (doubling up to sensorlink.BackoffCap).
func (l *LinkMetadata) Run(ctx context.Context) error {
	failures := 0
	var wait time.Duration
	for {
		if wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil
			case <-t.C:
			}
		}
		batch := l.head()
		if len(batch) == 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-l.wake:
			}
			wait = 0
			continue
		}
		err := l.post.PostMetadata(ctx, &sensorlink.MetadataRequest{Items: batch})
		if ctx.Err() != nil {
			return nil
		}
		wait = l.settle(len(batch), err, &failures)
	}
}

// head is a copy of the batch at the head of the queue.
func (l *LinkMetadata) head() []sensorlink.MetadataItem {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]sensorlink.MetadataItem(nil), l.pending[:min(len(l.pending), sensorlink.MaxMetadataItems)]...)
}

// settle applies core's answer to the n items at the head of the queue and returns how long to wait before the next request.
func (l *LinkMetadata) settle(n int, err error, failures *int) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	var se *sensorlink.Error
	isErr := errors.As(err, &se)
	if err == nil || isErr {
		*failures = 0
	}
	switch {
	case err == nil:
		now := l.clock()
		for _, w := range l.pending[:n] {
			l.sent[metaKey{w.Kind, w.Src, w.Dest}] = now
		}
		l.shift(n)
		return metaPostEvery
	case !isErr: // no answer: core is down or restarting
		*failures++
		return min(metaPostEvery<<min(*failures, 5), sensorlink.BackoffCap)
	case se.Code == sensorlink.CodeModuleOff:
		l.shift(len(l.pending)) // nothing is wanted any more (not a loss: the module was turned off)
		return metaPostEvery
	case se.Code == sensorlink.CodeInvalidRequest || se.Code == sensorlink.CodePayloadTooLarge || se.Code == sensorlink.CodeForbiddenRoute:
		l.lose(n, err) // refused for good (an older core has no metadata route): never offered again
		return metaPostEvery
	case se.Code == sensorlink.CodeStoreBusy:
		if l.tries++; l.tries >= maxMetaTries {
			l.lose(n, err)
		}
	}
	// rate limited, busy, not ready, updating: what core asked for, never less than the pace, never more than the cap
	return min(max(se.RetryAfter, metaPostEvery), sensorlink.BackoffCap)
}

func (l *LinkMetadata) lose(n int, err error) {
	l.lost += n
	l.lastErr = err
	l.shift(n)
}

// shift removes the first n pending items.
func (l *LinkMetadata) shift(n int) {
	for _, w := range l.pending[:n] {
		delete(l.queued, metaKey{w.Kind, w.Src, w.Dest})
	}
	l.pending = append(l.pending[:0], l.pending[n:]...)
	l.tries = 0
}

// forget drops the delivered items older than metaRepeat, and all of them when that is not enough to stay under maxMetaSent.
func (l *LinkMetadata) forget(now time.Time) {
	if len(l.sent) < maxMetaSent {
		return
	}
	for k, at := range l.sent {
		if now.Sub(at) >= metaRepeat {
			delete(l.sent, k)
		}
	}
	if len(l.sent) >= maxMetaSent {
		clear(l.sent)
	}
}

// wireMeta is the item core receives for it, or false for one the matching cannot use: a source that is not an IPv4 address, a
// flow to an address that no feed can list (private, loopback, link-local, multicast, shared, reserved), or a name of a shape
// the protocol refuses.
func wireMeta(it MetaItem) (sensorlink.MetadataItem, bool) {
	w := sensorlink.MetadataItem{At: it.At.UTC(), Src: it.SrcIP.String()}
	if !it.SrcIP.Is4() {
		return w, false
	}
	switch it.Kind {
	case MetaDNS:
		w.Kind = sensorlink.MetaDNS
	case MetaSNI:
		w.Kind = sensorlink.MetaSNI
	case MetaHTTP:
		w.Kind = sensorlink.MetaHTTP
	case MetaFlow:
		w.Kind = sensorlink.MetaFlow
	default:
		return w, false
	}
	if w.Kind == sensorlink.MetaFlow {
		if !listable(it.DstIP) {
			return w, false
		}
		w.Dest = it.DstIP.String()
	} else {
		w.Dest = strings.ToLower(strings.TrimSuffix(it.Name, "."))
	}
	return w, sensorlink.ValidMetadataItem(w)
}

var sharedNet = netip.MustParsePrefix("100.64.0.0/10")

// listable says whether a feed could list a: an IPv4 global unicast address that is not private or shared (core applies the
// full rule again, with the documentation and reserved ranges).
func listable(a netip.Addr) bool {
	return a.Is4() && a.IsGlobalUnicast() && !a.IsPrivate() && !sharedNet.Contains(a) && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}
