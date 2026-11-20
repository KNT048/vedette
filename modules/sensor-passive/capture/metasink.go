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
	// maxMetaPending is how many items wait for delivery (MetadataPostsPerFlush batches go out per flush); past it new items are
	// dropped and counted.
	maxMetaPending = 10 * sensorlink.MaxMetadataItems
	// maxMetaSent is how many delivered items are remembered for metaRepeat; past it the oldest are forgotten.
	maxMetaSent = 50_000
)

type metaKey struct{ kind, src, dest string }

// LinkMetadata is the MetadataSink of the sensor binary: it reduces what the Engine extracted to what core's bad-address
// matching needs (which LAN address asked for which name, or had a flow to which public address), keeps each of these once,
// and posts them to core over the sensor link, at most sensorlink.MetadataPostsPerFlush batches per flush so that the mirror
// port never takes the request budget the observations and the heartbeat need. Nothing else of a packet leaves the sensor:
// no port, no counter, no resolver address. What core cannot take now waits (bounded) for the next flush.
type LinkMetadata struct {
	post  MetadataPoster
	clock func() time.Time

	mu      sync.Mutex
	pending []sensorlink.MetadataItem
	queued  map[metaKey]bool
	sent    map[metaKey]time.Time
}

// NewLinkMetadata returns the sink that posts through p. clock nil means time.Now.
func NewLinkMetadata(p MetadataPoster, clock func() time.Time) *LinkMetadata {
	if clock == nil {
		clock = time.Now
	}
	return &LinkMetadata{post: p, clock: clock, queued: map[metaKey]bool{}, sent: map[metaKey]time.Time{}}
}

// Pending says whether items wait for delivery: the Runner then calls Metadata at its next flush even when nothing new came.
func (l *LinkMetadata) Pending() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.pending) > 0
}

// errMetaOverflow says that items were dropped because the queue was full.
var errMetaOverflow = errors.New("capture: the metadata queue is full")

// Metadata implements MetadataSink. It returns an error when items were dropped (queue full, core refused a batch) or when core
// could not take them now (they stay queued); the Runner counts and logs it.
func (l *LinkMetadata) Metadata(ctx context.Context, _ uint64, items []MetaItem) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	l.forget(now)
	dropped := 0
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
			dropped++
			continue
		}
		l.queued[k] = true
		l.pending = append(l.pending, w)
	}
	var err error
	if dropped > 0 {
		err = fmt.Errorf("%w: %d items dropped", errMetaOverflow, dropped)
	}
	for range sensorlink.MetadataPostsPerFlush {
		if len(l.pending) == 0 {
			break
		}
		n := min(len(l.pending), sensorlink.MaxMetadataItems)
		batch := l.pending[:n]
		perr := l.post.PostMetadata(ctx, &sensorlink.MetadataRequest{Items: batch})
		var se *sensorlink.Error
		switch {
		case perr == nil:
			for _, w := range batch {
				l.sent[metaKey{w.Kind, w.Src, w.Dest}] = now
			}
		case errors.As(perr, &se) && se.Code == sensorlink.CodeModuleOff:
			l.shift(len(l.pending)) // nothing is wanted any more
			return errors.Join(err, perr)
		case errors.As(perr, &se) && (se.Code == sensorlink.CodeInvalidRequest || se.Code == sensorlink.CodePayloadTooLarge || se.Code == sensorlink.CodeForbiddenRoute):
			// core refuses this batch for good (an older core has no metadata route): it is dropped, never offered again
			err = errors.Join(err, fmt.Errorf("capture: core refused %d metadata items: %w", n, perr))
		default:
			return errors.Join(err, perr) // core cannot take it now (rate, busy, unreachable): it waits for the next flush
		}
		l.shift(n)
	}
	return err
}

// shift removes the first n pending items.
func (l *LinkMetadata) shift(n int) {
	for _, w := range l.pending[:n] {
		delete(l.queued, metaKey{w.Kind, w.Src, w.Dest})
	}
	l.pending = append(l.pending[:0], l.pending[n:]...)
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
