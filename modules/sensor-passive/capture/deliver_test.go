package capture

// How the capture loop hands observations to core (run.go: flush, deliver, holdOff), against a Link the test scripts.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-passive/internal/pktgen"
)

// fakeLink is core as the capture sees it. Without a script it accepts every batch, rejecting (like the real core and its
// inventory) an item with an empty value, by index, and records what it took. post, when set, decides instead.
type fakeLink struct {
	mu      sync.Mutex
	posts   []*sensorlink.ObservationsRequest
	stored  map[string]int
	post    func(req *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error)
	beats   int
	beatErr error
	config  func(ctx context.Context, etag string, wait time.Duration) (sensorlink.ConfigReply, error)
	lastHB  *sensorlink.PassiveHeartbeat
}

func newFakeLink() *fakeLink { return &fakeLink{stored: map[string]int{}} }

func (l *fakeLink) PostObservations(_ context.Context, req *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.posts = append(l.posts, req)
	if l.post != nil {
		rep, err := l.post(req)
		if err == nil {
			l.record(req, rep)
		}
		return rep, err
	}
	rep := sensorlink.ObservationsReply{AckSeq: req.Seq, Rejected: []sensorlink.Rejected{}}
	for i, it := range req.Items {
		if it.Value == "" {
			rep.Rejected = append(rep.Rejected, sensorlink.Rejected{Index: i, Code: "invalid_item"})
		}
	}
	l.record(req, rep)
	return rep, nil
}

func (l *fakeLink) record(req *sensorlink.ObservationsRequest, rep sensorlink.ObservationsReply) {
	bad := map[int]bool{}
	for _, r := range rep.Rejected {
		bad[r.Index] = true
	}
	for i, it := range req.Items {
		if !bad[i] {
			l.stored[it.MAC+"|"+it.IP+"|"+it.Field+"|"+it.Value]++
		}
	}
}

func (l *fakeLink) PassiveHeartbeat(_ context.Context, hb *sensorlink.PassiveHeartbeat) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.beats++
	l.lastHB = hb
	if l.beatErr != nil {
		return "", l.beatErr
	}
	return strings.Repeat("a", 32), nil
}

func (l *fakeLink) Config(ctx context.Context, etag string, wait time.Duration) (sensorlink.ConfigReply, error) {
	if l.config != nil {
		return l.config(ctx, etag, wait)
	}
	<-ctx.Done()
	return sensorlink.ConfigReply{}, ctx.Err()
}

func (l *fakeLink) calls() int { l.mu.Lock(); defer l.mu.Unlock(); return len(l.posts) }

func (l *fakeLink) set(f func()) { l.mu.Lock(); f(); l.mu.Unlock() }

func (l *fakeLink) storedCount() int { l.mu.Lock(); defer l.mu.Unlock(); return len(l.stored) }

// deliverEnv is a Runner with a fake core and a clock the test moves.
type deliverEnv struct {
	r    *Runner
	link *fakeLink
	eng  *Engine
	mu   sync.Mutex
	then time.Time
}

func (e *deliverEnv) advance(d time.Duration) { e.mu.Lock(); e.then = e.then.Add(d); e.mu.Unlock() }

func newDeliverEnv(t *testing.T) *deliverEnv {
	t.Helper()
	e := &deliverEnv{link: newFakeLink(), then: pktgen.T0}
	clock := func() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.then }
	r, err := New(Config{Link: e.link, Interfaces: func(context.Context) ([]Interface, error) { return nil, nil }, Clock: clock, FlushEvery: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	e.r = r
	e.eng, _ = newEngine(engineConfig{Clock: clock})
	return e
}

// goodBatch is n good observations (one device, n addresses).
func goodBatch(n int) []observe.Observation {
	out := make([]observe.Observation, 0, n)
	for i := range n {
		ip := netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})
		out = append(out, observe.Observation{AssetHint: observe.AssetHint{MAC: "00:00:0c:00:00:01", IP: ip}, Field: observe.MAC,
			Value: "00:00:0c:00:00:01", Source: observe.Passive, Confidence: 0.9, SeenAt: pktgen.T0})
	}
	return out
}

// emptyHostname is an observation core rejects.
func emptyHostname(mac string) observe.Observation {
	return observe.Observation{AssetHint: observe.AssetHint{MAC: mac}, Field: observe.Hostname, Value: "", Source: observe.Passive, Confidence: 0.7, SeenAt: pktgen.T0}
}

func obsOf(m, value string) observe.Observation {
	return observe.Observation{AssetHint: observe.AssetHint{MAC: m}, Field: observe.Hostname, Value: value, Source: observe.Passive, Confidence: 0.5, SeenAt: pktgen.T0}
}

func arpAt(eng *Engine, at time.Duration) {
	eng.Handle(Packet{At: pktgen.T0.Add(at), Data: arpFrom(pktgen.Laptop, pktgen.LaptopIP)})
}

func hasVendor(obs []observe.Observation) bool {
	for _, o := range obs {
		if o.Field == observe.Vendor {
			return true
		}
	}
	return false
}

// One call carries the whole batch. Core names the items it rejects in rejected[]: they are dropped and counted, never sent again
// (D-112 (3)); the rest was taken. There is no second call for the rest: core already recorded it.
func TestDeliverDropsTheRejectedItemsAndTheRestIsTaken(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	batch := goodBatch(maxSubmitBatch - 3)
	batch = append(batch, emptyHostname("00:00:0c:00:00:02"), emptyHostname("00:00:0c:00:00:03"), emptyHostname("00:00:0c:00:00:04"))
	if got := e.r.deliver(t.Context(), e.eng, batch); got != delivered {
		t.Fatalf("deliver = %v", got)
	}
	if e.link.calls() != 1 {
		t.Errorf("%d calls for one batch, want 1", e.link.calls())
	}
	if e.link.storedCount() != maxSubmitBatch-3 {
		t.Errorf("%d observations stored, want %d", e.link.storedCount(), maxSubmitBatch-3)
	}
	if e.eng.Counters()["observation_rejected"] != 3 {
		t.Errorf("counters %v", e.eng.Counters())
	}
	if len(batch) != maxSubmitBatch || batch[len(batch)-1].Value != "" {
		t.Error("deliver changed the slice of its caller")
	}
}

// A rejected index that is out of range, repeated or negative says nothing about an item: it is ignored, not counted twice.
func TestDeliverIgnoresRejectedIndexesThatNameNothing(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	e.link.post = func(req *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
		return sensorlink.ObservationsReply{AckSeq: req.Seq, Rejected: []sensorlink.Rejected{{Index: 1, Code: "x"}, {Index: 1, Code: "x"}, {Index: -1, Code: "x"}, {Index: 99, Code: "x"}}}, nil
	}
	if got := e.r.deliver(t.Context(), e.eng, goodBatch(3)); got != delivered || e.eng.Counters()["observation_rejected"] != 1 {
		t.Errorf("deliver = %v, counters %v", got, e.eng.Counters())
	}
}

// What core cannot take says nothing about the items: one call, nothing dropped, the caller is told to retry the whole batch.
func TestDeliverDoesNotDropItemsAfterATransientError(t *testing.T) {
	t.Parallel()
	for name, err := range map[string]error{
		"429":               &sensorlink.Error{Status: 429, Code: sensorlink.CodeRateLimited, RetryAfter: time.Second},
		"426 update window": sensorlink.NewError(sensorlink.CodeProtoUnsupported),
		"cert retired":      sensorlink.NewError(sensorlink.CodeCertRetired),
		"no answer at all":  errors.New("dial tcp 127.0.0.1:8444: connection refused"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newDeliverEnv(t)
			e.link.post = func(*sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
				return sensorlink.ObservationsReply{}, err
			}
			if got := e.r.deliver(t.Context(), e.eng, goodBatch(maxSubmitBatch)); got != retry {
				t.Fatalf("deliver = %v, want retry", got)
			}
			if e.link.calls() != 1 || e.eng.Counters()["observation_rejected"] != 0 || e.eng.Counters()["batch_dropped"] != 0 {
				t.Errorf("%d calls, counters %v", e.link.calls(), e.eng.Counters())
			}
		})
	}
}

// A 503 is the one answer that may be about the items: deliver reports it apart, and still does not drop anything.
func TestDeliverReportsABusyStoreApart(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	e.link.post = func(*sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
		return sensorlink.ObservationsReply{}, sensorlink.StoreBusy(time.Second)
	}
	if got := e.r.deliver(t.Context(), e.eng, goodBatch(5)); got != busy || e.eng.Counters()["batch_dropped"] != 0 {
		t.Errorf("deliver = %v, counters %v", got, e.eng.Counters())
	}
}

// Any other answer says the batch itself is no good: dropped and counted, not retried (OTLP; sensor-protocol.md 7).
func TestDeliverDropsABatchCoreRefusesForGood(t *testing.T) {
	t.Parallel()
	for name, status := range map[string]struct {
		code   string
		status int
	}{"400": {sensorlink.CodeInvalidRequest, 400}, "403 forbidden route": {sensorlink.CodeForbiddenRoute, 403}, "500": {sensorlink.CodeInternal, 500}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newDeliverEnv(t)
			e.link.post = func(*sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
				return sensorlink.ObservationsReply{}, &sensorlink.Error{Status: status.status, Code: status.code}
			}
			if got := e.r.deliver(t.Context(), e.eng, goodBatch(7)); got != dropped {
				t.Fatalf("deliver = %v, want dropped", got)
			}
			if e.eng.Counters()["batch_dropped"] != 7 {
				t.Errorf("counters %v", e.eng.Counters())
			}
		})
	}
}

// 413 halves the batch: the same items go out again in smaller batches until they fit; a single item that is too large is dropped.
func TestTooLargeHalvesTheBatchAndDropsASingleItem(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	e.link.post = func(req *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
		if len(req.Items) > 100 {
			return sensorlink.ObservationsReply{}, sensorlink.NewError(sensorlink.CodePayloadTooLarge)
		}
		return sensorlink.ObservationsReply{AckSeq: req.Seq, Rejected: []sensorlink.Rejected{}}, nil
	}
	for i := range 400 {
		e.eng.Requeue([]observe.Observation{obsOf(fmt.Sprintf("00:00:0c:00:%02x:%02x", i>>8, i), "h")})
	}
	e.r.flush(t.Context(), e.eng, false)
	if e.eng.Pending() != 0 || e.link.storedCount() != 400 {
		t.Errorf("pending %d, stored %d: halving did not get everything through", e.eng.Pending(), e.link.storedCount())
	}
	e2 := newDeliverEnv(t)
	e2.link.post = func(*sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
		return sensorlink.ObservationsReply{}, sensorlink.NewError(sensorlink.CodePayloadTooLarge)
	}
	e2.eng.Requeue([]observe.Observation{obsOf("00:00:0c:00:00:01", "h")})
	e2.r.flush(t.Context(), e2.eng, false)
	if e2.eng.Pending() != 0 || e2.eng.Counters()["batch_dropped"] != 1 {
		t.Errorf("a single item over the limit: pending %d, counters %v", e2.eng.Pending(), e2.eng.Counters())
	}
}

// Every attempt has a seq of its own and the epoch never changes: core drops a repeated seq, so a retry with other items
// must not reuse one.
func TestEveryAttemptHasANewSeqInOneEpoch(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	e.link.post = func(*sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
		return sensorlink.ObservationsReply{}, sensorlink.StoreBusy(time.Second)
	}
	for range 3 {
		e.r.deliver(t.Context(), e.eng, goodBatch(2))
	}
	e.link.mu.Lock()
	defer e.link.mu.Unlock()
	seen := map[int64]bool{}
	for _, p := range e.link.posts {
		if p.Epoch != e.r.Epoch() || !epochOK(p.Epoch) || seen[p.Seq] || p.Seq < 1 {
			t.Errorf("epoch %q seq %d", p.Epoch, p.Seq)
		}
		seen[p.Seq] = true
	}
	if len(seen) != 3 {
		t.Errorf("%d distinct seqs in 3 attempts", len(seen))
	}
}

func epochOK(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// What core could not take waits in the engine and goes out as one batch after a pause (flush holds until then);
// once core is back everything arrives exactly once.
func TestFlushRetriesAWholeBatchWithBackoff(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	for i := range 40 {
		e.eng.Handle(Packet{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, netip.AddrFrom4([4]byte{10, 3, 0, byte(i)}), pktgen.MAC{}, pktgen.RouterIP)})
	}
	pending := e.eng.Pending()
	if pending == 0 {
		t.Fatal("nothing queued")
	}
	busy := func(*sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
		return sensorlink.ObservationsReply{}, sensorlink.StoreBusy(time.Second)
	}
	e.link.set(func() { e.link.post = busy })
	e.r.flush(t.Context(), e.eng, false)
	if e.link.calls() != 1 || e.eng.Pending() != pending {
		t.Fatalf("after the failure: %d calls, %d of %d pending", e.link.calls(), e.eng.Pending(), pending)
	}
	e.r.flush(t.Context(), e.eng, false) // no time passed: nothing is tried
	if e.link.calls() != 1 {
		t.Errorf("tried again at once: %d calls", e.link.calls())
	}
	e.advance(time.Second)
	e.r.flush(t.Context(), e.eng, false)
	if e.link.calls() != 1 {
		t.Errorf("tried again after 1 s: %d calls", e.link.calls())
	}
	e.advance(time.Minute)
	e.r.flush(t.Context(), e.eng, false) // second failure: the pause doubles
	if e.link.calls() != 2 {
		t.Fatalf("not tried after the pause: %d calls", e.link.calls())
	}
	e.advance(time.Minute)
	e.link.set(func() { e.link.post = nil })
	e.r.flush(t.Context(), e.eng, false)
	if e.eng.Pending() != 0 || e.link.storedCount() != pending {
		t.Errorf("after recovery: %d pending, %d stored, want 0 and %d", e.eng.Pending(), e.link.storedCount(), pending)
	}
	e.link.mu.Lock()
	for k, n := range e.link.stored {
		if n != 1 {
			t.Errorf("%s recorded %d times", k, n)
		}
	}
	e.link.mu.Unlock()
	if e.r.failures != 0 || !e.r.holdUntil.IsZero() {
		t.Errorf("the failure count was not cleared: %d", e.r.failures)
	}
}

// A Retry-After from core lengthens the pause, up to the cap.
func TestRetryAfterLengthensThePauseUpToTheCap(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	e.r.retryCap = 30 * time.Second
	e.link.post = func(*sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
		return sensorlink.ObservationsReply{}, &sensorlink.Error{Status: 429, Code: sensorlink.CodeRateLimited, RetryAfter: 45 * time.Second}
	}
	arpAt(e.eng, 0)
	e.r.flush(t.Context(), e.eng, false)
	if got := e.r.holdUntil.Sub(e.r.clock()); got != 30*time.Second {
		t.Errorf("pause %v, want the cap of 30 s (Retry-After was 45 s)", got)
	}
}

// The last flush of a capture has no later: it tries once, forgets what failed (the repeat filter lets it through next
// time) and counts it.
func TestFinalFlushForgetsWhatFails(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	e.eng.Handle(Packet{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, pktgen.PCIP, pktgen.MAC{}, pktgen.RouterIP)})
	n := e.eng.Pending()
	e.link.post = func(*sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
		return sensorlink.ObservationsReply{}, sensorlink.StoreBusy(time.Second)
	}
	e.r.flush(t.Context(), e.eng, true)
	if e.eng.Pending() != 0 || e.eng.Counters()["observation_failed"] != uint64(n) { //nolint:gosec // a handful of observations
		t.Errorf("pending %d, counters %v", e.eng.Pending(), e.eng.Counters())
	}
	e.eng.Handle(Packet{At: pktgen.T0.Add(time.Minute), Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, pktgen.PCIP, pktgen.MAC{}, pktgen.RouterIP)})
	if e.eng.Pending() == 0 {
		t.Error("what failed in the final flush is still suppressed as a repeat")
	}
}

// The memory queue is the only queue (D-112 (6)) and it is bounded: when it is full the oldest observations go, and are counted.
func TestRequeueIsBoundedAndDropsTheOldest(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(engineConfig{})
	old := goodBatch(maxPending - 5)
	for i := range old {
		old[i].Value = fmt.Sprintf("old-%d", i)
	}
	e.Requeue(old)
	fresh := goodBatch(20)
	for i := range fresh {
		fresh[i].Value = fmt.Sprintf("new-%d", i)
	}
	e.Requeue(fresh)
	if e.Pending() != maxPending || e.Counters()["observations_dropped"] != 15 {
		t.Fatalf("pending %d, counters %v", e.Pending(), e.Counters())
	}
	obs, _ := e.Drain(pktgen.T0, false)
	// the head of the queue is the oldest: the first 15 of it are gone, what was already queued behind it stayed
	if obs[0].Value != "new-15" || obs[len(obs)-1].Value != "old-4994" {
		t.Errorf("kept %q ... %q: the first 15 should be the ones dropped", obs[0].Value, obs[len(obs)-1].Value)
	}
}

// A queue that grows while core is away does not grow past the cap: the oldest is dropped for each new one, counted, and it
// may come back later (it is forgotten as sent).
func TestFullQueueDropsTheOldestAndCountsIt(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(engineConfig{})
	for i := range maxPending + 50 {
		e.queue(pktgen.T0, mac{2, 0, 0, 0, byte(i >> 8), byte(i)}, netip.Addr{}, observe.Hostname, "x", 0.5)
	}
	obs, _ := e.Drain(pktgen.T0, false)
	if len(obs) != maxPending || e.Counters()["observations_dropped"] != 50 {
		t.Fatalf("observations %d, counters %v", len(obs), e.Counters())
	}
	if obs[0].AssetHint.MAC != (mac{2, 0, 0, 0, 0, 50}).String() {
		t.Errorf("the first kept is %s: the 50 oldest should have gone", obs[0].AssetHint.MAC)
	}
	e.queue(pktgen.T0.Add(time.Second), mac{2, 0, 0, 0, 0, 0}, netip.Addr{}, observe.Hostname, "x", 0.5) // the first one dropped may come again at once
	if e.Pending() != 1 {
		t.Error("an observation dropped from a full queue is still suppressed as a repeat")
	}
}

// the vendor row of a new MAC is queued once, at admission. The book outlives the Engine, but the resend mark does not: a
// failed final flush or a capture error drops the Engine with its queue. Either way the next Engine must send it.
func TestVendorSurvivesANewEngine(t *testing.T) {
	t.Parallel()
	for name, lose := range map[string]func(e *deliverEnv, eng *Engine){
		"final flush failed (reload or end of recording)": func(e *deliverEnv, eng *Engine) {
			e.link.set(func() {
				e.link.post = func(*sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
					return sensorlink.ObservationsReply{}, sensorlink.StoreBusy(time.Second)
				}
			})
			e.r.flush(t.Context(), eng, true)
			e.link.set(func() { e.link.post = nil })
		},
		"capture error before the flush": func(*deliverEnv, *Engine) {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newDeliverEnv(t)
			eng1, _ := newEngine(engineConfig{Clock: e.r.clock, Devices: e.r.devices}) // as session() builds it
			arpAt(eng1, 0)
			arpAt(eng1, 3*time.Second)
			if !hasVendor(eng1.obs) {
				t.Fatal("setup: no vendor queued at admission")
			}
			lose(e, eng1)
			eng2, _ := newEngine(engineConfig{Clock: e.r.clock, Devices: e.r.devices}) // the next session
			for _, at := range []time.Duration{time.Minute, 20 * time.Minute, 2 * time.Hour} {
				arpAt(eng2, at)
			}
			e.r.flush(t.Context(), eng2, true)
			e.link.mu.Lock()
			defer e.link.mu.Unlock()
			for k := range e.link.stored {
				if strings.Contains(k, "|vendor|") {
					return
				}
			}
			t.Errorf("the vendor of %s never reached core after the Engine was replaced (stored %v)", pktgen.Laptop, e.link.stored)
		})
	}
}

// an error that is caused by one item blocks the queue for good unless the batch is split: the same batch goes back to
// the head every time and nothing behind it is ever sent. Three failures of the same batch split it; the item that stands alone
// and still fails while core takes writes (its heartbeat succeeds) is dropped.
func TestPoisonBatchIsSplitAndDroppedNotRetriedForever(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	e.link.post = func(req *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
		for _, it := range req.Items {
			if it.Value == "poison" {
				return sensorlink.ObservationsReply{}, sensorlink.StoreBusy(time.Second)
			}
		}
		return sensorlink.ObservationsReply{AckSeq: req.Seq, Rejected: []sensorlink.Rejected{}}, nil
	}
	e.eng.Requeue([]observe.Observation{obsOf("00:00:0c:00:00:09", "poison")})
	arpAt(e.eng, 0) // engine without strict limits: the MAC is reported at once
	for range 30 {  // 30 tries over an hour
		e.r.flush(t.Context(), e.eng, false)
		e.advance(2 * time.Minute)
	}
	if e.link.storedCount() == 0 {
		t.Errorf("after %d tries in an hour nothing behind the poisoned batch was delivered (%d pending)", e.link.calls(), e.eng.Pending())
	}
	if e.eng.Counters()["observation_failed"] != 1 {
		t.Errorf("the poison item was not counted: %v", e.eng.Counters())
	}
	if e.r.batchMax != 0 {
		t.Errorf("batchMax is %d after the hunt: a delivery ends it", e.r.batchMax)
	}
}

// M6: a batch is split, and a lone item blamed, only for a 503 while a heartbeat succeeds at that moment. A rate limit, an
// update window, a certificate being rotated or no answer at all say nothing about any item: the batch stays whole and nothing
// is dropped, however long it takes.
func TestNothingButABusyStoreSplitsOrBlames(t *testing.T) {
	t.Parallel()
	for name, err := range map[string]error{
		"429":              &sensorlink.Error{Status: 429, Code: sensorlink.CodeRateLimited, RetryAfter: time.Second},
		"426":              sensorlink.NewError(sensorlink.CodeProtoUnsupported),
		"cert_retired":     sensorlink.NewError(sensorlink.CodeCertRetired),
		"no answer at all": errors.New("connection refused"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, size := range []int{1, 8} { // a lone item (single-item mode) and a batch
				e := newDeliverEnv(t)
				var failing = true
				e.link.post = func(req *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
					if failing {
						return sensorlink.ObservationsReply{}, err
					}
					return sensorlink.ObservationsReply{AckSeq: req.Seq, Rejected: []sensorlink.Rejected{}}, nil
				}
				for i := range size {
					e.eng.Requeue([]observe.Observation{obsOf(fmt.Sprintf("00:00:0c:00:00:%02x", i+1), "h")}) // the heartbeat works: core is up
				}
				for range 30 {
					e.r.flush(t.Context(), e.eng, false)
					e.advance(2 * time.Minute)
				}
				if e.r.batchMax != 0 || e.eng.Pending() != size || e.eng.Counters()["observation_failed"] != 0 {
					t.Fatalf("size %d: batchMax %d, pending %d, counters %v: nothing may be split or blamed", size, e.r.batchMax, e.eng.Pending(), e.eng.Counters())
				}
				e.link.set(func() { failing = false })
				e.r.flush(t.Context(), e.eng, false)
				if e.eng.Pending() != 0 || e.link.storedCount() != size {
					t.Errorf("size %d after the link recovered: pending %d, stored %d", size, e.eng.Pending(), e.link.storedCount())
				}
			}
		})
	}
}

// A 503 with a heartbeat that fails too is the store, not an item; a 503 with a heartbeat that works is blamed on the batch.
func TestABusyStoreSplitsOnlyWhileTheHeartbeatSucceeds(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	e.link.post = func(*sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
		return sensorlink.ObservationsReply{}, sensorlink.StoreBusy(time.Second)
	}
	e.link.beatErr = sensorlink.StoreBusy(time.Second)
	for i := range 8 {
		e.eng.Requeue([]observe.Observation{obsOf(fmt.Sprintf("00:00:0c:00:00:%02x", i+1), "h")})
	}
	for range 12 {
		e.r.flush(t.Context(), e.eng, false)
		e.advance(2 * time.Minute)
	}
	if e.r.batchMax != 0 {
		t.Fatalf("split to %d while the heartbeat failed too", e.r.batchMax)
	}
	e.link.set(func() { e.link.beatErr = nil })
	for range 12 {
		e.r.flush(t.Context(), e.eng, false)
		e.advance(2 * time.Minute)
	}
	if e.eng.Counters()["observation_failed"] == 0 {
		t.Error("never split down to single items although core answered its heartbeat and kept failing every batch")
	}
}

// L5: a device whose items met the budget of core is not forgotten: the vendor row is still owed and goes out when the device is
// admitted later; an item rejected for good clears the debt.
func TestVendorStaysOwedWhenTheBudgetRejectedIt(t *testing.T) {
	t.Parallel()
	for code, owed := range map[string]bool{"budget_exhausted": true, "refused": false, "invalid_item": false} {
		e := newDeliverEnv(t)
		e.link.post = func(req *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
			rep := sensorlink.ObservationsReply{AckSeq: req.Seq, Rejected: []sensorlink.Rejected{}}
			for i := range req.Items {
				rep.Rejected = append(rep.Rejected, sensorlink.Rejected{Index: i, Code: code})
			}
			return rep, nil
		}
		arpAt(e.eng, 0)
		arpAt(e.eng, 3*time.Second)
		if !hasVendor(e.eng.obs) {
			t.Fatalf("%s: setup: no vendor queued at admission", code)
		}
		e.r.flush(t.Context(), e.eng, false)
		if got := e.eng.book.vendorOwed(mac(pktgen.Laptop)); got != owed {
			t.Errorf("%s: vendor owed = %v, want %v", code, got, owed)
		}
		arpAt(e.eng, 10*time.Second) // the next frame of the device
		if got := hasVendor(e.eng.obs); got != owed {
			t.Errorf("%s: the vendor row is queued again = %v, want %v", code, got, owed)
		}
	}
}

// If core's store is what fails (the heartbeat fails too), a lone item is not blamed: it stays queued.
func TestALoneItemIsNotBlamedWhileCoreFailsEverything(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	e.link.post = func(*sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
		return sensorlink.ObservationsReply{}, sensorlink.StoreBusy(time.Second)
	}
	e.link.beatErr = sensorlink.StoreBusy(time.Second)
	e.eng.Requeue([]observe.Observation{obsOf("00:00:0c:00:00:09", "innocent")})
	for range 30 {
		e.r.flush(t.Context(), e.eng, false)
		e.advance(2 * time.Minute)
	}
	if e.eng.Pending() != 1 || e.eng.Counters()["observation_failed"] != 0 {
		t.Errorf("pending %d, counters %v", e.eng.Pending(), e.eng.Counters())
	}
}

// module_off from a batch: nothing is sent any more, the queue is not requeued, the Runner is off.
func TestModuleOffFromABatchStopsEverything(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	e.link.post = func(*sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
		return sensorlink.ObservationsReply{}, sensorlink.NewError(sensorlink.CodeModuleOff)
	}
	arpAt(e.eng, 0)
	e.r.flush(t.Context(), e.eng, false)
	if !e.r.isOff() || e.eng.Pending() != 0 {
		t.Errorf("off %v, pending %d", e.r.isOff(), e.eng.Pending())
	}
}

// A flush interrupted by shutdown (ctx cancelled) is not a failure of core: the Runner keeps failures and holdUntil, so
// counting it would hold back the first flushes of the next Run.
func TestShutdownIsNotAFailureOfCore(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	e.link.post = func(*sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
		return sensorlink.ObservationsReply{}, context.Canceled
	}
	arpAt(e.eng, 0)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	e.r.flush(ctx, e.eng, false)
	if e.r.failures != 0 || !e.r.holdUntil.IsZero() {
		t.Errorf("shutdown left failures=%d holdUntil=%v on the Runner", e.r.failures, e.r.holdUntil)
	}
}

// a device the book admitted (a real one, or one of the flood's 60/min) has no budget of its own in the Engine. One MAC that
// sends DHCP requests with a new option-12 name each time must not pass more than the per-MAC budget of new values to core.
func TestOneKnownMACIsBoundedBeforeItLeavesTheSensor(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	ctx := t.Context()
	eng, _ := newEngine(engineConfig{Clock: e.r.clock, Devices: e.r.devices, OwnMACs: own.OwnMACs, OwnIPs: own.OwnIPs})
	dhcp := func(at time.Duration, name string) {
		req := pktgen.DHCP(1, pktgen.PC, netip.Addr{}, netip.Addr{}, pktgen.DHCPOpts{Type: 3, Hostname: name})
		eng.Handle(Packet{At: pktgen.T0.Add(at), Data: pktgen.UDPFrame(pktgen.Bcast, pktgen.PC, netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255"), 68, 67, req)})
	}
	dhcp(0, "pc")
	dhcp(3*time.Second, "pc") // admitted: two frames 3 s apart
	const frames = 2000       // 2,000 frames in 2 s
	for i := range frames {
		dhcp(4*time.Second+time.Duration(i)*time.Millisecond, fmt.Sprintf("n%05d", i))
		if eng.Pending() >= maxSubmitBatch {
			e.r.flush(ctx, eng, false)
		}
	}
	e.r.flush(ctx, eng, true)
	if n := e.link.storedCount(); n > 3*maxNewValuesPerHour {
		t.Errorf("one admitted MAC passed %d observations in 2 s of traffic to core; the per-MAC budget should bound it", n)
	}
}
