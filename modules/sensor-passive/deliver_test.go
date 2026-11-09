package sensorpassive

// How the capture loop hands observations to the inventory (run.go: flush, deliver, holdOff).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/sensor-passive/internal/pktgen"
)

// fakeInventory refuses, like inventory.Record at its boundary, a batch with an empty value, naming the item
// (observe.ErrRejected) and writing nothing. fail, when set, refuses every call (a busy or failing store).
type fakeInventory struct {
	mu     sync.Mutex
	calls  int
	stored map[string]int
	fail   error
}

func (s *fakeInventory) Record(_ context.Context, obs []observe.Observation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.fail != nil {
		return s.fail
	}
	for i, o := range obs {
		if o.Value == "" {
			return &observe.ErrRejected{Index: i, Err: fmt.Errorf("inventory: invalid input: observation %d: value must be 1 to 200 printable characters", i)}
		}
	}
	for _, o := range obs {
		s.stored[o.AssetHint.MAC+"|"+o.AssetHint.IP.String()+"|"+string(o.Field)+"|"+o.Value]++
	}
	return nil
}

func (s *fakeInventory) set(f func()) { s.mu.Lock(); f(); s.mu.Unlock() }

type fakeHost2 struct{}

func (fakeHost2) Interfaces(context.Context) ([]HostInterface, error)    { return nil, nil }
func (fakeHost2) SpanOptions(context.Context) (Extract, []Filter, error) { return Extract{}, nil, nil }

// deliverEnv is a Service with a fake inventory and a clock the test moves.
type deliverEnv struct {
	svc  *Service
	db   *store.DB
	inv  *fakeInventory
	eng  *Engine
	mu   sync.Mutex
	then time.Time
}

func (e *deliverEnv) advance(d time.Duration) { e.mu.Lock(); e.then = e.then.Add(d); e.mu.Unlock() }

func newDeliverEnv(t *testing.T) *deliverEnv {
	t.Helper()
	db := storetest.New(t)
	ctx := t.Context()
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "sensor-passive", Migrations); err != nil {
		t.Fatal(err)
	}
	e := &deliverEnv{db: db, inv: &fakeInventory{stored: map[string]int{}}, then: pktgen.T0}
	clock := func() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.then }
	s, err := New(Config{DB: db, Audit: audit.New(nil), Sink: e.inv, Host: fakeHost2{}, Clock: clock, FlushEvery: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = s
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

// emptyHostname is an observation the inventory refuses.
func emptyHostname(mac string) observe.Observation {
	return observe.Observation{AssetHint: observe.AssetHint{MAC: mac}, Field: observe.Hostname, Value: "", Source: observe.Passive, Confidence: 0.7, SeenAt: pktgen.T0}
}

// A refusal names the item: it is dropped and the rest goes out in one more call. No write per item (500 writes on the
// single SQLite writer for every batch it rides in) and no second attempt of the refused item for fifteen minutes.
func TestDeliverDropsTheNamedItemAndSendsTheRest(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	batch := goodBatch(maxSubmitBatch - 1)
	batch = append(batch, emptyHostname("00:00:0c:00:00:02"))
	if !e.svc.deliver(t.Context(), e.eng, batch) {
		t.Fatal("deliver says the inventory could not be reached")
	}
	if e.inv.calls != 2 {
		t.Errorf("%d inventory calls for one batch with one refused item, want 2", e.inv.calls)
	}
	if len(e.inv.stored) != maxSubmitBatch-1 {
		t.Errorf("%d observations recorded, want %d", len(e.inv.stored), maxSubmitBatch-1)
	}
	if e.eng.Counters()["observation_rejected"] != 1 {
		t.Errorf("counters %v", e.eng.Counters())
	}
	if len(batch) != maxSubmitBatch || batch[len(batch)-1].Value != "" {
		t.Error("deliver changed the slice of its caller")
	}
}

// Two bad items in one batch are two refusals, not a storm: one more call each.
func TestDeliverDropsEveryRefusedItem(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	batch := append(goodBatch(10), emptyHostname("00:00:0c:00:00:02"), emptyHostname("00:00:0c:00:00:03"))
	batch = append(batch[:5], append([]observe.Observation{emptyHostname("00:00:0c:00:00:04")}, batch[5:]...)...)
	if !e.svc.deliver(t.Context(), e.eng, batch) || len(e.inv.stored) != 10 || e.inv.calls != 4 {
		t.Errorf("calls %d, stored %d", e.inv.calls, len(e.inv.stored))
	}
	if e.eng.Counters()["observation_rejected"] != 3 {
		t.Errorf("counters %v", e.eng.Counters())
	}
}

// A store error says nothing about the items: one call, nothing dropped, the caller is told to retry the whole batch.
func TestDeliverDoesNotRetryItemsAfterATransientError(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	e.inv.fail = errors.New("store: begin: database is locked (SQLITE_BUSY)")
	if e.svc.deliver(t.Context(), e.eng, goodBatch(maxSubmitBatch)) {
		t.Fatal("a failing store reported as delivered")
	}
	if e.inv.calls != 1 || e.eng.Counters()["observation_rejected"] != 0 {
		t.Errorf("%d calls, counters %v", e.inv.calls, e.eng.Counters())
	}
}

// What the store could not take waits in the engine and goes out as one batch after a pause (flush holds until then);
// once the store is back everything arrives exactly once.
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
	e.inv.fail = errors.New("database is locked")
	e.svc.flush(t.Context(), e.eng, false)
	if e.inv.calls != 1 || e.eng.Pending() != pending {
		t.Fatalf("after the failure: %d calls, %d of %d pending", e.inv.calls, e.eng.Pending(), pending)
	}
	e.svc.flush(t.Context(), e.eng, false) // no time passed: nothing is tried
	if e.inv.calls != 1 {
		t.Errorf("tried again at once: %d calls", e.inv.calls)
	}
	e.advance(time.Second)
	e.svc.flush(t.Context(), e.eng, false)
	if e.inv.calls != 1 {
		t.Errorf("tried again after 1 s: %d calls", e.inv.calls)
	}
	e.advance(time.Minute)
	e.svc.flush(t.Context(), e.eng, false) // second failure: the pause doubles
	if e.inv.calls != 2 {
		t.Fatalf("not tried after the pause: %d calls", e.inv.calls)
	}
	e.advance(time.Minute)
	e.inv.set(func() { e.inv.fail = nil })
	e.svc.flush(t.Context(), e.eng, false)
	if e.eng.Pending() != 0 || len(e.inv.stored) != pending {
		t.Errorf("after recovery: %d pending, %d stored, want 0 and %d", e.eng.Pending(), len(e.inv.stored), pending)
	}
	for k, n := range e.inv.stored {
		if n != 1 {
			t.Errorf("%s recorded %d times", k, n)
		}
	}
	if e.svc.failures != 0 || !e.svc.holdUntil.IsZero() {
		t.Errorf("the failure count was not cleared: %d", e.svc.failures)
	}
}

// The last flush of a capture has no later: it tries once, forgets what failed (the repeat filter lets it through next
// time) and counts it.
func TestFinalFlushForgetsWhatFails(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	e.eng.Handle(Packet{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, pktgen.PCIP, pktgen.MAC{}, pktgen.RouterIP)})
	n := e.eng.Pending()
	e.inv.fail = errors.New("database is locked")
	e.svc.flush(t.Context(), e.eng, true)
	if e.eng.Pending() != 0 || e.eng.Counters()["observation_failed"] != uint64(n) { //nolint:gosec // a handful of observations
		t.Errorf("pending %d, counters %v", e.eng.Pending(), e.eng.Counters())
	}
	e.eng.Handle(Packet{At: pktgen.T0.Add(time.Minute), Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, pktgen.PCIP, pktgen.MAC{}, pktgen.RouterIP)})
	if e.eng.Pending() == 0 {
		t.Error("what failed in the final flush is still suppressed as a repeat")
	}
}

// Requeue respects the bound on pending observations and counts what does not fit.
func TestRequeueIsBounded(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(engineConfig{})
	e.Requeue(goodBatch(maxPending - 5))
	e.Requeue(goodBatch(20))
	if e.Pending() != maxPending || e.Counters()["observations_dropped"] != 15 {
		t.Errorf("pending %d, counters %v", e.Pending(), e.Counters())
	}
}

// When the inventory took the batch but saving its number failed, the batch is not recorded a second time.
func TestAcceptedBatchIsNeverRecordedTwice(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	if err := e.svc.ensureSensor(t.Context()); err != nil {
		t.Fatal(err)
	}
	// stands for any failure of the second transaction (disk full, I/O error, busy): saving seq fails
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		for _, q := range []string{
			`CREATE TRIGGER no_seq_insert BEFORE INSERT ON sp_seq BEGIN SELECT RAISE(FAIL, 'disk I/O error'); END`,
			`CREATE TRIGGER no_seq_update BEFORE UPDATE ON sp_seq BEGIN SELECT RAISE(FAIL, 'disk I/O error'); END`,
		} {
			if _, err := tx.ExecContext(t.Context(), q); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !e.svc.deliver(t.Context(), e.eng, goodBatch(20)) {
		t.Error("an accepted batch was reported as not delivered")
	}
	if e.inv.calls != 1 {
		t.Errorf("%d inventory calls, want 1", e.inv.calls)
	}
	for k, n := range e.inv.stored {
		if n > 1 {
			t.Errorf("%s recorded %d times", k, n)
		}
	}
}
