package sensorpassive

// How the capture loop hands observations to the inventory (run.go: flush, deliver, holdOff).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/inventory"
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

// scriptedSink is a Sink whose answer the test chooses per call.
type scriptedSink struct {
	mu     sync.Mutex
	calls  int
	answer func(obs []observe.Observation) error
	stored []observe.Observation
}

func (s *scriptedSink) Record(_ context.Context, obs []observe.Observation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if err := s.answer(obs); err != nil {
		return err
	}
	s.stored = append(s.stored, obs...)
	return nil
}

func obsOf(m string, field observe.Field, value string) observe.Observation {
	return observe.Observation{AssetHint: observe.AssetHint{MAC: m}, Field: field, Value: value, Source: observe.Passive, Confidence: 0.5, SeenAt: pktgen.T0}
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

// Claim: a refusal wrapped by another layer still names the item; only that item is dropped.
func TestDeliverDropsOnlyTheItemANestedRejectionNames(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	sink := &scriptedSink{answer: func(obs []observe.Observation) error {
		for i, o := range obs {
			if o.Value == "bad" {
				return fmt.Errorf("proxy: %w", &observe.ErrRejected{Index: i, Err: errors.New("refused")})
			}
		}
		return nil
	}}
	e.svc.sink = sink
	batch := []observe.Observation{obsOf("00:00:0c:00:00:01", observe.Hostname, "a"), obsOf("00:00:0c:00:00:02", observe.Hostname, "bad"), obsOf("00:00:0c:00:00:03", observe.Hostname, "c")}
	if !e.svc.deliver(t.Context(), e.eng, batch) || len(sink.stored) != 2 || sink.calls != 2 {
		t.Errorf("calls %d stored %d", sink.calls, len(sink.stored))
	}
}

// Claim: deliver always ends. A sink that names item 0 whatever the batch drops the batch item by item (n calls),
// it does not loop.
func TestDeliverEndsWhenTheSinkAlwaysNamesItemZero(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	sink := &scriptedSink{answer: func([]observe.Observation) error { return &observe.ErrRejected{Index: 0, Err: errors.New("no")} }}
	e.svc.sink = sink
	if !e.svc.deliver(t.Context(), e.eng, goodBatch(50)) || sink.calls != 50 || e.eng.Counters()["observation_rejected"] != 50 {
		t.Errorf("calls %d counters %v", sink.calls, e.eng.Counters())
	}
}

// End to end with the real inventory: two items refused at its boundary (an IPv6 hint, an unknown kind) are dropped, the
// three good ones in the same batch are recorded, the index points at the right item every time.
func TestDeliverToTheRealInventoryDropsOnlyTheRefusedItems(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	ctx := t.Context()
	if err := store.Migrate(ctx, e.db, "inventory", inventory.Migrations); err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.New(inventory.Config{DB: e.db, Audit: audit.New(nil), Clock: func() time.Time { return pktgen.T0 }})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.sink = inv
	v6 := obsOf("00:00:0c:00:00:02", observe.Hostname, "six")
	v6.AssetHint.IP = netip.MustParseAddr("fe80::1")
	batch := []observe.Observation{
		obsOf("00:00:0c:00:00:01", observe.Hostname, "one"), v6,
		obsOf("00:00:0c:00:00:03", observe.Hostname, "three"), obsOf("00:00:0c:00:00:04", observe.Kind, "toaster"),
		obsOf("00:00:0c:00:00:05", observe.Hostname, "five"),
	}
	if !e.svc.deliver(ctx, e.eng, batch) {
		t.Fatal("deliver failed")
	}
	l, err := inv.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, d := range l.Items {
		if d.MAC != nil {
			got[*d.MAC] = true
		}
	}
	if len(got) != 3 || !got["00:00:0c:00:00:01"] || !got["00:00:0c:00:00:03"] || !got["00:00:0c:00:00:05"] || e.eng.Counters()["observation_rejected"] != 2 {
		t.Errorf("devices %v counters %v", got, e.eng.Counters())
	}
}

// the vendor row of a new MAC is queued once, at admission. The book outlives the Engine, but the
// resend mark (Engine.resend) does not: Unmark only runs in the final flush, right before the Engine is thrown away,
// and a capture error drops the Engine with its queue unflushed. Either way the next Engine sees a known MAC, never
// queues its vendor again, and the device keeps an empty vendor until the process restarts.
func TestVendorSurvivesANewEngine(t *testing.T) {
	t.Parallel()
	for name, lose := range map[string]func(e *deliverEnv, eng *Engine){
		"final flush failed (reload or end of recording)": func(e *deliverEnv, eng *Engine) {
			e.inv.set(func() { e.inv.fail = errors.New("database is locked") })
			e.svc.flush(t.Context(), eng, true)
			e.inv.set(func() { e.inv.fail = nil })
		},
		"capture error before the flush": func(*deliverEnv, *Engine) {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newDeliverEnv(t)
			eng1, _ := newEngine(engineConfig{Clock: e.svc.clock, Devices: e.svc.devices}) // as session() builds it
			arpAt(eng1, 0)
			arpAt(eng1, 3*time.Second)
			if !hasVendor(eng1.obs) {
				t.Fatal("setup: no vendor queued at admission")
			}
			lose(e, eng1)
			eng2, _ := newEngine(engineConfig{Clock: e.svc.clock, Devices: e.svc.devices}) // the next session
			for _, at := range []time.Duration{time.Minute, 20 * time.Minute, 2 * time.Hour} {
				arpAt(eng2, at)
			}
			e.svc.flush(t.Context(), eng2, true)
			for k := range e.inv.stored {
				if strings.Contains(k, "|vendor|") {
					return
				}
			}
			t.Errorf("the vendor of %s never reached the inventory after the Engine was replaced (stored %v)", pktgen.Laptop, e.inv.stored)
		})
	}
}

// an error that is not ErrRejected but is caused by one item (or an ErrRejected whose Index is out of
// range) blocks the queue for good: the same batch goes back to the head every time, nothing behind it is ever sent,
// and the queue fills to maxPending. No such item was found reachable from the real inventory today.
func TestPoisonBatchIsSplitAndDroppedNotRetriedForever(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	sink := &scriptedSink{answer: func(obs []observe.Observation) error {
		for _, o := range obs {
			if o.Value == "poison" {
				return errors.New("inventory: record observation: constraint failed")
			}
		}
		return nil
	}}
	e.svc.sink = sink
	e.eng.Requeue([]observe.Observation{obsOf("00:00:0c:00:00:09", observe.Hostname, "poison")})
	arpAt(e.eng, 0) // engine without strict limits: the MAC is reported at once
	for range 30 {  // 30 tries over an hour
		e.svc.flush(t.Context(), e.eng, false)
		e.advance(2 * time.Minute)
	}
	if len(sink.stored) == 0 {
		t.Errorf("after %d tries in an hour nothing behind the poisoned batch was delivered (%d pending)", sink.calls, e.eng.Pending())
	}
}

// A flush interrupted by shutdown (ctx cancelled) is not an inventory failure: the Service keeps failures and holdUntil, so
// counting it would hold back the first flushes of the next Run (module on again).
func TestShutdownIsNotAnInventoryFailure(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	sink := &scriptedSink{answer: func([]observe.Observation) error { return context.Canceled }}
	e.svc.sink = sink
	arpAt(e.eng, 0)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	e.svc.flush(ctx, e.eng, false)
	if e.svc.failures != 0 || !e.svc.holdUntil.IsZero() {
		t.Errorf("shutdown left failures=%d holdUntil=%v on the Service", e.svc.failures, e.svc.holdUntil)
	}
}

// a device the book admitted (a real one, or one of the flood's 60/min) has no budget of its own. One
// MAC that sends DHCP requests with a new option-12 name each time writes a new inv_observation row per frame
// (append-only, INV-1 of inventory) at the speed of the writer: the table and the disk grow without limit, and every
// 500 rows are a write transaction on the single SQLite writer.
func TestOneKnownMACCannotGrowTheInventoryWithoutLimit(t *testing.T) {
	t.Parallel()
	e := newDeliverEnv(t)
	ctx := t.Context()
	if err := store.Migrate(ctx, e.db, "inventory", inventory.Migrations); err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.New(inventory.Config{DB: e.db, Audit: audit.New(nil), Clock: func() time.Time { return pktgen.T0.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.sink = inv
	eng, _ := newEngine(engineConfig{Clock: e.svc.clock, Devices: e.svc.devices, OwnMACs: own.OwnMACs, OwnIPs: own.OwnIPs})
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
			e.svc.flush(ctx, eng, false)
		}
	}
	e.svc.flush(ctx, eng, true)
	l, err := inv.Devices(ctx)
	if err != nil || len(l.Items) != 1 {
		t.Fatalf("devices %+v, %v", l.Items, err)
	}
	det, err := inv.Detail(ctx, l.Items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("one MAC, %d frames in 2 s: %d observation rows", frames, len(det.Observations))
	if len(det.Observations) > 3*maxNewValuesPerHour {
		t.Errorf("one admitted MAC wrote %d observation rows in 2 s of traffic; the per-MAC budget and the row cap should bound it", len(det.Observations))
	}
}
