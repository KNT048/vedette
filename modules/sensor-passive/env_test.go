package sensorpassive_test

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/inventory"
	sp "github.com/knt048/vedette/modules/sensor-passive"
	"github.com/knt048/vedette/modules/sensor-passive/internal/pktgen"
)

var allExtract = sp.Extract{DNS: true, TLSSNI: true, HTTPHost: true, Flows: true}

// fakeHost is the box as the tests see it: a management card with an IP and a SPAN card without one.
type fakeHost struct {
	mu      sync.Mutex
	ifaces  []sp.HostInterface
	filters []sp.Filter
}

func newHost() *fakeHost {
	return &fakeHost{ifaces: []sp.HostInterface{
		{Name: "eth0", MAC: pktgen.Box.String(), Link: true, Addresses: []netip.Addr{pktgen.BoxIP}},
		{Name: "eth1", MAC: "02:00:00:00:00:02", Link: true},
	}}
}

func (h *fakeHost) Interfaces(context.Context) ([]sp.HostInterface, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]sp.HostInterface(nil), h.ifaces...), nil
}

func (h *fakeHost) SpanOptions(context.Context) (sp.Extract, []sp.Filter, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return allExtract, append([]sp.Filter(nil), h.filters...), nil
}

func (h *fakeHost) setFilters(f ...sp.Filter) { h.mu.Lock(); h.filters = f; h.mu.Unlock() }
func (h *fakeHost) setLink(name string, up bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.ifaces {
		if h.ifaces[i].Name == name {
			h.ifaces[i].Link = up
		}
	}
}

// metaRecorder keeps what was handed to the MetadataSink.
type metaRecorder struct {
	mu      sync.Mutex
	batches [][]sp.MetaItem
	seqs    []uint64
}

func (m *metaRecorder) Metadata(_ context.Context, seq uint64, items []sp.MetaItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.batches = append(m.batches, items)
	m.seqs = append(m.seqs, seq)
	return nil
}

func (m *metaRecorder) all() []sp.MetaItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []sp.MetaItem
	for _, b := range m.batches {
		out = append(out, b...)
	}
	return out
}

// openSource is what Config.Open does in tests: the first call for each interface replays a recording;
// hold keeps the source open (idle) after the last frame, like a live line.
type openSource struct {
	mu     sync.Mutex
	opened []string
	closed int
	files  map[string][]pktgen.Frame // interface → frames
	hold   bool
}

func (o *openSource) open(iface string) (sp.Source, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.opened = append(o.opened, iface)
	return &replaySource{owner: o, frames: o.files[iface], hold: o.hold}, nil
}

func (o *openSource) opens() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.opened...)
}

func (o *openSource) closes() int { o.mu.Lock(); defer o.mu.Unlock(); return o.closed }

type replaySource struct {
	owner  *openSource
	frames []pktgen.Frame
	hold   bool
	i      int
}

func (r *replaySource) Next(ctx context.Context) (sp.Packet, error) {
	if err := ctx.Err(); err != nil {
		return sp.Packet{}, err
	}
	if r.i < len(r.frames) {
		f := r.frames[r.i]
		r.i++
		return sp.Packet{At: f.At, Data: f.Data}, nil
	}
	if !r.hold {
		return sp.Packet{}, io.EOF
	}
	select {
	case <-ctx.Done():
		return sp.Packet{}, ctx.Err()
	case <-time.After(5 * time.Millisecond):
		return sp.Packet{}, sp.ErrIdle
	}
}

func (r *replaySource) Close() error {
	r.owner.mu.Lock()
	r.owner.closed++
	r.owner.mu.Unlock()
	return nil
}

type env struct {
	t     *testing.T
	db    *store.DB
	inv   *inventory.Service
	svc   *sp.Service
	host  *fakeHost
	meta  *metaRecorder
	src   *openSource
	nowMu sync.Mutex
	now   func() time.Time
	sink  *countingSink
}

// countingSink wraps the inventory so tests can see what was recorded and when.
type countingSink struct {
	inner observe.Sink
	mu    sync.Mutex
	got   []observe.Observation
}

func (c *countingSink) Record(ctx context.Context, obs []observe.Observation) error {
	c.mu.Lock()
	c.got = append(c.got, obs...)
	c.mu.Unlock()
	return c.inner.Record(ctx, obs)
}

func (c *countingSink) count() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.got) }

type option func(*sp.Config, *env)

// withClock starts the test clock at base; it then runs with real time, so the loop's flush and heartbeat
// timers fire while the time stays near base.
func withClock(base time.Time) option {
	return func(_ *sp.Config, e *env) { e.now = elapsedFrom(base) }
}

func elapsedFrom(base time.Time) func() time.Time {
	start := time.Now()
	return func() time.Time { return base.Add(time.Since(start)) }
}

func newEnv(t *testing.T, files map[string][]pktgen.Frame, hold bool, opts ...option) *env {
	t.Helper()
	db := storetest.New(t)
	ctx := t.Context()
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "inventory", inventory.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "sensor-passive", sp.Migrations); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, db: db, host: newHost(), meta: &metaRecorder{}, src: &openSource{files: files, hold: hold}, now: elapsedFrom(pktgen.T0.Add(time.Minute))}
	aud := audit.New(nil)
	inv, err := inventory.New(inventory.Config{DB: db, Audit: aud, Clock: func() time.Time { return pktgen.T0.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	e.inv = inv
	e.sink = &countingSink{inner: inv}
	cfg := sp.Config{DB: db, Audit: aud, Sink: e.sink, Meta: e.meta, Host: e.host, Log: slog.New(slog.DiscardHandler), Version: "test", Name: "vedette-test",
		Open: e.src.open, FlushEvery: 10 * time.Millisecond, HeartbeatEvery: 10 * time.Millisecond, RetryEvery: 20 * time.Millisecond}
	for _, o := range opts {
		o(&cfg, e)
	}
	cfg.Clock = func() time.Time { e.nowMu.Lock(); f := e.now; e.nowMu.Unlock(); return f() }
	e.svc, err = sp.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// run starts the capture loop; the returned func stops it (module off) and waits for it to return.
func (e *env) run() (stop func()) {
	e.t.Helper()
	ctx, cancel := context.WithCancel(e.t.Context())
	done := make(chan error, 1)
	go func() { done <- e.svc.Run(ctx) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					e.t.Errorf("Run returned %v", err)
				}
			case <-time.After(5 * time.Second):
				e.t.Error("Run did not return after its context was cancelled")
			}
		})
	}
	e.t.Cleanup(stop)
	return stop
}

func (e *env) setInterface(iface string, span bool) {
	e.t.Helper()
	if err := e.svc.SetInterface(e.t.Context(), "admin@example.org", sp.SensorID, iface, span); err != nil {
		e.t.Fatalf("SetInterface(%q, %v): %v", iface, span, err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		pause(t, 5*time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (e *env) count(query string) int {
	e.t.Helper()
	var n int
	if err := e.db.Reader().QueryRowContext(e.t.Context(), query).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
	return n
}

// setClock replaces the test clock while the loop runs.
func (e *env) setClock(f func() time.Time) { e.nowMu.Lock(); e.now = f; e.nowMu.Unlock() }

// devices lists what the inventory holds, through its service (the tests never read inv_* tables themselves).
func (e *env) devices() []inventory.Device {
	e.t.Helper()
	l, err := e.inv.Devices(e.t.Context())
	if err != nil {
		e.t.Fatal(err)
	}
	return l.Items
}

// device finds one by MAC, or nil.
func (e *env) device(mac string) *inventory.Device {
	for _, d := range e.devices() {
		if d.MAC != nil && *d.MAC == mac {
			return &d
		}
	}
	return nil
}

// observations returns every observation of every device, as the inventory shows them.
func (e *env) observations() []inventory.ObservationRow {
	e.t.Helper()
	var out []inventory.ObservationRow
	for _, d := range e.devices() {
		det, err := e.inv.Detail(e.t.Context(), d.ID)
		if err != nil {
			e.t.Fatal(err)
		}
		out = append(out, det.Observations...)
	}
	return out
}

func (e *env) obsCount(pred func(inventory.ObservationRow) bool) int {
	n := 0
	for _, o := range e.observations() {
		if pred(o) {
			n++
		}
	}
	return n
}

// pause waits d (or until the test ends) on a timer, for "nothing happens" checks.
func pause(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case <-time.After(d):
	case <-t.Context().Done():
	}
}
