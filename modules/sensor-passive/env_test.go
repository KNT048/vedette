package sensorpassive_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/inventory"
	sp "github.com/knt048/vedette/modules/sensor-passive"
	"github.com/knt048/vedette/modules/sensor-passive/capture"
	"github.com/knt048/vedette/modules/sensor-passive/internal/pktgen"
)

var allExtract = sensorlink.Extract{DNS: true, SNI: true, HTTP: true, Flows: true}

// fakeHost is the box as the tests see it: a management card with an IP and a SPAN card without one.
type fakeHost struct {
	mu      sync.Mutex
	ifaces  []capture.Interface
	filters []sensorlink.Filter
	optErr  error // SpanOptions fails: the filters cannot be read
	noHost  bool  // no vedette-host answers (container-only)
	mgmt    string
}

func newHost() *fakeHost {
	return &fakeHost{ifaces: []capture.Interface{
		{Name: "eth0", MAC: pktgen.Box.String(), Link: true, Addresses: []netip.Prefix{netip.PrefixFrom(pktgen.BoxIP, 24)}},
		{Name: "eth1", MAC: "02:00:00:00:00:02", Link: true},
	}}
}

func (h *fakeHost) Interfaces(context.Context) ([]capture.Interface, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]capture.Interface(nil), h.ifaces...), nil
}

// HostCards answers like a host that knows the cards, or, with noHost set, like an install without vedette-host.
func (h *fakeHost) HostCards(ctx context.Context) ([]capture.Interface, bool, error) {
	h.mu.Lock()
	no := h.noHost
	h.mu.Unlock()
	if no {
		return nil, false, nil
	}
	c, err := h.Interfaces(ctx)
	return c, true, err
}

func (h *fakeHost) setNoHost(v bool) { h.mu.Lock(); h.noHost = v; h.mu.Unlock() }

// ManagementCard answers like HostCards: "no host" with noHost, else the management card set by setMgmt ("" by default).
func (h *fakeHost) ManagementCard(context.Context) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.mgmt, !h.noHost
}

func (h *fakeHost) setMgmt(name string) { h.mu.Lock(); h.mgmt = name; h.mu.Unlock() }

func (h *fakeHost) SpanOptions(context.Context) (sensorlink.Extract, []sensorlink.Filter, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.optErr != nil {
		return sensorlink.Extract{}, nil, h.optErr
	}
	return allExtract, append([]sensorlink.Filter(nil), h.filters...), nil
}

func (h *fakeHost) setOptErr(err error)               { h.mu.Lock(); h.optErr = err; h.mu.Unlock() }
func (h *fakeHost) setFilters(f ...sensorlink.Filter) { h.mu.Lock(); h.filters = f; h.mu.Unlock() }
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
	batches [][]capture.MetaItem
	seqs    []uint64
}

func (m *metaRecorder) Metadata(_ context.Context, seq uint64, items []capture.MetaItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.batches = append(m.batches, items)
	m.seqs = append(m.seqs, seq)
	return nil
}

func (m *metaRecorder) all() []capture.MetaItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []capture.MetaItem
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
	fail   bool // every open fails, like a card that vanished
	tries  int
	once   bool // play the recording once (a test that looks at timestamps or counts frames)
	read   int  // sources that have handed out their last frame
}

// drained reports whether some opened source has handed out every frame of its recording.
func (o *openSource) drained() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.read > 0
}

func (o *openSource) open(iface string) (capture.Source, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.opened = append(o.opened, iface)
	o.tries++
	if o.fail {
		return nil, errors.New("no such card")
	}
	frames := o.files[iface]
	if !o.once {
		frames = twice(frames)
	}
	return &replaySource{owner: o, frames: frames, hold: o.hold}, nil
}

func (o *openSource) opens() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.opened...)
}

func (o *openSource) closes() int { o.mu.Lock(); defer o.mu.Unlock(); return o.closed }

// twice plays a recording a second time, after the whole of it and a pause: the sensor reports a new MAC only when
// it was heard in two frames at least two seconds apart (SYS-6), and the second pass is what makes it so. The
// repeat filter keeps the second pass from sending anything twice.
func twice(frames []pktgen.Frame) []pktgen.Frame {
	if len(frames) == 0 {
		return nil
	}
	shift := frames[len(frames)-1].At.Sub(frames[0].At) + 3*time.Second
	out := append([]pktgen.Frame(nil), frames...)
	for _, f := range frames {
		out = append(out, pktgen.Frame{At: f.At.Add(shift), Data: f.Data})
	}
	return out
}

type replaySource struct {
	owner  *openSource
	frames []pktgen.Frame
	hold   bool
	i      int
	done   bool
}

func (r *replaySource) Next(ctx context.Context) (capture.Packet, error) {
	if err := ctx.Err(); err != nil {
		return capture.Packet{}, err
	}
	if r.i < len(r.frames) {
		f := r.frames[r.i]
		r.i++
		return capture.Packet{At: f.At, Data: f.Data}, nil
	}
	if !r.done {
		r.done = true
		r.owner.mu.Lock()
		r.owner.read++
		r.owner.mu.Unlock()
	}
	if !r.hold {
		return capture.Packet{}, io.EOF
	}
	select {
	case <-ctx.Done():
		return capture.Packet{}, ctx.Err()
	case <-time.After(5 * time.Millisecond):
		return capture.Packet{}, capture.ErrIdle
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
	cfg   sp.Config // what New got, for the capture of a remote run (see remote_test.go)
	rem   *remote
	beat  sync.Once

	forceRemote bool
	sensorCards func(context.Context) ([]capture.Interface, error) // what the remote capture believes its cards are (default: the host's)
	off         atomic.Bool                                        // the module is off: the link answers 409 module_off
}

// countingSink wraps the inventory so tests can see what was recorded and when.
type countingSink struct {
	inner     observe.Sink
	reject    string // a value the "inventory" refuses (the whole batch it is in, like the real one)
	poison    string // a value that makes the store fail with an error that names no item, every time
	failFirst int    // the first calls fail like a busy store
	mu        sync.Mutex
	got       []observe.Observation
	calls     int
}

func (c *countingSink) Record(ctx context.Context, obs []observe.Observation) error {
	c.mu.Lock()
	c.calls++
	if c.failFirst > 0 {
		c.failFirst--
		c.mu.Unlock()
		return errors.New("database is locked")
	}
	for _, o := range obs {
		if c.poison != "" && o.Value == c.poison {
			c.mu.Unlock()
			return errors.New("constraint failed")
		}
	}
	c.got = append(c.got, obs...)
	c.mu.Unlock()
	for i, o := range obs {
		if c.reject != "" && o.Value == c.reject {
			return &observe.ErrRejected{Index: i, Err: errors.New("refused")}
		}
	}
	return c.inner.Record(ctx, obs)
}

func (c *countingSink) count() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.got) }

type option func(*sp.Config, *env)

// withClock starts the test clock at base; it then runs with real time, so the loop's flush and heartbeat
// timers fire while the time stays near base.
func withLog(h slog.Handler) option { return func(c *sp.Config, _ *env) { c.Log = slog.New(h) } }

func withPoison(value string) option { return func(_ *sp.Config, e *env) { e.sink.poison = value } }

// withFlakyStore makes the first n writes to the inventory fail like a busy store.
func withFlakyStore(n int) option { return func(_ *sp.Config, e *env) { e.sink.failFirst = n } }

// withRemote runs the capture at the far end of the link whatever the environment says.
func withRemote() option { return func(_ *sp.Config, e *env) { e.forceRemote = true } }

func withReject(value string) option { return func(_ *sp.Config, e *env) { e.sink.reject = value } }

func withSummaryEvery(d time.Duration) option {
	return func(c *sp.Config, _ *env) { c.SummaryEvery = d }
}

// withSinglePass plays each recording once instead of twice (see twice).
func withSinglePass() option { return func(_ *sp.Config, e *env) { e.src.once = true } }

func withClock(base time.Time) option {
	return func(_ *sp.Config, e *env) { e.now = elapsedFrom(base) }
}

func elapsedFrom(base time.Time) func() time.Time {
	start := time.Now()
	return func() time.Time { return base.Add(time.Since(start)) }
}

func newEnv(t *testing.T, files map[string][]pktgen.Frame, hold bool, opts ...option) *env {
	t.Helper()
	db := storetest.Migrated(t, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "inventory", FS: inventory.Migrations},
		storetest.Migration{Module: "sensor-passive", FS: sp.Migrations})
	e := &env{t: t, db: db, host: newHost(), meta: &metaRecorder{}, src: &openSource{files: files, hold: hold}, now: elapsedFrom(pktgen.T0.Add(time.Minute))}
	aud := audit.New(nil)
	inv, err := inventory.New(inventory.Config{DB: db, Audit: aud, Clock: func() time.Time { return pktgen.T0.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	e.inv = inv
	e.sink = &countingSink{inner: inv}
	cfg := sp.Config{DB: db, Audit: aud, Sink: e.sink, Meta: e.meta, Host: e.host, Log: slog.New(slog.DiscardHandler), Version: "1.0.0", Name: "vedette-test",
		Enabled: func() bool { return !e.off.Load() },
		KnownMACs: func(ctx context.Context) ([]string, error) {
			l, err := inv.Devices(ctx)
			if err != nil {
				return nil, err
			}
			var macs []string
			for _, d := range l.Items {
				if d.MAC != nil {
					macs = append(macs, *d.MAC)
				}
			}
			return macs, nil
		},
		Open: e.src.open, FlushEvery: 10 * time.Millisecond, HeartbeatEvery: 10 * time.Millisecond, RetryEvery: 20 * time.Millisecond}
	for _, o := range opts {
		o(&cfg, e)
	}
	cfg.Clock = func() time.Time { e.nowMu.Lock(); f := e.now; e.nowMu.Unlock(); return f() }
	e.cfg = cfg
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
	job := e.job()
	go func() { done <- job(ctx) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					e.t.Errorf("Run returned %v", err)
				}
			case <-time.After(waitBound):
				e.t.Error("Run did not return after its context was cancelled")
			}
		})
	}
	e.t.Cleanup(stop)
	return stop
}

func (e *env) setInterface(iface string, span bool) {
	e.t.Helper()
	e.sensorBeat()
	if err := e.svc.SetInterface(e.t.Context(), "admin@example.org", sp.SensorID, iface, span); err != nil {
		e.t.Fatalf("SetInterface(%q, %v): %v", iface, span, err)
	}
}

// sensorBeat is the first heartbeat of the sensor: the cards it has. An admin can choose a card only among those a sensor
// reported (INV-9), so a test that sets the interface before the capture runs has the sensor say hello first. It is the same call
// the sensor makes, with the cards of the test's host.
func (e *env) sensorBeat() {
	e.t.Helper()
	e.beat.Do(func() {
		cards, _ := e.host.Interfaces(e.t.Context())
		hb := &sensorlink.PassiveHeartbeat{Version: "1.0.0", Interfaces: []sensorlink.HeartbeatIface{}, Drops: map[string]int64{}}
		for _, c := range cards {
			ips := []string{}
			for _, p := range c.Addresses {
				ips = append(ips, p.String())
			}
			hb.Interfaces = append(hb.Interfaces, sensorlink.HeartbeatIface{Name: c.Name, MAC: c.MAC, Link: c.Link, IPv4: ips})
		}
		if _, err := e.svc.PassiveHeartbeat(e.t.Context(), hb); err != nil {
			e.t.Fatal(err)
		}
	})
}

// waitBound is how long a test waits for a condition, and how long a stop may take before the test calls it stuck. A stop is
// 5 ms when the machine is free (measured over 20 switches through the link); the bound is for a starved one.
const waitBound = 30 * time.Second

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	// A passing wait returns the moment its condition holds, so this bound costs nothing when all is well; it only says how long a
	// condition that never comes is waited for. What the waits need is CPU, not time: the inventory writes parse their SQL again on
	// every call and -race makes that about ten times slower, and CI runs this suite three times over (in process, remote, and the
	// parent) next to other packages. On a quiet machine the longest wait is under a second; 5 s failed on a loaded runner with
	// nothing stuck (INV6, SP-4 store retry and the unknown-box test, three times in a week).
	deadline := time.Now().Add(waitBound)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		pause(t, 20*time.Millisecond)
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
