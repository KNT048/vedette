package capture

// The Runner as a whole (run.go: Run, captureLoop, session): what it does with the configuration core sends, module_off, filters
// that cannot be read, a card that cannot be opened. Against a Link the test scripts and recordings, never a live card.

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-passive/internal/pktgen"
)

// configServer is core's config endpoint for a test: a long poll that answers when the ETag differs and otherwise waits for set.
type configServer struct {
	mu      sync.Mutex
	cfg     sensorlink.Config
	version int
	err     error // answered instead of a config (module_off, no answer)
	changed chan struct{}
	polls   int
}

func newConfigServer(cfg sensorlink.Config) *configServer {
	return &configServer{cfg: cfg, version: 1, changed: make(chan struct{})}
}

func (c *configServer) set(cfg sensorlink.Config) {
	c.mu.Lock()
	c.cfg, c.err = cfg, nil
	c.version++
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
}

func (c *configServer) fail(err error) {
	c.mu.Lock()
	c.err = err
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
}

func (c *configServer) pollCount() int { c.mu.Lock(); defer c.mu.Unlock(); return c.polls }

func (c *configServer) poll(ctx context.Context, etag string, wait time.Duration) (sensorlink.ConfigReply, error) {
	for {
		c.mu.Lock()
		c.polls++
		tag := `"v` + strconv.Itoa(c.version) + `"`
		err, cfg, ch := c.err, c.cfg, c.changed
		c.mu.Unlock()
		switch {
		case err != nil:
			return sensorlink.ConfigReply{}, err
		case tag != etag:
			return sensorlink.ConfigReply{ETag: tag, Config: cfg}, nil
		}
		select {
		case <-ch:
		case <-time.After(wait):
			return sensorlink.ConfigReply{NotModified: true, ETag: etag}, nil
		case <-ctx.Done():
			return sensorlink.ConfigReply{}, ctx.Err()
		}
	}
}

// recSource replays frames for an interface (twice, see below) and then idles like a live line, counting opens and closes.
type recSource struct {
	mu     sync.Mutex
	opened []string
	closed int
	fail   bool
	err    error // what a failing open returns; nil: "no such card"
	tries  int
	frames []Packet
}

func (o *recSource) open(iface string) (Source, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.opened = append(o.opened, iface)
	o.tries++
	if o.fail {
		if o.err != nil {
			return nil, o.err
		}
		return nil, errors.New("no such card")
	}
	return &idleAfter{owner: o, frames: o.frames}, nil
}

func (o *recSource) opens() []string { o.mu.Lock(); defer o.mu.Unlock(); return slices.Clone(o.opened) }
func (o *recSource) closes() int     { o.mu.Lock(); defer o.mu.Unlock(); return o.closed }

type idleAfter struct {
	owner  *recSource
	frames []Packet
	i      int
}

func (s *idleAfter) Next(ctx context.Context) (Packet, error) {
	if err := ctx.Err(); err != nil {
		return Packet{}, err
	}
	if s.i < len(s.frames) {
		p := s.frames[s.i]
		s.i++
		return p, nil
	}
	select {
	case <-ctx.Done():
		return Packet{}, ctx.Err()
	case <-time.After(2 * time.Millisecond):
		return Packet{}, ErrIdle
	}
}

func (s *idleAfter) Close() error {
	s.owner.mu.Lock()
	s.owner.closed++
	s.owner.mu.Unlock()
	return nil
}

// lanFrames is the LAN fixture played twice: a new MAC is reported only when it was heard in two frames at least two seconds apart.
func lanFrames() []Packet {
	fr := pktgen.LANDiscovery()
	shift := fr[len(fr)-1].At.Sub(fr[0].At) + 3*time.Second
	var out []Packet
	for _, f := range fr {
		out = append(out, Packet{At: f.At, Data: f.Data})
	}
	for _, f := range fr {
		out = append(out, Packet{At: f.At.Add(shift), Data: f.Data})
	}
	return out
}

// elapsedFrom is a clock that starts at base and then runs with real time, so the loop's timers fire while the time stays near base.
func elapsedFrom(base time.Time) func() time.Time {
	start := time.Now()
	return func() time.Time { return base.Add(time.Since(start)) }
}

type runEnv struct {
	r    *Runner
	link *fakeLink
	cfg  *configServer
	src  *recSource
}

type runOpt func(*Config)

func newRunEnv(t *testing.T, first sensorlink.Config, opts ...runOpt) *runEnv {
	t.Helper()
	e := &runEnv{link: newFakeLink(), cfg: newConfigServer(first), src: &recSource{frames: lanFrames()}}
	e.link.config = e.cfg.poll
	cfg := Config{Link: e.link, Open: e.src.open, Version: "1.0.0",
		Interfaces: func(context.Context) ([]Interface, error) {
			return []Interface{{Name: "eth0", MAC: pktgen.Box.String(), Link: true, Addresses: []netip.Prefix{netip.PrefixFrom(pktgen.BoxIP, 24)}}, {Name: "eth1", MAC: "02:00:00:00:00:02", Link: true}}, nil
		},
		Clock:      elapsedFrom(pktgen.T0.Add(time.Minute)),
		FlushEvery: 10 * time.Millisecond, HeartbeatEvery: 10 * time.Millisecond, RetryEvery: 20 * time.Millisecond, ConfigWait: time.Second,
		ModuleOffEvery: 30 * time.Millisecond, RetryAfterCap: time.Millisecond}
	for _, o := range opts {
		o(&cfg)
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.r = r
	return e
}

// start runs the Runner; the test's end cancels it and waits for it, failing the test when it does not return.
func (e *runEnv) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- e.r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after its context was cancelled")
		}
	})
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		quiet(t, 3*time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func quiet(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case <-time.After(d):
	case <-t.Context().Done():
	}
}

// Run opens the card core names, reports what it hears, and says hello (cards, version) even while it has nothing to capture.
func TestRunCapturesOnTheCardCoreNamesAndReports(t *testing.T) {
	t.Parallel()
	e := newRunEnv(t, sensorlink.Config{Interface: "", Filters: []sensorlink.Filter{}})
	e.start(t)
	eventually(t, "a heartbeat while idle", func() bool { e.link.mu.Lock(); defer e.link.mu.Unlock(); return e.link.beats > 0 })
	e.link.mu.Lock()
	hb := e.link.lastHB
	e.link.mu.Unlock()
	if hb.Version != "1.0.0" || len(hb.Interfaces) != 2 || hb.Interfaces[0].Name != "eth0" || len(hb.Interfaces[0].IPv4) != 1 {
		t.Errorf("heartbeat %+v", hb)
	}
	if len(e.src.opens()) != 0 {
		t.Fatal("opened a card while core named none")
	}
	e.cfg.set(sensorlink.Config{Interface: "eth0", Filters: []sensorlink.Filter{}})
	eventually(t, "the devices of the LAN", func() bool { return e.link.storedCount() >= 10 })
	if got := e.src.opens(); !slices.Equal(got, []string{"eth0"}) {
		t.Errorf("opened %v", got)
	}
	eventually(t, "devices_seen in a heartbeat", func() bool {
		e.link.mu.Lock()
		defer e.link.mu.Unlock()
		return e.link.lastHB != nil && e.link.lastHB.DevicesSeen > 0 && e.link.lastHB.Span.LastPacketAt != nil
	})
}

// interface "" stops the capture at once, with no last flush (sensor-protocol.md 6.1); another card closes the old one after a
// last flush and opens the new one.
func TestConfigStopsOrMovesTheCapture(t *testing.T) {
	t.Parallel()
	e := newRunEnv(t, sensorlink.Config{Interface: "eth0", Filters: []sensorlink.Filter{}}, func(c *Config) { c.FlushEvery = time.Hour })
	e.start(t)
	eventually(t, "the card to open", func() bool { return len(e.src.opens()) == 1 })
	quiet(t, 50*time.Millisecond) // frames are handled, nothing is flushed: FlushEvery is an hour
	if e.link.calls() != 0 {
		t.Fatalf("%d batches before any flush was due", e.link.calls())
	}
	e.cfg.set(sensorlink.Config{Interface: "eth1", Filters: []sensorlink.Filter{}})
	eventually(t, "the move to eth1", func() bool { return slices.Equal(e.src.opens(), []string{"eth0", "eth1"}) })
	if e.src.closes() < 1 {
		t.Error("the old card was not closed")
	}
	eventually(t, "the last flush of the old capture", func() bool { return e.link.calls() > 0 })
	n := e.link.calls()
	e.cfg.set(sensorlink.Config{Interface: "", Filters: []sensorlink.Filter{}})
	eventually(t, "both cards closed", func() bool { return e.src.closes() == 2 })
	quiet(t, 50*time.Millisecond)
	if e.link.calls() != n {
		t.Errorf("a batch was sent after core said not to capture: %d, was %d", e.link.calls(), n)
	}
}

// module_off from config: capture stops, no last flush, the queue is gone, and core is asked again; when the module is back the
// capture starts again.
func TestModuleOffFromConfigStopsWithoutAFlushAndAsksAgain(t *testing.T) {
	t.Parallel()
	e := newRunEnv(t, sensorlink.Config{Interface: "eth0", Filters: []sensorlink.Filter{}}, func(c *Config) { c.FlushEvery = time.Hour })
	e.start(t)
	eventually(t, "the card to open", func() bool { return len(e.src.opens()) == 1 })
	quiet(t, 30*time.Millisecond)
	e.cfg.fail(sensorlink.NewError(sensorlink.CodeModuleOff))
	eventually(t, "the card to close", func() bool { return e.src.closes() == 1 })
	quiet(t, 60*time.Millisecond)
	if e.link.calls() != 0 {
		t.Fatalf("a batch was sent after module_off: %d", e.link.calls())
	}
	polls := e.cfg.pollCount()
	eventually(t, "core to be asked again", func() bool { return e.cfg.pollCount() > polls+1 })
	e.link.mu.Lock()
	beats := e.link.beats
	e.link.mu.Unlock()
	quiet(t, 40*time.Millisecond)
	e.link.mu.Lock()
	if e.link.beats != beats {
		t.Errorf("heartbeats went on while the module was off: %d -> %d", beats, e.link.beats)
	}
	e.link.mu.Unlock()
	e.cfg.set(sensorlink.Config{Interface: "eth0", Filters: []sensorlink.Filter{}})
	eventually(t, "the capture to start again", func() bool { return len(e.src.opens()) == 2 })
}

// module_off from a batch or a heartbeat stops the capture just the same, without a last flush.
func TestModuleOffFromAHeartbeatStopsTheCapture(t *testing.T) {
	t.Parallel()
	e := newRunEnv(t, sensorlink.Config{Interface: "eth0", Filters: []sensorlink.Filter{}}, func(c *Config) { c.FlushEvery = time.Hour; c.HeartbeatEvery = 40 * time.Millisecond })
	e.start(t)
	eventually(t, "the card to open", func() bool { return len(e.src.opens()) == 1 })
	e.link.set(func() { e.link.beatErr = sensorlink.NewError(sensorlink.CodeModuleOff) })
	eventually(t, "the card to close", func() bool { return e.src.closes() == 1 })
	if e.link.calls() != 0 {
		t.Errorf("a batch was sent after module_off: %d", e.link.calls())
	}
}

// Filters that cannot be read mean no capture, and the heartbeat says so (filters_invalid): the sensor does not guess at what core
// meant (D-80 (3)).
func TestUnreadableFiltersMeanNoCaptureAndAreReported(t *testing.T) {
	t.Parallel()
	e := newRunEnv(t, sensorlink.Config{Interface: "eth1", Span: true, Filters: []sensorlink.Filter{{Type: "port", Value: "nope"}}})
	e.start(t)
	eventually(t, "filters_invalid in a heartbeat", func() bool {
		e.link.mu.Lock()
		defer e.link.mu.Unlock()
		return e.link.lastHB != nil && e.link.lastHB.Drops["filters_invalid"] >= 1
	})
	if len(e.src.opens()) != 0 || e.link.calls() != 0 {
		t.Errorf("opened %v, %d batches: capture ran with a filter that could not be read", e.src.opens(), e.link.calls())
	}
	eventually(t, "capture_error filters_invalid", func() bool { return e.link.lastCaptureError() == sensorlink.CaptureFiltersInvalid })
	e.cfg.set(sensorlink.Config{Interface: "eth1", Span: true, Filters: []sensorlink.Filter{{Type: "port", Value: "443"}}})
	eventually(t, "the capture once the filters are good", func() bool { return len(e.src.opens()) == 1 })
	eventually(t, "no capture_error once it captures", func() bool { return e.link.lastCaptureError() == "" })
}

// D-399 (3), walk 4: a sensor without CAP_NET_RAW (rootless container) beats on as "online" while its capture socket cannot open; the
// heartbeat says why (a closed set of reasons, never the error text), and says nothing once the card opens.
func TestHeartbeatSaysWhyTheCaptureDoesNotRun(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("capture: open capture socket (needs CAP_NET_RAW): %w", syscall.EPERM), sensorlink.CaptureNoPermission},
		{fmt.Errorf("capture: interface %q: %w: route ip+net: no such network interface", "eth9", ErrNoInterface), sensorlink.CaptureNoInterface},
		{errors.New("capture: bind on \"eth0\": something else"), sensorlink.CaptureFailed},
	} {
		e := newRunEnv(t, sensorlink.Config{Interface: "eth0", Filters: []sensorlink.Filter{}})
		e.src.mu.Lock()
		e.src.fail, e.src.err = true, c.err
		e.src.mu.Unlock()
		e.start(t)
		eventually(t, "capture_error "+c.want, func() bool { return e.link.lastCaptureError() == c.want })
		e.src.mu.Lock()
		e.src.fail = false
		e.src.mu.Unlock()
		eventually(t, "no capture_error once the card opens", func() bool { return len(e.src.opens()) > 1 && e.link.lastCaptureError() == "" })
		e.cfg.set(sensorlink.Config{Interface: "", Filters: []sensorlink.Filter{}})
		eventually(t, "none while no card is wanted", func() bool { return e.link.lastCaptureError() == "" })
	}
}

// A card that cannot be opened is retried with a growing pause, and counted.
func TestFailingOpenBacksOffAndIsCounted(t *testing.T) {
	t.Parallel()
	e := newRunEnv(t, sensorlink.Config{Interface: "eth0", Filters: []sensorlink.Filter{}})
	e.src.fail = true
	start := time.Now()
	e.start(t)
	// RetryEvery is 20 ms. Four attempts take at least 20+40+80 = 140 ms with a doubling pause and only 60 ms with a constant one.
	eventually(t, "four attempts", func() bool { e.src.mu.Lock(); defer e.src.mu.Unlock(); return e.src.tries >= 4 })
	if d := time.Since(start); d < 140*time.Millisecond {
		t.Errorf("four attempts in %v, want at least 140 ms (20, 40, 80 ms pauses)", d)
	}
	eventually(t, "capture_failed in a heartbeat", func() bool {
		e.link.mu.Lock()
		defer e.link.mu.Unlock()
		return e.link.lastHB != nil && e.link.lastHB.Drops["capture_failed"] >= 3
	})
}

// flakySource delivers a few frames, then fails like a card that lost its link.
type flakySource struct{ n int }

func (f *flakySource) Next(ctx context.Context) (Packet, error) {
	if err := ctx.Err(); err != nil {
		return Packet{}, err
	}
	if f.n < 3 {
		f.n++
		return Packet{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, pktgen.PCIP, pktgen.MAC{}, pktgen.RouterIP)}, nil
	}
	return Packet{}, errors.New("receive: network is down")
}
func (f *flakySource) Close() error { return nil }

// Low: a live capture never ends cleanly, so the back-off was reset only by a settings change and every failure over the
// life of the process doubled the pause until it stuck at ten minutes. A session that received frames starts it over.
func TestBackoffStartsOverAfterASessionThatReceivedFrames(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	opens := 0
	e := newRunEnv(t, sensorlink.Config{Interface: "eth0", Filters: []sensorlink.Filter{}}, func(c *Config) {
		c.Open = func(string) (Source, error) {
			mu.Lock()
			opens++
			mu.Unlock()
			return &flakySource{}, nil
		}
	})
	e.start(t)
	quiet(t, 1500*time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	// base 20 ms: without the reset the pauses are 20, 40, 80 ... 640 ms and fewer than 8 opens fit in 1.5 s
	if opens < 15 {
		t.Errorf("only %d opens in 1.5 s: the pause kept growing after sessions that worked", opens)
	}
}

// A recording that ends (io.EOF) is flushed once and then the capture waits for the next configuration.
func TestEndOfARecordingFlushesOnce(t *testing.T) {
	t.Parallel()
	e := newRunEnv(t, sensorlink.Config{Interface: "eth0", Filters: []sensorlink.Filter{}}, func(c *Config) {
		c.FlushEvery = time.Hour
		c.Open = func(string) (Source, error) {
			fr := lanFrames()
			i := 0
			return srcFunc(func(context.Context) (Packet, error) {
				if i < len(fr) {
					i++
					return fr[i-1], nil
				}
				return Packet{}, io.EOF
			}), nil
		}
	})
	e.start(t)
	eventually(t, "the devices of the recording", func() bool { return e.link.storedCount() >= 10 })
	n := e.link.calls()
	quiet(t, 60*time.Millisecond)
	if e.link.calls() != n {
		t.Errorf("batches went on after the recording ended: %d, was %d", e.link.calls(), n)
	}
}

type srcFunc func(context.Context) (Packet, error)

func (f srcFunc) Next(ctx context.Context) (Packet, error) { return f(ctx) }
func (srcFunc) Close() error                               { return nil }

// A heartbeat says which cards the machine has: only those the protocol can carry (a name and a MAC of the protocol), at most 32,
// at most 8 IPv4 prefixes each, and no list that is null.
func TestHeartbeatCarriesOnlyWhatTheProtocolCan(t *testing.T) {
	t.Parallel()
	var cards []Interface
	for i := range 40 {
		cards = append(cards, Interface{Name: "eth" + strconv.Itoa(i), MAC: "02:00:00:00:00:" + hex2(i), Link: true})
	}
	cards = append(cards, Interface{Name: "bad name!", MAC: "02:00:00:00:99:99"}, Interface{Name: "nomac", MAC: "zz"})
	cards[0].Addresses = nil
	for i := range 12 {
		cards[1].Addresses = append(cards[1].Addresses, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(i), 1}), 24))
	}
	cards[2].Addresses = []netip.Prefix{netip.MustParsePrefix("fe80::1/64")}
	e := newRunEnv(t, sensorlink.Config{}, func(c *Config) {
		c.Interfaces = func(context.Context) ([]Interface, error) { return cards, nil }
	})
	hb, err := e.r.heartbeat(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(hb.Interfaces) != sensorlink.MaxHeartbeatIfaces || hb.Drops == nil || hb.Interfaces[0].IPv4 == nil {
		t.Fatalf("%d interfaces, drops %v", len(hb.Interfaces), hb.Drops)
	}
	if len(hb.Interfaces[1].IPv4) != sensorlink.MaxHeartbeatPrefixes || len(hb.Interfaces[2].IPv4) != 0 {
		t.Errorf("prefixes: %v / %v", hb.Interfaces[1].IPv4, hb.Interfaces[2].IPv4)
	}
}

func hex2(i int) string {
	const d = "0123456789abcdef"
	return string([]byte{d[i>>4&15], d[i&15]})
}

// Every counter this package can produce is in the closed set of the protocol, and every key of the set is produced somewhere:
// the heartbeat refuses a key it does not know (sensor-protocol.md 6.3), so a counter outside the set would be silently lost.
func TestEveryCounterIsInTheClosedSetOfTheProtocol(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range af.Decls {
			fd, isFunc := decl.(*ast.FuncDecl)
			wrapper := isFunc && fd.Name.Name == "CountDrop" // the one function that passes a counter on: its own callers are checked
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "drop" && sel.Sel.Name != "CountDrop" && sel.Sel.Name != "count") {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					if !wrapper {
						t.Errorf("%s counts something that is not a string literal: the closed set cannot be checked", f)
					}
					return true
				}
				k, _ := strconv.Unquote(lit.Value)
				used[k] = true
				if !sensorlink.ValidDropKey(k) {
					t.Errorf("%s counts %q, which is not in sensorlink.DropKeys", f, k)
				}
				return true
			})
		}
	}
	for _, k := range sensorlink.DropKeys {
		if !used[k] {
			t.Errorf("sensorlink.DropKeys has %q and nothing counts it", k)
		}
	}
	if len(sensorlink.DropKeys) > sensorlink.MaxDropKeys {
		t.Errorf("%d keys, the heartbeat takes %d", len(sensorlink.DropKeys), sensorlink.MaxDropKeys)
	}
}

// lastCaptureError is the capture_error of the last heartbeat core was sent ("" before the first).
func (l *fakeLink) lastCaptureError() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lastHB == nil {
		return ""
	}
	return l.lastHB.CaptureError
}
