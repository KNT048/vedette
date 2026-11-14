package sensoractive_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// allPortsCalls are the runs of argv that scanned every port (-p-), by target.
func allPortsCalls(e *env) []string {
	var out []string
	for _, c := range e.nm.calls(e.t) {
		if slices.Contains(c, "-p-") {
			out = append(out, strings.Join(targetsOf(c), ","))
		}
	}
	return out
}

// sweptToday records the sweep of the current window as done: Tick goes straight to the queue, SNMP and the weekly scans.
func sweptToday(e *env) {
	e.t.Helper()
	if err := e.db.Write(e.ctx(), func(tx dbTx) error {
		ts := e.clock().UTC().Format("2006-01-02T15:04:05.000Z")
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO sa_job (id, kind, started_at, finished_at, status) VALUES ('saj_today', 'sweep', ?, ?, 'done')`, ts, ts)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
}

func allPortsEnv(t *testing.T, mut ...func(*env)) *env {
	t.Helper()
	e := newEnv(t, fakeOpts{always: absFixture(t, "allports.xml")}, mut...)
	e.sweptBefore()
	e.inv.mu.Lock()
	e.inv.addrs = map[netip.Addr]string{netip.MustParseAddr("192.168.10.20"): "a-web", netip.MustParseAddr("192.168.10.30"): "a-printer"}
	e.inv.decision["a-printer"] = sa.Decision{Allowed: true, Rate: 100, Fragile: true, Reason: "ok"} // a fragile device the policy still lets discovery scan
	e.inv.mu.Unlock()
	sweptToday(e)
	return e
}

// webPorts are the ports the sink holds for a-web (192.168.10.20).
func (e *env) webPorts() []int {
	e.sink.mu.Lock()
	defer e.sink.mu.Unlock()
	var out []int
	for _, s := range e.sink.svc["192.168.10.20"] {
		out = append(out, s.Port)
	}
	slices.Sort(out)
	return out
}

// D-592 (review r1 H2): inside the window, a device that is not fragile gets one port discovery over every port a week (no -sV, no
// script, no -O, at most AllPortsMaxRate packets/s), then one -sV run on just the open ports the normal scan does not cover; both
// in the probe log. A fragile device never; a second tick of the same week sends nothing; a week later it runs again.
func TestAllPortsOncePerWeekAndNeverForAFragileDevice(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := allPortsCalls(e); !slices.Equal(got, []string{"192.168.10.20"}) {
		t.Fatalf("weekly scans %q, want one of 192.168.10.20 only", got)
	}
	calls := e.nm.calls(t)
	disc, follow := calls[len(calls)-2], calls[len(calls)-1]
	if r := disc[slices.Index(disc, "--max-rate")+1]; r != "100" || slices.Contains(disc, "-O") || slices.Contains(disc, "-sV") || slices.Contains(disc, "--script") || !slices.Contains(disc, "90m") {
		t.Fatalf("discovery argv %q", disc)
	}
	// allports.xml: 22, 80 and 40000 open; 22 and 80 are in the extra list (the normal scan reads them), 40000 is not
	if !slices.Contains(follow, "-sV") || follow[slices.Index(follow, "-p")+1] != "40000" || slices.Contains(follow, "-O") || follow[len(follow)-1] != "192.168.10.20" {
		t.Fatalf("follow-up argv %q", follow)
	}
	if got := e.str(`SELECT group_concat(shape, ',') FROM sa_probe WHERE targets = '192.168.10.20'`); got != "all_ports,port_versions" {
		t.Fatalf("probe rows of the weekly scan: %q", got)
	}
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := allPortsCalls(e); len(got) != 1 {
		t.Fatalf("a second tick of the same week scanned again: %q", got)
	}
	e.base = e.base.Add(7*24*time.Hour + time.Minute) // a week later, the same hour: inside the window again
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := allPortsCalls(e); !slices.Equal(got, []string{"192.168.10.20", "192.168.10.20"}) {
		t.Fatalf("a week later: %q", got)
	}
}

// D-592: a weekly scan needs a whole run's room in the window (AllPortsHostTimeout) and a rate of at least AllPortsMinRate;
// otherwise nothing is sent and Health says why for the rate. Unknown kind, never, first gentle, the box (by policy and by its
// addresses, review r1 L1), declared by hand and out of scope get none either.
func TestAllPortsNeedsRoomRateAndAKnownSafeDevice(t *testing.T) {
	t.Parallel()
	late := allPortsEnv(t, func(e *env) { e.base = local(9, 4, 0) }) // one hour before the window closes
	if err := late.svc.Tick(late.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := allPortsCalls(late); len(got) != 0 {
		t.Fatalf("started with an hour of window left: %q", got)
	}
	slow := allPortsEnv(t)
	slow.inv.mu.Lock()
	slow.inv.st.Rate = 20
	slow.inv.mu.Unlock()
	if err := slow.svc.Tick(slow.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := allPortsCalls(slow); len(got) != 0 {
		t.Fatalf("ran at 20 packets/s: %q", got)
	}
	if w := slow.svc.Health(slow.ctx()).Warning; !strings.Contains(w, "weekly scan of every port") {
		t.Fatalf("health warning %q", w)
	}
	for name, mut := range map[string]func(f *fakeInv){
		"unknown kind": func(f *fakeInv) { f.decision["a-web"] = sa.Decision{Allowed: true, Rate: 100, Unclassified: true} },
		"never": func(f *fakeInv) {
			f.decision["a-web"] = sa.Decision{Allowed: false, Never: true, Reason: "regular_scan_never"}
		},
		"first gentle":     func(f *fakeInv) { f.decision["a-web"] = sa.Decision{Allowed: true, Rate: 1, FirstGentle: true} },
		"the box":          func(f *fakeInv) { f.decision["a-web"] = sa.Decision{Allowed: false, Reason: "box"} },
		"declared by hand": func(f *fakeInv) { f.decision["a-web"] = sa.Decision{Allowed: false, Reason: "declared_by_hand"} },
		"a box address":    func(f *fakeInv) { f.box = []netip.Addr{netip.MustParseAddr("192.168.10.20")} },
		"out of scope":     func(f *fakeInv) { f.assets["a-web"] = netip.MustParseAddr("10.9.9.9") },
	} {
		e := allPortsEnv(t)
		e.inv.mu.Lock()
		mut(e.inv)
		e.inv.mu.Unlock()
		if err := e.svc.Tick(e.ctx()); err != nil {
			t.Fatal(err)
		}
		if got := allPortsCalls(e); len(got) != 0 {
			t.Errorf("%s: scanned every port: %q", name, got)
		}
		if n := e.count(`SELECT count(*) FROM sa_all_ports WHERE asset_id = 'a-web' AND outcome = 'not_eligible'`); n != 1 {
			t.Errorf("%s: not marked not eligible (%d)", name, n)
		}
	}
}

// D-592 (review r1 M3, M4): the weekly run only adds ports (the device's nmap software, its OS guess among them, is untouched);
// a normal scan afterwards keeps the ports the weekly run found outside its own lists; the next done weekly run that no longer sees
// a port drops it from that carry.
func TestAllPortsAddsPortsKeepsSoftwareAndTheNextWeekReplacesTheCarry(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	normal := writeFakeNmap(t, fakeOpts{}) // 22, 80, 8080 open, an OS match
	weekly := e.nm
	e.nm = normal
	e.build()
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	e.sink.mu.Lock()
	sw := slices.Clone(e.sink.sw["192.168.10.20"])
	e.sink.mu.Unlock()
	if !slices.ContainsFunc(sw, func(s observe.Software) bool { return s.Guess }) {
		t.Fatalf("the normal scan recorded no OS guess: %+v", sw)
	}
	e.nm = weekly
	e.build()
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := e.webPorts(); !slices.Equal(got, []int{22, 80, 8080, 40000}) {
		t.Fatalf("after the weekly scan: %v (added, nothing removed)", got)
	}
	e.sink.mu.Lock()
	after := e.sink.sw["192.168.10.20"]
	e.sink.mu.Unlock()
	if !slices.EqualFunc(after, sw, func(a, b observe.Software) bool { return a.Display == b.Display && a.Guess == b.Guess }) {
		t.Fatalf("the weekly scan changed the software: %+v, was %+v", after, sw)
	}
	e.nm = normal
	e.build()
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "again"); err != nil {
		t.Fatal(err)
	}
	if got := e.webPorts(); !slices.Equal(got, []int{22, 80, 8080, 40000}) {
		t.Fatalf("a normal scan after the weekly one: %v", got)
	}
	// a week later the weekly run no longer sees 40000 (device.xml): the carry is replaced, the next normal scan drops the port
	e.base = e.base.Add(7*24*time.Hour + time.Minute)
	e.build()
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "again"); err != nil {
		t.Fatal(err)
	}
	if got := e.webPorts(); !slices.Equal(got, []int{22, 80, 8080}) {
		t.Fatalf("after the next weekly run without 40000 and a normal scan: %v", got)
	}
}

// D-592 (review r1 M4): with no later weekly run, a port the weekly run found is carried by the normal scans for 14 days after that
// run, not for ever.
func TestAllPortsCarryEndsAfter14Days(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.nm = writeFakeNmap(t, fakeOpts{})
	e.build()
	e.base = e.base.Add(13 * 24 * time.Hour)
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "again"); err != nil {
		t.Fatal(err)
	}
	if got := e.webPorts(); !slices.Contains(got, 40000) {
		t.Fatalf("13 days after the weekly run: %v", got)
	}
	e.base = e.base.Add(2 * 24 * time.Hour)
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "again"); err != nil {
		t.Fatal(err)
	}
	if got := e.webPorts(); slices.Contains(got, 40000) {
		t.Fatalf("15 days after the weekly run the port is still carried: %v", got)
	}
}

// probeFunc is a Prober answering each argv with fn.
type probeFunc func(ctx context.Context, argv []string) (sa.Output, error)

func (f probeFunc) Probe(ctx context.Context, argv []string) (sa.Output, error) { return f(ctx, argv) }

func fixtureXML(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: a fixed name under testdata
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// withProber rebuilds the env's service around p.
func (e *env) withProber(p sa.Prober) {
	e.t.Helper()
	svc, err := sa.New(sa.Config{DB: e.db, Inventory: e.inv, Observe: e.sink, Software: e.sink, Services: e.sink, Events: e.ev, NmapPath: e.nm.path, Prober: p, Clock: e.clock, Location: e.loc})
	if err != nil {
		e.t.Fatal(err)
	}
	e.svc = svc
}

// blockingWeekly answers every run with device.xml, except the weekly discovery (-p-), which waits for its context to end.
type blockingWeekly struct {
	started chan struct{}
	once    sync.Once
	ended   chan error
}

func newBlockingWeekly(t *testing.T) (*blockingWeekly, probeFunc) {
	b := &blockingWeekly{started: make(chan struct{}), ended: make(chan error, 1)}
	xml := fixtureXML(t, "device.xml")
	return b, func(ctx context.Context, argv []string) (sa.Output, error) {
		if slices.Contains(argv, "-p-") {
			b.once.Do(func() { close(b.started) })
			<-ctx.Done()
			b.ended <- ctx.Err()
			return sa.Output{}, ctx.Err()
		}
		return sa.Output{XML: xml}, nil
	}
}

func runTick(e *env) <-chan error {
	done := make(chan error, 1)
	go func() { done <- e.svc.Tick(e.ctx()) }()
	return done
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// Review r1 M1: a Scan now identification goes before the weekly scan of every port: the weekly run in progress is stopped (its
// partial result dropped, the device still due) and the identification gets the slot at once, not "busy".
func TestAllPortsGivesWayToScanNow(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	b, p := newBlockingWeekly(t)
	e.withProber(p)
	tick := runTick(e)
	waitClosed(t, b.started, "the weekly run")
	start := time.Now()
	got, err := e.svc.IdentifyDevice(e.ctx(), "a-web")
	if err != nil || got.Why == sa.WhyBusy || time.Since(start) > 30*time.Second {
		t.Fatalf("identification = %+v, %v after %s", got, err, time.Since(start))
	}
	if err := <-b.ended; !errors.Is(err, context.Canceled) {
		t.Fatalf("the weekly run ended with %v, want stopped", err)
	}
	if err := <-tick; err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM sa_all_ports WHERE last_at IS NOT NULL AND asset_id = 'a-web'`); n != 0 {
		t.Fatal("the stopped weekly run was recorded as made: the device must stay due")
	}
}

// Review r1 M2 and L9: the weekly run stops when its device may no longer have it, through a settings change (the fragile kinds
// change devices without an event of their own) and through a change of the device itself.
func TestAllPortsStopsWhenTheDeviceTurnsFragile(t *testing.T) {
	t.Parallel()
	for name, notify := range map[string]func(e *env) error{
		"settings changed": func(e *env) error { return e.svc.SettingsChanged(e.ctx()) },
		"device changed":   func(e *env) error { return e.svc.AssetChanged(e.ctx(), "a-web") },
	} {
		for what, d := range map[string]sa.Decision{
			"fragile":      {Allowed: true, Rate: 100, Fragile: true},
			"unclassified": {Allowed: true, Rate: 100, Unclassified: true},
			"never":        {Allowed: false, Never: true, Reason: "regular_scan_never"},
		} {
			e := allPortsEnv(t)
			b, p := newBlockingWeekly(t)
			e.withProber(p)
			tick := runTick(e)
			waitClosed(t, b.started, "the weekly run")
			e.inv.mu.Lock()
			e.inv.decision["a-web"] = d
			e.inv.mu.Unlock()
			if err := notify(e); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-b.ended:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("%s, %s: the weekly run ended with %v", name, what, err)
				}
			case <-time.After(30 * time.Second):
				t.Fatalf("%s, %s: the weekly run did not stop", name, what)
			}
			if err := <-tick; err != nil {
				t.Fatal(err)
			}
		}
	}
}

// Review r1 M5: when the top-1000 run does not see the device and the extra run does, its ports are added, never a full
// replacement of the device's services and software.
func TestExtraOnlyHostOnlyAddsPorts(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	down, dev := fixtureXML(t, "down.xml"), fixtureXML(t, "device.xml")
	e.withProber(probeFunc(func(_ context.Context, argv []string) (sa.Output, error) {
		if slices.Contains(argv, "--top-ports") {
			return sa.Output{XML: down}, nil
		}
		return sa.Output{XML: dev}, nil
	}))
	e.sink.mu.Lock()
	e.sink.svc = map[string][]observe.Service{"192.168.10.20": {{Port: 9100, Proto: "tcp", Name: "jetdirect"}}}
	e.sink.sw = map[string][]observe.Software{"192.168.10.20": {{Display: "Linux", Guess: true}}}
	e.sink.mu.Unlock()
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	if got := e.webPorts(); !slices.Equal(got, []int{22, 80, 8080, 9100}) {
		t.Fatalf("ports %v: want 9100 kept and the extra run's added", got)
	}
	e.sink.mu.Lock()
	sw := e.sink.sw["192.168.10.20"]
	e.sink.mu.Unlock()
	if len(sw) != 1 || sw[0].Display != "Linux" {
		t.Fatalf("software replaced: %+v", sw)
	}
}

// Review r1 L9: an extra run that fails leaves the top-1000 result, recorded as a normal scan.
func TestExtraRunFailureKeepsTheTop1000Result(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	dev := fixtureXML(t, "device.xml")
	e.withProber(probeFunc(func(_ context.Context, argv []string) (sa.Output, error) {
		if slices.Contains(argv, "--top-ports") {
			return sa.Output{XML: dev}, nil
		}
		return sa.Output{}, sa.ErrWorkerLost
	}))
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	if got := e.webPorts(); !slices.Equal(got, []int{22, 80, 8080}) {
		t.Fatalf("ports %v", got)
	}
	if got := e.str(`SELECT group_concat(substr(result, 1, 6), ',') FROM sa_probe`); got != "ok: 1 ,failed" {
		t.Fatalf("probe results %q", got)
	}
}
