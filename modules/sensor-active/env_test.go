package sensoractive_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/exec/exectest"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// No test here runs a real nmap or sends a packet. The seam is the binary itself: a small shell script in
// t.TempDir(), registered as the nmap Binary of a real core/exec Runner (by the Service), that records its argv
// and prints a hand-written fixture from testdata/.

type fakeOpts struct {
	always   string // when set, print this file whatever the argv
	slowFrom int    // from this call number (1-based) the script sleeps 30 s before printing; 0 never
	exitCode int    // non-zero: exit with it after printing
}

type fakeNmap struct {
	path string
	log  string
}

func writeFakeNmap(t *testing.T, o fakeOpts) *fakeNmap {
	t.Helper()
	dir := t.TempDir()
	fx := func(name string) string {
		p, err := filepath.Abs(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	log := filepath.Join(dir, "argv.log")
	body := fmt.Sprintf(`#!/bin/sh
LOG=%q
if [ "$1" = "--version" ]; then echo "Nmap version 7.94SVN ( https://nmap.org )"; exit 0; fi
n=$(grep -c '^--$' "$LOG" 2>/dev/null)
[ -z "$n" ] && n=0
printf '%%s\n' "$@" >> "$LOG"
echo '--' >> "$LOG"
if [ %d -gt 0 ] && [ "$((n + 1))" -ge %d ]; then sleep 30; fi
`, log, o.slowFrom, o.slowFrom)
	if o.always != "" {
		body += "cat " + o.always + "\n"
	} else {
		body += fmt.Sprintf(`case " $* " in
  *" -sn "*) cat %q;;
  *" --max-retries "*) cat %q;;
  *) cat %q;;
esac
`, fx("sweep.xml"), fx("fragile.xml"), fx("device.xml"))
	}
	if o.exitCode != 0 {
		body += fmt.Sprintf("exit %d\n", o.exitCode)
	}
	path := filepath.Join(dir, "nmap")
	exectest.WriteScript(t, path, body)
	return &fakeNmap{path: path, log: log}
}

// calls returns the argv of every run, in order.
func (f *fakeNmap) calls(t *testing.T) [][]string {
	t.Helper()
	b, err := os.ReadFile(f.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out [][]string
	var cur []string
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if l == "--" {
			out = append(out, cur)
			cur = nil
			continue
		}
		cur = append(cur, l)
	}
	return out
}

// targetsOf are the addresses of an argv: everything after "-oX -".
func targetsOf(argv []string) []string {
	i := slices.Index(argv, "-oX")
	return argv[i+2:]
}

// fakeInv is the inventory port with the scope rule written out here, apart from the module's own code.
type fakeInv struct {
	mu       sync.Mutex
	st       sa.Settings
	assets   map[string]netip.Addr
	decision map[string]sa.Decision
	marked   []string
	addrs    map[netip.Addr]string
	macs     []string // KnownMACs
	checked  []netip.Addr
	// protected is what ProtectedIPs lists (a device by hand, never, fragile after its gentle scan, the box)
	protected []netip.Addr
}

func (f *fakeInv) Settings(context.Context) (sa.Settings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st, nil
}

func (f *fakeInv) set(fn func(*sa.Settings)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(&f.st)
}

func (f *fakeInv) InScope(_ context.Context, ip netip.Addr) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checked = append(f.checked, ip)
	in := false
	for _, r := range f.st.LANRanges {
		if p, err := netip.ParsePrefix(r); err == nil && p.Contains(ip) {
			in = true
		}
	}
	for _, x := range f.st.Exclusions {
		if a, err := netip.ParseAddr(x); err == nil && a == ip {
			in = false
		}
		if p, err := netip.ParsePrefix(x); err == nil && p.Contains(ip) {
			in = false
		}
	}
	return in, nil
}

func (f *fakeInv) ScanPolicy(_ context.Context, id string) (sa.Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.assets[id]; !ok {
		return sa.Decision{}, sa.ErrNotFound
	}
	if d, ok := f.decision[id]; ok {
		return d, nil
	}
	return sa.Decision{Allowed: true, Rate: f.st.Rate, Reason: "ok"}, nil
}

func (f *fakeInv) MarkFirstScan(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.marked = append(f.marked, id)
	return nil
}

func (f *fakeInv) Asset(_ context.Context, id string) (sa.Asset, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ip, ok := f.assets[id]
	if !ok {
		return sa.Asset{}, sa.ErrNotFound
	}
	return sa.Asset{ID: id, IP: ip}, nil
}

func (f *fakeInv) Addresses(context.Context) (map[netip.Addr]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[netip.Addr]string{}
	for k, v := range f.addrs {
		out[k] = v
	}
	return out, nil
}

func (f *fakeInv) KnownMACs(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.macs), nil
}

func (f *fakeInv) ProtectedIPs(context.Context) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.protected), nil
}

func (f *fakeInv) markedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.marked)
}

// sink records what the module reports to the inventory.
type sink struct {
	mu   sync.Mutex
	obs  []observe.Observation
	sw   map[string][]observe.Software // by IP
	svc  map[string][]observe.Service  // by IP
	fail error
}

func (s *sink) ReplaceServices(_ context.Context, h observe.AssetHint, src observe.Source, items []observe.Service) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if src != observe.Nmap {
		return fmt.Errorf("source %q", src)
	}
	if s.svc == nil {
		s.svc = map[string][]observe.Service{}
	}
	s.svc[h.IP.String()] = items
	return nil
}

func (s *sink) Record(_ context.Context, o []observe.Observation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	s.obs = append(s.obs, o...)
	return nil
}

func (s *sink) ReplaceSoftware(_ context.Context, h observe.AssetHint, src observe.Source, items []observe.Software) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if src != observe.Nmap {
		return fmt.Errorf("source %q", src)
	}
	if s.sw == nil {
		s.sw = map[string][]observe.Software{}
	}
	s.sw[h.IP.String()] = items
	return nil
}

func (s *sink) observations() []observe.Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.obs)
}

// events records what the module publishes.
type events struct {
	mu  sync.Mutex
	got []sa.Event
}

func (e *events) Publish(_ context.Context, ev sa.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.got = append(e.got, ev)
	return nil
}

func (e *events) named(name string) []sa.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []sa.Event
	for _, ev := range e.got {
		if ev.Name == name {
			out = append(out, ev)
		}
	}
	return out
}

type env struct {
	t    *testing.T
	db   *store.DB
	inv  *fakeInv
	sink *sink
	ev   *events
	nm   *fakeNmap
	svc  *sa.Service
	base time.Time
	t0   time.Time
	loc  func() *time.Location // the organization time zone; nil: the box's
	rem  *remote               // the far end of the remote Prober, when the suite runs with it (remote_test.go)
}

// local builds a time in the box's local zone (the zone the window is read in). 9 Nov 2026 is a Monday.
func local(day, hour, minute int) time.Time {
	return time.Date(2026, 11, day, hour, minute, 0, 0, time.Local)
}

// newEnv builds the service around a fake nmap. The clock starts at base and then runs in real time, so a run
// that sleeps really passes the end of the window. Default settings: every day 01:00-05:00, 100 packets/s,
// 192.168.10.0/26, scope confirmed; base is Monday 02:00 (inside).
func newEnv(t *testing.T, o fakeOpts, mut ...func(*env)) *env {
	t.Helper()
	db := storetest.New(t)
	if err := store.Migrate(t.Context(), db, "sensor-active", sa.Migrations); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, db: db, sink: &sink{}, ev: &events{}, base: local(9, 2, 0), t0: time.Now()}
	e.inv = &fakeInv{
		st: sa.Settings{Enabled: true, ScopeConfirmed: true, LANRanges: []string{"192.168.10.0/26"}, Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "01:00", To: "05:00", Rate: 100},
		assets: map[string]netip.Addr{
			"a-web":     netip.MustParseAddr("192.168.10.20"),
			"a-printer": netip.MustParseAddr("192.168.10.30"),
			"a-far":     netip.MustParseAddr("10.9.9.9"),
		},
		decision: map[string]sa.Decision{},
		addrs:    map[netip.Addr]string{},
	}
	e.nm = writeFakeNmap(t, o)
	for _, m := range mut {
		m(e)
	}
	e.build()
	e.t0 = time.Now() // the clock starts when the env is ready: starting the remote worker (keys, TLS) must not eat a 2 s window
	return e
}

func (e *env) clock() time.Time { return e.base.Add(time.Since(e.t0)) }

// prober is the Prober a Service of this env gets: nil (the local one) normally; in the remote run the Dispatcher with a worker
// that runs the env's current nmap path. When the path changed since the worker was made (a test that swaps the binary and
// builds again), the old worker is stopped and a new one is built for the new path.
func (e *env) prober() sa.Prober {
	if !remoteMode() {
		return nil
	}
	if e.rem != nil && e.rem.path != e.nm.path {
		e.rem.stop()
		e.rem = nil
	}
	if e.rem == nil {
		e.rem = startRemote(e)
	}
	return e.rem.d
}

func (e *env) build() {
	e.t.Helper()
	prober := e.prober()
	svc, err := sa.New(sa.Config{DB: e.db, Inventory: e.inv, Observe: e.sink, Software: e.sink, Services: e.sink, Events: e.ev, NmapPath: e.nm.path, Prober: prober, Clock: e.clock, Location: e.loc})
	if err != nil {
		e.t.Fatal(err)
	}
	e.svc = svc
}

func (e *env) ctx() context.Context { return e.t.Context() }

func (e *env) count(query string) int {
	e.t.Helper()
	var n int
	if err := e.db.Reader().QueryRowContext(e.ctx(), query).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
	return n
}

func (e *env) str(query string) string {
	e.t.Helper()
	var s string
	if err := e.db.Reader().QueryRowContext(e.ctx(), query).Scan(&s); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
	return s
}

type dbTx = *sql.Tx

// waitFor polls cond until it holds or 30 s pass (a busy machine under -race).
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); !cond(); <-time.After(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}
