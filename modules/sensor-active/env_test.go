package sensoractive_test

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"maps"
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
	"github.com/knt048/vedette/modules/core"
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
if [ "$1" = "--version" ]; then echo "Nmap version 7.95 ( https://nmap.org )"; exit 0; fi
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
  *" -T2 "*) cat %q;;
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
	approved  map[string]bool // Asset.Approved (SNMP)
	// snmpDecision is what SNMPPolicy answers for a device; a device not in it gets its ScanPolicy answer.
	snmpDecision map[string]sa.Decision
	box          []netip.Addr // BoxIPs: the box and its decoys (a part of protected)
	// onAddresses, when set, runs at every Addresses call, outside the lock (a test acting in the middle of a read's preparation).
	onAddresses func()
	// onInScope runs once, at the next InScope (outside the lock): a test changes something between a check and the run.
	onInScope func()
	// snmpRead and snmpOn are what SNMPKnown answers (move); turnedOn are the devices TurnSNMPOn was called for, and
	// turnOnErr what it answers.
	snmpRead, snmpOn []string
	turnedOn         []string
	turnOnErr        error
	// similar is what SimilarDevices answers for a source device (the inventory's maker and type comparison is its own test)
	similar map[string][]sa.SimilarDevice
}

func (f *fakeInv) SimilarDevices(_ context.Context, id string) ([]sa.SimilarDevice, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.assets[id]; !ok {
		return nil, sa.ErrNotFound
	}
	return slices.Clone(f.similar[id]), nil
}

func (f *fakeInv) SNMPKnown(context.Context) (read, on []string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.snmpRead), slices.Clone(f.snmpOn), nil
}

func (f *fakeInv) TurnSNMPOn(_ context.Context, _, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.turnOnErr != nil {
		return f.turnOnErr
	}
	f.turnedOn = append(f.turnedOn, id)
	return nil
}

func (f *fakeInv) BoxIPs(context.Context) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.box), nil
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
	hook := f.onInScope
	f.onInScope = nil
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
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

func (f *fakeInv) SNMPPolicy(ctx context.Context, id string) (sa.Decision, error) {
	f.mu.Lock()
	d, ok := f.snmpDecision[id]
	_, known := f.assets[id]
	f.mu.Unlock()
	if ok && known {
		return d, nil
	}
	return f.ScanPolicy(ctx, id)
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
	return sa.Asset{ID: id, IP: ip, Approved: f.approved[id], Name: "device " + id}, nil
}

func (f *fakeInv) Addresses(context.Context) (map[netip.Addr]string, error) {
	f.mu.Lock()
	hook := f.onAddresses
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
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
	mu     sync.Mutex
	obs    []observe.Observation
	sw     map[string][]observe.Software // by IP
	svc    map[string][]observe.Service  // by IP
	adds   int                           // AddServices calls
	scopes []observe.ServiceScope        // the scope of every ReplaceServices call
	fail   error
	// read is when each port was last read with versions, by IP, as the inventory keeps inv_service.read_at: set on every listed port
	// of a list that read versions and on a port that names a product; a removed port loses it. now is the clock it is set by,
	// ipOf the address of a device id (PortReadTimes).
	read map[string]map[int]time.Time
	now  func() time.Time
	ipOf func(id string) string
}

// markRead sets a port's read time (s.mu held).
func (s *sink) markRead(ip string, port int) {
	if s.read == nil {
		s.read = map[string]map[int]time.Time{}
	}
	if s.read[ip] == nil {
		s.read[ip] = map[int]time.Time{}
	}
	s.read[ip][port] = s.now()
}

// PortReadTimes is the read time of each port of a device, as the inventory answers it.
func (s *sink) PortReadTimes(_ context.Context, id string, src observe.Source) (map[int]time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if src != observe.Nmap {
		return nil, fmt.Errorf("source %q", src)
	}
	return maps.Clone(s.read[s.ipOf(id)]), nil
}

// AddServices merges like the inventory: a new port is added, a listed one keeps what it had unless the item names a product
// (inventory INV-23: then name, product, version and confidence are updated).
func (s *sink) AddServices(_ context.Context, h observe.AssetHint, src observe.Source, items []observe.Service) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if src != observe.Nmap {
		return fmt.Errorf("source %q", src)
	}
	if s.svc == nil {
		s.svc = map[string][]observe.Service{}
	}
	s.adds++
	k := h.IP.String()
	for _, it := range items {
		i := slices.IndexFunc(s.svc[k], func(x observe.Service) bool { return x.Port == it.Port && x.Proto == it.Proto })
		if it.Proto == "tcp" && it.Product != "" {
			s.markRead(k, it.Port)
		}
		switch {
		case i < 0:
			s.svc[k] = append(s.svc[k], it)
		case it.Product != "":
			old := s.svc[k][i]
			s.svc[k][i] = observe.Service{Port: it.Port, Proto: it.Proto, Name: it.Name, Product: it.Product, Version: it.Version, Detail: cmp.Or(it.Detail, old.Detail), Confidence: it.Confidence}
		}
	}
	return nil
}

// ReplaceServices replaces like the inventory: inside the scope the listed ports are written and the other rows removed; a row
// outside it stays (scope.KeepFor aside, which this fake does not age); with scope.NoVersions a listed port keeps what it had
// unless the item names a product.
func (s *sink) ReplaceServices(_ context.Context, h observe.AssetHint, src observe.Source, scope observe.ServiceScope, items []observe.Service) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if src != observe.Nmap {
		return fmt.Errorf("source %q", src)
	}
	if s.svc == nil {
		s.svc = map[string][]observe.Service{}
	}
	k := h.IP.String()
	in := func(sv observe.Service) bool {
		return scope.Ports == nil || sv.Proto == "tcp" && slices.ContainsFunc(scope.Ports, func(r observe.PortRange) bool { return sv.Port >= r.From && sv.Port <= r.To })
	}
	for _, it := range items {
		if !in(it) {
			return fmt.Errorf("service %d/%s is outside the scope", it.Port, it.Proto)
		}
	}
	for _, it := range items {
		if it.Proto == "tcp" && (!scope.NoVersions || it.Product != "") {
			s.markRead(k, it.Port)
		}
	}
	var out []observe.Service // a row keeps its place; a new port goes last
	for _, old := range s.svc[k] {
		if i := slices.IndexFunc(items, func(x observe.Service) bool { return x.Port == old.Port && x.Proto == old.Proto }); i >= 0 {
			it := items[i]
			if scope.NoVersions && it.Product == "" {
				it.Name, it.Product, it.Version, it.Confidence = old.Name, old.Product, old.Version, old.Confidence
				it.Detail = cmp.Or(it.Detail, old.Detail)
			}
			out = append(out, it)
		} else if !in(old) {
			out = append(out, old)
		} else if old.Proto == "tcp" {
			delete(s.read[k], old.Port)
		}
	}
	for _, it := range items {
		if !slices.ContainsFunc(s.svc[k], func(x observe.Service) bool { return x.Port == it.Port && x.Proto == it.Proto }) {
			out = append(out, it)
		}
	}
	s.scopes = append(s.scopes, scope)
	s.svc[k] = out
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

// ReplaceSoftware replaces like the inventory: a nil scope is the whole list, otherwise only the readings of the scope's instances.
func (s *sink) ReplaceSoftware(_ context.Context, h observe.AssetHint, src observe.Source, scope []string, items []observe.Software) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if src != observe.Nmap {
		return fmt.Errorf("source %q", src)
	}
	if s.sw == nil {
		s.sw = map[string][]observe.Software{}
	}
	in := func(inst string) bool { return scope == nil || slices.Contains(scope, inst) }
	var out []observe.Software
	for _, old := range s.sw[h.IP.String()] {
		if !in(old.Instance) {
			out = append(out, old)
		}
	}
	for _, it := range items {
		if in(it.Instance) {
			out = append(out, it)
		}
	}
	s.sw[h.IP.String()] = out
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
	// base and t0 are the test's clock (clock): the run manager reads it from its own goroutines, so they are read and written under
	// clk only (setBase, setClock, baseTime)
	clk  sync.Mutex
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
	if err := store.Migrate(t.Context(), db, "core", core.Migrations); err != nil { // core_run: every run of the module
		t.Fatal(err)
	}
	if err := store.Migrate(t.Context(), db, "sensor-active", sa.Migrations); err != nil {
		t.Fatal(err)
	}
	runViews(t, db)
	e := &env{t: t, db: db, sink: &sink{}, ev: &events{}, base: local(9, 2, 0), t0: time.Now()}
	e.sink.now = e.clock
	e.sink.ipOf = func(id string) string {
		e.inv.mu.Lock()
		defer e.inv.mu.Unlock()
		return e.inv.assets[id].String()
	}
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
	e.clk.Lock()
	e.t0 = time.Now() // the clock starts when the env is ready: starting the remote worker (keys, TLS) must not eat a 2 s window
	e.clk.Unlock()
	return e
}

func (e *env) clock() time.Time {
	e.clk.Lock()
	defer e.clk.Unlock()
	return e.base.Add(time.Since(e.t0))
}

// setBase moves the clock's base, keeping its start; setClock sets the base and starts the clock again now; baseTime reads the base.
func (e *env) setBase(t time.Time) {
	e.clk.Lock()
	defer e.clk.Unlock()
	e.base = t
}

func (e *env) setClock(t time.Time) {
	e.clk.Lock()
	defer e.clk.Unlock()
	e.base, e.t0 = t, time.Now()
}

func (e *env) baseTime() time.Time {
	e.clk.Lock()
	defer e.clk.Unlock()
	return e.base
}

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
	if e.svc != nil { // a new service is a restart: the old one's runs end with its process
		e.svc.Close()
	}
	svc, err := sa.New(sa.Config{DB: e.db, Inventory: e.inv, Observe: e.sink, Software: e.sink, Services: e.sink, Events: e.ev, NmapPath: e.nm.path, Prober: prober, Clock: e.clock, Location: e.loc})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(svc.Close)
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

// sweptBefore records a pass that finished a week ago: the box is not new, so no first pass runs outside the window.
func (e *env) sweptBefore() {
	e.t.Helper()
	err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO core_run (id, module, kind, lane, title, trigger, requested_by, status, queued_at, started_at, ended_at, updated_at)
			VALUES ('run_old', 'sensor-active', 'lan_sweep', 'nmap', 'LAN sweep', 'schedule', 'system', 'done', '2026-11-02T02:00:00.000Z', '2026-11-02T02:00:00.000Z', '2026-11-02T02:01:00.000Z', '2026-11-02T02:01:00.000Z')`)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

// waitFor polls cond until it holds or 30 s pass (a busy machine under -race).
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); !cond(); <-time.After(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// runViews adds two read-only views over core_run to a test database, so the tests read the module's runs as rows of a job and of
// the window's queue: jobs_v (kind sweep|device|snmp|external, the reason it ran for, status done|failed|running|stopped, the device)
// and queue_v (the device checks waiting for their turn in the window, with the reason they were queued for).
func runViews(t *testing.T, db *store.DB) {
	t.Helper()
	inventoryStub(t, db)
	reason := `CASE WHEN r.kind = 'all_ports' THEN 'all_ports' WHEN r.kind = 'service_scan' THEN 'exposure'
		WHEN r.kind = 'snmp_read' AND r.trigger = 'manual' THEN 'snmp_test' WHEN r.kind = 'snmp_read' THEN 'window'
		WHEN r.kind = 'device_check' AND r.trigger = 'manual' THEN 'scan_now'
		WHEN r.trigger_note = 'a new device appeared' THEN 'discovered' WHEN r.trigger_note = 'no check reached the device yet' THEN 'first_check'
		WHEN r.trigger_note = 'its network scan was turned on' THEN 'scan_on' WHEN r.trigger_note = 'it is owed a full scan after its gentle look' THEN 'normal_owed'
		WHEN r.trigger_note = 'it waits for its gentle look' THEN 'gentle_titles' WHEN r.trigger_note = 'a person asked to check it' THEN 'check_now'
		ELSE NULL END`
	err := db.Write(t.Context(), func(tx *sql.Tx) error {
		for _, q := range []string{
			`CREATE VIEW jobs_v AS SELECT r.id, r.rowid AS rowid,
				CASE r.kind WHEN 'lan_sweep' THEN 'sweep' WHEN 'snmp_read' THEN 'snmp' WHEN 'service_scan' THEN 'external' ELSE 'device' END AS kind,
				` + reason + ` AS reason,
				CASE r.status WHEN 'done' THEN 'done' WHEN 'failed' THEN 'failed' WHEN 'running' THEN 'running' WHEN 'queued' THEN 'running' WHEN 'stopping' THEN 'running' ELSE 'stopped' END AS status,
				r.status AS run_status, COALESCE(r.started_at, r.queued_at) AS started_at, r.ended_at AS finished_at,
				CASE WHEN r.kind IN ('lan_sweep', 'snmp_read') THEN r.done ELSE r.total END AS targets,
				(SELECT count(*) FROM core_run_item i WHERE i.run_id = r.id AND i.outcome = 'new') AS new_devices,
				COALESCE(r.error, r.stop_reason, r.waiting_for) AS error,
				CASE WHEN r.subject_kind = 'device' THEN r.subject_id END AS asset_id
				FROM core_run r WHERE r.module = 'sensor-active' AND r.status NOT IN ('waiting') `,
			`CREATE VIEW queue_v AS SELECT r.subject_id AS asset_id, ` + reason + ` AS reason, r.queued_at, 0 AS attempts
				FROM core_run r WHERE r.module = 'sensor-active' AND r.kind = 'device_check' AND r.status IN ('waiting', 'queued')`,
		} {
			if _, err := tx.ExecContext(t.Context(), q); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// doneRunSQL is the INSERT of a run of the module that ended done at ts (id, kind lan_sweep|device_check|..., the device or "").
const doneRunSQL = `INSERT INTO core_run (id, module, kind, lane, title, trigger, requested_by, subject_kind, subject_id, status, queued_at, started_at, ended_at, updated_at)
	VALUES (?1, 'sensor-active', ?2, 'nmap', 'a run', 'schedule', 'system', CASE WHEN ?4 <> '' THEN 'device' END, NULLIF(?4, ''), 'done', ?3, ?3, ?3, ?3)`

// dropQueueSQL ends every device check waiting in the window's queue.
const dropQueueSQL = `UPDATE core_run SET status = 'stopped', stop_reason = 'dropped by the test', ended_at = updated_at WHERE kind = 'device_check' AND status IN ('waiting', 'queued')`

// newService builds another service over the env's database in place of e.svc (a test with its own inventory or prober): one run
// manager per database, as on a box, so the old service is closed first.
func (e *env) newService(cfg sa.Config) (*sa.Service, error) {
	if e.svc != nil {
		e.svc.Close()
	}
	svc, err := sa.New(cfg)
	if err != nil {
		return nil, err
	}
	e.t.Cleanup(svc.Close)
	e.svc = svc
	return svc, nil
}

// inventoryStub stands for the inventory's device table in a test database without the inventory's schema: sa_snmp_device references
// inv_asset, and every device a test gives SNMP settings exists there (a trigger adds it), as on a box.
func inventoryStub(t *testing.T, db *store.DB) {
	t.Helper()
	err := db.Write(t.Context(), func(tx *sql.Tx) error {
		for _, q := range []string{
			`CREATE TABLE inv_asset (id TEXT NOT NULL PRIMARY KEY)`,
			`CREATE TRIGGER inv_asset_stub_ins BEFORE INSERT ON sa_snmp_device BEGIN INSERT OR IGNORE INTO inv_asset (id) VALUES (NEW.asset_id); END`,
			`CREATE TRIGGER inv_asset_stub_upd BEFORE UPDATE OF asset_id ON sa_snmp_device BEGIN INSERT OR IGNORE INTO inv_asset (id) VALUES (NEW.asset_id); END`,
		} {
			if _, err := tx.ExecContext(t.Context(), q); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
