package sensoractive_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
		_, err := tx.ExecContext(e.ctx(), doneRunSQL, "run_"+ts, sa.RunSweep, ts, "")
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
	// both devices had their first check long ago (a device no check ever reached is checked first: INV-27)
	err := e.db.Write(e.ctx(), func(tx dbTx) error {
		for _, id := range []string{"a-web", "a-printer"} {
			if _, err := tx.ExecContext(e.ctx(), doneRunSQL, "run-first-"+id, sa.RunCheck, "2026-11-02T02:00:00.000Z", id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(e.ctx(), `INSERT INTO sa_probe (time, run_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-02T02:00:01.000Z', ?, 'normal', 100, 1, '-sS', '192.168.10.1', 'ok: 1 hosts up')`, "run-first-"+id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// readAt is when the inventory fake says port of a-web (192.168.10.20) was last read with versions; zero: never.
func (e *env) readAt(port int) time.Time {
	e.sink.mu.Lock()
	defer e.sink.mu.Unlock()
	return e.sink.read["192.168.10.20"][port]
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

// Inside the window, a device that is not fragile gets one port discovery over every port a week (no -sV, no
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
	e.setBase(e.baseTime().Add(7*24*time.Hour + time.Minute)) // a week later, the same hour: inside the window again
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := allPortsCalls(e); !slices.Equal(got, []string{"192.168.10.20", "192.168.10.20"}) {
		t.Fatalf("a week later: %q", got)
	}
}

// A weekly scan needs a whole run's room in the window (AllPortsHostTimeout) and a rate of at least AllPortsMinRate;
// otherwise nothing is sent and Health says why for the rate. Unknown kind, never, first gentle, the box (by policy and by its
// addresses, review r1 L1), declared by hand and out of scope get none either.
func TestAllPortsNeedsRoomRateAndAKnownSafeDevice(t *testing.T) {
	t.Parallel()
	late := allPortsEnv(t, func(e *env) { e.setBase(local(9, 3, 15)) }) // 105 minutes left: not the 90 + 30 a run and its follow-up need (review r2 L2)
	if err := late.svc.Tick(late.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := allPortsCalls(late); len(got) != 0 {
		t.Fatalf("started with 105 minutes of window left: %q", got)
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

// The weekly run only adds ports (the device's nmap software, its OS guess among them, is untouched);
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
	// review r2 M2: the follow-up's product on 40000 is added; the normal scan's rows, the OS guess among them, stay
	if len(after) != len(sw)+1 || !slices.EqualFunc(after[:len(sw)], sw, func(a, b observe.Software) bool { return a.Display == b.Display && a.Guess == b.Guess }) ||
		after[len(sw)].Display != "Acme admin 1.0" {
		t.Fatalf("the weekly scan's software: %+v, was %+v", after, sw)
	}
	e.nm = normal
	e.build()
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "again"); err != nil {
		t.Fatal(err)
	}
	if got := e.webPorts(); !slices.Equal(got, []int{22, 80, 8080, 40000}) {
		t.Fatalf("a normal scan after the weekly one: %v", got)
	}
	// a week later the weekly run no longer sees 40000 (it looked at every port): the port is removed by that run itself
	e.nm = writeFakeNmap(t, fakeOpts{always: absFixture(t, "allports_gone.xml")})
	e.setBase(e.baseTime().Add(7*24*time.Hour + time.Minute))
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

// Review r2 M2/L6: a product found only on a non-standard port reaches the device's software list (the matcher's input), and a
// version that changes between two weekly runs replaces the old one in the software and the services; the OS guess stays.
func TestAllPortsVersionChangeReachesSoftwareAndServices(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	weekly := e.nm
	e.nm = writeFakeNmap(t, fakeOpts{})
	e.build()
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	e.nm = weekly
	e.build()
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.setBase(e.baseTime().Add(7*24*time.Hour + time.Minute))
	e.nm = writeFakeNmap(t, fakeOpts{always: absFixture(t, "allports2.xml")}) // 40000 now answers 2.0
	e.build()
	if err := e.db.Write(e.ctx(), func(tx dbTx) error { // the sweep of this window is done too
		ts := e.clock().UTC().Format("2006-01-02T15:04:05.000Z")
		_, err := tx.ExecContext(e.ctx(), doneRunSQL, "run_week2", sa.RunSweep, ts, "")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.sink.mu.Lock()
	defer e.sink.mu.Unlock()
	var displays []string
	guess := false
	for _, sw := range e.sink.sw["192.168.10.20"] {
		displays = append(displays, sw.Display)
		guess = guess || sw.Guess
	}
	if !slices.Contains(displays, "Acme admin 2.0") || slices.Contains(displays, "Acme admin 1.0") || !guess {
		t.Fatalf("software after the second weekly run: %q (OS guess kept: %v)", displays, guess)
	}
	i := slices.IndexFunc(e.sink.svc["192.168.10.20"], func(s observe.Service) bool { return s.Port == 40000 })
	if i < 0 || e.sink.svc["192.168.10.20"][i].Version != "2.0" {
		t.Fatalf("services: %+v", e.sink.svc["192.168.10.20"])
	}
}

// A normal scan replaces only the ports it looked at: a port the weekly run found outside them stays, and the scan asks the
// inventory to drop it once the weekly run has not seen it for 14 days.
func TestNormalScanKeepsThePortsOfTheWeeklyRunFor14Days(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.nm = writeFakeNmap(t, fakeOpts{})
	e.build()
	e.setBase(e.baseTime().Add(13 * 24 * time.Hour))
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "again"); err != nil {
		t.Fatal(err)
	}
	if got := e.webPorts(); !slices.Contains(got, 40000) {
		t.Fatalf("a normal scan removed a port it did not look at: %v", got)
	}
	e.sink.mu.Lock()
	defer e.sink.mu.Unlock()
	last := e.sink.scopes[len(e.sink.scopes)-1]
	if last.KeepFor != 14*24*time.Hour || last.NoVersions || len(last.Ports) == 0 || slices.ContainsFunc(last.Ports, func(r observe.PortRange) bool { return 40000 >= r.From && 40000 <= r.To }) {
		t.Fatalf("the normal scan's scope: %+v", last)
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
	svc, err := e.newService(sa.Config{DB: e.db, Inventory: e.inv, Observe: e.sink, Software: e.sink, Services: e.sink, Events: e.ev, NmapPath: e.nm.path, Prober: p, Clock: e.clock, Location: e.loc})
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
	if got := e.str(`SELECT group_concat(substr(result, 1, 6), ',') FROM sa_probe WHERE run_id NOT LIKE 'run-first-%'`); got != "ok: 1 ,failed" {
		t.Fatalf("probe results %q", got)
	}
}

// openPortsXML is an nmap XML of 192.168.10.20 with n open TCP ports (from 30001 up), the shape of a SYN proxy or a tarpit.
func openPortsXML(n int) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap" start="1762650000" version="7.95" xmloutputversion="1.05">
<host starttime="1762650001" endtime="1762650030"><status state="up" reason="syn-ack" reason_ttl="64"/>
<address addr="192.168.10.20" addrtype="ipv4"/>
<ports>
`)
	for i := range n {
		fmt.Fprintf(&b, `<port protocol="tcp" portid="%d"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="unknown" method="table" conf="3"/></port>`+"\n", 30001+i)
	}
	b.WriteString(`</ports>
</host>
<runstats><finished time="1762650031" elapsed="30.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
`)
	return []byte(b.String())
}

// Review r2 M1/L6: a device that answers the weekly discovery on more than 40 ports, or on so many that the output is refused (more
// than 1,500 ports listed), counts as done for the week: "answers on every port", no follow-up, no port added; the next window does
// not run -p- on it again.
func TestAllPortsDeviceThatAnswersEverywhereIsDoneForTheWeek(t *testing.T) {
	t.Parallel()
	for name, n := range map[string]int{"41 open ports": 41, "2000 open ports": 2000} {
		e := allPortsEnv(t)
		var calls []string
		var mu sync.Mutex
		xml := openPortsXML(n)
		e.withProber(probeFunc(func(_ context.Context, argv []string) (sa.Output, error) {
			mu.Lock()
			calls = append(calls, strings.Join(argv, " "))
			mu.Unlock()
			return sa.Output{XML: xml}, nil
		}))
		if err := e.svc.Tick(e.ctx()); err != nil {
			t.Fatal(err)
		}
		if got := e.str(`SELECT coalesce(outcome, '') FROM sa_all_ports WHERE asset_id = 'a-web'`); got != "answers_everywhere" {
			t.Fatalf("%s: outcome %q", name, got)
		}
		if len(e.webPorts()) != 0 || len(calls) != 1 || !strings.Contains(calls[0], "-p-") {
			t.Fatalf("%s: ports %v, runs %q", name, e.webPorts(), calls)
		}
		e.setBase(e.baseTime().Add(24 * time.Hour)) // the next window
		sweptToday(e)
		if err := e.svc.Tick(e.ctx()); err != nil {
			t.Fatal(err)
		}
		if len(calls) != 1 {
			t.Fatalf("%s: the next window ran again: %q", name, calls)
		}
	}
}

// Review r2 M1: any other failure is tried once more in the next window (not again in this one), then waits for the next week.
func TestAllPortsFailureRetriesOnceThenWaitsAWeek(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	var runs int
	var mu sync.Mutex
	e.withProber(probeFunc(func(_ context.Context, argv []string) (sa.Output, error) {
		if slices.Contains(argv, "-p-") {
			mu.Lock()
			runs++
			mu.Unlock()
		}
		return sa.Output{}, sa.ErrWorkerLost
	}))
	tick := func(day int) {
		t.Helper()
		e.setBase(local(9+day, 2, 0))
		if err := e.db.Write(e.ctx(), func(tx dbTx) error {
			ts := e.clock().UTC().Format("2006-01-02T15:04:05.000Z")
			_, err := tx.ExecContext(e.ctx(), doneRunSQL, fmt.Sprintf("run_d%d", day), sa.RunSweep, ts, "")
			return err
		}); err != nil && day > 0 {
			t.Fatal(err)
		}
		for range 2 { // two ticks in the window: the second never retries
			if err := e.svc.Tick(e.ctx()); err != nil {
				t.Fatal(err)
			}
		}
	}
	want := map[int]int{0: 1, 1: 2, 2: 2, 6: 2, 8: 3} // day -> weekly runs so far
	for _, day := range []int{0, 1, 2, 6, 8} {
		tick(day)
		mu.Lock()
		n := runs
		mu.Unlock()
		if n != want[day] {
			t.Fatalf("day %d: %d weekly runs, want %d (outcome %q)", day, n, want[day], e.str(`SELECT coalesce(outcome, '') FROM sa_all_ports WHERE asset_id = 'a-web'`))
		}
	}
}

// Review r2 L1: a Scan now that lands while the follow-up -sV runs stops the weekly run: nothing of it is recorded, the device stays
// due.
func TestAllPortsStoppedDuringTheFollowUpRecordsNothing(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	all, dev := fixtureXML(t, "allports.xml"), fixtureXML(t, "device.xml")
	started := make(chan struct{})
	var once sync.Once
	e.withProber(probeFunc(func(ctx context.Context, argv []string) (sa.Output, error) {
		switch {
		case slices.Contains(argv, "-p-"):
			return sa.Output{XML: all}, nil
		case slices.Contains(argv, "40000"): // the follow-up
			once.Do(func() { close(started) })
			<-ctx.Done()
			return sa.Output{}, ctx.Err()
		}
		return sa.Output{XML: dev}, nil
	}))
	tick := runTick(e)
	waitClosed(t, started, "the follow-up")
	if got, err := e.svc.IdentifyDevice(e.ctx(), "a-web"); err != nil || got.Why == sa.WhyBusy {
		t.Fatalf("identification = %+v, %v", got, err)
	}
	if err := <-tick; err != nil {
		t.Fatal(err)
	}
	if slices.Contains(e.webPorts(), 40000) || e.count(`SELECT count(*) FROM sa_all_ports WHERE asset_id = 'a-web' AND last_at IS NOT NULL`) != 0 || !e.readAt(40000).IsZero() {
		t.Fatalf("the stopped weekly run was recorded: ports %v", e.webPorts())
	}
}

// Review r2 L3: with more open ports to read than one follow-up takes, the ports never read go first the next week, then the ones
// read longest ago.
func TestAllPortsFollowUpRotates(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	xml := openPortsXML(25) // 30001..30025, none in the extra list
	var follow []string
	var mu sync.Mutex
	e.withProber(probeFunc(func(_ context.Context, argv []string) (sa.Output, error) {
		if i := slices.Index(argv, "-p"); i >= 0 {
			mu.Lock()
			follow = append(follow, argv[i+1])
			mu.Unlock()
		}
		return sa.Output{XML: xml}, nil
	}))
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.setBase(e.baseTime().Add(7*24*time.Hour + time.Minute))
	sweptToday(e)
	e.inv.mu.Lock()
	e.inv.addrs = map[netip.Addr]string{netip.MustParseAddr("192.168.10.20"): "a-web"} // the queued normal scan aside: weekly only
	e.inv.mu.Unlock()
	if err := e.db.Write(e.ctx(), func(tx dbTx) error { _, err := tx.ExecContext(e.ctx(), dropQueueSQL); return err }); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	ports := func(lo, hi int) string {
		var p []string
		for n := lo; n <= hi; n++ {
			p = append(p, strconv.Itoa(n))
		}
		return strings.Join(p, ",")
	}
	want := []string{ports(30001, 30020), ports(30001, 30015) + "," + ports(30021, 30025)}
	if !slices.Equal(follow, want) {
		t.Fatalf("follow-ups %q, want %q", follow, want)
	}
}

// The follow-up picks its ports by when the inventory says each was last read with versions (inv_service.read_at): a port read in
// the last 6 days is left alone, the ports never read go first, then the one read longest ago; every port it read gets its read
// time moved, also one whose read named no product, so the next week's follow-up reads the others first.
func TestAllPortsFollowUpPicksByTheInventoryReadTimes(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	xml := openPortsXML(22) // 30001..30022, no product on any
	var follow []string
	var mu sync.Mutex
	e.withProber(probeFunc(func(_ context.Context, argv []string) (sa.Output, error) {
		if i := slices.Index(argv, "-p"); i >= 0 {
			mu.Lock()
			follow = append(follow, argv[i+1])
			mu.Unlock()
		}
		return sa.Output{XML: xml}, nil
	}))
	now := e.clock()
	e.sink.mu.Lock()
	e.sink.svc = map[string][]observe.Service{"192.168.10.20": {
		{Port: 30001, Proto: "tcp", Name: "http"}, {Port: 30002, Proto: "tcp", Name: "http"}, {Port: 30003, Proto: "tcp", Name: "http"},
	}}
	e.sink.read = map[string]map[int]time.Time{"192.168.10.20": {
		30001: now.Add(-2 * 24 * time.Hour),  // read this week: left alone
		30002: now.Add(-20 * 24 * time.Hour), // read longest ago: after the ports never read
		30003: now.Add(-10 * 24 * time.Hour), // read less long ago: no room left
	}}
	e.sink.mu.Unlock()
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	var want []string
	for n := 30002; n <= 30022; n++ {
		if n != 30003 {
			want = append(want, strconv.Itoa(n))
		}
	}
	if len(follow) != 1 || follow[0] != strings.Join(want, ",") {
		t.Fatalf("follow-up -p %q, want %q", follow, strings.Join(want, ","))
	}
	if got := e.readAt(30001); !got.Equal(now.Add(-2 * 24 * time.Hour)) {
		t.Errorf("port 30001 (not read) read at %v: a scan that read no versions moved it", got)
	}
	if got := e.readAt(30003); !got.Equal(now.Add(-10 * 24 * time.Hour)) {
		t.Errorf("port 30003 (not read) read at %v", got)
	}
	for _, p := range []int{30002, 30004, 30022} {
		if got := e.readAt(p); got.Before(now) {
			t.Errorf("port %d was read but its read time is %v", p, got)
		}
	}
}

// Review r2 L4: the weekly round removes the row of a device the inventory no longer has, never of one that only lost its address.
func TestAllPortsCleanupKeepsADeviceWithoutAnAddress(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.inv.mu.Lock()
	e.inv.addrs = map[netip.Addr]string{} // a-web has no address now; a-printer is gone from the inventory
	delete(e.inv.assets, "a-printer")
	e.inv.mu.Unlock()
	e.setBase(e.baseTime().Add(time.Minute))
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := e.str(`SELECT group_concat(asset_id, ',') FROM sa_all_ports`); got != "a-web" {
		t.Fatalf("rows %q, want only a-web's", got)
	}
}

// jsonCopies counts the JSON cells the module's own tables hold for a device: a column whose CHECK says json_valid and whose value
// is not an empty list or object. What the scans found about a device belongs to the inventory, so after a normal scan and a weekly
// run of every port there are none (before the inventory had a scoped replace of services, the weekly state kept its own copies).
func (e *env) jsonCopies() int {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT m.name, c.name FROM sqlite_master m, pragma_table_info(m.name) c
		WHERE m.type = 'table' AND m.name LIKE 'sa\_%' ESCAPE '\' AND instr(m.sql, 'json_valid(' || c.name || ')') > 0`)
	if err != nil {
		e.t.Fatal(err)
	}
	var cols [][2]string
	for rows.Next() {
		var c [2]string
		if err := rows.Scan(&c[0], &c[1]); err != nil {
			e.t.Fatal(err)
		}
		cols = append(cols, c)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		e.t.Fatal(err)
	}
	n := 0
	for _, c := range cols {
		n += e.count(fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s IS NOT NULL AND %s NOT IN ('[]', '{}')`, c[0], c[1], c[1]))
	}
	return n
}

func TestNoPerDeviceJSONCopiesAfterAScan(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	weekly := e.nm
	e.nm = writeFakeNmap(t, fakeOpts{})
	e.build()
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	e.nm = weekly
	e.build()
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := e.webPorts(); !slices.Contains(got, 40000) {
		t.Fatalf("the weekly run found nothing: %v", got)
	}
	t.Logf("per-device JSON copies after a normal scan and a weekly run: %d", e.jsonCopies())
	if n := e.jsonCopies(); n != 0 {
		t.Fatalf("%d per-device JSON copies in the module's tables", n)
	}
}
