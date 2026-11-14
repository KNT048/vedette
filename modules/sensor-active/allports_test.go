package sensoractive_test

import (
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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

func allPortsEnv(t *testing.T, mut ...func(*env)) *env {
	t.Helper()
	fx, err := filepath.Abs(filepath.Join("testdata", "allports.xml"))
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, fakeOpts{always: fx}, mut...)
	e.sweptBefore()
	e.inv.mu.Lock()
	e.inv.addrs = map[netip.Addr]string{netip.MustParseAddr("192.168.10.20"): "a-web", netip.MustParseAddr("192.168.10.30"): "a-printer"}
	e.inv.decision["a-printer"] = sa.Decision{Allowed: true, Rate: 100, Fragile: true, Reason: "ok"} // a fragile device the policy still lets discovery scan
	e.inv.mu.Unlock()
	// the sweep of this window is done already: Tick goes straight to the queue, SNMP and the weekly scans
	if err := e.db.Write(e.ctx(), func(tx dbTx) error {
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO sa_job (id, kind, started_at, finished_at, status) VALUES ('saj_today', 'sweep', ?, ?, 'done')`,
			e.clock().UTC().Format("2006-01-02T15:04:05.000Z"), e.clock().UTC().Format("2006-01-02T15:04:05.000Z"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

// D-592: inside the window, a device that is not fragile gets one scan of every port a week (at most AllPortsMaxRate packets/s,
// logged as shape all_ports); a fragile one never; a second tick of the same week sends nothing; a week later it runs again.
func TestAllPortsOncePerWeekAndNeverForAFragileDevice(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := allPortsCalls(e); !slices.Equal(got, []string{"192.168.10.20"}) {
		t.Fatalf("weekly scans %q, want one of 192.168.10.20 only", got)
	}
	argv := e.nm.calls(t)[len(e.nm.calls(t))-1]
	if r := argv[slices.Index(argv, "--max-rate")+1]; r != "100" || slices.Contains(argv, "-O") || !slices.Contains(argv, "90m") {
		t.Fatalf("argv %q", argv)
	}
	if n := e.count(`SELECT count(*) FROM sa_probe WHERE shape = 'all_ports' AND targets = '192.168.10.20' AND result LIKE 'ok:%'`); n != 1 {
		t.Fatalf("probe rows of the weekly scan: %d", n)
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
// otherwise nothing is sent and Health says why for the rate. Unknown kind and never get none either.
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
	for name, d := range map[string]sa.Decision{
		"unknown kind": {Allowed: true, Rate: 100, Unclassified: true},
		"never":        {Allowed: false, Never: true, Reason: "regular_scan_never"},
		"first gentle": {Allowed: true, Rate: 1, FirstGentle: true},
		"the box":      {Allowed: false, Reason: "box"},
	} {
		e := allPortsEnv(t)
		e.inv.mu.Lock()
		e.inv.decision["a-web"] = d
		e.inv.mu.Unlock()
		if err := e.svc.Tick(e.ctx()); err != nil {
			t.Fatal(err)
		}
		if got := allPortsCalls(e); len(got) != 0 {
			t.Errorf("%s: scanned every port: %q", name, got)
		}
	}
}

// D-592: the weekly scan replaces the device's nmap services with every open port; a normal scan afterwards keeps the ports the
// weekly scan found outside its own list until the next weekly scan.
func TestAllPortsPortsSurviveTheNormalScan(t *testing.T) {
	t.Parallel()
	e := allPortsEnv(t)
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	ports := func() []int {
		e.sink.mu.Lock()
		defer e.sink.mu.Unlock()
		var out []int
		for _, s := range e.sink.svc["192.168.10.20"] {
			out = append(out, s.Port)
		}
		slices.Sort(out)
		return out
	}
	if got := ports(); !slices.Equal(got, []int{22, 80, 40000}) {
		t.Fatalf("after the weekly scan: %v", got)
	}
	e.nm = writeFakeNmap(t, fakeOpts{}) // the normal scan's output: 22, 80, 8080
	e.build()
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	if got := ports(); !slices.Equal(got, []int{22, 80, 8080, 40000}) {
		t.Fatalf("after a normal scan: %v", got)
	}
}
