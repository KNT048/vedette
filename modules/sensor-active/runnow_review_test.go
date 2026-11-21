package sensoractive_test

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sa "github.com/knt048/vedette/modules/sensor-active"
)

// The review of #857 (r1): a manual run under a clock and a Prober the test drives. Each nmap command calls on with its number
// (1-based) and argv while it runs, holding the nmap slot; the test changes the clock or the settings there. No sleep: every step
// waits on the run's state (WaitManual) or on a channel.

type stepClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *stepClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *stepClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type driven struct {
	*env
	clk   *stepClock
	mu    sync.Mutex
	argv  [][]string
	onRun func(n int, argv []string)
}

func (d *driven) calls() [][]string { d.mu.Lock(); defer d.mu.Unlock(); return slices.Clone(d.argv) }

// newDriven is newEnv outside the window (Monday 12:00) with the scope 192.168.10.0/24 (four sweep batches) and a Prober that
// answers a sweep with sweep.xml and a device with device.xml.
func newDriven(t *testing.T, mut ...func(*env)) *driven {
	t.Helper()
	e := newEnv(t, fakeOpts{}, append([]func(*env){func(e *env) { e.inv.st.LANRanges = []string{"192.168.10.0/24"} }}, mut...)...)
	d := &driven{env: e, clk: &stepClock{t: local(9, 12, 0)}}
	sweep, device := fixtureXML(t, "sweep.xml"), fixtureXML(t, "device.xml")
	pf := probeFunc(func(_ context.Context, argv []string) (sa.Output, error) {
		d.mu.Lock()
		d.argv = append(d.argv, slices.Clone(argv))
		n, on := len(d.argv), d.onRun
		d.mu.Unlock()
		if on != nil {
			on(n, argv)
		}
		if slices.Contains(argv, "-sn") {
			return sa.Output{XML: sweep}, nil
		}
		return sa.Output{XML: device}, nil
	})
	svc, err := e.newService(sa.Config{DB: e.db, Inventory: e.inv, Observe: e.sink, Software: e.sink, Services: e.sink, Events: e.ev, NmapPath: e.nm.path, Prober: pf, Clock: d.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return d
}

func sweeps(calls [][]string) (n int) {
	for _, c := range calls {
		if slices.Contains(c, "-sn") {
			n++
		}
	}
	return n
}

func probed(calls [][]string, ip string) bool {
	return slices.ContainsFunc(calls, func(c []string) bool { return slices.Contains(targetsOf(c), ip) })
}

// L12: the sweep's hour runs out after its first batch: no further batch; the pass waits for the scan window and goes on there.
func TestReview857_TheSweepStopsWhenItsHourIsOver(t *testing.T) {
	t.Parallel()
	d := newDriven(t)
	d.onRun = func(n int, _ []string) {
		if n == 1 {
			d.clk.add(time.Hour + time.Minute)
		}
	}
	if _, err := d.svc.StartManual(d.ctx(), "admin@example.com", nil, nil); err != nil {
		t.Fatal(err)
	}
	waitManual(t, d.env)
	if c := d.calls(); len(c) != 1 {
		t.Fatalf("%d nmap commands after the hour ran out, want the one batch: %q", len(c), c)
	}
	if got := d.str(`SELECT status || ': ' || waiting_for FROM core_run WHERE kind = 'lan_sweep'`); !strings.HasPrefix(got, "waiting: the scan window (opens ") {
		t.Fatalf("the person's sweep after its hour: %q, want it waiting for the window", got)
	}
}

// L12: discovery turned off, or an exclusion added, while a person's sweep runs: the next batch reads the settings again.
func TestReview857_ASweepFollowsTheSettingsWhileItRuns(t *testing.T) {
	t.Parallel()
	off := newDriven(t)
	off.onRun = func(n int, _ []string) {
		if n == 1 {
			off.inv.set(func(st *sa.Settings) { st.Enabled = false })
		}
	}
	if _, err := off.svc.StartManual(off.ctx(), "admin@example.com", nil, nil); err != nil {
		t.Fatal(err)
	}
	waitManual(t, off.env)
	if c := off.calls(); len(c) != 1 {
		t.Fatalf("discovery off after batch 1: %d commands", len(c))
	}

	excl := newDriven(t)
	excl.onRun = func(n int, _ []string) {
		if n == 1 {
			excl.inv.set(func(st *sa.Settings) { st.Exclusions = []string{"192.168.10.64/26"} })
		}
	}
	if _, err := excl.svc.StartManual(excl.ctx(), "admin@example.com", nil, nil); err != nil {
		t.Fatal(err)
	}
	waitManual(t, excl.env)
	c := excl.calls()
	if sweeps(c) < 2 {
		t.Fatalf("the sweep stopped instead of going on without the excluded range: %q", c)
	}
	for _, argv := range c[1:] {
		for _, tgt := range targetsOf(argv) {
			if a, err := netip.ParseAddr(strings.SplitN(tgt, "-", 2)[0]); err == nil && netip.MustParsePrefix("192.168.10.64/26").Contains(a) {
				t.Fatalf("an address excluded during the sweep was probed: %q", argv)
			}
		}
	}
}

// L12: each device of a person's check is its own run, checked again right before nmap: a device that moved out of the scope while the
// others ran is refused by its own check and nothing is sent to it.
func TestReview857_ADeviceCheckHasAnHourAndRechecksEachDevice(t *testing.T) {
	t.Parallel()
	d := newDriven(t, func(e *env) { e.inv.assets["a-third"] = netip.MustParseAddr("192.168.10.31") })
	d.onRun = func(n int, argv []string) {
		if slices.Contains(targetsOf(argv), "192.168.10.20") && n == 1 {
			d.inv.set(func(st *sa.Settings) { st.Exclusions = []string{"192.168.10.30"} }) // a-printer leaves the scope
		}
	}
	if _, err := d.svc.StartManual(d.ctx(), "admin@example.com", []string{"a-web", "a-printer", "a-third"}, nil); err != nil {
		t.Fatal(err)
	}
	waitManual(t, d.env)
	c := d.calls()
	if !probed(c, "192.168.10.20") || probed(c, "192.168.10.30") || !probed(c, "192.168.10.31") {
		t.Fatalf("commands %q: want .20 and .31, never .30 (excluded while the run went on)", c)
	}
}

// L1: the module turned off after the checks and before the claim refuses the run (the sticky off flag); turned on again, it runs.
// L4: a second sweep within SweepGap
// is refused with the time to wait. M2: a record that fails starts nothing.
func TestReview857_RefusalsBeforeAnythingStarts(t *testing.T) {
	t.Parallel()
	d := newDriven(t)
	d.svc.Stop()
	if _, err := d.svc.StartManual(d.ctx(), "admin@example.com", []string{"a-web"}, nil); !errors.Is(err, sa.ErrStopped) {
		t.Fatalf("module off: %v", err)
	}
	d.svc.Resume()

	fail := errors.New("the audit log is full")
	if _, err := d.svc.StartManual(d.ctx(), "admin@example.com", nil, func(*sql.Tx, sa.ManualRun) error { return fail }); !errors.Is(err, fail) {
		t.Fatalf("a failed record: %v", err)
	}
	if len(d.calls()) != 0 || d.svc.Manual(t.Context()) != nil {
		t.Fatal("a run whose record failed started")
	}
	var rec []sa.ManualRun
	m, err := d.svc.StartManual(d.ctx(), "admin@example.com", nil, func(_ *sql.Tx, m sa.ManualRun) error {
		if len(d.calls()) != 0 {
			t.Error("a command left before the record was written")
		}
		rec = append(rec, m)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rec) != 1 || rec[0].ID != m.ID || !slices.Equal(rec[0].Ranges, []string{"192.168.10.0/24"}) || !rec[0].Until.Equal(m.StartedAt.Add(time.Hour)) {
		t.Fatalf("recorded %+v, run %+v", rec, m)
	}
	waitManual(t, d.env)
	var soon *sa.TooSoonError
	if _, err := d.svc.StartManual(d.ctx(), "admin@example.com", nil, nil); !errors.As(err, &soon) || soon.RetryAfter <= 0 || soon.RetryAfter > sa.SweepGap {
		t.Fatalf("a second sweep at once: %v", err)
	}
	d.clk.add(sa.SweepGap)
	if _, err := d.svc.StartManual(d.ctx(), "admin@example.com", nil, nil); err != nil {
		t.Fatalf("after the gap: %v", err)
	}
	waitManual(t, d.env)
}

// L3: the box's own addresses and its decoys are refused whatever the device row says, even a passive-only one.
func TestReview857_TheBoxIsNeverChecked(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow, func(e *env) {
		e.inv.assets["a-old"] = netip.MustParseAddr("192.168.10.42")
		e.inv.decision["a-old"] = sa.Decision{Fragile: true, Reason: "fragile_passive_only"}
		e.inv.box = []netip.Addr{netip.MustParseAddr("192.168.10.42")}
		e.inv.protected = []netip.Addr{netip.MustParseAddr("192.168.10.42")}
	})
	var te *sa.TargetError
	if _, err := e.svc.StartManual(e.ctx(), "admin@example.com", []string{"a-old"}, nil); !errors.As(err, &te) || te.Reason != sa.RefuseOutOfScope || te.Detail != "box" {
		t.Fatalf("a passive-only row at the box's address: %v", err)
	}
	if res, err := e.svc.IdentifyDevice(e.ctx(), "a-old"); err != nil || res.Why != "box" || len(e.nm.calls(t)) != 0 {
		t.Fatalf("Scan now of it: %+v %v, %d commands", res, err, len(e.nm.calls(t)))
	}
}
