package sensoractive_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// markSweepDone writes a finished sweep for the current window so Tick goes straight to the queue.
func markSweepDone(t *testing.T, e *env, id string) {
	t.Helper()
	if err := e.db.Write(e.ctx(), func(tx dbTx) error {
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO sa_job (id, kind, started_at, finished_at, status) VALUES (?, 'sweep', ?, ?, 'done')`, id, store.FormatTS(e.clock()), store.FormatTS(e.clock()))
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// M4: a device scan cut by its deadline counts as an attempt and goes to the back of the queue, so it cannot
// block the devices behind it window after window (and is dropped after maxAttempts).
func TestQueueDeviceCutByTheDeadlineGoesToTheBack(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{slowFrom: 1}) // every nmap run sleeps 30 s, longer than what is left of the window
	for _, id := range []string{"a-printer", "a-web"} {
		if err := e.svc.Enqueue(e.ctx(), id, "discovered"); err != nil {
			t.Fatal(err)
		}
	}
	for i, day := range []int{9, 10, 11} {
		e.base, e.t0 = local(day, 4, 59).Add(57*time.Second), time.Now() // 3 s before the window closes
		markSweepDone(t, e, "saj-sweep-"+string(rune('a'+i)))
		if err := e.svc.Tick(e.ctx()); err != nil && !errors.Is(err, sa.ErrStopped) {
			t.Fatal(err)
		}
		if i == 0 {
			if got := e.count(`SELECT attempts FROM sa_queue WHERE asset_id = 'a-printer'`); got != 1 {
				t.Fatalf("a-printer was cut by its deadline: attempts = %d, want 1", got)
			}
			if got := e.str(`SELECT asset_id FROM sa_queue ORDER BY queued_at, asset_id LIMIT 1`); got != "a-web" {
				t.Fatalf("first in the queue = %q, want a-web: the cut device goes to the back", got)
			}
		}
	}
	var printer, web int
	for _, c := range e.nm.calls(t) {
		switch {
		case slices.Contains(c, "192.168.10.30"):
			printer++
		case slices.Contains(c, "192.168.10.20"):
			web++
		}
	}
	if web == 0 {
		t.Fatalf("three windows: a-printer cut %d times, a-web behind it never scanned", printer)
	}
}

// A scan stopped by a settings change is not an attempt: only a deadline is.
func TestQueueDeviceStoppedBySettingsKeepsItsAttempts(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{slowFrom: 1})
	if err := e.svc.Enqueue(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	markSweepDone(t, e, "saj-sweep-a")
	done := make(chan error, 1)
	go func() { done <- e.svc.Tick(e.ctx()) }()
	waitFor(t, "the fake nmap to start", func() bool { return len(e.nm.calls(t)) > 0 })
	e.inv.set(func(s *sa.Settings) { s.Enabled = false })
	if err := e.svc.SettingsChanged(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := e.count(`SELECT attempts FROM sa_queue WHERE asset_id = 'a-web'`); got != 0 {
		t.Fatalf("attempts = %d after a stop by settings, want 0", got)
	}
}

// POST-1 / D-84 (6) / M5: a sweep cut by the window's end continues where it stopped in the next window, so a range
// that one window cannot cover is finished over several days.
func TestSweepCutByTheWindowResumesWhereItStopped(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{slowFrom: 2}, func(e *env) {
		e.base = local(9, 4, 59).Add(57 * time.Second)
		e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/25"} }) // batches .1-.64 and .65-.126
	})
	if _, err := e.svc.DiscoverRanges(e.ctx()); !errors.Is(err, sa.ErrStopped) {
		t.Fatalf("first window: err = %v, want ErrStopped", err)
	}
	e.base, e.t0 = local(10, 4, 59).Add(57*time.Second), time.Now()
	_, _ = e.svc.DiscoverRanges(e.ctx())
	calls := e.nm.calls(t)
	if len(calls) < 3 {
		t.Fatalf("%d runs", len(calls))
	}
	if first := targetsOf(calls[2])[0]; first != "192.168.10.65" {
		t.Fatalf("the second window's sweep started at %s, want 192.168.10.65 (.1-.64 were finished in window 1)", first)
	}
}

// M5: a pass that reached the end is followed by a new pass from the first address; a sweep tests addresses in
// memory (no InScope call per address).
func TestSweepNewPassStartsAfterTheLastEnded(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	for day := 9; day <= 10; day++ {
		e.base, e.t0 = local(day, 2, 0), time.Now()
		if _, err := e.svc.DiscoverRanges(e.ctx()); err != nil {
			t.Fatal(err)
		}
	}
	calls := e.nm.calls(t)
	if len(calls) != 2 || !slices.Equal(targetsOf(calls[0]), targetsOf(calls[1])) {
		t.Fatalf("%d runs; each finished pass must cover the whole range again", len(calls))
	}
	if got := e.count(`SELECT count(*) FROM sa_sweep WHERE cursor IS NOT NULL`); got != 0 {
		t.Fatal("the cursor of a finished pass was kept")
	}
	if n := len(e.inv.checked); n != 0 {
		t.Fatalf("InScope was called %d times: addresses are tested in memory against the settings read once per batch", n)
	}
}

// M2: the sweep skips the addresses the inventory protects.
func TestContract_INV5_SweepSkipsProtectedAddresses(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, func(e *env) {
		e.inv.protected = []netip.Addr{netip.MustParseAddr("192.168.10.30"), netip.MustParseAddr("192.168.10.40"), netip.MustParseAddr("::ffff:192.168.10.5")}
	})
	if _, err := e.svc.DiscoverRanges(e.ctx()); err != nil {
		t.Fatal(err)
	}
	got := hostsOf(e.nm.calls(t))
	for _, ip := range []string{"192.168.10.30", "192.168.10.40", "192.168.10.5"} {
		if slices.Contains(got, ip) {
			t.Errorf("the sweep probed the protected address %s", ip)
		}
	}
	if !slices.Contains(got, "192.168.10.29") || !slices.Contains(got, "192.168.10.31") {
		t.Fatalf("the neighbours of a protected address are still swept: %v", got)
	}
}

// L2 / D-45: nmap finished the gentle scan but storing its results failed (a busy database, say). The one
// scan happened, so first_scan_at is set and the fragile device is not scanned a second time.
func TestContract_INV5_FirstScanIsMarkedWhenNmapFinishedEvenIfRecordingFails(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	h := &hookInv{fakeInv: e.inv}
	// the inventory's rule: first_gentle_scan until MarkFirstScan, then passive only
	h.policy = func(id string) (sa.Decision, bool) {
		if id != "a-printer" {
			return sa.Decision{}, false
		}
		if slices.Contains(e.inv.markedIDs(), id) {
			return sa.Decision{Reason: "fragile_passive_only"}, true
		}
		return sa.Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true}, true
	}
	sw := &failingSoftware{sink: e.sink, fail: errors.New("database is locked")}
	svc, err := sa.New(sa.Config{DB: e.db, Inventory: h, Observe: e.sink, Software: sw, Events: e.ev, NmapPath: e.nm.path, Prober: e.prober(), Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	first := svc.ScanDevice(e.ctx(), "a-printer", "discovered")
	sw.fail = nil
	second := svc.ScanDevice(e.ctx(), "a-printer", "discovered")
	if first == nil {
		t.Error("recording failed but the first ScanDevice reported success")
	}
	if !errors.Is(second, sa.ErrBlocked) {
		t.Errorf("second ScanDevice = %v, want ErrBlocked", second)
	}
	if n := len(e.nm.calls(t)); n != 1 {
		t.Fatalf("the fragile device got %d gentle scans, want 1", n)
	}
}

// failingSoftware fails ReplaceSoftware while fail is set (the inventory write after a finished nmap run).
type failingSoftware struct {
	*sink
	fail error
}

func (f *failingSoftware) ReplaceSoftware(ctx context.Context, h observe.AssetHint, src observe.Source, items []observe.Software) error {
	if f.fail != nil {
		return f.fail
	}
	return f.sink.ReplaceSoftware(ctx, h, src, items)
}

// M6 / INV-3: the window is read in the organization's time zone, not the clock's or the box's.
func TestContract_INV3_WindowIsReadInTheConfiguredZone(t *testing.T) {
	t.Parallel()
	zone := time.FixedZone("UTC+7", 7*3600)
	for name, c := range map[string]struct {
		at     time.Time
		inside bool
	}{
		"03:00 there is inside 01:00-05:00": {time.Date(2026, 11, 9, 3, 0, 0, 0, zone), true},
		"12:00 there is outside":            {time.Date(2026, 11, 9, 12, 0, 0, 0, zone), false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, fakeOpts{}, func(e *env) {
				e.base = c.at.UTC() // the clock says UTC; only the zone makes it 03:00 or 12:00
				e.loc = func() *time.Location { return zone }
			})
			_, err := e.svc.DiscoverRanges(e.ctx())
			if c.inside && err != nil || !c.inside && !errors.Is(err, sa.ErrOutsideWindow) {
				t.Fatalf("err = %v, inside = %v", err, c.inside)
			}
			if h := e.svc.Health(e.ctx()); h.Zone != "UTC+7" {
				t.Fatalf("Health.Zone = %q", h.Zone)
			}
		})
	}
	e := newEnv(t, fakeOpts{})
	if h := e.svc.Health(e.ctx()); h.Zone != time.Local.String() {
		t.Fatalf("default zone = %q, want the box's %q", h.Zone, time.Local)
	}
}

// M5: Health warns while the addresses divided by the rate cannot fit in one window, and the sweep logs it.
func TestHealthWarnsWhenASweepCannotFitTheWindow(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	if h := e.svc.Health(e.ctx()); h.Warning != "" || h.Status != "ok" {
		t.Fatalf("a /26 at 100 packets/s: %+v", h)
	}
	e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"10.0.0.0/16"}; s.Rate = 2 }) // 65534 s, window is 4 h
	h := e.svc.Health(e.ctx())
	if h.Status != "ok" || !strings.Contains(h.Warning, "several days") {
		t.Fatalf("a /16 at 2 packets/s in a 4 hour window: %+v", h)
	}
	e.inv.set(func(s *sa.Settings) { s.Enabled = false })
	if h := e.svc.Health(e.ctx()); h.Warning != "" {
		t.Fatalf("scanning is off, there is nothing to warn about: %+v", h)
	}
}

// M5 / INV-9: probe rows are compact (shape, rate, count, first, last) and still say what was sent.
func TestProbeRowsAreCompact(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/25"} })
	if _, err := e.svc.DiscoverRanges(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	if got := e.str(`SELECT group_concat(shape || ' ' || rate || ' ' || hosts || ' ' || targets, '; ') FROM sa_probe`); got !=
		"sweep 100 64 192.168.10.1-192.168.10.64; sweep 100 62 192.168.10.65-192.168.10.126; normal 100 1 192.168.10.20" {
		t.Fatalf("probe rows = %q", got)
	}
	probes, err := e.svc.Probes(e.ctx(), e.base.Add(-time.Hour), 100)
	if err != nil || len(probes) != 3 {
		t.Fatalf("Probes = %d rows, %v", len(probes), err)
	}
	if probes[1].Target != "192.168.10.65-192.168.10.126" || probes[1].Shape != "sweep" || probes[1].Rate != 100 || probes[2].Target != "192.168.10.20" {
		t.Fatalf("probes = %+v", probes)
	}
}

// L5: pruning the probe log also removes the jobs that have no probe row left; a job with a recent probe stays.
func TestPruneRemovesOldJobsWithTheirProbes(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	if _, err := e.svc.DiscoverRanges(e.ctx()); err != nil {
		t.Fatal(err)
	}
	old := store.FormatTS(e.clock().AddDate(0, 0, -400))
	if err := e.db.Write(e.ctx(), func(tx dbTx) error {
		if _, err := tx.ExecContext(e.ctx(), `INSERT INTO sa_job (id, kind, started_at, finished_at, status) VALUES ('saj-old', 'sweep', ?, ?, 'done')`, old, old); err != nil {
			return err
		}
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES (?, 'saj-old', 'sweep', 10, 1, '--privileged -sn -n --max-rate 10', '10.0.0.1', 'ok')`, old)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := e.svc.Prune(e.ctx()); err != nil || n != 1 {
		t.Fatalf("Prune = %d, %v; want 1", n, err)
	}
	if got := e.count(`SELECT count(*) FROM sa_job`); got != 1 {
		t.Fatalf("%d jobs after pruning, want only the recent one", got)
	}
}
