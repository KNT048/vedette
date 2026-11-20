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
		_, err := tx.ExecContext(e.ctx(), doneRunSQL, id, sa.RunSweep, store.FormatTS(e.clock()), "")
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// A check stopped by turning active scanning off waits (a waiting run) for scanning to be turned on again.
func TestQueueDeviceStoppedBySettingsKeepsWaiting(t *testing.T) {
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
	if got := e.count(`SELECT count(*) FROM queue_v WHERE asset_id = 'a-web'`); got != 1 {
		t.Fatalf("the check stopped by turning scanning off left the queue (%d), want it waiting", got)
	}
}

// POST-1: a sweep cut by the window's end continues where it stopped in the next window, so a range
// that one window cannot cover is finished over several days.
func TestSweepCutByTheWindowResumesWhereItStopped(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{slowFrom: 2}, func(e *env) {
		e.setBase(local(9, 4, 59).Add(57 * time.Second))
		e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/25"} }) // batches .1-.64 and .65-.126
	})
	if _, err := e.svc.DiscoverRanges(e.ctx()); !errors.Is(err, sa.ErrStopped) {
		t.Fatalf("first window: err = %v, want ErrStopped", err)
	}
	e.setClock(local(10, 4, 59).Add(57 * time.Second))
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
		e.setClock(local(day, 2, 0))
		if _, err := e.svc.DiscoverRanges(e.ctx()); err != nil {
			t.Fatal(err)
		}
	}
	calls := e.nm.calls(t)
	if len(calls) != 2 || !slices.Equal(targetsOf(calls[0]), targetsOf(calls[1])) {
		t.Fatalf("%d runs; each finished pass must cover the whole range again", len(calls))
	}
	if got := e.count(`SELECT count(*) FROM core_run WHERE kind = 'lan_sweep' AND status = 'done'`); got != 2 {
		t.Fatalf("%d passes done, want two runs, one per pass", got)
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

// nmap finished the gentle scan but storing its results failed (a busy database, say). The one
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
	// the gentle scan records only its ports (it leaves the software alone), so that is the write that fails
	svc, err := e.newService(sa.Config{DB: e.db, Inventory: h, Observe: e.sink, Software: sw, Services: sw, Events: e.ev, NmapPath: e.nm.path, Prober: e.prober(), Clock: e.clock})
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

func (f *failingSoftware) ReplaceSoftware(ctx context.Context, h observe.AssetHint, src observe.Source, scope []string, items []observe.Software) error {
	if f.fail != nil {
		return f.fail
	}
	return f.sink.ReplaceSoftware(ctx, h, src, scope, items)
}

// AddServices fails too while fail is set: a gentle scan's only list write.
func (f *failingSoftware) AddServices(ctx context.Context, h observe.AssetHint, src observe.Source, items []observe.Service) error {
	if f.fail != nil {
		return f.fail
	}
	return f.sink.AddServices(ctx, h, src, items)
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
				e.setBase(c.at.UTC()) // the clock says UTC; only the zone makes it 03:00 or 12:00
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
		"sweep 100 64 192.168.10.1-192.168.10.64; sweep 100 62 192.168.10.65-192.168.10.126; normal 100 1 192.168.10.20; extra_ports 100 1 192.168.10.20" {
		t.Fatalf("probe rows = %q", got)
	}
	probes, err := e.svc.Probes(e.ctx(), e.baseTime().Add(-time.Hour), 100)
	if err != nil || len(probes) != 4 {
		t.Fatalf("Probes = %d rows, %v", len(probes), err)
	}
	if probes[1].Target != "192.168.10.65-192.168.10.126" || probes[1].Shape != "sweep" || probes[1].Rate != 100 || probes[2].Target != "192.168.10.20" {
		t.Fatalf("probes = %+v", probes)
	}
}

// L5: pruning drops the probe rows older than the retention; the runs are core/run's to prune (400 days).
func TestPruneRemovesOldProbes(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	if _, err := e.svc.DiscoverRanges(e.ctx()); err != nil {
		t.Fatal(err)
	}
	old := store.FormatTS(e.clock().AddDate(0, 0, -400))
	if err := e.db.Write(e.ctx(), func(tx dbTx) error {
		if _, err := tx.ExecContext(e.ctx(), doneRunSQL, "run-old", sa.RunSweep, old, ""); err != nil {
			return err
		}
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO sa_probe (time, run_id, shape, rate, hosts, flags, targets, result) VALUES (?, 'run-old', 'sweep', 10, 1, '--privileged -sn -n --max-rate 10', '10.0.0.1', 'ok')`, old)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := e.svc.Prune(e.ctx()); err != nil || n != 1 {
		t.Fatalf("Prune = %d, %v; want 1", n, err)
	}
	if got := e.count(`SELECT count(*) FROM sa_probe WHERE run_id = 'run-old'`); got != 0 {
		t.Fatalf("%d old probes after pruning", got)
	}
}

// pendingInv is the inventory with PendingGentle: the devices still waiting for their one gentle scan.
type pendingInv struct {
	*fakeInv
	ids   []string
	reads int
}

func (p *pendingInv) PendingGentleScans(context.Context) ([]string, error) {
	p.reads++
	return p.ids, nil
}

// #714 round 2, M1: a device whose first scan inventory migration 0004 cleared gets no inventory.asset.discovered event;
// the first tick queues it (once per start) and the window runs its gentle scan with titles.
func TestPendingGentleScanRunsAtTheFirstWindowTick(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	p := &pendingInv{fakeInv: e.inv, ids: []string{"a-printer"}}
	e.inv.decision["a-printer"] = sa.Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true, Unclassified: true}
	svc, err := e.newService(sa.Config{DB: e.db, Inventory: p, Observe: e.sink, Software: e.sink, Services: e.sink, Events: e.ev, NmapPath: e.nm.path, Prober: e.prober(), Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	e.setClock(local(9, 2, 0)) // inside the 01:00-05:00 window
	markSweepDone(t, e, "saj-sweep-p")
	if err := svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	calls := e.nm.calls(t)
	if len(calls) != 1 || !slices.Contains(calls[0], "192.168.10.30") || !slices.Contains(calls[0], "http-title,ssl-cert,http-hp-ilo-info,vmware-version") {
		t.Fatalf("nmap runs = %q, want the gentle scan with titles of a-printer", calls)
	}
	if err := svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if p.reads != 1 {
		t.Fatalf("the waiting devices were read %d times: once per start", p.reads)
	}
}

// A device found while its kind was unknown is scanned once, gently. When it later becomes one the policy scans normally (its type
// was set, the fragile kinds changed) it owes a normal scan: the window queues it once; a device that is still fragile is left
// alone, and once the scan ran (whatever it found) nothing queues it again.
func TestWindowQueuesTheNormalScanADeviceOwes(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	e.inv.addrs = map[netip.Addr]string{netip.MustParseAddr("192.168.10.20"): "a-web", netip.MustParseAddr("192.168.10.30"): "a-printer"}
	// window 1: both are new and of unknown kind: one gentle scan each
	first := sa.Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true, Unclassified: true}
	e.inv.decision = map[string]sa.Decision{"a-web": first, "a-printer": first}
	for _, id := range []string{"a-web", "a-printer"} {
		if err := e.svc.Enqueue(e.ctx(), id, "discovered"); err != nil {
			t.Fatal(err)
		}
	}
	markSweepDone(t, e, "saj-sweep-a")
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM sa_probe WHERE shape IN ('gentle', 'gentle_titles')`); n != 2 {
		t.Fatalf("%d gentle scans in the first window, want 2", n)
	}
	// window 2: a-web was given a type the policy scans normally; a-printer is fragile
	e.inv.mu.Lock()
	e.inv.decision = map[string]sa.Decision{"a-printer": {Reason: "fragile_passive_only", Fragile: true}}
	e.inv.mu.Unlock()
	e.setClock(local(10, 2, 0))
	markSweepDone(t, e, "saj-sweep-b")
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	var web, printerNormal int
	for _, c := range e.nm.calls(t) {
		switch {
		case slices.Contains(c, "192.168.10.20") && slices.Contains(c, "-sV"):
			web++
		case slices.Contains(c, "192.168.10.30") && slices.Contains(c, "-sV"):
			printerNormal++
		}
	}
	if web == 0 || printerNormal != 0 {
		t.Fatalf("normal scans of a-web = %d (want at least 1), of the fragile a-printer = %d", web, printerNormal)
	}
	if n := e.count(`SELECT count(*) FROM jobs_v WHERE asset_id = 'a-web' AND reason = 'normal_owed'`); n != 1 {
		t.Fatalf("%d jobs of the owed scan", n)
	}
	// window 3: the scan has run, so nothing is owed
	e.setClock(local(11, 2, 0))
	markSweepDone(t, e, "saj-sweep-c")
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM jobs_v WHERE asset_id = 'a-web' AND reason = 'normal_owed'`); n != 1 {
		t.Fatalf("%d jobs of the owed scan after the next window, want still 1", n)
	}
}
