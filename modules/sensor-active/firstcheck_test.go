package sensoractive_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/progress"
	sa "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

const fwIP = "100.65.254.1"

// firstCheckEnv is the default env (window 01:00 to 05:00, the scope 192.168.10.0/26) with a device at fwIP that the inventory
// refuses while the range is not in the scope, as the real inventory does.
func firstCheckEnv(t *testing.T) *env {
	return newEnv(t, fakeOpts{}, func(e *env) {
		e.inv.assets["a-fw"] = netip.MustParseAddr(fwIP)
		e.inv.decision["a-fw"] = sa.Decision{Reason: "out_of_scope"}
		for id, ip := range e.inv.assets {
			e.inv.addrs[ip] = id
		}
	})
}

func (e *env) allowFirewall(ranges ...string) {
	e.inv.mu.Lock()
	delete(e.inv.decision, "a-fw")
	e.inv.mu.Unlock()
	e.inv.set(func(st *sa.Settings) { st.LANRanges = append(st.LANRanges, ranges...) })
}

func (e *env) fwChecks() int {
	n := 0
	for _, c := range e.nm.calls(e.t) {
		if slices.Contains(c, fwIP) {
			n++
		}
	}
	return n
}

// A device whose network scan was turned on while it was out of scope was refused at its turn and left the queue. A range added
// later covers it: the settings change makes the next tick of the open window queue its first check, once.
func TestFirstCheckAfterARangeCoversTheDevice(t *testing.T) {
	t.Parallel()
	e := firstCheckEnv(t)
	if err := e.svc.Enqueue(e.ctx(), "a-fw", "scan_on"); err != nil {
		t.Fatal(err)
	}
	markSweepDone(t, e, "saj-sweep-a")
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := e.fwChecks(); n != 0 || e.count(`SELECT count(*) FROM queue_v WHERE asset_id = 'a-fw'`) != 0 {
		t.Fatalf("an out-of-scope device was checked (%d) or is still queued", n)
	}
	e.allowFirewall("100.65.0.0/16")
	if err := e.svc.SettingsChanged(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Tick(e.ctx()); err != nil { // the window is open now: it does not wait for the next one
		t.Fatal(err)
	}
	if n := e.fwChecks(); n == 0 {
		t.Fatal("the range covers the device and the window is open, but its first check did not run")
	}
	if n := e.count(`SELECT count(*) FROM jobs_v WHERE asset_id = 'a-fw' AND reason = 'first_check'`); n != 1 {
		t.Fatalf("%d first-check jobs, want 1", n)
	}
	e.setClock(local(10, 2, 0)) // the next window: it was checked, so nothing is owed
	markSweepDone(t, e, "saj-sweep-b")
	if err := e.svc.SettingsChanged(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM jobs_v j WHERE asset_id = 'a-fw' AND kind = 'device' AND EXISTS (SELECT 1 FROM sa_probe p WHERE p.run_id = j.id)`); n != 1 {
		t.Fatalf("%d checks after the next window, want still 1", n)
	}
}

// Nobody has to ask: a device no check ever reached that the policy allows owes its first check in the next window, however it
// became allowed (a range changed, a type set, scan turned on while the queue did not know it).
func TestFirstCheckForADeviceNothingQueued(t *testing.T) {
	t.Parallel()
	e := firstCheckEnv(t)
	e.allowFirewall("100.65.0.0/16")
	markSweepDone(t, e, "saj-sweep-a")
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM jobs_v WHERE asset_id = 'a-fw' AND reason = 'first_check'`); n != 1 {
		t.Fatalf("%d first-check jobs, want 1", n)
	}
}

// The scan switch turned on queues the device; the check runs at the first tick of the window, before the window's sweep, and
// when the switch is turned on after the window opened tonight it runs at the next tick, not the next window.
func TestScanOnRunsInTheNextWindowBeforeTheSweep(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, func(e *env) { e.setBase(local(9, 0, 30)) }) // before tonight's window (01:00)
	e.sweptBefore()                                                         // not a new box: no first pass outside the window
	if err := e.svc.Enqueue(e.ctx(), "a-web", "scan_on"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := len(e.nm.calls(t)); n != 0 {
		t.Fatalf("%d commands before the window opened", n)
	}
	e.setClock(local(9, 3, 0)) // the window opened two hours ago
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	calls := e.nm.calls(t)
	first := slices.IndexFunc(calls, func(c []string) bool { return slices.Contains(c, "192.168.10.20") })
	sweep := slices.IndexFunc(calls, func(c []string) bool { return slices.Contains(c, "-sn") })
	if first < 0 || (sweep >= 0 && sweep < first) {
		t.Fatalf("the device's check (index %d) must come before the sweep (index %d): %q", first, sweep, calls)
	}
	if n := e.count(`SELECT count(*) FROM jobs_v WHERE asset_id = 'a-web' AND reason = 'scan_on'`); n != 1 {
		t.Fatalf("%d scan_on jobs", n)
	}
	// turned on at 03:30, after the window opened: the next tick runs it
	e.setClock(local(9, 3, 30))
	if err := e.svc.Enqueue(e.ctx(), "a-printer", "scan_on"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM jobs_v WHERE asset_id = 'a-printer' AND reason = 'scan_on'`); n != 1 {
		t.Fatalf("a device switched on inside the open window was not checked at the next tick: %d", n)
	}
}

// holdExternal runs an exposure scan that holds nmap until the returned release is called; progress is what the scan reports.
func holdExternal(t *testing.T, d *driven, report *progress.Update) (release func()) {
	t.Helper()
	in, out := make(chan struct{}), make(chan struct{})
	d.onRun = func(_ int, argv []string) {
		if slices.Contains(argv, boxIP.String()) {
			close(in)
			<-out
		}
	}
	ctx := t.Context()
	if report != nil {
		tr := progress.NewTracker(d.clk.now)
		tr.Report(*report)
		ctx = progress.WithSink(ctx, tr)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = d.svc.ScanExternal(ctx, boxIP, nmapargv.External, &ownFence{ok: []netip.Addr{boxIP}})
	}()
	select {
	case <-in:
	case <-time.After(20 * time.Second):
		t.Fatal("the exposure scan never reached nmap")
	}
	return func() { close(out); <-done }
}

func waitingText(t *testing.T, d *driven) string {
	t.Helper()
	var got string
	waitFor(t, "the check a person started to say what it waits for", func() bool {
		if m := d.svc.Manual(t.Context()); m != nil && m.Progress != nil && m.Progress.Message != nil && strings.HasPrefix(*m.Progress.Message, "Queued behind") {
			got = *m.Progress.Message
		}
		return got != ""
	})
	return got
}

// A check a person starts that meets an exposure scan holding nmap is a queued run right behind it that names the run it waits for,
// runs as soon as nmap is free, and leaves nothing waiting.
func TestPersonCheckWaitsBehindTheExposureScanAndRunsWhenFree(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		report *progress.Update
		want   string
	}{
		"with the scan's estimate": {&progress.Update{Phase: progress.PhasePorts, Percent: 10, Remaining: 6 * time.Minute}, "Queued behind “Service scan of 8.8.8.8 for External exposure”; it starts when that run ends"},
		"without an estimate":      {nil, "Queued behind “Service scan of 8.8.8.8 for External exposure”; it starts when that run ends"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := newDriven(t)
			release := holdExternal(t, d, c.report)
			if _, err := d.svc.StartManual(d.ctx(), "admin@example.com", []string{"a-web"}, nil); err != nil {
				release()
				t.Fatal(err)
			}
			got := waitingText(t, d)
			if got != c.want {
				release()
				t.Fatalf("waiting text %q, want %q", got, c.want)
			}
			if probed(d.calls(), "192.168.10.20") {
				release()
				t.Fatal("the check ran while the exposure scan held nmap")
			}
			if n := d.count(`SELECT count(*) FROM core_run WHERE kind = 'device_check' AND status = 'queued' AND subject_id = 'a-web'`); n != 1 {
				release()
				t.Fatalf("the check is not a queued run: %d", n)
			}
			release()
			waitManual(t, d.env)
			if !probed(d.calls(), "192.168.10.20") {
				t.Fatal("the check did not run when nmap was free")
			}
			if n := d.count(`SELECT count(*) FROM queue_v`); n != 0 {
				t.Fatalf("%d rows left in the queue", n)
			}
			if n := d.count(`SELECT count(*) FROM jobs_v WHERE asset_id = 'a-web' AND kind = 'device' AND status = 'done'`); n != 1 {
				t.Fatalf("%d finished checks of the device", n)
			}
		})
	}
}

// After a person's check ran, no other row of the device scans it again tonight.
func TestPersonCheckDropsTheDevicesOtherQueueRows(t *testing.T) {
	t.Parallel()
	d := newDriven(t)
	d.sweptBefore()
	for _, r := range []string{"first_check"} {
		if err := d.svc.Enqueue(d.ctx(), "a-web", r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.svc.StartManual(d.ctx(), "admin@example.com", []string{"a-web"}, nil); err != nil {
		t.Fatal(err)
	}
	waitManual(t, d.env)
	if n := d.count(`SELECT count(*) FROM queue_v WHERE asset_id = 'a-web'`); n != 0 {
		t.Fatalf("%d rows of the device left after its check", n)
	}
}

// The first check of a fragile device is the gentle one; a device the policy refuses is not queued at all.
func TestFirstCheckShapeAndRefusals(t *testing.T) {
	t.Parallel()
	e := firstCheckEnv(t)
	e.inv.mu.Lock()
	e.inv.decision["a-web"] = sa.Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true, Fragile: true}
	e.inv.decision["a-printer"] = sa.Decision{Reason: "fragile_passive_only", Fragile: true}
	e.inv.mu.Unlock()
	markSweepDone(t, e, "saj-sweep-a")
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM sa_probe p JOIN jobs_v j ON j.id = p.run_id WHERE j.asset_id = 'a-web' AND j.reason = 'first_check' AND p.shape IN ('gentle', 'gentle_titles')`); n != 1 {
		t.Fatalf("%d gentle probes of the fragile device's first check", n)
	}
	if n := e.count(`SELECT count(*) FROM sa_probe p JOIN jobs_v j ON j.id = p.run_id WHERE j.asset_id = 'a-web' AND p.shape IN ('normal', 'versions')`); n != 0 {
		t.Fatalf("%d normal probes of a fragile device", n)
	}
	if n := e.count(`SELECT count(*) FROM jobs_v WHERE asset_id = 'a-printer'`); n != 0 {
		t.Fatalf("a device the policy refuses was checked: %d", n)
	}
}

// A deleted device leaves no row in the queue.
func TestDeletedDeviceLeavesTheQueue(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	for _, r := range []string{"check_wait", "first_check"} {
		id := map[string]string{"check_wait": "a-web", "first_check": "a-printer"}[r]
		if err := e.svc.Enqueue(e.ctx(), id, r); err != nil {
			t.Fatal(err)
		}
		deleteDevice(t, e.db, e.svc, id)
	}
	if n := e.count(`SELECT count(*) FROM queue_v`); n != 0 {
		t.Fatalf("%d rows left", n)
	}
}
