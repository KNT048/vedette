package sensoractive_test

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/progress"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// outsideWindow is Monday 12:00: the env's window is every day 01:00 to 05:00.
func outsideWindow(e *env) { e.setBase(local(9, 12, 0)) }

func waitManual(t *testing.T, e *env) {
	t.Helper()
	if err := e.svc.WaitManual(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if e.svc.Manual(t.Context()) != nil {
		t.Fatal("the manual run is still listed after it ended")
	}
}

// INV-21 (#850): "Scan the LAN now" sweeps the whole scope at once, outside the window, as a run that is listed with its progress
// while it goes on; the window's own rules still hold (a sweep, the probe log).
func TestContract_INV21_ScanTheLANNowOutsideTheWindow(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow)
	m, err := e.svc.StartManual(e.ctx(), "admin@example.com", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID == "" || len(m.Assets) != 0 || !slices.Equal(m.Ranges, []string{"192.168.10.0/26"}) || m.Progress == nil || m.Progress.Phase != progress.PhaseDiscovery {
		t.Fatalf("run = %+v", m)
	}
	if cur := e.svc.Manual(t.Context()); cur == nil || cur.ID != m.ID {
		t.Fatalf("Manual() = %+v while the run goes on", cur)
	}
	if v, err := e.svc.Engine(e.ctx()); err != nil || v.Manual == nil || v.Manual.ID != m.ID {
		t.Fatalf("Engine().Manual = %+v, %v", v.Manual, err)
	}
	waitManual(t, e)
	var sweeps int
	for _, c := range e.nm.calls(t) {
		if slices.Contains(c, "-sn") {
			sweeps++
		}
	}
	if sweeps == 0 {
		t.Fatal("no sweep ran outside the window")
	}
	if n := e.count(`SELECT count(*) FROM jobs_v WHERE kind = 'sweep' AND status = 'done'`); n < 1 {
		t.Fatalf("done sweeps = %d", n)
	}
	v, err := e.svc.Engine(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if h, ok := v.Last[sa.KindSweep]; !ok || h.Status != sa.StatusDone {
		t.Fatalf("last sweep = %+v", v.Last)
	}
	// the next window opens Tuesday 01:00
	if want := local(10, 1, 0); v.NextWindow == nil || !v.NextWindow.Equal(want) || v.Open {
		t.Fatalf("next window = %v (open %v), want %v", v.NextWindow, v.Open, want)
	}
}

// INV-21: "Check this device now" runs the identification of the device a person named, by its address or its id, outside the window.
func TestContract_INV21_CheckThisDeviceNow(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow, func(e *env) {
		e.inv.addrs[netip.MustParseAddr("192.168.10.20")] = "a-web"
	})
	m, err := e.svc.StartManual(e.ctx(), "admin@example.com", []string{"192.168.10.20"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Assets, []string{"a-web"}) || m.IP != netip.MustParseAddr("192.168.10.20") {
		t.Fatalf("run = %+v", m)
	}
	waitManual(t, e)
	if n := e.count(`SELECT count(*) FROM jobs_v WHERE kind = 'device' AND reason = 'scan_now' AND status = 'done'`); n != 1 {
		t.Fatalf("device jobs = %d (%s; blocked %v; calls %q)", n, e.str(`SELECT ifnull(group_concat(kind || ' ' || ifnull(reason, '-') || ' ' || status || ' ' || ifnull(error, ''), '; '), 'none') FROM jobs_v`), e.ev.named(sa.EventScanBlocked), e.nm.calls(t))
	}
	var hit bool
	for _, c := range e.nm.calls(t) {
		hit = hit || slices.Contains(targetsOf(c), "192.168.10.20")
		if slices.Contains(c, "-sn") {
			t.Fatalf("a device check swept: %q", c)
		}
	}
	if !hit {
		t.Fatal("the device was not scanned")
	}
	// by id, two devices at once: the address of the run is only set for one device
	e.inv.addrs[netip.MustParseAddr("192.168.10.30")] = "a-printer"
	m, err = e.svc.StartManual(e.ctx(), "admin@example.com", []string{"a-web", "192.168.10.30", "a-web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Assets, []string{"a-web", "a-printer"}) || m.IP.IsValid() {
		t.Fatalf("run = %+v", m)
	}
	waitManual(t, e)
}

// INV-21: a run is refused before anything is sent when the switch, the scope or a target's rules do not allow it; one run at a time.
func TestContract_INV21_ManualRunRefusals(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, outsideWindow, func(e *env) {
		e.inv.addrs[netip.MustParseAddr("192.168.10.20")] = "a-web"
		e.inv.addrs[netip.MustParseAddr("10.9.9.9")] = "a-far"
		e.inv.assets["a-never"] = netip.MustParseAddr("192.168.10.40")
		e.inv.decision["a-never"] = sa.Decision{Never: true, Reason: "regular_scan_never"}
		e.inv.assets["a-hand"] = netip.MustParseAddr("192.168.10.41")
		e.inv.decision["a-hand"] = sa.Decision{Reason: "declared_by_hand"}
		e.inv.assets["a-box"] = netip.MustParseAddr("192.168.10.42")
		e.inv.protected = []netip.Addr{netip.MustParseAddr("192.168.10.42")}
		e.inv.assets["a-noip"] = netip.Addr{}
		e.inv.st.Exclusions = []string{"192.168.10.30"}
	})
	refused := func(targets []string, reason, detail string) {
		t.Helper()
		_, err := e.svc.StartManual(e.ctx(), "admin@example.com", targets, nil)
		var te *sa.TargetError
		if !errors.As(err, &te) || te.Reason != reason || (detail != "" && te.Detail != detail) {
			t.Fatalf("%q: err = %v, want %s (%s)", targets, err, reason, detail)
		}
	}
	refused([]string{"192.168.10.77"}, sa.RefuseUnknown, "")
	refused([]string{"a-nobody"}, sa.RefuseUnknown, "")
	refused([]string{"10.9.9.9"}, sa.RefuseOutOfScope, "")
	refused([]string{"a-printer"}, sa.RefuseOutOfScope, "") // 192.168.10.30 is excluded
	refused([]string{"a-box"}, sa.RefuseOutOfScope, "box")
	refused([]string{"a-never"}, sa.RefuseNotAllowed, "regular_scan_never")
	refused([]string{"a-hand"}, sa.RefuseNotAllowed, "declared_by_hand")
	refused([]string{"a-noip"}, sa.RefuseNotAllowed, "no_ip")
	refused([]string{"a-web", "a-never"}, sa.RefuseNotAllowed, "regular_scan_never") // one refused target refuses the run
	many := make([]string, sa.MaxManualTargets+1)
	for i := range many {
		many[i] = "a-web"
	}
	refused(many, sa.RefuseNotAllowed, "too_many")

	e.inv.set(func(st *sa.Settings) { st.ScopeConfirmed = false })
	if _, err := e.svc.StartManual(e.ctx(), "admin@example.com", nil, nil); !errors.Is(err, sa.ErrScopeNotConfirmed) {
		t.Fatalf("scope not confirmed: %v", err)
	}
	e.inv.set(func(st *sa.Settings) { st.ScopeConfirmed, st.Enabled = true, false })
	if _, err := e.svc.StartManual(e.ctx(), "admin@example.com", []string{"a-web"}, nil); !errors.Is(err, sa.ErrScanningOff) {
		t.Fatalf("scanning off: %v", err)
	}
	if n := len(e.nm.calls(t)); n != 0 || e.svc.Manual(t.Context()) != nil {
		t.Fatalf("a refused run sent %d nmap commands", n)
	}

	// a second run while the first goes on (its nmap does not end by itself) is queued behind it, never refused (INV-28)
	slow := newEnv(t, fakeOpts{slowFrom: 1}, outsideWindow)
	first, err := slow.svc.StartManual(slow.ctx(), "admin@example.com", []string{"a-web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m, err := slow.svc.StartManual(slow.ctx(), "admin@example.com", nil, nil); err != nil || m.ID == first.ID {
		t.Fatalf("second run: %+v, %v", m, err)
	}
	slow.svc.Stop()
	waitManual(t, slow)
}

// INV-21: turning the module off (Stop) ends a manual run.
func TestContract_INV21_StopEndsAManualRun(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{slowFrom: 1}, outsideWindow)
	if _, err := e.svc.StartManual(e.ctx(), "admin@example.com", nil, nil); err != nil {
		t.Fatal(err)
	}
	e.svc.Stop()
	waitManual(t, e)
	if n := e.count(`SELECT count(*) FROM jobs_v WHERE kind = 'sweep' AND status = 'done'`); n != 0 {
		t.Fatalf("a stopped sweep finished: %d done", n)
	}
}
