package sensoractive_test

import (
	"path/filepath"
	"slices"
	"testing"

	sa "github.com/knt048/vedette/modules/sensor-active"
)

func absFixture(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// D-501: a device known only by its address, picked in Scan now outside the discovery window, is identified at once with the
// normal scan (-sV -O) at a quarter of the rate; what nmap found is recorded (software with its CPE) and said in words; the run
// is in the probe log like any other.
func TestIdentifyDevice_UnknownDeviceOutsideTheWindow(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{always: absFixture(t, "iphone.xml")}, func(e *env) { e.base = local(9, 12, 0) }) // 12:00, the window is 01:00-05:00
	e.inv.decision["a-web"] = sa.Decision{Reason: "unclassified_passive_only", Unclassified: true}
	got, err := e.svc.IdentifyDevice(e.ctx(), "a-web")
	if err != nil {
		t.Fatal(err)
	}
	if got.Why != "" || !slices.Contains(got.Found, "Type: iot") {
		t.Fatalf("identification = %+v, want the phone identified", got)
	}
	calls := e.nm.calls(t)
	if len(calls) != 1 || !slices.Contains(calls[0], "-sV") || !slices.Contains(calls[0], "-O") || calls[0][slices.Index(calls[0], "--max-rate")+1] != "25" {
		t.Fatalf("nmap argv = %v, want one normal scan at 25 packets/s", calls)
	}
	e.sink.mu.Lock()
	sw := e.sink.sw["192.168.10.20"]
	e.sink.mu.Unlock()
	if len(sw) == 0 || sw[0].CPE != "cpe:/o:apple:iphone_os:15" {
		t.Fatalf("software = %+v, want the iOS row with its CPE", sw)
	}
	if n := e.count(`SELECT count(*) FROM sa_probe`); n != 1 {
		t.Fatalf("%d probe rows, want 1", n)
	}
	if r := e.str(`SELECT reason FROM sa_job`); r != "scan_now" {
		t.Fatalf("job reason %q", r)
	}
}

// A fragile device gets only the gentle scan: no software is replaced (the gentle scan has no -sV), and the reason says so.
func TestIdentifyDevice_FragileGetsTheGentleScanOnly(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	e.inv.decision["a-printer"] = sa.Decision{Reason: "fragile_passive_only", Fragile: true}
	got, err := e.svc.IdentifyDevice(e.ctx(), "a-printer")
	if err != nil {
		t.Fatal(err)
	}
	if got.Why != sa.WhyGentleOnly {
		t.Fatalf("identification = %+v, want gentle_only", got)
	}
	calls := e.nm.calls(t)
	if len(calls) != 1 || slices.Contains(calls[0], "-sV") || slices.Contains(calls[0], "-O") {
		t.Fatalf("nmap argv = %v, want one gentle scan", calls)
	}
	e.sink.mu.Lock()
	defer e.sink.mu.Unlock()
	if _, ok := e.sink.sw["192.168.10.30"]; ok {
		t.Fatalf("a gentle scan replaced the software: %v", e.sink.sw)
	}
}

// D-501 (walk 1 W1-6): a box that has never swept does not wait for the window: the next Tick sweeps and scans the queued devices
// at once, then a later Tick outside the window does nothing more.
func TestFirstPassOfANewBoxRunsOutsideTheWindow(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, func(e *env) { e.base = local(9, 12, 0) }) // noon, the window is 01:00-05:00
	if err := e.svc.Enqueue(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, c := range e.nm.calls(t) {
		kinds = append(kinds, c[1])
	}
	if !slices.Equal(kinds, []string{"-sn", "-sS"}) {
		t.Fatalf("first pass runs = %v, want the sweep then the queued device", kinds)
	}
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := len(e.nm.calls(t)); n != 2 {
		t.Fatalf("%d runs after a second Tick outside the window, want still 2", n)
	}
	// Outside the first pass the window is shut again: a device scan asked now waits for it.
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "x"); err == nil {
		t.Fatal("a device scan ran outside the window after the first pass")
	}
}

// Refusals send nothing and say why: active scanning off, a device added by hand, an address out of scope.
func TestIdentifyDevice_RefusalsSendNothing(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, id, why string
		mut           func(e *env)
	}{
		{"scanning off", "a-web", "scanning_off", func(e *env) { e.inv.set(func(s *sa.Settings) { s.Enabled = false }) }},
		{"by hand", "a-web", "declared_by_hand", func(e *env) { e.inv.decision["a-web"] = sa.Decision{Reason: "declared_by_hand"} }},
		{"out of scope", "a-far", "out_of_scope", func(*env) {}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, fakeOpts{})
			c.mut(e)
			got, err := e.svc.IdentifyDevice(e.ctx(), c.id)
			if err != nil {
				t.Fatal(err)
			}
			if got.Why != c.why || len(got.Found) != 0 {
				t.Fatalf("identification = %+v, want %s", got, c.why)
			}
			if n := len(e.nm.calls(t)); n != 0 {
				t.Fatalf("nmap ran %d times", n)
			}
		})
	}
}
