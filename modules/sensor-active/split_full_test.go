package sensoractive_test

import (
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	sa "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// A deep scan in two runs through the real worker: the port scan of every TCP port (no -sV, no script), then -sV and the scripts on
// the 3 ports it found open, with -p naming exactly those and never -p- again. Each run is behind both fences and has its probe row.
func TestDeepScanReadsTheScriptsOnlyOnTheOpenPortsTheSweepFound(t *testing.T) {
	t.Parallel()
	sweep := svXML(t, false, svPort(22, "ssh", ""), svPort(443, "https", ""), svPort(49152, "unknown", ""))
	full, err := filepath.Abs(filepath.Join("testdata", "external_full.xml"))
	if err != nil {
		t.Fatal(err)
	}
	e := externalEnvWithNmap(t, boxIP, fakeOpts{cases: []fakeCase{{match: " -p- --max-rate ", file: sweep}, {match: " --script ", file: full}}})
	own := &deepFence{ownFence: ownFence{ok: []netip.Addr{boxIP}}, now: nmapargv.ExternalFull}

	ports, err := e.svc.ScanFullPortsWith(e.ctx(), boxIP, sa.WideSettings(), own)
	if err != nil {
		t.Fatal(err)
	}
	var open []int
	for _, s := range ports.Services {
		open = append(open, s.Port)
	}
	if !slices.Equal(open, []int{22, 443, 49152}) || ports.Ports != 65535 || len(ports.Scripts) != 0 {
		t.Fatalf("the port scan read %v open of %d ports, %d scripts", open, ports.Ports, len(ports.Scripts))
	}
	got, err := e.svc.ScanFullOnWith(e.ctx(), boxIP, open, sa.WideSettings(), own)
	if err != nil {
		t.Fatal(err)
	}
	if got.Ports != 3 || !slices.Equal(got.Probed, open) || len(got.Services) != 3 || len(got.Scripts) != 5 {
		t.Fatalf("the full run on the open ports: %d ports %v probed, %d services, %d scripts", got.Ports, got.Probed, len(got.Services), len(got.Scripts))
	}
	wantSweep, _ := nmapargv.Build(nmapargv.ExternalFullPorts, nmapargv.FullRate, []netip.Addr{boxIP})
	wantFull, _ := nmapargv.BuildFor(nmapargv.ExternalFull, nmapargv.FullRate, open, []netip.Addr{boxIP})
	calls := e.nm.calls(t)
	if len(calls) != 2 || !slices.Equal(calls[0], wantSweep) || !slices.Equal(calls[1], wantFull) {
		t.Fatalf("nmap argv = %q\nwant %q\nthen %q", calls, wantSweep, wantFull)
	}
	if slices.Contains(calls[1], "-p-") || calls[1][slices.Index(calls[1], "-p")+1] != "22,443,49152" {
		t.Fatalf("the second run sweeps again or names other ports: %q", calls[1])
	}
	if s := e.str(`SELECT group_concat(shape || '|' || result, ' / ') FROM sa_probe`); s != "external_full|ok: 3 open ports, 0 script results / external_full|ok: 3 open ports, 5 script results" {
		t.Fatalf("probe rows = %s", s)
	}
	if f := e.str(`SELECT group_concat(flags, ' / ') FROM sa_probe`); !strings.Contains(f, " -p- --max-rate 300 ") || !strings.Contains(f, " -p 22,443,49152 --script ") {
		t.Fatalf("flags = %s", f)
	}
	if len(own.asked) != 2 || own.ownFence.asked != 2 {
		t.Fatalf("the fences were asked %v / %d times, want before each run", own.asked, own.ownFence.asked)
	}
	// a port the target's settings skip never reaches the second run; none left is not a run
	if _, err := e.svc.ScanFullOnWith(e.ctx(), boxIP, []int{25}, sa.DeepSettings{Groups: nmapargv.AllGroups, SkipPorts: []int{25}}, own); err == nil {
		t.Fatal("a full run on only skipped ports was started")
	}
	if n := len(e.nm.calls(t)); n != 2 {
		t.Fatalf("nmap ran %d times", n)
	}
}

// A worker whose heartbeat does not say full_ports (older than the split) gets neither run: nothing is queued, and the caller gets
// ErrFullPortsUnsupported to run the one full run on every port instead. Such a worker would refuse both jobs anyway (an unknown
// shape; ports on a shape that takes none), never run something wider.
func TestSplitDeepScanNeedsAWorkerThatSaysSo(t *testing.T) {
	t.Parallel()
	d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 20 * time.Millisecond})
	hb := sensorlink.HeartbeatNmap{Present: true, Version: nmapargv.ReviewedNmapVersion, Full: true, Ports: true, Narrow: true}
	if _, err := d.ActiveHeartbeat(t.Context(), &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: hb}); err != nil {
		t.Fatal(err)
	}
	if d.RunsFullPorts() {
		t.Fatal("a worker that does not say full_ports runs the split")
	}
	sweep, err := nmapargv.Build(nmapargv.ExternalFullPorts, nmapargv.FullRate, []netip.Addr{boxIP})
	if err != nil {
		t.Fatal(err)
	}
	list, err := nmapargv.BuildFor(nmapargv.ExternalFull, nmapargv.FullRate, []int{22, 443}, []netip.Addr{boxIP})
	if err != nil {
		t.Fatal(err)
	}
	for _, argv := range [][]string{sweep, list} {
		if _, err := d.Probe(t.Context(), argv); !errors.Is(err, sa.ErrFullPortsUnsupported) {
			t.Fatalf("%q: err = %v", argv, err)
		}
	}
	rep, err := d.Jobs(t.Context(), 0, nil)
	if err != nil || len(rep.Jobs) != 0 {
		t.Fatalf("jobs = %+v %v", rep.Jobs, err)
	}
	e := newEnv(t, fakeOpts{})
	svc, err := e.newService(sa.Config{DB: e.db, Inventory: e.inv, Observe: e.sink, Software: e.sink, Services: e.sink, Events: e.ev, Prober: d, Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	own := &deepFence{ownFence: ownFence{ok: []netip.Addr{boxIP}}, now: nmapargv.ExternalFull}
	if _, err := svc.ScanFullPortsWith(e.ctx(), boxIP, sa.WideSettings(), own); !errors.Is(err, sa.ErrFullPortsUnsupported) {
		t.Fatalf("ScanFullPortsWith: err = %v", err)
	}
	if len(own.asked) != 0 || e.count(`SELECT count(*) FROM sa_probe`) != 0 {
		t.Fatalf("the gate was asked %v, %d probe rows", own.asked, e.count(`SELECT count(*) FROM sa_probe`))
	}
}
