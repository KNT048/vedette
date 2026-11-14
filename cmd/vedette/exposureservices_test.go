package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
	"github.com/knt048/vedette/modules/exposure"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

var ownPublicIP = netip.MustParseAddr("8.8.8.8") // stands for the box's own verified public IP of the fixtures

// fakeScanWorker is the scan container's worker over the real mutual-TLS link to the stack's Dispatcher: it reports a heartbeat with
// nmap present, fetches jobs by long poll and posts what answer says for each. No process runs and no packet leaves.
type fakeScanWorker struct {
	mu   sync.Mutex
	jobs []sensorlink.Job
}

func startFakeScanWorker(t *testing.T, s *stack, answer func(sensorlink.Job) *sensorlink.JobResult) *fakeScanWorker {
	t.Helper()
	return startFakeScanWorkerFull(t, s, false, answer)
}

// startFakeScanWorkerFull is startFakeScanWorker whose heartbeat says, with full, that it runs the deep shapes (D-526); without it
// the worker is one of a release before them.
func startFakeScanWorkerFull(t *testing.T, s *stack, full bool, answer func(sensorlink.Job) *sensorlink.JobResult) *fakeScanWorker {
	t.Helper()
	f := &fakeScanWorker{}
	c := linktest.New(t, sensorBackend{s.d.SensorPassive, s.d.SensorDispatcher}).Client(t, sensorlink.Active)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			if _, err := c.ActiveHeartbeat(ctx, &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true, Version: "7.94", Full: full}}); err != nil {
				return
			}
			rep, err := c.Jobs(ctx, nil, time.Second)
			if err != nil {
				return
			}
			for _, j := range rep.Jobs {
				f.mu.Lock()
				f.jobs = append(f.jobs, j)
				f.mu.Unlock()
				_ = c.PostResult(ctx, j.ID, answer(j))
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
	return f
}

func (f *fakeScanWorker) received() []sensorlink.Job {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sensorlink.Job(nil), f.jobs...)
}

func nmapFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "modules", "sensor-active", "testdata", name)) //nolint:gosec // fixed fixture names
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func xmlResult(b []byte) *sensorlink.JobResult {
	r := &sensorlink.JobResult{Status: "done"}
	r.SetXML(b)
	return r
}

// gateFor is exposure's gate as the adapter calls it: yes for ok, and it records the actor.
type gateFor struct {
	mu     sync.Mutex
	ok     bool
	actors []string
}

func (g *gateFor) gate(_ context.Context, actor string, ip netip.Addr) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.actors = append(g.actors, actor)
	return g.ok && ip == ownPublicIP, nil
}

// D-514, end to end through the production builder (exposureServicesFor: the module switch, sensorActiveService, the Dispatcher)
// with a fake worker: the job is the external shape on the one address, exposure's gate is asked as the person who scanned, and the
// rows reach exposure with the address and the number of probed ports. Then the refusals the page shows: the worker's own-IP
// fence, a worker that does not know the shape (an older release), exposure's gate saying no (no job at all), nmap giving up.
func TestExposureServiceScanEndToEndWithAFakeWorker(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	var mu sync.Mutex
	answer := xmlResult(nmapFixture(t, "external.xml"))
	w := startFakeScanWorker(t, s, func(sensorlink.Job) *sensorlink.JobResult { mu.Lock(); defer mu.Unlock(); return answer })
	g := &gateFor{ok: true}
	sc := exposureServicesFor(*s.d, g.gate, nil) // the K-4 scope: ModeNow is never asked
	for deadline := time.Now().Add(20 * time.Second); strings.Contains(s.d.SensorDispatcher.NmapHealth(), "has not reported"); waitTick(t) {
		if time.Now().After(deadline) {
			t.Fatal("no heartbeat from the fake worker")
		}
	}
	target := exposure.ScanTarget{ID: "t1", Kind: exposure.KindIP, Value: ownPublicIP.String(), User: "ops@acme.example"}
	ctx := t.Context()

	got, err := sc.ScanServices(ctx, target, ownPublicIP)
	if err != nil {
		t.Fatal(err)
	}
	if got.Ports != 98 || len(got.Services) != 4 || got.Services[2] != (exposure.ServiceRow{IP: "8.8.8.8", Port: 8443, Name: "ssl/http", Product: "Apache httpd", Version: "2.4.49", CPE: "cpe:/a:apache:http_server:2.4.49", Extra: "(Unix)"}) { // tunnel="ssl" (D-522)
		t.Fatalf("got %+v", got)
	}
	jobs := w.received()
	if len(jobs) != 1 || jobs[0].Shape != "external" || jobs[0].Rate != 100 || len(jobs[0].Targets) != 1 || jobs[0].Targets[0] != "8.8.8.8" {
		t.Fatalf("jobs = %+v", jobs)
	}
	if len(g.actors) != 1 || g.actors[0] != "ops@acme.example" {
		t.Fatalf("the gate was asked as %v", g.actors)
	}

	refusal := func(name string, res *sensorlink.JobResult, want string) {
		t.Helper()
		mu.Lock()
		answer = res
		mu.Unlock()
		_, err := sc.ScanServices(ctx, target, ownPublicIP)
		var un *exposure.Unavailable
		if !errors.As(err, &un) || !strings.Contains(un.Reason, want) {
			t.Fatalf("%s: err = %v, want Unavailable %q", name, err, want)
		}
	}
	refusal("the worker's fence", &sensorlink.JobResult{Status: "refused", Reason: "not_own_ip", ExitCode: -1}, "no longer reaches the Internet through 8.8.8.8")
	refusal("the worker could not check", &sensorlink.JobResult{Status: "refused", Reason: "egress_unverified", ExitCode: -1}, "could not reach the public IP services to check that 8.8.8.8")
	refusal("an older worker", &sensorlink.JobResult{Status: "refused", Reason: "invalid_job", ExitCode: -1}, "may be older than the rest of Vedette")
	mu.Lock()
	answer = xmlResult(nmapFixture(t, "external_timedout.xml"))
	mu.Unlock()
	if _, err := sc.ScanServices(ctx, target, ownPublicIP); !errors.Is(err, exposure.ErrServicesTimedOut) { // D-522: its own line
		t.Fatalf("nmap gave up: err = %v", err)
	}

	before := len(w.received())
	g.mu.Lock()
	g.ok = false
	g.mu.Unlock()
	refusal("exposure's gate", answer, "no longer reaches the Internet through 8.8.8.8")
	if n := len(w.received()); n != before {
		t.Fatalf("a job went to the worker after exposure's gate said no (%d jobs, %d before)", n, before)
	}
	// output that is not believed is a failure (logged by exposure), never an empty list of services
	g.mu.Lock()
	g.ok = true
	g.mu.Unlock()
	mu.Lock()
	answer = xmlResult(nmapFixture(t, "external_unprobed.xml"))
	mu.Unlock()
	var un *exposure.Unavailable
	if _, err := sc.ScanServices(ctx, target, ownPublicIP); err == nil || errors.As(err, &un) {
		t.Fatalf("bad output: err = %v", err)
	}
}

// What the page reads when the step cannot run: the module off (nothing asked), the nmap slot busy, a stop by the module's switch;
// a stop by exposure's own bound stays the context's error, so exposure says "did not finish within 5 minutes".
func TestExposureServiceScanReasons(t *testing.T) {
	t.Parallel()
	ip := ownPublicIP
	scanErr := func(err error) func(context.Context, netip.Addr, nmapargv.Kind, sensoractive.OwnEgress) (sensoractive.External, error) {
		return func(context.Context, netip.Addr, nmapargv.Kind, sensoractive.OwnEgress) (sensoractive.External, error) {
			return sensoractive.External{}, err
		}
	}
	yes := func(context.Context, string, netip.Addr) (bool, error) { return true, nil }
	for name, c := range map[string]struct {
		sc   exposureServiceScan
		want string
	}{
		"module off": {exposureServiceScan{on: func() bool { return false }, scan: func(context.Context, netip.Addr, nmapargv.Kind, sensoractive.OwnEgress) (sensoractive.External, error) {
			panic("scanned while the module is off")
		}, gate: yes}, "Active discovery module is off"},
		"busy":             {exposureServiceScan{scan: scanErr(sensoractive.ErrBusy), gate: yes}, "busy with another scan"},
		"no time left":     {exposureServiceScan{scan: scanErr(sensoractive.ErrNoTime), gate: yes}, "too little of the 5 minutes"},
		"no check":         {exposureServiceScan{scan: scanErr(fmt.Errorf("%w: %w", sensoractive.ErrWorkerRefused, sensoractive.ErrEgressUnverified)), gate: yes}, "could not reach the public IP services"},
		"stopped":          {exposureServiceScan{scan: scanErr(sensoractive.ErrStopped), gate: yes}, "module was turned off"},
		"no worker":        {exposureServiceScan{scan: scanErr(sensoractive.ErrWorkerUnavailable), gate: yes}, "scan container is not available"},
		"no nmap":          {exposureServiceScan{scan: scanErr(sensoractive.ErrNmapMissing), gate: yes}, "scan container is not available"},
		"not the box's":    {exposureServiceScan{scan: scanErr(sensoractive.ErrNotOwnIP), gate: yes}, "no longer reaches the Internet through 8.8.8.8"},
		"refused, other":   {exposureServiceScan{scan: scanErr(sensoractive.ErrWorkerRefused), gate: yes}, "refused the job"},
		"terms withdrawn":  {exposureServiceScan{scan: scanErr(sensoractive.ErrNotDeep), gate: yes}, "testing terms of 8.8.8.8 are no longer accepted"},
		"old worker, deep": {exposureServiceScan{scan: scanErr(fmt.Errorf("sensoractive: %w", sensoractive.ErrFullUnsupported)), gate: yes}, "does not run the deep scan"},
	} {
		_, err := c.sc.ScanServices(t.Context(), exposure.ScanTarget{User: "a"}, ip)
		var un *exposure.Unavailable
		if !errors.As(err, &un) || !strings.Contains(un.Reason, c.want) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// D-522 (N5): nmap ran but its result says nothing about the services; exposure writes the line of each sentinel
	for in, want := range map[error]error{sensoractive.ErrHostTimedOut: exposure.ErrServicesTimedOut, sensoractive.ErrAnswersEverywhere: exposure.ErrAnswersEverywhere} {
		sc := exposureServiceScan{scan: scanErr(in), gate: yes}
		if _, err := sc.ScanServices(t.Context(), exposure.ScanTarget{User: "a"}, ip); !errors.Is(err, want) {
			t.Errorf("%v: err = %v, want %v", in, err, want)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	sc := exposureServiceScan{scan: scanErr(sensoractive.ErrStopped), gate: yes}
	var un *exposure.Unavailable
	if _, err := sc.ScanServices(ctx, exposure.ScanTarget{}, ip); !errors.Is(err, context.Canceled) || errors.As(err, &un) {
		t.Fatalf("a stopped run: err = %v", err)
	}
}

// D-526: the shape and the step's bound follow the target's mode: the K-4 scope keeps the External shape and 5 minutes exactly as
// before; accepted terms are the deep scan, the disruptive tick its disruptive shape, both bounded by FullServicesTimeout.
func TestExposureServiceShapeFollowsTheMode(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		mode  exposure.ScanMode
		kind  nmapargv.Kind
		bound time.Duration
	}{
		"terms not accepted":  {exposure.ScanMode{}, nmapargv.External, exposure.ServicesTimeout},
		"deep":                {exposure.ScanMode{Full: true}, nmapargv.ExternalFull, exposure.FullServicesTimeout},
		"deep and disruptive": {exposure.ScanMode{Full: true, Disruptive: true}, nmapargv.ExternalDisruptive, exposure.FullServicesTimeout},
	} {
		var kind nmapargv.Kind
		var given time.Duration
		sc := exposureServiceScan{scan: func(ctx context.Context, _ netip.Addr, k nmapargv.Kind, _ sensoractive.OwnEgress) (sensoractive.External, error) {
			d, _ := ctx.Deadline()
			kind, given = k, time.Until(d)
			return sensoractive.External{}, nil
		}}
		if _, err := sc.ScanServices(t.Context(), exposure.ScanTarget{Mode: c.mode}, ownPublicIP); err != nil || kind != c.kind || given > c.bound || given < c.bound-time.Minute {
			t.Errorf("%s: shape %s, bound %s, err %v", name, kind.Name(), given, err)
		}
	}
	// The bounds hold together (D-526): exposure's line says nmap's host timeout, and the step has room for the wait for the nmap
	// slot (2 minutes), core's fence (30 s), the worker's (25 s) and the pickup and the result (15 s) around it.
	if exposure.FullHostLimit != nmapargv.FullHostTimeout || exposure.FullServicesTimeout < nmapargv.FullHostTimeout+2*time.Minute+70*time.Second {
		t.Fatalf("exposure %s/%s against nmap's %s", exposure.FullServicesTimeout, exposure.FullHostLimit, nmapargv.FullHostTimeout)
	}
}

// modeAt is exposure's ModeNow as the adapter calls it: the mode the terms have now, with the actor and target it was asked for.
type modeAt struct {
	mu    sync.Mutex
	mode  exposure.ScanMode
	err   error
	asked []string
}

func (m *modeAt) now(_ context.Context, actor, id string) (exposure.ScanMode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.asked = append(m.asked, actor+"|"+id)
	return m.mode, m.err
}

// D-526, end to end through the production builder with a fake worker that says it runs the deep shapes: a deep scan asks
// ModeNow right before its job (as the person who scanned, for the target), sends external_full and hands the script results to
// exposure; the disruptive tick taken back meanwhile sends the full shape without the disruptive scripts; the terms withdrawn (or of
// an older version) send nothing and say so; a failing ModeNow sends nothing (fail closed); a worker of an older release that does
// not say it runs the deep shapes gets nothing and its line.
func TestExposureDeepScanEndToEndWithAFakeWorker(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	answer := xmlResult(nmapFixture(t, "external_full.xml"))
	w := startFakeScanWorkerFull(t, s, true, func(sensorlink.Job) *sensorlink.JobResult { return answer })
	m := &modeAt{mode: exposure.ScanMode{Full: true}}
	sc := exposureServicesFor(*s.d, (&gateFor{ok: true}).gate, m.now)
	for deadline := time.Now().Add(20 * time.Second); strings.Contains(s.d.SensorDispatcher.NmapHealth(), "has not reported"); waitTick(t) {
		if time.Now().After(deadline) {
			t.Fatal("no heartbeat from the fake worker")
		}
	}
	ctx := t.Context()
	target := exposure.ScanTarget{ID: "t1", Kind: exposure.KindIP, Value: ownPublicIP.String(), User: "ops@acme.example", Mode: exposure.ScanMode{Full: true}}
	got, err := sc.ScanServices(ctx, target, ownPublicIP)
	if err != nil {
		t.Fatal(err)
	}
	if got.Ports != 65535 || len(got.Services) != 3 || len(got.Scripts) != 5 || got.Scripts[4].ID != "smb-vuln-ms17-010" || got.Scripts[4].IP != "8.8.8.8" || len(got.Scripts[4].Findings) != 1 || got.Scripts[4].Findings[0].State != "vulnerable" || got.Scripts[4].Findings[0].CVEs[0] != "CVE-2017-0143" {
		t.Fatalf("got %+v", got)
	}
	if jobs := w.received(); len(jobs) != 1 || jobs[0].Shape != "external_full" || jobs[0].Rate != nmapargv.FullRate || jobs[0].Targets[0] != "8.8.8.8" {
		t.Fatalf("jobs = %+v", jobs)
	}
	if len(m.asked) != 1 || m.asked[0] != "ops@acme.example|t1" {
		t.Fatalf("ModeNow asked %v", m.asked)
	}

	target.Mode.Disruptive = true // asked with the tick, which was taken back before the job left
	if _, err := sc.ScanServices(ctx, target, ownPublicIP); err != nil {
		t.Fatal(err)
	}
	if jobs := w.received(); len(jobs) != 2 || jobs[1].Shape != "external_full" {
		t.Fatalf("jobs = %+v", jobs)
	}

	before := len(w.received())
	m.mu.Lock()
	m.mode = exposure.ScanMode{} // withdrawn
	m.mu.Unlock()
	_, err = sc.ScanServices(ctx, target, ownPublicIP)
	var un *exposure.Unavailable
	if !errors.As(err, &un) || !strings.Contains(un.Reason, "testing terms of 8.8.8.8 are no longer accepted") {
		t.Fatalf("withdrawn: err = %v", err)
	}
	m.mu.Lock()
	m.mode, m.err = exposure.ScanMode{Full: true}, errors.New("database is locked")
	m.mu.Unlock()
	if _, err := sc.ScanServices(ctx, target, ownPublicIP); err == nil || errors.As(err, &un) {
		t.Fatalf("ModeNow failed: err = %v", err)
	}
	if n := len(w.received()); n != before {
		t.Fatalf("a job went to the worker after the terms said no (%d jobs, %d before)", n, before)
	}
}

// D-526: a worker of an older release (its heartbeat does not say full) is never sent a deep scan; the page says to update.
func TestExposureDeepScanOldWorker(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	w := startFakeScanWorker(t, s, func(sensorlink.Job) *sensorlink.JobResult { return xmlResult(nmapFixture(t, "external_full.xml")) })
	sc := exposureServicesFor(*s.d, (&gateFor{ok: true}).gate, (&modeAt{mode: exposure.ScanMode{Full: true}}).now)
	for deadline := time.Now().Add(20 * time.Second); strings.Contains(s.d.SensorDispatcher.NmapHealth(), "has not reported"); waitTick(t) {
		if time.Now().After(deadline) {
			t.Fatal("no heartbeat from the fake worker")
		}
	}
	target := exposure.ScanTarget{ID: "t1", Kind: exposure.KindIP, Value: ownPublicIP.String(), User: "ops@acme.example", Mode: exposure.ScanMode{Full: true}}
	_, err := sc.ScanServices(t.Context(), target, ownPublicIP)
	var un *exposure.Unavailable
	if !errors.As(err, &un) || un.Reason != servicesOldFull {
		t.Fatalf("err = %v", err)
	}
	if n := len(w.received()); n != 0 {
		t.Fatalf("%d jobs went to the old worker", n)
	}
}
