package main

import (
	"context"
	"errors"
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
	f := &fakeScanWorker{}
	c := linktest.New(t, sensorBackend{s.d.SensorPassive, s.d.SensorDispatcher}).Client(t, sensorlink.Active)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			if _, err := c.ActiveHeartbeat(ctx, &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true, Version: "7.94"}}); err != nil {
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
	sc := exposureServicesFor(*s.d, g.gate)
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
	if got.Ports != 98 || len(got.Services) != 4 || got.Services[2] != (exposure.ServiceRow{IP: "8.8.8.8", Port: 8443, Name: "http", Product: "Apache httpd", Version: "2.4.49", CPE: "cpe:/a:apache:http_server:2.4.49", Extra: "(Unix)"}) {
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
	refusal("an older worker", &sensorlink.JobResult{Status: "refused", Reason: "invalid_job", ExitCode: -1}, "may be older than the rest of Vedette")
	refusal("nmap gave up", xmlResult(nmapFixture(t, "external_timedout.xml")), "gave up on the address after 3 minutes")

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
	scanErr := func(err error) func(context.Context, netip.Addr, sensoractive.OwnEgress) (sensoractive.External, error) {
		return func(context.Context, netip.Addr, sensoractive.OwnEgress) (sensoractive.External, error) {
			return sensoractive.External{}, err
		}
	}
	yes := func(context.Context, string, netip.Addr) (bool, error) { return true, nil }
	for name, c := range map[string]struct {
		sc   exposureServiceScan
		want string
	}{
		"module off": {exposureServiceScan{on: func() bool { return false }, scan: func(context.Context, netip.Addr, sensoractive.OwnEgress) (sensoractive.External, error) {
			panic("scanned while the module is off")
		}, gate: yes}, "Active discovery module is off"},
		"busy":            {exposureServiceScan{scan: scanErr(sensoractive.ErrBusy), gate: yes}, "busy with another scan"},
		"stopped":         {exposureServiceScan{scan: scanErr(sensoractive.ErrStopped), gate: yes}, "module was turned off"},
		"no worker":       {exposureServiceScan{scan: scanErr(sensoractive.ErrWorkerUnavailable), gate: yes}, "scan container is not available"},
		"no nmap":         {exposureServiceScan{scan: scanErr(sensoractive.ErrNmapMissing), gate: yes}, "scan container is not available"},
		"not the box's":   {exposureServiceScan{scan: scanErr(sensoractive.ErrNotOwnIP), gate: yes}, "no longer reaches the Internet through 8.8.8.8"},
		"refused, other":  {exposureServiceScan{scan: scanErr(sensoractive.ErrWorkerRefused), gate: yes}, "refused the job"},
		"nmap gave up on": {exposureServiceScan{scan: scanErr(sensoractive.ErrHostTimedOut), gate: yes}, "gave up"},
	} {
		_, err := c.sc.ScanServices(t.Context(), exposure.ScanTarget{User: "a"}, ip)
		var un *exposure.Unavailable
		if !errors.As(err, &un) || !strings.Contains(un.Reason, c.want) {
			t.Errorf("%s: err = %v", name, err)
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
