package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/pki"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/inventory"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// These tests run the sensor link of production (openSensorLink, sensorBackend, coreJobs) over loopback with the real PKI and the
// real services of the stack. No container, no nmap, no network beyond 127.0.0.1.

// testLink opens the sensor link on a free loopback port over the stack's services and serves it until the test ends.
func (s *stack) testLink(t *testing.T) (l *sensorLink, creds string) {
	t.Helper()
	creds = filepath.Join(t.TempDir(), "creds")
	l, err := openSensorLink(t.Context(), s.d, "127.0.0.1:0", creds)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = l.serve() }()
	t.Cleanup(func() {
		_ = l.close()
		<-done
	})
	return l, creds
}

func (s *stack) sensorClient(t *testing.T, l *sensorLink, creds string, role sensorlink.Role) *sensorlink.Client {
	t.Helper()
	c, err := sensorlink.NewClient(sensorlink.ClientOptions{BaseURL: "https://" + l.Addr(), CredsPath: filepath.Join(creds, string(role), pki.BundleName)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

// The PKI starts, and the bundles are written, before the port is opened: when the credentials cannot be written, nothing listens.
// The address is held by this test, so a Listen that ran first would fail with "address in use" and the error would say listen.
func TestSensorLinkStartsThePKIBeforeListening(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	held, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	file := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = openSensorLink(t.Context(), s.d, held.Addr().String(), filepath.Join(file, "creds")) // a directory cannot be made under a file
	if err == nil || !strings.Contains(err.Error(), "credentials") || strings.Contains(err.Error(), "listen") {
		t.Fatalf("err = %v, want the credentials failure and no listen", err)
	}

	s = newStack(t)           // pki.Open is once per secrets.Store: the first stack's is spent
	_, creds := s.testLink(t) // and the other way: when it listens, both bundles exist already
	for _, r := range sensorlink.Roles {
		if _, err := os.Stat(filepath.Join(creds, string(r), pki.BundleName)); err != nil {
			t.Fatalf("role %s: %v", r, err)
		}
	}
	if s.d.Authority == nil || s.d.SensorCreds != creds {
		t.Fatalf("deps lost the authority or the directory: %v %q", s.d.Authority, s.d.SensorCreds)
	}
}

// The listener refuses a peer with no client certificate, and a role's module off answers module_off on its routes only.
func TestSensorLinkRefusesAnonymousAndHonoursTheModuleSwitch(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	l, creds := s.testLink(t)

	anon := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}}} //nolint:gosec // the test checks the server's refusal, not its certificate
	defer anon.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+l.Addr()+sensorlink.PathPrefix+"/config", nil)
	if resp, err := anon.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("a peer with no client certificate got %d", resp.StatusCode)
	}

	active := s.sensorClient(t, l, creds, sensorlink.Active)
	passive := s.sensorClient(t, l, creds, sensorlink.Passive)
	hb := &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true, Version: "7.94"}}
	if _, err := active.ActiveHeartbeat(t.Context(), hb); err != nil {
		t.Fatal(err)
	}
	s.setModule("sensor-active", false)
	var e *sensorlink.Error
	if _, err := active.ActiveHeartbeat(t.Context(), hb); !errors.As(err, &e) || e.Code != sensorlink.CodeModuleOff {
		t.Fatalf("sensor-active off: %v, want module_off", err)
	}
	if _, err := passive.PassiveHeartbeat(t.Context(), &sensorlink.PassiveHeartbeat{Version: "1.0.0"}); err != nil {
		t.Fatalf("sensor-passive is on and must not be touched by the other module's switch: %v", err)
	}
	s.setModule("sensor-passive", false)
	if _, err := passive.PassiveHeartbeat(t.Context(), &sensorlink.PassiveHeartbeat{Version: "1.0.0"}); !errors.As(err, &e) || e.Code != sensorlink.CodeModuleOff {
		t.Fatalf("sensor-passive off: %v, want module_off", err)
	}
}

// A sensor enrols from its creds directory, heartbeats, and both halves of the one Backend answer: the passive sensor's observations
// reach the inventory, the active worker is handed the dispatcher's job and its result comes back to the probe.
func TestSensorLinkEndToEndThroughTheComposedBackend(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	l, creds := s.testLink(t)
	passive := s.sensorClient(t, l, creds, sensorlink.Passive)
	active := s.sensorClient(t, l, creds, sensorlink.Active)
	ctx := t.Context()

	// passive: config, heartbeat, observations
	if _, err := passive.Config(ctx, "", time.Second); err != nil {
		t.Fatal(err)
	}
	if inst, err := passive.PassiveHeartbeat(ctx, &sensorlink.PassiveHeartbeat{Version: "1.2.3", DevicesSeen: 1}); err != nil || inst == "" {
		t.Fatalf("passive heartbeat: %q %v", inst, err)
	}
	rep, err := passive.PostObservations(ctx, &sensorlink.ObservationsRequest{Epoch: strings.Repeat("a", 32), Seq: 1, Items: []sensorlink.ObservationItem{
		{MAC: "02:00:00:00:00:42", IP: "192.168.10.42", Field: "hostname", Value: "printer-42", Confidence: 0.6, SeenAt: time.Now().UTC()},
	}})
	if err != nil || rep.AckSeq != 1 || len(rep.Rejected) != 0 {
		t.Fatalf("observations: %+v %v", rep, err)
	}
	list, err := s.d.Inventory.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(list.Items, func(d inventory.Device) bool { return d.MAC != nil && *d.MAC == "02:00:00:00:00:42" }) {
		t.Fatalf("the device the passive sensor saw is not in the inventory: %+v", list.Items)
	}

	// active: the worker's heartbeat, a job handed over, its result back
	if _, err := active.ActiveHeartbeat(ctx, &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true, Version: "7.94"}}); err != nil {
		t.Fatal(err)
	}
	if msg := s.d.SensorDispatcher.NmapHealth(); msg != "" {
		t.Fatalf("NmapHealth after a heartbeat = %q", msg)
	}
	argv, err := nmapargv.Build(nmapargv.Sweep, 100, []netip.Addr{netip.MustParseAddr("192.168.10.0")})
	if err != nil {
		t.Fatal(err)
	}
	type probed struct {
		out sensoractive.Output
		err error
	}
	got := make(chan probed, 1)
	go func() { o, err := s.d.SensorDispatcher.Probe(ctx, argv); got <- probed{o, err} }()
	var job sensorlink.Job
	deadline := time.Now().Add(20 * time.Second)
	for job.ID == "" && time.Now().Before(deadline) {
		jr, err := active.Jobs(ctx, nil, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if len(jr.Jobs) > 0 {
			job = jr.Jobs[0]
		}
	}
	if job.ID == "" || job.Shape != "sweep" || !slices.Contains(job.Targets, "192.168.10.0") {
		t.Fatalf("the worker was handed %+v", job)
	}
	res := &sensorlink.JobResult{Status: "done"}
	res.SetXML([]byte("<nmaprun/>"))
	if err := active.PostResult(ctx, job.ID, res); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-got:
		if p.err != nil || !bytes.Equal(p.out.XML, []byte("<nmaprun/>")) {
			t.Fatalf("probe = %q %v", p.out.XML, p.err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the probe never got the worker's result")
	}
}

// The Server finds ResultRejector and the service finds NmapHealth by type assertion; a wrapper that hid either would make a refused
// result wait out its lease and make Health say "ok" about a worker that never reported (SP-3 review).
func TestTypeAssertedOptionalMethodsSurviveTheComposition(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	var be sensorlink.Backend = sensorBackend{s.d.SensorPassive, s.d.SensorDispatcher}
	if _, ok := be.(sensorlink.ResultRejector); !ok {
		t.Fatal("the composed Backend hides JobResultRejected: a refused result would not fail the job at once")
	}
	var pr sensoractive.Prober = s.d.SensorDispatcher
	if _, ok := pr.(interface{ NmapHealth() string }); !ok {
		t.Fatal("the Prober of the service hides NmapHealth")
	}
	svc, err := sensorActiveService(*s.d)
	if err != nil {
		t.Fatal(err)
	}
	if h := svc.Health(t.Context()); h.Status != "unavailable" || !strings.Contains(h.Message, "has not reported") {
		t.Fatalf("Health before any heartbeat of the worker = %+v, want unavailable (it never reported)", h)
	}
}

// Production runs no capture job and no nmap in core: not in the job list of any wired module, and the binary's non-test sources
// never build the local Prober.
func TestProductionRunsNoCaptureAndNoLocalNmap(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	for _, w := range wiredModules() {
		if w.Jobs == nil {
			continue
		}
		for _, j := range w.Jobs(*s.d) {
			if strings.Contains(j.Name, "capture") || strings.Contains(j.Name, "nmap") {
				t.Errorf("module %s still registers the job %q", w.ID, j.Name)
			}
		}
	}
	for _, w := range wiredModules() {
		if w.ID == "sensor-passive" && w.Jobs != nil {
			t.Error("sensor-passive has a Jobs func: its capture runs in the sensor container only")
		}
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && (id.Name == "NewLocalProber" || id.Name == "NmapPath") {
				t.Errorf("%s: %s is used in production wiring (D-141: nmap runs in the scan container)", fset.Position(id.Pos()), id.Name)
			}
			return true
		})
	}
	if _, err := newSensorActive(*s.d, nil); err == nil {
		t.Error("newSensorActive accepted a nil Prober: the module would start nmap in this process")
	}
}

// The daily job calls Authority.Renew: with a leaf past two thirds of its life, running the job writes a new bundle.
func TestRenewJobIsScheduledAndRenews(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	s := newStackWith(t, func(d *deps) { d.Clock = clock })
	if jobs := coreJobs(*s.d); len(jobs) != 0 {
		t.Fatalf("no sensor link, yet core registers %d jobs", len(jobs))
	}
	_, creds := s.testLink(t)
	var job func(context.Context) error
	for _, w := range wiredModules() {
		if w.ID != "core" || w.Jobs == nil {
			continue
		}
		for _, j := range w.Jobs(*s.d) {
			if j.Name == "sensor-cert-renew" {
				if j.Module != "core" || j.Every != 24*time.Hour {
					t.Fatalf("job %+v", j)
				}
				job = j.Run
			}
		}
	}
	if job == nil {
		t.Fatal("the core entry of wiredModules does not schedule sensor-cert-renew")
	}
	path := filepath.Join(creds, "passive", pki.BundleName)
	before, err := os.ReadFile(path) //nolint:gosec // a path in the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	if err := job(t.Context()); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(before, again) { //nolint:gosec // same
		t.Fatal("the job replaced a bundle that was not due")
	}
	mu.Lock()
	now = now.Add(5 * 24 * time.Hour) // past two thirds of the 7 days
	mu.Unlock()
	if err := job(t.Context()); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(path); bytes.Equal(before, after) { //nolint:gosec // same
		t.Fatal("the job did not renew a bundle that was due")
	}
}

// One provider of the box's addresses (vedette-host state/net, through d.HostNet) feeds the sweep's protected list, the honeypot's
// box address, core/conn's refusals and notify's webhook guard; a host that stops answering leaves the last set in place.
func TestBoxAddressProviderFeedsEveryConsumer(t *testing.T) {
	t.Parallel()
	host := &fakeNet{st: api.NetState{Interfaces: []api.NetInterface{{Name: "eno1", Addresses: []string{"192.168.77.5/24"}}}}}
	s := newStackWith(t, func(d *deps) { d.HostNet = newHostNetCache(hostNetSource(host, nil), time.Now) })
	box := netip.MustParseAddr("192.168.77.5")
	check := func(when string) {
		t.Helper()
		prot, err := (sensorInventory{inv: s.d.Inventory, hostNet: s.d.HostNet}).ProtectedIPs(t.Context())
		if err != nil || !slices.Contains(prot, box) {
			t.Errorf("%s: ProtectedIPs lacks the box address (%v)", when, err)
		}
		if !slices.Contains(notifyBoxAddrs(s.d.HostNet)(), box) {
			t.Errorf("%s: notify BoxAddrs lacks the box address", when)
		}
		bs := (&boxSources{hostCache: s.d.HostNet, now: time.Now}).BoxAddrs(t.Context())
		if !slices.Contains(bs, netip.PrefixFrom(box, 32)) {
			t.Errorf("%s: core/conn's box addresses lack it: %v", when, bs)
		}
		if got := hostIPv4s(t.Context(), s.d.HostNet); !slices.Contains(got, box) {
			t.Errorf("%s: the honeypot's source (hostIPv4s) lacks it", when)
		}
	}
	check("host answering")
	host.err = errors.New("host socket gone")
	s.d.HostNet.Invalidate() // the next read asks again, fails, and serves the previous set
	check("host unreachable")
	if host.calls < 2 {
		t.Fatalf("the host was asked %d times: the failure was not exercised", host.calls)
	}
}

// The two flags go together, and the credentials directory is an absolute path (the unit mounts it at a fixed place).
func TestSensorLinkFlagsGoTogether(t *testing.T) {
	t.Parallel()
	for name, args := range map[string][]string{
		"listen without creds":    {"-sensor-listen", "127.0.0.1:0"},
		"creds without listen":    {"-sensor-creds", "/var/lib/vedette-creds"},
		"relative creds":          {"-sensor-listen", "127.0.0.1:0", "-sensor-creds", "creds"},
		"listen is not host:port": {"-sensor-listen", "8444", "-sensor-creds", "/var/lib/vedette-creds"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := run(t.Context(), args, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "sensor") {
				t.Fatalf("run(%q) = %v, want a refusal about the sensor flags", args, err)
			}
		})
	}
}
