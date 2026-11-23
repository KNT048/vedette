package sensoractive_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
	sa "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

var boxIP = netip.MustParseAddr("8.8.8.8") // stands for the box's own verified public IP (testdata/external.xml)

// discoveryFixture is testdata/external_top_ports.xml (the external shape's discovery: 1000 ports probed, 22, 443 and 666 open)
// about ip, written to a temporary file for the fake nmap.
func discoveryFixture(t *testing.T, ip netip.Addr) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "external_top_ports.xml"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "discovery.xml")
	if err := os.WriteFile(p, bytes.ReplaceAll(b, []byte("198.51.100.7"), []byte(ip.String())), 0o600); err != nil { //nolint:gosec // a file of the test's own temp directory
		t.Fatal(err)
	}
	return p
}

// ownFence is the core side of the own-IP fence (exposure's gate in production): yes for the addresses in ok.
type ownFence struct {
	mu    sync.Mutex
	ok    []netip.Addr
	asked int
}

func (f *ownFence) OwnEgress(_ context.Context, ip netip.Addr) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked++
	return slices.Contains(f.ok, ip), nil
}

// workerEgress is the worker's public-IP check: every round names addr.
type workerEgress struct{ addr netip.Addr }

func (w workerEgress) Round(context.Context) (netip.Addr, error) { return w.addr, nil }

// externalEnv is an env whose Service hands nmap jobs to a real worker over the real mutual-TLS link, with the fake nmap
// printing testdata/external.xml and the worker's own-IP fence seeing egress.
func externalEnv(t *testing.T, egress netip.Addr) *env {
	t.Helper()
	return externalEnvWith(t, egress, "external.xml")
}

// externalEnvWith is externalEnv with the fake nmap printing testdata/name.
func externalEnvWith(t *testing.T, egress netip.Addr, name string) *env {
	t.Helper()
	fx, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return externalEnvWithNmap(t, egress, fakeOpts{always: fx, topPorts: discoveryFixture(t, boxIP)})
}

// externalEnvWithNmap is externalEnv with the fake nmap of o.
func externalEnvWithNmap(t *testing.T, egress netip.Addr, o fakeOpts) *env {
	t.Helper()
	e := newEnv(t, o)
	d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 20 * time.Millisecond})
	link := linktest.New(t, activeBackend{d})
	w, err := worker.New(worker.Config{Link: link.Client(t, sensorlink.Active), NmapPath: e.nm.path, Version: "1.0.0", Wait: time.Second, Egress: workerEgress{egress}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = w.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "the first heartbeat of the worker", func() bool { return !strings.Contains(d.NmapHealth(), "has not reported") })
	svc, err := e.newService(sa.Config{DB: e.db, Inventory: e.inv, Observe: e.sink, Software: e.sink, Services: e.sink, Events: e.ev, Prober: d, Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

// The default scan of the box's own public IP through the scan container, two nmap jobs under one job row: the discovery (SYN
// only, --top-ports 1000) and the -sV run over the fixed list plus the open port the discovery found outside it (666), each with its
// probe row and core's fence asked right before it; the services read from the -sV run, the probed ports from both (the
// discovery's scaninfo and the -sV run's list), and nothing written to the inventory. The LAN settings do not bind it: scanning
// switched off and an empty scope change nothing.
func TestScanExternalThroughTheWorker(t *testing.T) {
	t.Parallel()
	e := externalEnv(t, boxIP)
	e.inv.set(func(s *sa.Settings) { s.Enabled, s.LANRanges = false, nil })
	own := &ownFence{ok: []netip.Addr{boxIP}}
	got, err := e.svc.ScanExternal(e.ctx(), boxIP, nmapargv.External, own)
	if err != nil {
		t.Fatal(err)
	}
	wantPorts, err := nmapargv.ExternalVersionPorts([]int{22, 443, 666})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Services) != 4 || got.Services[2].Product != "Apache httpd" || got.Services[2].Version != "2.4.49" || got.Services[2].CPE != "cpe:/a:apache:http_server:2.4.49" {
		t.Fatalf("got %+v", got)
	}
	if got.Ports != len(got.Probed) || got.Ports < 1000 || !slices.Contains(got.Probed, 666) || !slices.Contains(got.Probed, 37777) || !slices.Contains(got.Probed, 1) {
		t.Fatalf("probed %d ports: %v", got.Ports, got.Probed)
	}
	if own.asked != 2 {
		t.Fatalf("the fence was asked %d times", own.asked)
	}
	list := make([]string, len(wantPorts))
	for i, p := range wantPorts {
		list[i] = strconv.Itoa(p)
	}
	calls := e.nm.calls(t)
	if len(calls) != 2 ||
		!slices.Equal(calls[0], []string{"--privileged", "-sS", "-Pn", "-n", "--max-rate", "100", "--max-retries", "2", "--host-timeout", "2m", "--top-ports", "1000", "--stats-every", "5s", "-oX", "-", "8.8.8.8"}) ||
		!slices.Equal(calls[1], []string{"--privileged", "-sS", "-sV", "-Pn", "-n", "--max-rate", "100", "--max-retries", "2", "--host-timeout", "3m", "-p", strings.Join(list, ","), "--stats-every", "5s", "-oX", "-", "8.8.8.8"}) {
		t.Fatalf("nmap argv = %q", calls)
	}
	if s := e.str(`SELECT group_concat(shape || '|' || rate || '|' || hosts || '|' || targets || '|' || result, ';') FROM (SELECT * FROM sa_probe ORDER BY id)`); s != "external|100|1|8.8.8.8|ok: 3 of 1000 ports open;external|100|1|8.8.8.8|ok: 4 open ports" {
		t.Fatalf("probe rows = %s", s)
	}
	if f := e.str(`SELECT flags FROM sa_probe ORDER BY id DESC LIMIT 1`); !strings.HasSuffix(f, "-p "+strings.Join(list, ",")+" --stats-every "+nmapargv.StatsEvery) {
		t.Fatalf("flags = %s", f)
	}
	if s := e.str(`SELECT kind || '|' || reason || '|' || status FROM jobs_v`); s != "external|exposure|done" {
		t.Fatalf("job = %s", s)
	}
	if len(e.sink.observations()) != 0 || len(e.sink.svc) != 0 {
		t.Fatal("an external scan wrote to the inventory")
	}
}

// discoveryVariant is the discovery fixture about the box's address with edit applied, written to a temporary file.
func discoveryVariant(t *testing.T, edit func([]byte) []byte) string {
	t.Helper()
	b, err := os.ReadFile(discoveryFixture(t, boxIP))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "variant.xml")
	if err := os.WriteFile(p, edit(b), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The fixed list always gets its -sV run, whatever the discovery said. A discovery that hit its host timeout, or whose output is not
// believed (a <scaninfo> that is not the top 1000), is followed by the -sV run over the fixed list alone: Probed is that list and
// DiscoveryCut says why. A discovery that saw the address answer on almost every port (a router or SYN proxy) is followed by the -sV
// run over the fixed list alone, and only the ports where -sV named a real service are kept (10443's tcpwrapped is dropped).
// The -sV options are those of the shape before the discovery existed.
func TestScanExternalAlwaysReadsTheFixedList(t *testing.T) {
	t.Parallel()
	var many strings.Builder
	for p := range 60 {
		fmt.Fprintf(&many, `<port protocol="tcp" portid="%d"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="tcpwrapped" method="table" conf="3"/></port>`, 100+p)
	}
	fixed := make([]string, len(nmapargv.ExtraPortNumbers))
	for i, p := range nmapargv.ExtraPortNumbers {
		fixed[i] = strconv.Itoa(p)
	}
	wantArgv := []string{"--privileged", "-sS", "-sV", "-Pn", "-n", "--max-rate", "100", "--max-retries", "2", "--host-timeout", "3m", "-p", strings.Join(fixed, ","), "--stats-every", "5s", "-oX", "-", "8.8.8.8"}
	fx, err := filepath.Abs(filepath.Join("testdata", "external.xml"))
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		edit       func([]byte) []byte
		cut, every bool
		services   int
		discovery  string
	}{
		"discovery timed out": {func(b []byte) []byte {
			return bytes.Replace(b, []byte("<host starttime"), []byte(`<host timedout="true" starttime`), 1)
		}, true, false, 4,
			"failed: nmap gave up on the address at its host timeout"},
		"discovery not believed": {func(b []byte) []byte {
			return bytes.Replace(b, []byte(`services="1-1000"`), []byte(`services="1-999"`), 1)
		}, true, false, 4,
			"failed: nmap probed 999 ports, not its top 1000; output discarded"},
		"answers everywhere": {func(b []byte) []byte {
			return bytes.Replace(b, []byte("</ports>"), []byte(many.String()+"</ports>"), 1)
		}, false, true, 3,
			"ok: more than 40 ports open, the address answers on almost every port; -sV reads the fixed list next"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := externalEnvWithNmap(t, boxIP, fakeOpts{always: fx, topPorts: discoveryVariant(t, c.edit)})
			got, err := e.svc.ScanExternal(e.ctx(), boxIP, nmapargv.External, &ownFence{ok: []netip.Addr{boxIP}})
			if err != nil {
				t.Fatal(err)
			}
			if got.DiscoveryCut != c.cut || got.AnswersEverywhere != c.every || !slices.Equal(got.Probed, nmapargv.ExtraPortNumbers) ||
				got.Ports != len(nmapargv.ExtraPortNumbers) || len(got.Services) != c.services {
				t.Fatalf("got cut=%v everywhere=%v %d ports, services %+v", got.DiscoveryCut, got.AnswersEverywhere, got.Ports, got.Services)
			}
			for _, x := range got.Services {
				if x.Name == "tcpwrapped" && c.every {
					t.Fatalf("kept a tcpwrapped port: %+v", x)
				}
			}
			if calls := e.nm.calls(t); len(calls) != 2 || !slices.Equal(calls[1], wantArgv) {
				t.Fatalf("nmap argv = %q", calls)
			}
			if r := e.str(`SELECT result FROM sa_probe ORDER BY id LIMIT 1`); r != c.discovery {
				t.Fatalf("discovery row = %s", r)
			}
		})
	}
}

// deepFence is ownFence with the DeepGate of a full run: the shape the target's terms allow now, as exposure's ModeNow
// says it in production; err fails the check.
type deepFence struct {
	ownFence
	now   nmapargv.Kind
	err   error
	asked []nmapargv.Kind
}

func (f *deepFence) ShapeNow(_ context.Context, asked nmapargv.Kind) (nmapargv.Kind, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, asked)
	return f.now, f.err
}

// The deep scan of an accepted target through the real worker: both fences asked right before the job, the probe row with
// the full shape and its flags (migration 0006), every TCP port and the scripts read. The disruptive tick taken back meanwhile runs
// the full shape without the disruptive scripts; a gate that allows more than asked never widens the run.
func TestScanExternalFullThroughTheWorker(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		asked, now, want nmapargv.Kind
	}{
		"full":                  {nmapargv.ExternalFull, nmapargv.ExternalFull, nmapargv.ExternalFull},
		"disruptive":            {nmapargv.ExternalDisruptive, nmapargv.ExternalDisruptive, nmapargv.ExternalDisruptive},
		"the tick taken back":   {nmapargv.ExternalDisruptive, nmapargv.ExternalFull, nmapargv.ExternalFull},
		"never more than asked": {nmapargv.ExternalFull, nmapargv.ExternalDisruptive, nmapargv.ExternalFull},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := externalEnvWith(t, boxIP, "external_full.xml")
			own := &deepFence{ownFence: ownFence{ok: []netip.Addr{boxIP}}, now: c.now}
			got, err := e.svc.ScanExternal(e.ctx(), boxIP, c.asked, own)
			if err != nil {
				t.Fatal(err)
			}
			if got.Ports != 65535 || len(got.Services) != 3 || len(got.Scripts) != 5 || own.asked[0] != c.asked || len(own.asked) != 1 || own.ownFence.asked != 1 {
				t.Fatalf("got %d ports %d services %d scripts, gate asked %v", got.Ports, len(got.Services), len(got.Scripts), own.asked)
			}
			want, _ := nmapargv.Build(c.want, nmapargv.FullRate, []netip.Addr{boxIP})
			if calls := e.nm.calls(t); len(calls) != 1 || !slices.Equal(calls[0], want) {
				t.Fatalf("nmap argv = %q, want %q", calls, want)
			}
			if s := e.str(`SELECT shape || '|' || rate || '|' || result FROM sa_probe`); s != c.want.Name()+"|300|ok: 3 open ports, 5 script results" {
				t.Fatalf("probe row = %s", s)
			}
			if f := e.str(`SELECT flags FROM sa_probe`); !strings.Contains(f, " -p- --script ") {
				t.Fatalf("flags = %s", f)
			}
		})
	}
}

// The terms withdrawn or of an older version right before the job (the gate says External), a gate that fails, or a fence
// without a DeepGate: nothing is sent, no probe row, and the run never falls back to the External shape by itself.
func TestScanExternalFullRefusedByTheDeepGate(t *testing.T) {
	t.Parallel()
	e := externalEnvWith(t, boxIP, "external_full.xml")
	for name, c := range map[string]struct {
		own  sa.OwnEgress
		want error
	}{
		"terms withdrawn": {&deepFence{ownFence: ownFence{ok: []netip.Addr{boxIP}}, now: nmapargv.External}, sa.ErrNotDeep},
		"no DeepGate":     {&ownFence{ok: []netip.Addr{boxIP}}, sa.ErrNotDeep},
		"the gate fails":  {&deepFence{ownFence: ownFence{ok: []netip.Addr{boxIP}}, now: nmapargv.ExternalFull, err: errors.New("database is locked")}, nil},
	} {
		_, err := e.svc.ScanExternal(e.ctx(), boxIP, nmapargv.ExternalFull, c.own)
		if err == nil || c.want != nil && !errors.Is(err, c.want) || c.want == nil && errors.Is(err, sa.ErrNotDeep) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if n := len(e.nm.calls(t)); n != 0 || e.count(`SELECT count(*) FROM sa_probe`) != 0 {
		t.Fatalf("nmap ran %d times, %d probe rows", n, e.count(`SELECT count(*) FROM sa_probe`))
	}
}

// A worker whose heartbeat does not say it runs the full shapes (older than protocol 5's field) never gets one: Probe refuses
// before anything is queued (pollLocked holds a pending one back the same way for a worker that stopped saying it since).
func TestFullShapeNeedsAWorkerThatSaysSo(t *testing.T) {
	t.Parallel()
	d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 20 * time.Millisecond})
	if _, err := d.ActiveHeartbeat(t.Context(), &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true, Version: "7.94SVN"}}); err != nil {
		t.Fatal(err)
	}
	argv, err := nmapargv.Build(nmapargv.ExternalFull, nmapargv.FullRate, []netip.Addr{boxIP})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Probe(t.Context(), argv); !errors.Is(err, sa.ErrFullUnsupported) {
		t.Fatalf("err = %v", err)
	}
	rep, err := d.Jobs(t.Context(), 0, nil)
	if err != nil || len(rep.Jobs) != 0 {
		t.Fatalf("jobs = %+v %v", rep.Jobs, err)
	}
}

// INV-13 of exposure, the core half of the fence: an address that is not the box's own now gets no job, no probe row, no packet.
func TestScanExternalRefusedByTheCoreFence(t *testing.T) {
	t.Parallel()
	e := externalEnv(t, boxIP)
	for name, own := range map[string]sa.OwnEgress{"not the box's": &ownFence{}, "no fence": nil} {
		if _, err := e.svc.ScanExternal(e.ctx(), boxIP, nmapargv.External, own); !errors.Is(err, sa.ErrNotOwnIP) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if n := len(e.nm.calls(t)); n != 0 || e.count(`SELECT count(*) FROM sa_probe`) != 0 {
		t.Fatalf("nmap ran %d times, %d probe rows", n, e.count(`SELECT count(*) FROM sa_probe`))
	}
	if s := e.str(`SELECT group_concat(status) FROM jobs_v`); s != "failed" {
		t.Fatalf("jobs = %s", s)
	}
}

// The worker half of the fence (a core that was taken over gains nothing): core said yes, the worker sees the box leave through
// another address, refuses not_own_ip and nmap never starts. The probe row was written before the job and says so.
func TestScanExternalRefusedByTheWorkerFence(t *testing.T) {
	t.Parallel()
	e := externalEnv(t, netip.MustParseAddr("1.1.1.1"))
	_, err := e.svc.ScanExternal(e.ctx(), boxIP, nmapargv.External, &ownFence{ok: []netip.Addr{boxIP}})
	if !errors.Is(err, sa.ErrNotOwnIP) {
		t.Fatalf("err = %v", err)
	}
	if n := len(e.nm.calls(t)); n != 0 {
		t.Fatalf("nmap ran %d times", n)
	}
	if r := e.str(`SELECT result FROM sa_probe`); !strings.HasPrefix(r, "refused: the scan worker found the address is not the box's own public IP") {
		t.Fatalf("probe result = %s", r)
	}
}

// Only a public address goes in the external shape: a LAN address, CGNAT or loopback is refused before anything else.
func TestScanExternalRefusesANonPublicAddress(t *testing.T) {
	t.Parallel()
	e := externalEnv(t, boxIP)
	for _, s := range []string{"192.168.10.20", "100.64.0.1", "127.0.0.1", "203.0.113.5"} {
		ip := netip.MustParseAddr(s)
		if _, err := e.svc.ScanExternal(e.ctx(), ip, nmapargv.External, &ownFence{ok: []netip.Addr{ip}}); err == nil || errors.Is(err, sa.ErrNotOwnIP) {
			t.Fatalf("%s: err = %v", s, err)
		}
	}
	if e.count(`SELECT count(*) FROM jobs_v`) != 0 {
		t.Fatal("a job was started")
	}
}

// A worker whose heartbeat does not say it takes a job's ports never gets a port_versions job: Probe refuses before anything is
// queued, and the weekly scan records the open ports without versions.
func TestPortVersionsNeedsAWorkerThatSaysSo(t *testing.T) {
	t.Parallel()
	d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 20 * time.Millisecond})
	if _, err := d.ActiveHeartbeat(t.Context(), &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true, Version: "7.95"}}); err != nil {
		t.Fatal(err)
	}
	argv, err := nmapargv.BuildFor(nmapargv.PortVersions, 50, []int{40000}, []netip.Addr{netip.MustParseAddr("192.168.10.20")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Probe(t.Context(), argv); !errors.Is(err, sa.ErrPortsUnsupported) {
		t.Fatalf("err = %v", err)
	}
	rep, err := d.Jobs(t.Context(), 0, nil)
	if err != nil || len(rep.Jobs) != 0 {
		t.Fatalf("jobs = %+v %v", rep.Jobs, err)
	}
}
