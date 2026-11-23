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

// svXML writes an -sV batch's XML about the box's address with the given <port> rows (timedOut: nmap gave up on the host) to a
// temporary file for the fake nmap.
func svXML(t *testing.T, timedOut bool, rows ...string) string {
	t.Helper()
	to := ""
	if timedOut {
		to = ` timedout="true"`
	}
	doc := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS -sV" start="1762650000" version="7.95" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="1" services="1"/>
<host starttime="1762650001" endtime="1762650010"` + to + `><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="8.8.8.8" addrtype="ipv4"/>
<hostnames/>
<ports>` + strings.Join(rows, "") + `</ports>
</host>
<runstats><finished time="1762650010" elapsed="9.00" summary="Nmap done" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
`
	p := filepath.Join(t.TempDir(), "sv.xml")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// svPort is one open port of an -sV batch's XML: a service a probe named (product may be empty) or tcpwrapped.
func svPort(port int, name, product string) string {
	return fmt.Sprintf(`<port protocol="tcp" portid="%d"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="%s" product="%s" method="probed" conf="10"/></port>`, port, name, product)
}

// batchArgv is the argv of an external -sV batch on the box's address with the given host timeout.
func batchArgv(ports []int, host string) []string {
	return []string{"--privileged", "-sS", "-sV", "-Pn", "-n", "--max-rate", "100", "--max-retries", "2", "--host-timeout", host, "-p", joinPorts(ports), "--stats-every", "5s", "-oX", "-", "8.8.8.8"}
}

func joinPorts(ports []int) string {
	ss := make([]string, len(ports))
	for i, p := range ports {
		ss[i] = strconv.Itoa(p)
	}
	return strings.Join(ss, ",")
}

// batchCase is the fake nmap's output for one -sV batch: the run whose -p is exactly ports prints file.
func batchCase(ports []int, file string) fakeCase {
	return fakeCase{match: " -p " + joinPorts(ports) + " ", file: file}
}

// sVArgvs are the -sV batch argvs of a run, in order.
func sVArgvs(calls [][]string) [][]string {
	var out [][]string
	for _, c := range calls {
		if slices.Contains(c, "-sV") {
			out = append(out, c)
		}
	}
	return out
}

// The default scan of the box's own public IP through the scan container, under one job row and one nmap slot: the discovery (SYN
// only, --top-ports 1000; 22, 443 and 666 open), then -sV in batches, each its own nmap job with its own host timeout and probe row
// and core's fence asked right before it: the surface list in three batches (22 and 443 in the first), the admin ports in two, then
// the open port found outside both (666). The services come from the batches, the probed ports from the discovery's scaninfo and
// every finished batch, and nothing is written to the inventory. The LAN settings do not bind it.
func TestScanExternalThroughTheWorker(t *testing.T) {
	t.Parallel()
	batches, err := nmapargv.ExternalBatches([]int{22, 443, 666})
	if err != nil || len(batches) != 6 {
		t.Fatalf("batches %v %v", batches, err)
	}
	empty := svXML(t, false)
	e := externalEnvWithNmap(t, boxIP, fakeOpts{always: empty, topPorts: discoveryFixture(t, boxIP), cases: []fakeCase{
		batchCase(batches[0], svXML(t, false, svPort(22, "ssh", "OpenSSH"), svPort(443, "https", "nginx"))),
		batchCase(batches[5], svXML(t, false, svPort(666, "http", "Apache httpd"))),
	}})
	e.inv.set(func(s *sa.Settings) { s.Enabled, s.LANRanges = false, nil })
	own := &ownFence{ok: []netip.Addr{boxIP}}
	got, err := e.svc.ScanExternal(e.ctx(), boxIP, nmapargv.External, own)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Services) != 3 || got.Services[0].Port != 22 || got.Services[2].Port != 666 || got.Services[2].Product != "Apache httpd" {
		t.Fatalf("services %+v", got.Services)
	}
	if got.Ports != len(got.Probed) || got.Ports < 1000 || !slices.Contains(got.Probed, 666) || !slices.Contains(got.Probed, 37777) || len(got.Unfinished) != 0 {
		t.Fatalf("probed %d ports, unfinished %v", got.Ports, got.Unfinished)
	}
	if own.asked != 1+len(batches) {
		t.Fatalf("the fence was asked %d times", own.asked)
	}
	calls := e.nm.calls(t)
	if len(calls) != 1+len(batches) ||
		!slices.Equal(calls[0], []string{"--privileged", "-sS", "-Pn", "-n", "--max-rate", "100", "--max-retries", "2", "--host-timeout", "2m", "--top-ports", "1000", "--stats-every", "5s", "-oX", "-", "8.8.8.8"}) {
		t.Fatalf("nmap argv = %q", calls)
	}
	for i, b := range batches { // in order, each at the longest host timeout: the run has its whole time left
		if !slices.Equal(calls[1+i], batchArgv(b, "120s")) {
			t.Fatalf("batch %d argv = %q", i+1, calls[1+i])
		}
	}
	if s := e.str(`SELECT group_concat(result, ';') FROM (SELECT * FROM sa_probe ORDER BY id)`); s != "ok: 3 of 1000 ports open;batch 1 of 6: ok: 2 open ports;batch 2 of 6: ok: 0 open ports;batch 3 of 6: ok: 0 open ports;batch 4 of 6: ok: 0 open ports;batch 5 of 6: ok: 0 open ports;batch 6 of 6: ok: 1 open ports" {
		t.Fatalf("probe rows = %s", s)
	}
	if f := e.str(`SELECT flags FROM sa_probe ORDER BY id DESC LIMIT 1`); f != strings.Join(batchArgv(batches[5], "120s")[:13], " ")+" --stats-every 5s" {
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

// The fixed list always gets its -sV batches, whatever the discovery said. After a discovery that hit its host timeout, or whose
// output is not believed (a <scaninfo> that is not the top 1000), the batches are the fixed list's alone (the surface list, then the
// admin ports): Probed is that list and DiscoveryCut says why. After a discovery that saw the address answer on almost every port
// (a router or SYN proxy), the batches are the fixed list's alone and only the ports where -sV named a real service are kept (the
// tcpwrapped 23 is dropped). The -sV options are those of the shape before the batches.
func TestScanExternalAlwaysReadsTheFixedList(t *testing.T) {
	t.Parallel()
	var many strings.Builder
	for p := range 60 {
		fmt.Fprintf(&many, `<port protocol="tcp" portid="%d"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="tcpwrapped" method="table" conf="3"/></port>`, 100+p)
	}
	fixed, err := nmapargv.ExternalBatches(nil)
	if err != nil || len(fixed) != 5 {
		t.Fatalf("batches %v %v", fixed, err)
	}
	for name, c := range map[string]struct {
		edit       func([]byte) []byte
		cut, every bool
		services   int
		discovery  string
	}{
		"discovery timed out": {func(b []byte) []byte {
			return bytes.Replace(b, []byte("<host starttime"), []byte(`<host timedout="true" starttime`), 1)
		}, true, false, 2,
			"failed: nmap gave up on the address at its host timeout"},
		"discovery not believed": {func(b []byte) []byte {
			return bytes.Replace(b, []byte(`services="1-1000"`), []byte(`services="1-999"`), 1)
		}, true, false, 2,
			"failed: nmap probed 999 ports, not its top 1000; output discarded"},
		"answers everywhere": {func(b []byte) []byte {
			return bytes.Replace(b, []byte("</ports>"), []byte(many.String()+"</ports>"), 1)
		}, false, true, 1,
			"ok: more than 40 ports open, the address answers on almost every port; -sV reads the fixed list next"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			first := svXML(t, false, svPort(22, "ssh", "OpenSSH"), svPort(23, "tcpwrapped", ""))
			if !c.every {
				first = svXML(t, false, svPort(22, "ssh", "OpenSSH"), svPort(443, "https", "nginx"))
			}
			e := externalEnvWithNmap(t, boxIP, fakeOpts{always: svXML(t, false), topPorts: discoveryVariant(t, c.edit), cases: []fakeCase{batchCase(fixed[0], first)}})
			got, err := e.svc.ScanExternal(e.ctx(), boxIP, nmapargv.External, &ownFence{ok: []netip.Addr{boxIP}})
			if err != nil {
				t.Fatal(err)
			}
			if got.DiscoveryCut != c.cut || got.AnswersEverywhere != c.every || !slices.Equal(got.Probed, nmapargv.ExtraPortNumbers) ||
				got.Ports != len(nmapargv.ExtraPortNumbers) || len(got.Services) != c.services {
				t.Fatalf("got cut=%v everywhere=%v %d ports, services %+v", got.DiscoveryCut, got.AnswersEverywhere, got.Ports, got.Services)
			}
			for _, x := range got.Services {
				if x.Name == "tcpwrapped" {
					t.Fatalf("kept a tcpwrapped port: %+v", x)
				}
			}
			sv := sVArgvs(e.nm.calls(t))
			if len(sv) != len(fixed) {
				t.Fatalf("%d -sV batches: %q", len(sv), sv)
			}
			for i, b := range fixed {
				if !slices.Equal(sv[i], batchArgv(b, "120s")) {
					t.Fatalf("batch %d argv = %q", i+1, sv[i])
				}
			}
			if r := e.str(`SELECT result FROM sa_probe ORDER BY id LIMIT 1`); r != c.discovery {
				t.Fatalf("discovery row = %s", r)
			}
		})
	}
}

// nmap drops every result of a host it gives up on, so a batch that times out loses only its own ports: the earlier batch's services
// are kept, the timed-out batch's ports are Unfinished and not Probed (that run never calls them closed), the later batches still
// run, and the probe row says which batch and why. The next run of the address starts with those ports; the batch that failed
// before is first, then the others in their usual order. A run where no batch finished says nmap gave up, as before.
func TestScanExternalBatchTimeoutKeepsTheRestAndRotates(t *testing.T) {
	t.Parallel()
	batches, err := nmapargv.ExternalBatches([]int{22, 443, 666})
	if err != nil {
		t.Fatal(err)
	}
	e := externalEnvWithNmap(t, boxIP, fakeOpts{always: svXML(t, false), topPorts: discoveryFixture(t, boxIP), cases: []fakeCase{
		batchCase(batches[0], svXML(t, false, svPort(22, "ssh", "OpenSSH"))),
		batchCase(batches[1], svXML(t, true)),
	}})
	own := &ownFence{ok: []netip.Addr{boxIP}}
	got, err := e.svc.ScanExternal(e.ctx(), boxIP, nmapargv.External, own)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Services) != 1 || got.Services[0].Port != 22 || !slices.Equal(got.Unfinished, batches[1]) {
		t.Fatalf("services %+v, unfinished %v", got.Services, got.Unfinished)
	}
	for _, p := range batches[1] {
		if slices.Contains(got.Probed, p) {
			t.Fatalf("port %d of the timed-out batch counted as probed", p)
		}
	}
	if !slices.Contains(got.Probed, 22) || !slices.Contains(got.Probed, 666) {
		t.Fatalf("probed %v", got.Probed)
	}
	if r := e.str(`SELECT result FROM sa_probe WHERE result LIKE 'batch 2 of %'`); r != "batch 2 of 6: failed: nmap gave up on the address at its host timeout" {
		t.Fatalf("batch 2 row = %s", r)
	}
	if n := len(sVArgvs(e.nm.calls(t))); n != len(batches) {
		t.Fatalf("%d -sV batches ran, want all %d", n, len(batches))
	}
	before := len(e.nm.calls(t))
	if _, err := e.svc.ScanExternal(e.ctx(), boxIP, nmapargv.External, own); err != nil {
		t.Fatal(err)
	}
	second := sVArgvs(e.nm.calls(t)[before:])
	want := append([][]int{batches[1], batches[0]}, batches[2:]...)
	for i, b := range want {
		if i >= len(second) || !slices.Equal(second[i], batchArgv(b, "120s")) {
			t.Fatalf("the next run's batch %d = %q, want ports %v", i+1, second, b)
		}
	}

	none := externalEnvWithNmap(t, boxIP, fakeOpts{always: svXML(t, true), topPorts: discoveryFixture(t, boxIP)})
	if _, err := none.svc.ScanExternal(none.ctx(), boxIP, nmapargv.External, own); !errors.Is(err, sa.ErrHostTimedOut) {
		t.Fatalf("no batch finished: err = %v", err)
	}
}

// A batch that was not started for want of time leaves a probe row that names its ports and why, and the next run starts with it,
// like a batch that timed out.
func TestScanExternalNotStartedBatchRotates(t *testing.T) {
	t.Parallel()
	batches, err := nmapargv.ExternalBatches(nil)
	if err != nil {
		t.Fatal(err)
	}
	e := externalEnvWithNmap(t, boxIP, fakeOpts{always: svXML(t, false), topPorts: discoveryFixture(t, boxIP)})
	at := "2026-11-01T10:00:00.000Z"
	flags := strings.Join(batchArgv(batches[3], "60s")[:13], " ") + " --stats-every 5s"
	e.exec(runRow("r-old", sa.RunService, "event", "done", at, ""),
		`INSERT INTO sa_probe (time, run_id, shape, rate, hosts, flags, targets, result) VALUES ('`+at+`', 'r-old', 'external', 100, 1, '`+flags+`', '8.8.8.8', 'batch 4 of 5: not started: too little time left in this scan; the next scan starts with these ports')`)
	if _, err := e.svc.ScanExternal(e.ctx(), boxIP, nmapargv.External, &ownFence{ok: []netip.Addr{boxIP}}); err != nil {
		t.Fatal(err)
	}
	if sv := sVArgvs(e.nm.calls(t)); len(sv) == 0 || !slices.Equal(sv[0], batchArgv(batches[3], "120s")) {
		t.Fatalf("the first -sV batch = %q, want ports %v", sv, batches[3])
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
