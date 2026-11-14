package sensoractive_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	sa "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

var boxIP = netip.MustParseAddr("8.8.8.8") // stands for the box's own verified public IP (testdata/external.xml)

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

// externalEnv is an env whose Service hands nmap jobs to a real worker over the real mutual-TLS link (D-113), with the fake nmap
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
	e := newEnv(t, fakeOpts{always: fx})
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
	svc, err := sa.New(sa.Config{DB: e.db, Inventory: e.inv, Observe: e.sink, Software: e.sink, Services: e.sink, Events: e.ev, Prober: d, Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

// D-514: -sV on the box's own public IP through the scan container: the fence asked right before the job, the probe row written
// with the external shape and its -p list, the job of kind external, the services read from the XML and nothing written to the
// inventory. The LAN settings do not bind it: scanning switched off and an empty scope change nothing.
func TestScanExternalThroughTheWorker(t *testing.T) {
	t.Parallel()
	e := externalEnv(t, boxIP)
	e.inv.set(func(s *sa.Settings) { s.Enabled, s.LANRanges = false, nil })
	own := &ownFence{ok: []netip.Addr{boxIP}}
	got, err := e.svc.ScanExternal(e.ctx(), boxIP, nmapargv.External, own)
	if err != nil {
		t.Fatal(err)
	}
	if got.Ports != 98 || len(got.Services) != 4 || got.Services[2].Product != "Apache httpd" || got.Services[2].Version != "2.4.49" || got.Services[2].CPE != "cpe:/a:apache:http_server:2.4.49" {
		t.Fatalf("got %+v", got)
	}
	if own.asked != 1 {
		t.Fatalf("the fence was asked %d times", own.asked)
	}
	calls := e.nm.calls(t)
	if len(calls) != 1 || !slices.Equal(calls[0], []string{"--privileged", "-sS", "-sV", "-Pn", "-n", "--max-rate", "100", "--max-retries", "2", "--host-timeout", "3m", "-p", nmapargv.ExternalPorts, "-oX", "-", "8.8.8.8"}) {
		t.Fatalf("nmap argv = %q", calls)
	}
	if s := e.str(`SELECT shape || '|' || rate || '|' || hosts || '|' || targets || '|' || result FROM sa_probe`); s != "external|100|1|8.8.8.8|ok: 4 open ports" {
		t.Fatalf("probe row = %s", s)
	}
	if f := e.str(`SELECT flags FROM sa_probe`); !strings.HasSuffix(f, "-p "+nmapargv.ExternalPorts) || len(f) <= 300 {
		t.Fatalf("flags = %s", f)
	}
	if s := e.str(`SELECT kind || '|' || reason || '|' || status FROM sa_job`); s != "external|exposure|done" {
		t.Fatalf("job = %s", s)
	}
	if len(e.sink.observations()) != 0 || len(e.sink.svc) != 0 {
		t.Fatal("an external scan wrote to the inventory")
	}
}

// deepFence is ownFence with the DeepGate of a full run (D-526): the shape the target's terms allow now, as exposure's ModeNow
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

// D-526: the deep scan of an accepted target through the real worker: both fences asked right before the job, the probe row with
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

// D-526: the terms withdrawn or of an older version right before the job (the gate says External), a gate that fails, or a fence
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

// D-526: a worker whose heartbeat does not say it runs the full shapes (older than protocol 5's field) never gets one: Probe refuses
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
	if s := e.str(`SELECT group_concat(status) FROM sa_job`); s != "failed" {
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
	if e.count(`SELECT count(*) FROM sa_job`) != 0 {
		t.Fatal("a job was started")
	}
}

// D-514: migration 0005 keeps the probe log's counter and every earlier shape, and takes the external shape with its 540-character
// flags (the -p list).
func TestMigration0005KeepsTheProbeCounter(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	before := fstest.MapFS{}
	if err := fs.WalkDir(sa.Migrations, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p >= "0005" {
			return err
		}
		b, err := fs.ReadFile(sa.Migrations, p)
		before[p] = &fstest.MapFile{Data: b}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "sensor-active", before); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) error {
		return db.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q, args...); return err })
	}
	must := func(q string, args ...any) {
		t.Helper()
		if err := exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	must(`INSERT INTO sa_job (id, kind, started_at, status) VALUES ('j', 'snmp', '2026-11-01T01:00:00.000Z', 'done')`)
	for i, shape := range []string{"sweep", "gentle_titles", "snmp"} {
		must(fmt.Sprintf(`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-01T01:00:00.000Z', 'j', '%s', 1, 1, '-sn', '192.168.1.%d', 'ok')`, shape, i+1))
	}
	must(`DELETE FROM sa_probe WHERE id > 1`) // the prune of old rows
	if err := store.Migrate(ctx, db, "sensor-active", sa.Migrations); err != nil {
		t.Fatal(err)
	}
	flags, _ := nmapargv.Flags(nmapargv.External, nmapargv.ExternalRate)
	must(`INSERT INTO sa_job (id, kind, started_at, status) VALUES ('x', 'external', '2026-11-13T01:00:00.000Z', 'done')`)
	must(`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-13T01:00:00.000Z', 'x', 'external', 100, 1, ?, '8.8.8.8', 'ok')`, strings.Join(flags, " "))
	var id int
	var shapes string
	if err := db.Reader().QueryRowContext(ctx, `SELECT max(id), group_concat(shape) FROM sa_probe`).Scan(&id, &shapes); err != nil || id != 4 || shapes != "sweep,external" {
		t.Fatalf("the next probe id is %d, shapes %s (%v), want 4", id, shapes, err)
	}
	if exec(`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-13T01:00:00.000Z', 'x', 'aggressive', 1, 1, '-A', '8.8.8.8', 'ok')`) == nil {
		t.Fatal("an unknown shape was accepted")
	}
}
