package honeypot_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/honeypot"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// fakeInv is the inventory as the tests see it: a /24, the box at .2 and some devices.
type fakeInv struct {
	mu      sync.Mutex
	devices []honeypot.Device
	ranges  []netip.Prefix
	box     honeypot.Box
	fail    error
}

func (f *fakeInv) Devices(context.Context) ([]honeypot.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	return append([]honeypot.Device(nil), f.devices...), nil
}

func (f *fakeInv) LANRanges(context.Context) ([]netip.Prefix, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netip.Prefix(nil), f.ranges...), nil
}

func (f *fakeInv) Box(context.Context) (honeypot.Box, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.box, nil
}

func (f *fakeInv) add(d honeypot.Device) {
	f.mu.Lock()
	f.devices = append(f.devices, d)
	f.mu.Unlock()
}

func dev(id, ip, name, kind string) honeypot.Device {
	d := honeypot.Device{ID: id, IP: addr(ip), Name: name, Hostname: name, Kind: kind, Approved: true}
	if name == "" {
		d.Name, d.Hostname = ip, ""
	}
	return d
}

// fakeHost records what the module asked of the host.
type fakeHost struct {
	mu        sync.Mutex
	status    honeypot.HostStatus
	ips       map[netip.Addr]bool
	running   bool
	calls     []string
	restarts  []bool // the restart flag of every StartContainer
	failStart error
	failStop  error
	failRm    error
	failAdd   map[netip.Addr]error // AddDecoyIP of these fails with the error (wrap honeypot.ErrRefused for a refusal)
	addTook   bool                 // a failed add was done by the host all the same (the answer was lost)
	onAdd    func() // called after an address was accepted
}

func newHost(available bool) *fakeHost {
	return &fakeHost{status: honeypot.HostStatus{Available: available, Reason: "this machine is not an appliance"}, ips: map[netip.Addr]bool{}}
}

func (h *fakeHost) Status(context.Context) (honeypot.HostStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.status, nil
}

func (h *fakeHost) AddDecoyIP(_ context.Context, ip netip.Addr) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "add "+ip.String())
	if err := h.failAdd[ip]; err != nil {
		if h.addTook {
			h.ips[ip] = true // the host did it, the answer was lost
		}
		return err
	}
	h.ips[ip] = true
	if h.onAdd != nil {
		h.onAdd()
	}
	return nil
}

func (h *fakeHost) RemoveDecoyIP(_ context.Context, ip netip.Addr) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "remove "+ip.String())
	if h.failRm != nil {
		return h.failRm
	}
	delete(h.ips, ip)
	return nil
}

func (h *fakeHost) StartContainer(_ context.Context, restart bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "start")
	h.restarts = append(h.restarts, restart)
	if h.failStart != nil {
		return h.failStart
	}
	h.running = true
	return nil
}

func (h *fakeHost) StopContainer(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "stop")
	if h.failStop != nil {
		return h.failStop
	}
	h.running = false
	return nil
}

func (h *fakeHost) log() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.calls...)
}

type fakeLogs struct{ lines []honeypot.LogEvent }

func (f fakeLogs) Around(context.Context, time.Time, time.Duration, netip.Addr) ([]honeypot.LogEvent, error) {
	return f.lines, nil
}

type gate struct {
	mu  sync.Mutex
	off bool
}

func (g *gate) Enabled(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.off || id != "honeypot"
}
func (g *gate) turnOff() { g.mu.Lock(); g.off = true; g.mu.Unlock() }

type pubs struct {
	mu   sync.Mutex
	list []honeypot.Event
}

func (p *pubs) Publish(_ context.Context, e honeypot.Event) error {
	p.mu.Lock()
	p.list = append(p.list, e)
	p.mu.Unlock()
	return nil
}

func (p *pubs) all() []honeypot.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]honeypot.Event(nil), p.list...)
}

var errStart = errors.New("start failed")

var t0 = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

type env struct {
	t    *testing.T
	svc  *honeypot.Service
	db   *store.DB
	inv  *fakeInv
	host *fakeHost
	pub  *pubs
	gate *gate
	dir  string
	now  time.Time
	cfg  honeypot.Config
}

type option func(*env)

func newEnv(t *testing.T, opts ...option) *env {
	t.Helper()
	db := storetest.New(t)
	ctx := t.Context()
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "honeypot", honeypot.Migrations); err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, db: db, host: newHost(true), pub: &pubs{}, gate: &gate{}, dir: t.TempDir(), now: t0,
		inv: &fakeInv{ranges: []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")}, box: honeypot.Box{IP: addr("192.168.10.2"), Name: "vedette-hq"},
			devices: []honeypot.Device{
				{ID: "a-box", IP: addr("192.168.10.2"), Name: "vedette-hq", Hostname: "vedette-hq", Kind: "server", IsBox: true, Approved: true},
				dev("a-pc07", "192.168.10.107", "PC-HR-01", "pc"),
				{ID: "a-srv", IP: addr("192.168.10.10"), Name: "SRV-FILE", Hostname: "SRV-FILE", Kind: "server", OS: "Windows Server 2019", Approved: true, Ports: []int{445}},
				dev("a-nas", "192.168.10.30", "NAS-PHOTOS", "nas"),
				dev("a-prn", "192.168.10.31", "PRN-LOBBY", "printer"),
			}}}
	e.cfg = honeypot.Config{DB: db, Audit: audit.New(func() time.Time { return e.now }), Secrets: sec, Inventory: e.inv, Host: e.host, Events: e.pub, Modules: e.gate,
		ConfigDir: filepath.Join(e.dir, "config"), LogDir: filepath.Join(e.dir, "log"), Clock: func() time.Time { return e.now }, Log: slog.New(slog.DiscardHandler), Location: func(context.Context) *time.Location { return time.UTC }}
	for _, o := range opts {
		o(e)
	}
	e.svc, err = honeypot.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) ctx() context.Context { return e.t.Context() }

func (e *env) confPath() string { return filepath.Join(e.dir, "config", honeypot.ConfFile) }

func (e *env) logPath() string { return filepath.Join(e.dir, "log", "opencanary.jsonl") }

// setup puts the usual state in: secondary IP, hostname, and the SSH and SMB traps on.
func (e *env) setup() {
	e.t.Helper()
	if _, err := e.svc.SetConfig(e.ctx(), "admin@acme.example", "192.168.10.240", "FILESRV-OLD"); err != nil {
		e.t.Fatal(err)
	}
	for _, s := range []honeypot.ServiceName{honeypot.SSH, honeypot.SMB} {
		if _, err := e.svc.SetTrap(e.ctx(), "admin@acme.example", s, true); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *env) count(query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.Reader().QueryRowContext(e.ctx(), query, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
	return n
}

func (e *env) auditActions() []string {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT action FROM core_audit ORDER BY seq`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

// ---- log lines as OpenCanary writes them ----

type ln struct {
	LogType  int
	Src, Dst string
	SrcPort  int
	DstPort  int
	At       time.Time
	Data     map[string]any
}

func (l ln) json() string {
	if l.Dst == "" {
		l.Dst = "192.168.10.240"
	}
	m := map[string]any{"dst_host": l.Dst, "dst_port": l.DstPort, "src_host": l.Src, "src_port": l.SrcPort, "logtype": l.LogType,
		"node_id": "vedette-honeypot", "local_time": l.At.Format("2006-01-02 15:04:05.000000"), "local_time_adjusted": l.At.Format("2006-01-02 15:04:05.000000"),
		"utc_time": l.At.Format("2006-01-02 15:04:05.000000"), "logdata": l.Data}
	b, _ := json.Marshal(m)
	return string(b)
}

func sshNew(src string, sport int, at time.Time) ln {
	return ln{LogType: 4000, Src: src, SrcPort: sport, DstPort: 22, At: at, Data: map[string]any{"LOCALVERSION": "SSH-2.0-OpenSSH_8.9p1"}}
}

func sshLogin(src string, sport int, at time.Time, user string) ln {
	return ln{LogType: 4002, Src: src, SrcPort: sport, DstPort: 22, At: at, Data: map[string]any{"USERNAME": user, "PASSWORD": "hunter2-never-stored", "REMOTEVERSION": "SSH-2.0-libssh"}}
}

func (e *env) appendLog(lines ...string) {
	e.t.Helper()
	if err := os.MkdirAll(filepath.Dir(e.logPath()), 0o750); err != nil {
		e.t.Fatal(err)
	}
	f, err := os.OpenFile(e.logPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, l := range lines {
		if _, err := fmt.Fprintln(f, l); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *env) poll() {
	e.t.Helper()
	if err := e.svc.Poll(e.ctx()); err != nil {
		e.t.Fatal(err)
	}
}

func apiCode(t *testing.T, err error) string {
	t.Helper()
	var ae *apierr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("not an API error: %v", err)
	}
	return ae.Code
}

func (h *fakeHost) isRunning() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.running }
func (h *fakeHost) ipCount() int    { h.mu.Lock(); defer h.mu.Unlock(); return len(h.ips) }

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		<-time.After(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

type fakeBus struct {
	names []string
	fns   []events.Handler
}

func (b *fakeBus) Subscribe(name string, fn events.Handler) func() {
	b.names = append(b.names, name)
	b.fns = append(b.fns, fn)
	return func() {}
}

func eventOf(name string) events.Event {
	return events.Event{Name: name, Data: map[string]any{"asset_id": "x"}}
}

type sqlTx = sql.Tx
