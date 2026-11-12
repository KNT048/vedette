package opstest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/peer"
	"github.com/knt048/vedette/host/server"
)

// The fake world of host.self_update (D-316, plan slice 2): the kept package of the running version,
// core's downloaded file, a manifest with a host part, and the answers of dpkg-query, dpkg-deb,
// systemctl is-active and the simulated apt install. Slice 2a covers Check and Run up to the park; the
// applier, the fake systemd-run and the restart markers come with slice 2b.

// HostPackage is the bytes of a fake vedette-host .deb of version (only its hash matters to the host).
func HostPackage(version string) []byte { return []byte("!<arch>\nvedette-host " + version + "\n") }

// SHA is the lowercase hex SHA-256 of b.
func SHA(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// KeepPackage writes <state>/selfupdate/packages/vedette-host_<version>_amd64.deb (0600), as install.sh does.
func (m *Machine) KeepPackage(version string, content []byte) string {
	m.t.Helper()
	dir := filepath.Join(m.State, "selfupdate", "packages")
	m.must(os.MkdirAll(dir, 0o700))
	p := filepath.Join(dir, "vedette-host_"+version+"_amd64.deb")
	m.must(os.WriteFile(p, content, 0o600))
	return p
}

// CorePackage writes core's download <core_data>/host-packages/<id>.deb (0600, core's owner) and returns the id.
func (m *Machine) CorePackage(content []byte) string {
	m.t.Helper()
	b := make([]byte, 16)
	_, err := rand.Read(b)
	m.must(err)
	id := hex.EncodeToString(b)
	dir := filepath.Join(m.CoreData, "host-packages")
	m.must(os.MkdirAll(dir, 0o700))
	m.must(os.WriteFile(filepath.Join(dir, id+".deb"), content, 0o600))
	return id
}

// CorePackagePath is the path of core's download.
func (m *Machine) CorePackagePath(id string) string {
	return filepath.Join(m.CoreData, "host-packages", id+".deb")
}

// HostInstalled makes dpkg-query say vedette-host <version> (SemVer; printed in the Debian form) has status.
func (m *Machine) HostInstalled(version, status string) {
	m.RuleText("dpkg-query", "vedette-host", strings.Replace(version, "-", "~", 1)+"|"+status, 0, "", "")
}

// DebFields makes dpkg-deb --field print the three fields of the staged file.
func (m *Machine) DebFields(pkg, debVersion, arch string) {
	m.RuleText("dpkg-deb", "/selfupdate/staged/", "Package: "+pkg+"\nVersion: "+debVersion+"\nArchitecture: "+arch+"\n", 0, "", "")
}

// KeptDebFields makes dpkg-deb --field of the kept package of version (SemVer) print its true fields.
func (m *Machine) KeptDebFields(version string) {
	m.RuleText("dpkg-deb", "/packages/vedette-host_"+version+"_amd64.deb",
		"Package: vedette-host\nVersion: "+strings.Replace(version, "-", "~", 1)+"\nArchitecture: amd64\n", 0, "", "")
}

// ApplierUnit makes systemctl is-active vedette-host-upgrade.service print state (exit 0 for active, 3 otherwise).
func (m *Machine) ApplierUnit(state string) {
	code := 3
	if state == "active" || state == "activating" {
		code = 0
	}
	m.RuleText("systemctl", "is-active vedette-host-upgrade.service", state+"\n", code, "", "")
}

// SimInstall makes the simulated apt install of the staged file print text and exit with code.
func (m *Machine) SimInstall(text string, code int) {
	m.RuleText("apt-get", "-s -q -o Debug::NoLocking=1 --no-remove --no-install-recommends install", text, code, "", "")
}

// SimInstallOK is the simulation of an install of vedette-host <debVersion> over <debFrom> with one new dependency.
func SimInstallOK(debFrom, debVersion string) string {
	return "Reading package lists...\nInst conntrack (1:1.4.8-1 Ubuntu:24.04/noble [amd64])\nInst vedette-host [" + debFrom + "] (" + debVersion + " local-deb [amd64])\n" +
		"Conf conntrack (1:1.4.8-1 Ubuntu:24.04/noble [amd64])\nConf vedette-host (" + debVersion + " local-deb [amd64])\n"
}

// HostFile is one host.files[] entry of a manifest.
type HostFile struct {
	Name   string
	SHA256 string
	Size   int64
}

// HostFileOf is the amd64 entry of a package's bytes.
func HostFileOf(version string, content []byte) HostFile {
	return HostFile{Name: "vedette-host_" + version + "_amd64.deb", SHA256: SHA(content), Size: int64(len(content))}
}

// HostManifestDoc is ManifestDoc of version with a host part (hostVersion and its files); no images.
func (r *Release) HostManifestDoc(version, hostVersion string, files ...HostFile) Doc {
	d := r.ManifestDoc(version, Img{Service: api.ServiceCore, Digest: "sha256:" + strings.Repeat("a", 64), Size: 1000})
	var fs []any
	for _, f := range files {
		fs = append(fs, Doc{"name": f.Name, "sha256": f.SHA256, "size": f.Size})
	}
	d["host"] = Doc{"version": hostVersion, "files": fs}
	return d
}

// SelfUpdateArgs builds the host.self_update args for raw documents signed by the active key.
func (r *Release) SelfUpdateArgs(version string, indexRaw, manifestRaw []byte, pkg string) api.HostSelfUpdateArgs {
	b := base64.StdEncoding.EncodeToString
	return api.HostSelfUpdateArgs{
		Version: version, Index: b(indexRaw), IndexSig: b(r.Sign(indexRaw)), Manifest: b(manifestRaw), ManifestSig: b(r.Sign(manifestRaw)), Package: pkg,
	}
}

// --- slice 2b: the world of the applier and of the host's own restart ------------------------------------

// SUWorld runs host.self_update end to end on the fake machine: hosts (Ops + Server on the same state and
// audit chain) that restart the way postinst's try-restart restarts the real one, the applier started in a
// goroutine by the StartUnit seam (after the real argv validator), and fakes of apt-get, dpkg, dpkg-query and
// systemctl that change the "installed version" by markers. Markers (Machine.Mark) shape a scenario:
//
//	policy-rc.d            postinst does not restart the host (the applier must)
//	new-host-dead          a host of the new version never starts, so it never writes started.json
//	crash-loop             while the new version is installed, NRestarts grows at every look
//	apt-fails              apt-get install of the staged file exits 100 and changes nothing
//	apt-fails-unpacked     apt-get install of the staged file unpacks it (the new version is installed) and exits 100
//	rollback-apt-fails     apt-get --allow-downgrades install exits 100
//	lock-outlives          apt waited DPkg::Lock::Timeout in vain: exits 100, nothing changed
//	half                   dpkg was cut mid-unpack: status half-installed, --audit not clean, apt refuses
//	dpkg-lock-once         the next dpkg -i of the staged file fails on the lock, and the probe then sees it held once
//	dispatch-fails         systemd-run fails (the unit name is taken)
//	dispatch-panics        the settle goroutine panics where it starts the unit
//
// The scripts wait for the world on a marker (postinst) the way the real try-restart waits for READY.
type SUWorld struct {
	T       testing.TB
	M       *Machine
	Rel     *Release
	Clock   *Clock
	From    string
	To      string
	Pkg     []byte // the new package
	OldExe  []byte // the bytes of the running (old) binary
	PkgID   string // core's file
	Applies atomic.Int32
	// Stop, when set, is asked after each phase the applier writes: true kills that applier there.
	Stop func(phase string) bool
	// Cancel, when set, is asked after each phase too: true cancels that applier's context there (RuntimeMaxSec,
	// a reboot, systemctl stop) and lets it go on, as the real one would until it notices.
	Cancel func(phase string) bool
	// Hold, when set, makes each applier wait for a value before it starts.
	Hold chan struct{}

	mu         sync.Mutex
	cur        *SUHost
	auditPath  string
	dirs       []string // the temp folders of the hosts' sockets (the first also holds the audit chain)
	hosts      []string // the version of each host started, in order
	dispatches [][]string
	applierBin [][]byte // what selfupdate/applier held at each dispatch
	ctx        context.Context
	exe        string
	watchDone  chan struct{}
}

// SUHost is one running host of the world.
type SUHost struct {
	Version string
	Ops     *ops.Ops
	Srv     *server.Server
	Client  *client.Client
	dir     string
	served  chan struct{} // closed when Serve returned (after Shutdown)
}

// NewSUWorld makes the machine of a host running from, the kept package of from (adopted at the first start),
// core's download of to, and the release documents. It starts the first host.
func NewSUWorld(t testing.TB, from, to string) *SUWorld {
	t.Helper()
	m := NewMachine(t)
	w := &SUWorld{
		T: t, M: m, Rel: NewRelease(t), Clock: NewClock(time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)),
		From: from, To: to, Pkg: HostPackage(to), OldExe: []byte("vedette-host " + from + " binary"), watchDone: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.ctx = ctx
	w.exe = filepath.Join(m.Rec, "self-exe")
	m.must(os.WriteFile(w.exe, w.OldExe, 0o700)) //nolint:gosec // test: the fake running binary
	m.KeepPackage(from, HostPackage(from))
	m.KeptDebFields(from)
	m.KeptDebFields(to)
	m.DebFields("vedette-host", strings.Replace(to, "-", "~", 1), "amd64")
	m.SimInstall(SimInstallOK(from, to), 0)
	m.Rule("apt-get", "-q update", "apt_update.txt", 0, "", "") // not "update": the staged path holds "selfupdate"
	m.must(os.WriteFile(filepath.Join(m.Rec, "mainpid"), []byte(fmt.Sprint(os.Getpid())), 0o600))
	w.fakes()
	w.PkgID = m.CorePackage(w.Pkg)
	w.cur = w.startHost(from)
	go w.watch()
	t.Cleanup(func() {
		cancel()
		<-w.watchDone
		defer func() {
			for _, d := range w.dirs {
				_ = os.RemoveAll(d)
			}
		}()
		w.mu.Lock()
		h := w.cur
		w.cur = nil
		w.mu.Unlock()
		if h != nil {
			h.stop()
		}
	})
	return w
}

// fakes writes the stateful fakes of apt-get, dpkg, dpkg-query and systemctl (rules added with Rule still fire first).
func (w *SUWorld) fakes() {
	restart := `req_restart() { [ -e "$REC/mark.policy-rc.d" ] && return 0; : > "$REC/mark.postinst"; while [ -e "$REC/mark.postinst" ]; do sleep 0.002; done; }
`
	fromDeb, toDeb := strings.Replace(w.From, "-", "~", 1), strings.Replace(w.To, "-", "~", 1)
	w.M.writeFakeWith("apt-get", restart+`case "$args" in
  *" --allow-downgrades install "*)
    [ -e "$REC/mark.rollback-apt-fails" ] && exit 100
    rm -f "$REC/mark.inst-new" "$REC/mark.half"; req_restart; exit 0 ;;
  *"DPkg::Lock::Timeout="*" install "*)
    [ -e "$REC/mark.apt-fails" ] && exit 100
    [ -e "$REC/mark.half" ] && { echo "E: dpkg was interrupted, you must manually run 'dpkg --configure -a'"; exit 100; }
    [ -e "$REC/mark.lock-outlives" ] && { echo "E: Could not get lock /var/lib/dpkg/lock-frontend"; exit 100; }
    : > "$REC/mark.inst-new"
    [ -e "$REC/mark.apt-fails-unpacked" ] && exit 100
    req_restart; exit 0 ;;
esac
`)
	w.M.writeFakeWith("dpkg", restart+`case "$args" in
  "--audit") [ -e "$REC/mark.half" ] && echo "The following packages are only half installed: vedette-host"; exit 0 ;;
  "--force-confdef --force-confold -i "*"/selfupdate/staged/"*)
    if [ -e "$REC/mark.dpkg-lock-once" ]; then rm -f "$REC/mark.dpkg-lock-once"; : > "$REC/mark.lock-held-once"; echo "dpkg: error: dpkg frontend lock is locked"; exit 2; fi
    rm -f "$REC/mark.half"; : > "$REC/mark.inst-new"; req_restart; exit 0 ;;
  "--force-confdef --force-confold -i "*"/selfupdate/packages/"*) rm -f "$REC/mark.half" "$REC/mark.inst-new"; req_restart; exit 0 ;;
esac
`)
	w.M.writeFakeWith("dpkg-query", `if [ -e "$REC/mark.half" ]; then echo "`+toDeb+`|half-installed"
elif [ -e "$REC/mark.inst-new" ]; then echo "`+toDeb+`|installed"
else echo "`+fromDeb+`|installed"; fi
exit 0
`)
	w.M.writeFakeWith("systemctl", `case "$args" in
  "is-active vedette-host-upgrade.service") if [ -e "$REC/mark.applier-running" ]; then echo active; exit 0; fi; echo inactive; exit 3 ;;
  "show vedette-host.service -p ActiveState,MainPID,NRestarts")
    n=$(cat "$REC/nrestarts" 2>/dev/null || echo 0)
    if [ -e "$REC/mark.crash-loop" ] && [ -e "$REC/mark.inst-new" ]; then n=$((n+1)); echo "$n" > "$REC/nrestarts"; fi
    echo "ActiveState=active"; echo "MainPID=$(cat "$REC/mainpid")"; echo "NRestarts=$n"; exit 0 ;;
  "restart vedette-host.service") : > "$REC/mark.postinst"; while [ -e "$REC/mark.postinst" ]; do sleep 0.002; done; exit 0 ;;
esac
`)
}

func (w *SUWorld) lockHeld(string) (bool, error) {
	if w.M.Marked("lock-held-once") {
		w.M.Mark("lock-held-once", false)
		return true, nil
	}
	return false, nil
}

func (w *SUWorld) deps(d *ops.Deps) {
	d.Keys = w.Rel.Keys
	d.SelfExe = w.exe
	d.StartUnit = w.startUnit
	d.LockHeld = w.lockHeld
	d.FreeBytes = func(string) (uint64, error) { return 100 << 30, nil }
}

// startHost starts a host of version on the state, as systemd would: New (Resume), Start, Listen, AfterReady.
// The socket lives in a short temp folder of its own (macOS limits socket paths); the audit chain is one file.
func (w *SUWorld) startHost(version string) *SUHost {
	t := w.T
	t.Helper()
	o := w.M.Ops(w.Clock.Now, func(c *ops.Config, d *ops.Deps) { c.Version = version; w.deps(d) })
	dir, err := os.MkdirTemp("", "su")
	if err != nil {
		t.Fatal(err)
	}
	w.dirs = append(w.dirs, dir)
	osrel := filepath.Join(dir, "os-release")
	if err := os.WriteFile(osrel, []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if w.auditPath == "" {
		w.auditPath = filepath.Join(dir, "log", "audit.jsonl")
	}
	reg, err := server.NewRegistry(o.Commands()...)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Options{
		SocketPath: filepath.Join(dir, "run", "h.sock"), SocketGID: os.Getgid(), StateDir: w.M.State, AuditPath: w.auditPath,
		Registry: reg, Readers: o.Readers(), WriteGate: o.WriteGate, Resume: o.Resume, Version: version, Now: w.Clock.Now,
		PeerCheck: func(net.Conn) (peer.Info, error) {
			return peer.Info{UID: 10001, PID: 4242, Unit: "vedette-core.service"}, nil
		},
		OSReleasePath: osrel, Logger: slog.New(slog.DiscardHandler), RequestsPerMinute: 100_000, WritesPerMinute: 100_000,
		OwnerUID: os.Getuid(), Exit: func(int) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	o.Start(w.ctx, srv)
	ln, err := srv.Listen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sh := &SUHost{Version: version, Ops: o, Srv: srv, Client: client.New(filepath.Join(dir, "run", "h.sock")), dir: dir, served: make(chan struct{})}
	go func() { _ = srv.Serve(ln); close(sh.served) }()
	o.AfterReady(w.ctx, srv)
	w.hosts = append(w.hosts, version)
	return sh
}

// stop shuts a host down as SIGTERM does: the server first, then Ops. Its socket folder goes (not the audit chain's).
func (h *SUHost) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = h.Srv.Shutdown(ctx)
	<-h.served
	h.Client.Close()
	h.Ops.Close()
	_ = os.Remove(filepath.Join(h.dir, "run", "h.sock"))
}

// Restart stops the current host and starts one of the installed version (what dpkg-query says), unless that
// is the new version and new-host-dead is set.
func (w *SUWorld) Restart() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur != nil {
		w.cur.stop()
		w.cur = nil
	}
	v := w.From
	if w.M.Marked("inst-new") {
		v = w.To
	}
	if v == w.To && w.M.Marked("new-host-dead") {
		return
	}
	w.cur = w.startHost(v)
}

// StopHost stops the current host and starts none (a box that went down).
func (w *SUWorld) StopHost() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur != nil {
		w.cur.stop()
		w.cur = nil
	}
}

// StartHost starts a host of the installed version when none runs.
func (w *SUWorld) StartHost() {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := w.From
	if w.M.Marked("inst-new") {
		v = w.To
	}
	w.cur = w.startHost(v)
}

// watch plays postinst's try-restart (and the applier's systemctl restart): when a fake asks for it with the
// postinst marker, restart the host, then let the fake go on. It waits on that state, not on a clock.
func (w *SUWorld) watch() {
	defer close(w.watchDone)
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-tick.C:
		}
		if w.M.Marked("postinst") {
			w.Restart()
			w.M.Mark("postinst", false)
		}
	}
}

// startUnit is Deps.StartUnit: argv passed the real validator; the applier copy runs in a goroutine.
func (w *SUWorld) startUnit(argv []string) error {
	if w.M.Marked("dispatch-panics") {
		panic("test: the settle goroutine panics")
	}
	if w.M.Marked("dispatch-fails") {
		return errors.New("unit vedette-host-upgrade.service was already loaded or has a fragment file")
	}
	path := argv[len(argv)-3]
	b, err := os.ReadFile(path) //nolint:gosec // test: the applier copy the argv names
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.dispatches = append(w.dispatches, slices.Clone(argv))
	w.applierBin = append(w.applierBin, b)
	w.mu.Unlock()
	w.M.Mark("applier-running", true)
	actx, cancel := context.WithCancel(w.ctx)
	stop := func(phase string) bool {
		if w.Cancel != nil && w.Cancel(phase) {
			cancel()
			return false
		}
		return w.Stop != nil && w.Stop(phase)
	}
	go func() {
		defer cancel()
		defer w.M.Mark("applier-running", false)
		if w.Hold != nil {
			select {
			case <-w.Hold:
			case <-w.ctx.Done():
				return
			}
		}
		w.Applies.Add(1)
		_ = ops.ApplyWithDeps(actx, ops.ApplyConfig{StateDir: filepath.Dir(filepath.Dir(path)), RunID: argv[len(argv)-1]}, ops.ApplyDeps{
			Root: w.M.Root, BinPaths: w.M.BinPaths(), Arch: "amd64", LockHeld: w.lockHeld, Stop: stop,
			Sleep: func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil },
		})
	}()
	return nil
}

// Clock is a settable clock shared by the hosts of a world and their commands.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock starts a clock at t.
func NewClock(t time.Time) *Clock { return &Clock{t: t} }

// Now is the clock's time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock on by d.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Args are the host.self_update args of the world's release.
func (w *SUWorld) Args() api.HostSelfUpdateArgs {
	man := w.Rel.HostManifestDoc("1.4.0", w.To, HostFileOf(w.To, w.Pkg))
	return w.Rel.SelfUpdateArgs("1.4.0", JSON(w.T, w.Rel.IndexDoc(5)), JSON(w.T, man), w.PkgID)
}

// Client is the client of the current host (nil when none runs).
func (w *SUWorld) Client() *client.Client {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur == nil {
		return nil
	}
	return w.cur.Client
}

// Host is the current host.
func (w *SUWorld) Host() *SUHost {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cur
}

// Hosts are the versions of the hosts started so far, in order.
func (w *SUWorld) Hosts() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.hosts)
}

// Dispatches are the systemd-run argv the hosts gave, and what the applier copy held at each.
func (w *SUWorld) Dispatches() ([][]string, [][]byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.dispatches), slices.Clone(w.applierBin)
}

// AuditPath is the one audit chain of every host of the world.
func (w *SUWorld) AuditPath() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.auditPath
}

// Until waits (on state) until cond holds; it fails the test after HangBound.
func (w *SUWorld) Until(what string, cond func() bool) {
	w.T.Helper()
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	for !cond() {
		select {
		case <-deadline.C:
			w.T.Fatalf("timed out waiting for %s", what)
		case <-tick.C:
		}
	}
}

// RunEnded waits until the run has ended on the current host and returns it.
func (w *SUWorld) RunEnded(id string) api.Run {
	w.T.Helper()
	var r api.Run
	w.Until("run "+id+" to end", func() bool {
		c := w.Client()
		if c == nil {
			return false
		}
		got, err := c.GetRun(context.Background(), id)
		r = got
		return err == nil && got.Status.Terminal()
	})
	return r
}

// Send starts host.self_update on the current host.
func (w *SUWorld) Send(a api.HostSelfUpdateArgs) (api.Run, error) {
	return w.Client().SelfUpdate(context.Background(), a, "0000aaaa-5555-4555-8555-555555555555", "admin@example.com")
}
