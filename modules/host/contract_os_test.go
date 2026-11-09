// Contract tests of the system commands of WP-07b part 1 (modules/host/CONTRACT.md): os.check,
// os.install, os.auto_security.set, os.reboot, os.reboot.cancel, backup.create, backup.restore,
// logs.export and the state endpoints. Every test runs on a fake machine (opstest): a temp root,
// fake binaries that record argv and environment, a real SQLite database. Nothing touches /etc,
// /var or /run, and no real apt, dpkg or systemctl ever starts.
package host_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

var cleanEnv = []string{"DEBIAN_FRONTEND=noninteractive", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}

var installPre = []string{
	"-y", "-q", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold",
	"--no-remove", "install", "--only-upgrade",
}

var (
	argvUpdate   = []string{"-q", "update"}
	argvSimulate = []string{"-q", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"}
)

// fakeTimers captures the timers Ops arms so tests fire them by hand.
type fakeTimers struct {
	mu sync.Mutex
	ts []*fakeTimer
}

type fakeTimer struct {
	d       time.Duration
	f       func()
	stopped bool
}

func (ft *fakeTimers) after(d time.Duration, f func()) func() bool {
	t := &fakeTimer{d: d, f: f}
	ft.mu.Lock()
	ft.ts = append(ft.ts, t)
	ft.mu.Unlock()
	return func() bool {
		ft.mu.Lock()
		defer ft.mu.Unlock()
		was := !t.stopped
		t.stopped = true
		return was
	}
}

// active returns the live timers except the hourly export sweep.
func (ft *fakeTimers) active() []*fakeTimer {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	var out []*fakeTimer
	for _, t := range ft.ts {
		if !t.stopped && t.d != time.Hour {
			out = append(out, t)
		}
	}
	return out
}

func (ft *fakeTimers) sweeps() []*fakeTimer {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	var out []*fakeTimer
	for _, t := range ft.ts {
		if !t.stopped && t.d == time.Hour {
			out = append(out, t)
		}
	}
	return out
}

func (t *fakeTimer) fire() {
	t.f()
}

type sysEnv struct {
	installing atomic.Bool
	m          *opstest.Machine
	o          *ops.Ops
	h          *servertest.Harness
	clock      *servertest.Clock
	timers     *fakeTimers
	n          atomic.Int64
}

type mut = func(*ops.Config, *ops.Deps)

func startSys(t *testing.T, muts ...mut) *sysEnv {
	t.Helper()
	m := opstest.NewMachine(t)
	e := &sysEnv{m: m, clock: servertest.NewClock(time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)), timers: &fakeTimers{}}
	all := append([]mut{func(_ *ops.Config, d *ops.Deps) {
		d.Installing = &e.installing
		d.AfterFunc = e.timers.after
		d.FreeBytes = func(string) (uint64, error) { return 100 << 30, nil }
	}}, muts...)
	e.o = m.Ops(e.clock.Now, all...)
	e.h = servertest.Start(t, e.o.Commands(), func(o *server.Options) {
		o.StateDir, o.Readers, o.Now = m.State, e.o.Readers(), e.clock.Now
	})
	return e
}

func (e *sysEnv) id() string { return fmt.Sprintf("%08x-5555-4555-8555-555555555555", e.n.Add(1)) }

// call sends a command and, when it was accepted, waits for the run to end.
func (e *sysEnv) call(t *testing.T, command string, args any) (api.Run, error) {
	t.Helper()
	run, err := e.h.Client.Run(context.Background(), command, args, e.id(), "admin@example.com")
	if err != nil {
		return api.Run{}, err
	}
	return waitDone(t, e.h.Client, run.RunID), nil
}

// ok runs a command that must end succeeded.
func (e *sysEnv) ok(t *testing.T, command string, args any) api.Run {
	t.Helper()
	r, err := e.call(t, command, args)
	if err != nil || r.Status != api.StatusSucceeded {
		t.Fatalf("%s: err %v run %+v", command, err, r)
	}
	return r
}

// final runs a command that must be accepted and end with the status and code.
func (e *sysEnv) final(t *testing.T, command string, args any, status api.Status, code string) api.Run {
	t.Helper()
	r, err := e.call(t, command, args)
	if err != nil {
		t.Fatalf("%s: %v", command, err)
	}
	if r.Status != status || (code != "" && (r.Error == nil || r.Error.Code != code)) {
		t.Fatalf("%s: want %s/%s, got %+v (error %+v)", command, status, code, r, r.Error)
	}
	return r
}

// refused runs a command that the server must refuse before it starts (HTTP error).
func (e *sysEnv) refused(t *testing.T, command string, args any, status int, code string) {
	t.Helper()
	_ = e.refusedWith(t, command, args, status, code)
}

// refusedWith is refused that also returns the error, for its hints.
func (e *sysEnv) refusedWith(t *testing.T, command string, args any, status int, code string) *client.Error {
	t.Helper()
	_, err := e.call(t, command, args)
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Status != status || ce.Code != code {
		t.Fatalf("%s: want %d %s, got %v", command, status, code, err)
	}
	return ce
}

func result[T any](t *testing.T, r api.Run) T {
	t.Helper()
	v, err := client.ResultOf[T](r)
	if err != nil {
		t.Fatalf("result of %s: %v (%s)", r.Command, err, r.Result)
	}
	return v
}

func (e *sysEnv) rules() {
	e.m.Rule("apt-get", "update", "apt_update.txt", 0, "", "")
	e.m.Rule("apt-get", "dist-upgrade", "sim_ubuntu.txt", 0, "", "")
	e.m.Rule("apt-config", "dump", "aptconfig_on.txt", 0, "", "")
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for !cond() {
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", what)
		case <-tick.C:
		}
	}
}

func rawGet(t *testing.T, h *servertest.Harness, path string) (int, []byte) {
	t.Helper()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", h.Socket)
	}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://host"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(api.HeaderProto, "1")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func assertEnvClean(t *testing.T, envs [][]string) {
	t.Helper()
	if len(envs) == 0 {
		t.Fatal("no process was started")
	}
	for i, env := range envs {
		if !slices.Equal(env, cleanEnv) {
			t.Errorf("process %d saw the environment %v, want exactly %v", i, env, cleanEnv)
		}
	}
}

// --- the command table matches the spec ----------------------------------------------------------

// documentedCommandsPart1 are the commands WP-07b part 1 implements.
var documentedCommandsPart1 = []string{
	"backup.create", "backup.restore", "logs.export", "os.auto_security.set", "os.check", "os.install", "os.reboot", "os.reboot.cancel",
}

// notYetImplemented are the commands of spec section 6 that later parts bring (net, decoy IP, containers).
var notYetImplemented = []string{
	"container.pull", "container.rollback", "container.start", "container.stop",
	"decoy_ip.add", "decoy_ip.remove", "net.apply", "net.confirm", "net.revert",
}

func TestContract_Part1_TheCommandTableMatchesSection6OfTheSpec(t *testing.T) {
	t.Parallel()
	if !slices.Equal(documentedCommands, documentedCommandsPart1) {
		t.Fatalf("documentedCommands = %v, want %v", documentedCommands, documentedCommandsPart1)
	}
	e := startSys(t)
	info, err := e.h.Client.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(info.Commands, documentedCommandsPart1) {
		t.Fatalf("info.commands = %v, want exactly %v", info.Commands, documentedCommandsPart1)
	}
	// Spec section 6 headings name every command; the implemented and the not-yet lists together are that table.
	spec, err := os.ReadFile("../../docs/specs/host-api.md")
	if err != nil {
		t.Fatal(err)
	}
	var inSpec []string
	for _, line := range strings.Split(string(spec), "\n") {
		if !strings.HasPrefix(line, "### 6.") {
			continue
		}
		for _, m := range regexp.MustCompile("`([a-z_]+(?:\\.[a-z_]+)+)`").FindAllStringSubmatch(line, -1) {
			inSpec = append(inSpec, m[1])
		}
	}
	slices.Sort(inSpec)
	all := slices.Concat(documentedCommandsPart1, notYetImplemented)
	slices.Sort(all)
	if !slices.Equal(inSpec, all) {
		t.Fatalf("spec section 6 lists %v, implemented + not yet = %v", inSpec, all)
	}
	// A not-yet command is an unknown command, like any other name outside the table.
	for _, name := range notYetImplemented {
		_, err := e.call(t, name, map[string]any{})
		var ce *client.Error
		if !errors.As(err, &ce) || ce.Status != http.StatusNotFound || ce.Code != api.CodeUnknownCommand {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, p := range []string{"/v1/state/net", "/v1/state/containers", "/v1/state/nope", "/v1/backups/x/y/content"} {
		if st, b := rawGet(t, e.h, p); st != http.StatusNotFound || errCode(b) != api.CodeUnknownCommand {
			t.Errorf("GET %s: %d %s", p, st, b)
		}
	}
}

// --- INV-2: bad args never reach the system -------------------------------------------------------

func TestContract_INV2_SystemCommandsRefuseBadArgsBeforeAnythingRuns(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.rules()
	meta := []string{"; id", "$(id)", "`id`", "a|b", "a&b", "a\nb", "../../etc/passwd", "'x'", `"x"`, "--yes", "-o APT::x=1", "a b", "\x00", "${IFS}"}
	type bad struct {
		cmd  string
		body string
	}
	var cases []bad
	add := func(cmd, body string, vals ...string) {
		for _, v := range vals {
			j, _ := json.Marshal(v)
			cases = append(cases, bad{cmd, strings.ReplaceAll(body, "%V", string(j))})
		}
	}
	add("os.install", `{"args":{"scope":%V}}`, append(meta, "", "ALL", "security ", "release", "dist-upgrade")...)
	add("os.reboot", `{"args":{"when":%V}}`, append(meta, "", "NOW", "window", "custom")...)
	add("os.reboot", `{"args":{"when":"at","at":%V}}`, append(meta, "", "tomorrow", "10:30", "2026-11-10")...)
	add("backup.create", `{"args":{"kind":%V,"include_secrets":false}}`, append(meta, "", "auto", "pre_", "PRE_UPDATE", "manual ")...)
	add("backup.create", `{"args":{"kind":"manual","label":%V}}`, "; id", "$(id)", "a|b", "<script>", "`id`", "../x", strings.Repeat("a", 65))
	add("backup.restore", `{"args":{"backup_id":%V}}`, append(meta, "", "abc", strings.Repeat("g", 32), strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("a", 33), "../"+strings.Repeat("a", 29))...)
	add("logs.export", `{"args":{"units":[%V],"since":"2026-11-09T00:00:00Z","until":"2026-11-09T01:00:00Z"}}`, append(meta, "", "Vedette-Core")...)
	add("logs.export", `{"args":{"units":["vedette-core"],"since":%V,"until":"2026-11-09T01:00:00Z"}}`, "yesterday", "2026-11-09", "", "1999-01-01T00:00:00Z")
	cases = append(cases,
		bad{"os.install", `{"args":{}}`}, bad{"os.install", `{"args":{"scope":"all","packages":["x"]}}`},
		bad{"os.install", `{"args":{"scope":["all"]}}`}, bad{"os.install", `{"args":{"scope":"all","argv":["x"]}}`},
		bad{"os.reboot", `{"args":{}}`}, bad{"os.reboot", `{"args":{"when":"now","at":"2026-11-10T00:00:00Z"}}`},
		bad{"os.reboot", `{"args":{"when":"at"}}`}, bad{"os.auto_security.set", `{"args":{"enabled":"yes"}}`},
		bad{"os.auto_security.set", `{"args":{"enabled":true,"origins":["x"]}}`}, bad{"os.check", `{"args":{"force":true}}`},
		bad{"os.reboot.cancel", `{"args":{"x":1}}`}, bad{"backup.restore", `{"args":{"path":"/etc/passwd"}}`},
		bad{"backup.restore", `{"args":{"backup_id":"` + strings.Repeat("a", 32) + `","path":"/x"}}`},
		bad{"backup.create", `{"args":{"kind":"manual","path":"/x"}}`}, bad{"backup.create", `{"args":{}}`},
		bad{"logs.export", `{"args":{"units":[],"since":"2026-11-09T00:00:00Z","until":"2026-11-09T01:00:00Z"}}`},
		bad{"logs.export", `{"args":{"units":["vedette-core","vedette-sensor","vedette-honeypot","vedette-scan","vedette-greenbone","vedette-host","vedette-core"],"since":"2026-11-09T00:00:00Z","until":"2026-11-09T01:00:00Z"}}`},
		bad{"logs.export", `{"args":{"units":["vedette-core"],"since":"2026-11-09T01:00:00Z","until":"2026-11-09T01:00:00Z"}}`},
		bad{"logs.export", `{"args":{"units":["vedette-core"],"since":"2026-11-09T02:00:00Z","until":"2026-11-09T01:00:00Z"}}`},
		bad{"logs.export", `{"args":{"units":["vedette-core"],"since":"2026-11-09T00:00:00Z","until":"2026-11-09T01:00:00Z","grep":"x"}}`},
	)
	for i, c := range cases {
		st, body := rawReq(t, e.h, "/v1/commands/"+c.cmd, hdr(fmt.Sprintf("%08x-6666-4666-8666-666666666666", i)), c.body)
		if st != http.StatusBadRequest || errCode(body) != api.CodeInvalidArgs {
			t.Errorf("%s %s: %d %s", c.cmd, c.body, st, body)
		}
	}
	if calls := e.m.AllCalls(); len(calls) != 0 {
		t.Fatalf("a process was started for bad args: %v", calls)
	}
	if got, _ := os.ReadDir(filepath.Join(e.m.State, "backups")); len(got) > 1 {
		t.Fatalf("a backup was written for bad args: %v", got)
	}
}

// --- os.check -------------------------------------------------------------------------------------

func TestContract_OSCheck_ArgvEnvResultAndDurableSnapshot(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.rules()
	e.m.WriteRoot("var/run/reboot-required", "*** System restart required ***\n")
	e.m.WriteRoot("var/run/reboot-required.pkgs", "linux-image-6.8.0-45-generic\nlibc6\n")

	if st, b := rawGet(t, e.h, "/v1/state/os"); st != http.StatusNotFound || errCode(b) != api.CodeNoCheckYet {
		t.Fatalf("before the first check: %d %s", st, b)
	}
	run := e.ok(t, "os.check", nil)
	st := result[api.OSState](t, run)

	if got := e.m.Calls("apt-get"); !slices.EqualFunc(got, [][]string{argvUpdate, argvSimulate}, slices.Equal) {
		t.Fatalf("apt-get argv = %q", got)
	}
	if got := e.m.Calls("apt-config"); !slices.EqualFunc(got, [][]string{{"dump"}}, slices.Equal) {
		t.Fatalf("apt-config argv = %q", got)
	}
	assertEnvClean(t, e.m.Envs("apt-get"))
	assertEnvClean(t, e.m.Envs("apt-config"))

	now := e.clock.Now()
	if st.OS.Distro != "ubuntu" || st.OS.Name != "Ubuntu 24.04.3 LTS" || st.OS.Release != "24.04" || st.OS.Kernel != "6.8.0-45-generic" {
		t.Errorf("os = %+v", st.OS)
	}
	if st.OS.SupportEnd != "2029-05-31" || st.OS.ExtendedEnd == nil || *st.OS.ExtendedEnd != "2034-04-30" {
		t.Errorf("support = %s / %v", st.OS.SupportEnd, st.OS.ExtendedEnd)
	}
	if !st.LastCheck.Equal(now) || !st.OS.LastCheck.Equal(now) || !st.OS.BootedAt.Equal(time.Date(2026, 11, 9, 10, 59, 59, 0, time.UTC)) {
		t.Errorf("times: last_check %v booted_at %v", st.LastCheck, st.OS.BootedAt)
	}
	if !slices.Equal(st.OS.Mirrors, []string{"archive.ubuntu.com", "evil", "ppa.example.net", "security.ubuntu.com"}) {
		t.Errorf("mirrors = %v", st.OS.Mirrors)
	}
	if len(st.Pending) != 2 || st.Pending[0].Name != "libc6" || st.Pending[0].Security || st.Pending[1].Name != "openssl" || !st.Pending[1].Security ||
		st.Pending[1].Current != "3.0.13-0ubuntu3.3" || st.Pending[1].New != "3.0.13-0ubuntu3.4" || st.Pending[1].Origin != "Ubuntu:24.04/noble-security" {
		t.Errorf("pending = %+v", st.Pending)
	}
	if st.Pending[0].CVEs == nil || len(st.Pending[0].CVEs) != 0 {
		t.Errorf("cves must be an empty array: %#v", st.Pending[0].CVEs)
	}
	if st.SecurityCount != 1 || !st.RebootRequired || !slices.Equal(st.RebootReasons, []string{"libc6", "linux-image-6.8.0-45-generic"}) || !st.AutoSecurity || st.RebootScheduledAt != nil {
		t.Errorf("state = %+v", st)
	}

	// The snapshot is durable and GET /v1/state/os serves it.
	got, err := e.h.Client.StateOS(context.Background())
	if err != nil || got.SecurityCount != 1 || len(got.Pending) != 2 || !got.LastCheck.Equal(now) {
		t.Fatalf("state/os: %+v %v", got, err)
	}
	again, err := e.m.Ops(e.clock.Now).Readers().OS(context.Background()) // a new Ops on the same state dir (a host restart)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(again); !bytes.Contains(b, []byte(`"security_count":1`)) {
		t.Fatalf("after a restart: %s", b)
	}
	// The reboot flag is live: clearing the file shows in the next read without another check.
	e.m.RemoveRoot("var/run/reboot-required")
	if got, _ = e.h.Client.StateOS(context.Background()); got.RebootRequired || len(got.RebootReasons) != 0 {
		t.Errorf("reboot flag is stale: %+v", got)
	}
}

func TestContract_OSCheck_DebianAndSecurityDetection(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.m.OSRelease("debian", "13", "Debian GNU/Linux 13 (trixie)")
	e.m.Rule("apt-get", "dist-upgrade", "sim_debian.txt", 0, "", "")
	e.m.Rule("apt-config", "dump", "aptconfig_off.txt", 0, "", "")
	st := result[api.OSState](t, e.ok(t, "os.check", nil))
	if st.OS.Distro != "debian" || st.OS.SupportEnd != "2028-08-09" || st.SecurityCount != 1 || st.AutoSecurity {
		t.Fatalf("%+v", st)
	}
	if st.Pending[0].Name != "openssl" || !st.Pending[0].Security || st.Pending[1].Name != "tzdata" || st.Pending[1].Security {
		t.Fatalf("%+v", st.Pending)
	}
}

func TestContract_OSCheck_Refusals(t *testing.T) {
	t.Parallel()
	t.Run("dpkg lock held: 409 with a 60 s retry hint, nothing runs, audited", func(t *testing.T) {
		t.Parallel()
		var held atomic.Bool
		held.Store(true)
		e := startSys(t, func(_ *ops.Config, d *ops.Deps) {
			d.LockHeld = func(p string) (bool, error) { return held.Load() && strings.HasSuffix(p, "lock-frontend"), nil }
		})
		e.rules()
		ce := e.refusedWith(t, "os.check", nil, http.StatusConflict, "dpkg_locked")
		if ce.RetryAfterS != 60 {
			t.Errorf("retry_after_s = %d", ce.RetryAfterS)
		}
		if len(e.m.AllCalls()) != 0 {
			t.Errorf("a process ran while the lock was held: %v", e.m.AllCalls())
		}
		runs, _ := e.h.Client.ListRuns(context.Background(), 5)
		if len(runs) != 1 || runs[0].Status != api.StatusRefused || runs[0].Error.Code != "dpkg_locked" {
			t.Errorf("runs = %+v", runs)
		}
		last := audit(t, e.h)
		if a := last[len(last)-1]; a.Command != "os.check" || a.Result != "refused" || a.Code == nil || *a.Code != "dpkg_locked" {
			t.Errorf("audit = %+v", a)
		}
		held.Store(false) // the same request id is not remembered after a refusal: a retry works
		e.ok(t, "os.check", nil)
	})
	t.Run("a lock probe that fails counts as held", func(t *testing.T) {
		t.Parallel()
		e := startSys(t, func(_ *ops.Config, d *ops.Deps) {
			d.LockHeld = func(string) (bool, error) { return false, errors.New("boom") }
		})
		e.refused(t, "os.check", nil, http.StatusConflict, "dpkg_locked")
	})
	t.Run("unsupported releases are not an appliance", func(t *testing.T) {
		t.Parallel()
		for _, rel := range [][2]string{{"ubuntu", "22.04"}, {"debian", "12"}, {"fedora", "40"}, {"", ""}, {"ubuntu", "24.04.1"}} {
			e := startSys(t)
			e.m.OSRelease(rel[0], rel[1], "x")
			e.refused(t, "os.check", nil, http.StatusPreconditionFailed, "not_appliance")
			e.refused(t, "os.install", map[string]string{"scope": "all"}, http.StatusPreconditionFailed, "not_appliance")
			e.refused(t, "os.auto_security.set", map[string]bool{"enabled": true}, http.StatusPreconditionFailed, "not_appliance")
			if len(e.m.AllCalls()) != 0 {
				t.Errorf("%v: a process ran: %v", rel, e.m.AllCalls())
			}
		}
	})
	t.Run("apt update failing fails the run and keeps no snapshot", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.m.Rule("apt-get", "update", "", 100, "", "")
		r := e.final(t, "os.check", nil, api.StatusFailed, "apt_failed")
		if strings.Contains(r.Error.Message, "/") && strings.Contains(r.Error.Message, "exec") {
			t.Errorf("message leaks internals: %q", r.Error.Message)
		}
		if st, b := rawGet(t, e.h, "/v1/state/os"); st != http.StatusNotFound {
			t.Errorf("state/os after a failed check: %d %s", st, b)
		}
	})
}

// --- os.install -----------------------------------------------------------------------------------

func (e *sysEnv) installRules() {
	e.m.Rule("apt-get", "update", "apt_update.txt", 0, "", "")
	e.m.Rule("apt-get", "install", "", 0, "", "installed")
	e.m.Rule("apt-get", "dist-upgrade", "sim_after.txt", 0, "installed", "")
	e.m.Rule("apt-get", "dist-upgrade", "sim_ubuntu.txt", 0, "", "")
	e.m.Rule("apt-config", "dump", "aptconfig_on.txt", 0, "", "")
	e.m.Rule("systemctl", "is-active", "active.txt", 0, "", "")
}

func aptCalls(e *sysEnv) [][]string { return e.m.Calls("apt-get") }

func TestContract_OSInstall_HostRecomputesThePackageListAndRunsTheFixedArgv(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.installRules()
	r := e.ok(t, "os.install", api.OSInstallArgs{Scope: "all"})
	res := result[api.OSRunResult](t, r)
	if res.Installed != 2 || res.Security != 1 || res.Backup == "" || res.RebootRequired || len(res.Health) != 1 || res.Health[0] != (api.Health{Name: "vedette-core", OK: true}) {
		t.Fatalf("result = %+v", res)
	}
	// No check was on record, so the host checked first (update + simulation), then simulated again,
	// installed exactly the packages of its own simulation, and read the result back.
	want := [][]string{argvUpdate, argvSimulate, argvSimulate, append(slices.Clone(installPre), "libc6", "openssl"), argvSimulate}
	if got := aptCalls(e); !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("apt-get argv:\n got %q\nwant %q", got, want)
	}
	assertEnvClean(t, e.m.Envs("apt-get"))
	// The backup came first and is a pre_os_update with secrets, which never leaves the box.
	bl, err := e.h.Client.StateBackups(context.Background())
	if err != nil || len(bl.Backups) != 1 || bl.Backups[0].BackupID != res.Backup || bl.Backups[0].Kind != "pre_os_update" || !bl.Backups[0].IncludesSecrets || bl.Backups[0].Downloadable {
		t.Fatalf("backups = %+v %v", bl, err)
	}
	if _, _, err := e.h.Client.DownloadBackup(context.Background(), res.Backup); !client.IsCode(err, api.CodeContainsSecrets) {
		t.Fatalf("download of a pre_* backup: %v", err)
	}
	// Everything the run executed stays inside the fixed command lines.
	for _, c := range e.m.AllCalls() {
		for _, tok := range strings.Fields(c) {
			if slices.Contains([]string{"do-release-upgrade", "purge", "remove", "autoremove", "full-upgrade"}, tok) || strings.HasPrefix(tok, "--allow-") || strings.Contains(tok, "sources.list") {
				t.Errorf("a forbidden word %q in %q", tok, c)
			}
		}
	}
	for _, c := range aptCalls(e) {
		if slices.Contains(c, "dist-upgrade") && !slices.Contains(c, "-s") {
			t.Errorf("dist-upgrade without -s: %q", c)
		}
	}
	// The snapshot now shows nothing pending.
	if st, err := e.h.Client.StateOS(context.Background()); err != nil || len(st.Pending) != 0 {
		t.Errorf("snapshot after install: %+v %v", st, err)
	}
}

func TestContract_OSInstall_ScopeSecurityInstallsSecurityPackagesOnly(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.installRules()
	e.ok(t, "os.check", nil)
	r := e.ok(t, "os.install", api.OSInstallArgs{Scope: "security"})
	res := result[api.OSRunResult](t, r)
	if res.Installed != 1 || res.Security != 1 {
		t.Fatalf("%+v", res)
	}
	calls := aptCalls(e)
	// The check is under 24 hours old: no second apt-get update.
	updates := 0
	for _, c := range calls {
		if slices.Equal(c, argvUpdate) {
			updates++
		}
	}
	if updates != 1 {
		t.Errorf("apt-get update ran %d times, want 1 (a fresh check is reused)", updates)
	}
	if got := calls[len(calls)-2]; !slices.Equal(got, append(slices.Clone(installPre), "openssl")) {
		t.Errorf("install argv = %q", got)
	}
}

func TestContract_OSInstall_AStaleCheckIsRepeated(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.installRules()
	e.ok(t, "os.check", nil)
	e.clock.Advance(25 * time.Hour)
	e.m.Mark("installed", false)
	e.ok(t, "os.install", api.OSInstallArgs{Scope: "all"})
	updates := 0
	for _, c := range aptCalls(e) {
		if slices.Equal(c, argvUpdate) {
			updates++
		}
	}
	if updates != 2 {
		t.Fatalf("apt-get update ran %d times, want 2 (a check older than 24 hours is repeated)", updates)
	}
}

func TestContract_OSInstall_RefusalsAndFailures(t *testing.T) {
	t.Parallel()
	t.Run("dpkg --audit not clean", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.installRules()
		e.m.Rule("dpkg", "--audit", "dpkg_audit_bad.txt", 0, "", "")
		e.refused(t, "os.install", api.OSInstallArgs{Scope: "all"}, http.StatusPreconditionFailed, "dpkg_inconsistent")
		if slices.ContainsFunc(aptCalls(e), func(c []string) bool { return slices.Contains(c, "install") }) {
			t.Error("apt install ran")
		}
	})
	t.Run("dpkg --audit exits non-zero", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.installRules()
		e.m.Rule("dpkg", "--audit", "", 1, "", "")
		e.refused(t, "os.install", api.OSInstallArgs{Scope: "all"}, http.StatusPreconditionFailed, "dpkg_inconsistent")
	})
	t.Run("less than 1 GiB free on /var", func(t *testing.T) {
		t.Parallel()
		e := startSys(t, func(_ *ops.Config, d *ops.Deps) { d.FreeBytes = func(string) (uint64, error) { return 1<<30 - 1, nil } })
		e.installRules()
		e.refused(t, "os.install", api.OSInstallArgs{Scope: "all"}, http.StatusPreconditionFailed, "low_disk")
		if len(aptCalls(e)) != 0 {
			t.Error("apt ran")
		}
	})
	t.Run("lock held", func(t *testing.T) {
		t.Parallel()
		e := startSys(t, func(_ *ops.Config, d *ops.Deps) { d.LockHeld = func(string) (bool, error) { return true, nil } })
		e.installRules()
		e.refused(t, "os.install", api.OSInstallArgs{Scope: "all"}, http.StatusConflict, "dpkg_locked")
	})
	t.Run("no backup possible: nothing is installed", func(t *testing.T) {
		t.Parallel()
		e := startSys(t, func(c *ops.Config, _ *ops.Deps) { c.CoreData = "" })
		e.installRules()
		e.final(t, "os.install", api.OSInstallArgs{Scope: "all"}, api.StatusRefused, "db_unreadable")
		if slices.ContainsFunc(aptCalls(e), func(c []string) bool { return slices.Contains(c, "install") }) {
			t.Error("apt install ran without a backup")
		}
	})
	t.Run("apt install fails: failed, nothing rolled back, partial result", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.installRules()
		e.m.ClearRules("apt-get")
		e.m.Rule("apt-get", "update", "apt_update.txt", 0, "", "")
		e.m.Rule("apt-get", "install", "", 100, "", "")
		e.m.Rule("apt-get", "dist-upgrade", "sim_ubuntu.txt", 0, "", "")
		r := e.final(t, "os.install", api.OSInstallArgs{Scope: "all"}, api.StatusFailed, "apt_failed")
		res := result[api.OSRunResult](t, r)
		if res.Installed != 0 || res.Backup == "" {
			t.Errorf("%+v", res)
		}
		for _, c := range e.m.AllCalls() {
			if slices.ContainsFunc(strings.Fields(c), func(w string) bool { return w == "remove" || w == "purge" || w == "autoremove" }) {
				t.Errorf("a removal ran: %q", c)
			}
		}
	})
	t.Run("health check fails: failed, packages stay, result names the check", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.installRules()
		e.m.ClearRules("systemctl")
		e.m.Rule("systemctl", "is-active", "inactive.txt", 3, "", "")
		r := e.final(t, "os.install", api.OSInstallArgs{Scope: "all"}, api.StatusFailed, "health_check_failed")
		res := result[api.OSRunResult](t, r)
		if res.Installed != 2 || len(res.Health) != 1 || res.Health[0].OK || res.Backup == "" {
			t.Errorf("%+v", res)
		}
		for _, c := range e.m.AllCalls() {
			if slices.ContainsFunc(strings.Fields(c), func(w string) bool { return w == "remove" || w == "purge" || w == "autoremove" || w == "--reinstall" }) {
				t.Errorf("health failure triggered %q", c)
			}
		}
	})
	t.Run("nothing to install: no backup, no install", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.installRules()
		e.m.ClearRules("apt-get")
		e.m.Rule("apt-get", "update", "apt_update.txt", 0, "", "")
		e.m.Rule("apt-get", "dist-upgrade", "sim_after.txt", 0, "", "")
		res := result[api.OSRunResult](t, e.ok(t, "os.install", api.OSInstallArgs{Scope: "all"}))
		if res.Installed != 0 || res.Backup != "" {
			t.Errorf("%+v", res)
		}
		if slices.ContainsFunc(aptCalls(e), func(c []string) bool { return slices.Contains(c, "install") }) {
			t.Error("apt install ran")
		}
		if bl, _ := e.h.Client.StateBackups(context.Background()); len(bl.Backups) != 0 {
			t.Errorf("a backup was made: %+v", bl)
		}
	})
}

// --- os.auto_security.set -------------------------------------------------------------------------

const wantUbuntuConf = `// Managed by vedette-host (os.auto_security.set). Changes are overwritten.
#clear Unattended-Upgrade::Allowed-Origins;
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Allowed-Origins {
	"${distro_id}:${distro_codename}-security";
	"${distro_id}ESMApps:${distro_codename}-apps-security";
	"${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
`

func TestContract_AutoSecurity_WritesTheFixedTemplateAndVerifiesTheEffect(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.m.Rule("apt-config", "dump", "aptconfig_on.txt", 0, "", "")
	e.m.Rule("systemctl", "is-enabled", "enabled.txt", 0, "", "")
	r := e.ok(t, "os.auto_security.set", api.OSAutoSecurityArgs{Enabled: true})
	if res := result[api.OSAutoSecurityResult](t, r); !res.Enabled {
		t.Fatalf("%+v", res)
	}
	path := filepath.Join(e.m.Root, "etc/apt/apt.conf.d/52vedette-unattended")
	got, err := os.ReadFile(path) //nolint:gosec // the test reads the file the command wrote
	if err != nil || string(got) != wantUbuntuConf {
		t.Fatalf("conf (%v):\n%s", err, got)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o644 {
		t.Errorf("mode = %o", st.Mode().Perm())
	}
	wantSys := [][]string{
		{"enable", "--now", "apt-daily.timer", "apt-daily-upgrade.timer"},
		{"is-enabled", "apt-daily.timer"}, {"is-enabled", "apt-daily-upgrade.timer"},
	}
	if got := e.m.Calls("systemctl"); !slices.EqualFunc(got, wantSys, slices.Equal) {
		t.Fatalf("systemctl argv = %q", got)
	}
	assertEnvClean(t, e.m.Envs("systemctl"))
	// Idempotent: the same call again leaves the same file, no temp files behind.
	e.ok(t, "os.auto_security.set", api.OSAutoSecurityArgs{Enabled: true})
	if again, _ := os.ReadFile(path); !bytes.Equal(again, got) { //nolint:gosec // the test reads the file the command wrote
		t.Error("the second run changed the file")
	}
	if ents, _ := os.ReadDir(filepath.Dir(path)); len(ents) != 1 {
		t.Errorf("apt.conf.d holds %d files", len(ents))
	}
}

func TestContract_AutoSecurity_DisableAndDebian(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.m.Rule("apt-config", "dump", "aptconfig_off.txt", 0, "", "")
	e.m.Rule("systemctl", "is-enabled", "disabled.txt", 1, "", "") // is-enabled exits 1 for "disabled"
	e.ok(t, "os.auto_security.set", api.OSAutoSecurityArgs{Enabled: false})
	if got := e.m.Calls("systemctl")[0]; !slices.Equal(got, []string{"disable", "--now", "apt-daily.timer", "apt-daily-upgrade.timer"}) {
		t.Errorf("argv = %q", got)
	}
	conf, _ := e.m.ReadRoot("etc/apt/apt.conf.d/52vedette-unattended")
	if !strings.Contains(conf, `APT::Periodic::Unattended-Upgrade "0";`) {
		t.Errorf("conf:\n%s", conf)
	}
	e.m.OSRelease("debian", "13", "Debian GNU/Linux 13 (trixie)")
	e.m.ClearRules("apt-config")
	e.m.Rule("apt-config", "dump", "aptconfig_on.txt", 0, "", "")
	e.m.ClearRules("systemctl")
	e.m.Rule("systemctl", "is-enabled", "enabled.txt", 0, "", "")
	e.ok(t, "os.auto_security.set", api.OSAutoSecurityArgs{Enabled: true})
	conf, _ = e.m.ReadRoot("etc/apt/apt.conf.d/52vedette-unattended")
	if !strings.Contains(conf, "Origins-Pattern") || !strings.Contains(conf, "label=Debian-Security") || strings.Contains(conf, "Allowed-Origins {") {
		t.Errorf("debian conf:\n%s", conf)
	}
}

func TestContract_AutoSecurity_AnExitCodeIsNotEnough(t *testing.T) {
	t.Parallel()
	t.Run("apt still reads the setting as off", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.m.Rule("apt-config", "dump", "aptconfig_off.txt", 0, "", "")
		e.m.Rule("systemctl", "is-enabled", "enabled.txt", 0, "", "")
		e.final(t, "os.auto_security.set", api.OSAutoSecurityArgs{Enabled: true}, api.StatusFailed, "effect_not_verified")
	})
	t.Run("apt still allows origins besides security", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.m.Rule("apt-config", "dump", "aptconfig_leaky.txt", 0, "", "")
		e.m.Rule("systemctl", "is-enabled", "enabled.txt", 0, "", "")
		e.final(t, "os.auto_security.set", api.OSAutoSecurityArgs{Enabled: true}, api.StatusFailed, "effect_not_verified")
	})
	t.Run("a timer is not enabled although systemctl exited 0", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.m.Rule("apt-config", "dump", "aptconfig_on.txt", 0, "", "")
		e.m.Rule("systemctl", "is-enabled", "disabled.txt", 0, "", "")
		e.final(t, "os.auto_security.set", api.OSAutoSecurityArgs{Enabled: true}, api.StatusFailed, "effect_not_verified")
	})
	t.Run("a masked timer when disabling is not 'disabled'", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.m.Rule("apt-config", "dump", "aptconfig_off.txt", 0, "", "")
		e.m.RuleText("systemctl", "is-enabled", "masked\n", 1, "", "")
		e.final(t, "os.auto_security.set", api.OSAutoSecurityArgs{Enabled: false}, api.StatusFailed, "effect_not_verified")
	})
	t.Run("apt.conf.d missing", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		_ = os.RemoveAll(filepath.Join(e.m.Root, "etc/apt/apt.conf.d"))
		e.final(t, "os.auto_security.set", api.OSAutoSecurityArgs{Enabled: true}, api.StatusFailed, "apt_not_configured")
		if len(e.m.Calls("systemctl")) != 0 {
			t.Error("the timers were touched")
		}
	})
}

// --- os.reboot ------------------------------------------------------------------------------------

func rebootCalls(e *sysEnv) int {
	n := 0
	for _, c := range e.m.Calls("systemctl") {
		if slices.Equal(c, []string{"reboot"}) {
			n++
		}
	}
	return n
}

func TestContract_Reboot_NowRecordsTheRunBeforeRebooting(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.o.Start(context.Background(), e.h.Server)
	r := e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
	if res := result[api.OSRebootResult](t, r); res.When != "now" || res.At != nil {
		t.Fatalf("%+v", res)
	}
	eventually(t, "systemctl reboot", func() bool { return rebootCalls(e) == 1 })
	// When the machine was told to reboot, the run file already said succeeded.
	at := e.m.RunsAtReboot()
	if !strings.Contains(at, `"command":"os.reboot"`) || !strings.Contains(at, `"status":"succeeded"`) {
		t.Fatalf("at reboot time the run was not yet recorded as succeeded: %s", at)
	}
	var started bool
	for _, a := range audit(t, e.h) {
		if a.Command == "os.reboot" && a.Code != nil && *a.Code == "reboot_started" && a.Actor == "system" {
			started = true
		}
	}
	if !started {
		t.Error("no reboot_started audit line")
	}
	assertEnvClean(t, e.m.Envs("systemctl"))
}

func TestContract_Reboot_NowIsLimitedTo3In24Hours(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	for i := 0; i < 3; i++ {
		e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
		eventually(t, "systemctl reboot", func() bool { return rebootCalls(e) == i+1 })
	}
	e.refused(t, "os.reboot", api.OSRebootArgs{When: "now"}, http.StatusConflict, "reboot_limit_reached")
	if rebootCalls(e) != 3 {
		t.Fatalf("%d reboots", rebootCalls(e))
	}
	e.clock.Advance(24*time.Hour + time.Minute)
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
	eventually(t, "the fourth reboot", func() bool { return rebootCalls(e) == 4 })
}

func TestContract_Reboot_AtIsScheduledReplacedAndCancelled(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.o.Start(context.Background(), e.h.Server)
	at := e.clock.Now().Add(90 * time.Minute)
	r := e.ok(t, "os.reboot", api.OSRebootArgs{When: "at", At: at.Format(time.RFC3339)})
	if res := result[api.OSRebootResult](t, r); res.At == nil || !res.At.Equal(at) {
		t.Fatalf("%+v", res)
	}
	if len(e.timers.active()) != 1 || e.timers.active()[0].d != 90*time.Minute {
		t.Fatalf("timers: %+v", e.timers.active())
	}
	e.m.Rule("apt-get", "dist-upgrade", "sim_ubuntu.txt", 0, "", "")
	e.m.Rule("apt-config", "dump", "aptconfig_on.txt", 0, "", "")
	e.ok(t, "os.check", nil)
	if st, _ := e.h.Client.StateOS(context.Background()); st.RebootScheduledAt == nil || !st.RebootScheduledAt.Equal(at) {
		t.Fatalf("state/os reboot_scheduled_at = %v", st.RebootScheduledAt)
	}
	// One schedule only: setting it again replaces the first.
	at2 := e.clock.Now().Add(3 * time.Hour)
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "at", At: at2.Format(time.RFC3339)})
	if act := e.timers.active(); len(act) != 1 || act[0].d != 3*time.Hour {
		t.Fatalf("the first timer is still armed: %+v", act)
	}
	if st, _ := e.h.Client.StateOS(context.Background()); st.RebootScheduledAt == nil || !st.RebootScheduledAt.Equal(at2) {
		t.Fatalf("schedule = %v", st.RebootScheduledAt)
	}
	// Cancel clears it; cancelling again is a success that does nothing.
	e.ok(t, "os.reboot.cancel", nil)
	if len(e.timers.active()) != 0 {
		t.Error("the timer is still armed after a cancel")
	}
	if st, _ := e.h.Client.StateOS(context.Background()); st.RebootScheduledAt != nil {
		t.Errorf("schedule after cancel = %v", st.RebootScheduledAt)
	}
	e.ok(t, "os.reboot.cancel", nil)
	if rebootCalls(e) != 0 {
		t.Error("the machine rebooted")
	}
}

func TestContract_Reboot_ScheduledRebootFiresOnce(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.o.Start(context.Background(), e.h.Server)
	at := e.clock.Now().Add(2 * time.Hour)
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "at", At: at.Format(time.RFC3339)})
	tm := e.timers.active()[0]
	// A timer that fires too early re-arms itself instead of rebooting.
	tm.fire()
	if rebootCalls(e) != 0 || len(e.timers.active()) != 1 {
		t.Fatalf("an early timer rebooted: %d, timers %d", rebootCalls(e), len(e.timers.active()))
	}
	e.clock.Advance(2 * time.Hour)
	e.timers.active()[0].fire()
	eventually(t, "the scheduled reboot", func() bool { return rebootCalls(e) == 1 })
	if raw, _ := os.ReadFile(filepath.Join(e.m.State, "os", "reboot.json")); bytes.Contains(raw, []byte(`"schedule"`)) {
		t.Errorf("the schedule is still set after it fired: %s", raw)
	}
	found := false
	for _, a := range audit(t, e.h) {
		if a.Command == "os.reboot" && a.Code != nil && *a.Code == "reboot_started" {
			found = true
		}
	}
	if !found {
		t.Error("no reboot_started line for the scheduled reboot")
	}
}

func TestContract_Reboot_ARunningCommandDelaysTheScheduledReboot(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.o.Start(context.Background(), e.h.Server)
	at := e.clock.Now().Add(2 * time.Hour)
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "at", At: at.Format(time.RFC3339)})
	e.clock.Advance(2 * time.Hour)
	e.installing.Store(true)
	e.timers.active()[0].fire()
	if rebootCalls(e) != 0 {
		t.Fatal("rebooted during an install")
	}
	act := e.timers.active()
	if len(act) != 1 || act[0].d != time.Minute {
		t.Fatalf("timers = %+v", act)
	}
	e.installing.Store(false)
	act[0].fire()
	eventually(t, "the delayed reboot", func() bool { return rebootCalls(e) == 1 })
}

func TestContract_Reboot_Refusals(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	now := e.clock.Now()
	at := func(d time.Duration) api.OSRebootArgs {
		return api.OSRebootArgs{When: "at", At: now.Add(d).Format(time.RFC3339)}
	}
	e.refused(t, "os.reboot", at(-time.Hour), http.StatusPreconditionFailed, "at_in_past")
	e.refused(t, "os.reboot", at(30*time.Second), http.StatusPreconditionFailed, "at_in_past")
	e.refused(t, "os.reboot", at(7*24*time.Hour+time.Minute), http.StatusPreconditionFailed, "at_too_far")
	e.ok(t, "os.reboot", at(60*time.Second+time.Second))
	e.ok(t, "os.reboot", at(7*24*time.Hour-time.Minute))
	// An offset time is the same instant: normalised to UTC.
	loc := time.FixedZone("x", 7*3600)
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "at", At: now.Add(3 * time.Hour).In(loc).Format(time.RFC3339)})
	if rebootCalls(e) != 0 {
		t.Error("a refusal or a schedule rebooted the machine")
	}

	// net_pending_confirm: no net commands exist yet, the check is a seam that answers false.
	pending := startSys(t, func(_ *ops.Config, d *ops.Deps) { d.NetPending = func() bool { return true } })
	pending.refused(t, "os.reboot", api.OSRebootArgs{When: "now"}, http.StatusConflict, "net_pending_confirm")
	pending.refused(t, "os.reboot", api.OSRebootArgs{When: "at", At: now.Add(time.Hour).Format(time.RFC3339)}, http.StatusConflict, "net_pending_confirm")
	if rebootCalls(pending) != 0 {
		t.Error("rebooted while a network change was pending")
	}
}

func TestContract_Reboot_InstallInProgressIsRefused(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.installing.Store(true) // the write lock normally answers busy first; this is the second line of defence
	e.refused(t, "os.reboot", api.OSRebootArgs{When: "now"}, http.StatusConflict, "install_in_progress")
	e.installing.Store(false)
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
}

func TestContract_Reboot_ScheduleSurvivesAHostRestart(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	at := e.clock.Now().Add(2 * time.Hour)
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "at", At: at.Format(time.RFC3339)})

	// A new server and a new Ops on the same state directory and audit file: a host restart.
	timers2 := &fakeTimers{}
	o2 := e.m.Ops(e.clock.Now, func(_ *ops.Config, d *ops.Deps) { d.AfterFunc = timers2.after })
	h2 := servertest.Start(t, o2.Commands(), func(o *server.Options) {
		o.StateDir, o.AuditPath, o.Readers, o.Now = e.m.State, e.h.AuditPath, o2.Readers(), e.clock.Now
	})
	e.clock.Advance(30 * time.Minute)
	o2.Start(context.Background(), h2.Server)
	defer o2.Close()
	act := timers2.active()
	if len(act) != 1 || act[0].d != 90*time.Minute {
		t.Fatalf("after a restart the timer is %+v, want one of 90 minutes", act)
	}
	e.m.Rule("apt-get", "dist-upgrade", "sim_ubuntu.txt", 0, "", "")
	if _, err := h2.Client.Run(context.Background(), "os.check", nil, e.id(), "x"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the check", func() bool {
		st, err := h2.Client.StateOS(context.Background())
		return err == nil && st.RebootScheduledAt != nil && st.RebootScheduledAt.Equal(at)
	})
	waitIdle(t, h2)
	e.clock.Advance(90 * time.Minute)
	act[0].fire()
	eventually(t, "the reboot after the restart", func() bool { return rebootCalls(e) == 1 })
}

func TestContract_Reboot_CompletionIsAuditedAfterANewBoot(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.o.Start(context.Background(), e.h.Server)
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
	eventually(t, "reboot", func() bool { return rebootCalls(e) == 1 })

	// Same boot after a host restart: the reboot never happened, nothing is claimed.
	same := e.m.Ops(e.clock.Now)
	h2 := servertest.Start(t, same.Commands(), func(o *server.Options) {
		o.StateDir, o.AuditPath, o.Readers, o.Now = e.m.State, e.h.AuditPath, same.Readers(), e.clock.Now
	})
	same.Start(context.Background(), h2.Server)
	for _, a := range audit(t, h2) {
		if a.Code != nil && *a.Code == "reboot_completed" {
			t.Fatal("reboot_completed on the same boot")
		}
	}
	// The pending reboot was dropped by that restart, so give the next boot a fresh one.
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
	eventually(t, "second reboot", func() bool { return rebootCalls(e) == 2 })
	e.m.SetBootID("99999999-8888-4777-8666-555555555555") // the kernel booted again
	next := e.m.Ops(e.clock.Now)
	h3 := servertest.Start(t, next.Commands(), func(o *server.Options) {
		o.StateDir, o.AuditPath, o.Readers, o.Now = e.m.State, e.h.AuditPath, next.Readers(), e.clock.Now
	})
	next.Start(context.Background(), h3.Server)
	completed := 0
	for _, a := range audit(t, h3) {
		if a.Command == "os.reboot" && a.Code != nil && *a.Code == "reboot_completed" && a.Actor == "system" {
			completed++
		}
	}
	if completed != 1 {
		t.Fatalf("%d reboot_completed lines, want 1", completed)
	}
	// And only once: another restart on the new boot says nothing more.
	again := e.m.Ops(e.clock.Now)
	h4 := servertest.Start(t, again.Commands(), func(o *server.Options) {
		o.StateDir, o.AuditPath, o.Readers, o.Now = e.m.State, e.h.AuditPath, again.Readers(), e.clock.Now
	})
	again.Start(context.Background(), h4.Server)
	n := 0
	for _, a := range audit(t, h4) {
		if a.Code != nil && *a.Code == "reboot_completed" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d reboot_completed lines after a second restart, want still 1", n)
	}
}

func TestContract_Reboot_AScheduleFromBeforeANewBootIsDropped(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "at", At: e.clock.Now().Add(2 * time.Hour).Format(time.RFC3339)})
	e.m.SetBootID("99999999-8888-4777-8666-555555555555")
	timers2 := &fakeTimers{}
	o2 := e.m.Ops(e.clock.Now, func(_ *ops.Config, d *ops.Deps) { d.AfterFunc = timers2.after })
	h2 := servertest.Start(t, o2.Commands(), func(o *server.Options) {
		o.StateDir, o.AuditPath, o.Readers, o.Now = e.m.State, e.h.AuditPath, o2.Readers(), e.clock.Now
	})
	o2.Start(context.Background(), h2.Server)
	if len(timers2.active()) != 0 {
		t.Fatal("a schedule from a previous boot was re-armed")
	}
	dropped := false
	for _, a := range audit(t, h2) {
		if a.Code != nil && *a.Code == "reboot_schedule_dropped" {
			dropped = true
		}
	}
	if !dropped {
		t.Error("the dropped schedule left no audit line")
	}
}

// --- backups --------------------------------------------------------------------------------------

func readBackupFiles(t *testing.T, e *sysEnv, id string) map[string][]byte {
	t.Helper()
	f, err := os.Open(filepath.Join(e.m.State, "backups", id+".tar.gz")) //nolint:gosec // the test reads an archive the command wrote
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	files := map[string][]byte{}
	if err := ops.ReadArchive(f, func(name string, data []byte) error { files[name] = data; return nil }); err != nil {
		t.Fatal(err)
	}
	return files
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.db")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestContract_Backup_ManualWithoutSecretsHoldsNoKeyAndIsDownloadable(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	r := e.ok(t, "backup.create", api.BackupCreateArgs{Kind: "manual", Label: "before the audit (nov)"})
	res := result[api.BackupResult](t, r)
	files := readBackupFiles(t, e, res.BackupID)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"manifest.json", "vedette.db"}) {
		t.Fatalf("members = %v (no key file, no config)", names)
	}
	man, err := ops.ParseManifest(files["manifest.json"])
	if err != nil || man.IncludesSecrets || man.Version != 1 || man.DBSchema != "core=3,findings=2" || man.CreatedAt != "2026-11-09T12:00:00Z" {
		t.Fatalf("manifest = %+v %v", man, err)
	}
	if bytes.Contains(files["vedette.db"], []byte("0123456789abcdef0123456789abcdef")) {
		t.Error("the master key is inside the database copy")
	}
	if got := e.m.Notes(writeTemp(t, files["vedette.db"])); !slices.Equal(got, []string{"first"}) {
		t.Fatalf("notes in the copy = %v", got)
	}
	st, err := os.Stat(filepath.Join(e.m.State, "backups", res.BackupID+".tar.gz"))
	if err != nil || st.Mode().Perm() != 0o600 || st.Size() != res.Size {
		t.Fatalf("archive: %v %v", st, err)
	}
	// Listed, and downloadable: the bytes are the archive, the hash matches the result.
	bl, _ := e.h.Client.StateBackups(context.Background())
	if len(bl.Backups) != 1 {
		t.Fatalf("%+v", bl)
	}
	b := bl.Backups[0]
	if b.BackupID != res.BackupID || b.Kind != "manual" || b.Label != "before the audit (nov)" || b.Size != res.Size || b.SHA256 != res.SHA256 || b.Version != 1 ||
		b.DBSchema != "core=3,findings=2" || b.IncludesSecrets || !b.Downloadable || !b.CreatedAt.Equal(e.clock.Now()) {
		t.Fatalf("listing = %+v", b)
	}
	body, size, err := e.h.Client.DownloadBackup(context.Background(), res.BackupID)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(body)
	_ = body.Close()
	if sha(data) != res.SHA256 || int64(len(data)) != size || size != res.Size {
		t.Fatalf("download differs from the archive")
	}
	// Nothing was left over.
	if ents, _ := os.ReadDir(filepath.Join(e.m.State, "tmp")); len(ents) != 0 {
		t.Errorf("temp files left: %v", ents)
	}
	// core's directory is as it was: no -wal/-shm files owned by anyone else, mode of the db unchanged.
	if st, _ := os.Stat(e.m.CoreDBPath()); st.Mode().Perm() != 0o600 {
		t.Errorf("db mode = %o", st.Mode().Perm())
	}
}

func TestContract_Backup_SecretsAndPreKinds(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	// manual + include_secrets: carries the key, is not downloadable.
	withKey := result[api.BackupResult](t, e.ok(t, "backup.create", api.BackupCreateArgs{Kind: "manual", IncludeSecrets: true}))
	if f := readBackupFiles(t, e, withKey.BackupID); string(f["vedette.key"]) != "0123456789abcdef0123456789abcdef" {
		t.Errorf("key member = %q", f["vedette.key"])
	}
	if _, _, err := e.h.Client.DownloadBackup(context.Background(), withKey.BackupID); !client.IsCode(err, api.CodeContainsSecrets) {
		t.Fatalf("download with secrets: %v", err)
	}
	// pre_* kinds force secrets even when the client says false, and never download.
	for _, kind := range []string{"pre_update", "pre_os_update", "pre_restore"} {
		res := result[api.BackupResult](t, e.ok(t, "backup.create", api.BackupCreateArgs{Kind: kind, IncludeSecrets: false}))
		if f := readBackupFiles(t, e, res.BackupID); len(f["vedette.key"]) == 0 {
			t.Errorf("%s has no key", kind)
		}
		st, body := rawGet2(t, e, "/v1/backups/"+res.BackupID+"/content")
		if st != http.StatusForbidden || errCode(body) != api.CodeContainsSecrets {
			t.Errorf("%s: %d %s", kind, st, body)
		}
	}
	// What is recorded in the audit line for the forced kinds is what ran.
	last := audit(t, e.h)
	var forced bool
	for _, a := range last {
		if a.Command == "backup.create" && bytes.Contains(a.ArgsRedacted, []byte(`"kind":"pre_restore"`)) && bytes.Contains(a.ArgsRedacted, []byte(`"include_secrets":true`)) {
			forced = true
		}
	}
	if !forced {
		t.Error("the audit line does not show include_secrets=true for pre_restore")
	}
	// Unknown ids and hostile paths.
	for _, p := range []string{
		"/v1/backups/" + strings.Repeat("a", 32) + "/content", "/v1/backups/..%2f..%2fetc%2fpasswd/content", "/v1/backups/..%2f..%2fetc%2fpasswd%00/content",
		"/v1/backups/" + strings.Repeat("A", 32) + "/content", "/v1/backups/index/content", "/v1/backups/" + strings.Repeat("a", 33) + "/content",
	} {
		if st, _ := rawGet2(t, e, p); st != http.StatusNotFound {
			t.Errorf("GET %s: %d", p, st)
		}
	}
	if st, body := rawGet2(t, e, "/v1/backups/"+strings.Repeat("a", 32)+"/content"); errCode(body) != api.CodeBackupUnknown {
		t.Errorf("unknown id: %d %s", st, body)
	}
	// Exports are not backups and the other way round.
	if st, _ := rawGet2(t, e, "/v1/exports/"+withKey.BackupID+"/content"); st != http.StatusNotFound {
		t.Errorf("a backup id served as an export: %d", st)
	}
}

func rawGet2(t *testing.T, e *sysEnv, path string) (int, []byte) {
	t.Helper()
	st, b := rawGet(t, e.h, path)
	return st, b
}

func TestContract_Backup_Retention(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	var firstPre string
	for i := 0; i < 5; i++ {
		e.clock.Advance(time.Minute)
		res := result[api.BackupResult](t, e.ok(t, "backup.create", api.BackupCreateArgs{Kind: "pre_os_update"}))
		if i == 0 {
			firstPre = res.BackupID
		}
	}
	for i := 0; i < 12; i++ {
		e.clock.Advance(time.Minute)
		e.ok(t, "backup.create", api.BackupCreateArgs{Kind: "manual"})
	}
	bl, _ := e.h.Client.StateBackups(context.Background())
	pre, manual := 0, 0
	for _, b := range bl.Backups {
		if strings.HasPrefix(b.Kind, "pre_") {
			pre++
		} else {
			manual++
		}
	}
	if pre != 3 || manual != 10 {
		t.Fatalf("kept %d pre_* and %d manual", pre, manual)
	}
	if _, err := os.Stat(filepath.Join(e.m.State, "backups", firstPre+".tar.gz")); !errors.Is(err, os.ErrNotExist) {
		t.Error("the oldest pre_* archive is still on disk")
	}
	ents, _ := os.ReadDir(filepath.Join(e.m.State, "backups"))
	if len(ents) != 13+1 { // 13 archives and index.json
		t.Errorf("%d files in backups/", len(ents))
	}
	if !slices.IsSortedFunc(bl.Backups, func(a, b api.Backup) int { return b.CreatedAt.Compare(a.CreatedAt) }) {
		t.Error("the listing is not newest first")
	}
}

func TestContract_Backup_ConsistentWhileCoreWrites(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	db := e.m.OpenCoreDB()
	defer func() { _ = db.Close() }()
	// Enough data that the copy takes several steps, and the database really is in WAL mode.
	pad := strings.Repeat("x", 400)
	if _, err := db.Exec(`WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 30000) INSERT INTO note(body) SELECT 'bulk ' || i || ?1 FROM c`, pad); err != nil {
		t.Fatal(err)
	}
	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode = %q %v", mode, err)
	}
	before := len(e.m.Notes(""))
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var written atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := db.Exec(`INSERT INTO note(body) VALUES ('concurrent')`); err == nil {
				written.Add(1)
			}
		}
	}()
	res := result[api.BackupResult](t, e.ok(t, "backup.create", api.BackupCreateArgs{Kind: "manual"}))
	close(stop)
	wg.Wait()
	files := readBackupFiles(t, e, res.BackupID)
	notes := e.m.Notes(writeTemp(t, files["vedette.db"]))
	if len(notes) < before {
		t.Fatalf("the copy has %d rows, core had %d before the backup started", len(notes), before)
	}
	if written.Load() == 0 {
		t.Log("the writer made no progress during the backup (machine busy); the consistency check still ran")
	}
	// The copy is one self-contained, sound file.
	if len(files["vedette.db"]) < 1<<20 {
		t.Errorf("database copy is only %d bytes", len(files["vedette.db"]))
	}
	// core's live files are untouched: no root-owned sidecars, same owner as the database.
	liveInfo, _ := os.Stat(e.m.CoreDBPath())
	for _, suffix := range []string{"-wal", "-shm"} {
		if st, err := os.Stat(e.m.CoreDBPath() + suffix); err == nil && st.Mode().Perm() != liveInfo.Mode().Perm() {
			t.Errorf("%s has mode %o, the database %o", suffix, st.Mode().Perm(), liveInfo.Mode().Perm())
		}
	}
}

func TestContract_Backup_RefusalsAndHostileCore(t *testing.T) {
	t.Parallel()
	t.Run("core_data not configured", func(t *testing.T) {
		t.Parallel()
		e := startSys(t, func(c *ops.Config, _ *ops.Deps) { c.CoreData = "" })
		e.refused(t, "backup.create", api.BackupCreateArgs{Kind: "manual"}, http.StatusPreconditionFailed, "db_unreadable")
	})
	t.Run("database missing", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		_ = os.Remove(e.m.CoreDBPath())
		e.refused(t, "backup.create", api.BackupCreateArgs{Kind: "manual"}, http.StatusPreconditionFailed, "db_unreadable")
	})
	t.Run("the database is a symlink: it is not followed", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		secret := filepath.Join(t.TempDir(), "shadow")
		if err := os.WriteFile(secret, []byte("root:x:0:0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(e.m.CoreDBPath())
		if err := os.Symlink(secret, e.m.CoreDBPath()); err != nil {
			t.Fatal(err)
		}
		e.refused(t, "backup.create", api.BackupCreateArgs{Kind: "manual"}, http.StatusPreconditionFailed, "db_unreadable")
	})
	t.Run("the key is a symlink: a backup with secrets is refused", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		_ = os.Remove(filepath.Join(e.m.CoreData, "vedette.key"))
		if err := os.Symlink("/etc/hosts", filepath.Join(e.m.CoreData, "vedette.key")); err != nil {
			t.Fatal(err)
		}
		e.refused(t, "backup.create", api.BackupCreateArgs{Kind: "pre_update"}, http.StatusPreconditionFailed, "key_unreadable")
		e.ok(t, "backup.create", api.BackupCreateArgs{Kind: "manual"}) // without secrets the key is not needed
	})
	t.Run("the database is not a database", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		if err := os.WriteFile(e.m.CoreDBPath(), []byte(strings.Repeat("not sqlite ", 1000)), 0o600); err != nil {
			t.Fatal(err)
		}
		e.final(t, "backup.create", api.BackupCreateArgs{Kind: "manual"}, api.StatusRefused, "db_unreadable")
		bl, _ := e.h.Client.StateBackups(context.Background())
		if len(bl.Backups) != 0 {
			t.Errorf("a backup of a broken database was kept: %+v", bl)
		}
	})
	t.Run("less than twice the database free", func(t *testing.T) {
		t.Parallel()
		e := startSys(t, func(_ *ops.Config, d *ops.Deps) { d.FreeBytes = func(string) (uint64, error) { return 1, nil } })
		e.refused(t, "backup.create", api.BackupCreateArgs{Kind: "manual"}, http.StatusPreconditionFailed, "low_disk")
	})
}

// restoreRules makes the fake systemctl behave like a unit that stops, then starts healthy.
func (e *sysEnv) restoreRules() {
	e.m.Rule("systemctl", "stop", "", 0, "", "stopped")
	e.m.Rule("systemctl", "start", "", 0, "", "started")
	e.m.Rule("systemctl", "is-active", "active.txt", 0, "started", "")
	e.m.Rule("systemctl", "is-active", "inactive.txt", 3, "stopped", "")
	e.m.Rule("systemctl", "is-active", "active.txt", 0, "", "")
}

func systemctlVerbs(e *sysEnv) []string {
	var v []string
	for _, c := range e.m.Calls("systemctl") {
		v = append(v, c[0])
	}
	return v
}

func TestContract_Restore_RoundTripOnARealDatabase(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.restoreRules()
	keyPath := filepath.Join(e.m.CoreData, "vedette.key")
	b1 := result[api.BackupResult](t, e.ok(t, "backup.create", api.BackupCreateArgs{Kind: "manual", IncludeSecrets: true}))
	// Core moves on: more data, a new key, a stale WAL left next to the database.
	db := e.m.OpenCoreDB()
	for _, b := range []string{"second", "third"} {
		if _, err := db.Exec(`INSERT INTO note(body) VALUES (?1)`, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(keyPath, []byte("ffffffffffffffffffffffffffffffff"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if err := os.WriteFile(e.m.CoreDBPath()+"-wal", []byte("stale wal that must not survive"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := e.ok(t, "backup.restore", api.BackupRestoreArgs{BackupID: b1.BackupID})
	res := result[api.BackupRestoreResult](t, r)
	if res.RestoredBackupID != b1.BackupID || res.PreRestoreBackupID == "" || res.Version != 1 || len(res.Health) != 1 || !res.Health[0].OK {
		t.Fatalf("result = %+v", res)
	}
	// core is stopped and started, in that order, and nothing else of core's unit.
	verbs := systemctlVerbs(e)
	iStop, iStart := slices.Index(verbs, "stop"), slices.Index(verbs, "start")
	if iStop < 0 || iStart < iStop || slices.Contains(verbs, "reboot") || slices.Contains(verbs, "restart") {
		t.Fatalf("systemctl verbs = %v", verbs)
	}
	for _, c := range e.m.Calls("systemctl") {
		if c[0] != "is-active" && c[1] != "vedette-core.service" {
			t.Errorf("systemctl touched %q", c)
		}
	}
	// The database is the backup's, the key is the backup's, the stale WAL is gone, owner and mode are right.
	if got := e.m.Notes(""); !slices.Equal(got, []string{"first"}) {
		t.Fatalf("notes after restore = %v", got)
	}
	if k, _ := os.ReadFile(keyPath); string(k) != "0123456789abcdef0123456789abcdef" { //nolint:gosec // the test reads the fake core key
		t.Errorf("key after restore = %q", k)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(e.m.CoreDBPath() + suffix); err == nil {
			t.Errorf("a stale %s file survived the restore", suffix)
		}
	}
	for _, p := range []string{e.m.CoreDBPath(), keyPath} {
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o", p, st.Mode().Perm())
		}
	}
	if ents, _ := os.ReadDir(e.m.CoreData); len(ents) != 2 {
		t.Errorf("core data has %d entries: %v", len(ents), ents)
	}
	// The pre_restore backup holds the state from just before: the way back.
	pre := readBackupFiles(t, e, res.PreRestoreBackupID)
	if got := e.m.Notes(writeTemp(t, pre["vedette.db"])); !slices.Equal(got, []string{"first", "second", "third"}) {
		t.Errorf("pre_restore notes = %v", got)
	}
	if string(pre["vedette.key"]) != "ffffffffffffffffffffffffffffffff" {
		t.Errorf("pre_restore key = %q", pre["vedette.key"])
	}
	bl, _ := e.h.Client.StateBackups(context.Background())
	var kinds []string
	for _, b := range bl.Backups {
		kinds = append(kinds, b.Kind)
	}
	slices.Sort(kinds)
	if !slices.Equal(kinds, []string{"manual", "pre_restore"}) {
		t.Errorf("kinds = %v", kinds)
	}
	// No marker of a restore in progress is left behind.
	if _, err := os.Stat(filepath.Join(e.m.State, "restore.json")); err == nil {
		t.Error("restore.json still exists")
	}
}

func TestContract_Restore_UnhealthyCoreIsRevertedToTheStateBefore(t *testing.T) {
	t.Parallel()
	e := startSys(t, func(_ *ops.Config, d *ops.Deps) { d.CoreWait = 300 * time.Millisecond })
	// First start: core never becomes active. Second start (the put-back): healthy.
	e.m.Rule("systemctl", "stop", "", 0, "", "stopped")
	e.m.Rule("systemctl", "start", "", 0, "!firststart", "firststart")
	e.m.Rule("systemctl", "start", "", 0, "firststart", "secondstart")
	e.m.Rule("systemctl", "is-active", "active.txt", 0, "secondstart", "")
	e.m.Rule("systemctl", "is-active", "inactive.txt", 3, "firststart", "")
	e.m.Rule("systemctl", "is-active", "inactive.txt", 3, "stopped", "")
	e.m.Rule("systemctl", "is-active", "active.txt", 0, "", "")
	b1 := result[api.BackupResult](t, e.ok(t, "backup.create", api.BackupCreateArgs{Kind: "manual", IncludeSecrets: true}))
	db := e.m.OpenCoreDB()
	if _, err := db.Exec(`INSERT INTO note(body) VALUES ('later')`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if err := os.WriteFile(filepath.Join(e.m.CoreData, "vedette.key"), []byte("ffffffffffffffffffffffffffffffff"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := e.final(t, "backup.restore", api.BackupRestoreArgs{BackupID: b1.BackupID}, api.StatusReverted, "restore_health_failed")
	res := result[api.BackupRestoreResult](t, r)
	if res.PreRestoreBackupID == "" || len(res.Health) != 1 || res.Health[0].OK {
		t.Fatalf("result = %+v", res)
	}
	if got := e.m.Notes(""); !slices.Equal(got, []string{"first", "later"}) {
		t.Fatalf("after the revert the database has %v, want the state from before the restore", got)
	}
	if k, _ := os.ReadFile(filepath.Join(e.m.CoreData, "vedette.key")); string(k) != "ffffffffffffffffffffffffffffffff" {
		t.Errorf("key after revert = %q", k)
	}
	if v := systemctlVerbs(e); strings.Count(strings.Join(v, ","), "start") != 2 {
		t.Errorf("verbs = %v", v)
	}
	if audit := audit(t, e.h); audit[len(audit)-1].Result != "reverted" {
		t.Errorf("the last audit line is %+v, want result reverted", audit[len(audit)-1])
	}
}

func TestContract_Restore_RefusalsLeaveCoreAlone(t *testing.T) {
	t.Parallel()
	mk := func(t *testing.T) (*sysEnv, api.BackupResult) {
		e := startSys(t)
		e.restoreRules()
		return e, result[api.BackupResult](t, e.ok(t, "backup.create", api.BackupCreateArgs{Kind: "manual"}))
	}
	stopped := func(e *sysEnv) bool { return slices.Contains(systemctlVerbs(e), "stop") }
	t.Run("unknown backup", func(t *testing.T) {
		t.Parallel()
		e, _ := mk(t)
		e.refused(t, "backup.restore", api.BackupRestoreArgs{BackupID: strings.Repeat("a", 32)}, http.StatusNotFound, "backup_unknown")
		if stopped(e) {
			t.Error("core was stopped")
		}
	})
	t.Run("the archive changed on disk", func(t *testing.T) {
		t.Parallel()
		e, b := mk(t)
		p := filepath.Join(e.m.State, "backups", b.BackupID+".tar.gz")
		f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // the test corrupts an archive it created
		_, _ = f.Write([]byte("x"))
		_ = f.Close()
		e.final(t, "backup.restore", api.BackupRestoreArgs{BackupID: b.BackupID}, api.StatusRefused, "checksum_mismatch")
		if stopped(e) {
			t.Error("core was stopped")
		}
	})
	t.Run("an archive that is hostile but matches its checksum", func(t *testing.T) {
		t.Parallel()
		e, b := mk(t)
		// Replace the archive by one with a path-traversal member and fix the index to match, as an
		// attacker who could write the state directory would: the extractor still refuses it.
		evil := hostileArchive(t)
		p := filepath.Join(e.m.State, "backups", b.BackupID+".tar.gz")
		_ = os.WriteFile(p, evil, 0o600)
		idx := filepath.Join(e.m.State, "backups", "index.json")
		raw, _ := os.ReadFile(idx) //nolint:gosec // the test edits the index it just created
		var ix map[string]any
		_ = json.Unmarshal(raw, &ix)
		rec := ix["backups"].([]any)[0].(map[string]any)
		rec["sha256"], rec["size"] = sha(evil), len(evil)
		raw, _ = json.Marshal(ix)
		_ = os.WriteFile(idx, raw, 0o600)
		e.final(t, "backup.restore", api.BackupRestoreArgs{BackupID: b.BackupID}, api.StatusFailed, "restore_failed")
		if stopped(e) {
			t.Error("core was stopped for a hostile archive")
		}
		if _, err := os.Stat(filepath.Join(e.m.State, "evil")); err == nil {
			t.Error("a member was extracted outside the temp directory")
		}
	})
	t.Run("a backup from a newer schema", func(t *testing.T) {
		t.Parallel()
		e, b := mk(t)
		e.m.NewCoreDB(map[string]int{"core": 1, "findings": 1}, 2) // the running core is older than the backup
		e.final(t, "backup.restore", api.BackupRestoreArgs{BackupID: b.BackupID}, api.StatusRefused, "schema_newer")
		if stopped(e) {
			t.Error("core was stopped")
		}
	})
	t.Run("secrets in the database but no key anywhere", func(t *testing.T) {
		t.Parallel()
		e, b := mk(t)
		_ = os.Remove(filepath.Join(e.m.CoreData, "vedette.key"))
		e.final(t, "backup.restore", api.BackupRestoreArgs{BackupID: b.BackupID}, api.StatusRefused, "secrets_missing")
		if stopped(e) {
			t.Error("core was stopped")
		}
	})
	t.Run("a backup without a key restores onto the box's own key", func(t *testing.T) {
		t.Parallel()
		e, b := mk(t)
		if err := os.WriteFile(filepath.Join(e.m.CoreData, "vedette.key"), []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 0o600); err != nil {
			t.Fatal(err)
		}
		e.ok(t, "backup.restore", api.BackupRestoreArgs{BackupID: b.BackupID})
		if k, _ := os.ReadFile(filepath.Join(e.m.CoreData, "vedette.key")); string(k) != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
			t.Errorf("the box's key was replaced: %q", k)
		}
	})
	t.Run("low disk", func(t *testing.T) {
		t.Parallel()
		var low atomic.Bool
		e := startSys(t, func(_ *ops.Config, d *ops.Deps) {
			d.FreeBytes = func(string) (uint64, error) {
				if low.Load() {
					return 1, nil
				}
				return 100 << 30, nil
			}
		})
		e.restoreRules()
		b := result[api.BackupResult](t, e.ok(t, "backup.create", api.BackupCreateArgs{Kind: "manual"}))
		low.Store(true)
		e.refused(t, "backup.restore", api.BackupRestoreArgs{BackupID: b.BackupID}, http.StatusPreconditionFailed, "low_disk")
	})
}

func hostileArchive(t *testing.T) []byte {
	t.Helper()
	return buildTarGz(t, map[string]string{"manifest.json": `{"version":1,"db_schema":"core=1","created_at":"2026-11-09T12:00:00Z","includes_secrets":false}`, "../evil": "x"}, []string{"manifest.json", "../evil"})
}

func buildTarGz(t *testing.T, members map[string]string, order []string) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := newTar(&raw)
	for _, n := range order {
		tw.add(t, n, members[n])
	}
	tw.close()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	_, _ = zw.Write(raw.Bytes())
	_ = zw.Close()
	return out.Bytes()
}

// --- logs.export ----------------------------------------------------------------------------------

func gunzipLines(t *testing.T, b []byte) []string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

func TestContract_LogsExport_ArgvFilterAndDownload(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.m.Rule("journalctl", "-u vedette-core", "journal_core.jsonl", 0, "", "")
	e.m.Rule("journalctl", "-u vedette-sensor", "journal_sensor.jsonl", 0, "", "")
	args := api.LogsExportArgs{Units: []string{"vedette-sensor", "vedette-core", "vedette-core"}, Since: "2026-11-09T00:00:00Z", Until: "2026-11-09T05:59:30.5Z"} // a fraction of a second rounds the end up
	res := result[api.LogsExportResult](t, e.ok(t, "logs.export", args))
	want := [][]string{
		{"-u", "vedette-core", "--since", "2026-11-09 00:00:00 UTC", "--until", "2026-11-09 05:59:31 UTC", "-o", "json", "--no-pager"},
		{"-u", "vedette-sensor", "--since", "2026-11-09 00:00:00 UTC", "--until", "2026-11-09 05:59:31 UTC", "-o", "json", "--no-pager"},
	}
	if got := e.m.Calls("journalctl"); !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("journalctl argv:\n got %q\nwant %q", got, want)
	}
	assertEnvClean(t, e.m.Envs("journalctl"))
	body, size, err := e.h.Client.DownloadExport(context.Background(), res.ExportID)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(body)
	_ = body.Close()
	if sha(data) != res.SHA256 || int64(len(data)) != size || size != res.Size {
		t.Fatal("download differs from the result")
	}
	lines := gunzipLines(t, data)
	if len(lines) != res.Lines || len(lines) != 9 {
		t.Fatalf("%d lines, result says %d", len(lines), res.Lines)
	}
	all := strings.Join(lines, "\n")
	for _, secret := range []string{"vdt_osquery_aB3dE5gH7jK9mN1pQ3sU5wY", "Zk3Jh8Pq9Rt2Vw5Xy7", "abcdef0123456789abcdef", "hunter2", "xoxb-1234567890", "xapp-1-A0123"} {
		if strings.Contains(all, secret) {
			t.Errorf("secret %q is in the export", secret)
		}
	}
	for _, l := range lines {
		if !json.Valid([]byte(l)) {
			t.Errorf("not JSON: %q", l)
		}
	}
	if !strings.Contains(all, "listening on :8443") || !strings.Contains(all, "heartbeat ok") || !strings.Contains(all, "[redacted]") {
		t.Errorf("the export lost its content or shows no redaction:\n%s", all)
	}
	if st, _ := rawGet(t, e.h, "/v1/exports/"+res.ExportID+"/content"); st != http.StatusOK {
		t.Errorf("a second download: %d", st)
	}
	st, body2 := rawGet2(t, e, "/v1/exports/"+strings.Repeat("b", 32)+"/content")
	if st != http.StatusNotFound || errCode(body2) != api.CodeExportUnknown {
		t.Errorf("unknown export: %d %s", st, body2)
	}
	if st, _ := rawGet2(t, e, "/v1/exports/..%2f..%2fetc%2fpasswd/content"); st != http.StatusNotFound {
		t.Errorf("traversal: %d", st)
	}
}

func TestContract_LogsExport_Refusals(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.m.Rule("journalctl", "-u", "journal_sensor.jsonl", 0, "", "")
	ok := func(units ...string) api.LogsExportArgs {
		return api.LogsExportArgs{Units: units, Since: "2026-10-01T00:00:00Z", Until: "2026-10-31T00:00:00Z"}
	}
	e.refused(t, "logs.export", ok("vedette-evil"), http.StatusPreconditionFailed, "unit_unknown")
	e.refused(t, "logs.export", ok("vedette-core", "ssh"), http.StatusPreconditionFailed, "unit_unknown")
	e.refused(t, "logs.export", api.LogsExportArgs{Units: []string{"vedette-core"}, Since: "2026-10-01T00:00:00Z", Until: "2026-11-02T00:00:01Z"}, http.StatusPreconditionFailed, "range_too_large")
	if len(e.m.Calls("journalctl")) != 0 {
		t.Fatal("journalctl ran for a refused request")
	}
	// Exactly 31 days is allowed.
	e.ok(t, "logs.export", api.LogsExportArgs{Units: []string{"vedette-core"}, Since: "2026-10-01T00:00:00Z", Until: "2026-11-01T00:00:00Z"})
}

func TestContract_LogsExport_TooLargeStopsAndNeverCuts(t *testing.T) {
	t.Parallel()
	t.Run("one unit over the limit", func(t *testing.T) {
		t.Parallel()
		e := startSys(t, func(_ *ops.Config, d *ops.Deps) { d.ExportLimit = 300 })
		e.m.Rule("journalctl", "-u", "journal_core.jsonl", 0, "", "")
		e.final(t, "logs.export", api.LogsExportArgs{Units: []string{"vedette-core"}, Since: "2026-11-09T00:00:00Z", Until: "2026-11-09T01:00:00Z"}, api.StatusRefused, "output_too_large")
		if ents, _ := os.ReadDir(filepath.Join(e.m.State, "exports")); len(ents) > 1 {
			t.Errorf("an export file was kept: %v", ents)
		}
	})
	t.Run("two units that together pass the limit", func(t *testing.T) {
		t.Parallel()
		e := startSys(t, func(_ *ops.Config, d *ops.Deps) { d.ExportLimit = 200 })
		e.m.Rule("journalctl", "-u", "journal_sensor.jsonl", 0, "", "")
		e.final(t, "logs.export", api.LogsExportArgs{Units: []string{"vedette-core", "vedette-sensor"}, Since: "2026-11-09T00:00:00Z", Until: "2026-11-09T01:00:00Z"}, api.StatusRefused, "output_too_large")
	})
	t.Run("journalctl fails", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.m.Rule("journalctl", "-u", "", 1, "", "")
		e.final(t, "logs.export", api.LogsExportArgs{Units: []string{"vedette-core"}, Since: "2026-11-09T00:00:00Z", Until: "2026-11-09T01:00:00Z"}, api.StatusFailed, "journal_failed")
	})
}

func TestContract_LogsExport_FilesAreDeletedAfter24Hours(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.o.Start(context.Background(), e.h.Server)
	e.m.Rule("journalctl", "-u", "journal_sensor.jsonl", 0, "", "")
	res := result[api.LogsExportResult](t, e.ok(t, "logs.export", api.LogsExportArgs{Units: []string{"vedette-sensor"}, Since: "2026-11-09T00:00:00Z", Until: "2026-11-09T01:00:00Z"}))
	file := filepath.Join(e.m.State, "exports", res.ExportID+".jsonl.gz")
	if _, err := os.Stat(file); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(23*time.Hour + 59*time.Minute)
	if st, _ := rawGet2(t, e, "/v1/exports/"+res.ExportID+"/content"); st != http.StatusOK {
		t.Fatalf("before 24 hours: %d", st)
	}
	e.clock.Advance(2 * time.Minute)
	// The hourly sweep removes it even if nobody asks.
	sw := e.timers.sweeps()
	if len(sw) == 0 {
		t.Fatal("no sweep timer armed")
	}
	sw[len(sw)-1].fire()
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the export file is still there after 24 hours")
	}
	if st, body := rawGet2(t, e, "/v1/exports/"+res.ExportID+"/content"); st != http.StatusNotFound || errCode(body) != api.CodeExportUnknown {
		t.Errorf("after 24 hours: %d %s", st, body)
	}
}

// --- audit and the source rules -------------------------------------------------------------------

func TestContract_INV12_SystemCommandsAreAuditedWithoutSecrets(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.rules()
	e.ok(t, "os.check", nil)
	e.refused(t, "os.install", map[string]string{"scope": "; id"}, http.StatusBadRequest, "invalid_args")
	e.ok(t, "backup.create", api.BackupCreateArgs{Kind: "manual", Label: "vdt_osquery_0123456789abcdef"})
	recs := audit(t, e.h)
	var checkLines, createLines int
	for _, a := range recs {
		switch a.Command {
		case "os.check":
			checkLines++
			if a.Peer.UID != 10001 || a.Actor != "admin@example.com" || a.ArgsDigest == "" {
				t.Errorf("incomplete: %+v", a)
			}
		case "backup.create":
			createLines++
		}
	}
	if checkLines != 2 || createLines != 2 { // accepted + result each
		t.Errorf("os.check %d lines, backup.create %d lines", checkLines, createLines)
	}
	data, _ := os.ReadFile(e.h.AuditPath)
	if bytes.Contains(data, []byte("vdt_osquery_0123456789abcdef")) {
		t.Error("a token in a label reached the audit file")
	}
}

func TestContract_FORBID_ReleaseUpgradesAndSourcesAreOutOfReach(t *testing.T) {
	t.Parallel()
	banned := []string{"do-release-upgrade", "sources.list", "sources.list.d", "full-upgrade", "autoremove", "--allow-unauthenticated", "/etc/apt/trusted.gpg", "do_release_upgrade"}
	for path, f := range hostSources(t) {
		if strings.Contains(path, "/opstest/") {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if l, ok := n.(*ast.BasicLit); ok && l.Kind == token.STRING {
				for _, b := range banned {
					if strings.Contains(l.Value, b) {
						t.Errorf("%s contains %q", path, b)
					}
				}
			}
			return true
		})
	}
	// The apt validator itself: dist-upgrade only as a simulation, installs only upgrade-only of valid names.
	good := slices.Concat(installPre, []string{"openssl", "libc6", "libfoo:amd64"})
	if err := ops.ValidateApt(good); err != nil {
		t.Fatalf("the fixed install argv is rejected: %v", err)
	}
	for _, args := range [][]string{
		{"dist-upgrade"}, {"-y", "dist-upgrade"}, {"-q", "-s", "dist-upgrade"}, {"full-upgrade"}, {"-q", "update", "--allow-unauthenticated"},
		{"install", "openssl"}, {"-y", "install", "openssl"}, {"-y", "remove", "x"}, {"-y", "purge", "x"}, {"autoremove"}, {"source", "x"},
		slices.Concat(installPre, []string{"-oAPT::Get::AllowUnauthenticated=1"}), slices.Concat(installPre, []string{"../x"}), slices.Concat(installPre, []string{"a b"}),
		slices.Concat(installPre, []string{"Upper"}), slices.Concat(installPre, []string{"x;y"}), slices.Concat(installPre, []string{"--reinstall"}),
		slices.Concat(installPre, []string{"x", "--allow-downgrades"}), slices.Concat(installPre, []string{""}),
		append(slices.Clone(installPre[:len(installPre)-1]), "install"), {"-q", "update", "extra"}, {},
		slices.Concat([]string{"-o", "Dir::Etc::sourcelist=/tmp/x"}, argvUpdate),
	} {
		if err := ops.ValidateApt(args); err == nil {
			t.Errorf("accepted apt argv %q", args)
		}
	}
	if err := ops.ValidateApt(slices.Concat(installPre, make([]string, 3001))); err == nil {
		t.Error("accepted 3001 empty names")
	}
	// systemctl: only the fixed verbs on fixed units.
	vs := ops.ValidateSystemctl("vedette-core.service")
	for _, args := range [][]string{{"reboot"}, {"stop", "vedette-core.service"}, {"start", "vedette-core.service"}, {"is-active", "vedette-core.service"},
		{"enable", "--now", "apt-daily.timer", "apt-daily-upgrade.timer"}, {"disable", "--now", "apt-daily.timer", "apt-daily-upgrade.timer"}, {"is-enabled", "apt-daily.timer"}} {
		if err := vs(args); err != nil {
			t.Errorf("rejected %q: %v", args, err)
		}
	}
	for _, args := range [][]string{{"poweroff"}, {"halt"}, {"stop", "sshd.service"}, {"stop", "vedette-sensor.service"}, {"disable", "vedette-core.service"}, {"mask", "vedette-core.service"},
		{"reboot", "--force"}, {"start", "vedette-core.service", "x"}, {"enable", "--now", "ssh.service"}, {"is-enabled", "ssh.service"}, {"daemon-reload"}, {"kill", "vedette-core.service"}, {}} {
		if err := vs(args); err == nil {
			t.Errorf("accepted systemctl %q", args)
		}
	}
	// journalctl: only the fixed form on the six units.
	jt := "2026-11-09 00:00:00 UTC"
	okJ := []string{"-u", "vedette-core", "--since", jt, "--until", jt, "-o", "json", "--no-pager"}
	if err := ops.ValidateJournal(okJ); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]string) []string{
		func(a []string) []string { a[1] = "ssh"; return a }, func(a []string) []string { a[1] = "../x"; return a },
		func(a []string) []string { a[3] = "yesterday"; return a }, func(a []string) []string { a[7] = "export"; return a },
		func(a []string) []string { return append(a, "-f") }, func(a []string) []string { a[0] = "--file"; return a },
		func(a []string) []string { return a[:8] },
	} {
		if err := ops.ValidateJournal(mutate(slices.Clone(okJ))); err == nil {
			t.Errorf("accepted journalctl argv")
		}
	}
}

func TestContract_FORBID_ProductionWiringNeverUsesTheTestSeams(t *testing.T) {
	t.Parallel()
	for path, f := range hostSources(t) {
		isOps := strings.Contains(path, "/host/ops/") && !strings.Contains(path, "/opstest/")
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if x.Sel.Name == "NewWithDeps" && !isOps && !strings.Contains(path, "/opstest/") {
					t.Errorf("%s uses ops.NewWithDeps, a test seam", path)
				}
			case *ast.ImportSpec:
				if strings.HasSuffix(x.Path.Value, `/opstest"`) && !strings.Contains(path, "/opstest/") {
					t.Errorf("%s imports test support", path)
				}
			}
			return true
		})
	}
}

// tarBuilder writes hostile or odd tar members that ops.WriteArchive refuses to produce.
type tarBuilder struct{ tw *tar.Writer }

func newTar(w io.Writer) *tarBuilder { return &tarBuilder{tw: tar.NewWriter(w)} }

func (b *tarBuilder) add(t *testing.T, name, data string) {
	t.Helper()
	if err := b.tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.tw.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
}

func (b *tarBuilder) close() { _ = b.tw.Close() }
