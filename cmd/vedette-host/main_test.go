package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/peer"
	"github.com/knt048/vedette/host/server"
)

func testEnv(t *testing.T) (environment, *[2]any) {
	t.Helper()
	seen := new([2]any)
	return environment{
		goos: "linux", euid: 0, configOwner: os.Getuid(),
		newChecker: func(uid int, unit, _ string) (peer.Checker, error) {
			seen[0], seen[1] = uid, unit
			return func(net.Conn) (peer.Info, error) { return peer.Info{UID: uid, PID: 1, Unit: unit}, nil }, nil
		},
		logger: slog.New(slog.DiscardHandler),
	}, seen
}

func writeConf(t *testing.T, dir, socket string) string {
	t.Helper()
	p := filepath.Join(dir, "host.conf")
	body := fmt.Sprintf("core_uid = 10001\ncore_gid = %d\nsensor_uid = 10002\nsensor_gid = 10002\ncore_unit = vedette-core.service\nsocket = %s\nsocket_gid = %d\n", os.Getgid(), socket, os.Getgid())
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVersion(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	// -version needs neither root nor Linux.
	env := environment{goos: "darwin", euid: 1000}
	if err := run(context.Background(), []string{"-version"}, &out, env); err != nil || out.String() != "dev\n" {
		t.Fatalf("out %q err %v", out.String(), err)
	}
}

func TestRefusesToStart(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "vm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	conf := writeConf(t, dir, filepath.Join(dir, "r", "h.sock"))
	good, _ := testEnv(t)
	tests := []struct {
		name string
		args []string
		mod  func(*environment)
		want string
	}{
		{"not linux", nil, func(e *environment) { e.goos = "darwin" }, "only on Linux"},
		{"windows", nil, func(e *environment) { e.goos = "windows" }, "only on Linux"},
		{"not root", nil, func(e *environment) { e.euid = 1000 }, "as root"},
		{"missing config", []string{"-config", filepath.Join(dir, "nope")}, nil, "no such file"},
		{"unknown flag", []string{"-nope"}, nil, "flag provided but not defined"},
		{"stray argument", []string{"-config", conf, "extra"}, nil, "unexpected argument"},
		{"bad socket flag", []string{"-config", conf, "-socket", "relative.sock"}, nil, "absolute"},
		{"checker unavailable", []string{"-config", conf}, func(e *environment) {
			e.newChecker = func(int, string, string) (peer.Checker, error) { return nil, peer.ErrUnsupportedOS }
		}, "unsupported operating system"},
		{"config writable by others", []string{"-config", writeOpen(t, dir)}, nil, "writable by group or others"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := good
			if tt.mod != nil {
				tt.mod(&env)
			}
			args := tt.args
			if args == nil {
				args = []string{"-config", conf}
			}
			err := run(context.Background(), args, io.Discard, env)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func writeOpen(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "open.conf")
	if err := os.WriteFile(p, []byte("x"), 0o666); err != nil { //nolint:gosec // the test needs a group/world-writable file
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil { //nolint:gosec // the test needs a group/world-writable file
		t.Fatal(err)
	}
	return p
}

func TestServesAndStopsOnSignal(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		// run builds the real Ops, whose Start would create the real namespace vedette-hp on this machine.
		t.Skip("not as root on Linux: Start would make a real network namespace")
	}
	dir, err := os.MkdirTemp("", "vm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "r", "h.sock")
	conf := writeConf(t, dir, filepath.Join(dir, "ignored.sock"))
	env, seen := testEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-config", conf, "-socket", sock, "-state-dir", filepath.Join(dir, "state"), "-audit-log", filepath.Join(dir, "log", "audit.jsonl")}, io.Discard, env)
	}()
	c := client.New(sock)
	defer c.Close()
	// The server is up once its socket has mode 0660: secureSocket sets it after listen(2), so a connection from then on
	// is queued until Serve accepts it. Wait on that state (at most 30 s, D-373), then ask once.
	end := time.Now().Add(30 * time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if st, err := os.Lstat(sock); err == nil && st.Mode().Type() == os.ModeSocket && st.Mode().Perm() == 0o660 {
			break
		}
		select {
		case e := <-done:
			t.Fatalf("run returned early: %v", e)
		default:
		}
		if time.Now().After(end) {
			t.Fatal("the server never came up")
		}
		<-tick.C
	}
	info, err := c.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"backup.create", "backup.purge", "backup.restore", "container.pull", "container.rollback", "container.start", "container.stop", "decoy_ip.add", "decoy_ip.remove", "decoy_ip.set_ports", "host.self_update", "logs.export", "net.apply", "net.confirm", "net.revert", "os.auto_security.set", "os.check", "os.install", "os.reboot", "os.reboot.cancel"}
	if info.Proto != 1 || info.HostVersion != "dev" || !slices.Equal(info.Commands, want) {
		t.Fatalf("info = %+v", info)
	}
	// The state endpoints of the system commands are wired, and the state directory holds their directories.
	if bl, err := c.StateBackups(context.Background()); err != nil || len(bl.Backups) != 0 {
		t.Fatalf("state/backups: %+v %v", bl, err)
	}
	if _, err := c.StateOS(context.Background()); !client.IsCode(err, "no_check_yet") {
		t.Fatalf("state/os before a check: %v", err)
	}
	for _, d := range []string{"os", "backups", "exports"} {
		if st, err := os.Stat(filepath.Join(dir, "state", d)); err != nil || st.Mode().Perm() != 0o700 {
			t.Fatalf("state/%s: %v %v", d, st, err)
		}
	}
	// The daemon holds the state lock: a bootstrap (or a second daemon) on the same directory cannot take it (D-142).
	other, err := ops.New(ops.Config{StateDir: filepath.Join(dir, "state"), CoreUnit: "vedette-core.service", OwnerUID: os.Getuid(), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.LockState(context.Background()); !errors.Is(err, ops.ErrStateLocked) {
		t.Fatalf("the daemon does not hold the state lock: %v", err)
	}
	other.Close()
	if seen[0] != 10001 || seen[1] != "vedette-core.service" {
		t.Fatalf("checker built with %v", *seen)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("clean stop returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not stop after the signal")
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket file left behind: %v", err)
	}
}

func bootArgs(conf, sock string, more ...string) []string {
	return append([]string{"-config", conf, "-socket", sock, "-bootstrap", "-index", "/x/i", "-index-sig", "/x/is", "-manifest", "/x/m", "-manifest-sig", "/x/ms"}, more...)
}

// vedette-host -bootstrap (D-142): one shot, never beside a running daemon, flags that belong to it only with it.
func TestBootstrapRefusesWhileTheDaemonRuns(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "vm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "h.sock")
	conf := writeConf(t, dir, sock)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	env, _ := testEnv(t)
	err = run(context.Background(), bootArgs(conf, sock), io.Discard, env)
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != exitDaemonRunning || !strings.HasPrefix(ee.line, "vedette-host: bootstrap: daemon_running: ") || strings.Contains(ee.line, "\n") {
		t.Fatalf("err = %v", err)
	}
	// A socket nobody listens on (a stale file) is not a running daemon: the next refusal is about the documents.
	_ = ln.Close()
	err = run(context.Background(), bootArgs(conf, sock), io.Discard, env)
	if !errors.As(err, &ee) || ee.code != exitUsage || !strings.Contains(ee.line, "-index") {
		t.Fatalf("after the daemon stopped: %v", err)
	}
}

func TestBootstrapFlagsAndFiles(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "vm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "h.sock")
	conf := writeConf(t, dir, sock)
	env, _ := testEnv(t)
	// The bootstrap flags without -bootstrap would start the daemon: refused.
	for _, f := range [][]string{{"-index", "x"}, {"-index-sig", "x"}, {"-manifest", "x"}, {"-manifest-sig", "x"}, {"-services", "core"}, {"-force-units"}} {
		err := run(context.Background(), append([]string{"-config", conf, "-socket", sock}, f...), io.Discard, env)
		if err == nil || !strings.Contains(err.Error(), "belong to -bootstrap") {
			t.Errorf("%v: %v", f, err)
		}
	}
	// -bootstrap needs all four documents; each must be a regular file.
	var ee *exitError
	err = run(context.Background(), []string{"-config", conf, "-socket", sock, "-bootstrap", "-index", "x"}, io.Discard, env)
	if !errors.As(err, &ee) || ee.code != exitUsage {
		t.Fatalf("missing flags: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(filepath.Join(dir, "real"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "real"), link); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{"missing": filepath.Join(dir, "nope"), "link": link, "directory": dir} {
		a := []string{"-config", conf, "-socket", sock, "-bootstrap", "-index", p, "-index-sig", p, "-manifest", p, "-manifest-sig", p}
		if err := run(context.Background(), a, io.Discard, env); !errors.As(err, &ee) || ee.code != exitUsage || !strings.Contains(ee.line, "-index") {
			t.Errorf("%s: %v", name, err)
		}
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, 300<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	a := []string{"-config", conf, "-socket", sock, "-bootstrap", "-index", big, "-index-sig", big, "-manifest", big, "-manifest-sig", big}
	if err := run(context.Background(), a, io.Discard, env); !errors.As(err, &ee) || ee.code != exitUsage {
		t.Errorf("over the limit: %v", err)
	}
}

func TestBootstrapExitCodes(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		err  error
		code int
		word string
	}{
		{&ops.BootstrapError{Code: ops.BootstrapAlreadyInstalled, Message: "core already runs 1.0.0"}, exitAlreadyInstalled, "already_installed"},
		{&ops.BootstrapError{Code: ops.BootstrapUnitForeign, Message: "x"}, exitUnit, "unit_foreign"},
		{&ops.BootstrapError{Code: "unit_unsafe", Message: "x"}, exitUnit, "unit_unsafe"},
		{&ops.BootstrapError{Code: ops.BootstrapBadArgs, Message: "x"}, exitUsage, "invalid_args"},
		{&ops.BootstrapError{Code: ops.BootstrapFailed, Message: "x"}, exitFailed, "bootstrap_failed"},
		{server.Refuse(412, "signature_invalid", "The manifest\ndoes not verify."), exitRefused, "signature_invalid"},
		{server.Refuse(412, "not_appliance", "x"), exitRefused, "not_appliance"},
		{&ops.BootstrapError{Code: "core_data_invalid", Message: "x"}, exitRefused, "core_data_invalid"},
		{&ops.BootstrapError{Code: ops.BootstrapMixedVersions, Message: "x"}, exitRefused, "mixed_versions"},
		{&ops.BootstrapError{Code: "unit_unwritable", Message: "x"}, exitFailed, "unit_unwritable"},
		{&ops.BootstrapError{Code: ops.BootstrapDaemonRunning, Message: "x"}, exitDaemonRunning, "daemon_running"},
		{&server.Failure{Code: "pull_failed", Message: "Podman could not pull the image."}, exitFailed, "pull_failed"},
		{errors.New("secret detail"), exitFailed, "bootstrap_failed"},
	} {
		ee := exitFor(c.err)
		if ee.code != c.code || !strings.HasPrefix(ee.line, "vedette-host: bootstrap: "+c.word+": ") || strings.Contains(ee.line, "\n") || strings.Contains(ee.line, "secret") {
			t.Errorf("%v: %d %q", c.err, ee.code, ee.line)
		}
	}
}
