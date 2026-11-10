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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/peer"
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
	body := fmt.Sprintf("core_uid = 10001\ncore_gid = 10001\ncore_unit = vedette-core.service\nsocket = %s\nsocket_gid = %d\n", socket, os.Getgid())
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
	deadline := time.After(10 * time.Second)
	for {
		info, err := c.Info(context.Background())
		if err == nil {
			want := []string{"backup.create", "backup.restore", "decoy_ip.add", "decoy_ip.remove", "logs.export", "net.apply", "net.confirm", "net.revert", "os.auto_security.set", "os.check", "os.install", "os.reboot", "os.reboot.cancel"}
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
			break
		}
		if !errors.Is(err, client.ErrUnreachable) {
			t.Fatal(err)
		}
		select {
		case <-deadline:
			t.Fatalf("the server never came up: %v", err)
		case e := <-done:
			t.Fatalf("run returned early: %v", e)
		case <-time.After(10 * time.Millisecond):
		}
	}
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
