package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVersionAndFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		args    []string
		wantOut string
		wantErr bool
	}{
		{name: "version", args: []string{"-version"}, wantOut: "dev\n"},
		{name: "unknown flag", args: []string{"-nope"}, wantErr: true},
		{name: "stray argument", args: []string{"serve"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			err := run(t.Context(), tt.args, &out, io.Discard)
			if (err != nil) != tt.wantErr {
				t.Fatalf("run(%q) error = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
			if tt.wantOut != "" && out.String() != tt.wantOut {
				t.Fatalf("run(%q) output = %q, want %q", tt.args, out.String(), tt.wantOut)
			}
			if tt.wantErr && strings.Contains(out.String(), "dev\n") {
				t.Fatalf("run(%q) printed the version on error", tt.args)
			}
		})
	}
}

type instance struct {
	addr   string
	cancel context.CancelFunc
	done   chan error
	db     string
	key    string
}

// start runs the process on a free port with a temp database and returns once it logs "listening".
func start(t *testing.T) *instance {
	t.Helper()
	dir := t.TempDir()
	in := &instance{db: filepath.Join(dir, "v.db"), key: filepath.Join(dir, "v.key"), done: make(chan error, 1)}
	var ctx context.Context
	ctx, in.cancel = context.WithCancel(t.Context())
	t.Cleanup(in.cancel)
	pr, pw := io.Pipe()
	go func() {
		in.done <- run(ctx, []string{"-db", in.db, "-key", in.key, "-listen", "127.0.0.1:0"}, io.Discard, pw)
		_ = pw.Close()
	}()
	sc := bufio.NewScanner(pr)
	for sc.Scan() {
		var line struct {
			Msg  string `json:"msg"`
			Addr string `json:"addr"`
		}
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatalf("log line is not JSON: %q", sc.Text())
		}
		if line.Msg == "listening" {
			in.addr = line.Addr
			go func() { _, _ = io.Copy(io.Discard, pr) }() // keep the pipe drained so logging never blocks
			return in
		}
	}
	t.Fatalf("run ended before listening: %v", <-in.done)
	return nil
}

func (in *instance) get(t *testing.T, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+in.addr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestRunServesAndStops(t *testing.T) {
	t.Parallel()
	in := start(t)

	// The whole chain answers: security headers, route table, module gate, auth hook, error format.
	if code, body := in.get(t, "/api/v1/modules"); code != 401 || !strings.Contains(body, `"code":"unauthenticated"`) {
		t.Fatalf("GET /modules without a session = %d %s", code, body)
	}
	if code, body := in.get(t, "/api/v1/setup"); code != 501 || !strings.Contains(body, `"code":"not_implemented"`) {
		t.Fatalf("GET /setup (public, not built yet) = %d %s", code, body)
	}
	if code, body := in.get(t, "/api/v1/nowhere"); code != 404 || !strings.Contains(body, `"code":"not_found"`) {
		t.Fatalf("unknown route = %d %s", code, body)
	}
	if code, _ := in.get(t, "/somewhere-else"); code != 404 {
		t.Fatalf("path outside the API = %d", code)
	}
	// Ships as code: the files exist with the right mode, and the migration ran.
	for _, p := range []string{in.db, in.key} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s: %v mode %v", p, err, info)
		}
	}

	in.cancel()
	select {
	case err := <-in.done:
		if err != nil {
			t.Fatalf("run returned %v after cancel", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not stop after the context was cancelled")
	}
	// The port is free again, and the database is closed cleanly (a second start works on the same files).
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", in.addr)
	if err != nil {
		t.Fatalf("port still held after shutdown: %v", err)
	}
	_ = ln.Close()
}

// A restart on the same files keeps working: migrations, seeding and the key are idempotent.
func TestRunTwiceOnTheSameFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for range 2 {
		ctx, cancel := context.WithCancel(t.Context())
		pr, pw := io.Pipe()
		done := make(chan error, 1)
		go func() {
			done <- run(ctx, []string{"-db", filepath.Join(dir, "v.db"), "-key", filepath.Join(dir, "v.key"), "-listen", "127.0.0.1:0"}, io.Discard, pw)
			_ = pw.Close()
		}()
		sc := bufio.NewScanner(pr)
		listening := false
		for sc.Scan() {
			if strings.Contains(sc.Text(), `"msg":"listening"`) {
				listening = true
				break
			}
		}
		cancel()
		go func() { _, _ = io.Copy(io.Discard, pr) }()
		if err := <-done; err != nil || !listening {
			t.Fatalf("run: %v (listening=%v)", err, listening)
		}
	}
}

func TestRunRefusesBadSetup(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := func() []string {
		return []string{"-db", filepath.Join(dir, "ok.db"), "-key", filepath.Join(dir, "ok.key"), "-listen", "127.0.0.1:0"}
	}
	t.Run("database directory missing", func(t *testing.T) {
		t.Parallel()
		err := run(t.Context(), []string{"-db", filepath.Join(dir, "nope", "v.db"), "-key", filepath.Join(dir, "k1"), "-listen", "127.0.0.1:0"}, io.Discard, io.Discard)
		if err == nil {
			t.Fatal("run succeeded")
		}
	})
	t.Run("key file with wrong mode", func(t *testing.T) {
		t.Parallel()
		key := filepath.Join(dir, "loose.key")
		if err := os.WriteFile(key, make([]byte, 32), 0o644); err != nil { //nolint:gosec // the test needs a loose file to prove it is refused
			t.Fatal(err)
		}
		err := run(t.Context(), []string{"-db", filepath.Join(dir, "k2.db"), "-key", key, "-listen", "127.0.0.1:0"}, io.Discard, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "mode") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("address in use", func(t *testing.T) {
		t.Parallel()
		ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		args := good()
		args[1] = filepath.Join(dir, "busy.db")
		args[3] = filepath.Join(dir, "busy.key")
		args[5] = ln.Addr().String()
		if err := run(t.Context(), args, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "listen") {
			t.Fatalf("err = %v", err)
		}
	})
}
