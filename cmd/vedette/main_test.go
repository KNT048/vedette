package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/jobs"
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
	if code, body := in.get(t, "/api/v1/setup"); code != 200 || !strings.Contains(body, `"complete":false`) {
		t.Fatalf("GET /setup (public, before first-run setup) = %d %s", code, body)
	}
	if code, body := in.get(t, "/api/v1/core/updates"); code != 401 || !strings.Contains(body, `"code":"unauthenticated"`) {
		t.Fatalf("GET /core/updates (not built, needs a session) = %d %s", code, body)
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

func TestIsLoopback(t *testing.T) {
	t.Parallel()
	for addr, want := range map[string]bool{
		"127.0.0.1:8080": true, "127.1.2.3:0": true, "[::1]:8080": true, "localhost:8080": true, "LOCALHOST:1": true,
		"[::ffff:127.0.0.1]:80": true,
		"0.0.0.0:8080":          false, "[::]:8080": false, ":8080": false, "192.168.1.10:8080": false,
		"10.0.0.1:80": false, "example.com:80": false, "127.0.0.1.example.com:80": false,
	} {
		got, err := isLoopback(addr)
		if err != nil || got != want {
			t.Errorf("isLoopback(%q) = %v, %v; want %v", addr, got, err, want)
		}
	}
	for _, bad := range []string{"8080", ""} {
		if _, err := isLoopback(bad); err == nil {
			t.Errorf("isLoopback(%q) accepted an address with no port", bad)
		}
	}
}

func TestRunRefusesHalfATLSPairAndBadHosts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := []string{"-db", filepath.Join(dir, "v.db"), "-key", filepath.Join(dir, "v.key"), "-listen", "127.0.0.1:0"}
	for name, extra := range map[string][]string{
		"cert only":    {"-tls-cert", "x.crt"},
		"key only":     {"-tls-key", "x.key"},
		"bad hosts":    {"-hosts", "ok.example,bad host!"},
		"hosts scheme": {"-hosts", "https://box.example"},
	} {
		if err := run(t.Context(), append(slices.Clone(base), extra...), io.Discard, io.Discard); err == nil {
			t.Errorf("%s: run succeeded", name)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "v.key")); err == nil {
		t.Error("the key file was created before the flags were refused")
	}
}

// failingListener makes srv.Serve return at once.
type failingListener struct{ net.Listener }

func (failingListener) Accept() (net.Conn, error) { return nil, errors.New("accept failed on purpose") }

type allOn struct{}

func (allOn) Enabled(string) bool { return true }

// The listener failing must not leave run waiting for a scheduler nobody cancelled.
func TestServeFailureStopsTheScheduler(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)
	for name, ignoresCtx := range map[string]bool{"job honours ctx": false, "job ignores ctx": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sched := jobs.New(log, allOn{}, nil)
			started := make(chan struct{})
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			if err := sched.Add(jobs.Job{Module: "core", Name: "slow", Every: time.Hour, Run: func(ctx context.Context) error {
				close(started)
				if ignoresCtx {
					<-release
				} else {
					<-ctx.Done()
				}
				return nil
			}}); err != nil {
				t.Fatal(err)
			}
			inner, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = inner.Close() }()
			done := make(chan error, 1)
			go func() {
				done <- serveUntilDone(t.Context(), log, &http.Server{ReadHeaderTimeout: time.Second}, failingListener{inner}, sched, 300*time.Millisecond)
			}()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "serve:") {
					t.Fatalf("err = %v, want a serve error", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("serveUntilDone did not return after the listener failed")
			}
			select {
			case <-started:
			default:
				t.Log("the job never started (the listener failed first); the scheduler still had to be stopped")
			}
		})
	}
}

// rawGet sends a request line exactly as written, so the client does not tidy the path first.
// rawGet sends a raw GET (no client-side path cleaning) and returns the status and headers.
func (in *instance) rawGet(t *testing.T, target string) (int, http.Header) {
	t.Helper()
	conn, err := new(net.Dialer).DialContext(t.Context(), "tcp", in.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, "GET "+target+" HTTP/1.1\r\nHost: "+in.addr+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header
}

// Responses the ServeMux makes itself (redirects, 404 for other paths) carry the API's headers and a request id.
func TestHeadersOnResponsesOutsideTheAPIHandler(t *testing.T) {
	t.Parallel()
	in := start(t)
	for target, status := range map[string]int{
		"/api/v1":                http.StatusTemporaryRedirect, // ServeMux adds the trailing slash
		"//":                     http.StatusTemporaryRedirect, // cleaned path
		"/api/v1/../x":           http.StatusTemporaryRedirect,
		"/api//v1/modules":       http.StatusTemporaryRedirect,
		"/elsewhere":             http.StatusNotFound,
		"/":                      http.StatusNotFound,
		"/api/v1x/modules":       http.StatusNotFound,
		"/api/v1/modules":        http.StatusUnauthorized, // inside the API: the same headers
		"/api/v1/does-not-exist": http.StatusNotFound,
	} {
		code, header := in.rawGet(t, target)
		if code != status {
			t.Errorf("GET %s = %d, want %d", target, code, status)
		}
		for h, want := range map[string]string{
			"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
			"X-Content-Type-Options":  "nosniff",
			"Referrer-Policy":         "no-referrer",
			"Cache-Control":           "no-store",
		} {
			if got := header.Get(h); got != want {
				t.Errorf("GET %s: %s = %q, want %q", target, h, got, want)
			}
		}
		if !strings.HasPrefix(header.Get("X-Request-Id"), "req-") {
			t.Errorf("GET %s: X-Request-Id = %q", target, header.Get("X-Request-Id"))
		}
	}
}
