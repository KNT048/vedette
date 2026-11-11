package main

// The box of the real-backend end-to-end run (WP-30, D-170): the same run() that main() calls, started inside a test binary so that later
// slices can put loopback fakes in the same process (the address policy refuses loopback except through the in-process test hooks).
// `make e2e-real` compiles this package with -tags webui and starts TestE2EBox; the browser specs of web/e2e-real/ read ready.json.
// TestE2EBox is skipped unless VEDETTE_E2E_DIR is set, so CI compiles it and never runs it.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// e2eReady is ready.json: everything a spec needs to find the box.
type e2eReady struct {
	BaseURL     string `json:"base_url"`
	SetupCode   string `json:"setup_code"`
	DataDir     string `json:"data_dir"`
	HoneypotDir string `json:"honeypot_dir"`
	// Control is the base URL of the loopback control server (WP-30 slice 3) and ControlToken the bearer token it asks for; SMTPPort is the
	// port of the fake SMTP server the specs point the email channel at (host 127.0.0.1, security none).
	Control      string `json:"control"`
	ControlToken string `json:"control_token"`
	SMTPPort     string `json:"smtp_port"`
}

// e2eLog is the box's log stream: every line goes to box.log, and the two lines the harness needs (the one-time setup code, D-75, and
// "listening") are picked up. Once both have been seen ready.json is written, once.
type e2eLog struct {
	mu    sync.Mutex
	file  *os.File
	buf   []byte
	ready e2eReady
	code  bool
	addr  bool
	sent  bool
	dir   string
	err   error
}

func (l *e2eLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.file.Write(p); err != nil {
		return 0, err
	}
	l.buf = append(l.buf, p...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			break
		}
		l.line(l.buf[:i])
		l.buf = l.buf[i+1:]
	}
	return len(p), nil
}

func (l *e2eLog) line(b []byte) {
	var e struct {
		Msg       string `json:"msg"`
		Addr      string `json:"addr"`
		SetupCode string `json:"setup_code"`
	}
	if json.Unmarshal(b, &e) != nil {
		return
	}
	switch {
	case e.SetupCode != "":
		l.ready.SetupCode, l.code = e.SetupCode, true
	case e.Msg == "listening" && e.Addr != "":
		l.ready.BaseURL, l.addr = "http://"+e.Addr, true
	}
	if l.code && l.addr && !l.sent && l.err == nil {
		l.sent = true
		l.err = writeReady(l.dir, l.ready)
	}
}

// writeReady writes ready.json (0600) through a temporary file and a rename, so a reader never sees half of it.
func writeReady(dir string, r e2eReady) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".ready.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "ready.json"))
}

// e2eBox runs the box in dir until ctx ends and returns what run returns. Layout: dir/data (0700) holds the database and the key,
// dir/hp the honeypot folders, dir/box.log the log, dir/ready.json is written once the box listens.
func e2eBox(ctx context.Context, dir string) error {
	data, hp := filepath.Join(dir, "data"), filepath.Join(dir, "hp")
	if err := os.MkdirAll(data, 0o700); err != nil { //nolint:gosec // test harness: the folder is the one the script made
		return err
	}
	if err := os.MkdirAll(hp, 0o755); err != nil { //nolint:gosec // the honeypot container reads this folder
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "box.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // test harness: the folder is the one the script made
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	ready := e2eReady{DataDir: data, HoneypotDir: hp}
	stopControl, err := startE2EControl(ctx, filepath.Join(data, "vedette.db"), &ready)
	if err != nil {
		return err
	}
	defer stopControl()
	log := &e2eLog{file: f, dir: dir, ready: ready}
	args := []string{
		"-db", filepath.Join(data, "vedette.db"), "-key", filepath.Join(data, "vedette.key"),
		"-listen", "127.0.0.1:0", "-host-socket", "", "-honeypot-dir", hp,
	}
	runErr := run(ctx, args, io.Discard, log)
	log.mu.Lock()
	defer log.mu.Unlock()
	return errors.Join(runErr, log.err)
}

// e2eStop is the context of the standalone box: SIGTERM or SIGINT, the death of the parent (the script that started it), or
// VEDETTE_E2E_MAX (default 45m) end it. The orphan reaper does not match this binary, so the box has to stop itself.
func e2eStop(t *testing.T) context.Context {
	t.Helper()
	limit := 45 * time.Minute
	if v := os.Getenv("VEDETTE_E2E_MAX"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			t.Fatalf("VEDETTE_E2E_MAX=%q is not a duration", v)
		}
		limit = d
	}
	ctx, stop := signal.NotifyContext(t.Context(), syscall.SIGTERM, syscall.SIGINT)
	ctx, cancel := context.WithTimeout(ctx, limit)
	ppid := os.Getppid()
	done := make(chan struct{})
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				if os.Getppid() != ppid {
					cancel()
					return
				}
			}
		}
	}()
	t.Cleanup(func() { close(done); cancel(); stop() })
	return ctx
}

func TestE2EBox(t *testing.T) {
	dir := os.Getenv("VEDETTE_E2E_DIR")
	if dir == "" {
		t.Skip("VEDETTE_E2E_DIR is not set: this is the box of `make e2e-real`")
	}
	if err := e2eBox(e2eStop(t), dir); err != nil {
		t.Fatalf("the box ended with an error: %v", err)
	}
}

// TestE2EBoxHarness runs in CI: the box starts, answers, writes ready.json, and stops on cancel without an error line in its log.
func TestE2EBoxHarness(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	stopped := make(chan struct{})
	go func() { done <- e2eBox(ctx, dir); close(stopped) }()
	t.Cleanup(func() { // the temp dir is removed only after the box has stopped, so wait for it
		cancel()
		select {
		case <-stopped:
		case <-time.After(15 * time.Second):
		}
	})

	var ready e2eReady
	deadline := time.Now().Add(20 * time.Second)
	for {
		b, err := os.ReadFile(filepath.Join(dir, "ready.json")) //nolint:gosec // test harness: the folder is the one the script made
		if err == nil && json.Unmarshal(b, &ready) == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("the box ended before it was ready: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("ready.json did not appear within 20 s")
		}
	}
	if info, err := os.Stat(filepath.Join(dir, "ready.json")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("ready.json mode: %v %v", info, err)
	}
	if ready.SetupCode == "" || ready.DataDir != filepath.Join(dir, "data") || ready.HoneypotDir != filepath.Join(dir, "hp") || !strings.HasPrefix(ready.BaseURL, "http://127.0.0.1:") {
		t.Fatalf("ready.json = %+v", ready)
	}

	reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer reqCancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, ready.BaseURL+"/api/v1/setup", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(req) // no idle connection to hold the shutdown
	if err != nil {
		t.Fatal(err)
	}
	var setup struct {
		Complete bool `json:"complete"`
	}
	err = json.NewDecoder(resp.Body).Decode(&setup)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || err != nil || setup.Complete {
		t.Fatalf("GET /api/v1/setup = %d complete=%v err=%v", resp.StatusCode, setup.Complete, err)
	}

	// the control server wants its token, and starts with an empty sink
	for token, want := range map[string]int{"": http.StatusUnauthorized, "Bearer wrong": http.StatusUnauthorized, "Bearer " + ready.ControlToken: http.StatusOK} {
		creq, err := http.NewRequestWithContext(reqCtx, http.MethodGet, ready.Control+"/smtp", nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			creq.Header.Set("Authorization", token)
		}
		cresp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(creq)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(cresp.Body)
		_ = cresp.Body.Close()
		if cresp.StatusCode != want || (want == http.StatusOK && strings.TrimSpace(string(body)) != `{"messages":[]}`) {
			t.Fatalf("GET /smtp with %q = %d %s", token, cresp.StatusCode, body)
		}
	}
	if ready.SMTPPort == "" {
		t.Fatalf("ready.json has no smtp_port: %+v", ready)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("e2eBox returned %v on cancel", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not return within 15 s of cancel")
	}
	logFile, err := os.Open(filepath.Join(dir, "box.log")) //nolint:gosec // test harness: the folder is the one the script made
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logFile.Close() }()
	sc := bufio.NewScanner(logFile)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var e struct {
			Level string `json:"level"`
		}
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Level == "ERROR" {
			t.Errorf("box.log has an error line: %s", sc.Text())
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(fmt.Errorf("read box.log: %w", err))
	}
}

// startE2EControl starts the fakes that live next to the box and the small loopback server the specs reach them through (WP-30 slice 3): the
// SMTP sink that receives the two-step codes, and two calls, both behind a bearer token that only ready.json (0600) holds:
//
//	GET  /smtp          -> {"messages": ["<raw message>", ...]}, every message the sink received, oldest first
//	POST /expire-codes  {"email": "..."} -> 204; the pending email code of that user is made to expire (the box has no fake clock, and the
//	                    real lifetime is 10 minutes), by writing core_email_code.expires_at through a second connection to the box's database
//
// It fills ready.SMTPPort, Control and ControlToken. Everything here is in a _test.go file: the production binary has none of it.
func startE2EControl(ctx context.Context, dbPath string, ready *e2eReady) (stop func(), err error) {
	sink, err := listenSMTPSink(ctx)
	if err != nil {
		return nil, err
	}
	tok := make([]byte, 24)
	if _, err := rand.Read(tok); err != nil {
		return nil, err
	}
	token := hex.EncodeToString(tok)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /smtp", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		msgs := append([]string{}, sink.messages()...) // [] and not null when nothing came yet
		_ = json.NewEncoder(w).Encode(map[string]any{"messages": msgs})
	})
	mux.HandleFunc("POST /expire-codes", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil || in.Email == "" {
			http.Error(w, "email is required", http.StatusBadRequest)
			return
		}
		db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: dbPath, RawQuery: url.Values{"_pragma": {"busy_timeout(5000)"}}.Encode()}).String())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer func() { _ = db.Close() }()
		res, err := db.ExecContext(r.Context(), `UPDATE core_email_code SET expires_at = '2000-01-01T00:00:00.000Z' WHERE user_id IN (SELECT id FROM core_user WHERE lower(email) = lower(?))`, in.Email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if n, _ := res.RowsAffected(); n != 1 {
			http.Error(w, "that user has no pending code", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			mux.ServeHTTP(w, r)
		}),
	}
	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() { _ = srv.Serve(ln) }()
	ready.Control, ready.ControlToken, ready.SMTPPort = "http://"+ln.Addr().String(), token, sink.port()
	return func() { _ = srv.Close() }, nil
}
