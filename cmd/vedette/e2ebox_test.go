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
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/feeds"
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
	// slice 4 (D-163), set with VEDETTE_E2E_HOST=1: the fake vedette-host's control endpoint and the second box that has no host
	HostControl   string `json:"host_control,omitempty"`
	HostToken     string `json:"host_token,omitempty"`
	BareURL       string `json:"bare_url,omitempty"`
	BareSetupCode string `json:"bare_setup_code,omitempty"`
	// sensorBin (slice 7, VEDETTE_E2E_SENSOR) is the vedette-sensor binary: set, the box opens its sensor link and the control endpoint
	// starts the sensors (e2esensor_test.go). Not part of ready.json.
	sensorBin string
	// slice 5 (D-93/D-94): the loopback devices a connection can be saved against, by kind (http, ssh, mcp): see e2edevices_test.go
	Devices map[string]e2eDeviceLogin `json:"devices,omitempty"`
	// the port of the syslog listener of the logs module (UDP and TCP, loopback): a spec declares a source with sender 127.0.0.1 and feeds it lines
	SyslogPort string      `json:"syslog_port,omitempty"`
	devs       *e2eDevices // not in ready.json: the control routes of this box (nil: the bare box has none)
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
	// onLink gets the address of the sensor link when core logs that it listens (slice 7); nil without sensors
	onLink func(addr string)
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
	case e.Msg == "sensor link listening" && e.Addr != "":
		if l.onLink != nil {
			l.onLink(e.Addr)
		}
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
func e2eBox(ctx context.Context, dir string) error { return e2eBoxWith(ctx, dir, "", "", e2eReady{}) }

// e2eBoxWith is e2eBox with a data folder other than dir/data (the fake host's core data), a host socket (empty: no host) and the
// fields of ready.json the caller already knows.
func e2eBoxWith(ctx context.Context, dir, dataDir, hostSocket string, seed e2eReady) error {
	data, hp := filepath.Join(dir, "data"), filepath.Join(dir, "hp")
	if dataDir != "" {
		data = dataDir
	}
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
	defer e2eOffline()()
	syslogPort, err := e2eFreePort(ctx)
	if err != nil {
		return err
	}
	seed.SyslogPort = strconv.Itoa(syslogPort)
	seed.DataDir, seed.HoneypotDir = data, hp
	var sensors *e2eSensors
	if seed.sensorBin != "" {
		sensors = newE2ESensors(ctx, seed.sensorBin, dir)
		defer sensors.stopAll()
	}
	stopControl, err := startE2EControl(ctx, filepath.Join(data, "vedette.db"), &seed, sensors)
	if err != nil {
		return err
	}
	defer stopControl()
	log := &e2eLog{file: f, dir: dir, ready: seed}
	args := []string{
		"-db", filepath.Join(data, "vedette.db"), "-key", filepath.Join(data, "vedette.key"),
		"-listen", "127.0.0.1:0", "-host-socket", hostSocket, "-honeypot-dir", hp,
		"-syslog-port", seed.SyslogPort, // not 514/5514: two runs at once, and a Mac may not bind 514 (logs spec)
	}
	if sensors != nil { // slice 7: the sensor link on a loopback port; the specs start the sensors through the control endpoint
		log.onLink = sensors.linkUp
		args = append(args, "-sensor-listen", "127.0.0.1:0", "-sensor-creds", sensors.creds)
	}
	runErr := run(ctx, args, io.Discard, log)
	log.mu.Lock()
	defer log.mu.Unlock()
	return errors.Join(runErr, log.err)
}

// The listener of the logs module binds loopback only in this test binary: a test box does not open a syslog port on the LAN. Set once, before any box starts (two boxes
// run in one process and read it from their own goroutines).
func init() { syslogHost = "127.0.0.1" }

// e2eFreePort returns a port that is free for both TCP and UDP on loopback right now (the syslog listener needs one number for both).
func e2eFreePort(ctx context.Context) (int, error) {
	for range 20 {
		tl, err := new(net.ListenConfig).Listen(ctx, "tcp4", "127.0.0.1:0")
		if err != nil {
			return 0, err
		}
		port := tl.Addr().(*net.TCPAddr).Port
		_ = tl.Close()
		ul, err := new(net.ListenConfig).ListenPacket(ctx, "udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			continue
		}
		_ = ul.Close()
		return port, nil
	}
	return 0, errors.New("no port free for TCP and UDP on loopback")
}

// e2eKEV is the CISA catalog the box of the run "downloads": one entry, so the Home title is the loaded one ("Today: N ..."), the same
// on every machine (the real catalog has 1.8k entries and the specs must not depend on it, D-170).
const e2eKEV = `{"title":"E2E catalog","catalogVersion":"2026.11.11","dateReleased":"2026-11-11T00:00:00.000Z","count":1,"vulnerabilities":[
{"cveID":"CVE-2026-0001","vendorProject":"E2E Vendor","product":"E2E Product","vulnerabilityName":"E2E fixture vulnerability","dateAdded":"2026-11-10","shortDescription":"A fixture entry of the end-to-end run.","requiredAction":"None.","dueDate":"2026-12-01","knownRansomwareCampaignUse":"Unknown","notes":"","cwes":[]}]}`

// e2eOffline gives the box of the run no internet. The feeds client answers the built-in CISA address (and its mirror) from e2eKEV, a
// loopback address from the real network (a custom feed pointed at a 127.0.0.1 fake, feeds.spec.ts), and refuses every other address at
// once, so EPSS and the IOC lists fail fast. Without this the box pulled the public feeds at start: ~80 MB written in one transaction that
// held the database writer for ~13 s, so the first sign-ins, the first-run setup and the first user created after the start stalled past
// the 8 s expect timeout, and what the specs saw depended on the network. The returned func puts the client back (the package var is
// shared with the other tests of this package, which never run while this one does: it is not parallel).
func e2eOffline() func() {
	e2eOfflineMu.Lock()
	defer e2eOfflineMu.Unlock()
	e2eOfflineN++
	if e2eOfflineN > 1 { // a second box in the same process (the bare box): the client is already the offline one
		return e2eOfflineRelease
	}
	e2eOfflinePrev = feedsClient
	c := feeds.NewClient(feeds.DefaultFetchTimeout)
	inner := c.Transport
	c.Transport = e2eRoundTrip(func(r *http.Request) (*http.Response, error) {
		if ip, err := netip.ParseAddr(r.URL.Hostname()); err == nil && ip.IsLoopback() {
			return inner.RoundTrip(r)
		}
		if r.URL.Path == "/sites/default/files/feeds/known_exploited_vulnerabilities.json" && r.URL.Host == "www.cisa.gov" ||
			r.URL.Path == "/cisagov/kev-data/develop/known_exploited_vulnerabilities.json" && r.URL.Host == "raw.githubusercontent.com" {
			h := http.Header{"Content-Type": {"application/json"}}
			return &http.Response{Status: "200 OK", StatusCode: http.StatusOK, Header: h, Body: io.NopCloser(strings.NewReader(e2eKEV)), ContentLength: int64(len(e2eKEV)), Request: r}, nil
		}
		return nil, errors.New("the box of the end-to-end run has no internet")
	})
	feedsClient = c
	return e2eOfflineRelease
}

var (
	e2eOfflineMu   sync.Mutex
	e2eOfflineN    int
	e2eOfflinePrev *http.Client
)

func e2eOfflineRelease() {
	e2eOfflineMu.Lock()
	defer e2eOfflineMu.Unlock()
	if e2eOfflineN--; e2eOfflineN == 0 {
		feedsClient = e2eOfflinePrev
	}
}

type e2eRoundTrip func(*http.Request) (*http.Response, error)

func (f e2eRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestE2EOffline pins what the feeds client of the box does: the catalog the specs rely on parses, a loopback address is reached, and any
// other address is refused.
func TestE2EOffline(t *testing.T) {
	restore := e2eOffline()
	defer restore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "loopback") }))
	defer srv.Close()
	get := func(u string) (string, error) {
		resp, err := feedsClient.Get(u) //nolint:noctx // a unit test of a transport
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		return string(b), err
	}
	kev, ok := feeds.BuiltinByID("cisa-kev")
	if !ok {
		t.Fatal("no built-in cisa-kev source")
	}
	for _, u := range []string{kev.URL, feeds.KEVMirrorURL} {
		body, err := get(u)
		if err != nil {
			t.Fatalf("GET %s: %v", u, err)
		}
		cat, err := feeds.ParseKEV([]byte(body))
		if err != nil || len(cat.Vulns) != 1 || cat.Vulns[0].CVE != "CVE-2026-0001" {
			t.Fatalf("the catalog of %s: %+v %v", u, cat, err)
		}
	}
	if body, err := get(srv.URL); err != nil || body != "loopback" {
		t.Fatalf("loopback = %q %v", body, err)
	}
	for _, u := range []string{"https://www.cisa.gov/other.json", "https://epss.cyentia.com/epss_scores-current.csv.gz", "http://10.0.0.1/x"} {
		if _, err := get(u); err == nil {
			t.Fatalf("GET %s was not refused", u)
		}
	}
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
	ctx := e2eStop(t)
	var host *e2eHost
	var seed e2eReady
	devs, logins := startE2EDevices(t)        // slice 5: the loopback devices of the Connections specs
	if os.Getenv("VEDETTE_E2E_HOST") == "1" { // slice 4: the fake host in this process, and the second box that has none
		host = startE2EHost(t)
		bare := startE2EBare(ctx, t, dir)
		seed = e2eReady{HostControl: host.ctlURL, HostToken: host.ctlToken, BareURL: bare.BaseURL, BareSetupCode: bare.SetupCode}
	}
	seed.sensorBin = os.Getenv("VEDETTE_E2E_SENSOR")
	seed.Devices, seed.devs = logins, devs
	data, sock := "", ""
	if host != nil {
		data, sock = host.dataDir, host.socket
	}
	if err := e2eBoxWith(ctx, dir, data, sock, seed); err != nil {
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
//	POST /exposure/prober, /exposure/txt, /exposure/scan: the exposure fakes (e2eexposure_test.go, #263)
//
// It fills ready.SMTPPort, Control and ControlToken. Everything here is in a _test.go file: the production binary has none of it.
func startE2EControl(ctx context.Context, dbPath string, ready *e2eReady, sensors *e2eSensors) (stop func(), err error) {
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
	e2eExposureRoutes(mux)
	if sensors != nil {
		sensors.routes(mux)
	}
	if ready.devs != nil {
		ready.devs.routes(mux)
	}
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
	releaseExposure := e2eExposureFakes()
	ready.Control, ready.ControlToken, ready.SMTPPort = "http://"+ln.Addr().String(), token, sink.port()
	return func() { _ = srv.Close(); releaseExposure() }, nil
}
