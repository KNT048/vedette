package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // a path the test made
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatalf("%s is not PEM", path)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEnsureCert(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	if err := ensureCert(crt, key, []string{"box.acme.example", "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{crt, key} {
		if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, info, err)
		}
	}
	c := readCert(t, crt)
	if pk, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pk.Curve != elliptic.P256() {
		t.Fatalf("public key is %T, want ECDSA P-256", c.PublicKey)
	}
	if got := c.NotAfter.Sub(c.NotBefore); got < 9*365*24*time.Hour || got > 11*365*24*time.Hour {
		t.Fatalf("validity = %v, want about 10 years", got)
	}
	var names []string
	names = append(names, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		names = append(names, ip.String())
	}
	for _, want := range []string{"box.acme.example", "192.0.2.10", "localhost", "127.0.0.1", "::1"} {
		found := false
		for _, n := range names {
			found = found || n == want
		}
		if !found {
			t.Errorf("SANs %v lack %q", names, want)
		}
	}
	if c.IsCA {
		t.Error("the certificate may sign others")
	}
	// Idempotent: a second call leaves the pair alone.
	before, _ := os.ReadFile(crt) //nolint:gosec // a path the test made
	if err := ensureCert(crt, key, []string{"other.example"}); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(crt); string(after) != string(before) { //nolint:gosec // a path the test made
		t.Fatal("ensureCert replaced an existing pair")
	}
	// A key without its certificate is refused; a certificate without its key is replaced.
	if err := os.Remove(crt); err != nil {
		t.Fatal(err)
	}
	if err := ensureCert(crt, key, nil); err == nil {
		t.Fatal("a key without its certificate was accepted")
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crt, []byte("leftover"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureCert(crt, key, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadTLS(crt, key); err != nil {
		t.Fatalf("the replaced pair does not load: %v", err)
	}
}

func TestParseHosts(t *testing.T) {
	t.Parallel()
	got, err := parseHosts(" Box.Acme.Example. , 192.0.2.10:8443,[2001:db8::1]:443, ::ffff:192.0.2.9 ,")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"box.acme.example", "192.0.2.10", "2001:db8::1", "192.0.2.9"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("parseHosts = %v, want %v", got, want)
	}
	for _, bad := range []string{"a b", "http://x", "-bad", "x/y", "a@b"} {
		if _, err := parseHosts(bad); err == nil {
			t.Errorf("parseHosts(%q) accepted", bad)
		}
	}
}

// logTap keeps the log lines of a run so a test can read what was logged before "listening".
type logTap struct {
	mu    sync.Mutex
	lines []string
}

func (l *logTap) add(s string) { l.mu.Lock(); l.lines = append(l.lines, s); l.mu.Unlock() }
func (l *logTap) text() string { l.mu.Lock(); defer l.mu.Unlock(); return strings.Join(l.lines, "\n") }

// startArgs runs the process with extra flags on top of a temp database and key and waits for "listening".
func startArgs(t *testing.T, dir string, extra ...string) (addr string, tap *logTap, cancel context.CancelFunc, done chan error) {
	t.Helper()
	var ctx context.Context
	ctx, cancel = context.WithCancel(t.Context())
	t.Cleanup(cancel)
	tap, done = &logTap{}, make(chan error, 1)
	pr, pw := io.Pipe()
	args := append([]string{"-db", filepath.Join(dir, "v.db"), "-key", filepath.Join(dir, "v.key")}, extra...)
	go func() { done <- run(ctx, args, io.Discard, pw); _ = pw.Close() }()
	sc := bufio.NewScanner(pr)
	for sc.Scan() {
		tap.add(sc.Text())
		var line struct{ Msg, Addr string }
		if json.Unmarshal(sc.Bytes(), &line) == nil && line.Msg == "listening" {
			go func() {
				for sc.Scan() {
					tap.add(sc.Text())
				}
			}()
			return line.Addr, tap, cancel, done
		}
	}
	t.Fatalf("run ended before listening: %v\n%s", <-done, tap.text())
	return "", nil, nil, nil
}

func tlsClient(t *testing.T, certPath string) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(readCert(t, certPath))
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
}

func getWithHost(t *testing.T, c *http.Client, url, host string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// A non-loopback listen address is served over TLS with a self-signed pair made next to the database; the
// Host allowlist defaults to the names of that certificate and 421s everything else, before routing.
func TestNonLoopbackListenMakesACertificateAndServesTLS(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	addr, _, cancel, done := startArgs(t, dir, "-listen", "0.0.0.0:0", "-hosts", "box.acme.example")
	crt, key := filepath.Join(dir, "vedette-selfsigned.crt"), filepath.Join(dir, "vedette-selfsigned.key")
	for _, p := range []string{crt, key} {
		if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, info, err)
		}
	}
	_, port, _ := strings.Cut(addr, "]:")
	if port == addr {
		_, port, _ = strings.Cut(addr, ":")
	}
	c := tlsClient(t, crt)
	base := "https://127.0.0.1:" + port
	// Plain HTTP to the TLS port gets no API answer.
	plain, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1:"+port+"/api/v1/setup", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(plain); err == nil {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatalf("plain HTTP was served on a TLS listener: %s", b)
		}
	}
	if code, body := getWithHost(t, c, base+"/api/v1/setup", ""); code != 200 || !strings.Contains(body, `"complete":false`) {
		t.Fatalf("GET /setup over TLS = %d %s", code, body)
	}
	// The configured name and the loopback names pass; anything else is 421 on API and non-API paths alike.
	for _, h := range []string{"box.acme.example", "BOX.acme.example:8443", "localhost", "127.0.0.1:" + port} {
		if code, body := getWithHost(t, c, base+"/api/v1/setup", h); code != 200 {
			t.Errorf("Host %q = %d %s, want 200", h, code, body)
		}
	}
	for _, h := range []string{"evil.example", "box.acme.example.evil.example", "192.0.2.77", "evil.example:443", ""} {
		for _, path := range []string{"/api/v1/setup", "/", "/api/v1/modules", "/anything"} {
			code, body := getWithHost(t, c, base+path, h)
			if h == "" { // an empty Host on HTTP/1.1 is the URL's own host: allowed
				continue
			}
			if code != 421 || !strings.Contains(body, `"code":"misdirected_request"`) {
				t.Errorf("Host %q GET %s = %d %s, want 421 misdirected_request", h, path, code, body)
			}
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// -tls-cert and -tls-key are used as given, on loopback too, and the default allowlist is their names.
func TestOwnCertificateOnLoopback(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "own.crt"), filepath.Join(dir, "own.key")
	if err := ensureCert(crt, key, []string{"nas.home.example"}); err != nil {
		t.Fatal(err)
	}
	addr, _, cancel, done := startArgs(t, dir, "-listen", "127.0.0.1:0", "-tls-cert", crt, "-tls-key", key)
	c := tlsClient(t, crt)
	if code, _ := getWithHost(t, c, "https://"+addr+"/api/v1/setup", ""); code != 200 {
		t.Fatalf("GET over TLS = %d", code)
	}
	if code, _ := getWithHost(t, c, "https://"+addr+"/api/v1/setup", "nas.home.example"); code != 200 {
		t.Fatalf("a name of the certificate = %d", code)
	}
	if code, _ := getWithHost(t, c, "https://"+addr+"/api/v1/setup", "other.example"); code != 421 {
		t.Fatalf("a name outside the certificate = %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "vedette-selfsigned.crt")); err == nil {
		t.Fatal("a self-signed pair was made although a certificate was given")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Loopback over plain HTTP allows only the loopback names unless -hosts adds more (D-77 neighbour: DNS rebinding).
func TestLoopbackHTTPHostAllowlist(t *testing.T) {
	t.Parallel()
	in := start(t)
	for host, want := range map[string]int{"localhost": 200, "127.0.0.1": 200, "[::1]:9": 200, "evil.example": 421, "192.0.2.5": 421} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+in.addr+"/api/v1/setup", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("Host %q = %d, want %d", host, resp.StatusCode, want)
		}
	}
}

// D-75: the setup code is printed at every start while setup is open, and the same code is printed again
// after a restart; it is stored in core_secret, never in a file of its own.
func TestSetupCodeIsLoggedAtEveryStartWhileSetupIsOpen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	codes := make([]string, 0, 2)
	for range 2 {
		_, tap, cancel, done := startArgs(t, dir, "-listen", "127.0.0.1:0")
		var code string
		for _, l := range strings.Split(tap.text(), "\n") {
			var line struct {
				Msg  string `json:"msg"`
				Code string `json:"setup_code"`
			}
			if json.Unmarshal([]byte(l), &line) == nil && line.Code != "" {
				code = line.Code
			}
		}
		if code == "" {
			t.Fatalf("no setup code in the log:\n%s", tap.text())
		}
		codes = append(codes, code)
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if codes[0] != codes[1] {
		t.Fatalf("the code changed between starts: %q then %q", codes[0], codes[1])
	}
}
