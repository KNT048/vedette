package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/server"
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
	if err := ensureCert(t, crt, key, []string{"box.acme.example", "192.0.2.10"}); err != nil {
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
	if got := c.NotAfter.Sub(c.NotBefore); got < 825*24*time.Hour || got > 826*24*time.Hour {
		t.Fatalf("validity = %v, want 825 days (Apple's limit) plus the hour of back-dating", got)
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
	if err := ensureCert(t, crt, key, []string{"other.example"}); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(crt); string(after) != string(before) { //nolint:gosec // a path the test made
		t.Fatal("ensureCert replaced an existing pair")
	}
	// A key without its certificate is refused; a certificate without its key is replaced.
	if err := os.Remove(crt); err != nil {
		t.Fatal(err)
	}
	if err := ensureCert(t, crt, key, nil); err == nil {
		t.Fatal("a key without its certificate was accepted")
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crt, []byte("leftover"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureCert(t, crt, key, nil); err != nil {
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
	tap, done = &logTap{}, make(chan error, 1)
	pr, pw := io.Pipe()
	args := append([]string{"-db", filepath.Join(dir, "v.db"), "-key", filepath.Join(dir, "v.key")}, extra...)
	stopped := make(chan struct{})
	go func() { defer close(stopped); done <- run(ctx, args, io.Discard, pw); _ = pw.Close() }()
	waitStopped(t, cancel, stopped)
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
	if err := ensureCert(t, crt, key, []string{"nas.home.example"}); err != nil {
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

// writeTestPair writes a certificate made from tmpl (self-signed, with a new P-256 key) and its key, both
// mode 0600, as an owner supplying their own pair would, and returns the paths and the key.
func writeTestPair(t *testing.T, dir string, tmpl *x509.Certificate) (crt, keyPath string, key *ecdsa.PrivateKey) {
	t.Helper()
	crt, keyPath = filepath.Join(dir, "own.crt"), filepath.Join(dir, "own.key")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = big.NewInt(7)
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	return crt, keyPath, key
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
}

func hostStatus(t *testing.T, h http.Handler, host string) int {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/setup", nil)
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// Review of WP-04b part 2 (L2): the master key file and the database are refused unless their mode is 0600,
// and the TLS private key is held to the same rule: a key readable by other local users lets them impersonate
// the box to every administrator.
func TestLoadTLSRefusesAGroupOrWorldReadableKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	if err := ensureCert(t, crt, key, []string{"box.acme.example"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadTLS(crt, key); err != nil {
		t.Fatalf("a 0600 key was refused: %v", err)
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
		if err := os.Chmod(key, mode); err != nil {
			t.Fatal(err)
		}
		_, _, err := loadTLS(crt, key)
		if err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("a TLS private key with mode %#o was loaded (err %v)", mode, err)
		}
	}
	// 0400 is fine (nobody else can read it), and so is a symlink to a good file (certbot links its live key).
	if err := os.Chmod(key, 0o400); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadTLS(crt, link); err != nil {
		t.Fatalf("a 0400 key through a symlink was refused: %v", err)
	}
	// A directory is not a key file.
	if _, _, err := loadTLS(crt, dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a directory as the key file: %v", err)
	}
}

// Review (L3): with a certificate the owner supplies and no -hosts, the Host allowlist is the names of the
// certificate; a wildcard name (*.corp.example) matches one label like the certificate does, so the box does
// not answer 421 to the very name its certificate is for.
func TestWildcardCertificateDefaultAllowlist(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	crt, key, _ := writeTestPair(t, dir, &x509.Certificate{Subject: pkix.Name{CommonName: "corp"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"*.corp.example"}})
	_, hosts, _, _, err := testTransport(t, options{db: filepath.Join(dir, "v.db"), listen: "0.0.0.0:8443", tlsCert: crt, tlsKey: key})
	if err != nil {
		t.Fatal(err)
	}
	h := server.HostAllowlist(hosts, okHandler())
	for host, want := range map[string]int{"vedette.corp.example:8443": 204, "a.b.corp.example": 421, "corp.example": 421, "evil.example": 421} {
		if got := hostStatus(t, h, host); got != want {
			t.Errorf("allowlist %v: Host %s = %d, want %d", hosts, host, got, want)
		}
	}
}

// A certificate with a common name and no subject alternative names (an old one) is matched by the common
// name; one that has names is matched by them only.
func TestCertificateNamesUseTheCommonNameOnlyWithoutSANs(t *testing.T) {
	t.Parallel()
	valid := func() (time.Time, time.Time) { return time.Now().Add(-time.Hour), time.Now().Add(time.Hour) }
	nb, na := valid()
	crt, key, _ := writeTestPair(t, t.TempDir(), &x509.Certificate{Subject: pkix.Name{CommonName: "Box.Corp.Example"}, NotBefore: nb, NotAfter: na})
	if _, names, err := loadTLS(crt, key); err != nil || len(names) != 1 || names[0] != "box.corp.example" {
		t.Fatalf("CN-only certificate: names %v, err %v", names, err)
	}
	crt, key, _ = writeTestPair(t, t.TempDir(), &x509.Certificate{Subject: pkix.Name{CommonName: "old.corp.example"}, NotBefore: nb, NotAfter: na, DNSNames: []string{"new.corp.example"}})
	if _, names, err := loadTLS(crt, key); err != nil || len(names) != 1 || names[0] != "new.corp.example" {
		t.Fatalf("certificate with SANs: names %v, err %v", names, err)
	}
	crt, key, _ = writeTestPair(t, t.TempDir(), &x509.Certificate{Subject: pkix.Name{CommonName: "Vedette box"}, NotBefore: nb, NotAfter: na})
	if _, names, err := loadTLS(crt, key); err != nil || len(names) != 0 {
		t.Fatalf("a common name that is not a host name gave names %v (err %v)", names, err)
	}
}

func TestParseHostsAcceptsOneLabelWildcards(t *testing.T) {
	t.Parallel()
	got, err := parseHosts("*.Corp.Example, box.lan")
	if err != nil || strings.Join(got, ",") != "*.corp.example,box.lan" {
		t.Fatalf("parseHosts = %v, %v", got, err)
	}
	for _, bad := range []string{"*", "*.", "a.*.example", "*.*.example", "x*.example", "**.example", "*.com", "*.com.", "*.168.1.10", "*.10", "*.1.2.3.4", "*.example.123"} {
		if _, err := parseHosts(bad); err == nil {
			t.Errorf("parseHosts(%q) accepted", bad)
		}
	}
	h := server.HostAllowlist(got, okHandler())
	if hostStatus(t, h, "vedette.corp.example") != 204 || hostStatus(t, h, "a.b.corp.example") != 421 {
		t.Fatal("-hosts *.corp.example does not match like a wildcard certificate")
	}
}

// A self-signed certificate made by the box expires within 30 days: the next start makes a new one for the
// same key (one atomic file write) with fresh names. One that has time left, and a certificate the owner
// supplied, are never replaced.
func TestEnsureCertRenewsItsOwnPairNearExpiry(t *testing.T) {
	t.Parallel()
	own := func(left time.Duration, org string) *x509.Certificate {
		return &x509.Certificate{Subject: pkix.Name{CommonName: "Vedette", Organization: []string{org}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(left), DNSNames: []string{"old.example"}}
	}
	cases := []struct {
		name  string
		tmpl  *x509.Certificate
		renew bool
	}{
		{"own pair, 10 days left", own(10*24*time.Hour, selfSignedOrg), true},
		{"own pair, already expired", own(-time.Hour, selfSignedOrg), true},
		// An old self-signed leaf is re-issued once under the box CA whatever time it has left (D-262); a
		// leaf that already chains to the CA and has time left is left alone (TestBoxCAFreshBoxLeafChainsToIt).
		{"old self-signed pair, 60 days left", own(60*24*time.Hour, selfSignedOrg), true},
		{"owner's pair, 10 days left", own(10*24*time.Hour, "Acme IT"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			crt, key, k := writeTestPair(t, t.TempDir(), tc.tmpl)
			before, _ := os.ReadFile(crt) //nolint:gosec // a path the test made
			if err := ensureCert(t, crt, key, []string{"new.example"}); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(crt) //nolint:gosec // a path the test made
			if replaced := string(after) != string(before); replaced != tc.renew {
				t.Fatalf("certificate replaced = %v, want %v", replaced, tc.renew)
			}
			if !tc.renew {
				return
			}
			c := readCert(t, crt)
			if left := time.Until(c.NotAfter); left < 824*24*time.Hour {
				t.Errorf("the new certificate has %v left", left)
			}
			if pk, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || !pk.Equal(&k.PublicKey) {
				t.Error("the renewed certificate is for another key")
			}
			if !strings.Contains(strings.Join(c.DNSNames, ","), "new.example") {
				t.Errorf("names %v lack new.example", c.DNSNames)
			}
			if info, err := os.Stat(crt); err != nil || info.Mode().Perm() != 0o600 {
				t.Errorf("mode after renewal: %v %v", info, err)
			}
			if _, _, err := loadTLS(crt, key); err != nil {
				t.Errorf("the renewed pair does not load: %v", err)
			}
		})
	}
}

// HSTS only for a certificate the owner supplied: with the self-signed one a browser would refuse to let the
// owner click through its warning for a year.
func TestStrictTransportSecurityOnlyWithAnOwnerCertificate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	crt, key, _ := writeTestPair(t, dir, &x509.Certificate{Subject: pkix.Name{CommonName: "box"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"box.corp.example"}})
	db := filepath.Join(dir, "v.db")
	for name, tc := range map[string]struct {
		o    options
		want bool
	}{
		"owner certificate":    {options{db: db, listen: "0.0.0.0:8443", tlsCert: crt, tlsKey: key}, true},
		"self-signed":          {options{db: db, listen: "0.0.0.0:8443"}, false},
		"plain http, loopback": {options{db: db, listen: "127.0.0.1:8080"}, false},
	} {
		_, hosts, hsts, _, err := testTransport(t, tc.o)
		if err != nil || hsts != tc.want {
			t.Fatalf("%s: hsts = %v, err %v, want %v", name, hsts, err, tc.want)
		}
		h := topHandler(slog.New(slog.DiscardHandler), okHandler(), hosts, hsts, nil)
		for _, host := range []string{"localhost", "evil.example"} { // the 421 carries it too
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/setup", nil)
			req.Host = host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			got := rec.Header().Get("Strict-Transport-Security")
			if tc.want && got != "max-age=31536000" || !tc.want && got != "" {
				t.Errorf("%s, Host %s: Strict-Transport-Security = %q", name, host, got)
			}
		}
	}
}

// Review 2 (L3): wildcard edge cases through the real flag parser and the allowlist.
func TestWildcardHostsEdgeCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		flag, host string
		want       int
		why        string
	}{
		{"*.corp.example.", "box.corp.example.", 204, "trailing dots on both sides"},
		{"*.corp.example", "BOX.Corp.Example:8443", 204, "case and port"},
		{"*.corp.example", "corp.example", 421, "the bare parent"},
		{"*.corp.example", ".corp.example", 421, "an empty label"},
		{"*.xn--bcher-kva.example", "box.xn--bcher-kva.example", 204, "punycode A-labels"},
		{"*.xn--bcher-kva.example", "box.bücher.example", 421, "a U-label Host never matches"},
		{"*.co.uk", "attacker.co.uk", 204, "documented residual: no public-suffix list, *.co.uk is accepted"},
		{"*.corp.example,192.168.1.10", "192.168.1.10", 204, "an IP entry still works beside a wildcard"},
	}
	for _, c := range cases {
		hosts, err := parseHosts(c.flag)
		if err != nil {
			t.Errorf("%s: -hosts %q refused: %v", c.why, c.flag, err)
			continue
		}
		if got := hostStatus(t, server.HostAllowlist(hosts, okHandler()), c.host); got != c.want {
			t.Errorf("%s: -hosts %q, Host %q = %d, want %d", c.why, c.flag, c.host, got, c.want)
		}
	}
	for _, flag := range []string{"*.com", "*.168.1.10"} {
		_, err := parseHosts(flag)
		if err == nil || !strings.Contains(err.Error(), "wildcard") {
			t.Errorf("-hosts %q: %v, want a clear refusal about the wildcard", flag, err)
		}
	}
}

// A wildcard never matches an IP literal, even when an entry like *.168.1.10 gets past the parser (the
// allowlist is also used with entries that did not come from -hosts).
func TestWildcardNeverMatchesAnIPLiteral(t *testing.T) {
	t.Parallel()
	h := server.HostAllowlist([]string{"*.168.1.10", "*.com", "*.corp.example"}, okHandler())
	for _, host := range []string{"192.168.1.10", "192.168.1.10:8443", "attacker.com", "com"} {
		if got := hostStatus(t, h, host); got != 421 {
			t.Errorf("Host %q = %d, want 421", host, got)
		}
	}
	if hostStatus(t, h, "box.corp.example") != 204 {
		t.Error("the valid wildcard stopped working")
	}
}

// Review 2 (L2): a symlink to a world-readable key is refused (os.Stat checks the target), and so is a
// dangling symlink.
func TestLoadTLSRefusesASymlinkToAWorldReadableKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	if err := ensureCert(t, crt, key, []string{"box.acme.example"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0o644); err != nil { //nolint:gosec // the point of the test
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadTLS(crt, link); err == nil {
		t.Fatal("a symlink to a 0644 key was accepted")
	}
	dangling := filepath.Join(dir, "dangling.key")
	if err := os.Symlink(filepath.Join(dir, "nope"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadTLS(crt, dangling); err == nil {
		t.Fatal("a dangling symlink was accepted")
	}
}

// A running box renews its own certificate (a day-by-day check, injected clock) and hands the new one to
// the next handshake through GetCertificate, without a restart; the key stays the same. A pair the owner
// supplied is never given a renewer.
func TestSelfSignedRenewerSwapsInTheRenewedCertificate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	o := options{db: filepath.Join(dir, "v.db"), listen: "0.0.0.0:8443", hosts: "box.acme.example"}
	cfg, _, _, renew, err := testTransport(t, o)
	if err != nil || renew == nil {
		t.Fatalf("transport: renew=%v err=%v", renew, err)
	}
	if len(cfg.Certificates) != 0 || cfg.GetCertificate == nil {
		t.Fatal("the self-signed pair is not served through GetCertificate")
	}
	now := time.Now()
	renew.now = func() time.Time { return now }
	first, _ := cfg.GetCertificate(nil)
	if err := renew.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if again, _ := cfg.GetCertificate(nil); again != first {
		t.Fatal("a certificate with 825 days left was replaced")
	}
	now = now.Add(800 * 24 * time.Hour) // 25 days left of 825
	tick := make(chan time.Time)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { renew.Run(ctx, slog.New(slog.DiscardHandler), tick, nil); close(done) }()
	tick <- now
	tick <- now // the second send returns only after the first Check finished
	cancel()
	<-done
	second, _ := cfg.GetCertificate(nil)
	if second == first {
		t.Fatal("the certificate was not swapped after 800 days")
	}
	leaf, err := x509.ParseCertificate(second.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if left := leaf.NotAfter.Sub(now); left < 824*24*time.Hour {
		t.Errorf("the renewed certificate has %v left at the injected time", left)
	}
	if !strings.Contains(strings.Join(leaf.DNSNames, ","), "box.acme.example") {
		t.Errorf("renewed names %v lack the -hosts name", leaf.DNSNames)
	}
	old, _ := x509.ParseCertificate(first.Certificate[0])
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(old.PublicKey) {
		t.Error("the renewed certificate is for another key")
	}

	crt, key, _ := writeTestPair(t, t.TempDir(), &x509.Certificate{Subject: pkix.Name{CommonName: "box"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"box.corp.example"}})
	if _, _, _, renew, err := testTransport(t, options{db: filepath.Join(dir, "v.db"), listen: "0.0.0.0:8443", tlsCert: crt, tlsKey: key}); err != nil || renew != nil {
		t.Fatalf("an owner's pair got a renewer: %v %v", renew, err)
	}
}
