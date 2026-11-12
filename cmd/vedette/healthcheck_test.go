package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/modules/honeypot"
)

// healthServer is a TLS server on 127.0.0.1 with a self-signed certificate, and the PEM file of that certificate.
func healthServer(t *testing.T, h http.Handler) (addr, certFile string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	certFile = filepath.Join(t.TempDir(), "box.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(certFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv.Listener.Addr().String(), certFile
}

// vedetteServer is a TLS server whose certificate the box's own routine made (Organization selfSignedOrg), and its PEM file.
func vedetteServer(t *testing.T, h http.Handler) (addr, certFile string) {
	t.Helper()
	dir := t.TempDir()
	certFile = filepath.Join(dir, "box.crt")
	keyFile := filepath.Join(dir, "box.key")
	if err := ensureCert(t, certFile, keyFile, nil); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), certFile
}

func listenTCP(t *testing.T) (net.Listener, error) {
	t.Helper()
	return new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
}

func healthHandler(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != coreHealthPath {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
	})
}

func TestCoreHealthcheck(t *testing.T) {
	t.Parallel()
	addr, cert := healthServer(t, healthHandler(200))
	missing := filepath.Join(t.TempDir(), "none.crt")

	t.Run("healthy, the box's own certificate, pinned", func(t *testing.T) {
		t.Parallel()
		a, c := vedetteServer(t, healthHandler(200))
		if err := coreHealthcheck(t.Context(), a, c, time.Second); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("healthy, certificate file unreadable: loopback skips verification", func(t *testing.T) {
		t.Parallel()
		if err := coreHealthcheck(t.Context(), addr, missing, time.Second); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a different certificate of the box's own kind is refused", func(t *testing.T) {
		t.Parallel()
		a, _ := vedetteServer(t, healthHandler(200))
		dir := t.TempDir()
		other := filepath.Join(dir, "other.crt")
		if err := ensureCert(t, other, filepath.Join(dir, "other.key"), nil); err != nil {
			t.Fatal(err)
		}
		if err := coreHealthcheck(t.Context(), a, other, time.Second); err == nil {
			t.Fatal("the pin must refuse another certificate that Vedette made")
		}
	})
	t.Run("an owner certificate (-tls-cert) is not pinned to the self-signed file", func(t *testing.T) {
		t.Parallel()
		// httptest's certificate is not one Vedette made (Organization "Acme Co"); the file next to -db holds the box's own
		// self-signed one, which this server does not serve: the check must still pass
		dir := t.TempDir()
		own := filepath.Join(dir, "own.crt")
		if err := ensureCert(t, own, filepath.Join(dir, "own.key"), nil); err != nil {
			t.Fatal(err)
		}
		if err := coreHealthcheck(t.Context(), addr, own, time.Second); err != nil {
			t.Fatalf("owner certificate: %v", err)
		}
		_ = cert
	})
	t.Run("a certificate file with no certificate in it is an error", func(t *testing.T) {
		t.Parallel()
		junk := filepath.Join(t.TempDir(), "junk.crt")
		if err := os.WriteFile(junk, []byte("not pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := coreHealthcheck(t.Context(), addr, junk, time.Second); err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("not 200 is unhealthy", func(t *testing.T) {
		t.Parallel()
		a, c := healthServer(t, healthHandler(503))
		if err := coreHealthcheck(t.Context(), a, c, time.Second); err == nil || !strings.Contains(err.Error(), "503") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a redirect is not followed and not healthy", func(t *testing.T) {
		t.Parallel()
		a, c := healthServer(t, http.RedirectHandler("/elsewhere", http.StatusTemporaryRedirect))
		if err := coreHealthcheck(t.Context(), a, c, time.Second); err == nil {
			t.Fatal("a 307 is not a 200")
		}
	})
	t.Run("not listening", func(t *testing.T) {
		t.Parallel()
		ln, err := listenTCP(t)
		if err != nil {
			t.Fatal(err)
		}
		dead := ln.Addr().String()
		_ = ln.Close()
		if err := coreHealthcheck(t.Context(), dead, missing, time.Second); err == nil {
			t.Fatal("nothing listens")
		}
	})
	t.Run("slow answers fail within the deadline", func(t *testing.T) {
		t.Parallel()
		release := make(chan struct{})
		a, c := healthServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		t.Cleanup(func() { close(release) })
		start := time.Now()
		if err := coreHealthcheck(t.Context(), a, c, 300*time.Millisecond); err == nil {
			t.Fatal("a server that never answers is unhealthy")
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("took %s, the deadline was 300ms", d)
		}
	})
	t.Run("a server that accepts and never speaks TLS fails within the deadline", func(t *testing.T) {
		t.Parallel()
		ln, err := listenTCP(t)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				t.Cleanup(func() { _ = c.Close() })
			}
		}()
		start := time.Now()
		if err := coreHealthcheck(t.Context(), ln.Addr().String(), missing, 300*time.Millisecond); err == nil {
			t.Fatal("want an error")
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("took %s", d)
		}
	})
}

// The check asks for a TLS 1.2+ listener only: a plain HTTP server on the port is not core.
func TestCoreHealthcheckRefusesPlainHTTP(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(healthHandler(200))
	t.Cleanup(srv.Close)
	if err := coreHealthcheck(t.Context(), srv.Listener.Addr().String(), "", time.Second); err == nil {
		t.Fatal("plain HTTP is not core's TLS listener")
	}
}

func listenLoopback(t *testing.T) int {
	t.Helper()
	ln, err := listenTCP(t)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func writeConf(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "opencanary.conf")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHoneypotHealthcheck(t *testing.T) {
	t.Parallel()
	port := listenLoopback(t)
	ps := strconv.Itoa(port)
	t.Run("the configured port answers", func(t *testing.T) {
		t.Parallel()
		conf := writeConf(t, `{"ssh.enabled": true, "ssh.port": `+ps+`}`)
		if err := honeypotHealthcheck(t.Context(), conf, time.Second); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a disabled service is not looked at", func(t *testing.T) {
		t.Parallel()
		conf := writeConf(t, `{"ssh.enabled": false, "ssh.port": 1, "http.enabled": true, "http.port": `+ps+`}`)
		if err := honeypotHealthcheck(t.Context(), conf, time.Second); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the port is closed", func(t *testing.T) {
		t.Parallel()
		ln, err := listenTCP(t)
		if err != nil {
			t.Fatal(err)
		}
		closed := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		conf := writeConf(t, `{"rdp.enabled": true, "rdp.port": `+strconv.Itoa(closed)+`}`)
		if err := honeypotHealthcheck(t.Context(), conf, time.Second); err == nil {
			t.Fatal("a closed port is unhealthy")
		}
	})
	t.Run("nothing of OpenCanary enabled: nothing should listen, healthy", func(t *testing.T) {
		t.Parallel()
		conf := writeConf(t, `{"ssh.enabled": false, "smb.enabled": true}`)
		if err := honeypotHealthcheck(t.Context(), conf, time.Second); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing, junk or oversized configuration is unhealthy", func(t *testing.T) {
		t.Parallel()
		for name, conf := range map[string]string{
			"missing":  filepath.Join(t.TempDir(), "none"),
			"junk":     writeConf(t, "not json"),
			"array":    writeConf(t, `[1]`),
			"badport":  writeConf(t, `{"ssh.enabled": true, "ssh.port": 70000}`),
			"strport":  writeConf(t, `{"ssh.enabled": true, "ssh.port": "22"}`),
			"nullport": writeConf(t, `{"ssh.enabled": true, "ssh.port": null}`),
			"fltport":  writeConf(t, `{"ssh.enabled": true, "ssh.port": 22.5}`),
			"toolarge": writeConf(t, `{"x": "`+strings.Repeat("a", honeypotConfMax)+`"}`),
		} {
			if err := honeypotHealthcheck(t.Context(), conf, time.Second); err == nil {
				t.Errorf("%s: want an error", name)
			}
		}
	})
	t.Run("a listener that never accepts still passes (the connect is the check) and a context cancel fails fast", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		conf := writeConf(t, `{"ssh.enabled": true, "ssh.port": `+ps+`}`)
		if err := honeypotHealthcheck(ctx, conf, time.Second); err == nil {
			t.Fatal("a cancelled context must fail")
		}
	})
}

// The real configuration core writes: the keys the check reads are the keys RenderConfig writes, so a rename on either side fails here.
func TestFirstTrapPortReadsWhatRenderConfigWrites(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		enabled []honeypot.ServiceName
		want    int
	}{
		{[]honeypot.ServiceName{honeypot.SMB, honeypot.SSH, honeypot.HTTP}, honeypot.SSH.Port()},
		{[]honeypot.ServiceName{honeypot.HTTP}, honeypot.HTTP.Port()},
		{[]honeypot.ServiceName{honeypot.SMB}, 0}, // Samba's, not OpenCanary's
		{nil, 0},
	} {
		b, err := honeypot.RenderConfig(honeypot.ConfigInput{Enabled: tc.enabled, LogPath: "/var/lib/vedette/honeypot/log/opencanary.jsonl"})
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), honeypot.ConfFile)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := firstTrapPort(p)
		if err != nil || got != tc.want {
			t.Errorf("enabled %v: port %d, %v; want %d", tc.enabled, got, err, tc.want)
		}
	}
}

func TestHealthCommand(t *testing.T) {
	t.Parallel()
	for args, want := range map[string]string{"healthcheck": "core", "honeypot healthcheck": "honeypot"} {
		if k, ok := healthCommand(strings.Fields(args)); !ok || k != want {
			t.Errorf("%q = %q, %v", args, k, ok)
		}
	}
	for _, args := range []string{"", "healthchek", "healthcheck now", "honeypot", "honeypot healthchek", "honeypot healthcheck x", "-listen :8443", "serve"} {
		if _, ok := healthCommand(strings.Fields(args)); ok {
			t.Errorf("%q must not be a health command", args)
		}
	}
	// run takes the health path before any flag: extra arguments fall through to the flag parser, which refuses them
	if err := run(t.Context(), []string{"healthcheck", "now"}, os.Stdout, os.Stderr); err == nil {
		t.Fatal("healthcheck takes no arguments")
	}
}

// The gate for HealthCmd= of the core and honeypot units: argv[0] is the binary's path in the image, the arguments are a health
// command of this very binary, and what the check opens is what the unit provides: core's check reaches the port the unit
// publishes and the certificate in the data volume, the honeypot's reads the config folder the unit mounts.
func TestCoreAndHoneypotUnitsHealthCmdMatchTheRealCommands(t *testing.T) {
	t.Parallel()
	render := func(svc string) (health []string, publish, volumes []string) {
		t.Helper()
		var interval, start, retries, ro, tmpfs string
		text, err := ops.RenderUnit(svc, "sha256:"+strings.Repeat("a", 64), true, 10001, 10002, 10003, 10004)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(string(text), "\n") {
			k, v, _ := strings.Cut(l, "=")
			switch k {
			case "HealthCmd":
				if err := json.Unmarshal([]byte(v), &health); err != nil {
					t.Fatalf("%s: HealthCmd=%q must be a JSON array (exec form, not run through /bin/sh -c): %v", svc, v, err)
				}
			case "HealthInterval":
				interval = v
			case "HealthStartPeriod":
				start = v
			case "HealthRetries":
				retries = v
			case "ReadOnly":
				ro = v
			case "Tmpfs":
				tmpfs = v
			case "PublishPort":
				publish = append(publish, v)
			case "Volume":
				volumes = append(volumes, v)
			}
		}
		if interval != "30s" || retries != "3" {
			t.Errorf("%s: HealthInterval=%q HealthRetries=%q, want 30s and 3", svc, interval, retries)
		}
		wantStart := map[string]string{"core": "60s", "honeypot": "30s"}[svc]
		if start != wantStart {
			t.Errorf("%s: HealthStartPeriod=%q, want %s", svc, start, wantStart)
		}
		wantTmpfs := "/tmp"
		if svc == "core" {
			wantTmpfs = "/tmp:size=64m" // core's tmpfs is bounded (D-150)
		}
		if ro != "true" || tmpfs != wantTmpfs {
			t.Errorf("%s: ReadOnly=%q Tmpfs=%q, want true and /tmp (core: /tmp:size=64m)", svc, ro, tmpfs)
		}
		return health, publish, volumes
	}
	targets := func(volumes []string) map[string]string {
		m := map[string]string{}
		for _, v := range volumes {
			if p := strings.Split(v, ":"); len(p) >= 2 {
				m[p[1]] = v
			}
		}
		return m
	}

	health, publish, volumes := render("core")
	if len(health) < 2 || health[0] != "/vedette" {
		t.Fatalf("core HealthCmd=%v must run /vedette", health)
	}
	if kind, ok := healthCommand(health[1:]); !ok || kind != "core" {
		t.Fatalf("core HealthCmd=%v is not the core health command of the binary", health)
	}
	_, port, _ := net.SplitHostPort(coreHealthAddr)
	if len(publish) == 0 || !strings.HasSuffix(publish[0], ":"+port) {
		t.Errorf("the check connects to %s but the unit publishes %v", coreHealthAddr, publish)
	}
	var o options
	flags, _ := newFlags(&o, os.Stderr)
	if err := flags.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if got := targets(volumes); got[path.Dir(coreCertFile)] == "" || path.Dir(coreCertFile) != path.Dir(o.db) {
		t.Errorf("the box's certificate %s is not next to -db %s in a mounted volume %v", coreCertFile, o.db, got)
	}

	health, _, volumes = render("honeypot")
	if len(health) < 2 || health[0] != "/vedette" {
		t.Fatalf("honeypot HealthCmd=%v must run /vedette", health)
	}
	if kind, ok := healthCommand(health[1:]); !ok || kind != "honeypot" {
		t.Fatalf("honeypot HealthCmd=%v is not the honeypot health command of the binary", health)
	}
	if o.honeypotDir != defaultHoneypotDir {
		t.Errorf("-honeypot-dir default %q != %q", o.honeypotDir, defaultHoneypotDir)
	}
	if got := targets(volumes); got[path.Join(defaultHoneypotDir, "config")] == "" {
		t.Errorf("the honeypot unit does not mount %s/config: %v", defaultHoneypotDir, got)
	}
}
