package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/knt048/vedette/modules/honeypot"
)

// The container health checks (D-137): `vedette healthcheck` (core) and `vedette honeypot healthcheck` (the honeypot image), the
// HealthCmd= lines of the units in host/ops/quadlet.go. Neither takes arguments, because the unit passes none; neither opens the
// database or reads the master key, so a check cannot hold a lock or leak a secret. Failure is one short line on stderr and exit 1
// (main prints the error). healthCommand is the one place that decides which of them an argv is, and the gate test of the units
// parses their HealthCmd= (a JSON array, the exec form, D-137) through it.
const (
	defaultHoneypotDir = "/var/lib/vedette/honeypot" // the default of -honeypot-dir, and where the honeypot unit mounts config/ and log/

	// coreHealthAddr is core's own listener inside its container: the unit publishes 8443 and runs -listen :8443 (TLS, because
	// the address is not loopback). coreHealthPath is the cheapest public route that reaches the database: it reads the
	// organisation row, so a 200 means the server, the router, the Host check and the database all answer.
	coreHealthAddr = "127.0.0.1:8443"
	coreHealthPath = "/api/v1/setup"
	// coreCertFile is the box's own certificate in the data volume (transport() in main.go makes it next to -db).
	coreCertFile    = "/var/lib/vedette/vedette-selfsigned.crt"
	coreHealthLimit = 3 * time.Second

	honeypotHealthLimit = 2 * time.Second
	healthBodyLimit     = 64 << 10
	honeypotConfMax     = 1 << 20
)

// healthCommand says which health check args ask for: "core" for `healthcheck`, "honeypot" for `honeypot healthcheck`.
func healthCommand(args []string) (kind string, ok bool) {
	switch {
	case len(args) == 1 && args[0] == "healthcheck":
		return "core", true
	case len(args) == 2 && args[0] == "honeypot" && args[1] == "healthcheck":
		return "honeypot", true
	}
	return "", false
}

func runHealthCommand(ctx context.Context, kind string) error {
	switch kind {
	case "core":
		return coreHealthcheck(ctx, coreHealthAddr, coreCertFile, coreHealthLimit)
	default:
		return honeypotHealthcheck(ctx, filepath.Join(defaultHoneypotDir, "config", honeypot.ConfFile), honeypotHealthLimit)
	}
}

// coreHealthcheck asks core's own HTTPS listener on addr for coreHealthPath and wants a 200 within limit.
//
// Trust. A leaf that Vedette made (Organization selfSignedOrg, tls.go) is pinned to certFile: it must be byte-for-byte the box's
// own certificate (a self-signed pair has no CA to verify against, and the name and expiry of a pinned leaf say nothing the pin
// does not). A leaf of any other organisation is one the owner supplied with -tls-cert: certFile is then not what is served, so
// there is nothing to pin against and verification is skipped, as it is when certFile cannot be read. That is safe here
// because the only thing sent is an unauthenticated GET with no cookie or credential, the address is loopback inside core's own
// container (no network carries it), and the answer is used only as "up": nothing from the body is trusted or kept.
// An unreadable certificate file is not an unhealthy box; a certificate file that is present and wrong is.
func coreHealthcheck(ctx context.Context, addr, certFile string, limit time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	pin, err := loadPin(certFile)
	if err != nil {
		return err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "127.0.0.1", InsecureSkipVerify: true} //nolint:gosec // see above: loopback only, pinned when the certificate is readable; VerifyConnection below does the check
	if pin != nil {
		cfg.VerifyConnection = func(cs tls.ConnectionState) error { // also runs on a resumed session
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the server presented no certificate")
			}
			leaf := cs.PeerCertificates[0]
			if !slices.Contains(leaf.Subject.Organization, selfSignedOrg) {
				return nil // an owner certificate (-tls-cert): see above
			}
			if !bytes.Equal(leaf.Raw, pin) {
				return errors.New("the certificate is not the box's own")
			}
			return nil
		}
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             nil, // never a proxy, whatever the environment says
			TLSClientConfig:   cfg,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+coreHealthPath, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("core does not answer on %s: %w", addr, unwrapURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, healthBodyLimit))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("core answered %d, want 200", resp.StatusCode)
	}
	return nil
}

// loadPin returns the DER of the first certificate in certFile, nil when the file cannot be read (see coreHealthcheck), an error
// when it can be read and holds none.
func loadPin(certFile string) ([]byte, error) {
	data, err := os.ReadFile(certFile) //nolint:gosec // a constant path in production, a test path in tests
	if err != nil {
		return nil, nil //nolint:nilerr // documented above: no readable certificate, no pin
	}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return nil, fmt.Errorf("%s holds no certificate", certFile)
		}
		if b.Type == "CERTIFICATE" {
			return b.Bytes, nil
		}
	}
}

// unwrapURL drops the *url.Error wrapper, whose text repeats the whole URL.
func unwrapURL(err error) error {
	var ue interface{ Unwrap() error }
	if errors.As(err, &ue) {
		return ue.Unwrap()
	}
	return err
}

// honeypotHealthcheck connects to one port OpenCanary was configured to listen on, on 127.0.0.1, within limit. The port comes
// from opencanary.conf, which core writes and the unit mounts read-only: never a number in this code. In the namespace vedette-hp
// `lo` is up and the output chain accepts `oif lo` (D-121 L8), so a loopback connection works there. The connection is a hit
// the trap logs from 127.0.0.1, which core drops as a source that cannot be real (D-89 (e)).
//
// Only services with a port key count: `smb` has none (OpenCanary only follows the log of Samba, the port is Samba's), so a
// configuration with no other trap enabled has nothing of OpenCanary's to connect to, and the check is healthy: nothing
// is supposed to be listening.
func honeypotHealthcheck(ctx context.Context, confFile string, limit time.Duration) error {
	port, err := firstTrapPort(confFile)
	if err != nil {
		return err
	}
	if port == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	conn, err := new(net.Dialer).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("the trap on port %d does not answer: %w", port, unwrapURL(err))
	}
	return conn.Close()
}

// firstTrapPort reads the configuration and returns the port of the first enabled service (in honeypot.Services order) that has one,
// 0 when there is none.
func firstTrapPort(confFile string) (int, error) {
	f, err := os.Open(confFile) //nolint:gosec // a constant path in production, a test path in tests
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, errors.New("opencanary.conf is missing")
		}
		return 0, fmt.Errorf("opencanary.conf: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, honeypotConfMax+1))
	if err != nil || len(data) > honeypotConfMax {
		return 0, errors.New("opencanary.conf cannot be read or is too large")
	}
	var conf map[string]json.RawMessage
	if err := json.Unmarshal(data, &conf); err != nil {
		return 0, errors.New("opencanary.conf is not a JSON object")
	}
	for _, s := range honeypot.Services {
		var on bool
		if json.Unmarshal(conf[string(s)+".enabled"], &on) != nil || !on {
			continue
		}
		raw, has := conf[string(s)+".port"]
		if !has {
			continue // no port key: not a listener of OpenCanary's
		}
		var port int
		if json.Unmarshal(raw, &port) != nil {
			return 0, fmt.Errorf("opencanary.conf: %s.port is not an integer", s) // present but unreadable: fail closed
		}
		if port < 1 || port > 65535 {
			return 0, fmt.Errorf("opencanary.conf: %s.port is %d", s, port)
		}
		return port, nil
	}
	return 0, nil
}
