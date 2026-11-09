package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/server"
)

// Self-signed certificate lifetime (WP-04b part 2): 825 days, the longest Apple platforms accept for a
// certificate (support.apple.com/en-us/103769, HT210176), the same as mkcert. The box makes a new one at
// start-up, and once a day while running, when its own pair expires within selfSignedRenewBefore (a new
// certificate for the same key, served without a restart); browsers still warn about a self-signed certificate, and the owner who wants a clean padlock
// passes -tls-cert and -tls-key (a certificate the owner supplies is never replaced).
const (
	selfSignedLifetime    = 825 * 24 * time.Hour
	selfSignedRenewBefore = 30 * 24 * time.Hour
	// selfSignedCheckEvery is how often a running box looks at its own certificate.
	selfSignedCheckEvery = 24 * time.Hour
	// selfSignedOrg marks the certificates this file makes: only those are renewed.
	selfSignedOrg = "Vedette (self-signed)"
)

var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// parseHosts splits the -hosts flag (comma separated names and IP addresses, ports allowed and dropped) into
// canonical entries. A name that cannot be a host name is refused: it would end up in a certificate. A name
// may start with "*." to cover one label, like a wildcard certificate (*.corp.example is box.corp.example,
// not a.b.corp.example nor corp.example) and needs at least two labels after "*." (*.com is refused;
// *.co.uk is accepted, there is no public-suffix list here).
func parseHosts(flag string) ([]string, error) {
	var out []string
	for _, h := range strings.Split(flag, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if host, port, err := net.SplitHostPort(h); err == nil {
			if _, perr := strconv.ParseUint(port, 10, 16); perr != nil {
				return nil, fmt.Errorf("-hosts: %q is not a host name or an IP address", h)
			}
			h = host
		}
		h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
		if a, err := netip.ParseAddr(h); err == nil {
			out = append(out, a.Unmap().WithZone("").String())
			continue
		}
		h = strings.ToLower(strings.TrimSuffix(h, "."))
		if !hostRE.MatchString(strings.TrimPrefix(h, "*.")) {
			return nil, fmt.Errorf("-hosts: %q is not a host name or an IP address", h)
		}
		if strings.HasPrefix(h, "*.") && !server.ValidWildcard(h) {
			return nil, fmt.Errorf("-hosts: %q is too broad or IP-shaped: a wildcard needs at least two labels after \"*.\" (*.corp.example) and never stands for an IP address", h)
		}
		out = append(out, h)
	}
	return out, nil
}

// localNames is what a self-signed certificate covers besides -hosts: the loopback names, the machine's host
// name and the addresses of its interfaces (so that opening the box by its LAN address works on first start).
func localNames() []string {
	out := []string{"localhost", "127.0.0.1", "::1"}
	if h, err := os.Hostname(); err == nil && hostRE.MatchString(h) {
		out = append(out, strings.ToLower(h))
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipn.IP); ok && !ip.IsLinkLocalUnicast() && !ip.IsMulticast() && !ip.IsUnspecified() {
					out = append(out, ip.Unmap().String())
				}
			}
		}
	}
	return out
}

// ensureCert creates the self-signed certificate and its key on first start, like ensureKey: P-256, 825
// days, both files mode 0600, the names of hosts (plus localNames) as subject alternative names. When the key
// file exists the pair is kept as it is (the owner may have put their own there), except that a pair this
// function made (subject organization selfSignedOrg) that expires within 30 days gets a new certificate for
// the same key, so a box that restarts now and then never runs out; delete both files to have new ones made.
// A key without its certificate is an error; a certificate without its key is a leftover of an interrupted
// first start and is replaced.
func ensureCert(certPath, keyPath string, hosts []string) error {
	return ensureCertAt(certPath, keyPath, hosts, time.Now)
}

// ensureCertAt is ensureCert with the clock injected.
func ensureCertAt(certPath, keyPath string, hosts []string, now func() time.Time) error {
	if _, err := os.Lstat(keyPath); err == nil {
		if _, err := os.Lstat(certPath); err != nil {
			return fmt.Errorf("tls: %s exists but %s does not: restore the certificate or delete the key to make a new pair", keyPath, certPath)
		}
		_, err := renewSelfSigned(certPath, keyPath, hosts, now)
		return err
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("tls key file: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("tls: generate key: %w", err)
	}
	certPEM, err := selfSignedPEM(key, hosts, now())
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("tls: encode key: %w", err)
	}
	if err := writeAtomic(certPath, certPEM); err != nil {
		return err
	}
	return writeAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

// renewSelfSigned replaces the certificate of a pair this program made when it expires within
// selfSignedRenewBefore of now(), signing with the key already there (one atomic file write: a crash cannot
// leave a certificate that does not match the key). It reports whether it replaced it. A pair it cannot
// read, or one that is not its own, is left for loadTLS to judge.
func renewSelfSigned(certPath, keyPath string, hosts []string, now func() time.Time) (bool, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return false, nil //nolint:nilerr // loadTLS reports a pair that cannot be loaded, with the file names
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || !slices.Contains(leaf.Subject.Organization, selfSignedOrg) || leaf.NotAfter.Sub(now()) > selfSignedRenewBefore {
		return false, nil //nolint:nilerr // see above
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return false, nil
	}
	certPEM, err := selfSignedPEM(signer, hosts, now())
	if err != nil {
		return false, err
	}
	return true, writeAtomic(certPath, certPEM)
}

// selfSignedRenewer serves the box's own self-signed pair through tls.Config.GetCertificate and swaps in
// the renewed certificate while the process runs (a box that is never restarted would otherwise let it
// expire after 825 days). It only ever touches the pair the box made, never an owner's -tls-cert.
type selfSignedRenewer struct {
	certPath, keyPath string
	hosts             []string
	now               func() time.Time

	mu   sync.RWMutex
	cert *tls.Certificate
}

// GetCertificate is tls.Config.GetCertificate.
func (r *selfSignedRenewer) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// Check renews the pair when it is near expiry and loads the new certificate for new handshakes.
func (r *selfSignedRenewer) Check() error {
	replaced, err := renewSelfSigned(r.certPath, r.keyPath, r.hosts, r.now)
	if err != nil || !replaced {
		return err
	}
	pair, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("tls: load renewed certificate: %w", err)
	}
	r.mu.Lock()
	r.cert = &pair
	r.mu.Unlock()
	return nil
}

// Run calls Check on every tick (the box passes a daily one) until ctx is done; a failure is logged and
// tried again at the next tick.
func (r *selfSignedRenewer) Run(ctx context.Context, log *slog.Logger, tick <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			if err := r.Check(); err != nil {
				log.ErrorContext(ctx, "renewing the self-signed certificate failed", "error", err)
			}
		}
	}
}

// selfSignedPEM makes a self-signed server certificate for key, valid selfSignedLifetime, for hosts and
// localNames.
func selfSignedPEM(key crypto.Signer, hosts []string, now time.Time) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("tls: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Vedette", Organization: []string{selfSignedOrg}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(selfSignedLifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	seen := map[string]bool{}
	for _, h := range append(append([]string(nil), hosts...), localNames()...) {
		if seen[h] {
			continue
		}
		seen[h] = true
		if a, err := netip.ParseAddr(h); err == nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, net.IP(a.AsSlice()))
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("tls: create certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// writeAtomic writes data to path with mode 0600 through a temporary file in the same directory, so a crash
// never leaves a half-written file under the final name.
func writeAtomic(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(f.Name())
		}
	}()
	if err = f.Chmod(0o600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("tls: write %s: %w", path, err)
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	return nil
}

// checkKeyFile refuses a TLS private key that is not a regular file (a symlink to one is fine: certbot
// links its live key) or that group or other users can read, like core/secrets does for the master key: a
// key others can read lets them impersonate the box to every administrator.
func checkKeyFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("tls: private key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("tls: private key %s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("tls: private key %s has mode %#o; group and other access must be off (chmod 600)", path, perm)
	}
	return nil
}

// loadTLS loads the pair and returns the server configuration and the names the certificate covers (its
// DNS names and addresses; the common name only when it has none, as old certificates were).
func loadTLS(certPath, keyPath string) (*tls.Config, []string, error) {
	if err := checkKeyFile(keyPath); err != nil {
		return nil, nil, err
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: load certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("tls: parse certificate: %w", err)
	}
	if now := time.Now(); now.After(leaf.NotAfter) {
		return nil, nil, fmt.Errorf("tls: the certificate %s expired on %s", certPath, leaf.NotAfter.Format(time.DateOnly))
	}
	names := append([]string(nil), leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok {
			names = append(names, a.Unmap().String())
		}
	}
	if len(names) == 0 {
		if cn := strings.ToLower(leaf.Subject.CommonName); hostRE.MatchString(strings.TrimPrefix(cn, "*.")) {
			names = append(names, cn)
		}
	}
	// HTTP/1.1 only: the stack is built and tested for it, and h2 would add attack surface for nothing here.
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}, names, nil
}
