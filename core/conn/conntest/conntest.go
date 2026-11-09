// Package conntest holds the fakes that the tests of core/conn, modules/core and cmd/vedette connect to: an HTTPS server, an SSH
// server and an MCP server, in process, on 127.0.0.1. Production code must never import it (TestConntestIsOnlyImportedByTests),
// and it is the only way a test reaches the loopback address that the address policy refuses: AllowLoopback opens one socket
// of one listener and gives it a name, for as long as the test runs.
package conntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/conn/internal/transport"
)

var names atomic.Int64

// AllowLoopback lets the dialer connect to the listener's socket, and only to that, until the test ends. It returns the host name
// that reaches it ("dev3.device.test"): a connection saved with that name in its target goes to the fake, while the address
// policy still refuses 127.0.0.1 and localhost typed by anybody. Loopback has no other path.
func AllowLoopback(t testing.TB, ln net.Listener) string {
	t.Helper()
	ap, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("conntest: listener address: %v", err)
	}
	name := fmt.Sprintf("dev%d.device.test", names.Add(1))
	t.Cleanup(transport.AllowSocketForTest(name, ap))
	return name
}

// NewCert makes a self-signed certificate for the names and 127.0.0.1: one that no public authority vouches for.
func NewCert(t testing.TB, dns ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "vedette test device"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: dns, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// LeafSHA256 is the hex SHA-256 of a certificate: the value of a TLS pin.
func LeafSHA256(c tls.Certificate) string {
	sum := sha256.Sum256(c.Certificate[0])
	return hex.EncodeToString(sum[:])
}

// ResolveTo makes a name reach an address that the policy may refuse, without opening any socket to it: the test of "a name that
// points at the metadata service or at the box". It returns the name.
func ResolveTo(t testing.TB, ip string) string {
	t.Helper()
	a, err := netip.ParseAddr(ip)
	if err != nil {
		t.Fatalf("conntest: %v", err)
	}
	name := fmt.Sprintf("dev%d.device.test", names.Add(1))
	t.Cleanup(transport.ResolveForTest(name, a))
	return name
}
