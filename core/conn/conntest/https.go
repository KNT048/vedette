package conntest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/knt048/vedette/core/conn/internal/transport"
)

// Req is one request an HTTPS fake received.
type Req struct {
	Method, Path, RawQuery string
	Header                 http.Header
	Body                   []byte
}

// HTTPS is an HTTPS server on loopback with a self-signed certificate. URL is what a connection's target would be.
type HTTPS struct {
	Host string // the name that reaches it
	URL  string // https://Host:port

	srv  *httptest.Server
	cert atomic.Pointer[tls.Certificate]
	mu   sync.Mutex
	reqs []Req
}

// NewHTTPS starts the fake; h answers every request (nil answers 200 {"ok":true}). Every request is recorded before h sees it.
func NewHTTPS(t testing.TB, h http.Handler) *HTTPS {
	t.Helper()
	if h == nil {
		h = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		})
	}
	s := &HTTPS{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		r.Body = io.NopCloser(bytes.NewReader(b))
		s.mu.Lock()
		s.reqs = append(s.reqs, Req{Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery, Header: r.Header.Clone(), Body: b})
		s.mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	ln := srv.Listener // httptest listens on 127.0.0.1
	s.Host = AllowLoopback(t, ln)
	c := NewCert(t, s.Host)
	s.cert.Store(&c)
	// GetConfigForClient, not GetCertificate: a client that dials an IP address sends no server name, and then the library would
	// serve Certificates[0] and never ask. Rotate must reach every client.
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{Certificates: []tls.Certificate{*s.cert.Load()}, MinVersion: tls.VersionTLS12}, nil
		},
	}
	srv.EnableHTTP2 = false
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // a client that refuses the certificate is part of the tests, not noise
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.srv = srv
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	s.URL = "https://" + s.Host + ":" + port
	return s
}

// Requests are the requests received so far.
func (s *HTTPS) Requests() []Req {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Req(nil), s.reqs...)
}

// SPKISHA256 is the pin of the certificate the server shows now.
func (s *HTTPS) SPKISHA256() string { return SPKISHA256(*s.cert.Load()) }

// Rotate gives the server a new certificate: the pin of the old one no longer matches.
func (s *HTTPS) Rotate(t testing.TB) {
	t.Helper()
	c := NewCert(t, s.Host)
	s.cert.Store(&c)
}

// Reissue gives the server a new certificate for the same key: the pin of the public key still matches.
func (s *HTTPS) Reissue(t testing.TB) {
	t.Helper()
	c := certFor(t, s.cert.Load().PrivateKey.(*ecdsa.PrivateKey), s.Host)
	s.cert.Store(&c)
}

// Roots is a pool that trusts the server's current certificate, to test a server that a public authority vouches for.
func (s *HTTPS) Roots() *x509.CertPool {
	p := x509.NewCertPool()
	c, _ := x509.ParseCertificate(s.cert.Load().Certificate[0])
	p.AddCert(c)
	return p
}

// Redirect makes every dial to from ("192.168.10.64:443": an address the policy allows, like a LAN device) reach this server, so a
// test can use a connection saved with an ordinary address without sending a packet to it.
func (s *HTTPS) Redirect(t testing.TB, from string) {
	t.Helper()
	f, err := netip.ParseAddrPort(from)
	if err != nil {
		t.Fatalf("conntest: %v", err)
	}
	to, err := netip.ParseAddrPort(s.srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("conntest: %v", err)
	}
	t.Cleanup(transport.RedirectForTest(f, to))
}
