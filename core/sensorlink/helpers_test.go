package sensorlink_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
)

var t0 = time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)

// clock is the seam for every time the server and the client look at.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: t0} }
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// testCA is an ephemeral CA the tests mint certificates from, so that every shape of bad certificate can be made.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t testing.TB) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test sensor CA"},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// leafOpts describes a leaf; the zero value is a good passive client certificate.
type leafOpts struct {
	serial    int64
	uris      []string // nil = the passive URI
	noURI     bool
	eku       []x509.ExtKeyUsage // nil = clientAuth
	notBefore time.Time
	notAfter  time.Time
	ips       []net.IP
	dns       []string
	other     *testCA // sign with another CA
	isCA      bool
}

func (ca *testCA) leaf(t testing.TB, o leafOpts) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if o.serial == 0 {
		o.serial = 100
	}
	if o.eku == nil {
		o.eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if o.notBefore.IsZero() {
		o.notBefore = t0.Add(-time.Minute)
	}
	if o.notAfter.IsZero() {
		o.notAfter = t0.Add(7 * 24 * time.Hour)
	}
	var uris []*url.URL
	if !o.noURI {
		us := o.uris
		if us == nil {
			us = []string{"vedette:sensor:passive"}
		}
		for _, s := range us {
			u, err := url.Parse(s)
			if err != nil {
				t.Fatal(err)
			}
			uris = append(uris, u)
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(o.serial), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: o.notBefore, NotAfter: o.notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: o.eku,
		URIs: uris, IPAddresses: o.ips, DNSNames: o.dns, BasicConstraintsValid: true, IsCA: o.isCA,
	}
	signer := ca
	if o.other != nil {
		signer = o.other
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer.cert, &key.PublicKey, signer.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
}

func (ca *testCA) serverLeaf(t testing.TB) tls.Certificate {
	return ca.leaf(t, leafOpts{serial: 7, noURI: true, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ips: []net.IP{net.IPv4(127, 0, 0, 1)}, dns: []string{"core"}})
}

// bundle is the PEM a role reads: key, leaf, CA.
func (ca *testCA) bundle(t testing.TB, c tls.Certificate) []byte {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	_ = pem.Encode(&b, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})
	_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	return b.Bytes()
}

// fakeIdentity is a sensorlink.Identity over a testCA; valid serials are set by the test.
type fakeIdentity struct {
	ca     *testCA
	server tls.Certificate
	mu     sync.Mutex
	valid  map[sensorlink.Role]map[int64]bool
}

func newIdentity(t testing.TB, ca *testCA) *fakeIdentity {
	return &fakeIdentity{ca: ca, server: ca.serverLeaf(t), valid: map[sensorlink.Role]map[int64]bool{}}
}

func (i *fakeIdentity) allow(role sensorlink.Role, serials ...int64) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.valid[role] = map[int64]bool{}
	for _, s := range serials {
		i.valid[role][s] = true
	}
}
func (i *fakeIdentity) ClientCAs() *x509.CertPool { return i.ca.pool }
func (i *fakeIdentity) ServerCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return &i.server, nil
}
func (i *fakeIdentity) SerialValid(role sensorlink.Role, s *big.Int) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return s.IsInt64() && i.valid[role][s.Int64()]
}

// fakeBackend answers every route with a canned reply; each func can be replaced by a test.
type fakeBackend struct {
	mu    sync.Mutex
	calls []string

	config func(ctx context.Context, wait time.Duration, inm string) (sensorlink.ConfigReply, error)
	obs    func(ctx context.Context, r *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error)
	jobs   func(ctx context.Context, wait time.Duration, running string) (sensorlink.JobsReply, error)
	result func(ctx context.Context, id string, r *sensorlink.JobResult) error
}

func (b *fakeBackend) called(name string) {
	b.mu.Lock()
	b.calls = append(b.calls, name)
	b.mu.Unlock()
}
func (b *fakeBackend) Calls() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.calls...)
}

const instanceID = "0123456789abcdef0123456789abcdef"

func (b *fakeBackend) Config(ctx context.Context, wait time.Duration, inm string) (sensorlink.ConfigReply, error) {
	b.called("config")
	if b.config != nil {
		return b.config(ctx, wait, inm)
	}
	if inm == `"e1"` {
		return sensorlink.ConfigReply{NotModified: true, ETag: `"e1"`}, nil
	}
	return sensorlink.ConfigReply{ETag: `"e1"`, Config: sensorlink.Config{Interface: "enp2s0", Span: true}}, nil
}
func (b *fakeBackend) Observations(ctx context.Context, r *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
	b.called("observations")
	if b.obs != nil {
		return b.obs(ctx, r)
	}
	return sensorlink.ObservationsReply{AckSeq: r.Seq}, nil
}
func (b *fakeBackend) PassiveHeartbeat(context.Context, *sensorlink.PassiveHeartbeat) (string, error) {
	b.called("heartbeat.passive")
	return instanceID, nil
}
func (b *fakeBackend) ActiveHeartbeat(context.Context, *sensorlink.ActiveHeartbeat) (string, error) {
	b.called("heartbeat.active")
	return instanceID, nil
}
func (b *fakeBackend) Jobs(ctx context.Context, wait time.Duration, running string) (sensorlink.JobsReply, error) {
	b.called("jobs")
	if b.jobs != nil {
		return b.jobs(ctx, wait, running)
	}
	return sensorlink.JobsReply{Instance: instanceID}, nil
}
func (b *fakeBackend) JobResult(ctx context.Context, id string, r *sensorlink.JobResult) error {
	b.called("result")
	if b.result != nil {
		return b.result(ctx, id, r)
	}
	return nil
}

// rig is a running sensor listener: the real tls.Config of the server on an httptest server.
type rig struct {
	ca  *testCA
	id  *fakeIdentity
	be  *fakeBackend
	clk *clock
	srv *sensorlink.Server
	ts  *httptest.Server

	mu      sync.Mutex
	serials []int64 // the leaf serial of each request, as the handler saw it
}

type rigOpt struct {
	moduleOn    func(sensorlink.Role) bool
	bodyTimeout time.Duration
	hdrTimeout  time.Duration
	http2       bool
}

func newRig(t *testing.T, o rigOpt) *rig {
	t.Helper()
	r := &rig{ca: newTestCA(t), be: &fakeBackend{}, clk: newClock()}
	r.id = newIdentity(t, r.ca)
	r.id.allow(sensorlink.Passive, 100, 101)
	r.id.allow(sensorlink.Active, 200, 201)
	srv, err := sensorlink.NewServer(sensorlink.Options{Identity: r.id, Backend: r.be, ModuleOn: o.moduleOn, Now: r.clk.Now, BodyTimeout: o.bodyTimeout})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = srv
	inner := srv.Handler()
	r.ts = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
			r.mu.Lock()
			r.serials = append(r.serials, req.TLS.PeerCertificates[0].SerialNumber.Int64())
			r.mu.Unlock()
		}
		inner.ServeHTTP(w, req)
	}))
	cfg := srv.TLSConfig()
	// httptest would add its own certificate when none is set; the real server serves through GetCertificate.
	cfg.Certificates = []tls.Certificate{r.id.server}
	r.ts.TLS = cfg
	r.ts.EnableHTTP2 = o.http2
	if o.hdrTimeout > 0 {
		r.ts.Config.ReadHeaderTimeout = o.hdrTimeout
	} else {
		r.ts.Config.ReadHeaderTimeout = sensorlink.ReadHeaderTimeout
	}
	r.ts.Config.WriteTimeout = sensorlink.WriteTimeout
	r.ts.StartTLS()
	t.Cleanup(r.ts.Close)
	return r
}

func (r *rig) addr() string { return r.ts.Listener.Addr().String() }

// peer is an http client that presents cert and trusts the CA the server leaf comes from.
type peer struct {
	c  *http.Client
	tr *http.Transport
}

func (r *rig) peer(t testing.TB, cert tls.Certificate) *peer {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: r.ca.pool, Certificates: []tls.Certificate{cert}, Time: r.clk.Now,
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
	}, DisableCompression: true}
	t.Cleanup(tr.CloseIdleConnections)
	return &peer{c: &http.Client{Transport: tr, Timeout: 20 * time.Second}, tr: tr}
}

type resp struct {
	status int
	hdr    http.Header
	body   string
	tls    *tls.ConnectionState
}

// call sends one request with the protocol header; extra headers override.
func (p *peer) call(t testing.TB, base, method, path string, body []byte, hdr map[string]string) (resp, error) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(sensorlink.ProtoHeader, sensorlink.ProtoVersion)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	res, err := p.c.Do(req)
	if err != nil {
		return resp{}, err
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return resp{status: res.StatusCode, hdr: res.Header, body: string(b), tls: res.TLS}, nil
}

func (r *rig) url() string { return "https://" + r.addr() }

func (r *rig) good(t testing.TB) *peer { return r.peer(t, r.ca.leaf(t, leafOpts{serial: 100})) }
func (r *rig) goodActive(t testing.TB) *peer {
	return r.peer(t, r.ca.leaf(t, leafOpts{serial: 200, uris: []string{"vedette:sensor:active"}}))
}

func writeFile(t testing.TB, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func nopBody(s string) *bytes.Reader { return bytes.NewReader([]byte(s)) }

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }
