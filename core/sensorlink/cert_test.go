package sensorlink_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
)

// selfSigned8443 is a certificate shaped like the one cmd/vedette/tls.go makes for the web UI on 8443: self-signed, both
// extended key usages, a SAN for the box. It even carries the passive role URI, to show that the name alone gets nobody in.
func selfSigned8443(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("vedette:sensor:passive")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{Organization: []string{"Vedette (self-signed)"}, CommonName: "box"},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(825 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, URIs: []*url.URL{u}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// D-109 (2), D-110 (1)(2): what the handshake refuses. Every case is refused with no HTTP answer and without touching the
// backend; the first row shows that a good certificate gets through the same rig.
func TestCertificatesRefused(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	other := newTestCA(t)
	srvAsClient := r.id.server
	for _, c := range []struct {
		name string
		cert tls.Certificate
		ok   bool
	}{
		{"a good passive leaf", r.ca.leaf(t, leafOpts{serial: 100}), true},
		{"a good active leaf", r.ca.leaf(t, leafOpts{serial: 200, uris: []string{"vedette:sensor:active"}}), true},
		{"signed by another CA", r.ca.leaf(t, leafOpts{serial: 100, other: other}), false},
		{"the self-signed certificate of 8443", selfSigned8443(t), false},
		{"expired", r.ca.leaf(t, leafOpts{serial: 100, notBefore: t0.Add(-48 * time.Hour), notAfter: t0.Add(-time.Minute)}), false},
		{"not yet valid", r.ca.leaf(t, leafOpts{serial: 100, notBefore: t0.Add(time.Hour)}), false},
		{"the server leaf used as a client (serverAuth only)", srvAsClient, false},
		{"serverAuth only with a role URI", r.ca.leaf(t, leafOpts{serial: 100, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}), false},
		{"clientAuth and serverAuth", r.ca.leaf(t, leafOpts{serial: 100, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}), false},
		{"any EKU", r.ca.leaf(t, leafOpts{serial: 100, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}), false},
		{"no EKU at all", r.ca.leaf(t, leafOpts{serial: 100, eku: []x509.ExtKeyUsage{}}), false},
		{"a role that does not exist", r.ca.leaf(t, leafOpts{serial: 100, uris: []string{"vedette:sensor:other"}}), false},
		{"the role in capitals", r.ca.leaf(t, leafOpts{serial: 100, uris: []string{"vedette:sensor:PASSIVE"}}), false},
		{"the role URI with a fragment", r.ca.leaf(t, leafOpts{serial: 100, uris: []string{"vedette:sensor:passive#x"}}), false},
		{"an https URI that names the role", r.ca.leaf(t, leafOpts{serial: 100, uris: []string{"https://vedette/sensor/passive"}}), false},
		{"two role URIs", r.ca.leaf(t, leafOpts{serial: 100, uris: []string{"vedette:sensor:passive", "vedette:sensor:active"}}), false},
		{"no URI", r.ca.leaf(t, leafOpts{serial: 100, noURI: true}), false},
		{"a CA certificate", r.ca.leaf(t, leafOpts{serial: 100, isCA: true}), false},
		{"a serial that was never issued", r.ca.leaf(t, leafOpts{serial: 999}), false},
		{"a serial of the other role", r.ca.leaf(t, leafOpts{serial: 200}), false}, // passive URI, active serial
	} {
		p := r.peer(t, c.cert)
		got, err := p.call(t, r.url(), "POST", "/sensor/v1/heartbeat", []byte(hbSpan), nil)
		// The active leaf posts the passive body to the shared route, so its answer is a 400: it still got in.
		if c.ok && (err != nil || got.status == 403) {
			t.Errorf("%s: %v %d, want it to get in", c.name, err, got.status)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: got an HTTP answer (%d %s), want the handshake refused", c.name, got.status, got.body)
		}
	}
	for _, call := range r.be.Calls() {
		if call != "heartbeat.passive" {
			t.Errorf("unexpected backend call %q", call)
		}
	}
	if n := len(r.be.Calls()); n != 1 {
		t.Errorf("%d backend calls, want exactly the one of the good passive leaf: %v", n, r.be.Calls())
	}
}

// A client that does not present a certificate at all is refused too.
func TestNoClientCertificate(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: r.ca.pool, MinVersion: tls.VersionTLS13}}, Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(t.Context(), "GET", r.url()+"/sensor/v1/config", nil)
	if res, err := c.Do(req); err == nil {
		_ = res.Body.Close()
		t.Fatalf("an anonymous request got %d", res.StatusCode)
	}
}

// reused reports whether a request went over a connection that was already open.
func reused(t *testing.T, p *peer, base string) (int, bool, string) {
	t.Helper()
	var re bool
	ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { re = i.Reused }})
	req, _ := http.NewRequestWithContext(ctx, "POST", base+"/sensor/v1/heartbeat", nopBody(hbSpan))
	req.Header.Set(sensorlink.ProtoHeader, sensorlink.ProtoVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err := p.c.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	b := make([]byte, 400)
	n, _ := res.Body.Read(b)
	return res.StatusCode, re, string(b[:n])
}

// D-110 (5): the serial is checked on every request. A keep-alive connection outlives the retirement of its serial, so the
// handshake check is not enough.
func TestRetiredSerialOnALiveConnection(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	p := r.peer(t, r.ca.leaf(t, leafOpts{serial: 100}))
	if st, _, _ := reused(t, p, r.url()); st != 200 {
		t.Fatalf("first request: %d", st)
	}
	if st, re, _ := reused(t, p, r.url()); st != 200 || !re {
		t.Fatalf("second request: %d reused=%v; want 200 on the same connection", st, re)
	}
	r.id.allow(sensorlink.Passive, 101, 102) // serial 100 is retired by two rotations
	st, re, body := reused(t, p, r.url())
	if !re {
		t.Fatal("the test did not use the live connection")
	}
	if st != 403 || !contains(body, "cert_retired") {
		t.Errorf("retired serial on a live connection: %d %s, want 403 cert_retired", st, body)
	}
	// the server closed that connection, so the next request makes a new one and the handshake refuses the serial
	before := len(r.be.Calls())
	if got, err := p.call(t, r.url(), "POST", "/sensor/v1/heartbeat", []byte(hbSpan), nil); err == nil {
		t.Errorf("a retired serial got %d on a new connection", got.status)
	}
	if len(r.be.Calls()) != before {
		t.Error("the backend was reached by a retired serial")
	}
}

// D-109 (2): VerifyConnection runs on a resumed TLS 1.3 session; VerifyPeerCertificate would not. A session ticket from before
// the retirement must not get a retired serial back in.
func TestRetiredSerialOnAResumedSession(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	p := r.peer(t, r.ca.leaf(t, leafOpts{serial: 100}))
	call := func() (resp, error) { return p.call(t, r.url(), "POST", "/sensor/v1/heartbeat", []byte(hbSpan), nil) }
	if got, err := call(); err != nil || got.status != 200 {
		t.Fatalf("first: %v %d", err, got.status)
	}
	p.tr.CloseIdleConnections()
	got, err := call()
	if err != nil || got.status != 200 {
		t.Fatalf("second: %v %d", err, got.status)
	}
	if got.tls == nil || !got.tls.DidResume {
		t.Fatal("the second connection did not resume the TLS session; the test would prove nothing")
	}
	p.tr.CloseIdleConnections()
	r.id.allow(sensorlink.Passive, 101, 102)
	got, err = call()
	if err == nil {
		t.Fatalf("a resumed session with a retired serial got %d %s", got.status, got.body)
	}
	if n := len(r.be.Calls()); n != 2 {
		t.Errorf("backend calls = %d, want the 2 before the retirement", n)
	}
}

// D-110 (3): a certificate that expires on a connection that stays open is refused at the next request.
func TestExpiryOnALiveConnection(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	p := r.peer(t, r.ca.leaf(t, leafOpts{serial: 100}))
	if st, _, _ := reused(t, p, r.url()); st != 200 {
		t.Fatal("first request")
	}
	r.clk.Advance(8 * 24 * time.Hour)
	st, re, body := reused(t, p, r.url())
	if !re || st != 403 || !contains(body, "cert_retired") {
		t.Errorf("expired certificate on a live connection: %d reused=%v %s, want 403 cert_retired", st, re, body)
	}
}
