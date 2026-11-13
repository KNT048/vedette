package listen

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testCert makes a self-signed certificate for 127.0.0.1 at run time (no key is ever committed) and the pool that trusts it.
func testCert(t *testing.T, cn string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// tlsRig is a TLS server on loopback; GetCertificate counts how often it is asked.
type tlsRig struct {
	*rig
	pool  *x509.CertPool
	calls atomic.Int32
	cert  atomic.Pointer[tls.Certificate]
}

func newTLSRig(t *testing.T, lim Limits, withTLS bool) *tlsRig {
	t.Helper()
	tr := &tlsRig{rig: &rig{t: t, done: make(chan error, 1)}}
	c, pool := testCert(t, "first")
	tr.pool = pool
	tr.cert.Store(&c)
	var cfg *tls.Config
	if withTLS {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			tr.calls.Add(1)
			return tr.cert.Load(), nil
		}}
	}
	lim.BatchWait = 10 * time.Millisecond
	srv, err := New(Config{Host: "127.0.0.1", Ports: []int{0}, Sink: tr.sink, Log: slog.New(slog.DiscardHandler), Limits: lim, TLS: cfg})
	if err != nil {
		t.Fatal(err)
	}
	tr.srv = srv
	return tr
}

func (tr *tlsRig) tlsAddr() string {
	tr.t.Helper()
	var a net.Addr
	waitFor(tr.t, "the TLS socket", func() bool { a = tr.srv.TLSAddr(); return a != nil })
	return a.String()
}

func (tr *tlsRig) dial(addr string, pool *x509.CertPool) (*tls.Conn, error) {
	d := tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}}
	c, err := d.DialContext(context.Background(), "tcp4", addr)
	if err != nil {
		return nil, err
	}
	return c.(*tls.Conn), nil
}

func (r *rig) setSource(addr netip.Addr, proto string) {
	r.t.Helper()
	if err := r.srv.SetSources(map[netip.Addr]Source{addr: {ID: "src-1", Proto: proto}}); err != nil {
		r.t.Fatal(err)
	}
}

func TestTLSBothFramingsAreStoredFromTheDeclaredSender(t *testing.T) {
	t.Parallel()
	tr := newTLSRig(t, Limits{}, true)
	tr.start()
	tr.set("tls")
	c, err := tr.dial(tr.tlsAddr(), tr.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := io.WriteString(c, "<34>one\n10 <34>two ab<34>three\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "three lines", func() bool { return len(tr.lines()) == 3 })
	for _, l := range tr.lines() {
		if l.SourceID != "src-1" {
			t.Errorf("line %q has source %q", l.Text, l.SourceID)
		}
	}
	if st := tr.srv.Status(); !st.TLS || st.Conns != 1 {
		t.Errorf("status %+v", st)
	}
}

// The sender is checked before the handshake: a connection from an address that is not a TLS source gets no handshake and no data is read.
func TestTLSFromAnUnknownSenderIsDroppedBeforeTheHandshake(t *testing.T) {
	t.Parallel()
	tr := newTLSRig(t, Limits{}, true)
	tr.start()
	tr.setSource(netip.MustParseAddr("10.9.9.9"), "tls") // loopback is not declared
	addr := tr.tlsAddr()
	if _, err := tr.dial(addr, tr.pool); err == nil {
		t.Fatal("an undeclared sender completed a handshake")
	}
	waitFor(t, "the connection to be counted as unknown", func() bool { return tr.srv.Stats().Unknown == 1 })
	if n := tr.calls.Load(); n != 0 {
		t.Errorf("the certificate was asked for %d times for an undeclared sender: the handshake ran", n)
	}
	if n := len(tr.lines()); n != 0 {
		t.Errorf("%d lines stored", n)
	}
}

// A sender declared as plain TCP is not served on the TLS port, and the reverse.
func TestTLSPortServesOnlyTLSSources(t *testing.T) {
	t.Parallel()
	tr := newTLSRig(t, Limits{}, true)
	tr.start()
	tr.set("tcp")
	if a := tr.srv.TLSAddr(); a != nil {
		t.Fatalf("a TCP source opened the TLS socket: %v", a)
	}
}

func TestTLSHandshakeIsBoundedAndASilentClientIsClosed(t *testing.T) {
	t.Parallel()
	tr := newTLSRig(t, Limits{HandshakeTimeout: 100 * time.Millisecond}, true)
	tr.start()
	tr.set("tls")
	c, err := dialCtx("tcp4", tr.tlsAddr()) // connects and sends nothing
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	waitFor(t, "the silent connection to be counted", func() bool { return tr.srv.Status().Conns == 1 })
	waitFor(t, "the server to close it", func() bool { return tr.srv.Status().Conns == 0 })
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || isNetTimeout(err) {
		t.Errorf("the connection is still open on the client side: %v", err)
	}
	if n := tr.srv.Stats().HandshakeFailed; n != 1 {
		t.Errorf("HandshakeFailed = %d", n)
	}
}

func isNetTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// A plain-text client on the TLS port is refused and counted, and a TLS client is served in the same time.
func TestAPlainClientOnTheTLSPortDoesNotStallOthers(t *testing.T) {
	t.Parallel()
	tr := newTLSRig(t, Limits{}, true)
	tr.start()
	tr.set("tls")
	addr := tr.tlsAddr()
	plain, err := dialCtx("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plain.Close() }()
	_, _ = io.WriteString(plain, "<34>this is not TLS\n")
	waitFor(t, "the plain client to be counted as a failed handshake", func() bool { return tr.srv.Stats().HandshakeFailed == 1 })
	c, err := tr.dial(addr, tr.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = io.WriteString(c, "<34>over tls\n")
	waitFor(t, "the TLS line", func() bool { return len(tr.texts()) == 1 })
	if got := tr.texts()[0]; got != "<34>over tls" {
		t.Errorf("stored %q (the plain client's text must not be stored)", got)
	}
}

// A renewed certificate is served by the next handshake with no restart: GetCertificate is asked for each one.
func TestTLSCertificateRenewalIsPickedUpByTheNextHandshake(t *testing.T) {
	t.Parallel()
	tr := newTLSRig(t, Limits{}, true)
	tr.start()
	tr.set("tls")
	addr := tr.tlsAddr()
	c1, err := tr.dial(addr, tr.pool)
	if err != nil {
		t.Fatal(err)
	}
	_ = c1.Close()
	renewed, pool2 := testCert(t, "renewed")
	tr.cert.Store(&renewed)
	if _, err := tr.dial(addr, tr.pool); err == nil { // the old pool no longer trusts what the box presents
		t.Fatal("the old certificate is still served after the renewal")
	}
	c2, err := tr.dial(addr, pool2)
	if err != nil {
		t.Fatalf("the renewed certificate is not served: %v", err)
	}
	_ = c2.Close()
	if n := tr.calls.Load(); n < 3 {
		t.Errorf("GetCertificate called %d times for three handshakes", n)
	}
}

// With no TLS configuration (a loopback or dev box) nothing listens for TLS, whatever the sources say.
func TestNoTLSConfigMeansNoTLSSocket(t *testing.T) {
	t.Parallel()
	tr := newTLSRig(t, Limits{}, false)
	tr.start()
	tr.set("tls")
	tr.tcpAddr() // the plain sockets are open (D-443): Run has applied the sources
	if st := tr.srv.Status(); st.TLS || st.TLSErr != "" {
		t.Errorf("status %+v", st)
	}
	if a := tr.srv.TLSAddr(); a != nil {
		t.Errorf("a TLS socket is open without a TLS config: %v", a)
	}
}

// D-443: the TLS socket stays open when the last TLS source goes; the open connection of that source is cut, and a new one from the
// same address is closed before any handshake and counted.
func TestTheTLSSocketOutlivesItsLastSourceButItsConnectionsGo(t *testing.T) {
	t.Parallel()
	tr := newTLSRig(t, Limits{}, true)
	tr.start()
	tr.set("tls")
	addr := tr.tlsAddr()
	c, err := tr.dial(addr, tr.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	waitFor(t, "the connection", func() bool { return tr.srv.Status().Conns == 1 })
	if err := tr.srv.SetSources(nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the open connection to be cut", func() bool { return tr.srv.Status().Conns == 0 })
	if tr.srv.TLSAddr() == nil {
		t.Fatal("the TLS socket closed with its last source")
	}
	if c2, err := tr.dial(addr, tr.pool); err == nil {
		_ = c2.Close()
		t.Error("a sender that is no longer a source completed a handshake")
	}
	waitFor(t, "the refused connection to be counted", func() bool { return tr.srv.Stats().Unknown >= 1 })
}

// A TLS source and a TCP source can both be declared (different senders): both sockets are open.
func TestTLSAndTCPSourcesAreServedTogether(t *testing.T) {
	t.Parallel()
	tr := newTLSRig(t, Limits{}, true)
	tr.start()
	other := netip.MustParseAddr("10.1.1.1")
	if err := tr.srv.SetSources(map[netip.Addr]Source{lo: {ID: "src-1", Proto: "tls"}, other: {ID: "src-2", Proto: "tcp"}}); err != nil {
		t.Fatal(err)
	}
	tr.tlsAddr()
	tr.tcpAddr()
}

func TestTLSPortsFollowThePlainOnes(t *testing.T) {
	t.Parallel()
	got, err := tlsPorts([]int{514, 5514, 0, 65534})
	want := []int{6514, 5515, 0, 65535}
	if err != nil {
		t.Fatal(err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tlsPorts: %v, want %v", got, want)
			break
		}
	}
	for _, bad := range []int{65535, 70000, -1} {
		if _, err := tlsPorts([]int{bad}); err == nil {
			t.Errorf("tlsPorts accepted %d: its successor is not a port (0 would bind a random one)", bad)
		}
	}
}

// A plain port with no TLS successor opens no TLS socket and says why, instead of binding a random port.
func TestNoTLSPortAfterTheLastPort(t *testing.T) {
	t.Parallel()
	tr := newTLSRig(t, Limits{}, true)
	srv, err := New(Config{Host: "127.0.0.1", Ports: []int{65535}, Sink: tr.sink, Log: slog.New(slog.DiscardHandler), TLS: &tls.Config{MinVersion: tls.VersionTLS12}})
	if err != nil {
		t.Fatal(err)
	}
	tr.srv = srv
	tr.start()
	_ = srv.SetSources(map[netip.Addr]Source{lo: {ID: "src-1", Proto: "tls"}}) // the refusal is returned or only recorded, depending on whether Run has started
	waitFor(t, "the reason the TLS socket is not open", func() bool { return srv.Status().TLSErr != "" })
	if st := srv.Status(); st.TLS || srv.TLSAddr() != nil {
		t.Errorf("status %+v", st)
	}
}

// stuckConn is the raw socket of the server side of a stuck sender: once armed, a Write signals that it started and blocks until the
// connection is closed (a send buffer that never drains, without filling a real one).
type stuckConn struct {
	net.Conn
	armed    atomic.Bool
	writing  chan struct{}
	closed   chan struct{}
	closeOne sync.Once
}

func (c *stuckConn) Write(p []byte) (int, error) {
	if !c.armed.Load() {
		return c.Conn.Write(p)
	}
	select {
	case c.writing <- struct{}{}:
	default:
	}
	<-c.closed
	return 0, net.ErrClosed
}

func (c *stuckConn) Close() error {
	c.closeOne.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// wedge sets up the frozen sender: a declared TLS 1.3 client completes the handshake, never reads again, and sends a record the server
// cannot decrypt. The server answers with an alert, a write inside Read that holds the TLS output lock; the raw socket under it
// (srv.wrapRaw) blocks every write once the handshake is done. This is the state a KeyUpdate request flood puts Go in (no TLS client
// in the standard library can send one), without needing openssl. It returns once the server's write has started and is blocked.
func (tr *tlsRig) wedge() {
	tr.t.Helper()
	sc := &stuckConn{writing: make(chan struct{}, 1), closed: make(chan struct{})}
	var first atomic.Bool
	tr.srv.wrapRaw = func(c net.Conn) net.Conn {
		if !first.CompareAndSwap(false, true) { // only the stuck sender's connection
			return c
		}
		sc.Conn = c
		return sc
	}
	tr.srv.afterHandshake = func(c net.Conn) {
		if c.(*tls.Conn).NetConn() == net.Conn(sc) {
			sc.armed.Store(true)
		}
	}
	tr.start()
	tr.set("tls")
	raw, err := (&net.Dialer{}).DialContext(context.Background(), "tcp4", tr.tlsAddr())
	if err != nil {
		tr.t.Fatal(err)
	}
	tr.t.Cleanup(func() { _ = raw.Close() })
	tc := tls.Client(raw, &tls.Config{RootCAs: tr.pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
	if err := tc.HandshakeContext(context.Background()); err != nil {
		tr.t.Fatal(err)
	}
	waitFor(tr.t, "the server to finish the handshake", func() bool { return sc.armed.Load() })
	rec := append([]byte{23, 3, 3, 0, 32}, make([]byte, 32)...) // application data that fails its authentication
	if _, err := raw.Write(rec); err != nil {
		tr.t.Fatal(err)
	}
	select {
	case <-sc.writing: // the alert write has started and is blocked
	case <-time.After(30 * time.Second):
		tr.t.Fatal("the server never wrote the alert")
	}
}

func within(t *testing.T, what string, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v: the listener is frozen", what, d)
	}
}

// H1: a declared TLS sender that never reads must not freeze the listener. Dropping its source, reading the status and stopping the
// server all return, the connection is cut, and its slot is freed.
func TestAStuckTLSSenderCannotFreezeReconfigurationOrStatus(t *testing.T) {
	t.Parallel()
	tr := newTLSRig(t, Limits{}, true)
	tr.wedge()
	if tr.srv.Status().Conns != 1 {
		t.Fatalf("status %+v", tr.srv.Status())
	}
	within(t, "SetSources(nil)", 5*time.Second, func() { _ = tr.srv.SetSources(nil) })
	within(t, "Status", 5*time.Second, func() { _ = tr.srv.Status() })
	waitFor(t, "the slot to be freed", func() bool { return tr.srv.Status().Conns == 0 })
	tr.set("tls") // and a new TLS connection is accepted again
	c, err := tr.dial(tr.tlsAddr(), tr.pool)
	if err != nil {
		t.Fatalf("a new connection after the stuck one: %v", err)
	}
	_ = c.Close()
}

func TestAStuckTLSSenderCannotHoldTheShutdown(t *testing.T) {
	t.Parallel()
	tr := newTLSRig(t, Limits{}, true)
	tr.wedge()
	within(t, "Run after cancel", 5*time.Second, func() {
		tr.stop()
		err := <-tr.done
		tr.done <- nil
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want nil or context.Canceled", err)
		}
	})
}

func pinOf(c tls.Certificate) string {
	sum := sha256.Sum256(c.Certificate[0])
	return hex.EncodeToString(sum[:])
}

// dialAs is a TLS client that presents cert (nil: none). With TLS 1.3 the server's refusal of a certificate shows on the first read, not in
// the handshake, so the caller learns of it by writing and then reading until the connection is closed.
func (tr *tlsRig) dialAs(cert *tls.Certificate) *tls.Conn {
	tr.t.Helper()
	cfg := &tls.Config{RootCAs: tr.pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	c, err := (&tls.Dialer{Config: cfg}).DialContext(context.Background(), "tcp4", tr.tlsAddr())
	if err != nil {
		tr.t.Fatal(err)
	}
	tr.t.Cleanup(func() { _ = c.Close() })
	return c.(*tls.Conn)
}

// closedByServer says whether the server ends the connection (a read returns an error) within the test's patience.
func closedByServer(t *testing.T, c net.Conn) bool {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	return err != nil && (!errors.As(err, &ne) || !ne.Timeout())
}

// D-435: a source that pins a client certificate takes lines only from the connection that presents exactly that certificate; no
// certificate, another one, and a pin changed under a live connection all end it, and nothing is stored.
func TestTLSPinnedClientCertificate(t *testing.T) {
	t.Parallel()
	tr := newTLSRig(t, Limits{}, true)
	good, _ := testCert(t, "device")
	other, _ := testCert(t, "other")
	tr.start()
	pin := func(p string) {
		t.Helper()
		if err := tr.srv.SetSources(map[netip.Addr]Source{lo: {ID: "src-1", Proto: "tls", ClientCertSHA256: p}}); err != nil {
			t.Fatal(err)
		}
	}
	pin(pinOf(good))
	for name, cert := range map[string]*tls.Certificate{"no certificate": nil, "another certificate": &other} {
		c := tr.dialAs(cert)
		_, _ = io.WriteString(c, "<34>refused\n")
		if !closedByServer(t, c) {
			t.Errorf("%s: the connection was not closed", name)
		}
	}
	waitFor(t, "two refusals", func() bool { return tr.srv.Stats().CertRejected == 2 })
	if n := len(tr.lines()); n != 0 {
		t.Fatalf("%d lines stored from a sender without the pinned certificate", n)
	}
	c := tr.dialAs(&good)
	if _, err := io.WriteString(c, "<34>accepted\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the line of the pinned certificate", func() bool { return len(tr.lines()) == 1 })
	pin(pinOf(other)) // the owner changes the pin: the live connection ends, it is not a failed handshake
	if !closedByServer(t, c) {
		t.Fatal("a connection whose certificate is no longer the pinned one stayed open")
	}
	if st := tr.srv.Stats(); st.HandshakeFailed != 0 {
		t.Errorf("stats %+v", st)
	}
	pin("") // no pin: a sender with no certificate is served again (the certificate is not even requested)
	c2 := tr.dialAs(nil)
	if _, err := io.WriteString(c2, "<34>again\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a line without a pin", func() bool { return len(tr.lines()) == 2 })
}

func TestPinMatches(t *testing.T) {
	t.Parallel()
	p := "ab" + strings.Repeat("0", 62)
	for _, tc := range []struct {
		got, want string
		ok        bool
	}{{p, p, true}, {"", "", false}, {"", p, false}, {p, "", false}, {p[:63], p, false}, {strings.Repeat("0", 64), p, false}} {
		if pinMatches(tc.got, tc.want) != tc.ok {
			t.Errorf("pinMatches(%q, %q) != %v", tc.got, tc.want, tc.ok)
		}
	}
}

// D-436: a declared sender may start HandshakeBurst TLS connections at once and HandshakeRate a second after that; the rest are closed before a
// handshake is paid for and counted as rejected.
func TestTLSHandshakeRatePerSender(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	tr := newTLSRig(t, Limits{HandshakeRate: 1, HandshakeBurst: 2}, true)
	tr.srv.now = clock
	tr.start()
	tr.set("tls")
	for i := range 2 {
		c, err := tr.dial(tr.tlsAddr(), tr.pool)
		if err != nil {
			t.Fatalf("connection %d inside the burst: %v", i+1, err)
		}
		_ = c.Close()
	}
	if _, err := tr.dial(tr.tlsAddr(), tr.pool); err == nil {
		t.Fatal("a third handshake inside the same instant was served")
	}
	if tr.srv.Stats().ConnRejected != 1 || tr.srv.Stats().HandshakeFailed != 0 {
		t.Fatalf("stats %+v", tr.srv.Stats())
	}
	mu.Lock()
	now = now.Add(1100 * time.Millisecond) // one token back
	mu.Unlock()
	c, err := tr.dial(tr.tlsAddr(), tr.pool)
	if err != nil {
		t.Fatalf("after a token was refilled: %v", err)
	}
	_ = c.Close()
}

// A source removed while its connection is still in the handshake closes it; that is the owner's edit, not a failed handshake (review L3).
func TestAConnectionCutBySetSourcesIsNotAFailedHandshake(t *testing.T) {
	t.Parallel()
	tr := newTLSRig(t, Limits{}, true)
	tr.start()
	tr.set("tls")
	raw, err := (&net.Dialer{}).DialContext(context.Background(), "tcp4", tr.tlsAddr()) // connects and says nothing: the server waits in the handshake
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	waitFor(t, "the connection to be counted", func() bool { return tr.srv.Status().Conns == 1 })
	if err := tr.srv.SetSources(nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the connection to be gone", func() bool { return tr.srv.Status().Conns == 0 })
	if got := tr.srv.Stats().HandshakeFailed; got != 0 {
		t.Fatalf("a connection cut by SetSources was counted as a failed handshake (%d)", got)
	}
}
