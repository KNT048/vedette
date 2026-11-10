package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
)

// D-139: the box's self-signed certificate follows its management address.

type fakeMgmt struct {
	mu    sync.Mutex
	addrs []string
	err   error
	calls int
}

func (f *fakeMgmt) set(err error, addrs ...string) {
	f.mu.Lock()
	f.addrs, f.err = addrs, err
	f.mu.Unlock()
}

func (f *fakeMgmt) get(context.Context) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	var out []netip.Addr
	for _, a := range f.addrs {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, f.err
}

func newTestRenewer(t *testing.T, m *fakeMgmt) (*selfSignedRenewer, string) {
	t.Helper()
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	if err := ensureCert(crt, key, []string{"box.acme.example"}); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := loadTLS(crt, key)
	if err != nil {
		t.Fatal(err)
	}
	r := &selfSignedRenewer{certPath: crt, keyPath: key, hosts: []string{"box.acme.example"}, now: time.Now, cert: &cfg.Certificates[0], kick: make(chan struct{}, 1), gap: 300 * time.Millisecond}
	if m != nil {
		r.mgmt = m.get
	}
	return r, crt
}

func servedLeaf(t *testing.T, r *selfSignedRenewer) *x509.Certificate {
	t.Helper()
	c, _ := r.GetCertificate(nil)
	l, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func hasIP(l *x509.Certificate, ip string) bool { return l.VerifyHostname(ip) == nil }

func TestCertGetsTheNewManagementAddressSameKeyAndOrg(t *testing.T) {
	t.Parallel()
	m := &fakeMgmt{}
	r, crt := newTestRenewer(t, m)
	first := servedLeaf(t, r)
	m.set(nil, "203.0.113.7")
	if err := r.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	second := servedLeaf(t, r)
	if !hasIP(second, "203.0.113.7") || second.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatalf("not re-issued with the new address: %v", second.IPAddresses)
	}
	if !second.PublicKey.(*ecdsa.PublicKey).Equal(first.PublicKey) {
		t.Error("the key changed")
	}
	if !slices.Contains(second.Subject.Organization, selfSignedOrg) {
		t.Errorf("organization %v", second.Subject.Organization)
	}
	if !slices.Contains(second.DNSNames, "box.acme.example") || !hasIP(second, "127.0.0.1") {
		t.Error("-hosts or loopback names lost")
	}
	if onDisk := readCert(t, crt); onDisk.SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Error("the file is not the served certificate")
	}
	// An unchanged set writes nothing.
	if err := r.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if servedLeaf(t, r).SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Error("an unchanged address set re-issued the certificate")
	}
}

func TestCertHasOldAndNewDuringTheWindowThenDropsTheOldOne(t *testing.T) {
	t.Parallel()
	m := &fakeMgmt{}
	r, _ := newTestRenewer(t, m)
	m.set(nil, "203.0.113.7")
	_ = r.Check(t.Context(), nil)
	m.set(nil, "203.0.113.7", "198.51.100.9") // confirm window: both
	_ = r.Check(t.Context(), nil)
	if l := servedLeaf(t, r); !hasIP(l, "203.0.113.7") || !hasIP(l, "198.51.100.9") {
		t.Fatalf("window: %v", l.IPAddresses)
	}
	m.set(nil, "203.0.113.7") // reverted
	_ = r.Check(t.Context(), nil)
	if l := servedLeaf(t, r); !hasIP(l, "203.0.113.7") || hasIP(l, "198.51.100.9") {
		t.Fatalf("after revert: %v", l.IPAddresses)
	}
}

func TestCertKeptWhenTheHostFailsOrSaysNothing(t *testing.T) {
	t.Parallel()
	m := &fakeMgmt{}
	r, _ := newTestRenewer(t, m)
	m.set(nil, "203.0.113.7")
	_ = r.Check(t.Context(), nil)
	cur := servedLeaf(t, r)
	for _, tc := range []struct {
		name string
		err  error
		a    []string
	}{{"error", errors.New("host down"), nil}, {"empty", nil, nil}, {"error with data", errors.New("x"), []string{"198.51.100.1"}}} {
		m.set(tc.err, tc.a...)
		if err := r.Check(t.Context(), nil); err != nil {
			t.Fatal(err)
		}
		if l := servedLeaf(t, r); l.SerialNumber.Cmp(cur.SerialNumber) != 0 {
			t.Errorf("%s: certificate re-issued", tc.name)
		}
	}
	// An expiry renewal while the host is down keeps the address it had.
	now := time.Now().Add(800 * 24 * time.Hour)
	r.now = func() time.Time { return now }
	m.set(errors.New("host down"))
	if err := r.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if l := servedLeaf(t, r); l.SerialNumber.Cmp(cur.SerialNumber) == 0 || !hasIP(l, "203.0.113.7") {
		t.Errorf("expiry renewal: %v", l.IPAddresses)
	}
}

func TestOwnerCertificateIsWarnedAboutOncePerChangeAndNeverWritten(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	crt, key, _ := writeTestPair(t, dir, &x509.Certificate{DNSNames: []string{"box.corp.example"}, IPAddresses: []net.IP{net.ParseIP("203.0.113.7")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour * 24)})
	cfg, _, err := loadTLS(crt, key)
	if err != nil {
		t.Fatal(err)
	}
	before := readCert(t, crt)
	m := &fakeMgmt{}
	w := newOwnerCertWarner(cfg, m.get)
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	check := func() {
		if err := w.Check(t.Context(), log); err != nil {
			t.Fatal(err)
		}
	}
	m.set(nil, "203.0.113.7")
	check()
	if buf.Len() != 0 {
		t.Fatalf("a covered address warned: %s", buf.String())
	}
	m.set(nil, "198.51.100.9")
	check()
	check()
	if n := strings.Count(buf.String(), "level=WARN"); n != 1 || !strings.Contains(buf.String(), "198.51.100.9") {
		t.Fatalf("warnings = %d: %s", n, buf.String())
	}
	m.set(nil, "198.51.100.10")
	check()
	if n := strings.Count(buf.String(), "level=WARN"); n != 2 {
		t.Fatalf("a new change did not warn again: %d", n)
	}
	m.set(errors.New("down"))
	check()
	if n := strings.Count(buf.String(), "level=WARN"); n != 2 {
		t.Fatal("a failing host warned")
	}
	if after := readCert(t, crt); after.SerialNumber.Cmp(before.SerialNumber) != 0 {
		t.Error("the owner's certificate was written")
	}
	if newOwnerCertWarner(cfg, nil) != nil || (*selfSignedRenewer)(nil) != nil {
		t.Error("nil source")
	}
}

// Two triggers close together are one run, and a change made inside the gap waits for it.
func TestKickIsRateLimited(t *testing.T) {
	t.Parallel()
	m := &fakeMgmt{}
	r, _ := newTestRenewer(t, m)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { r.Run(ctx, slog.New(slog.DiscardHandler), nil, nil); close(done) }()
	defer func() { cancel(); <-done }()
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		for i := 0; i < 200; i++ {
			if ok() {
				return
			}
			<-time.After(20 * time.Millisecond)
		}
		t.Fatalf("timed out: %s", what)
	}
	waitFor("start-up check", func() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.calls == 1 })
	serial0 := servedLeaf(t, r).SerialNumber
	m.set(nil, "203.0.113.7")
	r.Kick()
	r.Kick()
	waitFor("first kick", func() bool { return hasIP(servedLeaf(t, r), "203.0.113.7") })
	serial1 := servedLeaf(t, r).SerialNumber
	m.set(nil, "203.0.113.7", "198.51.100.9") // inside the gap
	r.Kick()
	<-time.After(100 * time.Millisecond)
	if servedLeaf(t, r).SerialNumber.Cmp(serial1) != 0 {
		t.Fatal("a second re-issue inside the gap")
	}
	waitFor("kick after the gap", func() bool { return hasIP(servedLeaf(t, r), "198.51.100.9") })
	if serial0.Cmp(serial1) == 0 {
		t.Fatal("no first re-issue")
	}
	m.mu.Lock()
	calls := m.calls
	m.mu.Unlock()
	if calls != 3 { // start, kick+kick (one), kick after the gap
		t.Errorf("host asked %d times, want 3", calls)
	}
}

// A TLS client that only trusts the new certificate gets through without a restart.
func TestTLSClientSeesTheNewCertificateWithoutRestart(t *testing.T) {
	t.Parallel()
	m := &fakeMgmt{}
	r, _ := newTestRenewer(t, m)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: r.GetCertificate, MinVersion: tls.VersionTLS12})
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
			go func() { _ = c.(*tls.Conn).HandshakeContext(context.Background()); _ = c.Close() }()
		}
	}()
	dial := func() error {
		pool := x509.NewCertPool()
		pool.AddCert(servedLeaf(t, r))
		c, err := (&tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: "203.0.113.7", MinVersion: tls.VersionTLS12}}).DialContext(t.Context(), "tcp", ln.Addr().String())
		if err == nil {
			_ = c.Close()
		}
		return err
	}
	if dial() == nil {
		t.Fatal("the old certificate covered an address it does not list")
	}
	m.set(nil, "203.0.113.7")
	if err := r.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if err := dial(); err != nil {
		t.Fatalf("after the change: %v", err)
	}
}

func TestHostMgmtIPv4sIsTheManagementCardOnly(t *testing.T) {
	t.Parallel()
	f := lanBox()
	f.st.Interfaces[0].Addresses = append(f.st.Interfaces[0].Addresses, "169.254.1.1/16", "192.168.10.250/24")
	f.st.Interfaces[1].Addresses = []string{"10.99.0.1/24"}
	got, err := hostMgmtIPv4s(f, nil)(t.Context())
	if err != nil || !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.168.10.250")}) {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := hostMgmtIPv4s(&fakeNet{err: errors.New("x")}, nil)(t.Context()); err == nil {
		t.Fatal("error swallowed")
	}
	if hostMgmtIPv4s(nil, nil) != nil {
		t.Fatal("no host, some source")
	}
	_ = api.NetRoleManagement
}

// M1: a change made another way (DHCP, console) is seen at the 10-minute tick, with no kick.
func TestAddressTickSeesAChangeWithoutAKick(t *testing.T) {
	t.Parallel()
	m := &fakeMgmt{}
	r, _ := newTestRenewer(t, m)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	tick, addrTick := make(chan time.Time), make(chan time.Time)
	go func() { r.Run(ctx, slog.New(slog.DiscardHandler), tick, addrTick); close(done) }()
	defer func() { cancel(); <-done }()
	m.set(nil, "203.0.113.7")
	addrTick <- time.Now()
	addrTick <- time.Now() // returns only after the first run finished
	if !hasIP(servedLeaf(t, r), "203.0.113.7") {
		t.Fatal("the address tick did not re-issue")
	}
	serial := servedLeaf(t, r).SerialNumber
	addrTick <- time.Now()
	addrTick <- time.Now()
	if servedLeaf(t, r).SerialNumber.Cmp(serial) != 0 {
		t.Fatal("an unchanged set re-issued")
	}
}

// L2: the new certificate is served from memory even when the disk cannot be read back, and a pair on disk that
// is not the served one is served instead.
func TestReissueDoesNotNeedTheDiskAndFollowsAReplacedPair(t *testing.T) {
	t.Parallel()
	m := &fakeMgmt{}
	r, _ := newTestRenewer(t, m)
	m.set(nil, "203.0.113.7")
	if err := os.Remove(r.keyPath); err != nil { // the read-back would fail
		t.Fatal(err)
	}
	if err := r.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if !hasIP(servedLeaf(t, r), "203.0.113.7") {
		t.Fatal("the new certificate is not served")
	}

	r2, _ := newTestRenewer(t, nil)
	other := t.TempDir()
	oc, ok := filepath.Join(other, "c.crt"), filepath.Join(other, "c.key")
	if err := ensureCert(oc, ok, []string{"other.example"}); err != nil {
		t.Fatal(err)
	}
	for src, dst := range map[string]string{oc: r2.certPath, ok: r2.keyPath} {
		b, err := os.ReadFile(src) //nolint:gosec // test paths
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil { //nolint:gosec // a path the test made
			t.Fatal(err)
		}
	}
	if err := r2.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(servedLeaf(t, r2).DNSNames, "other.example") {
		t.Fatal("the pair on disk was not served")
	}
}

// L3: after a re-issue the box's own health check (it pins the served certificate to the file) is healthy.
func TestHealthcheckIsHealthyAfterAReissue(t *testing.T) {
	t.Parallel()
	m := &fakeMgmt{}
	r, _ := newTestRenewer(t, m)
	srv := httptest.NewUnstartedServer(healthHandler(200))
	srv.TLS = &tls.Config{GetCertificate: r.GetCertificate, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	m.set(nil, "203.0.113.7")
	if err := r.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if err := coreHealthcheck(t.Context(), srv.Listener.Addr().String(), r.certPath, 2*time.Second); err != nil {
		t.Fatalf("unhealthy after the re-issue: %v", err)
	}
}

// L4: at most 16 addresses, each once, only private or global unicast; one warning when cut.
func TestHostMgmtIPv4sIsBoundedAndFiltered(t *testing.T) {
	t.Parallel()
	addrs := []string{"224.0.0.1/24", "240.0.0.1/24", "255.255.255.255/32", "0.0.0.0/0", "127.0.0.1/8", "169.254.1.1/16", "10.0.0.1/24", "10.0.0.1/24"}
	for i := 2; i < 25; i++ {
		addrs = append(addrs, fmt.Sprintf("10.0.0.%d/24", i))
	}
	f := &fakeNet{st: api.NetState{Interfaces: []api.NetInterface{{Name: "eth0", Role: api.NetRoleManagement, Addresses: addrs}}}}
	var buf bytes.Buffer
	src := hostMgmtIPv4s(f, slog.New(slog.NewTextHandler(&buf, nil)))
	for range 2 {
		got, err := src(t.Context())
		if err != nil || len(got) != maxMgmtAddrs || got[0].String() != "10.0.0.1" {
			t.Fatalf("%d %v %v", len(got), got, err)
		}
		for _, a := range got {
			if a.IsMulticast() || reservedV4.Contains(a) || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
				t.Errorf("%s accepted", a)
			}
		}
	}
	if n := strings.Count(buf.String(), "level=WARN"); n != 1 {
		t.Fatalf("warnings = %d", n)
	}
}

// L5: a changed address of the container alone does not re-issue.
func TestContainerAddressAloneDoesNotReissue(t *testing.T) {
	t.Parallel()
	m := &fakeMgmt{}
	r, _ := newTestRenewer(t, m)
	local := []string{"localhost", "127.0.0.1", "10.250.0.2"}
	r.local = func() []string { return local }
	m.set(nil, "203.0.113.7")
	if err := r.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	first := servedLeaf(t, r)
	if !hasIP(first, "10.250.0.2") {
		t.Fatal("localNames are not in the certificate")
	}
	local = []string{"localhost", "127.0.0.1", "10.250.0.3"}
	if err := r.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if servedLeaf(t, r).SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatal("a changed container address re-issued the certificate")
	}
}

// L6: one warning per outage of the host.
func TestHostOutageIsWarnedOnce(t *testing.T) {
	t.Parallel()
	m := &fakeMgmt{}
	r, _ := newTestRenewer(t, m)
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	m.set(errors.New("down"))
	for range 3 {
		if err := r.Check(t.Context(), log); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(buf.String(), "level=WARN"); n != 1 {
		t.Fatalf("warnings = %d", n)
	}
	m.set(nil, "203.0.113.7")
	_ = r.Check(t.Context(), log)
	m.set(errors.New("down again"))
	_ = r.Check(t.Context(), log)
	if n := strings.Count(buf.String(), "level=WARN"); n != 2 {
		t.Fatalf("a second outage: warnings = %d", n)
	}
}
