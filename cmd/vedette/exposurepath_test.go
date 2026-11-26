package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/exposure"
)

// pathConn is a connection that records whether anything was written to it or it was closed.
type pathConn struct {
	net.Conn
	mu     *sync.Mutex
	wrote  *bool
	closed *int
}

func (c pathConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	*c.wrote = true
	return len(b), nil
}

func (c pathConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	*c.closed++
	return nil
}

// INV-44: the check connects only to the RFC 5737 documentation ranges, on the ports asked, sends nothing and closes each connection;
// a port that two of the three addresses accept is the network's, one that only one accepts (a lab that routes one range) is not; a
// port that two of them refuse (an egress filter's reset) is refused by the network.
func TestExposurePathConnectsOnlyToNeverRoutedAddresses(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var dialed []string
	wrote, closed := false, 0
	accept := map[string]bool{
		"192.0.2.1:5060": true, "198.51.100.1:5060": true, "203.0.113.1:5060": true, // a SIP helper: every address
		"192.0.2.1:2000": true, "203.0.113.1:2000": true, // two of three
		"203.0.113.1:443": true, // one only: a lab network that routes 203.0.113.0/24
	}
	refuse := map[string]bool{"192.0.2.1:25": true, "198.51.100.1:25": true} // an egress filter on port 25
	p := exposurePath{dial: func(_ context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, network+" "+address)
		mu.Unlock()
		switch {
		case accept[address]:
			return pathConn{mu: &mu, wrote: &wrote, closed: &closed}, nil
		case refuse[address]:
			return nil, &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
		}
		return nil, errors.New("i/o timeout")
	}}
	got, err := p.PathAnswers(t.Context(), []int{25, 443, 2000, 5060, 70000})
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]string{25: exposure.PortClosed, 443: exposure.PortSilent, 2000: exposure.PortOpen, 5060: exposure.PortOpen}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("the network's answers: %v, want %v", got, want)
	}
	if len(dialed) != 12 {
		t.Fatalf("%d connects, want 12 (4 ports x 3 addresses): %v", len(dialed), dialed)
	}
	for _, d := range dialed {
		ap, err := netip.ParseAddrPort(d[len("tcp "):])
		if err != nil || d[:4] != "tcp " {
			t.Fatalf("connect %q", d)
		}
		if !slices.Contains(neverRouted, ap.Addr()) {
			t.Fatalf("connect to %s: only the RFC 5737 ranges may be asked", ap)
		}
	}
	if wrote || closed != 6 {
		t.Fatalf("wrote %v, closed %d of the 6 connections that opened", wrote, closed)
	}
	ranges := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")}
	for i, a := range neverRouted {
		if !ranges[i].Contains(a) {
			t.Fatalf("%s is not in %s", a, ranges[i])
		}
	}
}

// A stopped scan gets its own error, not "none answered".
func TestExposurePathStopsWithTheScan(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	p := exposurePath{dial: func(ctx context.Context, _, _ string) (net.Conn, error) { return nil, ctx.Err() }}
	if _, err := p.PathAnswers(ctx, []int{5060}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}

// A transparent proxy on a web port answers every address with its own page; through it, the target's own web service answers with
// its own. The comparison tells them apart: the same page as a never-routed address gets is the network's, another page the target's.
// A port that is not a web or TLS port of the fixed list gets nothing sent (only its banner is read), and only a public address is
// ever read.
func TestExposurePathComparesTheTargetsAnswerWithTheNetworks(t *testing.T) {
	t.Parallel()
	page := func(title string) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "test")
			_, _ = fmt.Fprintf(w, "<html><title>%s</title></html>", title)
		}))
		t.Cleanup(s.Close)
		return s
	}
	proxy, own := page("Blocked by the proxy"), page("Acme portal")
	target := netip.MustParseAddr("8.8.8.8")
	through := func(targetServer *httptest.Server) exposurePath {
		return exposurePath{public: func(netip.Addr) bool { return true }, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			ap := netip.MustParseAddrPort(address)
			to := proxy.Listener.Addr().String()
			if ap.Addr() == target {
				to = targetServer.Listener.Addr().String()
			}
			return (&net.Dialer{}).DialContext(ctx, network, to)
		}}
	}
	if same, err := through(own).SameAsPath(t.Context(), target, 80); err != nil || same {
		t.Fatalf("the target's own page through the proxy: same %v, err %v", same, err)
	}
	if same, err := through(proxy).SameAsPath(t.Context(), target, 80); err != nil || !same {
		t.Fatalf("only the proxy's page: same %v, err %v", same, err)
	}
	var mu sync.Mutex
	wrote := false
	none := exposurePath{dial: func(context.Context, string, string) (net.Conn, error) { // a service that sends nothing first
		return &bannerConn{mu: &mu, wrote: &wrote}, nil
	}, public: func(netip.Addr) bool { return true }}
	if same, err := none.SameAsPath(t.Context(), target, 5060); err != nil || !same || wrote {
		t.Fatalf("5060 (not a web or TLS port, nothing sent by the target): same %v, err %v, wrote %v", same, err, wrote)
	}
	if _, err := (exposurePath{dial: none.dial}).SameAsPath(t.Context(), netip.MustParseAddr("10.0.0.1"), 80); err == nil {
		t.Fatal("a private address was read")
	}
}

// endlessHeaders is a web server that answers with a status line and then header lines without end (up to 4 MiB, then it closes):
// it counts what the reader took from it.
type endlessHeaders struct {
	net.Conn
	mu   *sync.Mutex
	read *int
	sent int
}

func (c *endlessHeaders) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sent >= 4<<20 {
		return 0, io.EOF
	}
	src := []byte("X-Pad: " + strings.Repeat("a", 200) + "\r\n")
	if c.sent == 0 {
		src = []byte("HTTP/1.1 200 OK\r\n")
	}
	n := copy(b, src)
	c.sent += n
	*c.read += n
	return n, nil
}

func (c *endlessHeaders) Write(b []byte) (int, error)      { return len(b), nil }
func (c *endlessHeaders) Close() error                     { return nil }
func (c *endlessHeaders) SetDeadline(time.Time) error      { return nil }
func (c *endlessHeaders) SetReadDeadline(time.Time) error  { return nil }
func (c *endlessHeaders) SetWriteDeadline(time.Time) error { return nil }

// Reading what answers on a web port is bounded in bytes, headers included: an answer that never ends its headers is cut at
// pathReadLimit, not read for the whole read time. Cut there, it is no answer of the target: nothing is compared.
func TestExposurePathReadsABoundedAnswer(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	conns := 0
	reads := map[int]*int{}
	p := exposurePath{public: func(netip.Addr) bool { return true }, dial: func(context.Context, string, string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		conns++
		n := new(int)
		reads[conns] = n
		return &endlessHeaders{mu: &mu, read: n}, nil
	}}
	if same, err := p.SameAsPath(t.Context(), netip.MustParseAddr("8.8.8.8"), 80); err == nil {
		t.Fatalf("the target's answer was cut at the limit, yet compared: same %v", same)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reads) == 0 {
		t.Fatal("nothing was read")
	}
	for i, n := range reads {
		if *n > pathReadLimit {
			t.Fatalf("connection %d: read %d bytes, want at most %d", i, *n, pathReadLimit)
		}
	}
}

// bannerConn is a service that sends data by itself on connect and then closes; it records whether anything was written to it.
type bannerConn struct {
	net.Conn
	mu    *sync.Mutex
	data  []byte
	pos   int
	wrote *bool
	read  *int
}

func (c *bannerConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	n := copy(b, c.data[c.pos:])
	c.pos += n
	if c.read != nil {
		*c.read += n
	}
	return n, nil
}

func (c *bannerConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	*c.wrote = true
	return len(b), nil
}

func (c *bannerConn) Close() error                     { return nil }
func (c *bannerConn) SetDeadline(time.Time) error      { return nil }
func (c *bannerConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bannerConn) SetWriteDeadline(time.Time) error { return nil }

// On a port that is not a web or TLS port, a proxy or helper that accepts it for every address is told from the target's own service
// by what a server that speaks first sends on connect (its banner), nothing sent: a real SSH server behind such a proxy sends its
// banner, the never-routed address gets a closed connection, so the port is the target's. A port whose target sends nothing (a
// client-speaks-first service such as SIP) stays the network's, and so does a banner the proxy itself sends for every address (a
// time in it changes nothing). The banner is read up to a bound.
func TestExposurePathReadsTheBannerOfAServerThatSpeaksFirst(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	wrote := false
	endless := 0
	target := netip.MustParseAddr("8.8.8.8")
	p := exposurePath{public: func(netip.Addr) bool { return true }, dial: func(_ context.Context, _, address string) (net.Conn, error) {
		ap := netip.MustParseAddrPort(address)
		own := ap.Addr() == target
		var data []byte
		var read *int
		switch ap.Port() {
		case 22:
			if own {
				data = []byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
			}
		case 25: // an SMTP proxy that answers every address itself, with the time
			data = []byte("220 proxy.example ESMTP ready Thu, 26 Nov 2026 12:00:0" + map[bool]string{true: "1", false: "7"}[own] + " +0000\r\n")
		case 2222:
			data, read = []byte(strings.Repeat("a", 1<<20)), &endless
		}
		return &bannerConn{mu: &mu, data: data, wrote: &wrote, read: read}, nil
	}}
	if same, err := p.SameAsPath(t.Context(), target, 22); err != nil || same {
		t.Fatalf("22, the target's own SSH banner behind the proxy: same %v, err %v", same, err)
	}
	if same, err := p.SameAsPath(t.Context(), target, 5060); err != nil || !same {
		t.Fatalf("5060, nothing sent by either: same %v, err %v", same, err)
	}
	if same, err := p.SameAsPath(t.Context(), target, 25); err != nil || !same {
		t.Fatalf("25, the proxy's own banner for every address: same %v, err %v", same, err)
	}
	if _, err := p.SameAsPath(t.Context(), target, 2222); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if wrote {
		t.Fatal("something was sent to read a banner")
	}
	if endless == 0 || endless > 4*512 {
		t.Fatalf("an endless banner: read %d bytes over 4 connections, want at most 512 each", endless)
	}
}

// A target that sends nothing of its own on a port where the network's answer for a never-routed address is a banner (a proxy that
// writes an error when it cannot reach the destination, and relays a client-speaks-first service when it can) is told apart: the two
// answers differ, so the port is the target's. Only nothing on both sides is the network's.
func TestExposurePathTellsASilentTargetFromTheNetworksBanner(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	wrote := false
	target := netip.MustParseAddr("8.8.8.8")
	p := exposurePath{public: func(netip.Addr) bool { return true }, dial: func(_ context.Context, _, address string) (net.Conn, error) {
		var data []byte
		if netip.MustParseAddrPort(address).Addr() != target {
			data = []byte("proxy: the destination cannot be reached\r\n")
		}
		return &bannerConn{mu: &mu, data: data, wrote: &wrote}, nil
	}}
	if same, err := p.SameAsPath(t.Context(), target, 3389); err != nil || same {
		t.Fatalf("3389, the target sends nothing and the network sends its own banner: same %v, err %v", same, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if wrote {
		t.Fatal("something was sent to read a banner")
	}
}

// slowConn is a connection that accepts and then never answers: every read ends at the read deadline (a slow page).
type slowConn struct{ net.Conn }

func (slowConn) Read([]byte) (int, error)         { return 0, os.ErrDeadlineExceeded }
func (slowConn) Write(b []byte) (int, error)      { return len(b), nil }
func (slowConn) Close() error                     { return nil }
func (slowConn) SetDeadline(time.Time) error      { return nil }
func (slowConn) SetReadDeadline(time.Time) error  { return nil }
func (slowConn) SetWriteDeadline(time.Time) error { return nil }

// On a web or TLS port, the target's own answer is the evidence: when reading it failed (a slow page, a TLS handshake or a GET that
// ended without an answer), nothing of the target was compared, however the never-routed addresses ended too. The comparison
// reports that it did not run, so a stored row is not retired on it (the port is still left out as the network's).
func TestExposurePathDoesNotCompareATargetsWebAnswerThatFailed(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	wrote := false
	target := netip.MustParseAddr("8.8.8.8")
	closing := exposurePath{public: func(netip.Addr) bool { return true }, dial: func(context.Context, string, string) (net.Conn, error) {
		return &bannerConn{mu: &mu, wrote: &wrote}, nil // accepted, then closed without a byte: on the target and through the network
	}}
	for _, port := range []int{80, 443, 993} { // a web port, a web port with TLS, a TLS-only port
		if same, err := closing.SameAsPath(t.Context(), target, port); err == nil {
			t.Errorf("%d, the target's read ended without an answer, like the network's: same %v, want an error (not compared)", port, same)
		}
	}
	slow := exposurePath{public: func(netip.Addr) bool { return true }, dial: func(context.Context, string, string) (net.Conn, error) {
		return slowConn{}, nil
	}}
	if same, err := slow.SameAsPath(t.Context(), target, 443); err == nil {
		t.Errorf("443, the target's page timed out, like the network's: same %v, want an error (not compared)", same)
	}
	if same, err := slow.SameAsPath(t.Context(), target, 5060); err != nil || !same { // a banner port: nothing on both sides stays the network's
		t.Errorf("5060, nothing sent by either: same %v, err %v", same, err)
	}
}
