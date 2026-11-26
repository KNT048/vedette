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
// A port that is not a web or TLS port of the fixed list is not read at all, and only a public address is ever read.
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
	none := exposurePath{dial: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("a port that is not a web or TLS port was read")
		return nil, nil
	}, public: func(netip.Addr) bool { return true }}
	if same, err := none.SameAsPath(t.Context(), target, 5060); err != nil || !same {
		t.Fatalf("5060: same %v, err %v", same, err)
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
// pathReadLimit, not read for the whole read time.
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
	if _, err := p.SameAsPath(t.Context(), netip.MustParseAddr("8.8.8.8"), 80); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for i, n := range reads {
		if *n > pathReadLimit {
			t.Fatalf("connection %d: read %d bytes, want at most %d", i, *n, pathReadLimit)
		}
	}
}
