package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
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
// a port that two of the three addresses accept is the network's, one that only one accepts (a lab that routes one range) is not.
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
	p := exposurePath{dial: func(_ context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, network+" "+address)
		mu.Unlock()
		if accept[address] {
			return pathConn{mu: &mu, wrote: &wrote, closed: &closed}, nil
		}
		return nil, errors.New("i/o timeout")
	}}
	got, err := p.AnsweredByPath(t.Context(), []int{443, 2000, 5060, 70000})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []int{2000, 5060}) {
		t.Fatalf("answered by the network: %v, want [2000 5060]", got)
	}
	if len(dialed) != 9 {
		t.Fatalf("%d connects, want 9 (3 ports x 3 addresses): %v", len(dialed), dialed)
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
	if _, err := p.AnsweredByPath(ctx, []int{5060}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}
