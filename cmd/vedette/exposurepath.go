package main

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// neverRouted are one address of each RFC 5737 documentation range (TEST-NET-1, -2 and -3). No network routes them on the Internet,
// so nothing should accept a TCP connect to them: a port that does is answered by the network between the box and the Internet (a
// firewall's SIP or SCCP helper, a transparent proxy, a SYN proxy), whatever the destination.
var neverRouted = []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("203.0.113.1")}

// Bounds of the check: each connect waits at most pathTimeout, pathParallel at once.
const (
	pathTimeout  = 1500 * time.Millisecond
	pathParallel = 24
)

// exposurePath is exposure's PathChecker (INV-44): for each port, a plain TCP connect to each never-routed address, closed as soon as
// it opens (nothing is sent; the packets reach no one). A port two of the three addresses accept is answered by the box's own
// network: two, so a lab network that routes one of the ranges inside itself cannot make a real port vanish from every target.
type exposurePath struct {
	dial func(ctx context.Context, network, address string) (net.Conn, error)
}

func newExposurePath() exposurePath {
	return exposurePath{dial: (&net.Dialer{}).DialContext}
}

func (p exposurePath) AnsweredByPath(ctx context.Context, ports []int) ([]int, error) {
	type try struct {
		port int
		ip   netip.Addr
	}
	var tries []try
	for _, port := range ports {
		if port < 1 || port > 65535 {
			continue
		}
		for _, ip := range neverRouted {
			tries = append(tries, try{port, ip})
		}
	}
	var mu sync.Mutex
	accepted := map[int]int{}
	sem := make(chan struct{}, pathParallel)
	var wg sync.WaitGroup
	for _, t := range tries {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			dctx, cancel := context.WithTimeout(ctx, pathTimeout)
			defer cancel()
			c, err := p.dial(dctx, "tcp", netip.AddrPortFrom(t.ip, uint16(t.port)).String()) //nolint:gosec // checked to be 1..65535 above
			if err != nil {
				return
			}
			_ = c.Close()
			mu.Lock()
			accepted[t.port]++
			mu.Unlock()
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []int
	for port, n := range accepted {
		if n >= 2 {
			out = append(out, port)
		}
	}
	slices.Sort(out)
	return out, nil
}
