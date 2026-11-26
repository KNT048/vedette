package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/knt048/vedette/core/egressip"
	"github.com/knt048/vedette/modules/exposure"
)

// exposureLiveness is exposure's Liveness: before each engine step of a scan, and before its results are written, a plain TCP connect
// from the box to each port seen open earlier in the scan, closed as soon as it is made; no byte is sent (PRIVACY flow 9). A port that
// does not accept the connection within liveConnectTimeout, twice, no longer answers. Only a public IPv4 address is ever dialled.
type exposureLiveness struct {
	dial   func(ctx context.Context, network, address string) (net.Conn, error)
	public func(netip.Addr) bool // nil: egressip.IsPublicIPv4
}

// The bounds of one check: each port gets liveTries connects of at most liveConnectTimeout, at most liveParallel at once.
const (
	liveConnectTimeout = 3 * time.Second
	liveTries          = 2
	liveParallel       = 8
)

func exposureLivenessFor() exposureLiveness {
	return exposureLiveness{dial: (&net.Dialer{}).DialContext}
}

func (l exposureLiveness) Alive(ctx context.Context, ip netip.Addr, ports []int) (map[int]bool, error) {
	public := l.public
	if public == nil {
		public = egressip.IsPublicIPv4
	}
	if !public(ip.Unmap()) {
		return nil, fmt.Errorf("exposure liveness: %s is not a public IPv4 address", ip)
	}
	out := make(map[int]bool, len(ports))
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, liveParallel)
	for _, p := range ports {
		if p < 1 || p > 65535 {
			continue
		}
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			up := false
			for range liveTries {
				if ctx.Err() != nil {
					break
				}
				dctx, cancel := context.WithTimeout(ctx, liveConnectTimeout)
				c, err := l.dial(dctx, "tcp4", net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(p)))
				cancel()
				if err == nil {
					_ = c.Close()
					up = true
					break
				}
			}
			mu.Lock()
			out[p] = up
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil { // a stopped scan says nothing about the ports
		return nil, err
	}
	return out, nil
}

var _ exposure.Liveness = exposureLiveness{}
