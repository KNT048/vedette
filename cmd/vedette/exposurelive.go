package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/knt048/vedette/core/egressip"
	"github.com/knt048/vedette/modules/exposure"
)

// exposureLiveness is exposure's Liveness: before each engine step of a scan, and before its results are written, a plain TCP connect
// from the box to each port seen open earlier in the scan, closed as soon as it is made; no byte is sent (PRIVACY flow 9). A port that
// does not accept the connection within liveConnectTimeout, twice, no longer answers. Only a public IPv4 address is ever dialled.
type exposureLiveness struct {
	dial    func(ctx context.Context, network, address string) (net.Conn, error)
	public  func(netip.Addr) bool // nil: egressip.IsPublicIPv4
	timeout time.Duration         // one connect; 0: liveConnectTimeout
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
	got, err := l.Probe(ctx, ip, ports)
	if err != nil {
		return nil, err
	}
	out := make(map[int]bool, len(got))
	for p, a := range got {
		out[p] = a == exposure.PortOpen
	}
	return out, nil
}

// Probe is exposure's PortProber: the same connects as Alive, telling a port that refused them (a TCP reset: closed) from one that
// gave no answer at all (a timeout, or an ICMP host or network unreachable from a filter on the way: silent). Linux reports an ICMP
// port unreachable to connect as a refusal too, so a firewall that rejects the box that way (iptables REJECT's default) reads as
// closed here, as it does to the runner's connect.
func (l exposureLiveness) Probe(ctx context.Context, ip netip.Addr, ports []int) (map[int]string, error) {
	public := l.public
	if public == nil {
		public = egressip.IsPublicIPv4
	}
	if !public(ip.Unmap()) {
		return nil, fmt.Errorf("exposure liveness: %s is not a public IPv4 address", ip)
	}
	out := make(map[int]string, len(ports))
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
			answer := exposure.PortSilent
			for range liveTries {
				if ctx.Err() != nil {
					break
				}
				dctx, cancel := context.WithTimeout(ctx, cmp.Or(l.timeout, liveConnectTimeout))
				c, err := l.dial(dctx, "tcp4", net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(p)))
				cancel()
				if err == nil {
					_ = c.Close()
					answer = exposure.PortOpen
					break
				}
				if errors.Is(err, syscall.ECONNREFUSED) {
					answer = exposure.PortClosed
					break
				}
			}
			mu.Lock()
			out[p] = answer
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil { // a stopped scan says nothing about the ports
		return nil, err
	}
	return out, nil
}

var (
	_ exposure.Liveness   = exposureLiveness{}
	_ exposure.PortProber = exposureLiveness{}
)
