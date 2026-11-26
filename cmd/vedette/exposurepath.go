package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/knt048/vedette/core/egressip"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan/commonports"
)

// neverRouted are one address of each RFC 5737 documentation range (TEST-NET-1, -2 and -3). No network routes them on the Internet,
// so nothing should answer a TCP connect to them: a port that does (accepts it, or refuses it with a reset) is answered by the network
// between the box and the Internet (a firewall's SIP or SCCP helper, a transparent proxy, a SYN proxy, an egress filter), whatever
// the destination.
var neverRouted = []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("203.0.113.1")}

// Bounds of the check: each connect waits at most pathTimeout, pathParallel at once; reading what answers on a port (a TLS
// handshake, else one GET of /) takes at most pathReadTimeout and pathReadLimit bytes of the answer, headers included.
const (
	pathTimeout     = 1500 * time.Millisecond
	pathParallel    = 64
	pathReadTimeout = 5 * time.Second
	pathReadLimit   = 64 << 10
)

// exposurePath is exposure's PathChecker (INV-44), the calibration of a scan's vantage:
//   - PathAnswers: for each port, a plain TCP connect to each never-routed address, closed as soon as it opens (nothing is sent; the
//     packets reach no one but the box's own network). What two of the three addresses get is the network's answer: two, so a lab
//     network that routes one of the ranges inside itself cannot make a real port vanish from every target.
//   - SameAsPath: for a web or TLS port of the fixed list (commonports) that the network accepts for every address, what the target
//     answers there (its TLS certificate, else the status, Server header and title of one GET of /, as the scan's own check of a web
//     port reads) against what a never-routed address answers through the same network (the proxy's own certificate or error
//     page). Any other port is not read: the network's answer stands.
type exposurePath struct {
	dial   func(ctx context.Context, network, address string) (net.Conn, error)
	public func(netip.Addr) bool // nil: egressip.IsPublicIPv4
}

func newExposurePath() exposurePath {
	return exposurePath{dial: (&net.Dialer{}).DialContext}
}

// PathAnswers says what a TCP connect to the never-routed addresses gets on each port: exposure.PortOpen, PortClosed or PortSilent.
func (p exposurePath) PathAnswers(ctx context.Context, ports []int) (map[int]string, error) {
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
	got := map[int]map[string]int{}
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
			answer := exposure.PortSilent
			c, err := p.dial(dctx, "tcp", netip.AddrPortFrom(t.ip, uint16(t.port)).String()) //nolint:gosec // checked to be 1..65535 above
			switch {
			case err == nil:
				_ = c.Close()
				answer = exposure.PortOpen
			case errors.Is(err, syscall.ECONNREFUSED):
				answer = exposure.PortClosed
			}
			mu.Lock()
			if got[t.port] == nil {
				got[t.port] = map[string]int{}
			}
			got[t.port][answer]++
			mu.Unlock()
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := map[int]string{}
	for port, n := range got {
		out[port] = exposure.PortSilent
		for _, a := range []string{exposure.PortOpen, exposure.PortClosed} {
			if n[a] >= 2 {
				out[port] = a
			}
		}
	}
	return out, nil
}

// SameAsPath says whether what ip answers on port is what a never-routed address answers there through the same network.
func (p exposurePath) SameAsPath(ctx context.Context, ip netip.Addr, port int) (bool, error) {
	public := p.public
	if public == nil {
		public = egressip.IsPublicIPv4
	}
	if !public(ip.Unmap()) || port < 1 || port > 65535 {
		return false, fmt.Errorf("exposure path: %s:%d is not a public IPv4 address and port", ip, port)
	}
	use, ok := webUse(port)
	if !ok {
		return true, nil
	}
	target := p.answerOf(ctx, netip.AddrPortFrom(ip.Unmap(), uint16(port)), use)
	for _, a := range neverRouted {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if p.answerOf(ctx, netip.AddrPortFrom(a, uint16(port)), use) == target {
			return true, nil
		}
	}
	return false, ctx.Err()
}

// webUse is what the scan reads on port when it is a web or TLS port of the fixed list.
func webUse(port int) (commonports.Use, bool) {
	for _, p := range commonports.List {
		if p.Number == port && p.Use != commonports.Plain {
			return p.Use, true
		}
	}
	return commonports.Plain, false
}

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// answerOf is what answers on addr, in one line: on a TLS port the certificate it presents (fingerprint, subject and issuer), on a
// web port (or a TLS port whose handshake failed) the status, Server header and page title of one GET of /, else how the
// connection ended.
func (p exposurePath) answerOf(ctx context.Context, addr netip.AddrPort, use commonports.Use) string {
	rctx, cancel := context.WithTimeout(ctx, pathReadTimeout)
	defer cancel()
	if use == commonports.WebTLS || use == commonports.TLSOnly {
		if line, ok := p.certOf(rctx, addr); ok || use == commonports.TLSOnly {
			return line
		}
	}
	c, err := p.dial(rctx, "tcp", addr.String())
	if err != nil {
		return "connect " + errClass(err)
	}
	defer func() { _ = c.Close() }()
	dl, _ := rctx.Deadline()
	_ = c.SetDeadline(dl)
	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Vedette\r\nAccept: */*\r\nConnection: close\r\n\r\n", addr.Addr()); err != nil {
		return "write " + errClass(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(io.LimitReader(c, pathReadLimit)), nil) // headers and page together: an endless header is cut
	if err != nil {
		return "http " + errClass(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	title := ""
	if m := titleRE.FindSubmatch(body); m != nil {
		title = strings.Join(strings.Fields(html.UnescapeString(string(m[1]))), " ")
	}
	return fmt.Sprintf("http %d %s %s", res.StatusCode, res.Header.Get("Server"), title)
}

// certOf is the TLS certificate addr presents, in one line ("tls" and how the handshake ended when none); false when the handshake failed.
func (p exposurePath) certOf(ctx context.Context, addr netip.AddrPort) (string, bool) {
	c, err := p.dial(ctx, "tcp", addr.String())
	if err != nil {
		return "connect " + errClass(err), false
	}
	dl, _ := ctx.Deadline()
	_ = c.SetDeadline(dl)
	tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) //nolint:gosec // the certificate is read, not trusted
	defer func() { _ = tc.Close() }()
	if err := tc.HandshakeContext(ctx); err != nil {
		return "tls " + errClass(err), false
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "tls no certificate", true
	}
	sum := sha256.Sum256(certs[0].Raw)
	return "tls " + hex.EncodeToString(sum[:]) + " " + certs[0].Subject.String() + " " + certs[0].Issuer.String(), true
}

// errClass is how a connection ended, in one word.
func errClass(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "closed"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	}
	return "error"
}

var _ exposure.PathChecker = exposurePath{}
