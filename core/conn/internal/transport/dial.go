// Package transport opens the connections of core/conn to devices and services (D-94): HTTPS, SSH and MCP over streamable HTTP.
// Every one of them goes through Dialer, which resolves a name once and checks every address it dials against the address
// policy; none follows a redirect or reads a proxy from the environment; all of them cap the size and the time of what they
// send and read. Nothing here saves anything, and nothing returns device output except to the caller that asked for it: an
// error carries one cleaned line (CleanLine) and never a secret.
package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// Limits (D-94 (1), (2)).
const (
	MaxRequest     = 64 << 10 // bytes of a request body
	MaxResponse    = 1 << 20  // bytes read from a response
	MaxOutput      = 1 << 20  // bytes read from an SSH session
	ConnectTimeout = 5 * time.Second
	CallTimeout    = 15 * time.Second
	LineTimeout    = 20 * time.Second // SSH: one line
	SessionTimeout = 60 * time.Second // SSH: the whole session
)

// RefusedError is a dial the address policy stopped: no socket was opened to Addr.
type RefusedError struct {
	Addr netip.Addr
	Why  string
}

func (e *RefusedError) Error() string {
	return "Vedette never connects to " + e.Why + " (" + e.Addr.String() + ")"
}

// Dialer opens TCP connections to the address an administrator typed. A name is resolved once; every address that came back is
// checked before anything is dialled, and the address of every socket is checked again by the operating system's own hook in
// ControlContext, which sees the real peer of each attempt. Then the first address that answers is used: the TLS or SSH layer
// above talks to that IP with the typed name as the server name, so the name cannot point somewhere else a moment later.
type Dialer struct {
	// Refuse says why an address may never be dialled, or "" when it may. It is core/conn's policy (conn.RefusedAddr with the
	// addresses of the box), asked afresh on every dial. nil refuses nothing and is for tests of other packages only.
	Refuse func(ctx context.Context, a netip.Addr) string
	// Timeout is the whole dial, shared between the resolved addresses; 0 is ConnectTimeout. Tests shorten it.
	Timeout time.Duration

	// lookup and raw are seams for the tests of this package; nil uses the system resolver and a real socket.
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	raw    func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
}

// refusal is what the policy and the test hooks say about one address.
func (d *Dialer) refusal(ctx context.Context, ap netip.AddrPort) string {
	if testAllowed(ap) {
		return ""
	}
	if d.Refuse == nil {
		return ""
	}
	return d.Refuse(ctx, ap.Addr())
}

// DialContext connects to hostport (host:port, the host a name or an IP literal) within ConnectTimeout.
func (d *Dialer) DialContext(ctx context.Context, hostport string) (net.Conn, error) {
	host, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, fmt.Errorf("the address %q is not host:port", CleanLine(hostport))
	}
	port, err := net.DefaultResolver.LookupPort(ctx, "tcp", ps)
	if err != nil {
		return nil, fmt.Errorf("the port %q is not valid", CleanLine(ps))
	}
	budget := d.Timeout
	if budget <= 0 {
		budget = ConnectTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	addrs, err := d.resolve(ctx, strings.Trim(host, "[]"))
	if err != nil {
		return nil, err
	}
	// The whole answer is checked before the first socket: a name that mixes an allowed address and a refused one is refused.
	for _, a := range addrs {
		if why := d.refusal(ctx, netip.AddrPortFrom(a, uint16(port))); why != "" { //nolint:gosec // LookupPort returns 0..65535
			return nil, &RefusedError{Addr: a, Why: why}
		}
	}
	var last error
	for _, a := range addrs {
		ap := netip.AddrPortFrom(a, uint16(port)) //nolint:gosec // LookupPort returns 0..65535
		// Each address gets its own share of the budget: one that does not answer (an AAAA record on a box whose IPv6 goes nowhere)
		// must not use it all up before the next is tried.
		actx, acancel := context.WithTimeout(ctx, budget/time.Duration(len(addrs)))
		c, err := d.dialOne(actx, ap)
		acancel()
		if err == nil {
			return c, nil
		}
		var re *RefusedError
		if errors.As(err, &re) {
			return nil, err
		}
		last = err
	}
	if last == nil {
		last = errors.New("no address")
	}
	return nil, last
}

func (d *Dialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	if a, ok := testResolve(host); ok {
		return []netip.Addr{a}, nil
	}
	lookup := d.lookup
	if lookup == nil {
		lookup = func(ctx context.Context, h string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		}
	}
	addrs, err := lookup(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, errors.New("the name " + CleanLine(host) + " does not resolve")
	}
	// The resolver answers an IPv4 address from the hosts file as ::ffff:a.b.c.d; it is a plain IPv4 address, and the policy refuses
	// the mapped form for what it hides. An address typed by the administrator is not unmapped: it is checked as typed.
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return addrs, nil
}

func (d *Dialer) dialOne(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	if d.raw != nil {
		return d.raw(ctx, ap)
	}
	if to, ok := testRedirect(ap); ok {
		ap = to // tests only: the policy was asked about the address as typed; the socket is the fake's
	}
	nd := net.Dialer{
		Timeout: ConnectTimeout,
		// ControlContext sees the address of the socket itself, whatever path led to it.
		ControlContext: func(ctx context.Context, _, address string, _ syscall.RawConn) error {
			got, err := netip.ParseAddrPort(address)
			if err != nil {
				return errors.New("refused: the socket address is not an IP address")
			}
			if why := d.refusal(ctx, got); why != "" {
				return &RefusedError{Addr: got.Addr(), Why: why}
			}
			return nil
		},
	}
	return nd.DialContext(ctx, "tcp", ap.String())
}
