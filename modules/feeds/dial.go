package feeds

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// ErrBlockedAddress is a connection the dialer refuses by address.
var ErrBlockedAddress = errors.New("feeds: connection to this address is refused")

// resolver turns a host name into addresses. Tests replace it.
type resolver func(ctx context.Context, host string) ([]netip.Addr, error)

func systemResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

type schemeKey struct{}

// guardKey carries the destGuard of one Fetch to the dialer (the Client is shared, the box addresses are asked per connection).
type guardKey struct{}

// ErrBoxAddrsUnknown means the box does not know its own addresses yet (vedette-host has not answered since the start), so no
// destination can be checked against them: the connection is refused, as notify does (D-86 (2), D-208). The next pull retries.
var ErrBoxAddrsUnknown = errors.New("feeds: the box's own addresses are not known yet")

// destGuard refuses the box itself (D-208): loopback, which in the shipped container is Vedette, and the box's own host
// addresses (its interfaces plus what vedette-host reports), never the LAN subnets around them.
type destGuard struct {
	box           func() ([]netip.Addr, bool) // nil: the container's own interfaces only
	allowLoopback bool                        // tests only: Fetcher.allowLoopback is unexported
}

// boxAddrs is every address that is the box itself; known is false while Fetcher.BoxAddrs says so.
func (g *destGuard) boxAddrs() (out []netip.Addr, known bool) {
	known = true
	if g != nil && g.box != nil {
		out, known = g.box()
	}
	if ifs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifs {
			if p, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(p.IP); ok {
					out = append(out, ip.Unmap())
				}
			}
		}
	}
	return out, known
}

// refused reports whether ip is loopback or one of box. Loopback addresses follow allowLoopback alone (the box list always holds them).
func (g *destGuard) refused(ip netip.Addr, box []netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	if ip.IsLoopback() {
		return g == nil || !g.allowLoopback
	}
	for _, b := range box {
		if b.Unmap().WithZone("") == ip {
			return true
		}
	}
	return false
}

// metadataAddrs are cloud instance-metadata endpoints (link-local ones are
// already covered by the link-local rule; the others are listed here).
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("100.100.100.200"), netip.MustParseAddr("192.0.0.192"),
}

// refusedAlways: link-local (169.254/16, fe80::/10), the metadata endpoints,
// unspecified and multicast. No feed, https or not, has a reason to reach them.
func refusedAlways(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, m := range metadataAddrs {
		if ip == m {
			return true
		}
	}
	return false
}

// dialAllowed is the scheme rule at connect time: plain http only to a private or
// loopback address (INV-2 lets internal names use http; a name that resolves
// to a public address does not), https to any address that is not refused.
func dialAllowed(ip netip.Addr, scheme string) bool {
	if refusedAlways(ip) {
		return false
	}
	if scheme == "http" {
		ip = ip.Unmap()
		return ip.IsPrivate() || ip.IsLoopback()
	}
	return true
}

// dialControl runs on the socket just before connect, after any resolution, so
// it also stops a connection that was redirected by DNS rebinding.
func dialControl(_, address string, _ syscall.RawConn) error {
	return destControl(nil, nil)("", address, nil)
}

// destControl is dialControl plus the box rule (D-208): the same check again on the socket, after resolution.
func destControl(g *destGuard, box []netip.Addr) func(_, address string, _ syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return ErrBlockedAddress
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || refusedAlways(ip) {
			return ErrBlockedAddress
		}
		if box != nil && g.refused(ip, box) {
			return ErrBlockedAddress
		}
		return nil
	}
}

// guardedDial resolves the host exactly once, checks every address against
// dialAllowed for the request scheme (carried in the context), and connects to
// an allowed address literal, so a second DNS answer can never be used.
func guardedDial(res resolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		var ips []netip.Addr
		if ip, perr := netip.ParseAddr(host); perr == nil {
			ips = []netip.Addr{ip}
		} else if ips, err = res(ctx, host); err != nil {
			return nil, err
		}
		scheme, _ := ctx.Value(schemeKey{}).(string)
		g, _ := ctx.Value(guardKey{}).(*destGuard)
		box, known := g.boxAddrs()
		if !known {
			return nil, ErrBoxAddrsUnknown
		}
		if box == nil {
			box = []netip.Addr{} // non-nil: the socket hook checks the box rule too
		}
		d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: destControl(g, box)}
		var last error
		for _, ip := range ips {
			if !dialAllowed(ip, scheme) || g.refused(ip, box) {
				continue
			}
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		if last == nil {
			return nil, ErrBlockedAddress
		}
		return nil, last
	}
}
