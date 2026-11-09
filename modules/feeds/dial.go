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

// dialAllowed is the rule at connect time: plain http only to a private or
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
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ErrBlockedAddress
	}
	if ip, err := netip.ParseAddr(host); err != nil || refusedAlways(ip) {
		return ErrBlockedAddress
	}
	return nil
}

// guardedDial resolves the host exactly once, checks every address against
// dialAllowed for the request scheme (carried in the context), and connects to
// an allowed address literal, so a second DNS answer can never be used.
func guardedDial(res resolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: dialControl}
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
		var last error
		for _, ip := range ips {
			if !dialAllowed(ip, scheme) {
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
