package feeds

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// ErrBlockedAddress is a connection the dialer refuses by address.
var ErrBlockedAddress = errors.New("feeds: connection to this address is refused")

// ErrOwnAddress is ErrBlockedAddress for an address of the box itself that is not loopback: one of its interfaces,
// the address vedette-host reports, or the container's default gateway (on a container-only install, the machine
// Docker runs on). userError says so in plain words (D-420 (7)).
var ErrOwnAddress = fmt.Errorf("%w: it is the machine Vedette runs on", ErrBlockedAddress)

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
	box           func() ([]netip.Addr, bool)                                       // nil: the container's own interfaces only
	gateway       func() (netip.Addr, bool)                                         // the container's default gateway, part of the box set (as in core/conn)
	allowLoopback bool                                                              // tests only: Fetcher.allowLoopback is unexported
	dial          func(ctx context.Context, network, addr string) (net.Conn, error) // tests only: replaces the connect, after every check
}

// boxAddrs is every address that is the box itself; known is false while Fetcher.BoxAddrs says so.
func (g *destGuard) boxAddrs() (out []netip.Addr, known bool) {
	known = true
	if g != nil && g.box != nil {
		out, known = g.box()
	}
	if g != nil && g.gateway != nil {
		if gw, ok := g.gateway(); ok {
			out = append(out, gw.Unmap())
		}
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

// refused reports whether ip, or the IPv4 address embedded in it, is loopback or one of box. Loopback addresses follow
// allowLoopback alone (the box list always holds them).
func (g *destGuard) refused(ip netip.Addr, box []netip.Addr) bool {
	for _, f := range addrForms(ip) {
		if f.IsLoopback() {
			if g == nil || !g.allowLoopback {
				return true
			}
			continue
		}
		for _, b := range box {
			if b.Unmap().WithZone("") == f {
				return true
			}
		}
	}
	return false
}

// own reports whether ip is refused as one of box rather than as loopback (refused is true for both).
func (g *destGuard) own(ip netip.Addr, box []netip.Addr) bool {
	for _, f := range addrForms(ip) {
		if f.IsLoopback() {
			return false
		}
	}
	return g.refused(ip, box)
}

// addrForms is ip plus the IPv4 address a transition form carries: NAT64 (64:ff9b::/96, 64:ff9b:1::/48), 6to4 (2002::/16)
// and IPv4-compatible (::a.b.c.d). A connection to one of them reaches that IPv4 address through a translator, so both are checked.
func addrForms(ip netip.Addr) []netip.Addr {
	ip = ip.Unmap().WithZone("")
	out := []netip.Addr{ip}
	if !ip.Is6() {
		return out
	}
	b := ip.As16()
	var v4 [4]byte
	switch {
	case ip.Is4In6():
		return out
	case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 && b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0:
		copy(v4[:], b[12:16])
	case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && b[4] == 0 && b[5] == 1:
		for _, x := range nat64Local(b) {
			out = append(out, netip.AddrFrom4(x))
		}
		return out
	case b[0] == 0x20 && b[1] == 0x02:
		copy(v4[:], b[2:6])
	case allZero(b[:12]) && !ip.IsUnspecified() && ip != netip.IPv6Loopback():
		copy(v4[:], b[12:16])
	default:
		return out
	}
	return append(out, netip.AddrFrom4(v4))
}

// nat64Local lists the IPv4 addresses a 64:ff9b:1::/48 (RFC 8215) address can carry. The operator's prefix is a sub-prefix of that /48,
// so its length is /48, /56, /64 or /96 (never /32 or /40) and is not known from the address: it is read in each of those RFC 6052 layouts
// (byte 8 is the reserved u octet) and every reading is judged. A reading inside 0.0.0.0/8 is dropped: a translator never forwards to
// "this network", and it is what the zero suffix of a shorter prefix looks like in a longer layout.
func nat64Local(b [16]byte) [][4]byte {
	var out [][4]byte
	for _, v4 := range [][4]byte{
		{b[6], b[7], b[9], b[10]},
		{b[7], b[9], b[10], b[11]},
		{b[9], b[10], b[11], b[12]},
		{b[12], b[13], b[14], b[15]},
	} {
		if v4[0] != 0 {
			out = append(out, v4)
		}
	}
	return out
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// nonGlobal lists IPv4 ranges that are not global unicast (IsPrivate, loopback, link-local and multicast are tested apart).
var nonGlobal = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fec0::/10"),
}

// globalOnly is the only kind of address a pull may connect to while the box's own addresses are unknown: global unicast,
// none of private (RFC 1918, ULA), loopback, link-local, CGNAT or the other special ranges, in any of its transition forms.
func globalOnly(ip netip.Addr) bool {
	for _, f := range addrForms(ip) {
		if !f.IsGlobalUnicast() || f.IsPrivate() || f.IsLoopback() || f.IsLinkLocalUnicast() {
			return false
		}
		for _, p := range nonGlobal {
			if p.Contains(f) {
				return false
			}
		}
	}
	return true
}

// metadataAddrs are cloud instance-metadata endpoints (link-local ones are
// already covered by the link-local rule; the others are listed here).
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("fd00:ec2::254"), netip.MustParseAddr("fd20:ce::254"),
	netip.MustParseAddr("100.100.100.200"), netip.MustParseAddr("192.0.0.192"),
}

// refusedAlways: link-local (169.254/16, fe80::/10), the metadata endpoints,
// unspecified and multicast. No feed, https or not, has a reason to reach them.
func refusedAlways(ip netip.Addr) bool {
	for _, f := range addrForms(ip) {
		if refusedForm(f) {
			return true
		}
	}
	return false
}

func refusedForm(ip netip.Addr) bool {
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
	return destControl(nil, nil, false)("", address, nil)
}

// destControl is dialControl plus the box rule (D-208): the same check again on the socket, after resolution.
// strict is the rule while the box's addresses are unknown: only global unicast (globalOnly).
func destControl(g *destGuard, box []netip.Addr, strict bool) func(_, address string, _ syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return ErrBlockedAddress
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || refusedAlways(ip) {
			return ErrBlockedAddress
		}
		if strict && !globalOnly(ip) {
			return ErrBoxAddrsUnknown
		}
		if box != nil && g.refused(ip, box) {
			if g.own(ip, box) {
				return ErrOwnAddress
			}
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
		strict := !known // D-208: unknown addresses: a public address only; the rest waits for the answer
		if box == nil {
			box = []netip.Addr{} // non-nil: the socket hook checks the box rule too
		}
		d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: destControl(g, box, strict)}
		var last error
		waiting, own := false, false
		for _, ip := range ips {
			if !dialAllowed(ip, scheme) {
				continue
			}
			if g.refused(ip, box) {
				own = own || g.own(ip, box)
				continue
			}
			if strict && !globalOnly(ip) {
				waiting = true
				continue
			}
			dialFn := d.DialContext
			if g != nil && g.dial != nil {
				dialFn = g.dial
			}
			conn, err := dialFn(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		if last == nil {
			if waiting {
				return nil, ErrBoxAddrsUnknown
			}
			if own {
				return nil, ErrOwnAddress
			}
			return nil, ErrBlockedAddress
		}
		return nil, last
	}
}
