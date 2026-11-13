package feeds

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// ErrBlockedAddress is a connection the dialer refuses by address.
var ErrBlockedAddress = errors.New("feeds: connection to this address is refused")

// ErrOwnAddress is ErrBlockedAddress for Vedette itself (D-446): loopback, an address of core's own container, or one of
// Vedette's own ports on the machine's addresses (vedette-host's, the container's gateway). userError says so in plain words.
var ErrOwnAddress = fmt.Errorf("%w: it is Vedette itself", ErrBlockedAddress)

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

// vedettePorts are the ports Vedette itself answers on at the machine's addresses (D-446): the interface 8443, the sensor link 8444,
// MCP 8765, syslog 514 and syslog over TLS 6514 (install.sh preflight, the core unit's PublishPort lines, the container-only compose).
// Same list in notify, logs and ai.
var vedettePorts = []uint16{514, 6514, 8443, 8444, 8765}

// ownAddrs is Vedette itself (D-446): self, the addresses of core's own container, on every port (loopback is judged apart), and
// machine, the addresses of the machine it runs on (what vedette-host reports, the container's default gateway), on vedettePorts only:
// another program on the machine is a normal source. Every address is unmapped and without zone.
type ownAddrs struct{ self, machine []netip.Addr }

// destGuard refuses Vedette itself (D-208, D-446), never the LAN subnets around it.
type destGuard struct {
	box           func() ([]netip.Addr, bool)                                       // the machine's addresses (vedette-host); nil: none
	gateway       func() (netip.Addr, bool)                                         // the container's default gateway: the machine too
	allowLoopback bool                                                              // tests only: Fetcher.allowLoopback is unexported
	dial          func(ctx context.Context, network, addr string) (net.Conn, error) // tests only: replaces the connect, after every check
}

// ownAddrs is Vedette itself as it is now; known is false while Fetcher.BoxAddrs says so.
func (g *destGuard) ownAddrs() (out ownAddrs, known bool) {
	known = true
	if g != nil && g.box != nil {
		var m []netip.Addr
		m, known = g.box()
		for _, a := range m {
			out.machine = append(out.machine, a.Unmap().WithZone(""))
		}
	}
	if g != nil && g.gateway != nil {
		if gw, ok := g.gateway(); ok {
			out.machine = append(out.machine, gw.Unmap().WithZone(""))
		}
	}
	out.self = selfAddrs()
	return out, known
}

// selfAddrs are the addresses of this process's own interfaces (in the shipped container: core itself), loopback left out.
func selfAddrs() []netip.Addr {
	var out []netip.Addr
	if ifs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifs {
			if p, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(p.IP); ok && !ip.Unmap().IsLoopback() {
					out = append(out, ip.Unmap().WithZone(""))
				}
			}
		}
	}
	return out
}

// refused reports whether ip at port, or the IPv4 address embedded in it, is Vedette itself: loopback (unless allowLoopback),
// one of own.self, or one of own.machine on a port of vedettePorts.
func (g *destGuard) refused(ip netip.Addr, port uint16, own ownAddrs) bool {
	vport := slices.Contains(vedettePorts, port)
	for _, f := range addrForms(ip) {
		if f.IsLoopback() {
			if g == nil || !g.allowLoopback {
				return true
			}
			continue
		}
		if slices.Contains(own.self, f) || vport && slices.Contains(own.machine, f) {
			return true
		}
	}
	return false
}

// dialPort is the port of a host:port the dialer is given (0 when it has none).
func dialPort(s string) uint16 {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
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

// nat64Layouts are the RFC 6052 layouts a 64:ff9b:1::/48 sub-prefix can have (never /32 or /40): the prefix length and the byte
// offsets of the four IPv4 octets (byte 8 is the reserved u octet).
var nat64Layouts = []struct {
	bits int
	at   [4]int
}{{48, [4]int{6, 7, 9, 10}}, {56, [4]int{7, 9, 10, 11}}, {64, [4]int{9, 10, 11, 12}}, {96, [4]int{12, 13, 14, 15}}}

func nat64Embed(b [16]byte, at [4]int) [4]byte {
	return [4]byte{b[at[0]], b[at[1]], b[at[2]], b[at[3]]}
}

// nat64Always is what a guard never allows whatever the box's own addresses are (loopback, link-local, multicast, unspecified,
// broadcast, cloud metadata): a reading of such an address is judged in every layout, learned or not (D-442 (2)).
func nat64Always(a netip.Addr) bool {
	return a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || slices.Contains(metadataAddrs, a)
}

// nat64Local lists the IPv4 addresses a 64:ff9b:1::/48 (RFC 8215) address can carry. The operator's prefix is a sub-prefix of that /48
// and its length is not in the address. The address is read in each layout and every reading is judged, so a forbidden IPv4 address
// is never missed. When the network's own NAT64 prefix was learned (nat64Prefixes, RFC 7050) and covers the address, the learned
// layouts (all that cover it) are read for the checks that depend on the network (private ranges, the box's own addresses), and the
// other layouts only for nat64Always: DNS can narrow the first group, never switch off the second. A learned reading inside 0.0.0.0/8
// falls back to every layout. Otherwise a reading inside 0.0.0.0/8 is dropped: a translator never forwards to "this network", and it
// is what the zero suffix of a shorter prefix looks like in a longer layout. An operator prefix whose own bytes read as an
// always-refused address in a shorter layout (byte 6, or byte 7 for a /64 or /96, of 127 or 224-239, or the bytes a9fe) has every
// NAT64 destination refused (a known false positive: it fails closed).
func nat64Local(b [16]byte) [][4]byte {
	addr := netip.AddrFrom16(b)
	var out [][4]byte
	add := func(v4 [4]byte) {
		if v4[0] != 0 && !slices.Contains(out, v4) {
			out = append(out, v4)
		}
	}
	var bits []int
	for _, p := range nat64Prefixes() {
		if p.Contains(addr) {
			bits = append(bits, p.Bits())
		}
	}
	if len(bits) > 0 {
		learned := true
		for _, l := range nat64Layouts {
			if slices.Contains(bits, l.bits) {
				if v4 := nat64Embed(b, l.at); v4[0] == 0 {
					learned = false
				} else {
					add(v4)
				}
			}
		}
		if learned {
			for _, l := range nat64Layouts {
				if v4 := nat64Embed(b, l.at); nat64Always(netip.AddrFrom4(v4)) {
					add(v4)
				}
			}
			return out
		}
		out = nil
	}
	for _, l := range nat64Layouts {
		add(nat64Embed(b, l.at))
	}
	return out
}

// learnNAT64 reads the AAAA answers for ipv4only.arpa (RFC 7050, what Android, iOS and systemd-resolved do): an answer inside
// 64:ff9b:1::/48 that carries 192.0.0.170 or 192.0.0.171 in exactly one layout, with a zero u octet, gives the prefix and its length.
func learnNAT64(answers []netip.Addr) []netip.Prefix {
	local := netip.MustParsePrefix("64:ff9b:1::/48")
	var out []netip.Prefix
	for _, a := range answers {
		a = a.Unmap()
		if !a.Is6() || !local.Contains(a) {
			continue
		}
		b := a.As16()
		if b[8] != 0 {
			continue
		}
		bits := 0
		for _, l := range nat64Layouts {
			if v4 := nat64Embed(b, l.at); v4 == [4]byte{192, 0, 0, 170} || v4 == [4]byte{192, 0, 0, 171} {
				if bits != 0 {
					bits = -1
					break
				}
				bits = l.bits
			}
		}
		if bits > 0 {
			if p := netip.PrefixFrom(a, bits).Masked(); !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out
}

// nat64Cache asks the system resolver for ipv4only.arpa only when a 64:ff9b:1::/48 address is judged, for at most 2 s, and keeps the
// answer 6 hours (10 minutes when nothing was learned or the lookup failed, so a missing DNS64 costs one lookup per 10 minutes).
// One lookup runs at a time and nobody waits for it: a caller that finds it running (or a fresh cache) gets what is known, which is
// nothing at first, and nothing means every layout. The query carries no customer data (D-442).
type nat64Cache struct {
	mu       sync.Mutex
	lookup   func(ctx context.Context) ([]netip.Addr, error)
	now      func() time.Time
	prefixes []netip.Prefix
	until    time.Time
	busy     bool
}

func (c *nat64Cache) get() []netip.Prefix {
	c.mu.Lock()
	if c.busy || c.now().Before(c.until) {
		defer c.mu.Unlock()
		return c.prefixes
	}
	c.busy = true
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	answers, err := c.lookup(ctx)
	prefixes := learnNAT64(answers)
	ttl := 6 * time.Hour
	if err != nil || len(prefixes) == 0 {
		ttl = 10 * time.Minute
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.busy, c.prefixes, c.until = false, prefixes, c.now().Add(ttl)
	return prefixes
}

// nat64Prefixes is the learned NAT64 prefixes of this network. Tests replace it.
var nat64Prefixes = (&nat64Cache{
	lookup: func(ctx context.Context) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip6", "ipv4only.arpa")
	},
	now: time.Now,
}).get

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

// destControl is dialControl plus the rule of Vedette itself (D-208, D-446): the same check again on the socket, after resolution.
// strict is the rule while the box's addresses are unknown: only global unicast (globalOnly). own nil: dialControl, no own rule.
func destControl(g *destGuard, own *ownAddrs, strict bool) func(_, address string, _ syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, port, err := net.SplitHostPort(address)
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
		if own != nil && g.refused(ip, dialPort(port), *own) {
			return ErrOwnAddress
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
		own, known := g.ownAddrs()
		strict := !known // D-208: unknown addresses: a public address only; the rest waits for the answer
		d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: destControl(g, &own, strict)}
		var last error
		waiting, self := false, false
		for _, ip := range ips {
			if !dialAllowed(ip, scheme) {
				continue
			}
			if g.refused(ip, dialPort(port), own) {
				self = true
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
			if self {
				return nil, ErrOwnAddress
			}
			return nil, ErrBlockedAddress
		}
		return nil, last
	}
}
