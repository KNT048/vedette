package ops

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/knt048/vedette/host/api"
)

// The parts of GET /v1/state/net that tell core what the box itself depends on, so that response never acts on it (D-325, D-384): the
// IPv6 default route, the default gateways' MACs and the resolvers in use. Each is a bounded read of a kernel file or of the kernel's
// neighbour table; what does not parse is skipped. No program runs.

const (
	maxRoute6Bytes = 1 << 20
	maxRoute6Lines = 4096
	rtfReject      = 0x200
	maxResolvBytes = 64 << 10
	maxResolvLines = 1024
	maxResolvers   = 16
	maxNeighBytes  = 8 << 20
	nlmsgHdrLen    = 16
	nlmsgError     = 2
	nlmsgDone      = 3
	rtmNewNeigh    = 28
	ndmsgLen       = 12
	ndaDst         = 1
	ndaLLAddr      = 2
	nlaTypeMask    = 0x3fff                                  // drops the NESTED and NET_BYTEORDER flags of an attribute type
	nudValid       = 0x02 | 0x04 | 0x08 | 0x10 | 0x40 | 0x80 // REACHABLE, STALE, DELAY, PROBE, NOARP, PERMANENT: the kernel's NUD_VALID
)

const zero128 = "00000000000000000000000000000000"

// parseDefaultRoute6 reads /proc/net/ipv6_route text and returns the IPv6 default route with the lowest metric (the first on a tie):
// destination ::/0, flags UP and GATEWAY and not REJECT, a unicast next hop (link-local is the usual one: a router advertisement's) on a
// valid interface name. Lines that do not parse are skipped; input and line count are bounded, and the scanner stops at an over-long line
// (as parseDefaultRoute).
func parseDefaultRoute6(r io.Reader) (*api.NetRoute, bool) {
	sc := bufio.NewScanner(io.LimitReader(r, maxRoute6Bytes))
	sc.Buffer(make([]byte, 0, 512), 4096)
	var best *api.NetRoute
	var bestMetric uint64
	for n := 0; sc.Scan() && n < maxRoute6Lines; n++ {
		// destination, its prefix length, source, its prefix length, next hop, metric, refcount, use, flags, device
		f := strings.Fields(sc.Text())
		if len(f) != 10 || f[0] != zero128 || f[1] != "00" || !validIfaceName(f[9]) {
			continue
		}
		metric, err1 := strconv.ParseUint(f[5], 16, 32)
		flags, err2 := strconv.ParseUint(f[8], 16, 32)
		g, err3 := route6Addr(f[4])
		if err1 != nil || err2 != nil || err3 != nil || flags&(rtfUp|rtfGate) != rtfUp|rtfGate || flags&rtfReject != 0 || !unicast6(g) {
			continue
		}
		if best == nil || metric < bestMetric {
			best, bestMetric = &api.NetRoute{Iface: f[9], Gateway: g.String()}, metric
		}
	}
	return best, best != nil
}

// route6Addr reads an address of /proc/net/ipv6_route: 32 hexadecimal digits in network order.
func route6Addr(h string) (netip.Addr, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 16 {
		return netip.Addr{}, errors.New("not an address")
	}
	return netip.AddrFrom16([16]byte(b)), nil
}

// unicast6 is an IPv6 next hop or neighbour: global, unique-local or link-local unicast; not an IPv4-mapped form.
func unicast6(a netip.Addr) bool {
	return a.IsValid() && a.Is6() && !a.Is4In6() && a.Zone() == "" && (a.IsGlobalUnicast() || a.IsLinkLocalUnicast())
}

func (o *Ops) defaultRoute6() *api.NetRoute {
	f, err := os.Open(o.path("proc/net/ipv6_route"))
	if err != nil {
		return nil // no IPv6 in this kernel, or not readable: no route
	}
	defer func() { _ = f.Close() }()
	r, _ := parseDefaultRoute6(f)
	return r
}

// parseResolvConf returns the nameserver addresses of resolv.conf text in file order: IPv4 or IPv6 (a "%zone" is dropped), not loopback
// (the 127.0.0.53 stub of systemd-resolved, ::1), unspecified or multicast; at most maxResolvers. Other lines are skipped; input and line
// count are bounded, and the scanner stops at an over-long line with what came before it.
func parseResolvConf(r io.Reader) []netip.Addr {
	sc := bufio.NewScanner(io.LimitReader(r, maxResolvBytes))
	sc.Buffer(make([]byte, 0, 512), 4096)
	var out []netip.Addr
	for n := 0; sc.Scan() && n < maxResolvLines && len(out) < maxResolvers; n++ {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil {
			continue
		}
		a = a.Unmap().WithZone("")
		if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() {
			continue
		}
		out = append(out, a)
	}
	return out
}

// resolvConfs are the files resolvers reads: the servers systemd-resolved sends queries to (a DHCP lease's as well as configured ones),
// then /etc/resolv.conf (followed when it is a link; on Ubuntu it is resolved's stub, 127.0.0.53, which is skipped).
var resolvConfs = []string{"run/systemd/resolve/resolv.conf", "etc/resolv.conf"}

// resolvers are the DNS servers the box uses now. Both files are read, because either may be what a program on the box uses; a stale
// file only adds an address to response's never-touch list. Deduplicated, at most maxResolvers, never null.
func (o *Ops) resolvers() []string {
	out := []string{}
	for _, rel := range resolvConfs {
		for _, a := range readResolvConf(o.path(rel)) {
			if s := a.String(); len(out) < maxResolvers && !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

// readResolvConf parses one resolv.conf; a file that is absent, not regular or unreadable has no servers. The open never blocks on a FIFO.
func readResolvConf(path string) []netip.Addr {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // one of the fixed resolvConfs under the root
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil
	}
	return parseResolvConf(f)
}

// gatewayMACs fills the MAC of each default route's gateway from the kernel's neighbour table. A table that cannot be read leaves them
// empty: core then keeps the MAC it saw before.
func (o *Ops) gatewayMACs(ifaces []HostIface, routes ...*api.NetRoute) {
	if !slices.ContainsFunc(routes, func(r *api.NetRoute) bool { return r != nil }) {
		return
	}
	dump, err := o.d.NeighDump()
	if err != nil {
		o.log.Debug("the neighbour table could not be read; state/net reports no gateway MAC", "err", err)
		return
	}
	for _, r := range routes {
		if r == nil {
			continue
		}
		gw, err := netip.ParseAddr(r.Gateway)
		if err != nil {
			continue
		}
		for _, h := range ifaces {
			if h.Name == r.Iface {
				r.MAC = neighbourMAC(dump, h.Index, gw)
				break
			}
		}
	}
}

// neighbourMAC returns the MAC the kernel's neighbour table holds for addr on the interface with index ifindex, "" when there is none.
// The entry must be usable (NUD_VALID: not incomplete or failed) with a 6-byte unicast, non-zero link-layer address. dump is the reply
// of an RTM_GETNEIGH dump, netlink messages in host byte order, read up to maxNeighBytes; a message or attribute whose length does not
// fit, an error or the end of the dump ends the read.
func neighbourMAC(dump []byte, ifindex int, addr netip.Addr) string {
	if ifindex <= 0 || !addr.IsValid() {
		return ""
	}
	addr = addr.WithZone("")
	b := dump[:min(len(dump), maxNeighBytes)]
	for len(b) >= nlmsgHdrLen {
		l := int(binary.NativeEndian.Uint32(b[0:4]))
		typ := binary.NativeEndian.Uint16(b[4:6])
		if l < nlmsgHdrLen || l > len(b) || typ == nlmsgDone || typ == nlmsgError {
			return ""
		}
		if typ == rtmNewNeigh {
			if mac := neighEntryMAC(b[nlmsgHdrLen:l], ifindex, addr); mac != "" {
				return mac
			}
		}
		b = b[min(align4(l), len(b)):]
	}
	return ""
}

// neighEntryMAC reads one neighbour message (struct ndmsg, then attributes) and returns its MAC when it is the usable entry of addr on
// ifindex.
func neighEntryMAC(m []byte, ifindex int, addr netip.Addr) string {
	if len(m) < ndmsgLen || int64(binary.NativeEndian.Uint32(m[4:8])) != int64(ifindex) || binary.NativeEndian.Uint16(m[8:10])&nudValid == 0 {
		return ""
	}
	var dst, ll []byte
	for a := m[ndmsgLen:]; len(a) >= 4; {
		n := int(binary.NativeEndian.Uint16(a[0:2]))
		if n < 4 || n > len(a) {
			return ""
		}
		switch binary.NativeEndian.Uint16(a[2:4]) & nlaTypeMask {
		case ndaDst:
			dst = a[4:n]
		case ndaLLAddr:
			ll = a[4:n]
		}
		a = a[min(align4(n), len(a)):]
	}
	d, ok := netip.AddrFromSlice(dst)
	if !ok || d != addr || len(ll) != 6 || ll[0]&1 != 0 || slices.Equal(ll, make([]byte, 6)) {
		return ""
	}
	return net.HardwareAddr(ll).String()
}

func align4(n int) int { return (n + 3) &^ 3 }
