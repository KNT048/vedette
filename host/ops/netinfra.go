package ops

import (
	"bufio"
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/knt048/vedette/host/api"
)

// The parts of GET /v1/state/net that tell core what the box itself depends on, so that response never acts on it (D-325, D-450): the
// IPv6 default routes, the default gateways' MACs and the resolvers in use. Each is a bounded read of a kernel file or of the kernel's
// neighbour table; what does not parse is skipped. No program runs.

const (
	maxRoute6Bytes = 1 << 20
	maxRoute6Lines = 4096
	maxRoutes6     = 16
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
	nlaTypeMask    = 0x3fff // drops the NESTED and NET_BYTEORDER flags of an attribute type
	// REACHABLE, STALE, DELAY, PROBE, PERMANENT: the kernel's NUD_VALID without NOARP (a NOARP entry's address is not one a
	// neighbour answered with; D-450 review, LOW 2)
	nudValid = 0x02 | 0x04 | 0x08 | 0x10 | 0x80
	// the address dump (D-405): struct ifaddrmsg, its IFA_ADDRESS, IFA_LOCAL and IFA_FLAGS attributes, and IFA_F_PERMANENT
	rtmNewAddr    = 20
	ifaddrmsgLen  = 8
	ifaAddress    = 1
	ifaLocal      = 2
	ifaFlags      = 8
	ifaFPermanent = 0x80
	maxAddrBytes  = 8 << 20
)

const zero128 = "00000000000000000000000000000000"

// parseDefaultRoutes6 reads /proc/net/ipv6_route text and returns every IPv6 default route, lowest metric first (file order on a tie):
// destination ::/0, flags UP and GATEWAY and not REJECT, a unicast next hop (link-local is the usual one: a router advertisement's) on a
// valid interface name. The file lists every routing table (a VPN's, a VRF's, a policy table's) and each next hop of an equal-cost
// route on a line of its own, and any of them may carry the box's traffic, so all are reported (D-450 review, LOW 1); the same next hop
// on the same card once. Lines that do not parse are skipped; input and line count are bounded, the maxRoutes6 lowest-metric routes are
// kept, and the scanner stops at an over-long line (as parseDefaultRoute). Never nil.
func parseDefaultRoutes6(r io.Reader) []api.NetRoute {
	sc := bufio.NewScanner(io.LimitReader(r, maxRoute6Bytes))
	sc.Buffer(make([]byte, 0, 512), 4096)
	type route struct {
		api.NetRoute
		metric uint64
	}
	var all []route
	index := map[api.NetRoute]int{}
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
		nr := api.NetRoute{Iface: f[9], Gateway: g.String()}
		if i, ok := index[nr]; ok {
			all[i].metric = min(all[i].metric, metric)
		} else {
			index[nr] = len(all)
			all = append(all, route{nr, metric}) // bounded by maxRoute6Lines
		}
	}
	// sorted before the cut, so a low-metric route late in the file is never the one dropped (review round 2, LOW 1)
	slices.SortStableFunc(all, func(a, b route) int { return cmp.Compare(a.metric, b.metric) })
	out := make([]api.NetRoute, 0, min(len(all), maxRoutes6))
	for _, x := range all[:min(len(all), maxRoutes6)] {
		out = append(out, x.NetRoute)
	}
	return out
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

func (o *Ops) defaultRoutes6() []api.NetRoute {
	f, err := os.Open(o.path("proc/net/ipv6_route"))
	if err != nil {
		return []api.NetRoute{} // no IPv6 in this kernel, or not readable: no route
	}
	defer func() { _ = f.Close() }()
	return parseDefaultRoutes6(f)
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
// then /etc/resolv.conf (on Ubuntu a link to resolved's stub, 127.0.0.53, which is skipped).
var resolvConfs = []string{"run/systemd/resolve/resolv.conf", "etc/resolv.conf"}

// resolvers are the DNS servers the box uses now. Both files are read, because either may be what a program on the box uses; a stale
// file only adds an address to response's never-touch list. Deduplicated, at most maxResolvers, never null.
func (o *Ops) resolvers() []string {
	out := []string{}
	for _, rel := range resolvConfs {
		for _, a := range o.readResolvConf(rel) {
			if s := a.String(); len(out) < maxResolvers && !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

// readResolvConf parses one resolv.conf. The host is root and /run/systemd/resolve belongs to systemd-resolve (D-450 review, M2): a
// link there to /dev/watchdog would arm it when opened, one to /proc/kmsg would block the read. So a link is followed one level only,
// as Ubuntu's /etc/resolv.conf needs (an absolute target is read under the root), and the file is then opened by readResolvFile, which
// never follows a link in the last component.
func (o *Ops) readResolvConf(rel string) []netip.Addr {
	p := o.path(rel)
	if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		t, err := os.Readlink(p)
		if err != nil {
			return nil
		}
		if filepath.IsAbs(t) {
			p = o.path(t)
		} else {
			p = filepath.Join(filepath.Dir(p), t)
		}
	}
	return readResolvFile(p)
}

// readResolvFile reads a resolv.conf that is a regular file of 1 byte to maxResolvBytes (procfs files report size 0) at path itself, not
// through a link: lstat first, then an open with O_NOFOLLOW, O_NONBLOCK (a FIFO swapped in never blocks) and O_NOCTTY, then fstat must be
// the same regular file. Anything else has no servers. (A device cannot be swapped in between the lstat and the open: a link is refused
// by O_NOFOLLOW, a hard link cannot cross from /dev into /run or /etc, and making a device node needs CAP_MKNOD.)
func readResolvFile(path string) []netip.Addr {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > maxResolvBytes {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0) //nolint:gosec // a fixed resolv.conf path under the root
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	if fst, err := f.Stat(); err != nil || !fst.Mode().IsRegular() || !os.SameFile(st, fst) {
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

// dynamicAddrs reads the reply of an RTM_GETADDR dump and returns, by interface index, the addresses that have a lease: the kernel's
// IFA_F_PERMANENT flag is unset, which is what `ip address` prints as "dynamic" (a DHCP lease of systemd-networkd or NetworkManager,
// an IPv6 SLAAC address). An address set by hand or by a static configuration is permanent. The 32-bit IFA_FLAGS attribute wins over
// the 8-bit field of ifaddrmsg when present; for IPv4 the address is IFA_LOCAL (IFA_ADDRESS is the peer on a point-to-point link), as
// the net package reads it. Read up to maxAddrBytes; a message or attribute whose length does not fit, an error or the end of the
// dump ends the read with what came before (D-405).
// ponytail: dhclient (ifupdown) adds its lease without a lifetime, so it reads as permanent there; no Ubuntu or Debian server
// installs it any more, and the upgrade is reading the lease files of the network manager.
func dynamicAddrs(dump []byte) map[int][]netip.Prefix {
	out := map[int][]netip.Prefix{}
	b := dump[:min(len(dump), maxAddrBytes)]
	for len(b) >= nlmsgHdrLen {
		l := int(binary.NativeEndian.Uint32(b[0:4]))
		typ := binary.NativeEndian.Uint16(b[4:6])
		if l < nlmsgHdrLen || l > len(b) || typ == nlmsgDone || typ == nlmsgError {
			break
		}
		if typ == rtmNewAddr {
			if idx, p, ok := dynamicAddr(b[nlmsgHdrLen:l]); ok {
				out[idx] = append(out[idx], p)
			}
		}
		b = b[min(align4(l), len(b)):]
	}
	return out
}

// dynamicAddr reads one address message (struct ifaddrmsg, then attributes): its interface index and address when it has a lease.
func dynamicAddr(m []byte) (int, netip.Prefix, bool) {
	if len(m) < ifaddrmsgLen {
		return 0, netip.Prefix{}, false
	}
	bits, flags, idx := int(m[1]), uint32(m[2]), int(binary.NativeEndian.Uint32(m[4:8]))
	var addr, local []byte
	for a := m[ifaddrmsgLen:]; len(a) >= 4; {
		n := int(binary.NativeEndian.Uint16(a[0:2]))
		if n < 4 || n > len(a) {
			return 0, netip.Prefix{}, false
		}
		switch binary.NativeEndian.Uint16(a[2:4]) & nlaTypeMask {
		case ifaAddress:
			addr = a[4:n]
		case ifaLocal:
			local = a[4:n]
		case ifaFlags:
			if n == 8 {
				flags = binary.NativeEndian.Uint32(a[4:8])
			}
		}
		a = a[min(align4(n), len(a)):]
	}
	if local != nil {
		addr = local
	}
	ip, ok := netip.AddrFromSlice(addr)
	if !ok || idx <= 0 || flags&ifaFPermanent != 0 {
		return 0, netip.Prefix{}, false
	}
	p := netip.PrefixFrom(ip.Unmap(), bits)
	return idx, p, p.IsValid()
}
