package ops

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
)

// --- /proc/net/ipv6_route (D-390) ----------------------------------------------------------------------

// The kernel's own text: a default route learned from a router advertisement (flags UP|GATEWAY|EXPIRES|ADDRCONF), the on-link
// prefix, and the "unreachable" default the kernel keeps on lo (REJECT, no gateway).
const route6Text = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00450003     eth0\n" +
	"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n" +
	"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n"

func route6Line(nexthop, metric, flags, dev string) string {
	return zero128 + " 00 " + zero128 + " 00 " + nexthop + " " + metric + " 00000001 00000000 " + flags + " " + dev + "\n"
}

func routesText(rs []api.NetRoute) string {
	var s []string
	for _, r := range rs {
		s = append(s, r.Iface+" "+r.Gateway+" "+r.MAC)
	}
	return strings.Join(s, ",")
}

func TestParseDefaultRoutes6(t *testing.T) {
	t.Parallel()
	ll1, ll2, gl := "fe800000000000000000000000000001", "fe800000000000000000000000000002", "20010db8000000000000000000000001"
	cases := []struct{ name, text, want string }{
		{"router advertisement", route6Text, "eth0 fe80::1 "},
		{"lowest metric first", route6Line(ll1, "00000400", "00000003", "eth0") + route6Line(gl, "00000064", "00000003", "eth1"), "eth1 2001:db8::1 ,eth0 fe80::1 "},
		{"file order on a tie", route6Line(ll1, "00000064", "00000003", "eth0") + route6Line(gl, "00000064", "00000003", "eth1"), "eth0 fe80::1 ,eth1 2001:db8::1 "},
		// every table and every equal-cost next hop is a gateway the box may use (review LOW 1); one next hop on one card is listed once
		{"equal-cost next hops and another table", route6Line(ll1, "00000400", "00000003", "eth0") + route6Line(ll2, "00000400", "00000003", "eth0") + route6Line(gl, "00000001", "00000003", "wg0") + route6Line(ll1, "00000064", "00000003", "eth0"),
			"wg0 2001:db8::1 ,eth0 fe80::1 ,eth0 fe80::2 "},
		{"same next hop on two cards", route6Line(ll1, "00000400", "00000003", "eth0") + route6Line(ll1, "00000400", "00000003", "eth1"), "eth0 fe80::1 ,eth1 fe80::1 "},
		{"down route skipped", route6Line(ll1, "00000001", "00000002", "eth0"), ""},
		{"reject skipped", route6Line(ll1, "00000001", "00000203", "eth0"), ""},
		{"no gateway flag", route6Line(ll1, "00000001", "00000001", "eth0"), ""},
		{"zero next hop", route6Line(zero128, "00000001", "00000003", "eth0"), ""},
		{"loopback next hop", route6Line("00000000000000000000000000000001", "00000001", "00000003", "eth0"), ""},
		{"multicast next hop", route6Line("ff020000000000000000000000000001", "00000001", "00000003", "eth0"), ""},
		{"IPv4-mapped next hop", route6Line("00000000000000000000ffffc0a80a01", "00000001", "00000003", "eth0"), ""},
		{"not a default destination", strings.Replace(route6Line(ll1, "00000001", "00000003", "eth0"), zero128+" 00", "20010db8000000000000000000000000 00", 1), ""},
		{"a prefix length", strings.Replace(route6Line(ll1, "00000001", "00000003", "eth0"), zero128+" 00", zero128+" 40", 1), ""},
		{"bad iface name", route6Line(ll1, "00000001", "00000003", "-x"), ""},
		{"short hex", route6Line("fe8000000000000000000000000001", "00000001", "00000003", "eth0"), ""},
		{"bad metric", route6Line(ll1, "zz", "00000003", "eth0"), ""},
		{"extra field", strings.TrimSuffix(route6Line(ll1, "00000001", "00000003", "eth0"), "\n") + " x\n", ""},
		{"valid after garbage", "garbage\n\x00\x01\n\t\t\n" + route6Text, "eth0 fe80::1 "},
		{"empty", "", ""},
		{"a very long line", strings.Repeat("x", 100000) + "\n" + route6Text, ""}, // the scanner stops at an over-long line
	}
	for _, c := range cases {
		rs := parseDefaultRoutes6(strings.NewReader(c.text))
		if rs == nil || routesText(rs) != c.want {
			t.Errorf("%s: %q, want %q", c.name, routesText(rs), c.want)
		}
	}
}

func TestParseDefaultRoutes6IsBounded(t *testing.T) {
	t.Parallel()
	junk := strings.Repeat(route6Line("fe800000000000000000000000000001", "00000001", "00000001", "eth0"), maxRoute6Lines+10)
	if rs := parseDefaultRoutes6(strings.NewReader(junk + route6Text)); len(rs) != 0 {
		t.Fatalf("read past the line limit: %+v", rs)
	}
	var many strings.Builder
	for i := range 40 {
		many.WriteString(route6Line(fmt.Sprintf("fe80000000000000000000000000%04x", i+1), "00000400", "00000003", "eth0"))
	}
	if n := len(parseDefaultRoutes6(strings.NewReader(many.String()))); n != maxRoutes6 {
		t.Fatalf("%d routes, cap is %d", n, maxRoutes6)
	}
	// The cut keeps the lowest metrics wherever they are in the file (review round 2, LOW 1): the main route last after 40 others.
	many.WriteString(route6Line("20010db8000000000000000000000001", "00000001", "00000003", "eth1"))
	if rs := parseDefaultRoutes6(strings.NewReader(many.String())); len(rs) != maxRoutes6 || rs[0] != (api.NetRoute{Iface: "eth1", Gateway: "2001:db8::1"}) {
		t.Fatalf("the lowest-metric route, last in the file, was cut: %+v", rs)
	}
}

func FuzzParseDefaultRoutes6(f *testing.F) {
	f.Add(route6Text)
	f.Add("")
	f.Add(route6Line("ffffffffffffffffffffffffffffffff", "ffffffff", "ffffffff", "eth0"))
	f.Fuzz(func(t *testing.T, s string) {
		rs := parseDefaultRoutes6(strings.NewReader(s))
		if rs == nil || len(rs) > maxRoutes6 {
			t.Fatalf("%d routes", len(rs))
		}
		for i, r := range rs {
			if !validIfaceName(r.Iface) {
				t.Fatalf("interface %q", r.Iface)
			}
			if a, err := netip.ParseAddr(r.Gateway); err != nil || !unicast6(a) {
				t.Fatalf("gateway %q", r.Gateway)
			}
			if slices.Contains(rs[:i], r) {
				t.Fatalf("%+v listed twice", r)
			}
		}
	})
}

// --- resolv.conf (D-390) ---------------------------------------------------------------------------------

// What systemd-resolved writes to /run/systemd/resolve/resolv.conf when a DHCP lease gave the servers.
const resolvedText = "# This is /run/systemd/resolve/resolv.conf managed by man:systemd-resolved(8).\n" +
	"# Do not edit.\n#\n" +
	"nameserver 192.168.10.53\n" +
	"nameserver 2001:db8::53\n" +
	"nameserver fe80::53%eth0\n" +
	"search lan\n"

// Ubuntu's /etc/resolv.conf: the stub of systemd-resolved.
const stubText = "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch lan\n"

func addrsText(as []netip.Addr) string {
	var s []string
	for _, a := range as {
		s = append(s, a.String())
	}
	return strings.Join(s, ",")
}

func TestParseResolvConf(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, text, want string }{
		{"resolved", resolvedText, "192.168.10.53,2001:db8::53,fe80::53"},
		{"the stub is not a server", stubText, ""},
		{"loopback, unspecified, multicast", "nameserver ::1\nnameserver 0.0.0.0\nnameserver ::\nnameserver 224.0.0.251\nnameserver ff02::fb\nnameserver 127.0.0.1\n", ""},
		{"IPv4-mapped is IPv4", "nameserver ::ffff:192.168.10.54\n", "192.168.10.54"},
		{"comments, other keys, junk", "; nameserver 10.9.9.9\n# nameserver 10.9.9.8\nnameserverx 10.9.9.7\nnameserver\nnameserver dns.example\nnameserver 10.0.0.256\n\x00\x01\nnameserver\t10.0.0.53  # a comment\n", "10.0.0.53"},
		{"a very long line ends the read", "nameserver 10.0.0.1\n" + strings.Repeat("x", 100000) + "\nnameserver 10.0.0.2\n", "10.0.0.1"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		if got := addrsText(parseResolvConf(strings.NewReader(c.text))); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	var many strings.Builder
	for i := range 40 {
		fmt.Fprintf(&many, "nameserver 10.0.0.%d\n", i+1)
	}
	if n := len(parseResolvConf(strings.NewReader(many.String()))); n != maxResolvers {
		t.Errorf("%d servers, cap is %d", n, maxResolvers)
	}
	if n := len(parseResolvConf(strings.NewReader(strings.Repeat("search lan\n", maxResolvLines) + "nameserver 10.0.0.1\n"))); n != 0 {
		t.Errorf("read past the line limit: %d servers", n)
	}
}

func FuzzParseResolvConf(f *testing.F) {
	f.Add(resolvedText)
	f.Add(stubText)
	f.Add("nameserver fe80::1%25eth0\n")
	f.Fuzz(func(t *testing.T, s string) {
		got := parseResolvConf(strings.NewReader(s))
		if len(got) > maxResolvers {
			t.Fatalf("%d servers", len(got))
		}
		for _, a := range got {
			if !a.IsValid() || a.Zone() != "" || a.Is4In6() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
				t.Fatalf("server %v", a)
			}
		}
	})
}

// --- the neighbour table (D-390) -------------------------------------------------------------------------

func nlMsg(typ uint16, body []byte) []byte {
	b := make([]byte, nlmsgHdrLen, nlmsgHdrLen+len(body))
	binary.NativeEndian.PutUint32(b[0:4], uint32(nlmsgHdrLen+len(body))) //nolint:gosec // a test message of a few dozen bytes
	binary.NativeEndian.PutUint16(b[4:6], typ)
	return append(b, body...)
}

func nlAttr(typ uint16, v []byte) []byte {
	b := make([]byte, align4(4+len(v)))
	binary.NativeEndian.PutUint16(b[0:2], uint16(4+len(v))) //nolint:gosec // a test attribute of at most 20 bytes
	binary.NativeEndian.PutUint16(b[2:4], typ)
	copy(b[4:], v)
	return b
}

// nlNeigh is one RTM_NEWNEIGH message as the kernel sends it in a dump: struct ndmsg, NDA_DST, NDA_LLADDR (nil: none, as for an
// incomplete entry) and an NDA_CACHEINFO the reader skips.
func nlNeigh(ifindex uint32, state uint16, dst string, mac string) []byte {
	a := netip.MustParseAddr(dst)
	body := make([]byte, ndmsgLen)
	body[0] = 2 // AF_INET
	if a.Is6() {
		body[0] = 10 // AF_INET6 on Linux
	}
	binary.NativeEndian.PutUint32(body[4:8], ifindex)
	binary.NativeEndian.PutUint16(body[8:10], state)
	body = append(body, nlAttr(ndaDst, a.AsSlice())...)
	if mac != "" {
		hw, err := net.ParseMAC(mac)
		if err != nil {
			panic(err)
		}
		body = append(body, nlAttr(ndaLLAddr, hw)...)
	}
	body = append(body, nlAttr(3, make([]byte, 16))...)
	return nlMsg(rtmNewNeigh, body)
}

var nlDone = nlMsg(nlmsgDone, make([]byte, 4))

const (
	nudIncomplete, nudReachable, nudStale, nudFailed, nudPermanent = 0x01, 0x02, 0x04, 0x20, 0x80
)

func TestNeighbourMAC(t *testing.T) {
	t.Parallel()
	gw4, gw6 := netip.MustParseAddr("192.168.10.1"), netip.MustParseAddr("fe80::1")
	cases := []struct {
		name string
		dump []byte
		addr netip.Addr
		want string
	}{
		{"stale IPv4 entry", slices.Concat(nlNeigh(2, nudStale, "192.168.10.1", "00:11:22:33:44:55"), nlDone), gw4, "00:11:22:33:44:55"},
		{"IPv6 link-local", slices.Concat(nlNeigh(2, nudReachable, "192.168.10.1", "00:11:22:33:44:55"), nlNeigh(2, nudReachable, "fe80::1", "00:11:22:33:44:66"), nlDone), gw6, "00:11:22:33:44:66"},
		{"permanent", nlNeigh(2, nudPermanent, "192.168.10.1", "AA:BB:CC:00:00:01"), gw4, "aa:bb:cc:00:00:01"},
		{"another card's entry is not the gateway's", slices.Concat(nlNeigh(3, nudReachable, "192.168.10.1", "00:11:22:33:44:77"), nlNeigh(2, nudReachable, "192.168.10.1", "00:11:22:33:44:55")), gw4, "00:11:22:33:44:55"},
		{"only on another card", nlNeigh(3, nudReachable, "192.168.10.1", "00:11:22:33:44:77"), gw4, ""},
		{"incomplete", nlNeigh(2, nudIncomplete, "192.168.10.1", ""), gw4, ""},
		{"failed with an old address", nlNeigh(2, nudFailed, "192.168.10.1", "00:11:22:33:44:55"), gw4, ""},
		{"state none", nlNeigh(2, 0, "192.168.10.1", "00:11:22:33:44:55"), gw4, ""},
		{"NOARP is not an answer from a neighbour", nlNeigh(2, 0x40, "192.168.10.1", "00:11:22:33:44:55"), gw4, ""},
		{"zero MAC", nlNeigh(2, nudReachable, "192.168.10.1", "00:00:00:00:00:00"), gw4, ""},
		{"broadcast MAC", nlNeigh(2, nudPermanent, "192.168.10.1", "ff:ff:ff:ff:ff:ff"), gw4, ""},
		{"multicast MAC", nlNeigh(2, nudPermanent, "192.168.10.1", "01:00:5e:00:00:01"), gw4, ""},
		{"not a 6-byte address", nlNeigh(2, nudReachable, "192.168.10.1", "00:11:22:33:44:55:66:77"), gw4, ""},
		{"IPv4-mapped is not the IPv4 gateway", nlNeigh(2, nudReachable, "::ffff:192.168.10.1", "00:11:22:33:44:55"), gw4, ""},
		{"after the end of the dump", slices.Concat(nlDone, nlNeigh(2, nudReachable, "192.168.10.1", "00:11:22:33:44:55")), gw4, ""},
		{"after an error message", slices.Concat(nlMsg(nlmsgError, make([]byte, 20)), nlNeigh(2, nudReachable, "192.168.10.1", "00:11:22:33:44:55")), gw4, ""},
		{"truncated", nlNeigh(2, nudReachable, "192.168.10.1", "00:11:22:33:44:55")[:30], gw4, ""},
		{"another message type", slices.Concat(nlMsg(16, make([]byte, 16)), nlNeigh(2, nudReachable, "192.168.10.1", "00:11:22:33:44:55")), gw4, "00:11:22:33:44:55"},
		{"empty", nil, gw4, ""},
	}
	for _, c := range cases {
		if got := neighbourMAC(c.dump, 2, c.addr); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	// An attribute whose length runs past its message, and a message length past the dump, end the read.
	bad := nlNeigh(2, nudReachable, "192.168.10.1", "00:11:22:33:44:55")
	binary.NativeEndian.PutUint16(bad[nlmsgHdrLen+ndmsgLen:], 200)
	if got := neighbourMAC(bad, 2, gw4); got != "" {
		t.Errorf("an attribute longer than its message was read: %q", got)
	}
	long := nlNeigh(2, nudReachable, "192.168.10.1", "00:11:22:33:44:55")
	binary.NativeEndian.PutUint32(long[0:4], 1<<20)
	if got := neighbourMAC(long, 2, gw4); got != "" {
		t.Errorf("a message longer than the dump was read: %q", got)
	}
	if got := neighbourMAC(nlNeigh(0, nudReachable, "192.168.10.1", "00:11:22:33:44:55"), 0, gw4); got != "" {
		t.Errorf("an interface with no index matched: %q", got)
	}
}

func FuzzNeighbourMAC(f *testing.F) {
	f.Add(slices.Concat(nlNeigh(2, nudStale, "192.168.10.1", "00:11:22:33:44:55"), nlDone), "192.168.10.1")
	f.Add(nlNeigh(2, nudReachable, "fe80::1", "00:11:22:33:44:66"), "fe80::1")
	f.Add([]byte{}, "192.168.10.1")
	f.Fuzz(func(t *testing.T, dump []byte, addr string) {
		a, err := netip.ParseAddr(addr)
		if err != nil {
			return
		}
		got := neighbourMAC(dump, 2, a)
		if got == "" {
			return
		}
		hw, err := net.ParseMAC(got)
		if err != nil || len(hw) != 6 || hw[0]&1 != 0 || got != strings.ToLower(got) {
			t.Fatalf("MAC %q", got)
		}
	})
}

// FuzzNeighbourEntry builds a well-formed neighbour message from the fuzz input and checks neighbourMAC against the rule it implements
// (review LOW 3): the MAC comes back exactly when the entry is on the asked card, in a usable state, for the asked address, with a 6-byte
// unicast non-zero MAC.
func FuzzNeighbourEntry(f *testing.F) {
	f.Add(uint32(2), uint16(nudStale), []byte{192, 168, 10, 1}, []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55}, []byte{192, 168, 10, 1})
	f.Add(uint32(3), uint16(nudReachable), []byte{192, 168, 10, 1}, []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55}, []byte{192, 168, 10, 1})
	f.Add(uint32(2), uint16(0x40), netip.MustParseAddr("fe80::1").AsSlice(), []byte{1, 0, 0x5e, 0, 0, 1}, netip.MustParseAddr("fe80::1").AsSlice())
	f.Fuzz(func(t *testing.T, ifindex uint32, state uint16, dst, ll, query []byte) {
		addr, ok := netip.AddrFromSlice(query)
		if !ok || len(dst) > 64 || len(ll) > 64 {
			return
		}
		body := make([]byte, ndmsgLen)
		binary.NativeEndian.PutUint32(body[4:8], ifindex)
		binary.NativeEndian.PutUint16(body[8:10], state)
		body = slices.Concat(body, nlAttr(ndaDst, dst), nlAttr(ndaLLAddr, ll))
		got := neighbourMAC(slices.Concat(nlMsg(rtmNewNeigh, body), nlDone), 2, addr)
		want := ""
		if d, ok := netip.AddrFromSlice(dst); ok && d == addr && ifindex == 2 && state&nudValid != 0 &&
			len(ll) == 6 && ll[0]&1 == 0 && !slices.Equal(ll, make([]byte, 6)) {
			want = net.HardwareAddr(ll).String()
		}
		if got != want {
			t.Fatalf("index %d state %#x dst %x ll %x asked %v: %q, want %q", ifindex, state, dst, ll, addr, got, want)
		}
	})
}

// --- state/net (D-390) ----------------------------------------------------------------------------------

// D-390: state/net reports the IPv6 default route, the MAC of each default gateway from the neighbour table (the entry on the route's
// card) and the DNS servers in use, whoever set them (here a DHCP lease, as systemd-resolved lists it). A neighbour table that cannot
// be read leaves the MACs out and changes nothing else.
func TestNetStateReportsTheIPv6RouteTheGatewayMACsAndTheResolvers(t *testing.T) {
	t.Parallel()
	dump := slices.Concat(
		nlNeigh(3, nudReachable, "192.168.10.1", "00:11:22:33:44:77"), // the same address on another card: not the gateway
		nlNeigh(2, nudStale, "192.168.10.1", "00:11:22:33:44:55"),
		nlNeigh(2, nudReachable, "fe80::1", "00:11:22:33:44:66"),
		nlDone)
	o, root := netOps(t, withIfaces(
		HostIface{Name: "eth0", Index: 2, MAC: "02:00:00:00:00:01", Addrs: pfx("192.168.10.250/24", "fe80::5/64")},
		HostIface{Name: "eth1", Index: 3, MAC: "02:00:00:00:00:02"},
	), func(d *Deps) { d.NeighDump = func() ([]byte, error) { return dump, nil } })
	card(t, root, "eth0", stats("1", "1"), true)
	card(t, root, "eth1", stats("1", "1"), true)
	put(t, root, "proc/net/route", routeText)
	// a router advertisement's route on eth0, and a VPN table's default through wg0 (no neighbour entry: a tunnel has none)
	put(t, root, "proc/net/ipv6_route", route6Text+route6Line("20010db8000000000000000000000001", "00000800", "00000003", "wg0"))
	// Ubuntu's layout: /etc/resolv.conf is a relative link to resolved's stub
	put(t, root, "run/systemd/resolve/resolv.conf", resolvedText)
	put(t, root, "run/systemd/resolve/stub-resolv.conf", stubText+"nameserver 192.168.10.53\nnameserver 1.1.1.1\n")
	put(t, root, "etc/placeholder", "")
	if err := os.Symlink("../run/systemd/resolve/stub-resolv.conf", filepath.Join(root, "etc/resolv.conf")); err != nil {
		t.Fatal(err)
	}

	st := readState(t, o)
	if r := st.DefaultRoute; r == nil || r.Iface != "eth0" || r.Gateway != "192.168.10.1" || r.MAC != "00:11:22:33:44:55" {
		t.Fatalf("IPv4 route %+v", r)
	}
	if got, want := routesText(st.DefaultRoutes6), "eth0 fe80::1 00:11:22:33:44:66,wg0 2001:db8::1 "; got != want {
		t.Fatalf("IPv6 routes %q, want %q", got, want)
	}
	if got, want := strings.Join(st.Resolvers, ","), "192.168.10.53,2001:db8::53,fe80::53,1.1.1.1"; got != want {
		t.Fatalf("resolvers %s, want %s", got, want)
	}

	o.d.NeighDump = func() ([]byte, error) { return nil, errors.New("netlink refused") }
	st = readState(t, o)
	if st.DefaultRoute == nil || st.DefaultRoute.MAC != "" || routesText(st.DefaultRoutes6) != "eth0 fe80::1 ,wg0 2001:db8::1 " || len(st.Resolvers) != 4 {
		t.Fatalf("with no neighbour table: %+v %+v %v", st.DefaultRoute, st.DefaultRoutes6, st.Resolvers)
	}
}

// No IPv6 route file, no resolv.conf: no IPv6 route and an empty (never null) list of each. A FIFO at a resolv.conf name never blocks
// the host.
func TestNetStateWithoutIPv6OrResolvConf(t *testing.T) {
	t.Parallel()
	o, root := netOps(t, withIfaces(HostIface{Name: "eth0", Index: 2}))
	card(t, root, "eth0", stats("1", "1"), true)
	st := readState(t, o)
	if st.DefaultRoutes6 == nil || len(st.DefaultRoutes6) != 0 || st.Resolvers == nil || len(st.Resolvers) != 0 {
		t.Fatalf("routes6 %#v resolvers %#v", st.DefaultRoutes6, st.Resolvers)
	}
	put(t, root, "etc/placeholder", "")
	if err := syscall.Mkfifo(filepath.Join(root, "etc/resolv.conf"), 0o600); err != nil {
		t.Skip("no FIFOs here:", err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = o.readNet(context.Background()) }()
	select {
	case <-done:
	case <-time.After(HangBound):
		t.Fatal("state/net blocked on a FIFO at /etc/resolv.conf")
	}
}

// D-390 review (M2): the root host reads a file that systemd-resolved's user can replace. Only a regular file of 1 byte to 64 KiB is read,
// never through a link in /run/systemd/resolve (a link to /dev/watchdog would arm it, one to /proc/kmsg would block), and /etc/resolv.conf
// is followed one level only.
func TestResolversReadOnlySmallRegularFilesNotDevices(t *testing.T) {
	t.Parallel()
	o, root := netOps(t)
	put(t, root, "run/systemd/resolve/placeholder", "")
	put(t, root, "etc/placeholder", "")
	resolved := filepath.Join(root, "run/systemd/resolve/resolv.conf")
	etc := filepath.Join(root, "etc/resolv.conf")
	reset := func() {
		for _, p := range []string{resolved, etc, filepath.Join(root, "run/systemd/resolve/stub-resolv.conf")} {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
		}
	}
	symlink := func(target, at string) {
		t.Helper()
		if err := os.Symlink(target, at); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name, want string) {
		t.Helper()
		done := make(chan []string, 1)
		go func() { done <- o.resolvers() }()
		select {
		case got := <-done:
			if strings.Join(got, ",") != want {
				t.Errorf("%s: %v, want %q", name, got, want)
			}
		case <-time.After(HangBound):
			t.Fatalf("%s: the read blocked", name)
		}
		reset()
	}

	symlink("/dev/null", resolved) // a device behind a link in resolved's directory: never opened
	check("link to /dev/null", "")
	symlink(filepath.Join(root, "real.conf"), resolved) // a link to a good file is refused as well: resolved writes a regular file
	put(t, root, "real.conf", "nameserver 10.0.0.1\n")
	check("link in /run/systemd/resolve", "")
	put(t, root, "run/systemd/resolve/resolv.conf", "")
	check("empty file (procfs files report size 0)", "")
	put(t, root, "run/systemd/resolve/resolv.conf", "nameserver 10.0.0.1\n"+strings.Repeat("#", maxResolvBytes))
	check("over 64 KiB", "")
	if err := syscall.Mkfifo(resolved, 0o600); err == nil {
		check("FIFO", "")
	}
	// /etc/resolv.conf: one level of link (Ubuntu's), not two, and not to a device.
	put(t, root, "run/systemd/resolve/stub-resolv.conf", "nameserver 10.0.0.2\n")
	symlink("../run/systemd/resolve/stub-resolv.conf", etc)
	check("one level", "10.0.0.2")
	symlink("/run/systemd/resolve/stub-resolv.conf", etc) // an absolute target is read under the root
	put(t, root, "run/systemd/resolve/stub-resolv.conf", "nameserver 10.0.0.3\n")
	check("absolute target", "10.0.0.3")
	symlink("/dev/null", filepath.Join(root, "run/systemd/resolve/stub-resolv.conf"))
	symlink("../run/systemd/resolve/stub-resolv.conf", etc)
	check("two levels, the second to a device", "")
	symlink("/dev/null", etc)
	check("/etc/resolv.conf linked to /dev/null under the root", "")
}
