package ops

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
)

// --- the address flags (D-405) ---------------------------------------------------------------------------

// nlAddr is one RTM_NEWADDR message as the kernel sends it in a dump: struct ifaddrmsg with flags8, IFA_ADDRESS (the peer: a
// different address for IPv4, as on a point-to-point link), IFA_LOCAL for IPv4, and IFA_FLAGS when flags32 is set.
func nlAddr(ifindex uint32, cidr string, flags8 byte, flags32 *uint32) []byte {
	p := netip.MustParsePrefix(cidr)
	body := make([]byte, ifaddrmsgLen)
	body[0], body[1], body[2] = 2, byte(p.Bits()), flags8 //nolint:gosec // a prefix length fits in a byte
	if p.Addr().Is6() {
		body[0] = 10
	}
	binary.NativeEndian.PutUint32(body[4:8], ifindex)
	if p.Addr().Is4() {
		body = append(body, nlAttr(ifaAddress, []byte{10, 9, 9, 9})...) // the peer, never the card's address
		body = append(body, nlAttr(ifaLocal, p.Addr().AsSlice())...)
	} else {
		body = append(body, nlAttr(ifaAddress, p.Addr().AsSlice())...)
	}
	if flags32 != nil {
		v := make([]byte, 4)
		binary.NativeEndian.PutUint32(v, *flags32)
		body = append(body, nlAttr(ifaFlags, v)...)
	}
	return nlMsg(rtmNewAddr, body)
}

func TestDynamicAddrsReadsTheLeaseFlag(t *testing.T) {
	t.Parallel()
	perm, lease := uint32(ifaFPermanent), uint32(0x100) // IFA_F_NOPREFIXROUTE alone: not permanent
	dump := slices.Concat(
		nlAddr(2, "192.168.18.141/24", 0, nil),                // DHCP: no IFA_F_PERMANENT
		nlAddr(2, "fe80::1/64", ifaFPermanent, nil),           // link-local: permanent
		nlAddr(3, "192.168.18.140/24", ifaFPermanent, &lease), // IFA_FLAGS wins over the 8-bit field
		nlAddr(4, "192.168.50.2/24", 0, &perm),                // static, said by IFA_FLAGS only
		nlAddr(5, "2001:db8::5/64", 0, nil),                   // SLAAC
		nlMsg(nlmsgDone, make([]byte, 4)),
		nlAddr(6, "192.168.60.2/24", 0, nil), // after the end of the dump: not read
	)
	got := dynamicAddrs(dump)
	want := map[int][]netip.Prefix{
		2: {netip.MustParsePrefix("192.168.18.141/24")},
		3: {netip.MustParsePrefix("192.168.18.140/24")},
		5: {netip.MustParsePrefix("2001:db8::5/64")},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, w := range want {
		if !slices.Equal(got[i], w) {
			t.Fatalf("index %d: got %v, want %v", i, got[i], w)
		}
	}
	if len(dynamicAddrs(nil)) != 0 || len(dynamicAddrs([]byte{1, 2, 3})) != 0 {
		t.Fatal("an empty or short dump has no address")
	}
}

func FuzzDynamicAddrs(f *testing.F) {
	f.Add(nlAddr(2, "192.168.18.141/24", 0, nil))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, dump []byte) {
		for i, ps := range dynamicAddrs(dump) {
			for _, p := range ps {
				if i <= 0 || !p.IsValid() {
					t.Fatalf("index %d prefix %v", i, p)
				}
			}
		}
	})
}

// state/net lists the leased addresses of a card under dynamic, a subset of addresses; a card with none has [] (D-405).
func TestNetStateSaysWhichAddressesHaveALease(t *testing.T) {
	t.Parallel()
	o, root := netOps(t, withIfaces(
		HostIface{Name: "enp2s0", Index: 2, MAC: "02:00:00:00:00:01", Addrs: pfx("192.168.18.141/24", "fe80::1/64"), Dynamic: pfx("192.168.18.141/24")},
		HostIface{Name: "eth1", Index: 3, MAC: "02:00:00:00:00:02", Addrs: pfx("192.168.50.2/24")},
	))
	card(t, root, "enp2s0", stats("1", "1"), true)
	card(t, root, "eth1", stats("1", "1"), true)
	st := readState(t, o)
	byName := map[string][]string{}
	for _, i := range st.Interfaces {
		byName[i.Name] = i.Dynamic
	}
	if d := byName["enp2s0"]; !slices.Equal(d, []string{"192.168.18.141/24"}) {
		t.Fatalf("enp2s0 dynamic %v", d)
	}
	if d := byName["eth1"]; d == nil || len(d) != 0 {
		t.Fatalf("eth1 dynamic %#v, want []", d)
	}
}
