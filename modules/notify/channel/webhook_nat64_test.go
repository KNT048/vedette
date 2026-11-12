package channel

import (
	"net/netip"
	"slices"
	"testing"
)

// A local-use NAT64 prefix (64:ff9b:1::/48, RFC 8215) is judged by the IPv4 address in every RFC 6052 layout a sub-prefix of it can have (/48 /56 /64 /96).
func TestAddrFormsNAT64LocalEveryLayout(t *testing.T) {
	t.Parallel()
	// the byte offsets of the four IPv4 octets for each prefix length (byte 8 is the reserved u octet)
	layouts := map[string][4]int{
		"/48": {6, 7, 9, 10}, "/56": {7, 9, 10, 11}, "/64": {9, 10, 11, 12}, "/96": {12, 13, 14, 15},
	}
	b := [16]byte{0x00, 0x64, 0xff, 0x9b, 0x00, 0x01}
	for i := 6; i < 16; i++ {
		b[i] = byte(0x10 + i) // distinct bytes, so each layout yields its own IPv4 address
	}
	got := addrForms(netip.AddrFrom16(b))
	for name, pos := range layouts {
		want := netip.AddrFrom4([4]byte{b[pos[0]], b[pos[1]], b[pos[2]], b[pos[3]]})
		if !slices.Contains(got, want) {
			t.Errorf("layout %s: %s is not among %v", name, want, got)
		}
	}
	// the metadata address in a /64 layout
	if got := addrForms(netip.MustParseAddr("64:ff9b:1:1:64:6464:c800::")); !slices.Contains(got, netip.MustParseAddr("100.100.100.200")) {
		t.Errorf("the /64 form of 100.100.100.200 is not decoded: %v", got)
	}
}

// A public IPv4 address behind the local-use prefix is allowed in every layout: the zero suffix of a shorter prefix must not read as
// 0.0.0.0 and refuse it.
func TestWebhookDialGuardAllowsPublicIPv4InEveryNAT64Layout(t *testing.T) {
	t.Parallel()
	box := []netip.Addr{netip.MustParseAddr("192.168.10.2")}
	for _, a := range []string{"64:ff9b:1:808:8:800::", "64:ff9b:1:8:8:808::", "64:ff9b:1:0:8:808:800:0", "64:ff9b:1::808:808"} { // /48, /56, /64, /96
		if err := dialControl(false, func() ([]netip.Addr, bool) { return box, true })("tcp", "["+a+"]:443", nil); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
	for _, a := range []string{"64:ff9b:1:6464:64:c800::", "64:ff9b:1::6464:64c8"} { // 100.100.100.200 in /48 and /96
		if err := dialControl(false, func() ([]netip.Addr, bool) { return box, true })("tcp", "["+a+"]:443", nil); err == nil {
			t.Errorf("%s is allowed", a)
		}
	}
}
