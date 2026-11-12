package response

import (
	"net/netip"
	"testing"
)

// INV-17 (L4): the published block list holds public addresses only: every block of the IANA IPv4 and IPv6 Special-Purpose Address
// Registries that is not globally reachable is refused (see notPublishable), also behind an IPv4-mapped IPv6 address.
func TestPublishableRefusesTheSpecialPurposeBlocks(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		// IPv4
		"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "100.127.255.254", "0.1.2.3", "127.0.0.1", "169.254.1.1",
		"224.0.0.1", "239.1.1.1", "240.0.0.1", "255.255.255.255", "198.18.0.1", "198.19.255.254", "192.0.0.8", "192.0.0.170", "192.88.99.1",
		// IPv6
		"fc00::1", "fd12:3456::1", "fe80::1", "ff02::1", "::1", "::", "64:ff9b::a00:1", "64:ff9b:1::c0a8:101", "fec0::1", "2001:db8::1",
		"2001:db8:ffff::1", "100::1", "2001::1", "2001:2::1", "2001:10::1", "2002:c0a8:101::1", "3fff::1", "5f00::1",
		// IPv4-mapped
		"::ffff:10.0.0.1", "::ffff:192.168.1.1", "::ffff:100.64.0.1", "::ffff:198.18.0.1",
	} {
		if publishable(netip.MustParseAddr(s)) {
			t.Errorf("%s is publishable", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "198.51.100.7", "203.0.113.5", "192.0.2.1", "198.17.255.255", "198.20.0.1", "100.128.0.1", "172.32.0.1", "2606:4700::1111", "2a00:1450::1", "100:0:0:1::1", "64:ff9a::1", "::ffff:8.8.8.8"} {
		if !publishable(netip.MustParseAddr(s)) {
			t.Errorf("%s (public) is not publishable", s)
		}
	}
}
