package honeypot

import (
	"net/netip"
	"testing"
)

// INV-5: the network and broadcast addresses are never usable, for any prefix, not only ones whose host part starts at an even
// octet (#270: `|` and `-` share a precedence level, so lastAddr of 192.168.1.0/24 came out as 192.168.0.255).
func TestUsableRefusesNetworkAndBroadcast(t *testing.T) {
	cases := []struct {
		prefix, ip string
		want       bool
	}{
		{"192.168.1.0/24", "192.168.1.255", false},
		{"192.168.1.0/24", "192.168.1.0", false},
		{"192.168.1.0/24", "192.168.1.254", true},
		{"192.168.1.0/24", "192.168.0.255", false},
		{"192.168.10.0/24", "192.168.10.255", false},
		{"10.1.3.0/23", "10.1.3.255", false},
		{"10.1.2.0/23", "10.1.3.255", false},
		{"10.1.2.0/23", "10.1.2.255", true},
		{"172.16.5.64/26", "172.16.5.127", false},
		{"172.16.5.64/26", "172.16.5.126", true},
		{"10.0.0.0/8", "10.255.255.255", false},
		{"10.0.0.0/8", "10.255.255.254", true},
		{"192.168.1.4/30", "192.168.1.7", false},
		{"192.168.1.4/30", "192.168.1.6", true},
	}
	for _, c := range cases {
		p := netip.MustParsePrefix(c.prefix)
		if got := usable(p, netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("usable(%s, %s) = %v, want %v (lastAddr %s)", c.prefix, c.ip, got, c.want, lastAddr(p))
		}
	}
}
