package netguard

import (
	"net/netip"
	"testing"
)

// D-446: Vedette itself is refused on every port, the machine only on Vedette's own ports, and every address on those ports while the
// machine's addresses are not known.
func TestOwnRefuses(t *testing.T) {
	ip := netip.MustParseAddr
	o := Own{Machine: []netip.Addr{ip("192.168.18.141")}, Known: true, Self: []netip.Addr{ip("10.88.0.5"), ip("192.168.18.200")}}
	for _, c := range []struct {
		addr string
		port uint16
		want bool
	}{
		{"192.168.18.141", 8443, true}, {"192.168.18.141", 514, true}, {"192.168.18.141", 6514, true},
		{"192.168.18.141", 11434, false}, {"192.168.18.141", 443, false}, // another program on the machine
		{"::ffff:192.168.18.141", 8444, true}, {"64:ff9b::c0a8:128d", 8765, true}, // a transition form of the machine
		{"10.88.0.5", 443, true}, {"192.168.18.200", 80, true}, // core's container, a decoy: every port
		{"127.0.0.1", 11434, true}, {"::1", 443, true}, {"64:ff9b::7f00:1", 443, true},
		{"192.168.18.50", 8443, false},
	} {
		if got := o.Refuses(ip(c.addr), c.port, false); got != c.want {
			t.Errorf("%s:%d refused %v, want %v", c.addr, c.port, got, c.want)
		}
	}
	unknown := Own{}
	if !unknown.Refuses(ip("192.168.18.50"), 8443, false) || unknown.Refuses(ip("192.168.18.50"), 443, false) {
		t.Error("unknown machine addresses: Vedette's ports must be refused on every address, other ports not")
	}
	if o.Refuses(ip("127.0.0.1"), 443, true) || !o.Refuses(ip("10.88.0.5"), 443, true) {
		t.Error("allowLoopback must open loopback only")
	}
}
