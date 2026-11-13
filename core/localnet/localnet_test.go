package localnet

import (
	"net/netip"
	"testing"
)

func TestAddr(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]bool{
		"10.0.0.1": true, "172.16.0.1": true, "172.31.255.254": true, "192.168.1.1": true,
		"100.64.0.0": true, "100.65.254.7": true, "100.127.255.255": true, // RFC 6598 (D-461)
		"100.63.255.255": false, "100.128.0.0": false, "100.1.2.3": false, "172.32.0.1": false, "11.0.0.1": false, "8.8.8.8": false,
		"127.0.0.1": false, "169.254.1.1": false, "0.0.0.0": false, "255.255.255.255": false, "224.0.0.1": false,
		"::ffff:10.0.0.1": false, "::ffff:100.64.0.1": false, "fd00::1": false,
	} {
		if got := Addr(netip.MustParseAddr(s)); got != want {
			t.Errorf("Addr(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestPrefix(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]bool{
		"10.0.0.0/8": true, "172.16.0.0/12": true, "192.168.0.0/16": true, "192.168.10.0/24": true,
		"100.64.0.0/10": true, "100.65.254.0/24": true, "100.127.0.0/16": true, "100.100.100.100/32": true,
		"100.0.0.0/8": false, "100.64.0.0/9": false, "100.128.0.0/24": false, "100.63.0.0/16": false,
		"10.0.0.0/7": false, "172.16.0.0/11": false, "192.168.0.0/15": false, "0.0.0.0/0": false, "8.8.8.0/24": false,
		"fd00::/8": false,
	} {
		if got := Prefix(netip.MustParsePrefix(s)); got != want {
			t.Errorf("Prefix(%s) = %v, want %v", s, got, want)
		}
	}
	if Prefix(netip.Prefix{}) {
		t.Error("the zero prefix is local")
	}
}
