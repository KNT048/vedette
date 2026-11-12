package provider

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"syscall"
	"testing"
)

func init() {
	// The existing tests dial httptest servers on loopback for profiles that are not internal: that is allowed here only, from the
	// test code of this package. TestCloudDialRefusesPrivateAndLoopback switches it off.
	cloudMayDialPrivate = true
}

// L1 of the review of slice 1: no profile, internal or cloud, may reach a metadata service, a link-local, multicast or
// unspecified address; a cloud profile also stays off loopback and the private ranges.
func TestForbiddenAddresses(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]bool{
		"169.254.169.254": true, "169.254.170.2": true, "169.254.1.1": true, "fe80::1": true, "fd00:ec2::254": true, "fd20:ce::254": true, "100.100.100.200": true, "192.0.0.192": true, "100.100.100.201": false, "[::ffff:169.254.169.254]": true,
		"224.0.0.251": true, "239.255.255.250": true, "ff02::1": true, "0.0.0.0": true, "::": true, "255.255.255.255": true,
		"127.0.0.1": false, "::1": false, "10.0.0.1": false, "192.168.1.1": false, "100.64.0.1": false, "fd12:3456::1": false, "8.8.8.8": false, "2606:4700::1111": false,
	} {
		ip, err := netip.ParseAddr(strings.Trim(s, "[]"))
		if err != nil {
			t.Fatal(err)
		}
		if got := Forbidden(ip); got != want {
			t.Errorf("Forbidden(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestInternalDialRefusesForbiddenAddresses(t *testing.T) {
	t.Parallel()
	for addr, ok := range map[string]bool{
		"127.0.0.1:80": true, "[::1]:80": true, "10.1.2.3:443": true, "192.168.1.1:1": true, "100.64.0.1:1": true, "[fd12:3456::1]:1": true,
		"169.254.169.254:80": false, "169.254.10.10:1": false, "[fe80::1]:1": false, "[fd00:ec2::254]:80": false, "224.0.0.251:5353": false, "0.0.0.0:1": false, "[::]:1": false,
		"8.8.8.8:443": false,
	} {
		if err := internalOnlyControl("tcp", addr, nil); (err == nil) != ok {
			t.Errorf("internal %s: allowed=%v, want %v (%v)", addr, err == nil, ok, err)
		}
	}
}

func TestCloudDialRefusesPrivateAndLoopback(t *testing.T) {
	cloudMayDialPrivate = false
	t.Cleanup(func() { cloudMayDialPrivate = true })
	for addr, ok := range map[string]bool{
		"8.8.8.8:443": true, "[2606:4700::1111]:443": true, "1.1.1.1:80": true,
		"127.0.0.1:443": false, "[::1]:443": false, "10.0.0.1:443": false, "192.168.1.1:443": false, "172.16.0.1:443": false, "100.64.0.1:443": false,
		"[fd12:3456::1]:443": false, "[::ffff:10.0.0.1]:443": false, "[::ffff:127.0.0.1]:443": false,
		"169.254.169.254:80": false, "[fe80::1]:1": false, "[fd00:ec2::254]:80": false, "224.0.0.251:1": false, "0.0.0.0:1": false, "not an address": false,
	} {
		if err := cloudOnlyControl("tcp", addr, nil); (err == nil) != ok {
			t.Errorf("cloud %s: allowed=%v, want %v (%v)", addr, err == nil, ok, err)
		}
	}
	// end to end, no packet is sent: a cloud profile whose name resolves to this machine
	srv := serve(t, 200, `{}`, nil)
	_, err := must(t, cfg(StyleAnthropic, srv.URL)).Complete(context.Background(), simpleReq)
	if !errors.Is(err, ErrNetwork) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("cloud profile dialling loopback: %v", err)
	}
	// behind a proxy the dial goes to the proxy, so only the addresses nobody may use are refused there
	if cloudControlFor(true)("tcp", "10.9.9.9:3128", nil) != nil {
		t.Error("a corporate proxy on a private address must stay reachable")
	}
	if cloudControlFor(true)("tcp", "169.254.169.254:80", nil) == nil {
		t.Error("a proxy at a metadata address must be refused")
	}
}

// Review issue 2: IPv6 forms that carry an IPv4 address (NAT64, 6to4, IPv4-compatible, Teredo) must not get past the address
// policy by writing 127.0.0.1 or 169.254.169.254 inside them, as D-94 says for connections.
func TestForbiddenCarriesIPv4(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]bool{
		"64:ff9b::7f00:1": true, "64:ff9b::a9fe:a9fe": true, "64:ff9b::a00:1": true, "64:ff9b::808:808": true, "64:ff9b:1::1": true,
		"2002:7f00:1::1": true, "2002:a9fe:a9fe::": true, "2002:808:808::1": true,
		"::7f00:1": true, "::a9fe:a9fe": true, "::a00:1": true,
		"2001:0:4136:e378:8000:63bf:3fff:fdd2": true,                             // Teredo
		"::ffff:0:7f00:1":                      true, "::ffff:0:a9fe:a9fe": true, // IPv4-translated (SIIT), forbidden by D-94 too
		"::1": false, "2606:4700::1111": false, "2001:db8::1": false, "fd12:3456::1": false, "::ffff:8.8.8.8": false,
	} {
		ip := netip.MustParseAddr(s)
		if got := Forbidden(ip); got != want {
			t.Errorf("Forbidden(%s) = %v, want %v", s, got, want)
		}
	}
	for _, addr := range []string{"[64:ff9b::7f00:1]:443", "[2002:a9fe:a9fe::]:80", "[::7f00:1]:80"} {
		for name, ctl := range map[string]func(string, string, syscall.RawConn) error{"internal": internalOnlyControl, "cloud": cloudOnlyControl, "proxied": forbiddenOnlyControl} {
			if err := ctl("tcp", addr, nil); err == nil {
				t.Errorf("%s dial of %s was allowed", name, addr)
			}
		}
	}
}
