package provider

import (
	"context"
	"errors"
	"net/netip"
	"strings"
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
		"169.254.169.254": true, "169.254.170.2": true, "169.254.1.1": true, "fe80::1": true, "fd00:ec2::254": true, "[::ffff:169.254.169.254]": true,
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
