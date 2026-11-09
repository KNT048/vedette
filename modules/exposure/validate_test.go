package exposure

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// INV-6: a domain is only a domain name.
func TestContract_INV6_DomainOnly(t *testing.T) {
	t.Parallel()
	good := map[string]string{"example.com": "example.com", "  Shop.Acme-Demo.Example ": "shop.acme-demo.example", "a.b.c.d.example": "a.b.c.d.example", "example.com\n": "example.com", "xn--bcher-kva.example": "xn--bcher-kva.example"}
	for in, want := range good {
		if got, err := normalizeDomain(in); err != nil || got != want {
			t.Errorf("normalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []struct {
		in   string
		want *APIError
	}{
		{"", ErrEmpty}, {"   ", ErrEmpty},
		{"https://example.com", ErrBadValue}, {"example.com/admin", ErrBadValue}, {"example.com:8443", ErrBadValue}, {"user@example.com", ErrBadValue}, {"exa mple.com", ErrBadValue}, {"a\tb.example", ErrBadValue},
		{"8.8.8.8", ErrIPNotAllowed}, {"192.168.1.1", ErrIPNotAllowed},
		{"::1", ErrIPNotAllowed}, {"2001:db8::1", ErrIPNotAllowed}, {"[::1]", ErrIPNotAllowed}, {"2001:4860:4860::8888", ErrIPNotAllowed},
		{"example", ErrBadDomain}, {"-a.example", ErrBadDomain}, {"a-.example", ErrBadDomain}, {"a..example", ErrBadDomain}, {"example.123", ErrBadDomain}, {"exa_mple.com", ErrBadDomain},
		{strings.Repeat("a", 64) + ".example", ErrBadDomain}, {strings.Repeat("a.", 130) + "example", ErrBadDomain}, {"1.2.3", ErrBadDomain}, {"bücher.example", ErrBadDomain},
	}
	for _, c := range bad {
		if _, err := normalizeDomain(c.in); !errors.Is(err, c.want) {
			t.Errorf("normalizeDomain(%q) error = %v; want %v", c.in, err, c.want)
		}
	}
}

// INV-3: only global unicast IPv4 addresses are ever verified.
func TestIsPublicIPv4(t *testing.T) {
	t.Parallel()
	public := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "100.63.255.255", "100.128.0.0", "172.15.0.1", "172.32.0.1", "11.0.0.1", "223.255.255.254", "::ffff:8.8.8.8"}
	notPublic := []string{
		"0.0.0.0", "0.1.2.3", "10.0.0.1", "10.255.255.255", "100.64.0.1", "100.127.255.255", "127.0.0.1", "169.254.1.1", "172.16.0.1", "172.31.255.255",
		"192.0.0.1", "192.0.2.1", "192.168.0.1", "198.18.0.1", "198.19.255.255", "198.51.100.7", "203.0.113.10", "224.0.0.1", "239.1.1.1", "240.0.0.1", "255.255.255.255",
		"::1", "::", "2001:db8::1", "fe80::1", "fc00::1", "2606:4700::1111", "::ffff:10.0.0.1",
	}
	for _, s := range public {
		if !IsPublicIPv4(netip.MustParseAddr(s)) {
			t.Errorf("%s refused, want public", s)
		}
	}
	for _, s := range notPublic {
		if IsPublicIPv4(netip.MustParseAddr(s)) {
			t.Errorf("%s accepted, want refused", s)
		}
	}
	if IsPublicIPv4(netip.Addr{}) {
		t.Error("the zero address accepted")
	}
}
