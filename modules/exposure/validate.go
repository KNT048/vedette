package exposure

import (
	"net/netip"
	"regexp"
	"strings"
	"unicode"
)

// domainRE is a plain host name: labels of letters, digits and inner dashes, at least two labels, a
// letter-only last label. Upper case is folded before it is applied. IDN names go in as punycode.
var domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// normalizeDomain checks what the add-domain form sent, in the order of the mock: empty, then anything
// that is not a bare name, then an IP (never typed in, INV-2), then the name rules (INV-6).
func normalizeDomain(raw string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case v == "":
		return "", ErrEmpty
	case isIPv6(v): // an IP in any spelling is an IP: the same answer as IPv4, not "enter only a domain name"
		return "", ErrIPNotAllowed
	case strings.ContainsAny(v, "/:@") || strings.IndexFunc(v, unicode.IsSpace) >= 0:
		return "", ErrBadValue
	}
	if a, err := netip.ParseAddr(v); err == nil && a.Is4() {
		return "", ErrIPNotAllowed
	}
	if len(v) > 253 || !domainRE.MatchString(v) {
		return "", ErrBadDomain
	}
	return v, nil
}

// isIPv6 reports whether v is an IPv6 address as people write it: "2001:db8::1", "::1", "[::1]", "::ffff:8.8.8.8" or with a zone.
func isIPv6(v string) bool {
	if len(v) > 2 && v[0] == '[' && v[len(v)-1] == ']' {
		v = v[1 : len(v)-1]
	}
	a, err := netip.ParseAddr(v)
	return err == nil && a.Is6()
}

// Address ranges the box never verifies (INV-3). IsPrivate, IsLoopback, IsLinkLocalUnicast and the
// multicast tests of net/netip cover the rest; these are the shared-carrier and the special-purpose
// blocks that are not "private" in net/netip's sense. The documentation ranges (RFC 5737) are in the
// list: no real box leaves the Internet through them.
var reservedRanges = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
	} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

// IsPublicIPv4 reports whether a is a global unicast IPv4 address the box may verify: not private,
// loopback, link-local, shared carrier (CGNAT 100.64.0.0/10), documentation, multicast or reserved.
// IPv6 is refused for now (ponytail: the scan module targets IPv4; IPv6 is a later story).
func IsPublicIPv4(a netip.Addr) bool {
	a = a.Unmap()
	if !a.Is4() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range reservedRanges {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
