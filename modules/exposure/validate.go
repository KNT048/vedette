package exposure

import (
	"net/netip"
	"regexp"
	"strings"
	"unicode"

	"github.com/knt048/vedette/core/egressip"
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

// IsPublicIPv4 reports whether a is a global unicast IPv4 address the box may verify (INV-3): egressip.IsPublicIPv4, the rule the
// scan container's own-IP fence and nmapargv's external shape use too (D-514).
func IsPublicIPv4(a netip.Addr) bool { return egressip.IsPublicIPv4(a) }
