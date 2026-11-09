package channel

import (
	"net/netip"
	"regexp"
	"strings"
)

var (
	// Same shape as the SPA's DOMAIN_RE: dotted labels, alphabetic TLD.
	domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	// Unquoted local part only (RFC 5322 atext plus dots): no spaces, quotes, angle brackets, CR or LF.
	localPartRE = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$")
)

// validDomain reports whether s is a dotted domain name (not an IP).
func validDomain(s string) bool {
	return len(s) <= 253 && domainRE.MatchString(strings.ToLower(s))
}

// validIPv4 reports whether s is a dotted-quad IPv4 address (no zone, no leading zeros).
func validIPv4(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4()
}

// validHost reports whether s is a domain name or an IPv4 address (INV-8, SMTP host).
func validHost(s string) bool { return validIPv4(s) || validDomain(s) }

// validEmail accepts plain addr-spec only: local@domain, no display name, no
// quoted local part, no comments. CR, LF, spaces and angle brackets can never match.
func validEmail(s string) bool {
	at := strings.LastIndexByte(s, '@')
	if at < 1 || len(s) > 254 {
		return false
	}
	local, domain := s[:at], s[at+1:]
	return len(local) <= 64 && localPartRE.MatchString(local) && validDomain(domain)
}

// internalHost reports whether host is a private-network name or address:
// 10/8, 172.16/12, 192.168/16, 127/8, "localhost" and the suffixes .local, .lan,
// .internal, .localhost. Plain http (webhook) and unauthenticated SMTP are only
// allowed for such hosts. The list is the same as the feeds module's INV-2.
func internalHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return false
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if !a.Is4() {
			return false
		}
		for _, p := range privateV4 {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	if host == "localhost" {
		return true
	}
	for _, suf := range []string{".local", ".lan", ".internal", ".localhost"} {
		if strings.HasSuffix(host, suf) {
			return true
		}
	}
	return false
}

var privateV4 = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
}
