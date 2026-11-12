package feeds

import (
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// ---------- dates

var (
	dmyRE   = regexp.MustCompile(`^([0-9]{1,2})[/.-]([0-9]{1,2})[/.-]([0-9]{4})`)
	isoRE   = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})`)
	epochRE = regexp.MustCompile(`^[0-9]{9,13}$`)
)

// Layouts tried when a date is not ISO and has letters in it ("03 Nov 2026",
// RFC 1123 ...). parsers.ts leans on the engine's Date.parse heuristics; this
// is the explicit subset. A date without a zone is read as UTC.
var textDateLayouts = []string{
	time.RFC1123Z, time.RFC1123, "Mon, 2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST", "Mon, 2 Jan 2006 15:04:05",
	time.RFC822Z, time.RFC822, time.RFC850, time.ANSIC, time.UnixDate, time.RubyDate,
	"2 Jan 2006 15:04:05 -0700", "2 Jan 2006 15:04:05 MST", "2 Jan 2006 15:04:05", "2 Jan 2006", "2 January 2006",
	"Jan 2, 2006 15:04:05", "Jan 2, 2006", "January 2, 2006 15:04:05", "January 2, 2006", "Jan 2 2006", "January 2 2006",
	"2 Jan, 2006", "2 January, 2006",
}

func ymd(y, m, d int) (time.Time, bool) {
	if y < 100 { // JS Date.UTC maps 0..99 to 19xx, which the round-trip check rejects
		return time.Time{}, false
	}
	t := time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC)
	if t.Year() != y || int(t.Month()) != m || t.Day() != d {
		return time.Time{}, false
	}
	return t, true
}

func hasLetter(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

// normDate turns a date into YYYY-MM-DD (UTC) or reports false.
func normDate(raw string, f DateFormat) (string, bool) {
	s := jsTrim(raw)
	var t time.Time
	ok := false
	switch f {
	case DateEpoch:
		if epochRE.MatchString(s) {
			n, _ := strconv.ParseInt(s, 10, 64)
			if len(s) > 10 {
				t, ok = time.UnixMilli(n).UTC(), true
			} else {
				t, ok = time.Unix(n, 0).UTC(), true
			}
		}
	case DateDMY, DateMDY:
		if m := dmyRE.FindStringSubmatch(s); m != nil {
			a, _ := strconv.Atoi(m[1])
			b, _ := strconv.Atoi(m[2])
			y, _ := strconv.Atoi(m[3])
			if f == DateDMY {
				t, ok = ymd(y, b, a)
			} else {
				t, ok = ymd(y, a, b)
			}
		}
	default:
		if m := isoRE.FindStringSubmatch(s); m != nil {
			y, _ := strconv.Atoi(m[1])
			mo, _ := strconv.Atoi(m[2])
			d, _ := strconv.Atoi(m[3])
			t, ok = ymd(y, mo, d)
		} else if hasLetter(s) {
			for _, l := range textDateLayouts {
				if x, err := time.Parse(l, s); err == nil {
					t, ok = x.UTC(), true
					break
				}
			}
		}
	}
	if !ok {
		return "", false
	}
	return t.Format("2006-01-02"), true
}

// ---------- indicators

var kindAlias = map[string]string{
	"ip": "ip", "ipv4": "ip", "ip_address": "ip", "ipv4-addr": "ip", "ip:port": "ip",
	"domain": "domain", "fqdn": "domain", "hostname": "domain", "domain-name": "domain",
	"url":  "url",
	"hash": "hash", "md5": "hash", "sha1": "hash", "sha256": "hash", "md5_hash": "hash", "sha256_hash": "hash",
}

var (
	hashRE     = regexp.MustCompile(`^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$`)
	ipLikeRE   = regexp.MustCompile(`^[0-9a-fA-F:]{3,39}$`)
	ipPortRE   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$`)
	portTailRE = regexp.MustCompile(`:[0-9]+$`)
	cveRE      = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
)

// validDomain: at most 253 bytes, two or more labels; every label but the last is 1 to 63 of a-z, A-Z, 0-9 and "-" with no "-" at
// either end, the last is 2 to 63 letters or an IDN top-level domain in its ASCII form (`xn--p1ai` is .рф; hagezi TIF lists 50 such
// names on 2026-11-12). A loop rather than the regular expression it replaces (`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+
// ([a-zA-Z]{2,63}|[xX][nN]--[a-zA-Z0-9-]{0,58}[a-zA-Z0-9])$`, still the oracle of TestValidDomainIsTheRegexp): that one backtracked
// on every row and was a third of the time of parsing a 186,000-domain list.
func validDomain(v string) bool {
	if len(v) > 253 {
		return false
	}
	labels := 0
	for len(v) > 0 {
		i := strings.IndexByte(v, '.')
		if i < 0 {
			if labels == 0 || len(v) < 2 || len(v) > 63 {
				return false
			}
			if len(v) > 4 && strings.EqualFold(v[:4], "xn--") {
				return v[len(v)-1] != '-' && strings.IndexFunc(v[4:], func(r rune) bool { return r != '-' && !isLetter(r) && (r < '0' || r > '9') }) < 0
			}
			return strings.IndexFunc(v, func(r rune) bool { return !isLetter(r) }) < 0
		}
		l := v[:i]
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for j := 0; j < len(l); j++ {
			if c := l[j]; c != '-' && !isLetter(rune(c)) && (c < '0' || c > '9') {
				return false
			}
		}
		labels++
		v = v[i+1:]
	}
	return false // empty, or a trailing dot
}

func isLetter(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }

// canonicalIP validates with net/netip. Zones are refused; IPv4-mapped IPv6 is
// unmapped so a log entry and a feed entry compare equal. Leading-zero IPv4
// ("010.1.1.1", ambiguous octal) is refused by netip.
func canonicalIP(v string) (string, bool) {
	a, err := netip.ParseAddr(v)
	if err != nil || a.Zone() != "" {
		return "", false
	}
	return a.Unmap().String(), true
}

func hasHTTPPrefix(v string) (rest string, ok bool) {
	l := strings.ToLower(v)
	switch {
	case strings.HasPrefix(l, "https://"):
		return v[len("https://"):], true
	case strings.HasPrefix(l, "http://"):
		return v[len("http://"):], true
	}
	return "", false
}

// validIndicatorURL: http(s) with a host, no whitespace in the host part, at most 2000 chars.
func validIndicatorURL(v string) bool {
	rest, ok := hasHTTPPrefix(v)
	if !ok || jsLen(v) > 2000 {
		return false
	}
	host, _, _ := strings.Cut(rest, "/")
	if host == "" || strings.ContainsFunc(host, jsIsSpace) {
		return false
	}
	u, err := url.Parse(v)
	return err == nil && u.Hostname() != "" && u.User == nil
}

// validLink is the vulnerability `link` rule: http(s)://, then non-space characters only.
func validLink(v string) bool {
	rest, ok := hasHTTPPrefix(v)
	return ok && rest != "" && !strings.ContainsFunc(rest, jsIsSpace)
}

func detectKind(v string) string {
	if strings.Contains(v, ":") && ipLikeRE.MatchString(v) {
		return "ip"
	}
	if _, ok := canonicalIP(v); ok {
		return "ip"
	}
	if _, ok := hasHTTPPrefix(v); ok {
		return "url"
	}
	if hashRE.MatchString(v) {
		return "hash"
	}
	if validDomain(v) {
		return "domain"
	}
	return ""
}

// ---------- special-purpose addresses and local names (INV-12)

var specialPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{
		// IPv4: this network, private, shared (CGNAT), loopback, link-local, IETF protocol, TEST-NETs,
		// benchmarking, multicast, reserved and the limited broadcast.
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4",
		// IPv6: unspecified, loopback and IPv4-compatible, NAT64, discard, documentation, 6to4, unique local, link-local, multicast.
		"::/96", "64:ff9b::/96", "100::/64", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

// isSpecialAddr reports an address that is not a public, global unicast one.
// IPv4-mapped IPv6 addresses are judged as the IPv4 address they carry.
func isSpecialAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() {
		return true
	}
	for _, p := range specialPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

var reservedTLDs = map[string]bool{
	"local": true, "lan": true, "internal": true, "localhost": true, "arpa": true, "test": true, "invalid": true, "example": true,
}

// reservedName reports a single-label name or one under a reserved top-level label.
func reservedName(name string) bool {
	i := strings.LastIndexByte(name, '.')
	return i < 0 || reservedTLDs[name[i+1:]]
}

// localName reports a name that is not a public registrable domain: a
// reserved or local top-level label, or a name that is itself a public suffix
// ("com.vn", "co.uk", "github.io"). domain must be a valid lower-case name.
func localName(domain string) bool {
	if reservedName(domain) {
		return true
	}
	suffix, _ := publicsuffix.PublicSuffix(domain)
	return suffix == domain
}

// emptyFileHashes are the digests of zero bytes: they match every empty file.
var emptyFileHashes = map[string]bool{
	"d41d8cd98f00b204e9800998ecf8427e":                                 true,
	"da39a3ee5e6b4b0d3255bfef95601890afd80709":                         true,
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": true,
}

// testTLDs are the reserved top-level labels for documentation and tests (RFC 2606,
// RFC 6761), a subset of reservedTLDs: refused, but they are not local hosts.
var testTLDs = map[string]bool{"example": true, "test": true, "invalid": true}

// hostRejection says why a URL host is refused (an IP literal must be public, a
// name must not be local or reserved); none() when the host is public. The
// template starts with the %s for the URL; the reason only names the class.
func hostRejection(host string) rej {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	if a, err := netip.ParseAddr(h); err == nil {
		if isSpecialAddr(a) {
			return rj("%s points at a private, reserved or special-purpose address")
		}
		return rej{}
	}
	if !validDomain(h) {
		return rj("%s points at a local or private host")
	}
	if i := strings.LastIndexByte(h, '.'); i > 0 && testTLDs[h[i+1:]] {
		return rj("%s points at a reserved example or test name")
	}
	if reservedName(h) {
		return rj("%s points at a local or private host")
	}
	return rej{}
}

// normaliseIOC validates and canonicalises one IOC value of a kind. A rejection
// template starts with the %s for the value.
func normaliseIOC(kind, value string) (string, rej) {
	switch kind {
	case "ip":
		c, ok := canonicalIP(value)
		if !ok {
			return "", rj("%s is not a valid ip")
		}
		if a, _ := netip.ParseAddr(c); isSpecialAddr(a) {
			return "", rj("%s is a private, reserved or special-purpose address")
		}
		return c, rej{}
	case "domain":
		if !validDomain(value) {
			return "", rj("%s is not a valid domain")
		}
		d := strings.ToLower(value)
		if localName(d) {
			return "", rj("%s is a local, reserved or public-suffix name")
		}
		return d, rej{}
	case "url":
		if !validIndicatorURL(value) {
			return "", rj("%s is not a valid url")
		}
		u, err := url.Parse(value)
		if err != nil {
			return "", rj("%s points at a local or private host")
		}
		if why := hostRejection(u.Hostname()); !why.none() {
			return "", why
		}
		return value, rej{}
	case "hash":
		if !hashRE.MatchString(value) {
			return "", rj("%s is not a valid hash")
		}
		h := strings.ToLower(value)
		if emptyFileHashes[h] {
			return "", rj("%s is the hash of an empty file")
		}
		return h, rej{}
	}
	return "", rj("%s is not a valid indicator")
}
