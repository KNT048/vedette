package feeds

import (
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
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
	domainRE   = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)
	hashRE     = regexp.MustCompile(`^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$`)
	ipLikeRE   = regexp.MustCompile(`^[0-9a-fA-F:]{3,39}$`)
	ipPortRE   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$`)
	portTailRE = regexp.MustCompile(`:[0-9]+$`)
	cveRE      = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
)

func validDomain(v string) bool { return len(v) <= 253 && domainRE.MatchString(v) }

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
	return err == nil && u.Hostname() != ""
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
