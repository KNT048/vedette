package server

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/knt048/vedette/core/apierr"
)

// HostAllowlist answers 421 misdirected_request to every request whose Host header is not on the list, before
// any routing. This is the defence against DNS rebinding: a page on evil.example whose name an attacker later
// points at the box would otherwise be served as if it were the box, and could read the answers. Names
// compare case-insensitively without the port and without a trailing dot; IP literals compare in canonical
// form (an IPv6 literal in brackets). An entry that starts with "*." is a wildcard that matches like the one
// in a certificate: exactly one label (*.corp.example matches box.corp.example, not a.b.corp.example nor
// corp.example) and never an IP literal. A wildcard needs at least two labels after "*." (*.corp.example, not
// *.com) and is never IP-shaped; an entry that breaks this is ignored here (cmd/vedette refuses it when it
// parses -hosts). *.co.uk is accepted: no public-suffix list is shipped. "localhost", 127.0.0.1 and ::1 are always allowed: that is how a
// developer, and the box's own health check, reach it.
func HostAllowlist(allowed []string, next http.Handler) http.Handler {
	return HostAllowlistWith(allowed, nil, next)
}

// HostAllowlistWith is HostAllowlist that also accepts a Host that is an IP literal (port optional) for which own
// returns true: the addresses the box itself has right now. After a change of the management address the admin
// opens the box at the new one, which the list fixed at start cannot know; names stay pinned to the list. A DNS
// rebinding page is reached by name, never by one of the box's own addresses. own may be nil.
func HostAllowlistWith(allowed []string, own func(netip.Addr) bool, next http.Handler) http.Handler {
	set := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	var wild []string // the part after "*", ".corp.example"
	for _, h := range allowed {
		k := hostKey(h)
		switch {
		case k == "":
		case strings.HasPrefix(k, "*."):
			if ValidWildcard(k) {
				wild = append(wild, k[1:])
			}
		case strings.Contains(k, "*"): // only a leading "*." is a wildcard
		default:
			set[k] = true
		}
	}
	allowedHost := func(host string) bool {
		k := hostKey(host)
		if set[k] {
			return true
		}
		if k == "" || strings.Contains(k, "*") {
			return false
		}
		if a, err := netip.ParseAddr(k); err == nil { // a wildcard never matches an IP literal
			return own != nil && own(a)
		}
		for _, suffix := range wild {
			if label, ok := strings.CutSuffix(k, suffix); ok && label != "" && !strings.Contains(label, ".") {
				return true
			}
		}
		return false
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowedHost(r.Host) {
			apierr.Write(w, apierr.New(http.StatusMisdirectedRequest, apierr.CodeMisdirected, "This address is not one Vedette answers to. Open it with the name or address it was set up with."))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ValidWildcard reports whether h (lower case, "*." first) is a usable wildcard host: no other "*", at least
// two labels after "*." (so *.com is refused, *.corp.example is fine), and not IP-shaped (the last label,
// the top-level domain, is never all digits: *.168.1.10 would otherwise stand for 192.168.1.10).
func ValidWildcard(h string) bool {
	rest, ok := strings.CutPrefix(h, "*.")
	if !ok || strings.Contains(rest, "*") {
		return false
	}
	labels := strings.Split(rest, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" {
			return false
		}
	}
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}

// hostKey normalises a Host header value or a configured host (port optional) to a comparable key.
// It returns "" for an empty or malformed value, which never matches.
func hostKey(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().WithZone("").String()
	}
	if strings.ContainsAny(h, " /\\@?#[]") {
		return ""
	}
	return h
}
