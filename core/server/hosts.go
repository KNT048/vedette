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
// corp.example) and never an IP literal. "localhost", 127.0.0.1 and ::1 are always allowed: that is how a
// developer, and the box's own health check, reach it.
func HostAllowlist(allowed []string, next http.Handler) http.Handler {
	set := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	var wild []string // the part after "*", ".corp.example"
	for _, h := range allowed {
		k := hostKey(h)
		switch {
		case k == "":
		case strings.HasPrefix(k, "*.") && len(k) > 2 && !strings.Contains(k[2:], "*"):
			wild = append(wild, k[1:])
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
