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
// form (an IPv6 literal in brackets). "localhost", 127.0.0.1 and ::1 are always allowed: that is how a
// developer, and the box's own health check, reach it.
func HostAllowlist(allowed []string, next http.Handler) http.Handler {
	set := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	for _, h := range allowed {
		if k := hostKey(h); k != "" {
			set[k] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !set[hostKey(r.Host)] {
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
