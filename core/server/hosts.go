package server

import (
	"html"
	"io"
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
	return HostAllowlistFunc(HostMatcher(allowed, own), next)
}

// HostAllowlistFunc is HostAllowlist with the test given as a function: HostMatcher's, or one that also accepts a name the box learns
// while it runs (cmd/vedette: the Box address an administrator saves, D-465). The refusal is the same for every client (421, nothing
// routed); only its body differs: a browser opening a page gets a short HTML page (misdirectedPage), an API client the JSON error.
func HostAllowlistFunc(allowedHost func(host string) bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowedHost(r.Host) {
			if wantsPage(r) {
				writeMisdirectedPage(w, r.Host)
				return
			}
			apierr.Write(w, apierr.New(http.StatusMisdirectedRequest, apierr.CodeMisdirected, misdirectedText))
			return
		}
		next.ServeHTTP(w, r)
	})
}

const misdirectedText = "This address is not one Vedette answers to. Open it with the name or address it was set up with."

// misdirectedDoc is where the page sends the administrator: how to set the names the box answers to (D-556).
const misdirectedDoc = "https://github.com/KNT048/vedette/blob/main/docs/INSTALL-CONTAINER.md#2-say-where-it-lives"

// wantsPage: a browser loading a page (GET or HEAD that accepts text/html) outside the API. /api/ paths and every other client keep
// the JSON error, which the interface and scripts branch on.
func wantsPage(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
		return false
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

// writeMisdirectedPage answers 421 with a plain page: no script, no style (the CSP of Envelope allows neither inline), no list of the
// names the box answers to (the refused visitor need not learn them). It names the host the browser sent, normalised by hostKey
// and escaped, so the administrator sees which name to add; a malformed one is left out.
func writeMisdirectedPage(w http.ResponseWriter, host string) {
	opened := "a name it was not set up for"
	if k := hostKey(host); k != "" {
		opened = "<strong>" + html.EscapeString(k) + "</strong>, a name it was not set up for"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusMisdirectedRequest)
	_, _ = io.WriteString(w, `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Vedette: not this address</title></head>
<body>
<h1>This address is not one Vedette answers to</h1>
<p>You opened this box as `+opened+`. Open it with the name or address it was set up with.</p>
<p>To use this name too, an administrator adds it: on a Docker or Podman install, to the VEDETTE_HOSTS line of vedette.env, then runs <code>up -d</code> again; on the appliance, as the Box address in Settings, Box network.</p>
<p><a href="`+misdirectedDoc+`">How to set the names Vedette answers to</a></p>
</body></html>
`)
}

// HostMatcher is the test HostAllowlistWith applies to the Host header, for code that must ask the same question again (the agent-intake
// install scripts put a Host into text a server will run, so they re-check it against the very list that let the request in).
func HostMatcher(allowed []string, own func(netip.Addr) bool) func(host string) bool {
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
	return func(host string) bool {
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
