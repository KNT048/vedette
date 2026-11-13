package feeds

import (
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// IsInternalHost is the INV-2 list of hosts that may use plain http.
func IsInternalHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	switch h {
	case "localhost", "::1":
		return true
	}
	for _, suf := range []string{".local", ".lan", ".internal", ".localhost"} {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	a, err := netip.ParseAddr(h)
	if err != nil || !a.Is4() {
		return false
	}
	b := a.As4()
	return b[0] == 10 || b[0] == 127 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168)
}

// CheckURL is the INV-2 address rule: https, or http for internal hosts only.
// Credentials in the address are refused (they belong in the auth settings).
func CheckURL(raw string) error { return checkURL(raw, MaxURLLen) }

func checkURL(raw string, maxLen int) error {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > maxLen || hasControl(s) || strings.ContainsFunc(s, jsIsSpace) {
		return fail(ErrInvalidURL, "Enter a full address such as https://example.com/feed.json.")
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" || u.Opaque != "" {
		return fail(ErrInvalidURL, "Enter a full address such as https://example.com/feed.json.")
	}
	if u.User != nil {
		return fail(ErrInvalidURL, "Do not put a user name or password in the address; use the authentication settings.")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if IsInternalHost(u.Hostname()) {
			return nil
		}
		return fail(ErrHTTPSRequired, "Use an https:// address (http:// is only allowed for internal addresses).")
	}
	return fail(ErrInvalidURL, "Enter a full address such as https://example.com/feed.json.")
}

// blockedText is the sentence for an address no feed may ever be pulled from (D-208), at save (CheckDest) and at pull (userError).
const blockedText = "Vedette does not pull feeds from link-local, multicast, unspecified or cloud metadata addresses."

// ownText is the sentence for Vedette itself (ErrOwnAddress, D-446): the same sentence in feeds, notify, logs and ai.
const ownText = "That address is Vedette itself: loopback, Vedette's own container, or one of its ports (8443, 8444, 8765, 514, 6514) on the machine that runs it. For another program on that machine, enter the machine's LAN address and that program's port."

// CheckDest is the save-time half of INV-17 (D-420 (1)): an address whose host is a literal IP the pull would refuse
// (link-local, cloud metadata, unspecified, multicast, in any transition form: blockedText; Vedette itself, D-446: loopback,
// an address of own.self, or one of own.machine on a port of vedettePorts: ownText) or a loopback name (localhost, *.localhost:
// ownText) is refused when the feed is saved, with the pull's sentence.
// Other names are not resolved here (no DNS lookup in a request; the answer could change before the pull anyway): a name
// that resolves to a refused address is still refused by the dialer at every pull (guardedDial, destControl).
func CheckDest(raw string, own ownAddrs) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil // CheckURL refuses it with its own sentence
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if ip, err := netip.ParseAddr(h); err == nil {
		if refusedAlways(ip) {
			return fail(ErrBlockedHost, blockedText)
		}
		if (&destGuard{}).refused(ip, urlPort(u), own) {
			return fail(ErrBlockedHost, ownText)
		}
		return nil
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return fail(ErrBlockedHost, ownText)
	}
	return nil
}

// urlPort is the port a request to u connects to: the one written, else the scheme's (80 for http, 443 otherwise).
func urlPort(u *url.URL) uint16 {
	if p := u.Port(); p != "" {
		return dialPort(p)
	}
	if strings.EqualFold(u.Scheme, "http") {
		return 80
	}
	return 443
}

// sameAddress reports whether two feed addresses fetch the same document (D-420 (2)): scheme and host compared without
// case, a default port left out, the fragment ignored; the path and query must match exactly.
func sameAddress(a, b string) bool {
	ka, oka := addressKey(a)
	kb, okb := addressKey(b)
	return oka && okb && ka == kb
}

func addressKey(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return "", false
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.TrimSuffix(strings.ToLower(u.Hostname()), "."), u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + ":" + port + path + "?" + u.RawQuery, true
}

// CheckInterval is INV-5: 1..168 hours.
func CheckInterval(hours int) error {
	if hours < 1 || hours > 168 {
		return fail(ErrInvalidInterval, "The schedule must be between 1 and 168 hours.")
	}
	return nil
}

// CheckKindFormat is INV-5: the format must fit the kind.
func CheckKindFormat(k Kind, f Format) error {
	if k != KindVulnerabilities && k != KindIOC {
		return fail(ErrInvalidFormat, "Unknown feed kind.")
	}
	if !FormatAllowed(k, f) {
		what := "vulnerability"
		if k == KindIOC {
			what = "IOC"
		}
		return fail(ErrInvalidFormat, "This format does not fit a %s feed.", what)
	}
	return nil
}

// CheckName is INV-5: a non-empty name of at most 60 characters, unique
// case-insensitively among the built-in feed names and `others` (the names of
// the other custom feeds; leave out the feed being edited).
func CheckName(name string, others []string) error {
	n := strings.TrimSpace(name)
	if n == "" || utf8.RuneCountInString(n) > MaxNameLen || strings.ContainsFunc(n, unicode.IsControl) || hasControl(n) {
		return fail(ErrInvalidName, "Enter a name of up to 60 characters.")
	}
	taken := func(x string) bool { return strings.EqualFold(strings.TrimSpace(x), n) }
	for _, b := range builtinSources {
		if taken(b.Name) {
			return fail(ErrDuplicateName, "A feed with this name already exists.")
		}
	}
	for _, o := range others {
		if taken(o) {
			return fail(ErrDuplicateName, "A feed with this name already exists.")
		}
	}
	return nil
}

// AuthType is how a feed authenticates.
type AuthType string

// Authentication types.
const (
	AuthNone   AuthType = "none"
	AuthHeader AuthType = "header"
	AuthBearer AuthType = "bearer"
	AuthBasic  AuthType = "basic"
)

// Auth is the credential set the fetcher injects.
type Auth struct {
	Type       AuthType
	HeaderName string // AuthHeader
	Username   string // AuthBasic
	Secret     Secret
}

var headerNameRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,80}$`)

// Headers a feed must not set: they would change the framing, the identity of
// the request (FORBID-2) or the caching handshake the fetcher owns.
var reservedHeaders = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true, "upgrade": true,
	"te": true, "trailer": true, "proxy-authorization": true, "user-agent": true, "accept-encoding": true,
	"if-none-match": true, "if-modified-since": true, "range": true, "cookie": true,
}

// CheckAuth validates the auth settings of a feed (INV-6). newSecret is the
// secret typed by the user, nil when editing and keeping the stored one;
// hasStored says a secret is already stored.
func CheckAuth(t AuthType, headerName, username string, newSecret *string, hasStored bool) error {
	switch t {
	case AuthNone:
		return nil
	case AuthHeader:
		if !headerNameRE.MatchString(headerName) || reservedHeaders[strings.ToLower(headerName)] {
			return fail(ErrInvalidAuth, "Enter a valid header name, for example X-Api-Key.")
		}
	case AuthBasic:
		u := strings.TrimSpace(username)
		if u == "" || utf8.RuneCountInString(u) > 80 || strings.Contains(u, ":") || strings.ContainsFunc(u, unicode.IsControl) {
			return fail(ErrInvalidAuth, "Enter the user name (up to 80 characters, no colon).")
		}
	case AuthBearer:
	default:
		return fail(ErrInvalidAuth, "Unknown authentication type.")
	}
	if newSecret == nil {
		if !hasStored {
			return fail(ErrInvalidAuth, "Enter the secret.")
		}
		return nil
	}
	return CheckSecret(*newSecret)
}
