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
func CheckURL(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > MaxURLLen || hasControl(s) || strings.ContainsFunc(s, jsIsSpace) {
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
	if n == "" || utf8.RuneCountInString(n) > MaxNameLen || strings.ContainsFunc(n, unicode.IsControl) {
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
