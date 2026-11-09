package channel

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"
)

const redacted = "[redacted]"

// Secret holds a channel credential (bot token, SMTP password, webhook URL,
// signing key, OA access token). It never prints its value: String, Format,
// GoString, slog and JSON all yield "[redacted]". Reveal is the only way out and
// is meant for the single place that builds the outgoing request.
type Secret struct{ v string }

// NewSecret wraps a credential.
func NewSecret(v string) Secret { return Secret{v: v} }

// Reveal returns the plain value.
func (s Secret) Reveal() string { return s.v }

// IsZero reports whether no value is set.
func (s Secret) IsZero() bool { return s.v == "" }

// String returns the placeholder.
func (s Secret) String() string { return redacted }

// GoString returns the placeholder.
func (s Secret) GoString() string { return redacted }

// Format makes every fmt verb (%v %+v %#v %s %q %x) print the placeholder.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText keeps JSON and other text encoders from leaking the value.
func (s Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// scrub removes every secret value from s. It is the last line of defence for
// error text; values shorter than 4 bytes are ignored (they would mangle text).
// For a URL-shaped secret (Slack webhook) the path and each path segment are
// removed too, because a server may echo only the path.
func scrub(s string, secrets ...Secret) string {
	for _, sec := range secrets {
		for _, v := range pieces(sec.v) {
			s = strings.ReplaceAll(s, v, redacted)
		}
	}
	return s
}

// pieces returns the strings to remove for one secret value, longest first.
func pieces(v string) []string {
	if len(v) < 4 {
		return nil
	}
	out := []string{v}
	if u, err := url.Parse(v); err == nil && u.Scheme != "" && u.Host != "" {
		if len(u.Path) >= 4 {
			out = append(out, u.Path)
		}
		for _, seg := range strings.Split(u.Path, "/") {
			if len(seg) >= 4 {
				out = append(out, seg)
			}
		}
	}
	return out
}
