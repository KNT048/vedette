package channel

import (
	"net/url"
	"strings"

	"github.com/kiennt048/vedette/core/secrets"
)

const redacted = "[redacted]"

// isSet reports whether v holds a value (core/secrets.Value has no IsSet).
func isSet(v secrets.Value) bool { return v.Reveal() != "" }

// scrub removes every secret value from s. It is the last line of defence for
// error text; values shorter than 4 bytes are ignored (they would mangle text).
// For a URL-shaped secret (Slack or webhook URL) the path, the query and each
// path segment and query value are removed too, because a server may echo only
// part of the URL.
func scrub(s string, hide ...secrets.Value) string {
	for _, sec := range hide {
		for _, v := range pieces(sec.Reveal()) {
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
		if len(u.RawQuery) >= 4 {
			out = append(out, u.RawQuery)
		}
		for _, vals := range u.Query() {
			for _, q := range vals {
				if len(q) >= 4 {
					out = append(out, q)
				}
			}
		}
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
