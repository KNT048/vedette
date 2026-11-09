package transport

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxLine is the longest line of device text that is ever kept (D-94 (5)).
const MaxLine = 200

// CleanLine makes text fit in a message or a log line: one line, no control characters, at most MaxLine characters. Anything that
// came from a device or a server passes through it before it leaves this package, and every secret in redact is replaced first.
func CleanLine(s string, redact ...string) string {
	for _, r := range redact {
		if len(r) >= 4 {
			s = strings.ReplaceAll(s, r, "***")
		}
	}
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsControl(r) || unicode.IsSpace(r) || r == utf8.RuneError:
			space = b.Len() > 0
		default:
			if space {
				b.WriteByte(' ')
				space = false
			}
			b.WriteRune(r)
		}
	}
	out := b.String()
	if utf8.RuneCountInString(out) > MaxLine {
		out = string([]rune(out)[:MaxLine-1]) + "…"
	}
	return out
}
