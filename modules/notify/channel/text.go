package channel

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits on untrusted text, applied before any rendering.
const (
	maxTitle  = 200
	maxLine   = 1000
	maxItem   = 200
	maxItems  = 20
	maxDevice = 200
)

// clean makes untrusted text safe to print: invalid UTF-8 becomes U+FFFD,
// control characters and Unicode format characters (bidi overrides, zero-width
// marks) are dropped, tabs become spaces, and line separators become "\n" when
// multiline is true or a space otherwise.
func clean(s string, multiline bool) string {
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == ' ' || r == ' ' || r == '\u0085':
			if multiline {
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
		case r == '\t':
			b.WriteByte(' ')
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == '￾', r == '￿':
			// dropped
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// truncRunes cuts s to at most n runes, ending with an ellipsis when it cut.
func truncRunes(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// norm returns a copy of m with every text field cleaned and size-limited. It is
// the only way adapters read the fields.
func (m Message) norm() Message {
	one := func(s string, n int) string { return truncRunes(strings.TrimSpace(clean(s, false)), n) }
	multi := func(s string, n int) string { return truncRunes(strings.TrimSpace(clean(s, true)), n) }
	out := Message{
		ID:       one(m.ID, 100),
		Kind:     one(m.Kind, 30),
		Severity: m.Severity,
		Title:    one(m.Title, maxTitle),
		Device:   one(m.Device, maxDevice),
		What:     multi(m.What, maxLine),
		Action:   multi(m.Action, maxLine),
		Link:     m.Link,
	}
	for i, it := range m.Items {
		if i == maxItems {
			out.Items = append(out.Items, "…and more")
			break
		}
		if it = one(it, maxItem); it != "" {
			out.Items = append(out.Items, it)
		}
	}
	return out
}

// head is the first line of a text rendering: "High: title".
func (m Message) head() string { return severityLabel[m.Severity] + ": " + m.Title }

// lines is the plain-text layout shared by chat channels (and, with a greeting,
// email): what happened, where, what to do first, the detail lines and the link.
// m must be normalised.
func (m Message) lines(link string) []string {
	l := []string{m.head()}
	if m.Device != "" {
		l = append(l, "Device: "+m.Device)
	}
	if m.What != "" {
		l = append(l, m.What)
	}
	if m.Action != "" {
		l = append(l, "What to do first: "+m.Action)
	}
	for _, it := range m.Items {
		l = append(l, "- "+it)
	}
	return append(l, "Details: "+link)
}
