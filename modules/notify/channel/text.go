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
		ID:           one(m.ID, 100),
		Kind:         one(m.Kind, 30),
		Severity:     m.Severity,
		Title:        one(m.Title, maxTitle),
		Device:       one(m.Device, maxDevice),
		What:         multi(m.What, maxLine),
		Action:       multi(m.Action, maxLine),
		Link:         m.Link,
		IncidentKind: one(m.IncidentKind, 30),
	}
	for i, d := range m.Devices {
		if i == maxItems {
			break
		}
		if d.Name = one(d.Name, maxDevice); d.Name != "" {
			out.Devices = append(out.Devices, DeviceRef{ID: one(d.ID, 96), Name: d.Name})
		}
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
	if link == "" {
		return append(l, openVedetteLine)
	}
	return append(l, "Details: "+link)
}

// openVedetteLine replaces the link line when the message has no link (the box address is not configured).
const openVedetteLine = "Open Vedette to see details."

// mapText applies f to every feed-sourced field (title, device, what, action,
// items). ID, Kind, Severity and Link are not feed text: the link is the box's
// own and stays a real link.
func (m Message) mapText(f func(string) string) Message {
	m.Title, m.Device, m.What, m.Action = f(m.Title), f(m.Device), f(m.What), f(m.Action)
	items := make([]string, len(m.Items))
	for i, it := range m.Items {
		items[i] = f(it)
	}
	m.Items = items
	return m
}

var zwj = string(rune(0x200d)) // zero-width joiner

// defang stops chat apps that render plain text from turning feed text into
// links, mentions or bot commands: an "@" or "/" that is not glued to a
// preceding letter or digit (so "://", "@user", "/start" and "(/cmd)", but not
// "and/or" or "a@b") gets a zero-width joiner after it. Bare domain names,
// email addresses, hashtags and phone numbers are still auto-linked by some
// apps: that residue is documented, not neutralised.
func defang(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	prev := ' '
	for _, r := range s {
		b.WriteRune(r)
		if (r == '@' || r == '/') && !unicode.IsLetter(prev) && !unicode.IsDigit(prev) {
			b.WriteString(zwj)
		}
		prev = r
	}
	return b.String()
}

// slackFormat neutralises Slack mrkdwn formatting in feed text. Slack has no
// escape for * _ ~ ` so each is replaced by a look-alike that formats nothing;
// an underscore between two letters or digits (snake_case, which Slack never
// formats) is kept.
func slackFormat(s string) string {
	r := []rune(s)
	var b strings.Builder
	b.Grow(len(s))
	word := func(i int) bool { return i >= 0 && i < len(r) && (unicode.IsLetter(r[i]) || unicode.IsDigit(r[i])) }
	for i, c := range r {
		switch {
		case c == '*':
			c = 0x2217
		case c == '~':
			c = 0x223C
		case c == '`':
			c = 0x02CB
		case c == '_' && (!word(i-1) || !word(i+1)):
			c = 0xFF3F
		}
		b.WriteRune(c)
	}
	return b.String()
}
