package transport

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxLine is the longest line of device text that is ever kept (D-94 (5)).
const MaxLine = 200

// minSecret is the shortest secret that is looked for: a shorter string would match ordinary text.
const minSecret = 4

// CleanLine makes text fit in a message or a log line: one line, no control characters, at most MaxLine characters. Anything that
// came from a device or a server passes through it before it leaves this package, and every secret in redact is replaced first
// (Redact). The user name is not a secret and is not in redact; the Basic value (user:secret) is.
func CleanLine(s string, redact ...string) string {
	s = Redact(s, redact...)
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsControl(r) || unicode.IsSpace(r) || r == utf8.RuneError:
			space = b.Len() > 0
		case isInvisible(r): // bidi overrides and zero-width characters make a line read differently from what it holds
			continue
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
		out = dropPartial(string([]rune(out)[:MaxLine-1]), forms(redact)) + "…"
	}
	return out
}

// Secrets are the strings of a sign-in that must not appear in any text: the secret, and for Basic the whole value "user:secret"
// (so a password that holds "user:" is still one string). The user name alone is not a secret.
func Secrets(authType, username, secret string) []string {
	if secret == "" {
		return nil
	}
	if authType == "basic" {
		return []string{username + ":" + secret, secret}
	}
	return []string{secret}
}

// isInvisible is a character that is not a control character but changes how text reads or hides: format characters (bidi overrides,
// zero-width), the line and paragraph separators, and variation selectors.
func isInvisible(r rune) bool {
	return unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' || unicode.Is(unicode.Variation_Selector, r)
}

// Forms are the ways a secret can show in text that a device or server echoes: in clear, escaped for JSON (with Go's escaping of
// < > & and with the \/ that some encoders add) and for a URL (query and path), and in base64, standard and URL-safe, as the whole
// value and at each of the three alignments it can have inside a longer base64 text (the edges that depend on neighbouring bytes
// are left off). A secret shorter than minSecret has none. Pass the whole Basic value ("user:secret") as a secret of its own.
func Forms(secret string) []string {
	if len(secret) < minSecret {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(f string) {
		if len(f) >= minSecret && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	add(secret)
	if b, err := json.Marshal(secret); err == nil {
		j := string(b[1 : len(b)-1])
		add(j)
		add(strings.ReplaceAll(j, "/", `\/`))
		add(strings.ReplaceAll(secret, "/", `\/`))
	}
	add(url.QueryEscape(secret))
	add(url.PathEscape(secret))
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for k := range 3 {
			e := enc.EncodeToString(append(make([]byte, k), secret...))
			skip := [3]int{0, 2, 3}[k] // characters that hold bytes of what came before
			tail := [3]int{0, 2, 1}[(k+len(secret))%3]
			if len(e) > skip+tail {
				add(e[skip : len(e)-tail])
			}
			if k == 0 {
				add(enc.EncodeToString([]byte(secret))) // the whole value
			}
		}
		add(base64.StdEncoding.EncodeToString([]byte(secret)))
	}
	return out
}

func forms(secrets []string) []string {
	var all []string
	for _, s := range secrets {
		all = append(all, Forms(s)...)
	}
	return all
}

// Redact replaces every form of every secret with "***", the longest first, so a form that holds another is not left half done.
func Redact(s string, secrets ...string) string {
	fs := forms(secrets)
	sort.SliceStable(fs, func(i, j int) bool { return len(fs[i]) > len(fs[j]) })
	for _, f := range fs {
		s = strings.ReplaceAll(s, f, "***")
	}
	return s
}

// dropPartial removes from the end of s a prefix (of minSecret characters or more) of any form: after a cut, half a secret may be
// the last thing in the text.
func dropPartial(s string, fs []string) string {
	for changed := true; changed; {
		changed = false
		for _, f := range fs {
			for l := len(f) - 1; l >= minSecret; l-- {
				if strings.HasSuffix(s, f[:l]) {
					s, changed = strings.TrimSuffix(s, f[:l]), true
					break
				}
			}
		}
	}
	return s
}

var ansiCSI = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]?`)

// CleanText is CleanLine for several lines: newline and tab stay, every other control character, escape sequence (ANSI CSI, and an
// unfinished one), invisible character and line or paragraph separator goes, every secret in redact is replaced first, and the result
// is cut to at most limit bytes on a character boundary with the partial secret at the cut removed. The second result says it was
// cut. The secrets are removed from the whole text before the cut, so half of one never survives it.
func CleanText(s string, limit int, redact ...string) (string, bool) {
	s = ansiCSI.ReplaceAllString(Redact(s, redact...), "")
	var b strings.Builder
	cut := false
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
		case r == '\r' || unicode.IsControl(r) || isInvisible(r) || r == utf8.RuneError:
			continue
		}
		if b.Len()+utf8.RuneLen(r) > limit {
			cut = true
			break
		}
		b.WriteRune(r)
	}
	out := b.String()
	if cut {
		out = dropPartial(out, forms(redact))
	}
	return out, cut
}
