package feeds

// Helpers that reproduce the JavaScript semantics the SPA parser (parsers.ts)
// relies on, so Go and TypeScript agree on the same input.

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// jsIsSpace is JavaScript's \s / String.prototype.trim whitespace set.
func jsIsSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

func jsTrim(s string) string { return strings.TrimFunc(s, jsIsSpace) }

// jsLen is String.length (UTF-16 code units).
func jsLen(s string) int {
	n := 0
	for _, r := range s {
		n++
		if r >= 0x10000 {
			n++
		}
	}
	return n
}

// jsSlice is s.slice(0, n) on UTF-16 units; it never splits a surrogate pair.
func jsSlice(s string, n int) string {
	units := 0
	for i, r := range s {
		w := 1
		if r >= 0x10000 {
			w = 2
		}
		if units+w > n {
			return s[:i]
		}
		units += w
	}
	return s
}

var jsDecimal = regexp.MustCompile(`^[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$`)

// jsNumber is Number(s) restricted to finite results: ok is false for NaN and
// for infinities, which every caller rejects anyway.
func jsNumber(s string) (float64, bool) {
	s = jsTrim(s)
	if s == "" {
		return 0, true
	}
	if len(s) > 2 && s[0] == '0' {
		base := 0
		switch s[1] {
		case 'x', 'X':
			base = 16
		case 'o', 'O':
			base = 8
		case 'b', 'B':
			base = 2
		}
		if base != 0 {
			n, err := strconv.ParseUint(s[2:], base, 64)
			if err != nil {
				return 0, false
			}
			return float64(n), true
		}
	}
	if !jsDecimal.MatchString(s) {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false
	}
	return f, true
}

// jsNumString is String(number): shortest round-trip digits, JS exponent rules.
func jsNumString(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		return "0"
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde+XX
	mant, exp, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	x, _ := strconv.Atoi(exp)
	n, k := x+1, len(digits)
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits
	}
	es := "+"
	if n-1 < 0 {
		es = "-"
	}
	ae := n - 1
	if ae < 0 {
		ae = -ae
	}
	if k == 1 {
		return sign + digits + "e" + es + strconv.Itoa(ae)
	}
	return sign + digits[:1] + "." + digits[1:] + "e" + es + strconv.Itoa(ae)
}

// unsafeRune reports characters that must never reach a log, a notification
// or a page verbatim: C0 controls (except tab, newline, carriage return), DEL,
// C1 controls, Unicode format characters (bidi overrides and isolates,
// zero-width characters, BOM, ...) and the line and paragraph separators.
func unsafeRune(r rune) bool {
	switch {
	case r < 0x20:
		return r != '\t' && r != '\n' && r != '\r'
	case r == 0x7f, r >= 0x80 && r <= 0x9f, r == 0x2028, r == 0x2029:
		return true
	}
	return r > 0x9f && unicode.Is(unicode.Cf, r)
}

func hasControl(s string) bool { return strings.ContainsFunc(s, unsafeRune) }

// hasControlStrict also refuses tab, newline and carriage return: for identifiers.
func hasControlStrict(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unsafeRune(r) || r == '\t' || r == '\n' || r == '\r' })
}

// stripFormat removes the format characters, C1 controls and separators that
// hasControl would refuse, for free-text fields where dropping them is enough.
// C0 controls are kept so that the caller still rejects them.
func stripFormat(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return unsafeRune(r) && r >= 0x7f }) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unsafeRune(r) && r >= 0x7f {
			return -1
		}
		return r
	}, s)
}

// quoteVal renders a feed-supplied value for a message: truncated, then quoted
// with Go escapes so control and format characters show as \x1b or \u202e.
func quoteVal(s string) string {
	// D-208: a feed value is a short snippet, never more: unprintable runes (controls, bidi overrides) become spaces first.
	return strconv.Quote(strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, jsSlice(s, 40)))
}

// cleanText strips a UTF-8 BOM and replaces invalid UTF-8 so nothing downstream
// (JSON, SQLite text columns) sees broken encoding.
func cleanText(b []byte) string {
	s := strings.TrimPrefix(string(b), "\ufeff")
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\ufffd")
	}
	return s
}
