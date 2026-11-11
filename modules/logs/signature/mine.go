package signature

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Mine turns a log message into its template: the words that make a kind of line stay, the values that change from one line
// to the next are masked, so that a device cannot make one signature per value. Masked: IPv4 addresses (with their port) -> <ip>,
// hexadecimal values, MAC and IPv6 addresses -> <hex>, digit runs -> <n>, a long identifier or random-looking token -> <tok>,
// a path (a word that starts with "/") -> <path>, a quoted string -> <s>, the value after "=" -> <v> unless it is a short plain
// word (an enumeration such as action=deny) or an address or number, and the name that follows "user", "username" or "for"
// -> <name> ("Invalid user oracle" and "Invalid user postgres" are one signature; a list of user names is not a list of
// signatures). The rule is fixed and has no state, so the same line has the same signature on any box, in any order, after a
// restart (Drain-style template mining without the learned tree). Mine is total: any input gives a non-empty, valid UTF-8 text
// of at most MaxSignatureBytes bytes, with no control character.
func Mine(text string) string {
	text = maskQuotes(strings.ToValidUTF8(clip(text, maxScan), "?"))
	var out []string
	size, maskNext := 0, false
	for _, w := range strings.FieldsFunc(text, func(r rune) bool { return r == ' ' || unicode.IsControl(r) }) {
		if size >= MaxSignatureBytes {
			break
		}
		var m string
		switch low := lowerWord(w); {
		case maskNext && (low == "invalid" || low == "illegal" || low == "user" || low == "username"): // "for invalid user x": the name comes after "user"
			m = w
		case maskNext && plainName(w):
			m, maskNext = "<name>", false
		default:
			m, maskNext = maskWord(w), low == "user" || low == "username" || low == "for"
		}
		out = append(out, m)
		size += len(m) + 1
	}
	res := strings.TrimSpace(cut(strings.Join(out, " "), MaxSignatureBytes))
	if res == "" {
		return "(empty)"
	}
	return res
}

// lowerWord is the word in ASCII lower case without the punctuation that ends it.
func lowerWord(w string) string {
	return strings.ToLower(strings.TrimRight(w, ":,;."))
}

// plainName says whether w can be the name of an account: it starts with a letter and has only letters, digits and . _ - (at most 64).
func plainName(w string) bool {
	if w == "" || len(w) > 64 || (w[0] < 'A' || w[0] > 'Z' && w[0] < 'a' || w[0] > 'z') {
		return false
	}
	for i := 0; i < len(w); i++ {
		if !isAtomByte(w[i]) || w[i] == ':' {
			return false
		}
	}
	return true
}

// enumLike says whether v is a short plain word: letters, '_' and '-' only, at most 16 bytes (deny, accept, forward).
func enumLike(v string) bool {
	if v == "" || len(v) > 16 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; (c < 'A' || c > 'Z' && c < 'a' || c > 'z') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// maskQuotes replaces every "quoted string" (closed within 256 bytes) by <s>, or by the bare word when it is an enumeration.
func maskQuotes(s string) string {
	if !strings.Contains(s, `"`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '"' {
			b.WriteByte(s[i])
			i++
			continue
		}
		end := -1
		for j := i + 1; j < len(s) && j <= i+256; j++ {
			if s[j] == '\\' {
				j++
				continue
			}
			if s[j] == '"' {
				end = j
				break
			}
		}
		if end < 0 { // not closed: the quote is just a character
			b.WriteByte('"')
			i++
			continue
		}
		if in := s[i+1 : end]; enumLike(in) {
			b.WriteString(in)
		} else {
			b.WriteString("<s>")
		}
		i = end + 1
	}
	return b.String()
}

// maskWord masks one word (no space in it).
func maskWord(w string) string {
	if len(w) > 1 && w[0] == '/' {
		return "<path>"
	}
	if i := strings.IndexByte(w, '='); i > 0 {
		key := w[:i]
		ok := true
		for k := 0; k < len(key); k++ {
			if !isAtomByte(key[k]) || key[k] == ':' {
				ok = false
			}
		}
		if ok {
			return maskPlain(key) + "=" + maskValue(w[i+1:])
		}
	}
	return maskPlain(w)
}

// maskValue masks what follows "=": a short plain word stays, an address, a number or a hex value keep their own mask, everything
// else is <v>. Punctuation that ends the value stays where it is.
func maskValue(v string) string {
	core := strings.TrimRight(v, ",;)]}")
	tail := v[len(core):]
	switch {
	case core == "":
		return v
	case core[0] == '<': // already masked (a quoted string)
		return v
	case enumLike(core):
		return v
	}
	switch m := maskPlain(core); m {
	case "<ip>", "<n>", "<hex>":
		return m + tail
	}
	return "<v>" + tail
}

// maskPlain walks a word and masks its atoms; punctuation and non-ASCII text are kept as they are.
func maskPlain(text string) string {
	var b strings.Builder
	for i := 0; i < len(text); {
		c := text[i]
		if isAtomByte(c) {
			j := i
			for j < len(text) && isAtomByte(text[j]) {
				j++
			}
			maskAtom(&b, text[i:j])
			i = j
			continue
		}
		r, n := utf8.DecodeRuneInString(text[i:])
		if r == utf8.RuneError && n == 1 || !unicode.IsControl(r) {
			b.WriteString(text[i : i+n])
		}
		i += n
	}
	return b.String()
}

// isAtomByte says whether c can be part of a word or a value: letters, digits and the joiners of addresses and identifiers.
func isAtomByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == ':' || c == '-' || c == '_'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// maskAtom writes one atom with its variable parts masked.
func maskAtom(b *strings.Builder, a string) {
	for a != "" {
		if n := ipv4Prefix(a); n > 0 {
			b.WriteString("<ip>")
			a = a[n:]
			if len(a) > 1 && a[0] == ':' && isDigit(a[1]) { // the port belongs to the address
				k := 1
				for k < len(a) && isDigit(a[k]) {
					k++
				}
				a = a[k:]
			}
			continue
		}
		if hexLike(a) {
			b.WriteString("<hex>")
			return
		}
		if randomLike(a) {
			b.WriteString("<tok>")
			return
		}
		for i := 0; i < len(a); {
			if isDigit(a[i]) {
				for i < len(a) && isDigit(a[i]) {
					i++
				}
				b.WriteString("<n>")
				continue
			}
			b.WriteByte(a[i])
			i++
		}
		return
	}
}

// ipv4Prefix returns the length of a dotted quad at the start of a (four numbers of at most three digits, each at most 255,
// not followed by another ".digit"), or 0.
func ipv4Prefix(a string) int {
	i := 0
	for part := 0; part < 4; part++ {
		start, v := i, 0
		for i < len(a) && i-start < 3 && isDigit(a[i]) {
			v = v*10 + int(a[i]-'0')
			i++
		}
		if i == start || v > 255 {
			return 0
		}
		if part < 3 {
			if i >= len(a) || a[i] != '.' {
				return 0
			}
			i++
		}
	}
	if i < len(a) && (isDigit(a[i]) || a[i] == '.' && i+1 < len(a) && isDigit(a[i+1])) {
		return 0
	}
	return i
}

// hexLike says whether the atom is a hexadecimal value, a hash, a MAC or an IPv6 address: 0x followed by hex digits; or only hex
// digits with at least 8 of them and one digit; or hex digits joined by at least two ':' or '-' with at least 6 digits in all and
// one letter (so a time 12:30:45 and a date 2026-11-09 are numbers, not hex).
func hexLike(a string) bool {
	if len(a) > 2 && a[0] == '0' && (a[1] == 'x' || a[1] == 'X') {
		for i := 2; i < len(a); i++ {
			if !isHex(a[i]) {
				return false
			}
		}
		return true
	}
	hex, seps, digits, letters := 0, 0, 0, 0
	for i := 0; i < len(a); i++ {
		switch c := a[i]; {
		case isDigit(c):
			hex++
			digits++
		case isHex(c):
			hex++
			letters++
		case c == ':' || c == '-':
			seps++
		default:
			return false
		}
	}
	if seps == 0 {
		return hex >= 8 && digits > 0
	}
	return seps >= 2 && hex >= 6 && letters > 0
}

// clip returns at most n bytes of s, cut on a character boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return cut(s, n)
}

// cut returns at most n bytes of s without splitting a character.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// randomLike says whether an atom looks like an identifier or a random token and not like a word: 16 bytes or more with letters and
// digits mixed, or 20 bytes or more with an upper-case letter after the first character, or 24 bytes or more with a digit or an
// upper-case letter (session ids, base64, tokens, serial numbers).
func randomLike(a string) bool {
	if len(a) < 16 {
		return false
	}
	digit, letter, upper := false, false, false
	for i := 0; i < len(a); i++ {
		switch c := a[i]; {
		case isDigit(c):
			digit = true
		case c >= 'A' && c <= 'Z':
			letter = true
			upper = upper || i > 0
		case c >= 'a' && c <= 'z':
			letter = true
		}
	}
	return digit && letter || len(a) >= 20 && upper || len(a) >= 24 && (digit || upper)
}
