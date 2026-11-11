package signature

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Mine turns a log message into its template: the words that make a kind of line stay, the values that change from one line
// to the next are masked. IPv4 addresses (with their port) become <ip>, hexadecimal values, MAC and IPv6 addresses <hex>, and
// every run of digits <n>, so "user admin logged in from 192.168.10.113 via winbox" and the same line from another address
// have the same template. It is the template miner of the generic profile (Drain-style, with fixed masks instead of a learned
// tree: it needs no state, so the same line has the same signature on any box, in any order, after a restart).
// Mine is total: any input gives a non-empty, valid UTF-8 text of at most MaxSignatureBytes bytes, with no control character.
func Mine(text string) string {
	text = strings.ToValidUTF8(clip(text, maxScan), "?")
	var b strings.Builder
	space := false
	for i := 0; i < len(text) && b.Len() < MaxSignatureBytes; {
		c := text[i]
		switch {
		case c == ' ' || c == '\t' || c < 0x20 || c == 0x7f:
			space = true
			i++
			continue
		case isAtomByte(c):
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			j := i
			for j < len(text) && isAtomByte(text[j]) {
				j++
			}
			maskAtom(&b, text[i:j])
			i = j
		default: // punctuation and non-ASCII text are kept as they are
			r, n := utf8.DecodeRuneInString(text[i:])
			if unicode.IsControl(r) { // C1 controls: a space, like the C0 ones
				space = true
				i += n
				continue
			}
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			b.WriteString(text[i : i+n])
			i += n
		}
	}
	out := strings.TrimSpace(cut(b.String(), MaxSignatureBytes))
	if out == "" {
		return "(empty)"
	}
	return out
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
