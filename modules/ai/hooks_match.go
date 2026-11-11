package ai

import (
	"context"
	"errors"
	"io"
	"math"
	"net/netip"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// span is a byte range of the text to mask.
type span struct{ start, end int }

func maskSpans(s string, spans []span) string {
	var b strings.Builder
	last := 0
	for _, sp := range spans {
		if sp.start < last { // overlapping spans (after mapping back from normalised text): the earlier one covers it
			if sp.end > last {
				sp.start = last
			} else {
				continue
			}
		}
		b.WriteString(s[last:sp.start])
		b.WriteString("[masked]")
		last = sp.end
	}
	b.WriteString(s[last:])
	return b.String()
}

// ---- normalisation: personal data is matched on a plain form of the text, and masked in the original

// scanText is the text a hook run looks at. The normalised form is built once and thrown away when a mask
// changes the text.
type scanText struct {
	orig       string
	built      bool
	norm       string
	start, end []int32 // per byte of norm: the byte range of the original rune it came from
}

// normalized returns the plain form used for personal-data matching and, per byte, where it came from:
//   - full-width ASCII (U+FF01-FF5E) and the ideographic full stop become ASCII;
//   - every Unicode decimal digit becomes 0-9, every Unicode space becomes a space;
//   - format characters (zero-width space and joiners, BOM, soft hyphen) and combining marks are dropped, so
//     decomposed Vietnamese text reads as plain letters;
//   - invalid UTF-8 bytes are dropped.
func (t *scanText) normalized() string {
	if t.built {
		return t.norm
	}
	t.built = true
	var b strings.Builder
	b.Grow(len(t.orig))
	t.start = make([]int32, 0, len(t.orig))
	t.end = make([]int32, 0, len(t.orig))
	for i := 0; i < len(t.orig); {
		r, w := utf8.DecodeRuneInString(t.orig[i:])
		from, to := i, i+w
		i += w
		if r == utf8.RuneError && w == 1 {
			continue
		}
		r, keep := foldRune(r)
		if !keep {
			continue
		}
		n := utf8.RuneLen(r)
		b.WriteRune(r)
		for range n {
			t.start = append(t.start, int32(from))
			t.end = append(t.end, int32(to)) //nolint:gosec // bounded by MaxHookInputBytes (1 MiB)
		}
	}
	t.norm = b.String()
	return t.norm
}

// mapSpan maps a byte range of the normalised text back to the original text.
func (t *scanText) mapSpan(a, b int) span { return span{int(t.start[a]), int(t.end[b-1])} }

func foldRune(r rune) (rune, bool) {
	switch {
	case r < 0x80:
		return r, true
	case r >= 0xFF01 && r <= 0xFF5E:
		return r - 0xFEE0, true
	case r == 0x3002:
		return '.', true
	case unicode.IsSpace(r):
		return ' ', true
	case unicode.Is(unicode.Cf, r), unicode.Is(unicode.Mn, r):
		return 0, false
	case unicode.Is(unicode.Nd, r):
		return '0' + digitValue(r), true
	}
	return r, true
}

// digitValue is the value of a Unicode decimal digit: Nd ranges begin at a zero digit and hold whole sets of ten.
func digitValue(r rune) rune {
	for _, rg := range unicode.Nd.R16 {
		if r >= rune(rg.Lo) && r <= rune(rg.Hi) {
			return (r - rune(rg.Lo)) % 10
		}
	}
	for _, rg := range unicode.Nd.R32 {
		if r >= rune(rg.Lo) && r <= rune(rg.Hi) { //nolint:gosec // Unicode code points are below 0x110000
			return (r - rune(rg.Lo)) % 10 //nolint:gosec // Unicode code points are below 0x110000
		}
	}
	return 0
}

// plain adapts a finder that works on the normalised text: its spans are mapped back to the original.
func plain(find func(norm string) []span) func(context.Context, *scanText) ([]span, error) {
	return func(ctx context.Context, t *scanText) ([]span, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		norm := t.normalized()
		var out []span
		for _, sp := range find(norm) {
			out = append(out, t.mapSpan(sp.start, sp.end))
		}
		return out, nil
	}
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isDigitByte(b byte) bool { return b >= '0' && b <= '9' }

// ---- customer patterns: bounded work

const (
	scanChunk = 32 << 10 // keyword scan: bytes of text between context checks
)

// ctxRunes feeds a string to the regexp engine rune by rune and stops the scan, from inside the engine, when the
// context ends: ReadRune then fails, the engine treats it as the end of the text, and scanRegexp discards the
// result. This is what makes a deadline hold even in the middle of one long match attempt.
type ctxRunes struct {
	ctx context.Context //nolint:containedctx // a short-lived reader that lives for one scan call
	s   string
	i   int
	n   int
	err error
}

func (r *ctxRunes) ReadRune() (rune, int, error) {
	if r.i >= len(r.s) {
		return 0, 0, io.EOF
	}
	if r.n++; r.n&0x3ff == 0 {
		if err := r.ctx.Err(); err != nil {
			r.err = err
			return 0, 0, err
		}
	}
	c, w := utf8.DecodeRuneInString(r.s[r.i:])
	r.i += w
	return c, w, nil
}

// scanRegexp finds the non-empty matches of a customer regex. Go's regexp is RE2 (time linear in the text, no
// catastrophic backtracking) and the program size is limited when the hook is saved, but a program of
// MaxRegexProgram steps over 1 MiB can still take seconds; the scan therefore reads through ctxRunes and
// returns the context's error as soon as the deadline passes. After a match the search restarts at its end, so
// ^ and \b see the cut as the start of the text (a rare extra match, which only masks more).
// errTooManyMatches: more than MaxMatchesPerScan matches in one text.
var errTooManyMatches = errors.New("ai: too many matches")

func scanRegexp(ctx context.Context, re *regexp.Regexp, s string) ([]span, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []span
	for pos := 0; pos < len(s); {
		rr := &ctxRunes{ctx: ctx, s: s[pos:]}
		loc := re.FindReaderIndex(rr)
		if rr.err != nil {
			return nil, rr.err
		}
		if loc == nil {
			break
		}
		if loc[1] > loc[0] {
			if len(out) == MaxMatchesPerScan {
				return nil, errTooManyMatches
			}
			out = append(out, span{pos + loc[0], pos + loc[1]})
		}
		pos += max(loc[1], loc[0]+1)
	}
	return out, nil
}

// scanKeywords finds whole-word, case-insensitive occurrences: the byte before and after must not be a word
// character. (The JavaScript original used lookarounds; RE2 has none, so this is done by hand, which is also
// exact when one keyword is a prefix of another.) The context is checked every chunk.
func scanKeywords(ctx context.Context, s string, words []string) ([]span, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []span
	for i := 0; i < len(s); {
		if i%scanChunk == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		hit := 0
		for _, w := range words {
			n := len(w)
			if i+n > len(s) || !strings.EqualFold(s[i:i+n], w) {
				continue
			}
			if (i > 0 && isWordByte(s[i-1])) || (i+n < len(s) && isWordByte(s[i+n])) {
				continue
			}
			hit = max(hit, n)
		}
		if hit > 0 {
			out = append(out, span{i, i + hit})
			i += hit
			continue
		}
		i++
	}
	return out, nil
}

// estimateInsts approximates the size of the compiled program of a parsed regex with repeats expanded, using
// saturating arithmetic so a hostile pattern cannot overflow it. It is checked before the program is built.
func estimateInsts(re *syntax.Regexp) int {
	sum := 0
	for _, sub := range re.Sub {
		sum = satAddInt(sum, estimateInsts(sub))
	}
	switch re.Op {
	case syntax.OpLiteral:
		return satAddInt(sum, len(re.Rune))
	case syntax.OpRepeat:
		copies := re.Max
		if copies < 0 {
			copies = max(re.Min, 1) + 1
		}
		copies = max(copies, 1)
		return satAddInt(satMulInt(sum, copies), copies)
	}
	return satAddInt(sum, 1)
}

func satAddInt(a, b int) int {
	if a > math.MaxInt-b {
		return math.MaxInt
	}
	return a + b
}

func satMulInt(a, b int) int {
	if a != 0 && b > math.MaxInt/a {
		return math.MaxInt
	}
	return a * b
}

// ---- built-in patterns (ported from harness.ts; JavaScript lookarounds replaced by explicit checks), run on the
// normalised text

const (
	letters  = `\p{L}`
	nameCap  = `\p{Lu}[\p{Ll}\p{Lu}]+`
	accWords = `(?:chủ tài khoản|chu tai khoan|tài khoản|tai khoan|họ và tên|ho va ten|họ tên|ho ten|account|username|user|login|employee|owner)`
	accLead  = `(?:^|[^\p{L}\p{N}_])(?i:` + accWords + `)(?:\s+(?:of|for|name|của))?`
)

var (
	emailRE    = regexp.MustCompile(`[\p{L}\p{N}_.+-]+@[\p{L}\p{N}_-]+(?:\.[\p{L}\p{N}_-]+)+`)
	accountCap = regexp.MustCompile(accLead + `\s*[:=]?\s+(` + nameCap + `(?:\s+` + nameCap + `){1,3})`)
	accountLow = regexp.MustCompile(accLead + `\s*[:=]\s*(` + letters + `+(?:\s+` + letters + `+){1,2})`)
	offTopic   = regexp.MustCompile(`(?i)\b(?:poems?|poetry|songs?|lyrics|jokes?|haiku|limerick|horoscope|recipes?|essay|homework|movies?|novel|fairy ?tale|bedtime story|write (?:me )?a story)\b`)
)

func findAll(re *regexp.Regexp, s string, group int) []span {
	var out []span
	for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
		if a, b := m[2*group], m[2*group+1]; a >= 0 && b > a {
			out = append(out, span{a, b})
		}
	}
	return out
}

func findEmails(norm string) []span { return findAll(emailRE, norm, 0) }

// findAccountNames finds a person's name written after an account keyword, in English or Vietnamese (with or
// without diacritics): capitalised names with or without a colon, and names in any case after a colon or equals sign.
func findAccountNames(norm string) []span {
	return append(findAll(accountCap, norm, 1), findAll(accountLow, norm, 1)...)
}

func findOffTopic(norm string) []span { return findAll(offTopic, norm, 0) }

func isIDSep(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f' || b == '\v' || b == '.' || b == '-'
}

// findIDNumbers finds identity numbers of exactly 9 or 12 digits as people write them: unbroken, or in groups of
// three or more digits joined by up to three separator characters ([ \t\n.-]), such as 0790.1234.5678,
// 123 456 789 or 079 012 345 678. A digit run longer than that is not an ID number. Dotted IPv4 addresses are
// left alone. (A list of numbers that happens to be nine digits in groups, such as three 3-digit ports with
// spaces between them, is blocked too; the person can rephrase.)
func findIDNumbers(s string) []span {
	s = blankIPs(s) // an IP literal is never part of an ID number's digit run (D-205); blanked byte for byte, offsets are unchanged
	var out []span
	for i := 0; i < len(s); {
		if !isDigitByte(s[i]) {
			i++
			continue
		}
		start, end, digits := i, i, 0
		groups, allDots := 0, true
		maxGroup, minGroup := 0, math.MaxInt
		for j := i; j < len(s) && isDigitByte(s[j]); {
			k := j
			for k < len(s) && isDigitByte(s[k]) {
				k++
			}
			g := k - j
			groups++
			digits += g
			maxGroup, minGroup = max(maxGroup, g), min(minGroup, g)
			end = k
			// A separator run of one to three characters followed by a digit continues the number.
			m := k
			for m < len(s) && m-k < 4 && isIDSep(s[m]) {
				m++
			}
			if m-k >= 1 && m-k <= 3 && m < len(s) && isDigitByte(s[m]) {
				for _, c := range []byte(s[k:m]) {
					if c != '.' {
						allDots = false
					}
				}
				j = m
				continue
			}
			break
		}
		i = end
		if digits != 9 && digits != 12 {
			continue
		}
		if groups > 1 && (minGroup < 3 || (allDots && groups == 4 && maxGroup <= 3 && isIPv4(s[start:end]))) {
			continue
		}
		if cveBefore(s, start) {
			continue
		}
		out = append(out, span{start, end})
	}
	return dropInside(out, findPhones(s)) // findPhones blanks the addresses again: a no-op on the blanked text
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n := 0
		for _, c := range []byte(p) {
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

func isPhoneSep(b byte) bool {
	return isIDSep(b) || b == '(' || b == ')'
}

// phoneReps consumes repetitions of (separator{0,3} digit) from pos and returns the end offset after each count
// lo..hi; ends[k-lo] is -1 when fewer than k repetitions exist.
func phoneReps(s string, pos, lo, hi int) []int {
	ends := make([]int, 0, hi-lo+1)
	for k := 1; k <= hi; k++ {
		q, n := pos, 0
		for q < len(s) && n < 3 && isPhoneSep(s[q]) {
			q++
			n++
		}
		if q >= len(s) || !isDigitByte(s[q]) {
			for len(ends) < hi-lo+1 {
				ends = append(ends, -1)
			}
			return ends
		}
		pos = q + 1
		if k >= lo {
			ends = append(ends, pos)
		}
	}
	return ends
}

// bestEnd picks the largest count whose next byte is not a digit.
func bestEnd(s string, ends []int) int {
	for k := len(ends) - 1; k >= 0; k-- {
		if e := ends[k]; e >= 0 && (e == len(s) || !isDigitByte(s[e])) {
			return e
		}
	}
	return -1
}

// phoneAt tries the phone shapes at i, with optional parentheses around the country part:
//
//	A: (+84) | (84) | +84 | 84 | 0, then 8-10 more digits   Vietnamese numbers
//	B: (+d{1,3}) | +d{1,3}, then 7-12 more digits           other international numbers
//
// Digits may be separated by up to three spaces, dots or dashes. A must not follow a word character or a dot.
func phoneAt(s string, i int) int {
	open := 0
	if s[i] == '(' {
		open = 1
	}
	j := i + open
	if j >= len(s) {
		return -1
	}
	closeParen := func(p int) int {
		if open == 1 && p < len(s) && s[p] == ')' {
			return p + 1
		}
		return p
	}
	if i == 0 || (!isWordByte(s[i-1]) && s[i-1] != '.') {
		for _, prefix := range []string{"+84", "84", "0"} {
			if strings.HasPrefix(s[j:], prefix) {
				if e := bestEnd(s, phoneReps(s, closeParen(j+len(prefix)), 8, 10)); e >= 0 {
					return e
				}
			}
		}
	}
	if s[j] == '+' {
		for d := 3; d >= 1; d-- {
			if j+d < len(s) && allDigits(s[j+1:j+1+d]) {
				if e := bestEnd(s, phoneReps(s, closeParen(j+1+d), 7, 12)); e >= 0 {
					return e
				}
			}
		}
	}
	return -1
}

func allDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := range len(s) {
		if !isDigitByte(s[i]) {
			return false
		}
	}
	return true
}

// findPhones finds phone numbers. An IP address literal (IPv4 or IPv6) is not a phone number (D-205): the finder reads the
// text with each valid address blanked out (same length, so offsets are unchanged), so it never matches inside or across one,
// and a number written next to an address is still found. After a match the search goes on one byte past its start, so a
// number that begins inside an earlier, longer candidate (the "01" of NAS-01 before "(0912 345 678)") is masked too: spans may
// overlap and maskSpans merges them (when in doubt, mask).
func findPhones(s string) []span {
	s = blankIPs(s)
	var out []span
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '+' || c == '(' || isDigitByte(c) {
			if e := phoneAt(s, i); e > i {
				out = append(out, span{i, e})
			}
		}
	}
	return out
}

var (
	ipv4RE = regexp.MustCompile(`[0-9]{1,3}(?:\.[0-9]{1,3}){3}`)
	hexRE  = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*`)
)

// blankIPs returns s with every valid IPv4 and IPv6 literal replaced, byte for byte, by '#'. IPv4 candidates are four dotted
// groups of up to three digits that are not part of a longer digit run; IPv6 candidates are runs of hex digits, colons and dots
// that hold a colon (so ::ffff:1.2.3.4 is one), tried whole and then with trailing and a single leading ':' or '.' trimmed.
// netip decides what is valid; a candidate it rejects is left alone.
func blankIPs(s string) string {
	if !strings.ContainsAny(s, ".:") {
		return s
	}
	var b []byte
	blank := func(a, z int) {
		if b == nil {
			b = []byte(s)
		}
		for k := a; k < z; k++ {
			b[k] = '#'
		}
	}
	for _, m := range ipv4RE.FindAllStringIndex(s, -1) {
		if (m[0] > 0 && isDigitByte(s[m[0]-1])) || (m[1] < len(s) && isDigitByte(s[m[1]])) {
			continue
		}
		if _, err := netip.ParseAddr(s[m[0]:m[1]]); err == nil {
			blank(m[0], m[1])
		}
	}
	for _, m := range hexRE.FindAllStringIndex(s, -1) {
		a, z := m[0], m[1]
		for try := 0; try < 2 && a < z; try++ {
			for e := z; e > a; e-- {
				if addr, err := netip.ParseAddr(s[a:e]); err == nil && addr.Is6() {
					blank(a, e)
					break
				}
				if c := s[e-1]; c != ':' && c != '.' {
					break // only trailing ':' and '.' are trimmed
				}
			}
			if s[a] != ':' || (a+1 < z && s[a+1] == ':') {
				break
			}
			a++
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

// cveBefore reports whether the digits at start are the tail of a CVE identifier (CVE-2024-12345), which is public
// data and often has nine digits.
func cveBefore(s string, start int) bool {
	return start >= 4 && strings.EqualFold(s[start-4:start], "cve-")
}

// dropInside removes the spans that lie wholly inside one of the guards. A nine-digit group that is the tail of a
// phone number with a country prefix (+84 912 345 678) is a phone number, not an identity number.
func dropInside(spans, guards []span) []span {
	var out []span
	for _, sp := range spans {
		inside := false
		for _, g := range guards {
			inside = inside || (sp.start >= g.start && sp.end <= g.end)
		}
		if !inside {
			out = append(out, sp)
		}
	}
	return out
}
