package ai

import (
	"context"
	"errors"
	"io"
	"math"
	"net/netip"
	"regexp"
	"regexp/syntax"
	"sort"
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
// 123 456 789 or 079 012 345 678. A digit run longer than that is not an ID number. IP address literals are blanked
// first (blankIPs), so they are left alone and never join a digit run; dotted digits that are not an address are ID-shaped. (A list of numbers that happens to be nine digits in groups, such as three 3-digit ports with
// spaces between them, is blocked too; the person can rephrase.)
func findIDNumbers(s string) []span {
	// Two readings, and an ID in either is an ID: one with every address blanked (an address is never part of a digit run), and one
	// that keeps the addresses whose first or last group is only digits touching other digits (123 456 789::1, ::123 456 789: the
	// group may be the ID's own).
	out := append(idRuns(blankIPs(s, false, false)), idRuns(blankIPs(s, false, true))...)
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	return dropInside(out, findPhones(s))
}

func idRuns(s string) []span {
	var out []span
	for i := 0; i < len(s); {
		if !isDigitByte(s[i]) {
			i++
			continue
		}
		start, end, digits := i, i, 0
		groups := 0
		minGroup := math.MaxInt
		for j := i; j < len(s) && isDigitByte(s[j]); {
			k := j
			for k < len(s) && isDigitByte(s[k]) {
				k++
			}
			g := k - j
			groups++
			digits += g
			minGroup = min(minGroup, g)
			end = k
			// A separator run of one to three characters followed by a digit continues the number.
			m := k
			for m < len(s) && m-k < 4 && isIDSep(s[m]) {
				m++
			}
			if m-k >= 1 && m-k <= 3 && m < len(s) && isDigitByte(s[m]) {
				j = m
				continue
			}
			break
		}
		i = end
		if digits != 9 && digits != 12 {
			continue
		}
		if groups > 1 && minGroup < 3 {
			continue
		}
		if cveBefore(s, start) {
			continue
		}
		out = append(out, span{start, end})
	}
	return dropInside(out, findPhones(s))
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

// findPhones finds phone numbers. An IP address literal (IPv4 or IPv6) that stands alone is not a phone number (D-205): the
// finder reads the text with each such address blanked out (same length, so offsets are unchanged), so it never matches inside
// or across one, and a number written next to an address is still found. After a match the search goes on one byte past its
// start, so a number that begins inside an earlier, longer candidate (the "01" of NAS-01 before "(0912 345 678)") is masked
// too: spans overlap and maskSpans merges them (when in doubt, mask). Time is linear: at most ten digits are read at each byte.
func findPhones(s string) []span {
	s = blankIPs(s, true, true)
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

var ipv4RE = regexp.MustCompile(`[0-9]{1,3}(?:\.[0-9]{1,3}){3}`)

const (
	maxIPv6 = 45 // the longest IPv6 literal netip accepts without a zone ("0000:...:0000" with an embedded IPv4)
	maxLead = 32 // how far back a country code is looked for before an IPv4 candidate
)

func isAddrByte(c byte) bool {
	return c == ':' || c == '.' || isDigitByte(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// phoneBefore (bare: also the prefixes without a plus; only the phone finder asks for these) reports whether a country code or trunk prefix (+cc, or digits that start with 84 or 0) stands
// before s[a:], with only digits and up to
// phone separators in between: then the digits at a are the rest of a phone number, not an address ("+84 91.234.56.78").
func phoneBefore(s string, a int, bare bool) bool {
	k := a
	for k > 0 && a-k < maxLead && (isDigitByte(s[k-1]) || isPhoneSep(s[k-1])) {
		k--
	}
	if k > 0 && s[k-1] == '+' {
		return true
	}
	for i := k; i < a; { // each digit run of the window: "84" or "0" that is not glued to a word, or a code right after '+'
		if !isDigitByte(s[i]) {
			i++
			continue
		}
		e := i
		for e < a && isDigitByte(s[e]) {
			e++
		}
		run := s[i:e]
		if (i > 0 && s[i-1] == '+') || (bare && (strings.HasPrefix(run, "0") || strings.HasPrefix(run, "84"))) {
			return true
		}
		i = e
	}
	return false
}

// phoneInside reports whether an IPv4 candidate that starts with a phone prefix as its first group ("84.255.255.255", "84.32.175.88 25")
// is a phone number: the rest has the digits of one (8 or more), or more digits follow it.
func phoneInside(s string, a, z int) bool {
	dot := strings.IndexByte(s[a:z], '.')
	if first := s[a : a+dot]; first != "84" && first != "0" {
		return false
	}
	n := 0
	for _, c := range []byte(s[a+dot : z]) {
		if isDigitByte(c) {
			n++
		}
	}
	return n >= 8 || digitAfterSeps(s, z)
}

// digitAfterSeps reports whether one to three phone separators and then a digit follow position e.
func digitAfterSeps(s string, e int) bool {
	k, n := e, 0
	for k < len(s) && n < 3 && isPhoneSep(s[k]) {
		k++
		n++
	}
	return n > 0 && k < len(s) && isDigitByte(s[k])
}

// blankIPs returns s with every IPv4 and IPv6 literal that stands alone replaced, byte for byte, by '#'; netip decides what
// is valid. Fail closed: an IPv4 candidate inside a longer dotted chain (1.2.3.4.5), or after a country code, is left alone
// (a dotted phone number such as +84 91.234.56.78 is also a valid address, and must be masked); an IPv6 candidate glued to a
// word ("Tel::0912") is left alone, and, when phones is set, so is one whose last group is only digits and is followed by
// separators and more digits (2001:db8::0912 345 678: the digits are a phone number). The ID finder passes phones=false: it
// wants the whole address out of any digit run, so it keeps only the '+' and chain rules. IPv6 runs longer than an address are skipped without parsing, so the pass is
// linear.
func blankIPs(s string, phones, edges bool) string {
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
		a, z := m[0], m[1]
		if (a > 0 && isDigitByte(s[a-1])) || (z < len(s) && isDigitByte(s[z])) {
			continue
		}
		if (a >= 2 && s[a-1] == '.' && isDigitByte(s[a-2])) || (z+1 < len(s) && s[z] == '.' && isDigitByte(s[z+1])) || phoneBefore(s, a, phones) || (phones && phoneInside(s, a, z)) {
			continue
		}
		if _, err := netip.ParseAddr(s[a:z]); err == nil {
			blank(a, z)
		}
	}
	for i := 0; i < len(s); {
		if !isAddrByte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isAddrByte(s[j]) {
			j++
		}
		if j-i <= maxIPv6+4 {
			blankV6(s, i, j, edges, blank)
		}
		i = j
	}
	if b == nil {
		return s
	}
	return string(b)
}

// blankV6 tries the address-byte run s[a:z]: whole, then with up to three trailing ':' or '.' (a sentence's full stop) trimmed,
// then without one leading ':' (as in "ip:fe80::1"). At most five parses of at most 45 bytes each.
func blankV6(s string, a, z int, edges bool, blank func(a, z int)) {
	for try := 0; try < 2 && a < z; try++ {
		if a == 0 || !isWordByte(s[a-1]) {
			for e, trims := z, 0; e > a && trims <= 3 && e-a <= maxIPv6; e, trims = e-1, trims+1 {
				if addr, err := netip.ParseAddr(s[a:e]); err == nil && addr.Is6() && (e != z || z == len(s) || !isWordByte(s[z])) {
					if !edges || (!phoneFollows(s, a, e) && !phonePrecedes(s, a, e)) {
						blank(a, e)
					}
					return
				}
				if c := s[e-1]; c != ':' && c != '.' {
					break
				}
			}
		}
		if s[a] != ':' || (a+1 < z && s[a+1] == ':') {
			return
		}
		a++
	}
}

// phoneFollows reports whether the address s[a:e] ends in a group of digits only (or digits and dots) that is followed by up to three phone
// separators and another digit: the group may be the start of a phone number.
func phoneFollows(s string, a, e int) bool {
	g := e
	for g > a && (isDigitByte(s[g-1]) || s[g-1] == '.') { // the last group, or an IPv4 tail (::0.21.22.160 062)
		g--
	}
	if g == e || g == a || s[g-1] != ':' || !isDigitByte(s[e-1]) {
		return false
	}
	return digitAfterSeps(s, e)
}

// cveBefore reports whether the digits at start are the tail of a CVE identifier (CVE-2024-12345), which is public
// data and often has nine digits.
func cveBefore(s string, start int) bool {
	return start >= 4 && strings.EqualFold(s[start-4:start], "cve-")
}

// dropInside removes the spans that lie wholly inside one of the guards. A nine-digit group that is the tail of a
// phone number with a country prefix (+84 912 345 678) is a phone number, not an identity number.
func dropInside(spans, guards []span) []span {
	// Both lists are sorted by start, so one pass does it: a span lies inside a guard when the guard with the furthest end
	// among those that start at or before it reaches its end.
	var out []span
	g, reach := 0, -1
	for _, sp := range spans {
		for g < len(guards) && guards[g].start <= sp.start {
			reach = max(reach, guards[g].end)
			g++
		}
		if sp.end > reach {
			out = append(out, sp)
		}
	}
	return out
}

// phonePrecedes is phoneFollows turned around: the address s[a:e] starts with a group of digits only, and a digit and up to three
// phone separators come right before it (0912 345 678::1: the "678" is the number's, not the address's).
func phonePrecedes(s string, a, e int) bool {
	g := a
	for g < e && isDigitByte(s[g]) {
		g++
	}
	if g == a || g == e || s[g] != ':' {
		return false
	}
	k, n := a, 0
	for k > 0 && n < 3 && isPhoneSep(s[k-1]) {
		k--
		n++
	}
	return n > 0 && k > 0 && isDigitByte(s[k-1])
}
