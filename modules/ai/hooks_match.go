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
	case r >= 0x2010 && r <= 0x2015, r == 0x2212, r == 0xFE58, r == 0xFE63:
		return '-', true // hyphens, en and em dashes, minus signs
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
	return plainCtx(func(_ context.Context, norm string) ([]span, error) { return find(norm), nil })
}

// plainCtx is plain for a finder that checks the context itself between its steps, so a deadline holds inside it.
func plainCtx(find func(ctx context.Context, norm string) ([]span, error)) func(context.Context, *scanText) ([]span, error) {
	return func(ctx context.Context, t *scanText) ([]span, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		found, err := find(ctx, t.normalized())
		if err != nil {
			return nil, err
		}
		var out []span
		for _, sp := range found {
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
// three or more digits joined by up to three separator characters (idRuns), such as 0790.1234.5678, 123 456 789,
// 079-012-345-678 or 079/012/345/678. IP address literals are blanked first (blankIPs), so they are left alone and never join a
// digit run. Versions, builds, update numbers, advisory ids, CPE names, digests and port lists are blanked by their context next
// (notIDForms), so they are not read and do not join the number beside them. A number next to an ID number does not hide it: the
// words of a run are read on their own too (idRuns). (A list of numbers that happens to be nine digits in groups without such a
// context is blocked; the person can rephrase.)
func findIDNumbers(s string) []span {
	// A number written after an ID label (CCCD 079201234567, CMND:123456789, passport C1234567) is an ID number whatever it sits in
	// or next to: a link, a hash, letters. Read first, from the text as it is, so no blanking below can hide it.
	labelled := labelledIDs(blankUUIDs(blankIPs(s, false, false)))
	// The forms the box's own data is full of (a CVE id, a record id, a timestamp, a link, a hash) are blanked next: a digit run inside
	// them is part of that form, not an ID number (beta 0.1.0-beta.1, item 19: a tool result was held back as "an ID number").
	s = blankForms(s)
	// Two readings, and an ID in either is an ID: one with every address blanked (an address is never part of a digit run), and one
	// that keeps the addresses whose first or last group is only digits touching other digits (123 456 789::1, ::123 456 789: the
	// group may be the ID's own).
	out := append(idRuns(blankIPs(s, false, false)), idRuns(blankIPs(s, false, true))...)
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	out = append(dropInside(out, findPhones(s)), labelled...)
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	return out
}

// The labels that say the number after them is a person's ID, with or without diacritics. A strong label (citizen ID, old ID card,
// personal identification number, passport) never stands before a hash or a part number, so its number is read even glued to letters
// on either side (CMND AS201234567, CCCD deadbeef079201234567, CMND 123456789abcdef0). The weak label "ID" does stand before record
// ids and hashes: its number must end at a boundary. Only a whole word is a label ("asset_id", "android" are not). Up to four
// separator characters (spaces, : . # = _ quotes / @ -) and an optional "số"/"no." may stand between a label and its number.
const (
	strongIDLabels = `cccd|cmnd|căn cước(?: công dân)?|can cuoc(?: cong dan)?|chứng minh(?: nhân dân| thư)?|chung minh(?: nhan dan| thu)?|số định danh(?: cá nhân)?|so dinh danh(?: ca nhan)?|passport|hộ chiếu|ho chieu`
	labelLead      = `(?i)(?:^|[^\p{L}\p{N}_])`
	labelSep       = `(?:[\s:.#=_"'/@\-]{0,4}(?:số|so|no\.?|number)?)?[\s:.#=_"'/@\-]{0,4}`
	idDigits       = `(\d+(?:[ .\-]{1,3}\d+)*)`
	wordEnd        = `(?:$|[^\p{L}\p{N}_])`
)

var (
	strongIDRE = regexp.MustCompile(labelLead + `(?:` + strongIDLabels + `)` + labelSep + `[A-Za-z]{0,16}` + idDigits)
	weakIDRE   = regexp.MustCompile(labelLead + `id` + labelSep + idDigits + wordEnd)
	// passportRE: a Vietnamese passport number (one letter and seven digits, C1234567) right after a passport label. Without the label
	// the shape is too common (model numbers, part numbers) to block.
	passportRE = regexp.MustCompile(labelLead + `(?:passport|hộ chiếu|ho chieu)` + labelSep + `([A-Za-z]\d{7})` + wordEnd)
	uuidRE     = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
)

// labelledIDs finds the ID numbers written after a label: 9 or 12 digits in all, in one group or in groups of three or more (the rule
// of idRuns: build id 10.0.19045.3693 is a version, not an ID), and a passport number after a passport label. The caller blanks
// addresses and UUIDs first: a record id after "Request ID" is not a person's ID.
func labelledIDs(s string) []span {
	var out []span
	for _, re := range []*regexp.Regexp{strongIDRE, weakIDRE} {
		for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
			if e := idShapedWords(s[m[2]:m[3]]); e > 0 {
				out = append(out, span{m[2], m[2] + e})
			}
		}
	}
	return append(out, findAll(passportRE, s, 1)...)
}

// idShapedWords returns the end of the ID number at the start of run, or 0: the whole run when it is ID-shaped, or else the first
// words of it (up to white space) that are (CMND AS201234567 5: a number after the ID does not hide it).
func idShapedWords(run string) int {
	if idShaped(run) {
		return len(run)
	}
	for i := 0; i < len(run); i++ {
		if isSpaceByte(run[i]) && i > 0 && isDigitByte(run[i-1]) && idShaped(run[:i]) {
			return i
		}
	}
	return 0
}

// idShaped reports whether a run of digit groups is ID-shaped: 9 or 12 digits, and every group of three or more when there are several.
func idShaped(run string) bool {
	digits, groups, minGroup, g := 0, 0, math.MaxInt, 0
	for i := 0; i <= len(run); i++ {
		if i < len(run) && isDigitByte(run[i]) {
			g++
			continue
		}
		if g > 0 {
			digits, groups, minGroup = digits+g, groups+1, min(minGroup, g)
			g = 0
		}
	}
	return (digits == 9 || digits == 12) && (groups == 1 || minGroup >= 3)
}

// blankUUIDs replaces every UUID with letters, keeping offsets.
func blankUUIDs(s string) string {
	return uuidRE.ReplaceAllStringFunc(s, func(m string) string { return strings.Repeat("x", len(m)) })
}

// notIDForms are the written forms whose digits are never an ID number. Each match is blanked (blankForms) before the digit runs are
// read; a number after an ID label is found before that (labelledIDs). An all-digit dotted 0790.1234.5678 stays ID-shaped (a Cisco
// MAC address in that form has a letter in nearly every case, and then it is blanked), and so does a bare 2023-36844: only an
// advisory id written with a known prefix (CVE-, ELSA-, GHSA-…) is blanked. Each form is anchored on its own context (a prefix, a
// keyword, a fixed shape) and leaves out the shapes ID numbers are written in (a first group that starts with 0, groups of three
// digits), so the same digits standing on their own are still read. A blanked form also never joins the number next to it into
// one long run, so an ID number written right after a build or an update number is found.
var notIDForms = []*regexp.Regexp{
	linkRE, // a link: its scheme, host and path segments (blankLink); never userinfo, a query, a fragment or an ID-shaped segment
	uuidRE, // a UUID
	regexp.MustCompile(`\b[a-z][a-z0-9]{0,31}-[a-z2-7]{26}\b`), // a record id of this box (store.NewID: dev-…, fnd-…)
	cveFormRE,
	advisoryRE,
	ghsaRE,
	regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?\b`), // a date or a timestamp
	cpeRE,
	digestRE,
	hexRE,                                  // a hash or a long hex id (with a letter a-f; not one that starts with "cccd")
	ciscoMAC,                               // a Cisco MAC address (kept when all digits: see above)
	regexp.MustCompile(`\bASN?\d{1,10}\b`), // an autonomous system number written as one word (AS13335, ASN401234567)
	kbRE,
	versionFormRE,
	buildRE,
	androidBuildRE,
	portListRE,
}

var (
	linkRE   = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s"'<>\\?#,;]+`)
	hexRE    = regexp.MustCompile(`(?i)\b[0-9a-f]{16,}\b`)
	ciscoMAC = regexp.MustCompile(`(?i)\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b`)
	// cveFormRE: a CVE id, also written with a space, an underscore, a colon or nothing after "CVE" (CVE 2024-12345, CVE2024-12345).
	cveFormRE = regexp.MustCompile(`(?i)\bcve[-_: ]?(?:19|20)\d{2}-\d{4,7}\b`)
	// advisoryRE: an advisory id of the shape PREFIX-YEAR-NUMBER from a known source (ELSA-2024-12345, CNVD-2024-12345,
	// EUVD-2025-14498, BDU:2024-01234, MAL-2024-12345, NTAP-20240621-0002, BIT-nginx-2024-12345). The prefix is one of the
	// advisory sources, written as they write it, and glued to a year (19xx or 20xx, optionally with month and day) by "-" or ":";
	// another word or abbreviation before a bare 2012-34567 does not make it an advisory.
	advisoryRE = regexp.MustCompile(`\b(?:` + advisoryPrefixes + `)[-:](?:19|20)\d{2}(?:\d{2}){0,2}[-:]\d{1,7}\b`)
	// ghsaRE: a GitHub advisory id: three groups of four characters from its own alphabet, which has digits 2-9 (GHSA-2345-6789-2345).
	ghsaRE = regexp.MustCompile(`(?i)\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b`)
	// cpeRE: the part of a CPE name that names the product: the part, the vendor and the product, up to the version
	// (cpe:2.3:o:microsoft:windows_11_24h2, cpe:/o:juniper:junos). The version and the later fields are read like any other text, and
	// the match stops at the first character a CPE field does not have.
	cpeRE = regexp.MustCompile(`(?i)\bcpe:(?:2\.3:[aho*-]|/[aho]):` + cpeField + `:` + cpeField)
	// digestRE: a base64 or hex digest written after its algorithm (sha384-<base64> as in a subresource integrity value,
	// sha256:<hex>). keepForm keeps a match without a letter or with a run of nine or more digits: a digest has neither, in practice.
	digestRE = regexp.MustCompile(`(?i)\b(?:sha(?:1|224|256|384|512)|sha3-(?:224|256|384|512)|md5|blake2[bs]?|blake3)[-:=][a-z0-9+/]{20,}={0,2}`)
	// kbRE: a Microsoft update number (KB5034441, KB 5034441): six or seven digits after a capital "KB", never with a leading zero.
	kbRE = regexp.MustCompile(`\bKB ?[1-9]\d{5,6}\b`)
	// versionFormRE: a dotted number right after a version word or a "v" glued to it (version 2024.003.20180, v7.2.13). Only the
	// dotted number is taken: a number after it, with a space between, is read on its own. Its first group never starts with 0, and
	// keepForm keeps three or four groups of exactly three digits (123.456.789): that is how ID numbers are written, not versions.
	versionFormRE = regexp.MustCompile(`(?i)(?:\b(?:version|ver|build|release|firmware|kernel|revision|rev)\.?[ \t]*[:#=]?[ \t]*v?|\bv)(?:0|[1-9]\d*)(?:\.\d+)+\b`)
	// buildRE: a bare build number: a Windows build and its revision (26100.1742, 7601.24546: a first group of four or five digits
	// that does not start with 0), or a date-stamped version (20260129.1928). keepForm keeps a match with a digit, or a dot and a
	// digit, on either side: then it is part of a longer dotted number (10.0.26100.1742 is read whole).
	buildRE = regexp.MustCompile(`[1-9]\d{3,4}\.\d{1,5}|(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\.\d{1,6}`)
	// androidBuildRE: an Android build id (UP1A.231005.007, AP2A.240905.003): a four-character branch code, a six-digit date and a
	// three-digit number.
	androidBuildRE = regexp.MustCompile(`\b[A-Z]{2}[A-Z0-9]{2}\.\d{6}\.\d{3}\b`)
	// portListRE: a list of port numbers after "port", "ports" or "cổng" (ports 8080 8443 9443, port 3389 8443/tcp). A port is
	// written without a leading zero, so a citizen ID number (it starts with 0) never joins the list; keepForm also keeps a list
	// with a number above 65535 or with three 3-digit numbers in a row (271 234 567 is how a 9-digit ID number is written).
	portListRE = regexp.MustCompile(`(?i)(?:\bports?|\bcổng)[ \t]*[:=]?[ \t]*` + portNum + `(?:[ \t]*(?:,|and|or|&)?[ \t]*` + portNum + `)*`)
)

const (
	portNum = `[1-9]\d{0,4}\b(?:/(?:tcp|udp)\b)?`
	// cpeField is one field of a CPE name: letters, digits, . _ ~ % - and a character escaped with a backslash.
	cpeField = `(?:[a-z0-9._~%-]|\\[^\s])*`
	// advisoryPrefixes are the advisory sources whose ids are PREFIX-YEAR-NUMBER: Linux distributions (Oracle, Alma, Rocky, Red Hat,
	// CentOS, Debian, Ubuntu, SUSE, Amazon, Mageia, Fedora), national databases (China CNVD/CNNVD, EU EUVD, Russia BDU, Japan JVNDB,
	// Germany WID-SEC), package databases (OSV, PyPI, RustSec, Go, GSD, OpenSSF malicious packages, Bitnami), and vendors (NetApp, Talos,
	// ZDI, Tenable, VDE).
	advisoryPrefixes = `ELSA|ALSA|RLSA|RHSA|RHBA|RHEA|CESA|DSA|DLA|USN|SUSE-SU|openSUSE-SU|ALAS2023|ALAS2|ALAS|MGASA|FEDORA|` +
		`CNVD|CNNVD|EUVD|BDU|JVNDB|WID-SEC|OSV|PYSEC|RUSTSEC|GO|GSD|MAL|BIT(?:-[A-Za-z0-9]+){0,3}|NTAP|TALOS|ZDI|TRA|VDE`
)

// keepForm reports whether a match s[a:z] of a form must not be blanked: a hex run or a Cisco MAC with no letter a-f is only digits,
// a hex run that starts with the label "cccd" is a label glued to its number (CCCD079201234567), a digest with no letter or with nine
// digits in a row is not a digest, a version written in groups of three digits or a port list that is not only ports has the shape
// of an ID number, and a bare build with digits next to it is part of a longer number.
func keepForm(re *regexp.Regexp, s string, a, z int) bool {
	m := s[a:z]
	switch re {
	case hexRE:
		return !hasHexLetter(m) || strings.HasPrefix(strings.ToLower(m), "cccd")
	case ciscoMAC:
		return !hasHexLetter(m)
	case digestRE:
		body := m[strings.IndexAny(m, "-:=")+1:]
		return strings.IndexFunc(body, unicode.IsLetter) < 0 || longestDigits(body) >= 9
	case versionFormRE:
		return threeDigitGroups(m)
	case buildRE:
		return (a > 0 && (isDigitByte(s[a-1]) || (s[a-1] == '.' && a >= 2 && isDigitByte(s[a-2])))) ||
			(z < len(s) && (isDigitByte(s[z]) || (s[z] == '.' && z+1 < len(s) && isDigitByte(s[z+1]))))
	case portListRE: // a list cut short by a group that is not a port is part of a longer number (port 271 034 567)
		return !allPorts(m) || digitAfterIDSeps(s, z)
	}
	return false
}

// digitAfterIDSeps reports whether one to three ID separators and then a digit follow position e.
func digitAfterIDSeps(s string, e int) bool {
	k := e
	for k < len(s) && k-e < 3 && isIDGroupSep(s[k]) {
		k++
	}
	return k > e && k < len(s) && isDigitByte(s[k])
}

// longestDigits is the length of the longest run of digits in s.
func longestDigits(s string) int {
	best, n := 0, 0
	for i := range len(s) {
		if isDigitByte(s[i]) {
			n++
			best = max(best, n)
		} else {
			n = 0
		}
	}
	return best
}

// threeDigitGroups reports whether the dotted number that ends m is three or four groups of exactly three digits (123.456.789).
func threeDigitGroups(m string) bool {
	k := len(m)
	for k > 0 && (isDigitByte(m[k-1]) || m[k-1] == '.') {
		k--
	}
	groups := strings.Split(m[k:], ".")
	if len(groups) != 3 && len(groups) != 4 {
		return false
	}
	for _, g := range groups {
		if len(g) != 3 {
			return false
		}
	}
	return true
}

// allPorts reports whether every digit run of s is a port number (1-65535) and no three runs in a row have three digits each.
func allPorts(s string) bool {
	three := 0
	for i := 0; i < len(s); {
		if !isDigitByte(s[i]) {
			i++
			continue
		}
		n, j := 0, i
		for j < len(s) && isDigitByte(s[j]) {
			if n = n*10 + int(s[j]-'0'); n > 65535 {
				return false
			}
			j++
		}
		if three = three + 1; j-i != 3 {
			three = 0
		}
		if three == 3 {
			return false
		}
		i = j
	}
	return true
}

// blankLink blanks the parts of a link (linkRE) whose digits are never a person's ID: the scheme, the host and every path segment
// except one that is only 9 or 12 digits (https://x.vn/u/079201234567 names a person). Userinfo is kept (http://u:079201234567@h/),
// and linkRE already stops before a query or a fragment. b is the text being blanked; m the bounds of the match.
func blankLink(b []byte, s string, m []int) {
	link := s[m[0]:m[1]]
	rest := strings.Index(link, "://") + 3
	authEnd := len(link)
	if k := strings.IndexByte(link[rest:], '/'); k >= 0 {
		authEnd = rest + k
	}
	host := rest
	if k := strings.LastIndexByte(link[rest:authEnd], '@'); k >= 0 {
		host = rest + k + 1 // userinfo stays as it is
	}
	fill := func(a, z int) {
		for k := m[0] + a; k < m[0]+z; k++ {
			b[k] = 'x'
		}
	}
	fill(0, rest-3) // the scheme; "://" stays: it never joins digits
	fill(host, authEnd)
	for i := authEnd; i < len(link); {
		j := i + 1
		for j < len(link) && link[j] != '/' {
			j++
		}
		if seg := link[i+1 : j]; !allDigits(seg) || (len(seg) != 9 && len(seg) != 12) {
			fill(i+1, j)
		}
		i = j
	}
}

func hasHexLetter(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') }) >= 0
}

// formNeeds holds, for the forms that have one, the words (in lower case) of which a match holds at least one. A form runs only on
// a text that has one of them, so a long text pays only for the forms it can hold.
var formNeeds = map[*regexp.Regexp][]string{
	linkRE:         {"://"},
	cveFormRE:      {"cve"},
	advisoryRE:     strings.Split(strings.ToLower(strings.NewReplacer("(?:-[A-Za-z0-9]+){0,3}", "", "SUSE-SU", "suse").Replace(advisoryPrefixes)), "|"),
	ghsaRE:         {"ghsa"},
	cpeRE:          {"cpe:"},
	digestRE:       {"sha", "md5", "blake"},
	ciscoMAC:       {"."},
	kbRE:           {"kb"},
	versionFormRE:  {"."},
	buildRE:        {"."},
	androidBuildRE: {"."},
	portListRE:     {"port", "cổng"},
}

func formMayMatch(re *regexp.Regexp, lower string) bool {
	need, ok := formNeeds[re]
	if !ok {
		return true
	}
	for _, w := range need {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// blankForms replaces every match of notIDForms with letters, so offsets stay and a blanked form never joins a digit run.
func blankForms(s string) string {
	var b []byte
	lower := strings.ToLower(s)
	for _, re := range notIDForms {
		if !formMayMatch(re, lower) {
			continue
		}
		for _, m := range re.FindAllStringIndex(s, -1) {
			if keepForm(re, s, m[0], m[1]) {
				continue
			}
			if b == nil {
				b = []byte(s)
			}
			if re == linkRE {
				blankLink(b, s, m)
				continue
			}
			for k := m[0]; k < m[1]; k++ {
				b[k] = 'x'
			}
		}
		if b != nil {
			s = string(b)
			b = nil
		}
	}
	return s
}

// isIDGroupSep reports whether b may stand between the digit groups of an ID number: the separators of isIDSep and also / and _
// (079/201/234/567, 079_201_234_567). A dash of any kind is folded to '-' by the normalisation.
func isIDGroupSep(b byte) bool { return isIDSep(b) || b == '/' || b == '_' }

func isSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f' || b == '\v'
}

// digitGroup is one unbroken group of digits of a run; word reports that the separator before it ends a word (it holds white space
// or is a comma).
type digitGroup struct {
	start, end int
	word       bool
}

// idRuns finds the ID-shaped digit runs of s. A run is digit groups joined by one to three separators (isIDGroupSep); a comma joins
// groups only in a run that starts with 0 and only on its own (079,201,234,567), because counts written with thousands separators
// (123,456,789 lines) never start with 0. A run is an ID number when it holds 9 or 12 digits in one group or in groups of three or
// more. When the whole run is not, a word of it (the groups between white space or commas) can be, and so can a stretch of words
// whose groups all have three digits or more: the number next to an ID never hides it (Windows 11 079201234567, 079201234567 2,
// room 5 079 201 234 567). Groups joined by a dot stay one word, so a decimal or a version (1.123456789, v2.079123456789) is not cut.
func idRuns(s string) []span {
	var out []span
	var gs []digitGroup
	for i := 0; i < len(s); {
		if !isDigitByte(s[i]) {
			i++
			continue
		}
		gs = gs[:0]
		comma := s[i] == '0'
		word := false
		for j := i; ; {
			k := j
			for k < len(s) && isDigitByte(s[k]) {
				k++
			}
			gs = append(gs, digitGroup{j, k, word})
			if comma && k+1 < len(s) && s[k] == ',' && isDigitByte(s[k+1]) {
				j, word = k+1, true
				continue
			}
			// A separator run of one to three characters followed by a digit continues the number.
			m := k
			word = false
			for m < len(s) && m-k < 4 && isIDGroupSep(s[m]) {
				word = word || isSpaceByte(s[m])
				m++
			}
			if m-k >= 1 && m-k <= 3 && m < len(s) && isDigitByte(s[m]) {
				j = m
				continue
			}
			break
		}
		i = gs[len(gs)-1].end
		out = appendIDRuns(out, s, gs)
	}
	return dropInside(out, findPhones(s))
}

// appendIDRuns adds the ID numbers of one run (see idRuns): the whole run, or else each word and each stretch of words whose groups
// all have three digits or more. Each group is in at most two parts tested, so the work is linear.
func appendIDRuns(out []span, s string, gs []digitGroup) []span {
	try := func(part []digitGroup) bool {
		if idGroups(s, part) {
			out = append(out, span{part[0].start, part[len(part)-1].end})
			return true
		}
		return false
	}
	if try(gs) {
		return out
	}
	stretch := -1 // the first group of the current stretch of long words
	for a := 0; a < len(gs); {
		b := a + 1
		for b < len(gs) && !gs[b].word {
			b++
		}
		long := true
		for _, g := range gs[a:b] {
			long = long && g.end-g.start >= 3
		}
		if b-a < len(gs) {
			try(gs[a:b])
		}
		switch {
		case long && stretch < 0:
			stretch = a
		case !long && stretch >= 0:
			try(gs[stretch:a])
			stretch = -1
		}
		a = b
	}
	if stretch > 0 { // a stretch from the first group to the end is the whole run, tested above
		try(gs[stretch:])
	}
	// A citizen ID number starts with 0 (its province code): inside a run, the groups from the start of a word with a leading 0 that
	// add up to 9 or 12 digits, each of three or more, are an ID number, whatever comes before or after them (port 8443 079 201 234 567,
	// 079 201 234 567 1234). At most four such groups are read from each start.
	for a := 0; a < len(gs); a++ {
		if (a > 0 && !gs[a].word) || s[gs[a].start] != '0' {
			continue
		}
		digits := 0
		for b := a; b < len(gs) && b < a+4; b++ {
			n := gs[b].end - gs[b].start
			if n < 3 && b > a {
				break
			}
			if digits += n; (digits == 9 || digits == 12) && b > a {
				try(gs[a : b+1])
			}
		}
	}
	return out
}

// idGroups reports whether the groups hold 9 or 12 digits, in one group or in groups of three or more, and are not the tail of a CVE id.
func idGroups(s string, gs []digitGroup) bool {
	digits, minGroup := 0, math.MaxInt
	for _, g := range gs {
		digits += g.end - g.start
		minGroup = min(minGroup, g.end-g.start)
	}
	return (digits == 9 || digits == 12) && (len(gs) == 1 || minGroup >= 3) && !cveBefore(s, gs[0].start)
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

// findPhones finds phone numbers. An IP address literal (IPv4 or IPv6) that stands alone is not a phone number: the
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

// blankIPs returns s with every IPv4 and IPv6 literal that stands alone replaced, byte for byte, by 'x'; netip decides what
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
			b[k] = 'x' // a letter: a filled address never reads as a separator between digits (R3 L-1)
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
	if g == e || g == a || !isDigitByte(s[e-1]) { // any digit run at the edge, also one glued to hex letters (R3 M-1)
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
	if g == a || g == e { // R3 M-1
		return false
	}
	k, n := a, 0
	for k > 0 && n < 3 && isPhoneSep(s[k-1]) {
		k--
		n++
	}
	return n > 0 && k > 0 && isDigitByte(s[k-1])
}
