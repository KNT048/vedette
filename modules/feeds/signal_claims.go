package feeds

import (
	"html"
	"regexp"
	"slices"
	"strings"
)

// Exploitation claims in a vendor's own words. A sentence claims exploitation when it holds an exploitation phrase ("exploited in the
// wild", "aware of attempted exploitation", "observed to be exploited" …) that no negation or condition in the same clause, up to the
// phrase's end, takes back ("not aware of", "no evidence", "if", "whether" …). The claim belongs to the CVE ids named in that same clause; a clause
// that names none speaks of the vulnerability its section is about ("this vulnerability", "these vulnerabilities"), and the caller
// decides which CVEs that is (claimedCVEs). The rule was measured on a year of vendor advisories: a window of characters around the
// phrase instead of the sentence picked up the CVE of the next entry or of a sentence saying the opposite.

// maxClaimText bounds the text one string contributes (bytes): advisory sections are a few kilobytes; the rest of a longer string is
// not read. maxClaimSentence bounds a sentence the phrases are looked for in (vendors' longest are a few hundred bytes): a longer
// "sentence" is not prose and is skipped, which bounds the work of the patterns on hostile text to the length of the text.
const (
	maxClaimText     = 64 << 10
	maxClaimSentence = 2 << 10
)

var (
	// exploitPhraseRE: the phrases vendors use for exploitation seen in the wild. Proof-of-concept code being available is not one.
	exploitPhraseRE = regexp.MustCompile(`(?i)(exploited in the wild|in[- ]the[- ]wild exploitation|exploits? for [^.]{0,80}? exists? in the wild|` +
		`actively exploited|active exploitation|under (?:limited,? )?(?:and )?(?:targeted )?exploitation|ha(?:s|ve) been exploited|` +
		`may have been exploited|being exploited|been observed exploit|aware of [^.]{0,100}?(?:exploitation|exploited|attacks? (?:that )?leverag|malicious use)|` +
		`observed [^.]{0,60}?exploit(?:ation|ed)|attempted exploitation|exploitation (?:attempts? )?(?:has|have) been (?:observed|detected|reported)|` +
		`exploited as a zero-day|exploited (?:by|in attacks))`)
	// claimNegationRE: before the phrase in its clause, these take the claim back or make it a condition.
	claimNegationRE = regexp.MustCompile(`(?i)(\bto stop\b|\bcan only be\b|\bif\b|\bwhether\b|\bnot aware\b|\bno (?:known|evidence|indication|reports?)\b|` +
		`\bnot (?:been|known|currently|observed|seen)\b|\bunaware\b|\bis not\b|\bare not\b|\bnor\b|\bwithout evidence\b|\bno public\b|\bno longer\b)`)
	// claimClauseRE: where a sentence turns to another subject ("…of CVE-A, but is aware of exploitation of CVE-B").
	claimClauseRE = regexp.MustCompile(`(?i)(;|,? but |,? however,? |,? whereas |,? while )`)
	// claimCVERE: a CVE id inside text (bounded digits, as cvesOf).
	claimCVERE = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,12}\b`)
	// claimPluralRE: a clause about every vulnerability of its section.
	claimPluralRE = regexp.MustCompile(`(?i)\b(these|the|both|all(?: of the)?|all the) (vulnerabilities|issues|flaws|cves)\b`)
)

// claimWords: every exploitation phrase holds one of them; a sentence without any is not matched against the patterns.
var claimWords = []string{"exploit", "malicious use", "leverag"}

// textClaim is one clause that claims exploitation: the CVE ids it names (upper case, in order, distinct) and whether it speaks of
// every vulnerability of its section ("these vulnerabilities").
type textClaim struct {
	CVEs   []string
	Plural bool
}

// exploitationClaims reads text (plain or HTML) sentence by sentence and returns its claiming clauses.
func exploitationClaims(text string) []textClaim {
	if len(text) > maxClaimText {
		text = text[:maxClaimText]
	}
	if strings.ContainsRune(text, '<') {
		text = stripTags(text)
	}
	if strings.ContainsRune(text, '&') {
		text = html.UnescapeString(text)
	}
	var out []textClaim
	for _, sentence := range claimSentences(text) {
		lower := strings.ToLower(sentence)
		if len(sentence) > maxClaimSentence || !slices.ContainsFunc(claimWords, func(w string) bool { return strings.Contains(lower, w) }) ||
			!exploitPhraseRE.MatchString(sentence) {
			continue
		}
		for _, clause := range claimClauseRE.Split(sentence, -1) {
			m := exploitPhraseRE.FindStringIndex(clause)
			if m == nil || claimNegationRE.MatchString(clause[:m[1]]) { // up to the phrase's end: "is not aware of … exploitation"
				continue
			}
			c := textClaim{Plural: claimPluralRE.MatchString(clause)}
			for _, id := range claimCVERE.FindAllString(clause, -1) {
				if id = strings.ToUpper(id); !slices.Contains(c.CVEs, id) {
					c.CVEs = append(c.CVEs, id)
				}
			}
			out = append(out, c)
		}
	}
	return out
}

// stripTags replaces each HTML tag (a "<" with a ">" within 500 bytes and no "<" between) by a line break, in one pass.
func stripTags(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	for i := 0; i < len(text); {
		if text[i] == '<' {
			if j := strings.IndexAny(text[i+1:min(len(text), i+502)], "<>"); j >= 0 && text[i+1+j] == '>' {
				b.WriteByte('\n')
				i += j + 2
				continue
			}
		}
		b.WriteByte(text[i])
		i++
	}
	return b.String()
}

// claimSentences splits text at line breaks and at a full stop, question or exclamation mark followed by a space or the end.
func claimSentences(text string) []string {
	var out []string
	start := 0
	for i := 0; i < len(text); i++ {
		switch c := text[i]; {
		case c == '\n' || c == '\r':
		case (c == '.' || c == '!' || c == '?') && (i+1 == len(text) || text[i+1] == ' ' || text[i+1] == '\t' || text[i+1] == '\n' || text[i+1] == '\r' || text[i+1] == 0xc2):
			// 0xc2: a no-break space (U+00A0) as vendors' HTML exports write it
		default:
			continue
		}
		if s := strings.TrimSpace(text[start:i]); s != "" {
			out = append(out, s)
		}
		start = i + 1
	}
	if s := strings.TrimSpace(text[start:]); s != "" {
		out = append(out, s)
	}
	return out
}

// claimedCVEs is the CVEs of scope (the CVEs the text's section is about, in order) that the text claims are exploited: those a
// claiming clause names, or, for a clause that names no CVE, the section's only CVE, or all of them when the clause speaks of every
// vulnerability. A clause that names only CVEs outside the scope (another advisory's) claims nothing here.
func claimedCVEs(text string, scope []string) []string {
	var out []string
	add := func(c string) {
		if slices.Contains(scope, c) && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	for _, c := range exploitationClaims(text) {
		switch {
		case len(c.CVEs) > 0:
			for _, id := range c.CVEs {
				add(id)
			}
		case len(scope) == 1 || c.Plural:
			for _, id := range scope {
				add(id)
			}
		}
	}
	return out
}
