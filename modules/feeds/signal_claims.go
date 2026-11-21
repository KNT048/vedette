package feeds

import (
	"html"
	"regexp"
	"slices"
	"strings"
)

// Exploitation claims in a vendor's own words. A clause claims exploitation when it holds one of a closed list of positive phrases,
// each tied to exploitation actually seen ("exploited in the wild", "active exploitation", "attempted exploitation", "aware of
// malicious use" …; never "could be exploited by", "exploit code is available" or "from being exploited"), and nothing in the clause
// up to the phrase's end takes it back: a negation ("not", "n't", "never", "no", "nor", "without" …), a condition ("if", "whether",
// "unless"), a possibility ("could be", "can allow" …) or a purpose ("to stop", "prevent"); nor does an answer right after it
// ("Exploited in the wild: No"). Sentences end at a line break or at a full stop, question or exclamation mark followed by a space;
// clauses at ";", "but", "however", "while", "whereas", "although", "except" and at "and" followed by a new subject or verb ("…of
// CVE-A and is not aware of … CVE-B"). The claim belongs to the CVE ids named in that clause; a clause that names none speaks of the
// vulnerability its section is about ("this vulnerability", "these vulnerabilities"), and the caller decides which CVEs that is
// (claimedCVEs). The rule was measured on a year of vendor advisories: a window of characters around the phrase instead of the
// clause picked up the CVE of the next entry or of a sentence saying the opposite.

// maxClaimText bounds the text one string contributes (bytes): advisory sections are a few kilobytes; the rest of a longer string is
// not read. maxClaimSentence bounds a sentence the phrases are looked for in (vendors' longest are a few hundred bytes): a longer
// "sentence" is not prose and is skipped, which bounds the work of the patterns on hostile text to the length of the text.
const (
	maxClaimText     = 64 << 10
	maxClaimSentence = 2 << 10
)

var (
	// exploitPhraseRE: the phrases vendors use for exploitation seen in the wild, and only those.
	exploitPhraseRE = regexp.MustCompile(`(?i)(exploited in the wild|exploitation in the wild|in[- ]the[- ]wild exploitation|` +
		`exploits? for [^.]{0,80}? exists? in the wild|actively (?:being )?exploited|actively exploiting|` +
		`(?:active|attempted|limited|targeted|ongoing|confirmed|successful|widespread) exploitation of|exploitation of [^.]{0,80}? in the wild|` +
		`(?:active|attempted|limited|targeted|ongoing|confirmed) exploitation|exploitation attempts|attempts to exploit|` +
		`under (?:limited,? )?(?:and )?(?:targeted )?exploitation|may have been exploited|known to (?:have been|be) exploited|` +
		`exploited (?:as|in) (?:a |an )?zero[- ]day|zero[- ]day exploitation|exploited in (?:targeted |limited |real[- ]world |active )?attacks|` +
		`aware of (?:the |any )?(?:malicious use|exploitation of))`)
	// claimNegationRE: in the clause up to the phrase's end, these take the claim back or make it a condition, a possibility or a
	// purpose.
	claimNegationRE = regexp.MustCompile(`(?i)(\b(?:not|never|no|nor|none|without|unaware|unlikely|if|whether|unless|cannot)\b|n't\b|` +
		`\bcan only be\b|\bto stop\b|\bprevent|\b(?:could|can|might|would|should)\s+(?:be|allow|enable|lead|result|permit)\b)`)
	// claimAnswerRE: right after the phrase, an answer that says no ("Exploited in the wild: No").
	claimAnswerRE = regexp.MustCompile(`(?i)^[^:=.;]{0,30}[:=]\s*(?:no|false|none|n/a|unknown)\b`)
	// claimClauseRE: where a sentence turns to another subject.
	claimClauseRE = regexp.MustCompile(`(?i)(;|,? but |,? however,? |,? whereas |,? while |,? although |,? except |` +
		`,? and (?:is|are|was|were|has|have|had|it|its|this|that|these|those|the|there|cisco|fortinet|microsoft|apple|google)\b)`)
	// claimCVERE: a CVE id inside text (bounded digits, as cvesOf).
	claimCVERE = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,12}\b`)
	// claimPluralRE: a clause about every vulnerability of its section ("these vulnerabilities"), unless it picks some of them
	// (claimSomeRE: "one of the vulnerabilities").
	claimPluralRE = regexp.MustCompile(`(?i)\b(these|the|both|all(?: of the)?|all the) (vulnerabilities|issues|flaws|cves)\b`)
	claimSomeRE   = regexp.MustCompile(`(?i)\b(one|some|any|either|neither|none|each|several|certain|many|few|two|three|which) of\s*$`)
)

// claimWords: every exploitation phrase holds one of them; a sentence without any is not matched against the patterns.
var claimWords = []string{"exploit", "malicious use"}

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
			if m == nil || claimNegationRE.MatchString(clause[:m[1]]) || claimAnswerRE.MatchString(clause[m[1]:]) {
				continue // up to the phrase's end: "is not aware of … exploitation"; after it: ": No"
			}
			c := textClaim{}
			if p := claimPluralRE.FindStringIndex(clause); p != nil && !claimSomeRE.MatchString(clause[:p[0]]) {
				c.Plural = true
			}
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
