package feeds

import (
	"context"
	"html"
	"regexp"
	"strings"
)

// Exploitation claims in a vendor's own words, read by templates, never guessed. Where a document has a structured field (a CSAF
// exploit_status threat, Microsoft's Exploited flag) that field decides. Otherwise each source has a closed list of the sentence
// forms its vendor writes (claimForm), taken from its real documents: a sentence about exploitation that matches a claiming form is
// a claim; one that matches a known form that claims nothing (a denial, proof-of-concept code, a precondition) is not; any other
// sentence that mentions exploitation is "unclassified": not a claim, and counted on the feed's log so new wording is noticed and
// added as a form, never interpreted. A question is never a claim.
//
// Sentences end at a line break or at a full stop, question or exclamation mark followed by a space. Each is put in canonical form
// before the forms are tried: lower case, spaces collapsed, link targets dropped (["https://…"]), each CVE id or list of CVE ids as
// {cve}, a leading "In March 2026," or "On November 5, 2025," as {when}, the final full stop dropped. A claiming form names its
// subject: the CVE ids written in the sentence, else every vulnerability of the section ("these vulnerabilities") or its only one
// ("this vulnerability": a section of several CVEs makes that sentence unclassified).

// maxClaimText bounds the text one string contributes (bytes); maxClaimSentence bounds a sentence (vendors' longest are a few
// hundred bytes): a longer one is not a vendor's sentence and is unclassified.
const (
	maxClaimText     = 64 << 10
	maxClaimSentence = 2 << 10
)

// claimForm is one sentence form of a vendor, as a pattern over the canonical sentence (whole sentence).
type claimForm struct {
	re   *regexp.Regexp
	kind formKind
	all  bool // without CVE ids it speaks of every vulnerability of its section; else of the section's only one
}

// formKind says what a sentence of a form states.
type formKind int

const (
	formClaim   formKind = iota // exploitation is known
	formDenial                  // the vendor knows of no exploitation: of the CVEs it names, or of the vulnerability it speaks of
	formNeutral                 // a known form that claims nothing (proof-of-concept code, a precondition)
)

func forms(kind formKind, all bool, patterns ...string) []claimForm {
	out := make([]claimForm, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, claimForm{re: regexp.MustCompile(`^(?:` + p + `)$`), kind: kind, all: all})
	}
	return out
}

var (
	claimWordsRE = regexp.MustCompile(`(?i)exploit|malicious use|in the wild`) // a sentence about exploitation
	claimCVERE   = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,12}\b`)
	// claimTurnRE: words of a claim, or of a turn to one, that no sentence of a denial or neutral form holds: such a sentence goes on
	// past what the form knows and is unclassified, so a claim after a denial is never swallowed.
	claimTurnRE = regexp.MustCompile(`in the wild|became aware|is aware of (?:the )?(?:active|attempted|limited|successful|exploitation|malicious)|` +
		`(?:has|have) been exploited|being exploited|, but |(?:has|have|been) observed`)
	// canonical form
	claimLinkRE  = regexp.MustCompile(`\s*\["[^"\]]{0,500}"\]`)
	claimCVEsRE  = regexp.MustCompile(`cve-[0-9]{4}-[0-9]{4,12}(?:(?:,| and| or|, and|, or) cve-[0-9]{4}-[0-9]{4,12})*`)
	claimWhenRE  = regexp.MustCompile(`^(?:in|on) (?:january|february|march|april|may|june|july|august|september|october|november|december)(?: [0-9]{1,2},)? [0-9]{4}, `)
	claimSpaceRE = regexp.MustCompile(`\s+`)
)

// The parts of Cisco's sentences.
const (
	ciscoPSIRT    = `(?:the cisco (?:psirt|product security incident response team \(psirt\)))`
	ciscoWhen     = `(?:\{when\} )?`
	ciscoOne      = `(?:this (?:vulnerability|issue)|the (?:vulnerability|issue) (?:that is )?described in (?:this advisory|\{cve\})(?: only)?|\{cve\})`
	ciscoMany     = `(?:these vulnerabilities|the vulnerabilities (?:that are )?described in (?:this advisory|\{cve\})(?: only)?|\{cve\})`
	ciscoAwareOf  = ciscoWhen + ciscoPSIRT + ` (?:is|became) aware of (?:the )?`
	ciscoExploits = `(?:(?:active|attempted|limited|successful) )?exploitation of `
	ciscoWild     = `(?: in the wild)?(?: after local administrator credentials were compromised)?`
	// what a denial or a proof-of-concept note speaks of, as Cisco ends those sentences
	ciscoOf = `(?:this (?:vulnerability|issue)|these vulnerabilities|the (?:vulnerability|vulnerabilities|issue) (?:that (?:is|are) )?described in ` +
		`(?:this advisory|\{cve\})|any of the other vulnerabilities that are described in this advisory|\{cve\})`
)

// ciscoForms: Cisco's "Exploitation and Public Announcements" section, as written in its advisories of 2025–2026.
var ciscoForms = concatForms(
	forms(formClaim, false,
		ciscoAwareOf+ciscoExploits+ciscoOne+ciscoWild,
		ciscoAwareOf+`malicious use of `+ciscoOne),
	forms(formClaim, true,
		ciscoAwareOf+ciscoExploits+ciscoMany+ciscoWild,
		ciscoAwareOf+`malicious use of `+ciscoMany),
	forms(formDenial, false,
		`(?:except as otherwise noted previously, )?`+ciscoPSIRT+` is not aware of (?:any )?(?:public announcements or )?malicious use of `+ciscoOf+
			`(?: against any cisco product)?`),
	forms(formNeutral, false,
		ciscoPSIRT+` is (?:aware that proof-of-concept exploit code is available for|not aware of proof-of-concept exploit code for) `+ciscoOf,
		`\{when\} this vulnerability was added to the known exploited vulnerabilit(?:y|ies) \(kev\) (?:database|catalog) of the u\.s`,
		`to exploit this vulnerability, an attacker must have [a-z0-9 -]{1,60} privileges on an affected (?:system|device)`,
		`cisco is not aware of successful exploitation by other methods`), // narrows how, not whether: no denial
)

// fortinetForms: Fortinet's descriptions of a vulnerability, as written in its advisories of 2024–2026.
var fortinetForms = concatForms(
	forms(formClaim, false,
		`(?:fortinet has observed this to be|this has been (?:observed|reported) to be|this vulnerability was found being|`+
			`please note that reports show this is being|fortinet is aware of an instance where this vulnerability was) exploited in the wild`+
			`(?: on [a-z0-9 -]{1,60}| and urges vulnerable customers to [a-z0-9 .,:-]{1,200}|, customers are urged to apply the workaround below|`+
			` by two malicious forticloud accounts, which were locked out on [0-9-]{10})?`),
	forms(formNeutral, false,
		`(?:however, )?(?:successful )?exploitation requires [a-z0-9 ,()/-]{1,300}`,
		`the presence of security controls [a-z0-9 ,()-]{1,200} required for exploitation`,
		`this vulnerability can only be abused as a consequence of [a-z0-9 ,()-]{1,300}`,
		`in order to protect its customers from further exploit, [a-z0-9 ,-]{1,200}`,
		`the vulnerability can be exploited via [a-z0-9 ,()-]{1,200}`,
		`patch bypass for persistency abused in a post-exploit scenario in [a-z0-9 -]{1,60}`,
		`an exposure of sensitive information [a-z0-9 ,()\[\]/-]{1,400}post-exploit cases, via crafted http requests`),
)

func concatForms(parts ...[]claimForm) []claimForm {
	var out []claimForm
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// claimWork counts the steps of reading claims (sentences, CVE ids, revisions): a test checks it grows with the document's size only.
type claimWork struct{ steps int }

func (w *claimWork) step(n int) {
	if w != nil {
		w.steps += n
	}
}

// claimReader reads the claims of one document against a vendor's forms, within the scope of its sections. It reads every sentence
// of a section, then settles (result): a denial that names a CVE takes it out of a claim made for the whole section; a CVE both
// claimed and denied by name, or a section both claimed and denied as a whole, is a contradiction, not a claim, and is counted as
// unclassified.
type claimReader struct {
	forms        []claimForm
	order        []string        // the CVEs claimed, in order
	byName       map[string]bool // claimed by a sentence that names it
	whole        map[string]bool // claimed by a sentence about the section's vulnerabilities
	deniedByName map[string]bool
	deniedWhole  bool // a denial about the section's vulnerabilities
	wholeDone    bool // the whole document's scope is claimed already (its CVEs are not walked again)
	unclassified int
	total        int // the CVEs of the document
	budget       int // bytes of text still read (csafMaxClaimText for a document)
	work         *claimWork
}

func newClaimReader(forms []claimForm, budget int, work *claimWork) *claimReader {
	return &claimReader{forms: forms, byName: map[string]bool{}, whole: map[string]bool{}, deniedByName: map[string]bool{}, budget: budget, work: work}
}

func (r *claimReader) claim(cve string, named bool) {
	if !r.byName[cve] && !r.whole[cve] {
		r.order = append(r.order, cve)
	}
	if named {
		r.byName[cve] = true
	} else {
		r.whole[cve] = true
	}
}

// result is the CVEs claimed once every sentence is read, denials applied.
func (r *claimReader) result() []string {
	out := make([]string, 0, len(r.order))
	conflictWhole := false
	for _, c := range r.order {
		r.work.step(1)
		switch {
		case r.deniedByName[c] && r.byName[c]:
			r.unclassified++ // the same CVE claimed and denied by name
		case r.deniedByName[c]:
			// claimed for the whole section, denied by name: not this one
		case r.deniedWhole && !r.byName[c]:
			conflictWhole = true
		default:
			out = append(out, c)
		}
	}
	if conflictWhole {
		r.unclassified++ // the section claimed and denied as a whole
	}
	return out
}

// read reads one text (plain or HTML) of a section whose CVEs are scope (scopeSet: the same as a set). It stops when ctx ends.
func (r *claimReader) read(ctx context.Context, text string, scope []string, scopeSet map[string]bool) error {
	if len(text) > maxClaimText {
		text = text[:maxClaimText]
	}
	if r.budget -= len(text); r.budget < 0 || !claimWordsRE.MatchString(text) {
		return nil
	}
	if strings.ContainsRune(text, '<') {
		text = stripTags(text)
	}
	if strings.ContainsRune(text, '&') {
		text = html.UnescapeString(text)
	}
	for i, sentence := range claimSentences(text) {
		r.work.step(1)
		if i%64 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if !claimWordsRE.MatchString(sentence) {
			continue
		}
		if len(sentence) > maxClaimSentence || strings.HasSuffix(sentence, "?") {
			r.unclassified++
			continue
		}
		canon, named := canonicalSentence(sentence)
		r.work.step(len(named))
		var form *claimForm
		for i := range r.forms {
			f := &r.forms[i]
			if f.re.MatchString(canon) && (f.kind == formClaim || !claimTurnRE.MatchString(canon)) {
				form = f
				break
			}
		}
		switch {
		case form == nil:
			r.unclassified++
		case form.kind == formNeutral:
		case form.kind == formDenial && len(named) > 0:
			for _, c := range named {
				if scopeSet[c] {
					r.deniedByName[c] = true
				}
			}
		case form.kind == formDenial:
			if !strings.HasPrefix(canon, "except as otherwise noted previously") { // that one leaves the claims before it
				r.deniedWhole = true
			}
		case len(named) > 0:
			for _, c := range named {
				if scopeSet[c] {
					r.claim(c, true)
				}
			}
		case form.all || len(scope) == 1:
			if r.wholeDone && len(scope) == r.total {
				continue
			}
			for _, c := range scope {
				r.claim(c, false)
			}
			r.work.step(len(scope))
			r.wholeDone = r.wholeDone || len(scope) == r.total
		default:
			r.unclassified++ // "this vulnerability" in a section of several
		}
	}
	return nil
}

// canonicalSentence is a sentence in the canonical form the forms are written for, and the CVE ids it names outside link targets
// (upper case, in order, distinct).
func canonicalSentence(s string) (string, []string) {
	s = claimLinkRE.ReplaceAllString(s, "")
	var named []string
	seen := map[string]bool{}
	for _, id := range claimCVERE.FindAllString(s, -1) {
		if id = strings.ToUpper(id); !seen[id] {
			seen[id] = true
			named = append(named, id)
		}
	}
	s = strings.ToLower(claimSpaceRE.ReplaceAllString(strings.TrimSpace(s), " "))
	s = strings.TrimRight(s, ".! ")
	s = claimCVEsRE.ReplaceAllString(s, "{cve}")
	s = claimWhenRE.ReplaceAllString(s, "{when} ")
	return s, named
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

// claimSentences splits text at line breaks and at a full stop, question or exclamation mark followed by a space or the end (the
// mark stays with its sentence, so a question can be told).
func claimSentences(text string) []string {
	var out []string
	start := 0
	for i := 0; i < len(text); i++ {
		end := i
		switch c := text[i]; {
		case c == '\n' || c == '\r':
		case (c == '.' || c == '!' || c == '?') && (i+1 == len(text) || text[i+1] == ' ' || text[i+1] == '\t' || text[i+1] == '\n' || text[i+1] == '\r' || text[i+1] == 0xc2):
			end = i + 1 // 0xc2: a no-break space (U+00A0) as vendors' HTML exports write it
		default:
			continue
		}
		if s := strings.TrimSpace(text[start:end]); s != "" {
			out = append(out, s)
		}
		start = i + 1
	}
	if s := strings.TrimSpace(text[start:]); s != "" {
		out = append(out, s)
	}
	return out
}
