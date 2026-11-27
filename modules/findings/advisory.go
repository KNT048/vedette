package findings

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/versionscheme"
)

// Reading a vendor's advisory without AI. Before any AI call, the box reads the CVE's reference pages itself and decides when the vendor
// states its affected versions in a form it knows: a CSAF advisory (JSON: product_tree, the CVE's product_status, a vers range per
// product version), or the plain-text phrasing vendors such as Juniper write ("23.2 versions from 23.2R2-S1 before 23.2R2-S5", "All
// versions before 21.4R3-S9"). The ranges are compared with the product's version scheme. "Affected" needs the version inside a stated
// range; "not affected" needs a range of the version's own release train that ends at or before it (the vendor states the fix of that
// train), never silence. What decides is quoted. A page that states nothing the box can read leaves the CVE to the AI, and the
// unparsed text is kept for an audit (Undecided unparsed_vendor_text).

// advisoryVerdict is what one page decided for one version.
type advisoryVerdict struct {
	verdict string // VerdictAffected or VerdictNotAffected
	quote   string
	url     string
}

// textRange is one range a page states: start "" is no start (all versions before), endIncl says the end is included.
type textRange struct {
	start, end string
	line       string // the release line the phrase names ("23.2"), "" for "all versions"
	endIncl    bool
	quote      string
}

var (
	// "All versions before 21.4R3-S9", "all versions prior to 7.4.1"
	reAllBefore = regexp.MustCompile(`(?i)\ball versions (?:before|prior to|earlier than)\s+([0-9][0-9A-Za-z.\-_]*[0-9A-Za-z])`)
	// "23.2 versions from 23.2R2-S1 before 23.2R2-S5", "23.2 versions before 23.2R2-S5", "24.2 versions prior to 24.2R2-S3"
	reLineRange = regexp.MustCompile(`(?i)\b([0-9]+(?:\.[0-9]+)*[A-Za-z0-9]*)\s+versions?\s+(?:from\s+([0-9][0-9A-Za-z.\-_]*[0-9A-Za-z])\s+)?(?:before|prior to|earlier than)\s+([0-9][0-9A-Za-z.\-_]*[0-9A-Za-z])`)
	// "versions 7.0.0 through 7.0.12", "from 7.0.0 through 7.0.12"
	reThrough = regexp.MustCompile(`(?i)\b(?:versions?|from)\s+([0-9][0-9A-Za-z.\-_]*[0-9A-Za-z])\s+(?:through|to)\s+([0-9][0-9A-Za-z.\-_]*[0-9A-Za-z])`)
)

// textRanges reads the ranges a page's text states, each with the sentence it is in.
func textRanges(text string) []textRange {
	var out []textRange
	for _, sentence := range sentences(text) {
		for _, m := range reAllBefore.FindAllStringSubmatch(sentence, -1) {
			out = append(out, textRange{end: m[1], quote: sentence})
		}
		for _, m := range reLineRange.FindAllStringSubmatch(sentence, -1) {
			out = append(out, textRange{line: m[1], start: m[2], end: m[3], quote: sentence})
		}
		for _, m := range reThrough.FindAllStringSubmatch(sentence, -1) {
			out = append(out, textRange{start: m[1], end: m[2], endIncl: true, quote: sentence})
		}
	}
	return out
}

// sentences cuts a page's text into lines and sentences short enough to quote.
func sentences(text string) []string {
	var out []string
	for _, l := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' || r == '•' || r == ';' }) {
		for _, s := range strings.SplitAfter(l, ". ") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, clipBytes(s, 400))
			}
		}
	}
	return out
}

// mentionsProduct says a page names the product (its catalogue name or its product word).
func mentionsProduct(text string, id CheckID) bool {
	low := strings.ToLower(text)
	_, product, _ := strings.Cut(id.Product, "|")
	if product != "" && strings.Contains(low, strings.ToLower(product)) {
		return true
	}
	if p, ok := productid.ByKey(id.Product); ok && p.Display != "" && strings.Contains(low, strings.ToLower(p.Display)) {
		return true
	}
	return false
}

// readAdvisory decides, from the pages a check read, whether the version of id is affected, deterministically; ok is false when no page
// states ranges the box can read for it. unparsed is a part of a page that names the product but gave no readable range (for the audit).
func readAdvisory(pages []FetchedPage, id CheckID, cve string) (v advisoryVerdict, ok bool, unparsed *Undecided) {
	scheme := productScheme(id.Product)
	for _, p := range pages {
		if p.Status != "ok" || p.Text == "" {
			continue
		}
		var rs []textRange
		names, others := cveMentions(p.Text, cve)
		if p.JSON {
			rs = csafRanges(p.Text, id, cve)
		} else if names && mentionsProduct(p.Text, id) { // plain text decides only on a page about this CVE
			rs = textRanges(p.Text)
		}
		if len(rs) == 0 {
			if unparsed == nil && !p.JSON && mentionsProduct(p.Text, id) {
				unparsed = &Undecided{Reason: UndecidedUnparsedVendor, URL: p.URL, Text: snippetAround(p.Text, id)}
			}
			continue
		}
		// "not affected" from plain text needs a page about this CVE alone: on a page that names others, the ranges read may be another
		// CVE's while this one's are in words the box cannot read (a CSAF document's ranges are the CVE's own)
		if verdict, quote, decided := judgeTextRanges(rs, id.Version, scheme); decided && (verdict == VerdictAffected || p.JSON || !others) {
			return advisoryVerdict{verdict: verdict, quote: quote, url: p.URL}, true, nil
		}
		if unparsed == nil {
			unparsed = &Undecided{Reason: UndecidedRangesDoNotCover, URL: p.URL, Text: clipBytes(rs[0].quote, undecidedText)}
			for _, r := range rs {
				if len(unparsed.Ranges) == undecidedRows {
					break
				}
				unparsed.Ranges = append(unparsed.Ranges, "["+r.start+", "+r.end+map[bool]string{true: "]", false: ")"}[r.endIncl])
			}
		}
	}
	return advisoryVerdict{}, false, unparsed
}

var reCVEID = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,}\b`)

// cveMentions says whether text names cve, and whether it names any other CVE.
func cveMentions(text, cve string) (names, others bool) {
	for _, m := range reCVEID.FindAllString(text, -1) {
		if strings.EqualFold(m, cve) {
			names = true
		} else {
			others = true
		}
	}
	return names, others
}

// snippetAround is up to undecidedText bytes of text around the first mention of the product's word.
func snippetAround(text string, id CheckID) string {
	_, product, _ := strings.Cut(id.Product, "|")
	i := strings.Index(strings.ToLower(text), strings.ToLower(product))
	if i < 0 || product == "" {
		i = 0
	}
	start := max(0, i-100)
	for start > 0 && start < len(text) && text[start]&0xC0 == 0x80 {
		start--
	}
	return clipBytes(strings.TrimSpace(text[start:]), undecidedText)
}

// judgeTextRanges decides one version against the ranges a page states: affected inside one (the first that contains it is quoted); not
// affected only when a range of the version's own release train ends at or before it and none contains it; else nothing.
func judgeTextRanges(rs []textRange, version string, scheme *versionscheme.Scheme) (verdict, quote string, ok bool) {
	if scheme != nil {
		installed, okI := scheme.Installed(version, "")
		if !okI {
			return "", "", false
		}
		var spans []versionscheme.Span
		var quotes []string
		for _, r := range rs {
			start := r.start
			if start == "" && r.line != "" {
				start = r.line // "23.2 versions before 23.2R2-S5": from the line's start
			}
			ex, in := r.end, ""
			if r.endIncl {
				ex, in = "", r.end
			}
			sp, okS := scheme.Span(start, ex, in)
			if !okS {
				continue
			}
			spans, quotes = append(spans, sp), append(quotes, r.quote)
		}
		for i, sp := range spans {
			if versionscheme.Judge(installed, []versionscheme.Span{sp}).State == versionscheme.Affected {
				return VerdictAffected, quotes[i], true
			}
		}
		if len(spans) > 0 && endsInTrain(spans, installed) && versionscheme.Judge(installed, spans).State == versionscheme.NotAffected {
			for i, sp := range spans {
				if sp.End != nil && sp.End.Train == installed.Train && sp.End.Variant == installed.Variant {
					return VerdictNotAffected, quotes[i], true
				}
			}
		}
		return "", "", false
	}
	// no scheme: only "affected" is decided, by the generic order, inside a range with an end
	for _, r := range rs {
		start := r.start
		if start == "" {
			start = r.line
		}
		if start != "" {
			if c, okC := CompareVersions(version, start); !okC || c < 0 {
				continue
			}
		}
		c, okC := CompareVersions(version, r.end)
		if okC && (c < 0 || r.endIncl && c == 0) && (r.line == "" || strings.HasPrefix(version, r.line)) {
			return VerdictAffected, r.quote, true
		}
	}
	return "", "", false
}

// csafRanges reads a CSAF advisory's ranges of the product for the CVE: the known_affected product ids of the CVE, each a product
// version (an exact release) or a vers range ("vers:generic/>=23.2R2-S1|<23.2R2-S5") under a product name that names the product.
func csafRanges(doc string, id CheckID, cve string) []textRange {
	var d struct {
		ProductTree struct {
			Branches []csafBranch `json:"branches"`
		} `json:"product_tree"`
		Vulnerabilities []struct {
			CVE           string `json:"cve"`
			ProductStatus struct {
				KnownAffected []string `json:"known_affected"`
			} `json:"product_status"`
		} `json:"vulnerabilities"`
	}
	if json.Unmarshal([]byte(doc), &d) != nil {
		return nil
	}
	products := map[string]csafProduct{}
	for _, b := range d.ProductTree.Branches {
		walkCSAF(b, "", products)
	}
	var out []textRange
	for _, v := range d.Vulnerabilities {
		if !strings.EqualFold(v.CVE, cve) {
			continue
		}
		for _, pid := range v.ProductStatus.KnownAffected {
			p, ok := products[pid]
			if !ok || !mentionsProduct(p.name, id) {
				continue
			}
			quote := clipBytes("known_affected: "+p.name+" "+p.version, 400)
			if strings.HasPrefix(strings.ToLower(p.version), "vers:") {
				out = append(out, versRanges(p.version, quote)...)
				continue
			}
			out = append(out, textRange{start: p.version, end: p.version, endIncl: true, quote: quote})
		}
	}
	return out
}

type csafBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Branches []csafBranch `json:"branches"`
	Product  *struct {
		ProductID string `json:"product_id"`
	} `json:"product"`
}

type csafProduct struct{ name, version string }

func walkCSAF(b csafBranch, name string, out map[string]csafProduct) {
	switch b.Category {
	case "product_name", "product_family":
		name = strings.TrimSpace(name + " " + b.Name)
	case "product_version", "product_version_range":
		if b.Product != nil && b.Product.ProductID != "" {
			out[b.Product.ProductID] = csafProduct{name: name, version: b.Name}
		}
	}
	for _, c := range b.Branches {
		walkCSAF(c, name, out)
	}
}

// versRanges reads a vers range ("vers:generic/>=23.2R2-S1|<23.2R2-S5", "vers:generic/<21.4R3-S9"): each lower bound with the upper
// bound after it is one range.
func versRanges(vers, quote string) []textRange {
	_, body, ok := strings.Cut(vers, "/")
	if !ok {
		return nil
	}
	var out []textRange
	var cur textRange
	for _, c := range strings.Split(body, "|") {
		c = strings.TrimSpace(c)
		switch {
		case strings.HasPrefix(c, ">="):
			cur = textRange{start: c[2:], quote: quote}
		case strings.HasPrefix(c, "<="):
			cur.end, cur.endIncl, cur.quote = c[2:], true, quote
			out, cur = append(out, cur), textRange{}
		case strings.HasPrefix(c, "<"):
			cur.end, cur.quote = c[1:], quote
			out, cur = append(out, cur), textRange{}
		case c != "" && !strings.ContainsAny(c, "<>=!*"):
			out = append(out, textRange{start: c, end: c, endIncl: true, quote: quote})
		}
	}
	return slices.DeleteFunc(out, func(r textRange) bool { return r.end == "" })
}

// quoteFound says the AI's quote is in the page it cited (or the record), word for word once whitespace is folded: the guard against a
// sentence the AI made up. It is no second reading of the verdict.
func quoteFound(quote, text string) bool {
	q := foldSpace(quote)
	return len(q) >= 12 && strings.Contains(foldSpace(text), q)
}

func foldSpace(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }

// quoteNamesRange says a quote names a release range of the version's own line: it names the version or its release line and a
// range word ("before", "through", "prior to", "earlier than", "from", "up to"). A lexical check of the quote, not a reading of it.
func quoteNamesRange(quote string, id CheckID) bool {
	low := strings.ToLower(quote)
	// the version as a whole ("7.4.10" does not name 7.4.1; a sentence's last period may follow it), the line also inside a release
	version := regexp.MustCompile(`(?:^|[^0-9a-z.])` + regexp.QuoteMeta(strings.ToLower(id.Version)) + `(?:$|[^0-9a-z.]|\.(?:$|[^0-9a-z]))`)
	names := id.Version != "" && version.MatchString(low) || id.Line != "" && regexp.MustCompile(`(?:^|[^0-9.])`+regexp.QuoteMeta(strings.ToLower(id.Line))+`(?:$|[^0-9])`).MatchString(low)
	if !names {
		return false
	}
	for _, w := range []string{"before", "through", "prior to", "earlier than", "from ", "up to", "and earlier", "and later"} {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
}
