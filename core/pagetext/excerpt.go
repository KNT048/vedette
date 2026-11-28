package pagetext

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// The budgets of the passages cut from one page.
const (
	ShortPage      = 8000 // a page this short that names an id is kept whole: its fix is often in a sentence that does not repeat the id
	pagePassages   = 8
	pageChars      = 7000
	passageChars   = 2500
	dedicatedChars = 9000
	dedicatedHead  = 4000
)

// Passage is one excerpt of a page: Kind page (the page whole, or the head of a page about the id), row (a table row with its header
// rows and section), section (a heading with its section) or para (a paragraph with its section heading).
type Passage struct {
	Kind string
	Text string
}

// Labels of an excerpt's lines: the appliance's, never the page's words (a quote check drops them).
const (
	LabelHeader  = "[table header] "
	LabelRow     = "[row] "
	LabelSection = "[section] "
	LabelLead    = "[section lead] "
	LabelHeading = "[heading] "
)

// reLabel finds the labels in a quote.
var reLabel = regexp.MustCompile(`\[(?:table header|row|section|section lead|heading)\] ?`)

// DropLabels removes the appliance's labels from a text (a quote the AI copied with them).
func DropLabels(s string) string { return reLabel.ReplaceAllString(s, "") }

var (
	reAdvisory  = []*regexp.Regexp{regexp.MustCompile(`\b([A-Za-z]{2,8})[-_]?(\d{2,4})[-_:](\d{1,7})\b`), regexp.MustCompile(`\b([A-Za-z]{2,6})(\d{4,8})\b`)}
	notAdvisory = map[string]bool{"cve": true, "cwe": true, "cpe": true, "html": true, "http": true, "https": true, "www": true, "id": true, "page": true,
		"issue": true, "bug": true, "show": true, "utf": true, "iso": true, "rfc": true, "msg": true}
)

// AdvisoryIDs are the advisory ids a CVE record cites (MS15-044, VMSA-2019-0022, MFSA2010-73, RHSA-2016:1430, JSA10718), read from its
// text and its reference addresses by their shape alone, no vendor list.
func AdvisoryIDs(text string, refs []string) []string {
	srcs := []string{text}
	for _, r := range refs {
		if u, err := url.Parse(r); err == nil {
			p, _ := url.PathUnescape(u.EscapedPath())
			srcs = append(srcs, p+"?"+u.RawQuery)
		}
	}
	set := map[string]string{}
	for _, s := range srcs {
		for _, re := range reAdvisory {
			for _, m := range re.FindAllStringSubmatch(s, -1) {
				digits := strings.Join(m[2:], "")
				if notAdvisory[strings.ToLower(m[1])] || len(digits) < 4 {
					continue
				}
				set[strings.ToLower(m[0])] = m[0]
			}
		}
	}
	var out []string
	for low, id := range set {
		prefix := false // an id that only starts a longer one (mfsa2010 of mfsa2010-73) would match every advisory of that year
		for o := range set {
			prefix = prefix || o != low && strings.HasPrefix(o, low)
		}
		if !prefix {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

var reLettersDigits = regexp.MustCompile(`[A-Za-z]+|\d+`)

// IDPattern matches the CVE id and the advisory ids as a page writes them (case and separators free: MS15-044, ms15_044).
func IDPattern(cve string, advisories []string) *regexp.Regexp {
	parts := []string{`\b` + regexp.QuoteMeta(cve) + `\b`}
	for _, a := range advisories {
		var ps []string
		for _, x := range reLettersDigits.FindAllString(a, -1) {
			ps = append(ps, regexp.QuoteMeta(x))
		}
		if len(ps) > 0 {
			parts = append(parts, `\b`+strings.Join(ps, `[-_: ]?`)+`\b`)
		}
	}
	return regexp.MustCompile(`(?i)` + strings.Join(parts, "|"))
}

// ProductPattern matches the product researched as a page writes it ("SQL Server", "Java SE", "Windows 11"), the vendor's word
// dropped; nil when it has no word to match.
func ProductPattern(vendor, product string) *regexp.Regexp {
	w := strings.Fields(strings.ToLower(product))
	if len(w) > 1 && w[0] == strings.ToLower(vendor) {
		w = w[1:]
	}
	var terms []string
	for k := len(w); k > 0; k-- {
		t := strings.Join(w[:k], " ")
		if k >= 2 || len(t) >= 4 {
			var q []string
			for _, x := range w[:k] {
				q = append(q, regexp.QuoteMeta(x))
			}
			terms = append(terms, `(?:^|[^\w.])`+strings.Join(q, `\s+`)+`(?:$|\W)`)
		}
	}
	if len(terms) == 0 {
		return nil
	}
	return regexp.MustCompile(`(?i)` + strings.Join(terms, "|"))
}

func line(b Block) string {
	if b.Kind == Row && b.IsHeader {
		return LabelHeader + b.Text
	}
	return b.Text
}

// Cut cuts the passages of one page that name ids: a short page that names one is kept whole; a page about the CVE (dedicated: its
// id in the address or title, or an advisory id there on the vendor's own site) keeps its head and then only the blocks naming an id
// or the product; any other page keeps each block naming an id with its context (a table row with its header rows and the heading
// above the table, a heading with its section, a paragraph with its heading and, for a bare label, the blocks that follow).
func Cut(blocks []Block, ids, product *regexp.Regexp, dedicated bool) []Passage {
	total, named := 0, false
	for _, b := range blocks {
		total += len(b.Text) + 1
		named = named || ids.MatchString(b.Text)
	}
	if !named && !dedicated {
		return nil
	}
	if named && total <= ShortPage {
		var lines []string
		for _, b := range blocks[firstH1(blocks):] {
			lines = append(lines, line(b))
		}
		return []Passage{{Kind: "page", Text: strings.Join(lines, "\n")}}
	}
	if dedicated {
		return cutDedicated(blocks, ids, product)
	}
	var out []Passage
	used := map[int]bool{}
	chars := 0
	for i, b := range blocks {
		if used[i] || !ids.MatchString(b.Text) {
			continue
		}
		var lines []string
		idx := []int{i}
		heading := sectionOf(blocks, i)
		kind := "para"
		switch b.Kind {
		case Row:
			kind = "row"
			if heading != "" {
				lines = append(lines, LabelSection+heading)
			}
			if b.Header != "" {
				lines = append(lines, LabelHeader+strings.ReplaceAll(b.Header, "\n", "\n"+LabelHeader))
			}
			lines = append(lines, LabelRow+b.Text)
		case Heading:
			kind = "section"
			lines = append(lines, LabelHeading+b.Text)
			n := 0
			for j := i + 1; j < len(blocks) && j < i+40; j++ {
				nb := blocks[j]
				if nb.Kind == Heading && nb.Level <= b.Level {
					break
				}
				if n += len(nb.Text); n > passageChars {
					break
				}
				lines = append(lines, line(nb))
				idx = append(idx, j)
			}
		default:
			if heading != "" {
				lines = append(lines, LabelSection+heading)
			}
			lines = append(lines, b.Text)
			if len(b.Text) < 160 { // a bare label ("CVE-2026-5731: ...") whose text follows
				n := 0
				for j := i + 1; j < len(blocks) && j < i+6; j++ {
					nb := blocks[j]
					if nb.Kind == Heading || ids.MatchString(nb.Text) {
						break
					}
					if n += len(nb.Text); n > 900 {
						break
					}
					lines = append(lines, line(nb))
					idx = append(idx, j)
				}
			}
		}
		text := clipText(strings.Join(lines, "\n"), passageChars)
		if chars+len(text) > pageChars || len(out) >= pagePassages {
			break
		}
		for _, j := range idx {
			used[j] = true
		}
		chars += len(text)
		out = append(out, Passage{Kind: kind, Text: text})
	}
	return out
}

// Dedicated says a page is about the CVE: its id in the address or title, or a cited advisory id there on the vendor's own site.
func Dedicated(pageURL, title, cve string, advisories []string, vendorSite bool) bool {
	where := strings.ToLower(pageURL + " " + title)
	if strings.Contains(where, strings.ToLower(cve)) {
		return true
	}
	if !vendorSite {
		return false
	}
	return slices.ContainsFunc(advisories, func(a string) bool { return strings.Contains(where, strings.ToLower(a)) })
}

func cutDedicated(blocks []Block, ids, product *regexp.Regexp) []Passage {
	first := slices.IndexFunc(blocks, func(b Block) bool { return ids.MatchString(b.Text) })
	if first < 0 {
		return nil
	}
	start := first
	if h := slices.IndexFunc(blocks[:first], func(b Block) bool { return b.Kind == Heading && b.Level == 1 }); h >= 0 && first-h < 200 {
		start = h // the page's own title heading above the first mention (an advisory names the CVE only further down)
	} else {
		for i := first - 1; i >= 0 && i > first-30; i-- {
			if blocks[i].Kind == Heading && blocks[i].Level <= 2 {
				start = i
				break
			}
		}
	}
	var lines []string
	n, lastHeader := 0, ""
	for _, b := range blocks[start:] {
		if n > dedicatedHead && !ids.MatchString(b.Text) && (product == nil || !product.MatchString(b.Text)) {
			continue
		}
		l := line(b)
		if b.Kind == Row && !b.IsHeader {
			if b.Header != "" && b.Header != lastHeader {
				l = LabelHeader + strings.ReplaceAll(b.Header, "\n", "\n"+LabelHeader) + "\n" + LabelRow + l
			}
			lastHeader = b.Header
		}
		if n+len(l) > dedicatedChars {
			if rest := dedicatedChars - n; rest > 0 {
				lines = append(lines, clipText(l, rest))
			}
			break
		}
		n += len(l) + 1
		lines = append(lines, l)
	}
	return []Passage{{Kind: "page", Text: strings.Join(lines, "\n")}}
}

func firstH1(blocks []Block) int {
	if i := slices.IndexFunc(blocks, func(b Block) bool { return b.Kind == Heading && b.Level == 1 }); i >= 0 {
		return i
	}
	return 0
}

// sectionOf is the heading above block i, with the section's lead paragraph when the block is further down.
func sectionOf(blocks []Block, i int) string {
	h := -1
	for j := i - 1; j >= 0 && j > i-400; j-- {
		if blocks[j].Kind == Heading {
			h = j
			break
		}
	}
	if h < 0 {
		return ""
	}
	out := blocks[h].Text
	for j := h + 1; j < i && j < h+6; j++ {
		if blocks[j].Kind == Paragraph && len(blocks[j].Text) >= 60 {
			out += "\n" + LabelLead + clipText(blocks[j].Text, 600)
			break
		}
	}
	return out
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
