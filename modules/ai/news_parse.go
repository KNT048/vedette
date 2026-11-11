package ai

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// Everything here reads text from the Internet: untrusted, size-capped before it arrives (newsMaxBody), and capped again on the way
// out. A parser that cannot read its input fails closed (errNewsParse): the source is skipped, never half-read into a prompt.

const (
	maxSourceText = 6000   // bytes of one source's text in the prompt
	maxFeedItems  = 200    // items read from one feed
	maxItemText   = 4000   // bytes kept from one feed item
	maxFeedMatch  = 3      // items of one feed that name the CVE, sent at most
	maxXMLDepth   = 64     // nesting depth of a feed
	maxXMLTokens  = 400000 // tokens read from one feed
	maxHTMLTokens = 400000 // tokens read from one page
	maxRepos      = 10     // GitHub repositories listed
	maxRefs       = 25     // NVD references listed
)

// sanitizeWeb makes fetched text safe to put in a fenced data block: valid UTF-8, no control or format characters (bidi overrides,
// zero-width characters) except line breaks, runs of spaces collapsed, at most one empty line in a row.
func sanitizeWeb(s string) string {
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	b.Grow(len(s))
	space, newlines := false, 0
	for _, r := range s {
		switch {
		case r == '\n' || r == ' ' || r == ' ' || r == '\r':
			space = false
			if newlines < 2 && b.Len() > 0 {
				b.WriteByte('\n')
			}
			newlines++
			continue
		case unicode.IsSpace(r):
			space = true
			continue
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || invisible(r):
			continue
		}
		if space && newlines == 0 && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space, newlines = false, 0
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// invisible lists the characters outside Cc/Cf that render as nothing and can hide text: variation selectors, the combining
// grapheme joiner, the Hangul fillers, Mongolian variation selectors and the interlinear annotation marks.
func invisible(r rune) bool {
	return (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) || r == 0x034F || r == 0x115F || r == 0x1160 || r == 0x3164 ||
		r == 0xFFA0 || (r >= 0x180B && r <= 0x180F) || (r >= 0xFFF9 && r <= 0xFFFB)
}

// webLine is one field of fetched data on one line, cut to n bytes.
func webLine(s string, n int) string {
	return clipBytes(strings.Join(strings.Fields(sanitizeWeb(s)), " "), n)
}

// clipBytes cuts s to at most n bytes on a rune boundary.
func clipBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// asciiUpper upper-cases ASCII letters only, so byte offsets stay the same.
func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

// cveIndexes returns where the CVE id occurs in s (any case), not as the start of a longer id (CVE-2024-3400 is not in CVE-2024-34001).
func cveIndexes(s, cve string) []int {
	up, id := asciiUpper(s), asciiUpper(cve)
	var out []int
	for i := 0; i < len(up); {
		j := strings.Index(up[i:], id)
		if j < 0 {
			break
		}
		at, end := i+j, i+j+len(id)
		before := at == 0 || !isAlnum(up[at-1])
		after := end == len(up) || (up[end] < '0' || up[end] > '9')
		if before && after {
			out = append(out, at)
		}
		i = end
	}
	return out
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func containsCVE(s, cve string) bool { return len(cveIndexes(s, cve)) > 0 }

// excerpt keeps a long page short: its start, then the text around each mention of the CVE, up to max bytes in all.
func excerpt(text, cve string, limit int) string {
	if len(text) <= limit {
		return text
	}
	const head, before, after = 1500, 1200, 1800
	var b strings.Builder
	b.WriteString(clipBytes(text, head))
	last := head
	for _, i := range cveIndexes(text, cve) {
		if b.Len() >= limit {
			break
		}
		start, end := max(i-before, last), min(i+after, len(text))
		if start >= end {
			continue
		}
		for start > 0 && !utf8.RuneStart(text[start]) {
			start--
		}
		for end < len(text) && !utf8.RuneStart(text[end]) {
			end++
		}
		if start > last {
			b.WriteString("\n…\n")
		}
		b.WriteString(text[start:end])
		last = end
	}
	return clipBytes(b.String(), limit)
}

// safeLink returns u when it is a plain printable-ASCII https address of a reasonable length (and, with host set, on that host), else "".
func safeLink(u, host string) string {
	u = strings.TrimSpace(u)
	for i := 0; i < len(u); i++ {
		if u[i] < 0x21 || u[i] > 0x7e { // a real link is percent-encoded; raw bytes could hide bidi or zero-width characters
			return ""
		}
	}
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" || p.Host == "" || p.User != nil || len(u) > 500 || strings.ContainsAny(u, " \t\r\n<>\"'`") {
		return ""
	}
	if host != "" && !strings.EqualFold(p.Hostname(), host) {
		return ""
	}
	return p.String()
}

// ---- HTML to text

var (
	htmlSkip  = map[string]bool{"script": true, "style": true, "noscript": true, "template": true, "svg": true, "iframe": true, "object": true, "nav": true, "footer": true, "select": true}
	htmlBlock = map[string]bool{"p": true, "div": true, "br": true, "li": true, "tr": true, "h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
		"section": true, "article": true, "table": true, "ul": true, "ol": true, "pre": true, "blockquote": true, "dd": true, "dt": true, "hr": true, "td": true, "th": true}
)

// htmlToText reads the visible text of an HTML page or fragment: scripts, styles, navigation and footers are dropped, block elements
// become line breaks, entities are decoded. It reads at most maxHTMLTokens tokens and returns at most limit bytes.
func htmlToText(src string, limit int) string {
	z := html.NewTokenizer(strings.NewReader(src))
	z.SetMaxBuf(512 << 10)
	var b strings.Builder
	skip := 0
	for n := 0; n < maxHTMLTokens && b.Len() < limit; n++ {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return clipBytes(sanitizeWeb(b.String()), limit)
		case html.TextToken:
			if skip == 0 {
				b.Write(z.Text())
			}
		case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
			name, _ := z.TagName()
			tag := string(name)
			if htmlSkip[tag] && tt != html.SelfClosingTagToken {
				if tt == html.StartTagToken {
					skip++
				} else if skip > 0 {
					skip--
				}
			}
			if htmlBlock[tag] {
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
		}
	}
	return clipBytes(sanitizeWeb(b.String()), limit) // sanitized first: a broken byte becomes a 3-byte U+FFFD
}

// ---- NVD (services.nvd.nist.gov, CVE API 2.0)

type nvdText struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetric struct {
	CVSS struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		Vector       string  `json:"vectorString"`
	} `json:"cvssData"`
}

type nvdAnswer struct {
	Vulns []struct {
		CVE struct {
			ID           string    `json:"id"`
			Published    string    `json:"published"`
			LastModified string    `json:"lastModified"`
			Status       string    `json:"vulnStatus"`
			KEVAdded     string    `json:"cisaExploitAdd"`
			KEVAction    string    `json:"cisaRequiredAction"`
			Descriptions []nvdText `json:"descriptions"`
			Metrics      struct {
				V40 []nvdMetric `json:"cvssMetricV40"`
				V31 []nvdMetric `json:"cvssMetricV31"`
			} `json:"metrics"`
			Weaknesses []struct {
				Description []nvdText `json:"description"`
			} `json:"weaknesses"`
			References []struct {
				URL  string   `json:"url"`
				Tags []string `json:"tags"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// nvdInfo is what the box takes from an NVD record: the text for the prompt and the links tagged as the vendor's advisory, patch or
// mitigation (candidates for the vendor page, still checked against advisoryHosts).
type nvdInfo struct {
	found   bool
	text    string
	vendors []string
}

func parseNVD(body []byte, cve string) (nvdInfo, error) {
	var a nvdAnswer
	if err := json.Unmarshal(body, &a); err != nil {
		return nvdInfo{}, errNewsParse
	}
	for _, v := range a.Vulns {
		c := v.CVE
		if !strings.EqualFold(c.ID, cve) {
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, "NVD record %s (status %s, published %s, last modified %s)\n", cve, webLine(c.Status, 40), webLine(c.Published, 30), webLine(c.LastModified, 30))
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				fmt.Fprintf(&b, "Description: %s\n", webLine(d.Value, 2000))
				break
			}
		}
		for _, m := range []struct {
			name string
			list []nvdMetric
		}{{"CVSS 4.0", c.Metrics.V40}, {"CVSS 3.1", c.Metrics.V31}} {
			if len(m.list) > 0 {
				x := m.list[0].CVSS
				fmt.Fprintf(&b, "%s: %s %s (%s)\n", m.name, strconv.FormatFloat(x.BaseScore, 'f', 1, 64), webLine(x.BaseSeverity, 20), webLine(x.Vector, 160))
			}
		}
		var cwes []string
		for _, w := range c.Weaknesses {
			for _, d := range w.Description {
				if len(cwes) < 6 {
					cwes = append(cwes, webLine(d.Value, 40))
				}
			}
		}
		if len(cwes) > 0 {
			fmt.Fprintf(&b, "Weakness: %s\n", strings.Join(cwes, ", "))
		}
		if c.KEVAdded != "" {
			fmt.Fprintf(&b, "Added to CISA's exploited list: %s. Required action: %s\n", webLine(c.KEVAdded, 30), webLine(c.KEVAction, 400))
		}
		info := nvdInfo{found: true}
		n := 0
		for _, r := range c.References {
			link := safeLink(r.URL, "")
			if link == "" {
				continue
			}
			tags := make([]string, 0, len(r.Tags))
			for _, t := range r.Tags {
				tags = append(tags, webLine(t, 40))
				if t == "Vendor Advisory" || t == "Patch" || t == "Mitigation" {
					info.vendors = append(info.vendors, link)
				}
			}
			if n < maxRefs {
				if n == 0 {
					b.WriteString("References:\n")
				}
				fmt.Fprintf(&b, "- %s [%s]\n", link, strings.Join(tags, ", "))
				n++
			}
		}
		info.text = clipBytes(sanitizeWeb(b.String()), maxSourceText)
		return info, nil
	}
	if a.Vulns == nil && !bytes.Contains(body, []byte(`"vulnerabilities"`)) && !bytes.Contains(body, []byte(`"totalResults"`)) {
		return nvdInfo{}, errNewsParse // not an answer of the CVE API
	}
	return nvdInfo{}, nil
}

// ---- GitHub repository search (api.github.com/search/repositories)

type ghRepo struct {
	FullName    string  `json:"full_name"`
	Description *string `json:"description"`
	Stars       int     `json:"stargazers_count"`
	Fork        bool    `json:"fork"`
	Archived    bool    `json:"archived"`
	Created     string  `json:"created_at"`
	Pushed      string  `json:"pushed_at"`
}

// ghInfo is the search answer as the box uses it: the repositories whose name or description names the CVE.
type ghInfo struct {
	total int // repositories the search found
	named int // of those read, the ones that name the CVE
	text  string
}

func parseGitHubSearch(body []byte, cve string) (ghInfo, error) {
	var a struct {
		Total *int     `json:"total_count"`
		Items []ghRepo `json:"items"`
	}
	if err := json.Unmarshal(body, &a); err != nil || a.Total == nil {
		return ghInfo{}, errNewsParse
	}
	info := ghInfo{total: *a.Total}
	var b strings.Builder
	for _, r := range a.Items {
		desc := ""
		if r.Description != nil {
			desc = *r.Description
		}
		if !containsCVE(r.FullName, cve) && !containsCVE(desc, cve) {
			continue
		}
		info.named++
		if info.named > maxRepos {
			continue
		}
		var flags []string
		if r.Fork {
			flags = append(flags, "fork")
		}
		if r.Archived {
			flags = append(flags, "archived")
		}
		fmt.Fprintf(&b, "- %s (%d stars, created %s, last push %s%s): %s\n", webLine(r.FullName, 120), r.Stars, webLine(clipBytes(r.Created, 10), 10),
			webLine(clipBytes(r.Pushed, 10), 10), prefixed(", ", strings.Join(flags, ", ")), webLine(desc, 300))
	}
	head := fmt.Sprintf("GitHub repository search for %s: %d repositories found, %d of the first %d name the CVE in their name or description.\n", cve, info.total, info.named, len(a.Items))
	if info.named == 0 {
		head = fmt.Sprintf("GitHub repository search for %s: no public repository names the CVE in its name or description (%d found by the search).\n", cve, info.total)
	}
	info.text = clipBytes(sanitizeWeb(head+b.String()), maxSourceText)
	return info, nil
}

func prefixed(p, s string) string {
	if s == "" {
		return ""
	}
	return p + s
}

// ---- RSS 2.0 and Atom

type feedItem struct {
	Title, Link, Date, Text string
}

// parseFeed reads the items of an RSS 2.0 or Atom feed. encoding/xml expands no external entity and reads no DTD, so a document
// cannot grow itself (billion laughs); depth, token count, item count and field sizes are capped on top. A feed in an encoding other
// than UTF-8, ASCII or Latin-1 is refused.
func parseFeed(body []byte) ([]feedItem, error) {
	d := xml.NewDecoder(bytes.NewReader(body))
	d.Strict = false
	d.Entity = xml.HTMLEntity
	d.CharsetReader = feedCharset
	var items []feedItem
	var cur *feedItem
	var field string
	var buf strings.Builder
	depth, itemDepth, root := 0, 0, false
	for n := 0; n < maxXMLTokens; n++ {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if len(items) > 0 {
				break // keep what was read before the broken part
			}
			return nil, errNewsParse
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth > maxXMLDepth {
				if len(items) > 0 {
					return items, nil
				}
				return nil, errNewsParse
			}
			name := t.Name.Local
			if depth == 1 {
				root = name == "rss" || name == "feed" || name == "RDF"
			}
			if cur == nil && (name == "item" || name == "entry") {
				cur, itemDepth = &feedItem{}, depth
				continue
			}
			if cur == nil || depth != itemDepth+1 {
				continue
			}
			buf.Reset()
			switch name {
			case "title":
				field = "title"
			case "link":
				field = "link"
				for _, a := range t.Attr { // Atom: <link rel="alternate" href="..."/>
					if a.Name.Local == "href" && cur.Link == "" && (attr(t.Attr, "rel") == "" || attr(t.Attr, "rel") == "alternate") {
						cur.Link = strings.TrimSpace(a.Value)
					}
				}
			case "description", "summary", "content", "encoded":
				field = "text"
			case "pubDate", "updated", "published", "date":
				field = "date"
			default:
				field = ""
			}
		case xml.CharData:
			if field != "" && buf.Len() < 512<<10 {
				buf.Write(t)
			}
		case xml.EndElement:
			if cur != nil && depth == itemDepth+1 && field != "" {
				v := buf.String()
				switch field {
				case "title":
					cur.Title = webLine(htmlToText(v, 2000), 300)
				case "link":
					if cur.Link == "" {
						cur.Link = strings.TrimSpace(v)
					}
				case "text":
					if t := htmlToText(v, 64<<10); len(t) > len(cur.Text) {
						cur.Text = t
					}
				case "date":
					cur.Date = webLine(v, 40)
				}
				field = ""
			}
			if cur != nil && depth == itemDepth {
				cur.Text = clipBytes(cur.Text, maxItemText)
				items = append(items, *cur)
				cur, field = nil, ""
				if len(items) >= maxFeedItems {
					return items, nil
				}
			}
			depth--
		}
	}
	if !root {
		return nil, errNewsParse
	}
	return items, nil
}

func attr(as []xml.Attr, name string) string {
	for _, a := range as {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// feedCharset is the decoder's CharsetReader: UTF-8 and ASCII as they are, Latin-1 (and Windows-1252, read as Latin-1) converted.
func feedCharset(label string, r io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "utf-8", "utf8", "us-ascii", "ascii":
		return r, nil
	case "iso-8859-1", "latin1", "latin-1", "windows-1252", "cp1252":
		b, err := io.ReadAll(io.LimitReader(r, newsMaxBody+1))
		if err != nil {
			return nil, err
		}
		var out strings.Builder
		out.Grow(len(b))
		for _, c := range b {
			out.WriteRune(rune(c))
		}
		return strings.NewReader(out.String()), nil
	}
	return nil, errNewsParse
}

// feedMentions is the text about the CVE in a feed: up to maxFeedMatch items that name it, each with its title, date, link and the
// text around the mention. The links are those of the feed's own host only.
func feedMentions(items []feedItem, cve, host string) (text string, hits []feedItem) {
	var b strings.Builder
	for _, it := range items {
		if len(hits) == maxFeedMatch {
			break
		}
		if !containsCVE(it.Title, cve) && !containsCVE(it.Text, cve) {
			continue
		}
		it.Link = safeLink(it.Link, host)
		hits = append(hits, it)
		fmt.Fprintf(&b, "Post: %s (%s)\nLink: %s\n%s\n\n", it.Title, it.Date, it.Link, excerpt(it.Text, cve, 1800))
	}
	return clipBytes(sanitizeWeb(b.String()), maxSourceText), hits
}
