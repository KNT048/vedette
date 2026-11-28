// Package pagetext reads a web page the appliance fetched into blocks (headings, paragraphs and table rows that know their table's
// header rows) and cuts from them the passages that name an identifier (a CVE, an advisory). It is general: no site is parsed its own
// way. The full text of a page is its blocks one per line, so a passage is always text of the page as the appliance holds it.
package pagetext

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// Kinds of Block.
const (
	Heading   = 'h'
	Paragraph = 'p'
	Row       = 'r'
)

// Block is one block of a page: a heading (Level 1..6), a paragraph or list item, or a table row (its cells joined by " | "). A row
// that is one of its table's header rows has IsHeader; every other row carries its table's header rows in Header (one per line).
type Block struct {
	Kind     byte
	Level    int
	Text     string
	Header   string
	IsHeader bool
}

// maxTokens bounds the HTML tokens read from one page; maxHeaderRows the header rows of one table (a two- or three-level header):
// a table of header rows only does not grow one header row by row.
const (
	maxTokens     = 600000
	maxHeaderRows = 4
)

var (
	skipTags  = map[string]bool{"script": true, "style": true, "svg": true, "template": true, "iframe": true, "object": true, "canvas": true, "select": true, "button": true, "head": true}
	blockTags = map[string]bool{"p": true, "div": true, "section": true, "article": true, "header": true, "footer": true, "main": true, "aside": true, "nav": true,
		"li": true, "ul": true, "ol": true, "dl": true, "dt": true, "dd": true, "pre": true, "blockquote": true, "br": true, "hr": true, "form": true,
		"figure": true, "figcaption": true, "caption": true, "details": true, "summary": true, "h1": true, "h2": true, "h3": true, "h4": true, "h5": true,
		"h6": true, "body": true, "tbody": true, "thead": true}
	headingLevel = map[string]int{"h1": 1, "h2": 2, "h3": 3, "h4": 4, "h5": 5, "h6": 6}
	// a page that ships its content as an HTML template inside a script (client-rendered blogs) has it read too
	reTemplate = regexp.MustCompile(`(?is)<script[^>]*type=['"]text/(?:template|html|x-[\w-]*template)['"][^>]*>(.*?)</script>`)
	reSpace    = regexp.MustCompile(`\s+`)
	dashes     = strings.NewReplacer("\u2010", "-", "\u2011", "-", "\u2012", "-", "\u2013", "-", "\u2014", "-", "\u2212", "-", "\u00a0", " ", "\u200b", "", "\u00ad", "")
)

type table struct {
	row     []string
	cell    *strings.Builder
	header  string
	rows    int
	headers int
	allTH   bool
	inRow   bool
}

type parser struct {
	out    []Block
	buf    strings.Builder
	tag    string
	tables []*table
}

func clean(s string) string {
	return strings.TrimSpace(reSpace.ReplaceAllString(dashes.Replace(s), " "))
}

func (p *parser) flush() {
	t := clean(p.buf.String())
	p.buf.Reset()
	if t == "" {
		return
	}
	if lvl := headingLevel[p.tag]; lvl > 0 {
		p.out = append(p.out, Block{Kind: Heading, Level: lvl, Text: t})
		return
	}
	p.out = append(p.out, Block{Kind: Paragraph, Text: t})
}

func (t *table) endCell() {
	if t.cell != nil && t.inRow {
		t.row = append(t.row, clean(t.cell.String()))
	}
	t.cell = nil
}

func (p *parser) endRow(t *table) {
	t.endCell()
	if t.inRow {
		text := strings.Trim(strings.TrimSpace(strings.Join(t.row, " | ")), "| ")
		if text != "" {
			// header rows: the first row, and every all-<th> row while only header rows came before it (two-level headers); an all-<th>
			// row further down starts a new block of the same table
			isHeader := t.headers < maxHeaderRows && (t.rows == 0 || t.allTH && t.rows == t.headers)
			switch {
			case isHeader:
				t.headers++
				if t.header != "" {
					t.header += "\n"
				}
				t.header += text
			case t.allTH:
				t.header = text
			}
			b := Block{Kind: Row, Text: text, IsHeader: isHeader}
			if !isHeader {
				b.Header = t.header
			}
			p.out = append(p.out, b)
			t.rows++
		}
	}
	t.row, t.inRow = nil, false
}

func (p *parser) start(name string) {
	var t *table
	if n := len(p.tables); n > 0 {
		t = p.tables[n-1]
	}
	switch {
	case name == "table":
		if t == nil {
			p.flush()
		}
		p.tables = append(p.tables, &table{})
	case t != nil && name == "tr":
		p.endRow(t)
		t.inRow, t.allTH = true, true
	case t != nil && (name == "td" || name == "th"):
		if !t.inRow {
			t.inRow, t.allTH = true, true
		}
		t.endCell()
		t.cell = &strings.Builder{}
		if name == "td" {
			t.allTH = false
		}
	case t != nil && t.cell != nil:
		if blockTags[name] {
			t.cell.WriteByte(' ')
		}
	case t == nil && blockTags[name]:
		p.flush()
		p.tag = name
	}
}

func (p *parser) end(name string) {
	var t *table
	if n := len(p.tables); n > 0 {
		t = p.tables[n-1]
	}
	switch {
	case name == "table" && t != nil:
		p.endRow(t)
		p.tables = p.tables[:len(p.tables)-1]
	case t != nil && (name == "td" || name == "th"):
		t.endCell()
	case t != nil && name == "tr":
		p.endRow(t)
	case t == nil && blockTags[name]:
		p.flush()
		p.tag = "p"
	}
}

func (p *parser) text(s string) {
	if n := len(p.tables); n > 0 {
		if t := p.tables[n-1]; t.cell != nil {
			t.cell.WriteString(s)
		}
		return // text in a table outside any cell is layout noise
	}
	p.buf.WriteString(s)
}

// HTML reads an HTML page into its blocks and title.
func HTML(src string) (blocks []Block, title string) { return parseHTML(src, false) }

// parseHTML reads a page; inNoscriptPage says it is the text of a <noscript>, whose own <noscript> is not read again (each level would
// copy the rest of the page).
func parseHTML(src string, inNoscriptPage bool) (blocks []Block, title string) {
	src = reTemplate.ReplaceAllString(src, "$1")
	z := html.NewTokenizer(strings.NewReader(src))
	z.SetMaxBuf(1 << 20)
	p := &parser{tag: "p"}
	skip, inTitle, inNoscript := 0, false, false
	var ttl strings.Builder
	for range maxTokens {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		switch tt {
		case html.TextToken:
			switch {
			case inTitle:
				ttl.Write(z.Text())
			case inNoscript && inNoscriptPage:
			case inNoscript && skip == 0 && len(p.tables) == 0:
				// the tokenizer gives a <noscript> as raw text: what a page shows without scripts is read as a page of its own
				sub, _ := parseHTML(string(z.Text()), true)
				p.flush()
				p.out = append(p.out, sub...)
			case skip == 0:
				p.text(string(z.Text()))
			}
		case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
			b, _ := z.TagName()
			name := string(b)
			if name == "title" {
				inTitle = tt == html.StartTagToken
				continue
			}
			if name == "noscript" {
				inNoscript = tt == html.StartTagToken
				continue
			}
			if skipTags[name] {
				switch {
				case tt == html.StartTagToken:
					skip++
				case tt == html.EndTagToken && skip > 0:
					skip--
				}
				continue
			}
			if skip > 0 {
				continue
			}
			if tt == html.EndTagToken {
				p.end(name)
			} else {
				p.start(name)
				if tt == html.SelfClosingTagToken || name == "br" || name == "hr" {
					p.end(name)
				}
			}
		}
	}
	for len(p.tables) > 0 {
		p.end("table")
	}
	p.flush()
	return p.out, clean(ttl.String())
}

// Plain reads a text document into paragraphs (split at empty lines), and a JSON document into its lines.
func Plain(src string, lines bool) []Block {
	var parts []string
	if lines {
		parts = strings.Split(src, "\n")
	} else {
		parts = regexp.MustCompile(`\n\s*\n`).Split(src, -1)
	}
	var out []Block
	for _, s := range parts {
		if t := clean(s); t != "" {
			out = append(out, Block{Kind: Paragraph, Text: t})
		}
	}
	return out
}

// Text is the page's full text: its blocks, one per line.
func Text(blocks []Block) string {
	var b strings.Builder
	for _, bl := range blocks {
		b.WriteString(bl.Text)
		b.WriteByte('\n')
	}
	return b.String()
}

// Clip keeps the blocks whose text fits in limit bytes, the last one cut at a rune boundary.
func Clip(blocks []Block, limit int) []Block {
	n := 0
	for i, b := range blocks {
		if n+len(b.Text)+1 > limit {
			cut := max(0, limit-n-1)
			for cut > 0 && !utf8.RuneStart(b.Text[cut]) {
				cut--
			}
			out := blocks[:i:i]
			if cut > 0 {
				b.Text = b.Text[:cut]
				out = append(out, b)
			}
			return out
		}
		n += len(b.Text) + 1
	}
	return blocks
}
