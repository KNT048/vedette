package channel

import (
	"html"
	"strings"
)

// Doc is a document an email carries whole (the periodic report): a heading, short paragraphs and sections of paragraphs and
// tables. Only the email channel renders it, as a multipart/alternative message: a plain-text part and an HTML part. Every string
// is untrusted: it is cleaned (control and format characters) and cut to a length, and the HTML part escapes it; the HTML has no
// script, no remote image or style, and no link except the message's own link to the box. A document bigger than maxDocHTML stops
// at a section or row boundary and says the rest is on the page the link opens.
type Doc struct {
	Heading  string
	Intro    []string // paragraphs under the heading
	Sections []DocSection
	Footer   string
}

// DocSection is one titled section: paragraphs, then tables, then a closing line ("12 more open findings are not listed.").
type DocSection struct {
	Title      string
	Paragraphs []string
	Tables     []DocTable
	More       string
}

// DocTable is a table with a caption (may be empty), a header row and rows of cells; a row may have fewer cells than the header.
type DocTable struct {
	Caption string
	Head    []string
	Rows    [][]string
}

const (
	maxDocCell  = 600     // runes of one cell or paragraph
	maxDocTitle = 200     // runes of a heading or a caption
	maxDocHTML  = 400_000 // bytes of the HTML part before the rest is left to the page
	maxDocRows  = 500     // rows of one table, whatever their size
)

// docCut is the line a document ends with when it was cut to fit an email.
const docCut = "This email has the first part of the report only. The whole report is on its page in Vedette."

func docText(s string, n int) string { return truncRunes(strings.TrimSpace(clean(s, false)), n) }

// docWriter renders a document as text and HTML at once, so both parts stop at the same place when the size cap is reached.
type docWriter struct {
	text, html strings.Builder
	cut        bool
}

func (w *docWriter) full(next int) bool {
	if w.html.Len()+next > maxDocHTML {
		w.cut = true
	}
	return w.cut
}

func (w *docWriter) para(s string, tag string) {
	s = docText(s, maxDocCell)
	if s == "" || w.full(len(s)*2+40) {
		return
	}
	w.text.WriteString(s + "\n\n")
	switch tag {
	case "h1":
		w.html.WriteString(`<h1 style="font-size:20px;margin:0 0 12px">` + html.EscapeString(s) + "</h1>\n")
	case "h2":
		w.html.WriteString(`<h2 style="font-size:16px;margin:24px 0 8px;border-bottom:1px solid #ddd;padding-bottom:4px">` + html.EscapeString(s) + "</h2>\n")
	default:
		w.html.WriteString(`<p style="margin:0 0 8px">` + html.EscapeString(s) + "</p>\n")
	}
}

func (w *docWriter) table(t DocTable) {
	if len(t.Rows) == 0 || w.cut {
		return
	}
	head := make([]string, len(t.Head))
	for i, h := range t.Head {
		head[i] = docText(h, maxDocTitle)
	}
	var hb strings.Builder
	hb.WriteString(`<table style="border-collapse:collapse;width:100%;margin:0 0 12px;font-size:13px">`)
	c := docText(t.Caption, maxDocTitle)
	if c != "" {
		hb.WriteString(`<caption style="text-align:left;font-weight:bold;padding:4px 0">` + html.EscapeString(c) + "</caption>")
	}
	hb.WriteString("<tr>")
	for _, h := range head {
		hb.WriteString(`<th style="text-align:left;border-bottom:1px solid #ccc;padding:4px 6px">` + html.EscapeString(h) + "</th>")
	}
	hb.WriteString("</tr>\n")
	if w.full(hb.Len() + 20) {
		return
	}
	w.html.WriteString(hb.String())
	if c != "" { // only once the table is in the HTML part: both parts stop at the same place
		w.text.WriteString(c + "\n")
	}
	for k, row := range t.Rows {
		if k == maxDocRows {
			w.cut = true
			break
		}
		var rb strings.Builder
		var tl []string
		rb.WriteString("<tr>")
		for i := range max(len(head), len(row)) {
			c := ""
			if i < len(row) {
				c = docText(row[i], maxDocCell)
			}
			rb.WriteString(`<td style="vertical-align:top;border-bottom:1px solid #eee;padding:4px 6px">` + html.EscapeString(c) + "</td>")
			if c != "" {
				if i < len(head) && head[i] != "" {
					c = head[i] + ": " + c
				}
				tl = append(tl, c)
			}
		}
		rb.WriteString("</tr>\n")
		if w.full(rb.Len() + 10) {
			break
		}
		w.html.WriteString(rb.String())
		w.text.WriteString("- " + strings.Join(tl, "; ") + "\n")
	}
	w.html.WriteString("</table>\n")
	w.text.WriteString("\n")
}

// render returns the plain-text and the HTML body of d with the link line, and whether d was cut to fit.
func (d *Doc) render(link string) (text, body string, cut bool) {
	w := &docWriter{}
	w.para(d.Heading, "h1")
	for _, p := range d.Intro {
		w.para(p, "")
	}
	for _, s := range d.Sections {
		if w.cut {
			break
		}
		w.para(docText(s.Title, maxDocTitle), "h2")
		for _, p := range s.Paragraphs {
			w.para(p, "")
		}
		for _, t := range s.Tables {
			w.table(t)
		}
		w.para(s.More, "")
	}
	cut = w.cut
	w.cut = false // the closing lines always fit: the cap leaves room for them
	if cut {
		w.text.WriteString(docCut + "\n\n")
		w.html.WriteString(`<p style="margin:16px 0 8px;font-weight:bold">` + html.EscapeString(docCut) + "</p>\n")
	}
	if link != "" {
		w.text.WriteString("Open the report in Vedette: " + link + "\n\n")
		w.html.WriteString(`<p style="margin:16px 0 8px"><a href="` + html.EscapeString(link) + `">Open the report in Vedette</a></p>` + "\n")
	} else {
		w.text.WriteString(openVedetteLine + "\n\n")
		w.html.WriteString(`<p style="margin:16px 0 8px">` + html.EscapeString(openVedetteLine) + "</p>\n")
	}
	if f := docText(d.Footer, maxDocCell); f != "" {
		w.text.WriteString(f + "\n")
		w.html.WriteString(`<p style="margin:16px 0 0;color:#666;font-size:12px">` + html.EscapeString(f) + "</p>\n")
	}
	w.text.WriteString("\nThis email was sent automatically by Vedette on your company box.\n")
	page := `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head>` +
		`<body style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#222;line-height:1.45;max-width:860px;margin:0 auto;padding:16px">` + "\n" +
		w.html.String() + `<p style="margin:16px 0 0;color:#666;font-size:12px">This email was sent automatically by Vedette on your company box.</p>` + "\n</body></html>\n"
	return w.text.String(), page, cut
}
