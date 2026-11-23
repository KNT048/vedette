package channel

import (
	"fmt"
	"html"
	"io"
	"mime/quotedprintable"
	"strings"
)

// Doc is a document an email carries whole (the periodic report): a heading, short paragraphs and sections of paragraphs and
// tables. Only the email channel renders it, as a multipart/alternative message: a plain-text part and an HTML part. Every string
// is untrusted: it is cleaned (control and format characters) and cut to a length, and the HTML part escapes it; the HTML has no
// script, no remote image or style, and no link except the message's own link to the box. The message stays small enough that mail
// clients show it whole (Gmail clips a message above about 102 KB behind "View entire message"): each table lists at most
// mailRowsMax rows and says how many more are on the report's page, and fit lowers that number until the sent message is at most
// maxDocMessage; every section heading and the link to the report are always in it.
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
	maxDocCell  = 400 // runes of one cell or paragraph
	maxDocTitle = 200 // runes of a heading or a caption
	// maxDocMessage is the most bytes the two encoded parts of a document's message may take together (headers and MIME lines add
	// about 1 KB, so the whole message stays under 90 KB): under the 102 KB at which Gmail clips a message.
	maxDocMessage = 88_000
)

// mailRows are the row limits per table fit tries, largest first; then budgets of raw bytes after which tables are left out.
var (
	mailRows    = []int{25, 15, 10, 5, 3}
	mailBudgets = []int{60_000, 40_000, 20_000, 0}
)

// docCut is the line a document ends with when whole tables had to be left out to fit an email.
const docCut = "This email has part of the report only. The whole report is on its page in Vedette."

// docStyle is the one style sheet of the HTML part (Gmail and Outlook read a <style> in the head): no style attribute per cell.
const docStyle = `body{font-family:Segoe UI,Helvetica,Arial,sans-serif;color:#222;line-height:1.4;max-width:860px;margin:0 auto;padding:12px}` +
	`h1{font-size:20px;margin:0 0 10px}h2{font-size:16px;margin:20px 0 6px;border-bottom:1px solid #ddd}p{margin:0 0 8px}` +
	`table{border-collapse:collapse;width:100%;margin:0 0 10px;font-size:13px}caption{text-align:left;font-weight:bold;padding:4px 0}` +
	`th,td{text-align:left;vertical-align:top;border-bottom:1px solid #eee;padding:3px 5px}.m{color:#666;font-size:12px}`

func docText(s string, n int) string { return truncRunes(strings.TrimSpace(clean(s, false)), n) }

// docWriter renders a document as text and HTML at once, so both parts list the same tables and rows.
type docWriter struct {
	text, html strings.Builder
	rows       int // the most rows of one table
	budget     int // raw bytes of both parts after which tables are left out (0: no budget)
	cut        bool
}

func (w *docWriter) size() int { return w.text.Len() + w.html.Len() }

func (w *docWriter) over(next int) bool { return w.budget > 0 && w.size()+next > w.budget }

func (w *docWriter) para(s, tag string) {
	if s = docText(s, maxDocCell); s == "" {
		return
	}
	w.text.WriteString(s + "\n\n")
	open, end := "<p>", "</p>\n"
	switch tag {
	case "h1", "h2":
		open, end = "<"+tag+">", "</"+tag+">\n"
	case "m":
		open = `<p class="m">`
	}
	w.html.WriteString(open + html.EscapeString(s) + end)
}

// table writes at most w.rows rows of t and a line with how many more are on the report's page. It returns false when the budget
// left the whole table out.
func (w *docWriter) table(t DocTable) bool {
	if len(t.Rows) == 0 {
		return true
	}
	head := make([]string, len(t.Head))
	for i, h := range t.Head {
		head[i] = docText(h, maxDocTitle)
	}
	var hb, tb strings.Builder
	hb.WriteString("<table>")
	if c := docText(t.Caption, maxDocTitle); c != "" {
		hb.WriteString("<caption>" + html.EscapeString(c) + "</caption>")
		tb.WriteString(c + "\n")
	}
	hb.WriteString("<tr>")
	for _, h := range head {
		hb.WriteString("<th>" + html.EscapeString(h) + "</th>")
	}
	hb.WriteString("</tr>\n")
	if w.over(hb.Len() + tb.Len()) {
		w.cut = true
		return false
	}
	w.html.WriteString(hb.String())
	w.text.WriteString(tb.String())
	n := 0
	for _, row := range t.Rows {
		if n == w.rows {
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
			rb.WriteString("<td>" + html.EscapeString(c) + "</td>")
			if c != "" {
				if i < len(head) && head[i] != "" {
					c = head[i] + ": " + c
				}
				tl = append(tl, c)
			}
		}
		rb.WriteString("</tr>\n")
		line := "- " + strings.Join(tl, "; ") + "\n"
		if n > 0 && w.over(rb.Len()+len(line)) {
			break
		}
		w.html.WriteString(rb.String())
		w.text.WriteString(line)
		n++
	}
	w.html.WriteString("</table>\n")
	if more := len(t.Rows) - n; more > 0 {
		w.para(fmt.Sprintf("%d more on the report page.", more), "m")
	} else {
		w.text.WriteString("\n")
	}
	return true
}

// render returns the plain-text and the HTML body of d with the link line, each table listing at most rows rows.
func (d *Doc) render(link string, rows, budget int) (text, body string) {
	w := &docWriter{rows: rows, budget: budget}
	w.para(d.Heading, "h1")
	for _, p := range d.Intro {
		w.para(p, "")
	}
	for _, s := range d.Sections { // every heading and paragraph is written: only tables give way to the budget
		w.para(docText(s.Title, maxDocTitle), "h2")
		for _, p := range s.Paragraphs {
			w.para(p, "")
		}
		left := 0
		for _, t := range s.Tables {
			if !w.table(t) {
				left++
			}
		}
		if left > 0 {
			w.para(fmt.Sprintf("%d more tables of this section are on the report page.", left), "m")
		}
		w.para(s.More, "")
	}
	if w.cut {
		w.text.WriteString(docCut + "\n\n")
		w.html.WriteString("<p><b>" + html.EscapeString(docCut) + "</b></p>\n")
	}
	if link != "" {
		w.text.WriteString("Open the report in Vedette: " + link + "\n\n")
		w.html.WriteString(`<p><a href="` + html.EscapeString(link) + `">Open the report in Vedette</a></p>` + "\n")
	} else {
		w.para(openVedetteLine, "")
	}
	w.para(d.Footer, "m")
	w.text.WriteString("This email was sent automatically by Vedette on your company box.\n")
	page := `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>` + docStyle + `</style></head><body>` + "\n" +
		w.html.String() + `<p class="m">This email was sent automatically by Vedette on your company box.</p>` + "\n</body></html>\n"
	return w.text.String(), page
}

// fit renders d with the most rows per table, then the largest budget, that keep the encoded message within maxDocMessage.
func (d *Doc) fit(link string) (text, body string) {
	for _, rows := range mailRows {
		if text, body = d.render(link, rows, 0); qpSize(text)+qpSize(body) <= maxDocMessage {
			return text, body
		}
	}
	for _, b := range mailBudgets {
		if text, body = d.render(link, mailRows[len(mailRows)-1], max(b, 1)); qpSize(text)+qpSize(body) <= maxDocMessage {
			return text, body
		}
	}
	return text, body
}

// qpSize is how many bytes s takes quoted-printable, as the message carries it.
func qpSize(s string) int {
	var c countWriter
	w := quotedprintable.NewWriter(&c)
	_, _ = io.WriteString(w, s)
	_ = w.Close()
	return int(c)
}

type countWriter int

func (c *countWriter) Write(p []byte) (int, error) { *c += countWriter(len(p)); return len(p), nil }
