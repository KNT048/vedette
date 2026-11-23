package channel

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"
)

// parts reads a multipart/alternative email into its parts by content type, decoded.
func parts(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	m, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	mt, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("content type %q, %v", m.Header.Get("Content-Type"), err)
	}
	out := map[string]string{}
	r := multipart.NewReader(m.Body, params["boundary"])
	for {
		p, err := r.NextPart() // decodes quoted-printable
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(p)
		if err != nil {
			t.Fatal(err)
		}
		pt, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
		out[pt] = string(b)
	}
	return out
}

func reportDoc(rows int) *Doc {
	t := DocTable{Caption: "fw-01 · 1 finding", Head: []string{"Finding", "Status and why"}}
	for i := range rows {
		t.Rows = append(t.Rows, []string{fmt.Sprintf("CVE-2026-%d · FortiOS 7.2.0", 1000+i), "Exploited in the wild. Exploited in the wild: CISA KEV (4 Mar); fix by 25 Mar 2025"})
	}
	return &Doc{Heading: "Security report", Intro: []string{"Acme · 16 Nov 2026 – 22 Nov 2026"},
		Sections: []DocSection{{Title: "Summary", Paragraphs: []string{"Open now: 1."}}, {Title: "Still open", Tables: []DocTable{t}}, {Title: "Coverage", Paragraphs: []string{"Devices: 2."}}},
		Footer:   "Made by Vedette 23 Nov 2026 08:00 (Asia/Ho_Chi_Minh)."}
}

// A report mail carries the report: a plain-text part and an HTML part with the same sections, the HTML escaped (a device name from the
// network cannot add markup, a script or a remote image) and the only link the box's own.
func TestEmailOfADocumentIsHTMLWithATextAlternative(t *testing.T) {
	d := reportDoc(1)
	d.Sections[1].Tables[0].Rows[0][0] = `CVE-2026-1 on <img src="https://evil.example/x.png"><script>alert(1)</script>`
	m := Message{Kind: "report", Severity: "info", Title: "Security report: 1 open", Link: "https://box.example:8443/reports/sent/rep-1", Doc: d}
	raw, err := buildMIME("alerts@acme.example", []string{"it@acme.example"}, m.norm(), m.Link, time.Date(2026, 11, 23, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	p := parts(t, raw)
	text, page := p["text/plain"], p["text/html"]
	for _, want := range []string{"Security report", "Summary", "Still open", "Coverage", "Exploited in the wild: CISA KEV (4 Mar); fix by 25 Mar 2025",
		"https://box.example:8443/reports/sent/rep-1", "Made by Vedette"} {
		if !strings.Contains(text, want) || !strings.Contains(page, strings.ReplaceAll(want, "&", "&amp;")) {
			t.Errorf("%q missing from a part", want)
		}
	}
	if strings.Contains(page, "<script") || strings.Contains(page, "<img") || !strings.Contains(page, "&lt;script&gt;") {
		t.Errorf("network text is not escaped in the HTML part")
	}
	if strings.Count(page, "href=") != 1 || !strings.Contains(page, `href="https://box.example:8443/reports/sent/rep-1"`) || strings.Contains(page, "src=\"http") {
		t.Errorf("the HTML part links anywhere but the box, or loads something remote")
	}
}

// A report too big for a mail stops at a row and says the rest is on the report's page, the link always present.
func TestEmailOfAHugeDocumentIsCutWithTheLink(t *testing.T) {
	m := Message{Kind: "report", Severity: "info", Title: "Security report", Link: "https://box.example:8443/reports/sent/rep-2", Doc: reportDoc(20_000)}
	raw, err := buildMIME("alerts@acme.example", []string{"it@acme.example"}, m.norm(), m.Link, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p := parts(t, raw)
	for typ, body := range p {
		if !strings.Contains(body, docCut) || !strings.Contains(body, "https://box.example:8443/reports/sent/rep-2") {
			t.Errorf("%s: no cut line or no link", typ)
		}
	}
	if n := len(p["text/html"]); n > maxDocHTML+10_000 {
		t.Errorf("the HTML part is %d bytes, over the cap", n)
	}
	if strings.Contains(p["text/html"], "Coverage") {
		t.Errorf("a section after the cut is in the mail")
	}
}

// Every other message is the plain-text mail it was.
func TestEmailWithoutADocumentIsPlainText(t *testing.T) {
	m := Message{Kind: "vuln", Severity: "high", Title: "t", What: "w"}
	raw, err := buildMIME("alerts@acme.example", []string{"it@acme.example"}, m.norm(), "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "Content-Type: text/plain; charset=utf-8") || strings.Contains(string(raw), "multipart") {
		t.Fatalf("mail = %s", raw)
	}
}
