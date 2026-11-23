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

// fullReport is a report at its largest: seven sections, three of them with 100-row tables of long names and reasons.
func fullReport() *Doc {
	long := func(i int, what string) string {
		return fmt.Sprintf("%s %d — %s", what, i, strings.Repeat("Exploited in the wild: CISA KEV (4 Mar) · Rapid7, Mandiant (5 Mar); fix by 25 Mar 2025 ", 3))
	}
	table := func(name string) DocTable {
		t := DocTable{Caption: name + " · 100 findings", Head: []string{"Finding", "Device", "Status", "Why", "How Vedette knows", "Severity", "Fix", "First seen"}}
		for i := range 100 {
			t.Rows = append(t.Rows, []string{fmt.Sprintf("CVE-2026-%d · VMware vCenter Server 8.0.2.00100 build 22385739", 10000+i),
				fmt.Sprintf("hypervisor-cluster-node-%03d.datacenter-east.corp.example (192.0.2.%d)", i, i%250), "Exploited in the wild", long(i, "reasons"),
				"Not confirmed yet: based on a version someone entered", "Critical 9.8", "Update VMware vCenter Server to 8.0.3.00400", "24 Nov 2026"})
		}
		return t
	}
	return &Doc{Heading: "Security report", Intro: []string{"Acme Corporation · 17 Nov 2026 – 23 Nov 2026"},
		Sections: []DocSection{
			{Title: "Summary", Paragraphs: []string{"Open now: 300 (280 at the start of the period). New this period: 100. Handled this period: 100."}},
			{Title: "Handled this period", Tables: []DocTable{table("Handled")}},
			{Title: "Still open", Tables: []DocTable{table("hypervisor-cluster-node-001")}, More: "200 more open findings are not listed."},
			{Title: "New this period", Tables: []DocTable{table("New")}},
			{Title: "External exposure", Paragraphs: []string{"External exposure scanning is off, so this report does not cover what the Internet sees."}},
			{Title: "Detections", Paragraphs: []string{"Nothing was detected in this period."}},
			{Title: "Coverage", Paragraphs: []string{"Devices: 412. With an agent: 37 of 412. Not added yet: 12."}},
		}, Footer: "Made by Vedette 24 Nov 2026, 08:00 (Asia/Ho_Chi_Minh)."}
}

// A full-size report fits a mail client whole: Gmail clips a message above about 102 KB behind "View entire message", which hid the
// later sections and the link (a 3 x 100-row report was about 278 KB). The sent message is at most 90 KB, every section heading and
// the link are in both parts, and each table says how many of its rows are on the report page.
func TestEmailOfAFullReportFitsAMailClient(t *testing.T) {
	m := Message{Kind: "report", Severity: "info", Title: "Security report: 300 open", Link: "https://box.example:8443/reports/sent/rep-2", Doc: fullReport()}
	raw, err := buildMIME("alerts@acme.example", []string{"it@acme.example"}, m.norm(), m.Link, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sent message: %d bytes", len(raw))
	if len(raw) > 90_000 {
		t.Fatalf("the sent message is %d bytes, over 90 KB: a mail client clips it", len(raw))
	}
	p := parts(t, raw)
	for typ, body := range p {
		for _, want := range []string{"Summary", "Handled this period", "Still open", "New this period", "External exposure", "Detections", "Coverage",
			"https://box.example:8443/reports/sent/rep-2", "200 more open findings are not listed.", "Made by Vedette"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: %q missing", typ, want)
			}
		}
		if strings.Count(body, "more on the report page.") != 3 {
			t.Errorf("%s: each of the three tables says how many rows are on the report page", typ)
		}
		if strings.Contains(body, docCut) {
			t.Errorf("%s: whole tables were left out of a report that fits with fewer rows", typ)
		}
	}
	if strings.Count(p["text/html"], "<tr>") != strings.Count(p["text/plain"], "\n- ")+3 { // a header row per table
		t.Errorf("the parts list different rows: %d HTML rows, %d text rows", strings.Count(p["text/html"], "<tr>"), strings.Count(p["text/plain"], "\n- "))
	}
	if strings.Contains(p["text/html"], " style=") {
		t.Error("the HTML part repeats inline styles: one style sheet in the head is enough")
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

// Both parts stop at the same place: a table that no longer fits leaves no caption behind in the text part.
func TestEmailOfACutDocumentHasTheSameTablesInBothParts(t *testing.T) {
	var sec DocSection
	sec.Title = "Still open"
	for i := range 2000 {
		sec.Tables = append(sec.Tables, DocTable{Caption: fmt.Sprintf("device-%04d %s", i, strings.Repeat("x", 180)),
			Head: []string{strings.Repeat("h", 150), strings.Repeat("i", 150)}, Rows: [][]string{{"a"}}})
	}
	m := Message{Kind: "report", Severity: "info", Title: "Security report", Link: "https://box.example:8443/reports/sent/rep-4",
		Doc: &Doc{Heading: "Security report", Sections: []DocSection{sec}}}
	raw, err := buildMIME("alerts@acme.example", []string{"it@acme.example"}, m.norm(), m.Link, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p := parts(t, raw)
	if !strings.Contains(p["text/html"], docCut) {
		t.Fatal("the document was not cut")
	}
	for i := range 2000 {
		c := fmt.Sprintf("device-%04d ", i)
		if strings.Contains(p["text/plain"], c) != strings.Contains(p["text/html"], c) {
			t.Fatalf("%q is in one part only", c)
		}
	}
}
