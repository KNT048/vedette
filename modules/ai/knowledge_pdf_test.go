package ai_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/pdftext/pdftexttest"
)

// PDF in the knowledge base (S-AI-7, INV-10, D-264): the text is read by core/pdftext in a limited child process. These tests start
// the real child (pdftexttest.BuildChild registers one per process), so none of them may run in parallel with another that does.

// pdfWith is a one-page PDF with the given trailer extras (for example an /Encrypt entry) and text as its only content.
func pdfWith(text, trailerExtra string) []byte {
	var b bytes.Buffer
	offs := map[int]int{}
	b.WriteString("%PDF-1.4\n")
	obj := func(n int, body string) {
		offs[n] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", n, body)
	}
	content := "BT /F1 12 Tf 72 700 Td (" + text + ") Tj ET"
	obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>")
	obj(4, fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content))
	obj(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	xref := b.Len()
	b.WriteString("xref\n0 6\n0000000000 65535 f \n")
	for n := 1; n <= 5; n++ {
		fmt.Fprintf(&b, "%010d 00000 n \n", offs[n])
	}
	fmt.Fprintf(&b, "trailer\n<< /Size 6 /Root 1 0 R %s >>\nstartxref\n%d\n%%%%EOF\n", trailerExtra, xref)
	return b.Bytes()
}

func TestContract_INV10_APDFIsReadAndSearchable(t *testing.T) {
	pdftexttest.BuildChild(t)
	a := newAPI(t)
	a.kbIndexProfile()
	d := a.kbAdd("diagram.PDF", pdfWith("The core switch sits in the basement rack", ""), "")
	if d["status"] != "ready" || d["chunks"] != float64(1) {
		t.Fatalf("pdf = %v", d)
	}
	if n := a.count(`SELECT COUNT(*) FROM ai_knowledge_chunk_fts WHERE ai_knowledge_chunk_fts MATCH 'basement'`); n != 1 {
		t.Fatalf("%d chunks match the PDF's text", n)
	}
	if rows := strings.Join(a.auditRows(), "\n"); strings.Contains(rows, "ai.knowledge.failed") {
		t.Fatalf("audit: %s", rows)
	}
}

func TestContract_INV10_ANonPDFWithAPDFNameIsRefusedAtUpload(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile()
	_, m, raw := a.do("POST", "/ai/knowledge", "admin", kbBody("notes.pdf", []byte("just some text"), ""))
	msg, _ := m["error"].(map[string]any)["message"].(string)
	if errCode(m) != "invalid_content" || !strings.Contains(msg, "not a PDF") || !strings.Contains(msg, "Only PDF, MD, TXT and DOCX") {
		t.Fatalf("fake pdf = %s", raw)
	}
	if n := a.count(`SELECT COUNT(*) FROM ai_knowledge_doc`); n != 0 {
		t.Fatalf("%d documents saved", n)
	}
}

func TestContract_INV10_APasswordPDFEndsReadyWithNoChunksAndSaysWhy(t *testing.T) {
	pdftexttest.BuildChild(t)
	a := newAPI(t)
	a.kbIndexProfile()
	enc := pdfWith("secret", "/Encrypt << /Filter /Standard /V 1 /R 2 /O (12345678901234567890123456789012) /U (12345678901234567890123456789012) /P -4 >> /ID [(a)(a)]")
	d := a.kbAdd("locked.pdf", enc, "")
	if d["status"] != "ready" || d["chunks"] != float64(0) {
		t.Fatalf("encrypted pdf = %v", d)
	}
	if rows := strings.Join(a.auditRows(), "\n"); !strings.Contains(rows, "ai.knowledge.failed locked.pdf the PDF is protected with a password; remove the password and upload it again") {
		t.Fatalf("audit: %s", rows)
	}
}

func TestContract_INV10_AHostilePDFEndsUnreadAndTheBoxKeepsWorking(t *testing.T) {
	pdftexttest.BuildChild(t)
	a := newAPI(t)
	a.kbIndexProfile()
	huge := []byte("%PDF-1.4\nxref\n0 4000000000\n0000000000 65535 f \ntrailer\n<< /Size 4000000000 /Root 1 0 R >>\nstartxref\n9\n%%EOF\n")
	// a classic table whose trailer /Prev points back at the same table: the library loops for ever on it
	loop := []byte("%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R /Prev 60 >>\nstartxref\n60\n%%EOF\n")
	for name, data := range map[string][]byte{"huge.pdf": huge, "loop.pdf": loop} {
		d := a.kbAdd(name, data, "")
		if d["status"] != "ready" || d["chunks"] != float64(0) {
			t.Fatalf("%s = %v", name, d)
		}
	}
	rows := strings.Join(a.auditRows(), "\n")
	for _, name := range []string{"huge.pdf", "loop.pdf"} {
		if !strings.Contains(rows, "ai.knowledge.failed "+name+" ") {
			t.Errorf("audit lacks %s: %s", name, rows)
		}
	}
	if strings.Contains(rows, "panic") || strings.Contains(rows, "goroutine") {
		t.Fatalf("the child's own text reached the audit: %s", rows)
	}
	if d := a.kbAdd("after.pdf", pdfWith("Backups run at night", ""), ""); d["chunks"] != float64(1) {
		t.Fatalf("after the hostile files = %v", d)
	}
}

func TestContract_INV10_WithoutAPDFChildTheDocumentEndsUnreadWithAClearReason(t *testing.T) {
	a := newAPI(t) // no pdftexttest.BuildChild: this test binary registers no child
	a.kbIndexProfile()
	d := a.kbAdd("plain.pdf", pdfWith("text", ""), "")
	if d["status"] != "ready" || d["chunks"] != float64(0) {
		t.Fatalf("pdf without a child = %v", d)
	}
	if rows := strings.Join(a.auditRows(), "\n"); !strings.Contains(rows, "ai.knowledge.failed plain.pdf the PDF reader is not available on this box") {
		t.Fatalf("audit: %s", rows)
	}
}
