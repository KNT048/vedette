package pdftext

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	osexec "os/exec" //nolint:depguard // test harness: builds the test child and starts it with fixed argv, no shell; SYS-1 is about the product
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The tests run the real child: TestMain builds testdata/child (the same ChildMain as `vedette pdftext`) once, without -race, and
// points childPath at it. Every PDF below is hand-made in code so the offsets of its xref stay right; the hostile ones are the
// samples of the review of #323 (a Go fatal error or an endless loop in the library).

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pdftext-child")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	exe := filepath.Join(dir, "child")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	build := osexec.CommandContext(ctx, "go", "build", "-o", exe, "./testdata/child") //nolint:gosec // fixed argv, a test helper
	build.Env = append(os.Environ(), "GOFLAGS=")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building the test child: %v\n%s", err, out)
		os.Exit(1)
	}
	childPath = func() (string, error) { return exe, nil }
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// pdfBuilder writes objects and the offsets of their "n 0 obj" lines.
type pdfBuilder struct {
	buf  bytes.Buffer
	offs map[int]int
}

func newPDF(version string) *pdfBuilder {
	b := &pdfBuilder{offs: map[int]int{}}
	b.buf.WriteString("%PDF-" + version + "\n")
	return b
}

func (b *pdfBuilder) obj(n int, body string) {
	b.offs[n] = b.buf.Len()
	fmt.Fprintf(&b.buf, "%d 0 obj\n%s\nendobj\n", n, body)
}

func (b *pdfBuilder) stream(n int, dict string, data []byte) {
	b.offs[n] = b.buf.Len()
	fmt.Fprintf(&b.buf, "%d 0 obj\n<< %s /Length %d >>\nstream\n", n, dict, len(data))
	b.buf.Write(data)
	b.buf.WriteString("\nendstream\nendobj\n")
}

func (b *pdfBuilder) tail(startxref int) []byte {
	fmt.Fprintf(&b.buf, "startxref\n%d\n%%%%EOF\n", startxref)
	return b.buf.Bytes()
}

// xrefEntry is a row of an xref stream with W [1 2 1]: kind 1 = offset, kind 2 = (stream number, index in it).
func xrefEntry(kind byte, a int, c byte) []byte {
	return []byte{kind, byte(a >> 8 & 0xff), byte(a & 0xff), c}
}

// normalPDF is a small valid file whose page says text.
func normalPDF(text string) []byte {
	return pagePDF([]byte("BT /F1 12 Tf 72 700 Td (" + text + ") Tj ET"))
}

// pagePDF is a one-page file with the given content stream and a Helvetica font as /F1.
func pagePDF(content []byte) []byte {
	b := newPDF("1.4")
	b.obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	b.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	b.obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>")
	b.stream(4, "", content)
	b.obj(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	xref := b.buf.Len()
	var x strings.Builder
	x.WriteString("xref\n0 6\n0000000000 65535 f \n")
	for n := 1; n <= 5; n++ {
		fmt.Fprintf(&x, "%010d 00000 n \n", b.offs[n])
	}
	b.buf.WriteString(x.String())
	b.buf.WriteString("trailer\n<< /Size 6 /Root 1 0 R >>\n")
	return b.tail(xref)
}

// xrefStreamPDF is a file whose only structure is an xref stream (object 1) with the given dictionary extras and rows.
func xrefStreamPDF(extra string, size int, rows ...[]byte) []byte {
	b := newPDF("1.5")
	b.stream(1, fmt.Sprintf("/Type /XRef /Size %s /W [1 2 1] %s", fmt.Sprint(size), extra), bytes.Join(rows, nil))
	return b.tail(b.offs[1])
}

func hostile() map[string][]byte {
	free := xrefEntry(0, 0, 255)
	self := xrefEntry(1, 9, 0) // object 1 is the xref stream, at offset 9

	// 251-byte class: an xref stream that claims four billion objects. make([]xref, size) asks for ~100 GB.
	hugeSize := []byte("%PDF-1.5\n1 0 obj\n<< /Type /XRef /Size 4000000000 /W [1 2 1] /Length 0 >>\nstream\n\nendstream\nendobj\nstartxref\n9\n%%EOF\n")

	// A table xref that announces four billion rows.
	hugeTable := []byte("%PDF-1.4\nxref\n0 4000000000\n0000000000 65535 f \ntrailer\n<< /Size 4000000000 /Root 1 0 R >>\nstartxref\n9\n%%EOF\n")

	// A row that starts at object 3e9: ensureXrefLen grows the table to 3e9 entries (~70 GB).
	hugeStart := []byte("%PDF-1.4\nxref\n3000000000 1\n0000000009 00000 n \ntrailer\n<< /Size 1 /Root 1 0 R >>\nstartxref\n9\n%%EOF\n")

	// The startxref points 3e9 bytes into a 150-byte file.
	farStart := append(bytes.TrimRight(normalPDF("x")[:100], "\x00"), []byte("\nstartxref\n3000000000\n%%EOF\n")...)

	// Object 2 (the root) lives in object stream 3, and object stream 3 lives in object stream 3: resolve recurses for ever.
	selfStream := xrefStreamPDF("/Root 2 0 R", 4, free, self, xrefEntry(2, 3, 0), xrefEntry(2, 3, 0))

	// Object 3 is a real object stream with /Extends pointing at itself and no object in it; the root is in it.
	b := newPDF("1.5")
	b.stream(3, "/Type /ObjStm /N 0 /First 1 /Extends 3 0 R", nil)
	xrefAt := b.buf.Len()
	b.stream(1, "/Type /XRef /Size 4 /W [1 2 1] /Root 2 0 R", bytes.Join([][]byte{free, xrefEntry(1, xrefAt, 0), xrefEntry(2, 3, 0), xrefEntry(1, b.offs[3], 0)}, nil))
	extends := b.tail(xrefAt)

	// An xref stream whose /Prev is itself: the chain never ends.
	prevStream := xrefStreamPDF("/Prev 9", 2, free, self)

	// A classic table whose trailer /Prev points at the same table.
	t := newPDF("1.4")
	t.obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	tx := t.buf.Len()
	fmt.Fprintf(&t.buf, "xref\n0 2\n0000000000 65535 f \n%010d 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R /Prev %d >>\n", t.offs[1], tx)
	prevTable := t.tail(tx)

	return map[string][]byte{
		"huge-xref-stream-size": hugeSize, "huge-xref-table": hugeTable, "huge-xref-row-start": hugeStart, "startxref-3e9": farStart,
		"self-containing-objstm": selfStream, "extends-self": extends,
		"prev-self-stream": prevStream, "prev-self-table": prevTable,
	}
}

func TestNormalPDFReturnsItsText(t *testing.T) {
	text, err := PDFText(context.Background(), bytes.NewReader(normalPDF("Hello Vedette")))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "Hello Vedette") {
		t.Fatalf("text = %q", text)
	}
}

// Each hostile file must end in ErrLimit or ErrCrashed (or a clean refusal), never take the test process down, and within the time
// the limits allow. The wall clock is shortened to 3 s here; the CPU limit has its own test.
func TestHostilePDFsDoNotKillTheCaller(t *testing.T) {
	defer func(d time.Duration) { wallLimit = d }(wallLimit)
	wallLimit = 3 * time.Second
	for name, data := range hostile() {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			text, err := PDFText(context.Background(), bytes.NewReader(data))
			took := time.Since(start)
			t.Logf("%s: %d bytes -> err=%v text=%d bytes in %v", name, len(data), err, len(text), took)
			if !errors.Is(err, ErrLimit) && !errors.Is(err, ErrCrashed) && !errors.Is(err, ErrNotPDF) {
				t.Fatalf("err = %v, want ErrLimit, ErrCrashed or ErrNotPDF", err)
			}
			if took > wallLimit+3*time.Second {
				t.Fatalf("took %v with a wall limit of %v", took, wallLimit)
			}
		})
	}
}

// The files that must fail on a limit, not by luck of a clean refusal: the fatal ones are ErrCrashed, the endless ones ErrLimit.
func TestHostileKindsOfFailure(t *testing.T) {
	defer func(d time.Duration) { wallLimit = d }(wallLimit)
	wallLimit = 3 * time.Second
	h := hostile()
	for name, want := range map[string]error{
		"huge-xref-stream-size": ErrCrashed, "self-containing-objstm": ErrCrashed,
		"extends-self": ErrLimit, "prev-self-stream": ErrLimit, "prev-self-table": ErrLimit,
	} {
		if _, err := PDFText(context.Background(), bytes.NewReader(h[name])); !errors.Is(err, want) {
			t.Errorf("%s: err = %v, want %v", name, err, want)
		}
	}
}

// RLIMIT_CPU is the second line (the first is the wall clock): with the wall clock out of the way, an endless loop is stopped by the
// kernel after 60 s of CPU.
func TestCPULimitStopsAnEndlessLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("takes 60 s")
	}
	defer func(d time.Duration) { wallLimit = d }(wallLimit)
	wallLimit = 5 * time.Minute
	start := time.Now()
	_, err := PDFText(context.Background(), bytes.NewReader(hostile()["prev-self-stream"]))
	took := time.Since(start)
	if !errors.Is(err, ErrLimit) || took > 90*time.Second || took < 30*time.Second {
		t.Fatalf("err = %v after %v, want ErrLimit after about 60 s of CPU", err, took)
	}
}

func TestNotAPDFAndEncryptedAndInputCap(t *testing.T) {
	if _, err := PDFText(context.Background(), strings.NewReader("hello")); !errors.Is(err, ErrNotPDF) {
		t.Fatalf("plain text: %v", err)
	}
	if _, err := PDFText(context.Background(), strings.NewReader("%PDF-1.4\nnonsense")); !errors.Is(err, ErrNotPDF) {
		t.Fatalf("a header and nonsense: %v", err)
	}
	big := append([]byte("%PDF-1.4\n"), make([]byte, MaxInput)...)
	if _, err := PDFText(context.Background(), bytes.NewReader(big)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over the input cap: %v", err)
	}
	atCap := append([]byte("%PDF-1.4\n"), make([]byte, MaxInput-9)...)
	if _, err := PDFText(context.Background(), bytes.NewReader(atCap)); !errors.Is(err, ErrNotPDF) { // read, refused as not readable
		t.Fatalf("exactly the input cap: %v", err)
	}
}

// The child enforces the input cap on its own, not only through the parent (it is a subcommand anyone with the binary can run).
func TestChildRefusesOversizeInputItself(t *testing.T) {
	exe, _ := childPath()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := osexec.CommandContext(ctx, exe) //nolint:gosec // the test child built by TestMain
	cmd.Stdin = bytes.NewReader(append([]byte("%PDF-1.4\n"), make([]byte, MaxInput)...))
	err := cmd.Run()
	var ee *osexec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != ExitTooLarge {
		t.Fatalf("err = %v, want exit %d", err, ExitTooLarge)
	}
}

// A page whose text is longer than MaxText comes back cut at MaxText, valid UTF-8, with ErrTruncated and the text.
func TestOutputIsCappedAtMaxText(t *testing.T) {
	line := strings.Repeat("ab", 1000)
	var content strings.Builder
	content.WriteString("BT /F1 12 Tf 72 700 Td ")
	for range 3000 { // 6 MB of text
		fmt.Fprintf(&content, "(%s) Tj T* ", line)
	}
	content.WriteString("ET")
	data := pagePDF([]byte(content.String()))
	if len(data) > MaxInput {
		t.Fatalf("test file is %d bytes", len(data))
	}
	text, err := PDFText(context.Background(), bytes.NewReader(data))
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("err = %v", err)
	}
	if len(text) == 0 || len(text) > MaxText {
		t.Fatalf("len(text) = %d, want 1..%d", len(text), MaxText)
	}
}

func TestArgvIsExactlyTheSubcommand(t *testing.T) {
	if validArgs([]string{Subcommand}) != nil {
		t.Fatal("the subcommand is refused")
	}
	for _, a := range [][]string{nil, {}, {"pdftext", "x"}, {"healthcheck"}, {"-db", "x"}} {
		if validArgs(a) == nil {
			t.Fatalf("argv %q accepted", a)
		}
	}
}

func TestCancelledContextReturnsItsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PDFText(ctx, bytes.NewReader(normalPDF("x"))); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}
