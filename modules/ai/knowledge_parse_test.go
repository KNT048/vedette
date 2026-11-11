package ai

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// The readers of the knowledge base (S-AI-7, INV-10, SYS-6): good files, hostile files, files that are too large. Each reader also has
// a fuzz target (go test -fuzz FuzzDocx ./modules/ai).

func docx(parts map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range parts {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(body))
	}
	_ = zw.Close()
	return buf.Bytes()
}

const wordNS = `xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"`

func wordDoc(body string) []byte {
	return docx(map[string]string{"word/document.xml": `<?xml version="1.0" encoding="UTF-8"?><w:document ` + wordNS + `><w:body>` + body + `</w:body></w:document>`})
}

func TestDocKind(t *testing.T) {
	for name, want := range map[string]string{"a.pdf": "pdf", "A.PDF": "pdf", "x.md": "md", "x.txt": "txt", "x.DOCX": "docx", "x.doc": "", "x": "", "x.pdf.exe": "", ".md": "md", "x.": ""} {
		if got := docKind(name); got != want {
			t.Errorf("docKind(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestDecodeText(t *testing.T) {
	for name, c := range map[string]struct {
		in   []byte
		want string
		bad  bool
	}{
		"utf-8":          {[]byte("Tường lửa"), "Tường lửa", false},
		"utf-8 bom":      {[]byte("\xEF\xBB\xBFhello"), "hello", false},
		"utf-16 le":      {[]byte{0xFF, 0xFE, 'h', 0, 'i', 0, 0xFD, 0x1E}, "hi\u1efd", false},
		"utf-16 be":      {[]byte{0xFE, 0xFF, 0, 'h', 0, 'i'}, "hi", false},
		"utf-16 odd":     {[]byte{0xFF, 0xFE, 'h'}, "", true},
		"utf-16 lone":    {[]byte{0xFF, 0xFE, 0x00, 0xD8}, "", true},
		"latin-1":        {[]byte("caf\xe9"), "", true},
		"nul":            {[]byte("a\x00b"), "", true},
		"empty":          {nil, "", false},
		"cut character":  {[]byte("ab\xe1\xbb"), "", true},
		"overlong slash": {[]byte("a\xc0\xafb"), "", true},
	} {
		got, err := decodeText(c.in)
		if (err != nil) != c.bad || (!c.bad && got != c.want) {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
}

func TestCleanDocText(t *testing.T) {
	in := "  Hello\t\tworld \u202Eevil\u202C\u200b\u2060 text\x00\x07\r\n\r\n\r\n\r\nNext\u2028line\u00ADx\uFEFF  "
	got := cleanDocText(in)
	want := "Hello world evil text\n\nNext\nlinex"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := cleanDocText("Tiếng Việt: ừ ờ ở"); got != "Tiếng Việt: ừ ờ ở" {
		t.Fatalf("Vietnamese was changed: %q", got)
	}
	if got := cleanDocText("é ạ"); got != "é ạ" {
		t.Fatalf("combining marks were dropped: %q", got)
	}
}

func TestExtractTextMarkdownAndTxt(t *testing.T) {
	for _, k := range []string{"md", "txt"} {
		text, trunc, err := extractText(t.Context(), k, []byte("# Title\n\nFirst   line.\n\n\n\nSecond \u202Eline."))
		if err != nil || trunc || text != "# Title\n\nFirst line.\n\nSecond line." {
			t.Errorf("%s: %q %v %v", k, text, trunc, err)
		}
	}
	if _, _, err := extractText(t.Context(), "txt", []byte(" \n\u200b \t")); !errors.Is(err, errDocEmpty) {
		t.Errorf("blank text: %v", err)
	}
	big := bytes.Repeat([]byte("Tường lửa chính. "), maxStoredText/10)
	text, trunc, err := extractText(t.Context(), "txt", big)
	if err != nil || !trunc || len(text) > maxStoredText || !utf8.ValidString(text) {
		t.Errorf("big text: %d %v %v %v", len(text), trunc, utf8.ValidString(text), err)
	}
}

func TestDocxGood(t *testing.T) {
	d := wordDoc(`<w:p><w:r><w:t>Chính sách</w:t></w:r><w:r><w:tab/><w:t xml:space="preserve"> mật khẩu</w:t></w:r></w:p><w:p><w:r><w:t>Line two</w:t><w:br/><w:t>after break</w:t></w:r></w:p><w:p><w:del><w:r><w:delText>deleted</w:delText></w:r></w:del><w:r><w:instrText> HYPERLINK "x" </w:instrText></w:r></w:p>`)
	text, _, err := extractText(t.Context(), "docx", d)
	if err != nil || text != "Chính sách mật khẩu\nLine two\nafter break" {
		t.Fatalf("%q %v", text, err)
	}
}

func TestDocxHostile(t *testing.T) {
	bomb := make([]byte, 60<<20) // 60 MB of zeros compresses to about 60 KB
	cases := map[string]struct {
		data []byte
		want error
	}{
		"not a zip":        {append([]byte("PK\x03\x04"), bytes.Repeat([]byte{9}, 200)...), errDocBad},
		"no text part":     {docx(map[string]string{"word/styles.xml": "<a/>"}), errDocBad},
		"zip bomb":         {docx(map[string]string{"word/document.xml": string(bomb)}), errDocBomb},
		"nested too deep":  {wordDoc(strings.Repeat("<w:p>", docxXMLDepth+5)), errDocBomb},
		"unknown entity":   {wordDoc(`<w:p><w:r><w:t>&xxe;</w:t></w:r></w:p>`), errDocBad},
		"broken xml":       {wordDoc(`<w:p><w:r><w:t>unclosed`), errDocBad},
		"other charset":    {docx(map[string]string{"word/document.xml": `<?xml version="1.0" encoding="ISO-8859-9"?><a>x</a>`}), errDocBad},
		"doctype entities": {docx(map[string]string{"word/document.xml": `<!DOCTYPE d [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]><w:document ` + wordNS + `><w:t>&b;&b;&b;</w:t></w:document>`}), errDocBad},
	}
	for name, c := range cases {
		_, _, err := extractText(t.Context(), "docx", c.data)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	many := map[string]string{"word/document.xml": "<a/>"}
	for i := range docxEntries + 1 {
		many[fmt.Sprintf("f%d", i)] = "x"
	}
	if _, _, err := extractText(t.Context(), "docx", docx(many)); !errors.Is(err, errDocBomb) {
		t.Errorf("many entries: %v", err)
	}
	// text that packs far tighter than any document does is refused as well
	if _, _, err := extractText(t.Context(), "docx", docx(map[string]string{"word/document.xml": "<w:document " + wordNS + "><w:t>" + strings.Repeat("a", 30<<20) + "</w:t></w:document>"})); !errors.Is(err, errDocBomb) {
		t.Errorf("30 MB of one letter: %v", err)
	}
}

func TestChunkText(t *testing.T) {
	if got := chunkText(""); len(got) != 0 {
		t.Fatalf("empty = %q", got)
	}
	short := chunkText("One.\n\nTwo.\nThree.")
	if len(short) != 1 || short[0] != "One.\nTwo.\nThree." {
		t.Fatalf("short = %q", short)
	}
	var paras []string
	for i := range 40 {
		paras = append(paras, fmt.Sprintf("Mục %d: %s", i, strings.Repeat("tường lửa chính ", 30)))
	}
	cs := chunkText(strings.Join(paras, "\n"))
	if len(cs) < 5 {
		t.Fatalf("chunks = %d", len(cs))
	}
	var total int
	for _, c := range cs {
		if len(c) == 0 || len(c) > chunkBytes || !utf8.ValidString(c) || c != strings.TrimSpace(c) {
			t.Fatalf("bad chunk (%d bytes): %q", len(c), c)
		}
		total += strings.Count(c, "tường")
	}
	if total != 40*30 {
		t.Fatalf("words lost: %d", total)
	}
	// one paragraph longer than a chunk, with no space at all, in two-byte and three-byte characters
	for _, r := range []string{"ơ", "界"} {
		long := strings.Repeat(r, chunkBytes*3)
		parts := chunkText(long)
		var joined string
		for _, p := range parts {
			if len(p) > chunkBytes || !utf8.ValidString(p) {
				t.Fatalf("%q: bad part of %d bytes", r, len(p))
			}
			joined += p
		}
		if joined != long {
			t.Fatalf("%q: text lost", r)
		}
	}
}

func TestFTSQuery(t *testing.T) {
	for in, want := range map[string]string{
		"":                           "",
		"a b c":                      "",
		"Tường lửa":                  `"tường" OR "lửa"`,
		"backups backups BACKUPS":    `"backups"`,
		`NEAR(a bc, 3) OR "x" AND y`: `"near" OR "bc" OR "or" OR "and"`,
		`col:term "quoted"`:          `"col" OR "term" OR "quoted"`,
		"CVE-2022-27593":             `"cve" OR "2022" OR "27593"`,
		"x*  ^y -zz (ww)":            `"zz" OR "ww"`,
		"éa":                        "\"éa\"",
	} {
		if got := ftsQuery(in); got != want {
			t.Errorf("ftsQuery(%q) = %q, want %q", in, got, want)
		}
	}
	many := strings.Repeat("word", 1)
	var b strings.Builder
	for i := range 100 {
		fmt.Fprintf(&b, "%s%d ", many, i)
	}
	if got := strings.Count(ftsQuery(b.String()), " OR ") + 1; got != ragTerms {
		t.Errorf("terms = %d, want %d", got, ragTerms)
	}
}

var queryShape = regexp.MustCompile(`^("[^"\s]{2,}"( OR "[^"\s]{2,}"){0,23})?$`)

func FuzzFTSQuery(f *testing.F) {
	for _, s := range []string{"NEAR(a b)", `"x" OR`, "Tường lửa", "a:b", "\x00", "((("} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		q := ftsQuery(s)
		if !queryShape.MatchString(q) {
			t.Fatalf("ftsQuery(%q) = %q is not a list of quoted words", s, q)
		}
	})
}

// cleanOK says the text has nothing a reader cannot see.
func cleanOK(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			return false
		}
	}
	return true
}

func FuzzDecodeText(f *testing.F) {
	for _, s := range []string{"Tường lửa", "\xEF\xBB\xBFx", "\xFF\xFEa\x00", "\xFE\xFF\x00a", "\xff", "a\x00"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if got, err := decodeText(data); err == nil && !utf8.ValidString(got) {
			t.Fatalf("invalid UTF-8 out of %q", data)
		}
		if text, _, err := extractText(context.Background(), "txt", data); err == nil && (!cleanOK(text) || strings.TrimSpace(text) == "") {
			t.Fatalf("text %q out of %q", text, data)
		}
	})
}

func FuzzDocx(f *testing.F) {
	f.Add(wordDoc(`<w:p><w:r><w:t>Chính sách</w:t></w:r></w:p>`))
	f.Add(wordDoc(`<w:p><w:t>&amp;&#x1F600;&#0;</w:t></w:p>`))
	f.Add(docx(map[string]string{"word/document.xml": "<a>"}))
	f.Add([]byte("PK\x03\x04"))
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		text, _, err := extractText(ctx, "docx", data)
		if err == nil && (!cleanOK(text) || len(text) > maxStoredText) {
			t.Fatalf("bad text %q", text)
		}
	})
}

func FuzzChunkText(f *testing.F) {
	f.Add("A paragraph.\n\nAnother one. With sentences! And more?")
	f.Add(strings.Repeat("ơ", 5000))
	f.Add(strings.Repeat("word ", 2000))
	f.Fuzz(func(t *testing.T, s string) {
		clean := cleanDocText(s)
		var n int
		for _, c := range chunkText(clean) {
			if c == "" || len(c) > chunkBytes || !utf8.ValidString(c) {
				t.Fatalf("bad chunk %q", c)
			}
			n += len(c)
		}
		if n > len(clean) {
			t.Fatalf("chunks hold more than the text: %d > %d", n, len(clean))
		}
	})
}
