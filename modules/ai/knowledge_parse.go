package ai

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/ledongthuc/pdf"

	"github.com/knt048/vedette/core/observe"
)

// Reading a document of the knowledge base (S-AI-7, INV-10). A document is untrusted data (SYS-6): every reader fails closed, has a
// size cap and never runs anything in the file. Only text comes out; pictures, fonts and the file itself are dropped.

// Limits of the readers.
const (
	MaxDocBytes    = 10 << 20 // the file, as uploaded
	maxStoredText  = 4 << 20  // text kept per document: 50 documents hold at most 200 MB of chunk text
	chunkBytes     = 3200     // size of a chunk, as the mock's chunksOf
	docxEntries    = 2000     // entries in the archive; a Word file has a few dozen
	docxXMLBytes   = 50 << 20 // the text part, uncompressed: a zip bomb is stopped at this size
	docxRatio      = 200      // uncompressed to compressed size of the text part; Word text compresses 5 to 20 times
	docxXMLTokens  = 5_000_000
	docxXMLDepth   = 100
	pdfPages       = 3000
	pdfTimeout     = 60 * time.Second
	extractTimeout = 90 * time.Second
)

// Errors of the readers: each is a plain reason the audit row and the administrator can read.
var (
	errDocEmpty   = errors.New("no text was found in it (a scanned document or pictures only)")
	errDocBad     = errors.New("it could not be read as a document of its type")
	errDocBomb    = errors.New("it is too large when unpacked")
	errDocTimeout = errors.New("reading it took too long")
	errDocCrypt   = errors.New("it is protected with a password")
)

var pdfRunning atomic.Int32 // PDF readers in flight, those let go of after a timeout included

const pdfStuckMax = 3

// docKind is the type of a document, from the extension of its name: "pdf", "md", "txt" or "docx"; "" for any other.
func docKind(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return ""
	}
	switch k := strings.ToLower(name[i+1:]); k {
	case "pdf", "md", "txt", "docx":
		return k
	}
	return ""
}

// sniffDoc is the quick check made while the upload is answered: the bytes must look like the type the name claims. It reads
// nothing deep, so a file that passes can still fail in the indexer (the audit row says why).
func sniffDoc(kind string, data []byte) error {
	switch kind {
	case "pdf":
		if !bytes.Contains(data[:min(len(data), 1024)], []byte("%PDF-")) {
			return errors.New("this is not a PDF file")
		}
	case "docx":
		if !bytes.HasPrefix(data, []byte("PK\x03\x04")) {
			return errors.New("this is not a Word (DOCX) file")
		}
	default:
		if _, err := decodeText(data); err != nil {
			return err
		}
	}
	return nil
}

// decodeText reads a text file as UTF-8 (a BOM is dropped), or UTF-16 when it starts with a byte order mark (what Windows Notepad
// calls "Unicode"). Any other bytes are refused: guessing an old Vietnamese code page (TCVN3, Windows-1258) would store
// scrambled text without anyone seeing it.
func decodeText(data []byte) (string, error) {
	var s string
	switch {
	case bytes.HasPrefix(data, []byte{0xFF, 0xFE}), bytes.HasPrefix(data, []byte{0xFE, 0xFF}):
		le := data[0] == 0xFF
		body := data[2:]
		if len(body)%2 != 0 {
			return "", errors.New("the text file is not valid UTF-16")
		}
		u := make([]uint16, len(body)/2)
		for i := range u {
			if le {
				u[i] = uint16(body[2*i]) | uint16(body[2*i+1])<<8
			} else {
				u[i] = uint16(body[2*i])<<8 | uint16(body[2*i+1])
			}
		}
		s = string(utf16.Decode(u))
		if strings.ContainsRune(s, utf8.RuneError) {
			return "", errors.New("the text file is not valid UTF-16")
		}
	default:
		data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
		if !utf8.Valid(data) {
			return "", errors.New("the text file is not UTF-8. Save it as UTF-8 and add it again")
		}
		s = string(data)
	}
	if strings.ContainsRune(s, 0) {
		return "", errors.New("this is not a text file")
	}
	return s, nil
}

// cleanDocText keeps what a person reads: letters, digits, punctuation, spaces and line breaks. Control, bidirectional, zero-width and
// other invisible characters are dropped (they hide text from a reader and carry it to the model), a tab becomes a space, a line
// separator a line break. Runs of spaces collapse; runs of blank lines collapse to one.
func cleanDocText(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	var b strings.Builder
	b.Grow(len(s))
	nl, sp := 0, false
	for _, r := range s {
		switch {
		case r == '\n' || r == 0x85 || r == 0x2028 || r == 0x2029:
			nl++
			sp = false
			continue
		case r == '\t' || r == ' ' || r == 0xA0 || unicode.Is(unicode.Zs, r):
			sp = true
			continue
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || observe.Ignorable(r) || r == utf8.RuneError || !unicode.IsPrint(r):
			continue
		}
		switch {
		case nl > 0 && b.Len() > 0:
			b.WriteString(strings.Repeat("\n", min(nl, 2)))
		case sp && b.Len() > 0:
			b.WriteByte(' ')
		}
		nl, sp = 0, false
		b.WriteRune(r)
	}
	return b.String()
}

// extractText reads the text of a document of the kind. truncated is true when the text was longer than maxStoredText and was cut.
// The reader of a PDF runs a library that has no way to be stopped: after pdfTimeout it is let go of (it ends on its own).
func extractText(ctx context.Context, kind string, data []byte) (text string, truncated bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, extractTimeout)
	defer cancel()
	var raw string
	switch kind {
	case "md", "txt":
		raw, err = decodeText(data)
	case "docx":
		raw, err = docxText(ctx, data)
	case "pdf":
		raw, err = pdfText(ctx, data)
	default:
		err = errDocBad
	}
	if err != nil {
		return "", false, err
	}
	text = cleanDocText(raw)
	if len(text) > maxStoredText {
		text, truncated = strings.ToValidUTF8(text[:maxStoredText], ""), true
	}
	if strings.TrimSpace(text) == "" {
		return "", false, errDocEmpty
	}
	return text, truncated, nil
}

// docxText returns the text runs of word/document.xml. Nothing else of the archive is opened: no macros, no embedded files, no
// relationships to follow.
func docxText(ctx context.Context, data []byte) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", errDocBad
	}
	if len(zr.File) > docxEntries {
		return "", errDocBomb
	}
	var part *zip.File
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			part = f
			break
		}
	}
	if part == nil {
		return "", errDocBad
	}
	if part.UncompressedSize64 > docxXMLBytes || part.UncompressedSize64 > uint64(docxRatio)*max(part.CompressedSize64, 1)+4096 {
		return "", errDocBomb
	}
	rc, err := part.Open()
	if err != nil {
		return "", errDocBad
	}
	defer func() { _ = rc.Close() }()
	// The declared size can lie: the real read is capped too, and one byte more than the cap is a bomb.
	lr := &io.LimitedReader{R: rc, N: docxXMLBytes + 1}
	dec := xml.NewDecoder(lr)
	dec.Strict = true
	var out strings.Builder
	depth, tokens, inText := 0, 0, false
	for {
		if tokens&0xFFF == 0 && ctx.Err() != nil {
			return "", errDocTimeout
		}
		tok, err := dec.RawToken()
		if lr.N <= 0 {
			return "", errDocBomb
		}
		if errors.Is(err, io.EOF) {
			if depth != 0 {
				return "", errDocBad // cut off in the middle: a part of the text would pass for all of it
			}
			break
		}
		if err != nil {
			return "", errDocBad
		}
		if tokens++; tokens > docxXMLTokens {
			return "", errDocBomb
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth++; depth > docxXMLDepth {
				return "", errDocBomb
			}
			switch t.Name.Local {
			case "t":
				inText = true
			case "tab":
				out.WriteByte(' ')
			case "br", "cr":
				out.WriteByte('\n')
			}
		case xml.EndElement:
			depth--
			switch t.Name.Local {
			case "t":
				inText = false
			case "p":
				out.WriteByte('\n')
			}
		case xml.CharData:
			if inText {
				out.Write(t)
			}
		}
		if out.Len() > 2*maxStoredText {
			break // more than will be kept: stop reading
		}
	}
	return out.String(), nil
}

// pdfText returns the text of a PDF, page by page, in a goroutine that recovers from the panics the library raises on malformed
// files and is abandoned after pdfTimeout. Encrypted files are refused (no password is ever asked for).
func pdfText(ctx context.Context, data []byte) (string, error) {
	type result struct {
		text string
		err  error
	}
	// The library cannot be stopped: a reader that is let go of after pdfTimeout may run on. Three of them at once are the most the box
	// carries; then PDFs are refused until a restart (ponytail: reading in a child process with a limit is the way out).
	if pdfRunning.Load() >= pdfStuckMax {
		return "", errDocTimeout
	}
	done := make(chan result, 1)
	pctx, cancel := context.WithTimeout(ctx, pdfTimeout)
	defer cancel()
	pdfRunning.Add(1)
	go func() {
		var res result
		defer pdfRunning.Add(-1)
		defer func() {
			if r := recover(); r != nil {
				res = result{err: errDocBad}
			}
			done <- res
		}()
		res.text, res.err = readPDF(pctx, data)
	}()
	select {
	case r := <-done:
		return r.text, r.err
	case <-pctx.Done():
		return "", errDocTimeout
	}
}

func readPDF(ctx context.Context, data []byte) (string, error) {
	r, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "password") {
			return "", errDocCrypt
		}
		return "", errDocBad
	}
	var out strings.Builder
	for _, page := range pdfPageList(r.Trailer().Key("Root").Key("Pages")) {
		if ctx.Err() != nil {
			return "", errDocTimeout
		}
		s, err := pdf.Page{V: page}.GetPlainText(nil)
		if err != nil {
			continue // one page that cannot be read does not lose the others
		}
		out.WriteString(strings.ToValidUTF8(s, " "))
		out.WriteByte('\n')
		if out.Len() > 2*maxStoredText {
			break
		}
	}
	return out.String(), nil
}

// pdfPageList walks the page tree itself, with a depth limit and a budget of nodes, instead of asking the library for page number
// n: the library's lookup loops for ever on a tree that points to itself, and a file can say so.
func pdfPageList(root pdf.Value) []pdf.Value {
	var pages []pdf.Value
	budget := 4 * pdfPages
	var walk func(node pdf.Value, depth int)
	walk = func(node pdf.Value, depth int) {
		kids := node.Key("Kids")
		for i := 0; i < kids.Len() && budget > 0 && len(pages) < pdfPages; i++ {
			budget--
			kid := kids.Index(i)
			switch kid.Key("Type").Name() {
			case "Pages":
				if depth < 24 {
					walk(kid, depth+1)
				}
			case "Page":
				pages = append(pages, kid)
			}
		}
	}
	walk(root, 0)
	return pages
}

// chunkText cuts text into pieces of at most chunkBytes, at a blank line, a line end, a sentence end or a space, in that order of
// preference, never inside a character. The text is already clean (cleanDocText).
func chunkText(text string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if t := strings.TrimSpace(cur.String()); t != "" {
			out = append(out, t)
		}
		cur.Reset()
	}
	for _, para := range strings.Split(text, "\n") {
		para = strings.TrimSpace(para)
		if para == "" {
			continue
		}
		for len(para) > chunkBytes { // a paragraph longer than a chunk is cut on its own
			flush()
			cut := cutPoint(para, chunkBytes)
			out = append(out, strings.TrimSpace(para[:cut]))
			para = strings.TrimSpace(para[cut:])
		}
		if cur.Len() > 0 && cur.Len()+1+len(para) > chunkBytes {
			flush()
		}
		if cur.Len() > 0 {
			cur.WriteByte('\n')
		}
		cur.WriteString(para)
	}
	flush()
	return out
}

// cutPoint is where to cut s (longer than max) so the first part is at most max bytes: after the last sentence end or space in the
// second half, else at max, moved back to a character boundary.
func cutPoint(s string, limit int) int {
	head := s[:limit]
	for _, sep := range []string{". ", "! ", "? ", "; ", " "} {
		if i := strings.LastIndex(head, sep); i >= limit/2 {
			return i + len(sep)
		}
	}
	for limit > 1 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return limit
}

// errReason is the sentence the audit row carries for a document that could not be indexed.
func errReason(err error) string {
	for _, known := range []error{errDocEmpty, errDocBad, errDocBomb, errDocTimeout, errDocCrypt} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return "it could not be read"
}
