package ai

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/pdftext"
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
	extractTimeout = 90 * time.Second
)

// Errors of the readers: each is a plain reason the audit row and the administrator can read.
var (
	errDocEmpty   = errors.New("no text was found in it (a scanned document or pictures only)")
	errDocBad     = errors.New("it could not be read as a document of its type")
	errDocBomb    = errors.New("it is too large when unpacked")
	errDocTimeout = errors.New("reading it took too long")
	// The PDF reader runs in a limited child process (core/pdftext, D-264); its errors become these plain reasons. Nothing of the
	// child's own text is ever shown.
	errDocPassword = errors.New("the PDF is protected with a password; remove the password and upload it again")
	errDocLimit    = errors.New("the PDF could not be read safely (it is damaged, or too complex to open); save it again or export it to text")
	errDocNoReader = errors.New("the PDF reader is not available on this box")
)

// docKind is the type of a document, from the extension of its name: "md", "txt", "docx" or "pdf"; "" for any other.
func docKind(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return ""
	}
	switch k := strings.ToLower(name[i+1:]); k {
	case "md", "txt", "docx", "pdf":
		return k
	}
	return ""
}

// sniffDoc is the quick check made while the upload is answered: the bytes must look like the type the name claims. It reads
// nothing deep, so a file that passes can still fail in the indexer (the audit row says why).
func sniffDoc(kind string, data []byte) error {
	switch kind {
	case "docx":
		if !bytes.HasPrefix(data, []byte("PK\x03\x04")) {
			return errors.New("this is not a Word (DOCX) file")
		}
	case "pdf":
		if !bytes.Contains(data[:min(len(data), 1024)], []byte("%PDF-")) { // the same test as the child's
			return errors.New("this is not a PDF file")
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
func extractText(ctx context.Context, kind string, data []byte) (text string, truncated bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, extractTimeout)
	defer cancel()
	var raw string
	cut := false
	switch kind {
	case "md", "txt":
		raw, err = decodeText(data)
	case "docx":
		raw, err = docxText(ctx, data)
	case "pdf":
		raw, cut, err = pdfText(ctx, data)
	default:
		err = errDocBad
	}
	if err != nil {
		return "", false, err
	}
	text = cleanDocText(raw)
	truncated = cut
	if len(text) > maxStoredText {
		text, truncated = strings.ToValidUTF8(text[:maxStoredText], ""), true
	}
	if strings.TrimSpace(text) == "" {
		return "", false, errDocEmpty
	}
	return text, truncated, nil
}

// pdfText reads a PDF through the limited child process of core/pdftext (D-264). cut is true when the child cut the text at its cap.
func pdfText(ctx context.Context, data []byte) (text string, cut bool, err error) {
	text, err = pdftext.PDFText(ctx, bytes.NewReader(data))
	switch {
	case err == nil:
		return text, false, nil
	case errors.Is(err, pdftext.ErrTruncated):
		return text, true, nil
	case errors.Is(err, pdftext.ErrEncrypted):
		return "", false, errDocPassword
	case errors.Is(err, pdftext.ErrNoChild):
		return "", false, errDocNoReader
	case errors.Is(err, pdftext.ErrLimit), errors.Is(err, pdftext.ErrCrashed):
		return "", false, errDocLimit
	case errors.Is(err, pdftext.ErrNotPDF), errors.Is(err, pdftext.ErrTooLarge):
		return "", false, errDocBad
	case errors.Is(err, context.DeadlineExceeded):
		return "", false, errDocTimeout
	}
	return "", false, err
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
	for _, known := range []error{errDocEmpty, errDocBad, errDocBomb, errDocTimeout, errDocPassword, errDocLimit, errDocNoReader} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return "it could not be read"
}
