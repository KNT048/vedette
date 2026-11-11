package pdftext

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strings"

	"github.com/ledongthuc/pdf"
)

// Exit codes of the child (`vedette pdftext`). A Go fatal error or panic exits with 2, so 2 is never a code of ours: the parent reads
// it as a crash.
const (
	ExitOK        = 0
	ExitNotPDF    = 10 // not a PDF, or one the library cannot read
	ExitEncrypted = 11 // a password is needed
	ExitTooLarge  = 12 // more than MaxInput bytes on stdin
	ExitSetup     = 13 // the limits could not be set: the child refuses to read anything without them
	ExitCut       = 14 // the text is complete up to MaxText bytes and was cut there
)

const (
	pages       = 3000  // pages read of one file
	pageNodes   = 12000 // nodes of the page tree visited
	maxTreeDeep = 24
	maxStack    = 64 << 20  // goroutine stack: a self-containing object stream stops here, not at the 1 GB default
	softMemory  = 384 << 20 // the GC works harder from here, before RLIMIT_AS (512 MiB) is reached
)

// ChildMain is the whole of `vedette pdftext`: the PDF on stdin, plain text on stdout, an exit code from the list above. The limits
// are set before the first byte of the file is read, so there is no window in which untrusted input meets an unlimited process
// (setting them from the parent with prlimit after the start would leave that window). Nothing but a fixed word goes to stderr.
func ChildMain(stdin io.Reader, stdout, stderr io.Writer) int {
	if err := setLimits(); err != nil {
		say(stderr, "limits not set")
		return ExitSetup
	}
	debug.SetMaxStack(maxStack)
	debug.SetMemoryLimit(softMemory)

	data, err := io.ReadAll(io.LimitReader(stdin, MaxInput+1))
	switch {
	case err != nil:
		say(stderr, "input unreadable")
		return ExitNotPDF
	case len(data) > MaxInput:
		say(stderr, "input too large")
		return ExitTooLarge
	case !looksLikePDF(data):
		say(stderr, "not a PDF")
		return ExitNotPDF
	}
	text, cut, err := extract(data)
	switch {
	case errors.Is(err, pdf.ErrInvalidPassword):
		say(stderr, "encrypted")
		return ExitEncrypted
	case err != nil:
		say(stderr, "unreadable")
		return ExitNotPDF
	}
	if _, err := io.WriteString(stdout, Marker+text); err != nil {
		return ExitNotPDF
	}
	if cut {
		return ExitCut
	}
	return ExitOK
}

// say writes one fixed word to stderr; a failed write changes nothing, the exit code is the answer.
func say(w io.Writer, what string) { _, _ = fmt.Fprintln(w, "pdftext: "+what) }

func looksLikePDF(data []byte) bool {
	return bytes.Contains(data[:min(len(data), 1024)], []byte("%PDF-"))
}

// extract returns the text of the pages, at most MaxText bytes (cut is true when the text was longer). A panic of the library (an
// index out of range in a damaged file) is an unreadable file; the fatal errors recover cannot catch end the child, which is the
// reason this runs in a child at all.
func extract(data []byte) (text string, cut bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			text, cut, err = "", false, errors.New("pdftext: the library panicked")
		}
	}()
	r, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", false, err
	}
	var out strings.Builder
	for _, page := range pageList(r.Trailer().Key("Root").Key("Pages")) {
		s, err := pdf.Page{V: page}.GetPlainText(nil)
		if err != nil {
			continue // one page that cannot be read does not lose the others
		}
		out.WriteString(strings.ToValidUTF8(s, " "))
		out.WriteByte('\n')
		if out.Len() >= MaxText {
			break
		}
	}
	text = out.String()
	if len(text) > MaxText {
		text, cut = strings.ToValidUTF8(text[:MaxText], ""), true
	}
	return text, cut, nil
}

// pageList walks the page tree itself, with a depth limit and a budget of nodes, instead of asking the library for page number n:
// the library's lookup loops for ever on a tree that points to itself, and a file can say so.
func pageList(root pdf.Value) []pdf.Value {
	var list []pdf.Value
	budget := pageNodes
	var walk func(node pdf.Value, depth int)
	walk = func(node pdf.Value, depth int) {
		kids := node.Key("Kids")
		for i := 0; i < kids.Len() && budget > 0 && len(list) < pages; i++ {
			budget--
			kid := kids.Index(i)
			switch kid.Key("Type").Name() {
			case "Pages":
				if depth < maxTreeDeep {
					walk(kid, depth+1)
				}
			case "Page":
				list = append(list, kid)
			}
		}
	}
	walk(root, 0)
	return list
}
