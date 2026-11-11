// Package pdftext reads the text of a PDF in a child process with limits (D-264, issue #324).
//
// The Go PDF library hits fatal errors that recover() cannot catch (out of memory on a huge xref, stack overflow on an object stream
// that contains itself) and loops for ever on a /Prev or /Extends that points back. In the core process any of them would stop the
// box, so the library runs only in `vedette pdftext` (ChildMain, the same binary), started through core/exec with a fixed argv, the
// file on stdin, a clean environment, limits it sets on itself before reading, a wall-clock kill, and capped output.
//
// The one entry for other packages is PDFText. The file is untrusted data (SYS-6); the child never writes a file, never opens the
// network and gets nothing from the environment.
package pdftext

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/exec"
)

// Limits. MaxInput and MaxText are the caps of D-209 (the upload, and the text kept per document).
const (
	MaxInput  = 10 << 20 // bytes of the PDF
	MaxText   = 4 << 20  // bytes of text returned; the rest is cut
	maxStderr = 512
	maxActive = 2 // children at once: each may take 512 MiB of address space
)

// wallLimit: the child is killed after this, whatever the caller's deadline (a test shortens it).
var wallLimit = 60 * time.Second

// Subcommand is the argv[1] of the child: `vedette pdftext`.
const Subcommand = "pdftext"

var (
	// ErrNotPDF means the bytes are not a PDF, or the library cannot read them.
	ErrNotPDF = errors.New("pdftext: not a readable PDF")
	// ErrEncrypted means the PDF needs a password.
	ErrEncrypted = errors.New("pdftext: the PDF is protected with a password")
	// ErrTooLarge means the file is longer than MaxInput.
	ErrTooLarge = errors.New("pdftext: the PDF is too large")
	// ErrLimit means the child ran out of time (wallLimit, RLIMIT_CPU) or was killed by the kernel; the file is hostile or enormous.
	ErrLimit = errors.New("pdftext: reading the PDF hit a limit")
	// ErrCrashed means the child died on its own (a Go fatal error such as out of memory under RLIMIT_AS or a stack overflow, or a
	// failed limit setup) or spoke out of turn. The core process is untouched.
	ErrCrashed = errors.New("pdftext: the PDF reader crashed")
	// ErrTruncated is returned WITH the text: the text is valid and complete up to MaxText bytes, and was cut there.
	ErrTruncated = errors.New("pdftext: the text was cut at the limit")
)

// childPath is the program to run: this binary. A test replaces it with a build of the child that has no race detector (which reserves
// terabytes of address space and cannot live under RLIMIT_AS).
var childPath = os.Executable

var active = make(chan struct{}, maxActive)

// PDFText reads a PDF from r and returns its text (UTF-8, at most MaxText bytes). Errors: ErrNotPDF, ErrEncrypted, ErrTooLarge,
// ErrLimit, ErrCrashed (test with errors.Is), or the context's error when the caller cancels. ErrTruncated comes with a usable text.
// It waits for a free slot (two children at once) until ctx ends.
func PDFText(ctx context.Context, r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxInput+1))
	switch {
	case err != nil:
		return "", fmt.Errorf("%w: reading the input: %w", ErrNotPDF, err)
	case len(data) > MaxInput:
		return "", ErrTooLarge
	case !looksLikePDF(data):
		return "", ErrNotPDF
	}
	select {
	case active <- struct{}{}:
		defer func() { <-active }()
	case <-ctx.Done():
		return "", ctx.Err()
	}
	exe, err := childPath()
	if err != nil {
		return "", fmt.Errorf("%w: own path: %w", ErrCrashed, err)
	}
	run, err := exec.NewRunner(slog.Default(), exec.Binary{
		Name: "vedette-pdftext", Path: exe,
		Validate:  validArgs,
		MaxOutput: MaxText + 1, // one byte over the cap means the child did not keep to it
		MaxStderr: maxStderr,
	})
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCrashed, err)
	}
	ctx, cancel := context.WithTimeout(ctx, wallLimit)
	defer cancel()
	res, err := run.Run(ctx, "vedette-pdftext", []string{Subcommand}, bytes.NewReader(data))

	// stderr is never logged or returned: it is the child's own words, and the child read untrusted bytes.
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.Is(err, context.DeadlineExceeded):
		return "", ErrLimit
	case errors.Is(err, context.Canceled):
		return "", err
	case errors.As(err, &exitErr):
		switch exitErr.ExitCode {
		case ExitNotPDF:
			return "", ErrNotPDF
		case ExitEncrypted:
			return "", ErrEncrypted
		case ExitTooLarge:
			return "", ErrTooLarge
		case ExitCut:
			if !res.Truncated {
				return strings.ToValidUTF8(string(res.Stdout), ""), ErrTruncated
			}
			return "", ErrCrashed
		case -1: // killed by a signal: SIGXCPU or SIGKILL from the kernel's limits
			return "", ErrLimit
		}
		return "", ErrCrashed
	default:
		return "", fmt.Errorf("%w: %w", ErrCrashed, err)
	}
	if res.Truncated {
		return "", ErrCrashed
	}
	return strings.ToValidUTF8(string(res.Stdout), ""), nil
}

// validArgs is the allowlist of the argv: exactly the subcommand, nothing else.
func validArgs(args []string) error {
	if !slices.Equal(args, []string{Subcommand}) {
		return errors.New("the argv must be exactly the pdftext subcommand")
	}
	return nil
}
