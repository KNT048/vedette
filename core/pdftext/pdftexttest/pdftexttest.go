// Package pdftexttest lets the tests of any package that calls pdftext.PDFText (the AI knowledge base, say) run a real PDF child.
//
// PDFText starts a child only if a binary registered itself, and a test binary must not: it would run its own suite again with argv
// `pdftext`. BuildChild builds the separate child program (child/, the same ChildMain as `vedette pdftext`) without the race detector,
// which reserves terabytes of address space and cannot live under RLIMIT_AS, and registers it for the length of the test.
package pdftexttest

import (
	"context"
	"os"
	osexec "os/exec" //nolint:depguard // test support: builds the test child with fixed argv, no shell; SYS-1 is about the product
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/pdftext"
)

// BuildChild builds the child into the test's temporary directory, registers it with pdftext.SetChild, and unregisters it when the
// test ends. ldflags are extra `-ldflags` words, e.g. "-X github.com/knt048/vedette/core/pdftext.limitCPUText=2" (Linux). It returns
// the path of the child. Tests that call it must not run in parallel with each other: the registration is one per process.
func BuildChild(t testing.TB, ldflags ...string) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "child")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	args := []string{"build", "-o", exe}
	if len(ldflags) > 0 {
		args = append(args, "-ldflags", strings.Join(ldflags, " "))
	}
	args = append(args, "github.com/knt048/vedette/core/pdftext/pdftexttest/child")
	build := osexec.CommandContext(ctx, "go", args...) //nolint:gosec // fixed argv, a test helper
	build.Env = append(os.Environ(), "GOFLAGS=")       // no -race from the caller's flags: the child must run under RLIMIT_AS
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the PDF test child: %v\n%s", err, out)
	}
	pdftext.SetChild(exe)
	t.Cleanup(func() { pdftext.SetChild("") })
	return exe
}
