package main

import (
	"strings"
	"testing"
)

// The child of core/pdftext starts this binary with exactly one argument; nothing else may reach ChildMain, and the server's own
// argv must never be taken for it.
func TestPDFTextCommandIsExactlyOneArgument(t *testing.T) {
	if !pdftextCommand([]string{"pdftext"}) {
		t.Fatal("`vedette pdftext` is not recognised")
	}
	for _, args := range []string{"", "pdftext x", "x pdftext", "-version", "healthcheck", "honeypot healthcheck", "PDFTEXT"} {
		if pdftextCommand(strings.Fields(args)) {
			t.Fatalf("%q is taken for the PDF child", args)
		}
	}
}
