// Command child is the PDF reader child for the tests, built without the race detector (which reserves more address space than
// RLIMIT_AS allows). It is the same ChildMain that `vedette pdftext` runs.
package main

import (
	"os"

	"github.com/knt048/vedette/core/pdftext"
)

func main() { os.Exit(pdftext.ChildMain(os.Stdin, os.Stdout, os.Stderr)) }
