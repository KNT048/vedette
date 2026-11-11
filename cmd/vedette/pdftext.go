package main

import "github.com/knt048/vedette/core/pdftext"

// `vedette pdftext` (D-264): the child process that reads a PDF for the AI knowledge base. core/pdftext starts this same binary with
// exactly this one argument, the file on stdin and text on stdout. It is checked in main before any flag, signal handler, database
// or key, and it exits with the code of pdftext.ChildMain (a Go fatal error exits 2, which the parent reads as a crash).
func pdftextCommand(args []string) bool {
	return len(args) == 1 && args[0] == pdftext.Subcommand
}
