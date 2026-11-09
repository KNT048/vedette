// Command vedette is the box's main process: the core API, the embedded web
// interface and the module registry (D-8, D-55). The server itself arrives with
// WP-04; until then the binary only reports its version.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "vedette:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("vedette", flag.ContinueOnError)
	fs.SetOutput(stdout)
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		_, err := fmt.Fprintln(stdout, version)
		return err
	}
	return errors.New("the server is not built yet; run with -version")
}
