// Command vedette-host is the small root helper on the appliance host (D-55):
// OS updates, box network, signed image pulls, container start and rollback,
// backups. It serves a fixed command list on a local socket
// (docs/specs/host-api.md). The socket server arrives with WP-07; until then the
// binary only reports its version.
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
		fmt.Fprintln(os.Stderr, "vedette-host:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("vedette-host", flag.ContinueOnError)
	fs.SetOutput(stdout)
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		_, err := fmt.Fprintln(stdout, version)
		return err
	}
	return errors.New("the socket server is not built yet; run with -version")
}
