package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/knt048/vedette/core/selfcheck"
)

// selfcheckCommand reports whether args ask for `selfcheck`: a read-only pass over the database that counts the rows that
// break each registered data invariant. It never migrates or writes; run it after a deploy or when a number looks wrong.
func selfcheckCommand(args []string) bool { return len(args) > 0 && args[0] == "selfcheck" }

func runSelfcheck(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vedette selfcheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	db := flags.String("db", "/var/lib/vedette/vedette.db", "path of the SQLite database (opened read-only)")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: vedette selfcheck [-db path]\n\n"+
			"Prints one line per data invariant with the number of rows that break it, and exits 1 when any is not zero.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	return selfcheck.Command(ctx, *db, selfcheck.Registered(), stdout)
}
