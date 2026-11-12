package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
)

// resetAdminCommand reports whether args ask for `reset-admin` (D-389): the box console's way back in for an administrator who
// lost the two-step device or the password when no other administrator can help. It runs next to the serving process, in the
// same container (`docker exec vedette-core /vedette reset-admin <email>`, `sudo podman exec ...` on an appliance): SQLite in
// WAL mode takes the second writer, and every account fact core checks (password, cred_version, two-step method, sessions) is
// read from the database. Only the failure counters of the sign-in limit live in core's memory: a wait already running stays
// (at most 10 minutes; restarting core clears it). ponytail: two argon2 runs (64 MiB each) inside core's container memory
// limit; upgrade path: skip the dummy hash in this process if a box ever runs that tight.
func resetAdminCommand(args []string) bool { return len(args) > 0 && args[0] == "reset-admin" }

// runResetAdmin opens the existing database and key (it never creates either: a wrong -db must not make an empty box),
// resets the account with auth.ConsoleReset and prints the temporary password once, on stdout only.
func runResetAdmin(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vedette reset-admin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	db := flags.String("db", "/var/lib/vedette/vedette.db", "path of the SQLite database")
	key := flags.String("key", "/var/lib/vedette/vedette.key", "path of the secrets master key file")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: vedette reset-admin [-db path] [-key path] <administrator email>\n\n"+
			"Sets a temporary password (valid 72 hours, replaced at the next sign-in), turns two-step sign-in off and ends every\n"+
			"session of that administrator. Written to the audit log as user.console_reset.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return errors.New("reset-admin needs exactly one argument: the administrator's sign-in email")
	}
	for _, p := range []string{*db, *key} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("%s: %w (run this where Vedette keeps its data, or pass -db and -key)", p, err)
		}
	}
	k, err := secrets.LoadKeyFile(*key)
	if err != nil {
		return err
	}
	sec, err := secrets.New(k)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	d, err := store.Open(ctx, *db, log)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	svc, err := auth.New(auth.Config{DB: d, Secrets: sec, Audit: audit.New(nil), Log: log})
	if err != nil {
		return err
	}
	email := flags.Arg(0)
	temp, ended, err := svc.ConsoleReset(ctx, email)
	if err != nil {
		return err
	}
	sessions := "sessions"
	if ended == 1 {
		sessions = "session"
	}
	_, err = fmt.Fprintf(stdout, "Reset %s: two-step sign-in is off and %d %s ended.\n"+
		"Temporary password (valid 72 hours; you choose a new one when you sign in):\n%s\n", email, ended, sessions, temp)
	return err
}
