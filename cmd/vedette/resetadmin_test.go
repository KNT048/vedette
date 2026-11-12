package main

import (
	"bytes"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
)

// D-389: `vedette reset-admin <email>` resets the administrator in the box's own files and prints the temporary password once;
// a wrong -db is refused, never created.
func TestResetAdminCommand(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbPath, keyPath := filepath.Join(dir, "v.db"), filepath.Join(dir, "v.key")
	seedMigrated(t, dbPath)
	if err := secrets.GenerateKeyFile(keyPath); err != nil {
		t.Fatal(err)
	}
	func() { // the administrator, made with the box's key; closed before the command opens the files
		k, err := secrets.LoadKeyFile(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		sec, err := secrets.New(k)
		if err != nil {
			t.Fatal(err)
		}
		log := slog.New(slog.NewTextHandler(io.Discard, nil))
		db, err := store.Open(t.Context(), dbPath, log)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		svc, err := auth.New(auth.Config{DB: db, Secrets: sec, Audit: audit.New(nil), Log: log})
		if err != nil {
			t.Fatal(err)
		}
		hash, err := svc.HashPassword(t.Context(), "lamp river forty two", "owner@acme.example")
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Write(t.Context(), func(tx *sql.Tx) error {
			_, err := svc.CreateUser(t.Context(), tx, "system", auth.NewUser{Name: "Owner", Email: "owner@acme.example", Role: routes.Admin, PasswordHash: hash})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}()

	var out, errOut bytes.Buffer
	if err := run(t.Context(), []string{"reset-admin", "-db", filepath.Join(dir, "missing.db"), "-key", keyPath, "owner@acme.example"}, &out, &errOut); err == nil {
		t.Fatal("a missing database was accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "missing.db")); err == nil {
		t.Fatal("reset-admin created a database")
	}
	if err := run(t.Context(), []string{"reset-admin", "-db", dbPath, "-key", keyPath, "owner@acme.example"}, &out, &errOut); err != nil {
		t.Fatalf("reset-admin: %v (%s)", err, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "Reset owner@acme.example: two-step sign-in is off") || len(lines[2]) != 20 {
		t.Fatalf("output = %q", out.String())
	}
	if strings.Contains(errOut.String(), lines[2]) {
		t.Fatal("the temporary password reached the log")
	}
}
