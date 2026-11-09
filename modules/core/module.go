// Package core is the always-on core module: its migrations and contract tests.
// The libraries it builds on live in core/ (store, secrets, chain, audit, exec); dependency
// direction is module -> core, never the reverse (CONTRACT FORBID-2).
package core

import (
	"embed"
	"io/fs"
)

//go:embed migrations/sqlite/*.sql
var migrationFiles embed.FS

// Migrations holds the SQLite migrations of the core module, rooted at the directory
// that contains the NNNN_*.sql files. Pass it to store.Migrate(ctx, db, "core", core.Migrations).
var Migrations = mustSub(migrationFiles, "migrations/sqlite")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("core: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}
