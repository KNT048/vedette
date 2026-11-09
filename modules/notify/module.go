package notify

import (
	"embed"
	"io/fs"
)

//go:embed migrations/sqlite/*.sql
var migrationFiles embed.FS

// Migrations holds the SQLite migrations of the module, rooted at the directory that contains the
// NNNN_*.sql files. Pass it to store.Migrate(ctx, db, "notify", notify.Migrations).
var Migrations = mustSub(migrationFiles, "migrations/sqlite")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("notify: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}
