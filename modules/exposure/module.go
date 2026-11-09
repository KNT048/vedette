package exposure

import (
	"embed"
	"io/fs"
)

//go:embed migrations/sqlite/*.sql
var migrationFiles embed.FS

// Migrations holds the SQLite migrations of the exposure module, rooted at the directory that holds
// the NNNN_*.sql files. Apply them after core's: store.Migrate(ctx, db, "exposure", exposure.Migrations).
var Migrations = mustSub(migrationFiles, "migrations/sqlite")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("exposure: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}
