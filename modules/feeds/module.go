package feeds

import (
	"embed"
	"io/fs"
)

//go:embed migrations/sqlite/*.sql
var migrationFiles embed.FS

// Migrations holds the SQLite migrations of the feeds module, rooted at the directory that holds the
// NNNN_*.sql files. Pass it to store.Migrate(ctx, db, "feeds", feeds.Migrations) after core's.
var Migrations = mustSub(migrationFiles, "migrations/sqlite")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("feeds: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}
