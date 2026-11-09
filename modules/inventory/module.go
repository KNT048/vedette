// Package inventory is the inventory module: the list of devices and software on the network,
// declared by hand, imported from CSV, or fed by sensors and agents through core/observe, with a source
// and a confidence on every value (S-INV-1, 2, 3, 5). Service is the only writer of the inv_* tables (INV-2).
package inventory

import (
	"embed"
	"io/fs"
)

//go:embed migrations/sqlite/*.sql
var migrationFiles embed.FS

// Migrations holds the SQLite migrations of the module, rooted at the directory that contains the
// NNNN_*.sql files. Pass it to store.Migrate(ctx, db, "inventory", inventory.Migrations).
var Migrations = mustSub(migrationFiles, "migrations/sqlite")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("inventory: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}
