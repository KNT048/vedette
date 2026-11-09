// Package exposure is the external-exposure module (S-EXP-1, modules/exposure/CONTRACT.md): it proves ownership of
// a domain (DNS TXT) or of the box's public IPs (found by the box itself through three public services, D-81),
// takes the commitment, and keeps the daily snapshots of what the Internet sees. The scan itself is the scan module's.
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
