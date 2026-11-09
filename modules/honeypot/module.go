// Package honeypot is the honeypot module: decoy services (SMB, RDP, SSH, MSSQL, HTTP), decoy devices and honey tokens
// on a secondary IP of the box, and the hits they catch (S-HP-1, S-HP-2, D-50, D-55, D-89). The traps themselves are
// OpenCanary in the `honeypot` container; this package never opens a trap port, never connects to a source (INV-1), and
// never touches the network or the OS: the host is reached through the Host port, the inventory through Inventory, and
// hits arrive as JSON lines in a file on a shared volume that core only reads (every byte of it is untrusted, SYS-6).
package honeypot

import (
	"embed"
	"io/fs"
)

//go:embed migrations/sqlite/*.sql
var migrationFiles embed.FS

// Migrations holds the SQLite migrations of the module, rooted at the directory that contains the
// NNNN_*.sql files. Pass it to store.Migrate(ctx, db, "honeypot", honeypot.Migrations).
var Migrations = mustSub(migrationFiles, "migrations/sqlite")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("honeypot: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}
