// Package reports is the reports module (S-REP-1, S-REP-2, modules/reports/CONTRACT.md): the one-page weekly report, sent by
// email on a schedule through notify, and the personal-data-protection self-assessment under Law 91/2025/QH15 and Decree
// 356/2025/NĐ-CP. PDF is made by the browser from the print pages (D-55); the server renders no PDF and no HTML.
package reports

import (
	"embed"
	"io/fs"
)

//go:embed migrations/sqlite/*.sql
var migrationFiles embed.FS

// Migrations holds the SQLite migrations of the reports module, rooted at the directory that holds the NNNN_*.sql files. Apply
// them after core's: store.Migrate(ctx, db, "reports", reports.Migrations).
var Migrations = mustSub(migrationFiles, "migrations/sqlite")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("reports: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}
