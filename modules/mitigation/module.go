// Package mitigation is the "What to do" part of a finding: confirmed packs loaded from a signed
// update, the "Applied" log, the compromise indicators and the AI explanation. Findings themselves
// belong to modules/findings (D-57 (6)); this module only reads them through findings.Service.
package mitigation

import (
	"embed"
	"io/fs"
)

//go:embed migrations/sqlite/*.sql
var migrationFiles embed.FS

// Migrations holds the SQLite migrations of the mitigation module. Apply them after the migrations of
// core and findings: the tables point at fnd_finding.
var Migrations = mustSub(migrationFiles, "migrations/sqlite")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("mitigation: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}
