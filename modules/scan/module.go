// Package scan is the vulnerability-scan module (S-SCAN-1..4, modules/scan/CONTRACT.md): it confirms exploited
// vulnerabilities with safe nuclei templates on devices inside the confirmed scope, inside the time window, at the
// rate and with the exclusions the admin set, and keeps the probe log. Consent and scope stay here, in core; nuclei
// itself is a pinned binary run by the worker in the scan container (D-113, D-125), reached through Engine.
package scan

import (
	"embed"
	"io/fs"
)

// ModuleID is the id of this module in the registry, the module gate and core/jobs.
const ModuleID = "scan"

//go:embed migrations/sqlite/*.sql
var migrationFiles embed.FS

// Migrations holds the SQLite migrations of the scan module, rooted at the directory that holds the NNNN_*.sql
// files. Apply them after core's and inventory's: store.Migrate(ctx, db, "scan", scan.Migrations).
var Migrations = mustSub(migrationFiles, "migrations/sqlite")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("scan: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}
