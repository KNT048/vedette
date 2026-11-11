// Package logs receives, stores and searches the logs of the customer's devices (S-LOG-1..4, WP-24).
//
// Storage is split in two databases on purpose. The configuration (sources, retention, later the SIEM settings) is in the
// main database, audited in the same transaction as the change (SYS-3) and part of the backup. The volume (received
// lines, per-source counters) is in its own file, logs.db, with its own single writer: at up to 2,000 lines a second
// per source, a syslog flood must never wait for, or hold, the writer of the main database (the findings events that a
// busy writer dropped, #159/#160). The two never reference each other: a line names its source by id only.
package logs

import (
	"embed"
	"io/fs"
)

//go:embed migrations/config/*.sql
var configFiles embed.FS

//go:embed migrations/volume/*.sql
var volumeFiles embed.FS

// ConfigMigrations are the migrations of the main database (store.Migrate(ctx, db, "logs", ConfigMigrations)).
var ConfigMigrations = mustSub(configFiles, "migrations/config")

// VolumeMigrations are the migrations of logs.db (store.Migrate(ctx, logsDB, "logs", VolumeMigrations)).
var VolumeMigrations = mustSub(volumeFiles, "migrations/volume")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("logs: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}
