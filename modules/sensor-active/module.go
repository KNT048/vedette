// Package sensoractive is the sensor-active module: active device discovery with nmap, only inside the
// customer's confirmed LAN scope, time window and speed limit (S-INV-1, S-SCAN-4). It has no endpoints and
// imports no other module: the inventory is reached through the Inventory port and core/observe, adapted in
// cmd/vedette. nmap is the customer's own OS package, started only through core/exec (D-4).
package sensoractive

import (
	"embed"
	"io/fs"
)

//go:embed migrations/sqlite/*.sql
var migrationFiles embed.FS

// Migrations holds the SQLite migrations of the module, rooted at the directory that contains the
// NNNN_*.sql files. Pass it to store.Migrate(ctx, db, "sensor-active", sensoractive.Migrations).
var Migrations = mustSub(migrationFiles, "migrations/sqlite")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("sensoractive: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}
