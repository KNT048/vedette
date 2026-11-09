// Package sensorpassive is the passive discovery module (S-INV-1, S-INV-3, S-LOG-4): it listens on the
// network without ever sending a frame and reports what it hears. Two things come out of a packet:
//
//   - discovery (ARP, DHCP, mDNS, SSDP, LLDP) goes to the inventory as observations with source "passive";
//   - on a SPAN/TAP port, metadata (DNS query names, TLS SNI, HTTP Host, IP flow counters) goes to a MetadataSink.
//
// Packet contents are never stored (D-43, INV-3). Everything that arrives is untrusted (SYS-6): the parsers
// are fail-closed, bounded, and fuzzed. The capture types have no way to write to the network (INV-1).
package sensorpassive

import (
	"embed"
	"io/fs"
)

//go:embed migrations/sqlite/*.sql
var migrationFiles embed.FS

// Migrations holds the SQLite migrations of the module, rooted at the directory that contains the
// NNNN_*.sql files. Pass it to store.Migrate(ctx, db, "sensor-passive", sensorpassive.Migrations).
var Migrations = mustSub(migrationFiles, "migrations/sqlite")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("sensorpassive: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}
