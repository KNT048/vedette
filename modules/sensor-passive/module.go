// Package sensorpassive is the core half of the passive discovery module (S-INV-1, S-INV-3, S-LOG-4). The half that listens on the
// network without ever sending a frame is package capture, which runs in the sensor container (vedette-sensor passive) and tells core
// what it heard over the mutual-TLS sensor link; this package serves that link's passive role (Config, Observations,
// PassiveHeartbeat), keeps what the sensor reported, and answers the API. Two things come out of a packet:
//
//   - discovery (ARP, DHCP, mDNS, SSDP, LLDP) goes to the inventory as observations with source "passive";
//   - on a SPAN/TAP port, metadata (DNS query names, TLS SNI, HTTP Host, IP flow counters) goes to a capture.MetadataSink.
//
// Packet contents are never stored (D-43, INV-3). Everything a sensor sends is untrusted (SYS-6): core validates each item,
// applies its own budgets and clamps the confidence. Until SP-5 the capture also runs inside core (Service.Run).
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
