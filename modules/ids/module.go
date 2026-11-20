// Package ids is the intrusion detection module: alerts of IPS and IDS events and their link to the vulnerabilities of the attacked
// device (S-IDS-1). In this release its source is the IPS and IDS events customers' firewalls write in the logs they send to the box
// (FortiGate IPS, Suricata and Snort on pfSense, OPNsense and other gateways, Sophos, SonicWall, Palo Alto, Meraki): the logs module
// hands each stored line over, this package reads the ones that are IPS events (every byte is untrusted, SYS-6), and keeps one alert per
// signature, source, destination and hour with the CVE ids the event names. Detection never blocks traffic; the module never opens a
// port, never runs a process and never calls out. Other sources (an engine on the box) add values to ids_alert.source.
package ids

import (
	"embed"
	"io/fs"
)

//go:embed migrations/sqlite/*.sql
var migrationFiles embed.FS

// Migrations holds the SQLite migrations of the module.
var Migrations = mustSub(migrationFiles, "migrations/sqlite")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("ids: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}
