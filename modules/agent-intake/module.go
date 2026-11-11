// Package agentintake is the agent-intake module (S-INV-4, WP-26, D-169): Vedette as the TLS server of osquery. It owns the enrolment
// tokens and the enrolled nodes, parses what osquery sends (every byte of it is untrusted, SYS-6) and hands devices and software to the
// inventory through core/observe. The admin routes, the install scripts and Wazuh are later slices.
package agentintake

import (
	"embed"
	"io/fs"
)

//go:embed migrations/sqlite/*.sql
var migrationFiles embed.FS

// Migrations holds the SQLite migrations of the module. Pass it to store.Migrate(ctx, db, "agent-intake", agentintake.Migrations).
var Migrations = mustSub(migrationFiles, "migrations/sqlite")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("agentintake: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}

// The request body caps of the public operations (D-169 (8), INV-7), by operationId. cmd/vedette hands them to server.Config through
// moduleWiring.BodyLimits; the server refuses a declared length over the cap before reading and cuts a body that grows past it.
const (
	maxEnrollBody = 64 << 10
	maxConfigBody = 4 << 10
	maxLogBody    = 4 << 20
	maxStatusBody = 1 << 10
)

// BodyLimits is the per-operation request cap of the osquery operations (operationId → bytes).
var BodyLimits = map[string]int64{
	"inventory_post_intake_osquery_enroll": maxEnrollBody,
	"inventory_post_intake_osquery_config": maxConfigBody,
	"inventory_post_intake_osquery_log":    maxLogBody,
	"inventory_post_intake_osquery_status": maxStatusBody,
}
