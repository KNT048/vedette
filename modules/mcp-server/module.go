// Package mcpserver is the read-only MCP server of the box (S-MCP-1, modules/mcp-server/CONTRACT.md): external agents and SIEMs
// look up devices, findings and the vulnerability feeds with scoped, revocable tokens, over MCP's Streamable HTTP transport on
// a loopback address (D-230..D-234). It has no write tool and no path into response (SYS-8, D-41).
package mcpserver

import (
	"embed"
	"io/fs"
)

//go:embed migrations/sqlite/*.sql
var migrationFiles embed.FS

// Migrations holds the SQLite migrations of the mcp-server module. Apply them after core's:
// store.Migrate(ctx, db, "mcp-server", mcpserver.Migrations).
var Migrations = mustSub(migrationFiles, "migrations/sqlite")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("mcpserver: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}
