// Package authoidc is the auth-oidc module (S-CORE-3, D-194..D-196): sign-in through an OpenID Connect identity provider with the
// authorization code flow and PKCE. It owns the configuration, the pending flows, discovery and the check of the ID token; the
// account and the session are core's (core/auth.SSOSignIn). Every byte from the identity provider is untrusted (SYS-6).
package authoidc

import (
	"embed"
	"io/fs"
)

//go:embed migrations/sqlite/*.sql
var migrationFiles embed.FS

// Migrations holds the SQLite migrations of the module. Pass it to store.Migrate(ctx, db, "auth-oidc", authoidc.Migrations).
var Migrations = mustSub(migrationFiles, "migrations/sqlite")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("authoidc: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}
