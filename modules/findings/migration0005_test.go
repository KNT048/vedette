package findings_test

import (
	"database/sql"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/mitigation"
)

// Migration 0005 (D-498) rebuilds fnd_finding, the parent of the ON DELETE CASCADE keys of findings and mitigation: every
// child row and every copied value survives it, the history stays append-only, and foreign keys are on again afterwards.
func TestMigration0005_KeepsTheRowsThatHangOffAFinding(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	before := fstest.MapFS{}
	if err := fs.WalkDir(findings.Migrations, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(p, "0005") {
			return err
		}
		b, err := fs.ReadFile(findings.Migrations, p)
		before[p] = &fstest.MapFile{Data: b}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, m := range []storetest.Migration{{Module: "core", FS: core.Migrations}, {Module: "findings", FS: before}, {Module: "mitigation", FS: mitigation.Migrations}} {
		if err := store.Migrate(ctx, db, m.Module, m.FS); err != nil {
			t.Fatal(err)
		}
	}
	const ts = "2026-11-09T10:00:00.000Z"
	exec := func(qs ...string) {
		t.Helper()
		if err := db.Write(ctx, func(tx *sql.Tx) error {
			for _, q := range qs {
				if _, err := tx.ExecContext(ctx, q); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	exec(
		`INSERT INTO fnd_finding (id, asset_id, cve, status, severity, confidence, basis, evidence, first_seen, last_seen, resolved_by, resolved_at, resolution_note, resolution_reason)
			VALUES ('f-1', 'a-1', 'CVE-2022-27593', 'not_relevant', 'medium', 0.5, 'product', '{"summary":"s"}', '`+ts+`', '`+ts+`', 'system', '`+ts+`', 'Not affected: 6.1.2', 'not_affected_version')`,
		`INSERT INTO fnd_finding_history (id, finding_id, ts, user, action, note) VALUES ('fh-1', 'f-1', '`+ts+`', 'system', 'created', 'Matched product')`,
		`INSERT INTO mit_applied (finding_id, item, ts, user) VALUES ('f-1', 'patch', '`+ts+`', 'it@acme.example')`,
		`INSERT INTO mit_ai_output (finding_id, skill, payload, model, created_at) VALUES ('f-1', 'explain', '{}', 'm', '`+ts+`')`,
	)
	const cols = `id || asset_id || cve || status || severity || confidence || basis || evidence || first_seen || last_seen || resolved_by || resolved_at || resolution_note || resolution_reason`
	read := func(q string) (out string) {
		t.Helper()
		if err := db.Reader().QueryRowContext(ctx, q).Scan(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	was := read(`SELECT ` + cols + ` FROM fnd_finding`)
	if err := store.Migrate(ctx, db, "findings", findings.Migrations); err != nil {
		t.Fatal(err)
	}
	if got := read(`SELECT ` + cols + ` FROM fnd_finding`); got != was {
		t.Fatalf("copied values changed: %q, was %q", got, was)
	}
	if read(`SELECT count(*) || '/' || (SELECT count(*) FROM mit_applied) || '/' || (SELECT count(*) FROM mit_ai_output) FROM fnd_finding_history`) != "1/1/1" {
		t.Fatal("the rebuild deleted rows that hang off a finding")
	}
	rows, err := db.Reader().QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	broken := rows.Next()
	_ = rows.Close()
	if broken {
		t.Fatal("foreign_key_check reports rows")
	}
	if err := db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE fnd_finding_history SET note = 'x'`)
		return err
	}); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("history update after the rebuild: %v", err)
	}
	exec(`DELETE FROM fnd_finding WHERE id = 'f-1'`)
	if read(`SELECT count(*) || '/' || (SELECT count(*) FROM mit_applied) || '/' || (SELECT count(*) FROM mit_ai_output) FROM fnd_finding_history`) != "0/0/0" {
		t.Fatal("foreign keys are off after the migration: deleting a finding left its rows")
	}
}
