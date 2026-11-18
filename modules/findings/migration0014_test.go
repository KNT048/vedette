package findings_test

import (
	"database/sql"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/mitigation"
)

// Migration 0014 rebuilds fnd_finding so a confirmed finding may rest on a version the device itself stated: every row and every
// child row survives it, foreign keys are on again afterwards, and the CHECK allows basis version only with evidence.source snmp or
// agent.
func TestMigration0014_KeepsTheRowsAndAllowsADeviceStatedVersion(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	before := fstest.MapFS{}
	if err := fs.WalkDir(findings.Migrations, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p >= "0014" { // the migrations before 0014
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
	const ts = "2026-11-18T10:00:00.000Z"
	write := func(qs ...string) error {
		return db.Write(ctx, func(tx *sql.Tx) error {
			for _, q := range qs {
				if _, err := tx.ExecContext(ctx, q); err != nil {
					return err
				}
			}
			return nil
		})
	}
	insert := func(id, cve, status, basis, evidence string) string {
		return `INSERT INTO fnd_finding (id, asset_id, cve, status, severity, confidence, basis, evidence, first_seen, last_seen)
			VALUES ('` + id + `', 'a-1', '` + cve + `', '` + status + `', 'high', 0.7, '` + basis + `', '` + evidence + `', '` + ts + `', '` + ts + `')`
	}
	// before: a version finding the device stated cannot be confirmed yet
	if err := write(insert("f-0", "CVE-2025-61620", "confirmed", "version", `{"summary":"s","source":"snmp"}`)); err == nil {
		t.Fatal("0013 stored a confirmed finding with basis version")
	}
	if err := write(
		insert("f-1", "CVE-2025-61624", "suspected", "version", `{"summary":"s","source":"snmp"}`),
		`UPDATE fnd_finding SET software_id = 'os:a-1', proved_version = '7.2.13' WHERE id = 'f-1'`,
		`INSERT INTO fnd_finding_history (id, finding_id, ts, user, action, note) VALUES ('fh-1', 'f-1', '`+ts+`', 'system', 'created', 'Matched version')`,
		`INSERT INTO fnd_not_installed (finding_id, mark) VALUES ('f-1', 'mark-key')`,
		`INSERT INTO mit_applied (finding_id, item, ts, user) VALUES ('f-1', 'patch', '`+ts+`', 'it@acme.example')`,
		`INSERT INTO mit_ai_output (finding_id, skill, payload, model, created_at) VALUES ('f-1', 'explain', '{}', 'm', '`+ts+`')`,
	); err != nil {
		t.Fatal(err)
	}
	const cols = `id || asset_id || cve || status || severity || confidence || basis || evidence || first_seen || last_seen || software_id || proved_version`
	read := func(q string) (out string) {
		t.Helper()
		if err := db.Reader().QueryRowContext(ctx, q).Scan(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	children := `SELECT (SELECT count(*) FROM fnd_finding_history) || '/' || (SELECT count(*) FROM fnd_not_installed) || '/' || (SELECT count(*) FROM mit_applied) || '/' || (SELECT count(*) FROM mit_ai_output)`
	was := read(`SELECT ` + cols + ` FROM fnd_finding`)
	if err := store.Migrate(ctx, db, "findings", findings.Migrations); err != nil {
		t.Fatal(err)
	}
	if got := read(`SELECT ` + cols + ` FROM fnd_finding`); got != was {
		t.Fatalf("copied values changed: %q, was %q", got, was)
	}
	if got := read(children); got != "1/1/1/1" {
		t.Fatalf("the rebuild deleted rows that hang off a finding: %s", got)
	}
	// after: confirmed with basis version only when the device stated the version
	if err := write(`UPDATE fnd_finding SET status = 'confirmed' WHERE id = 'f-1'`); err != nil {
		t.Fatalf("a version the device stated over SNMP cannot confirm: %v", err)
	}
	if err := write(insert("f-2", "CVE-2025-68686", "confirmed", "version", `{"summary":"s","source":"agent"}`)); err != nil {
		t.Fatalf("a version the agent stated cannot confirm: %v", err)
	}
	for _, ev := range []string{`{"summary":"s"}`, `{"summary":"s","source":"scan"}`, `{"summary":"s","source":"manual"}`, `{"summary":"s","source":1}`} {
		if err := write(insert("f-3", "CVE-2025-00001", "confirmed", "version", ev)); err == nil {
			t.Fatalf("confirmed with basis version and evidence %s was stored", ev)
		}
	}
	if err := write(insert("f-4", "CVE-2025-00002", "confirmed", "product", `{"summary":"s","source":"snmp"}`)); err == nil {
		t.Fatal("confirmed with basis product was stored")
	}
	if err := write(`DELETE FROM fnd_finding WHERE id IN ('f-1', 'f-2')`); err != nil {
		t.Fatal(err)
	}
	if got := read(children); got != "0/0/0/0" {
		t.Fatalf("foreign keys are off after the migration: deleting a finding left its rows: %s", got)
	}
}
