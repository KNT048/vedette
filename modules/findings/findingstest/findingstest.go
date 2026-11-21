// Package findingstest helps tests that store findings without the inventory module: fnd_finding and fnd_question have real foreign
// keys to inventory's device and software line tables, and such tests describe devices only through fake ports.
package findingstest

import (
	"database/sql"
	"testing"

	"github.com/knt048/vedette/core/store"
)

// ParentRows adds test-only triggers to a database migrated with core, inventory and findings: a finding or a question that points at
// a device or a software line the database does not have creates a plain row for it first, so the foreign keys hold.
func ParentRows(t testing.TB, db *store.DB) {
	t.Helper()
	const ts = `'2026-01-01T00:00:00.000Z'`
	// NOT EXISTS, not INSERT OR IGNORE: a statement's own conflict clause would override OR IGNORE inside the trigger and turn a
	// conflict of the outer write into one on these rows, hiding the real error.
	asset := `INSERT INTO inv_asset (id, origin, first_seen, last_seen) SELECT NEW.asset_id, 'discovered', ` + ts + `, ` + ts + `
		WHERE NOT EXISTS (SELECT 1 FROM inv_asset WHERE id = NEW.asset_id);`
	line := `INSERT INTO inv_software (id, asset_id, product_key, line, display, vendor, product, source, confidence, seen_at, first_seen, last_seen)
		SELECT NEW.software_id, NEW.asset_id, 'test|' || NEW.software_id, '', NEW.software_id, 'test', NEW.software_id, 'agent', 1, ` + ts + `, ` + ts + `, ` + ts + `
		WHERE NEW.software_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inv_software WHERE id = NEW.software_id);`
	for _, q := range []string{
		`CREATE TRIGGER test_fnd_finding_parents BEFORE INSERT ON fnd_finding BEGIN ` + asset + line + ` END`,
		// only a move to another device or line a test names; never the foreign key's own SET NULL
		`CREATE TRIGGER test_fnd_finding_parents_moved BEFORE UPDATE OF asset_id, software_id ON fnd_finding
			WHEN NEW.asset_id IS NOT OLD.asset_id OR NEW.software_id IS NOT NULL AND NEW.software_id IS NOT OLD.software_id
			BEGIN ` + asset + line + ` END`,
		`CREATE TRIGGER test_fnd_question_parents BEFORE INSERT ON fnd_question BEGIN ` + asset + line + ` END`,
	} {
		if err := db.Write(t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), q); return err }); err != nil {
			t.Fatal(err)
		}
	}
}
