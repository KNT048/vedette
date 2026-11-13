package ai_test

import (
	"database/sql"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/core"
)

// D-531, migration 0009: a box upgraded from daily caps keeps the same allowance over a month: the shared cap of ai_setting config
// and each profile's cap become 30 times themselves, under the new names; the daily column is gone.
func TestUpgradeTurnsDailyCapsIntoMonthlyBudgets(t *testing.T) {
	db := storetest.New(t)
	ctx := t.Context()
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	old := fstest.MapFS{}
	if err := fs.WalkDir(ai.Migrations, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p >= "0009" {
			return err
		}
		b, err := fs.ReadFile(ai.Migrations, p)
		old[p] = &fstest.MapFile{Data: b}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "ai", old); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO ai_profile (id, name, name_key, kind, api_style, base_url, model, location, daily_cap, created_at, updated_at) VALUES ('p1', 'Lab', 'lab', 'openai-compatible', 'openai', 'http://10.0.0.5:11434/v1', 'm', 'internal', 50000, '2026-11-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z')`,
		`INSERT INTO ai_setting (key, value, updated_at, updated_by) VALUES ('config', '{"tier":"min","daily_cap":200000,"redact_pii":true}', '2026-11-01T00:00:00.000Z', 'admin@acme.example')`,
	} {
		if err := db.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q); return err }); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Migrate(ctx, db, "ai", ai.Migrations); err != nil {
		t.Fatal(err)
	}
	var budget int
	var cfg string
	if err := db.Reader().QueryRowContext(ctx, `SELECT monthly_budget FROM ai_profile WHERE id = 'p1'`).Scan(&budget); err != nil || budget != 1_500_000 {
		t.Fatalf("profile budget = %d, %v", budget, err)
	}
	if err := db.Reader().QueryRowContext(ctx, `SELECT value FROM ai_setting WHERE key = 'config'`).Scan(&cfg); err != nil || cfg != `{"tier":"min","redact_pii":true,"monthly_budget":6000000}` {
		t.Fatalf("config = %s, %v", cfg, err)
	}
	if _, err := db.Reader().QueryContext(ctx, `SELECT daily_cap FROM ai_profile`); err == nil {
		t.Fatal("the daily column is still there")
	}
}
