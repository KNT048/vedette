package store_test

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/knt048/vedette/core/store"
)

// QuickCheck passes a sound database and refuses one whose pages are broken.
func TestQuickCheckFindsDamage(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "v.db")
	db, err := store.Open(ctx, path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "probe", fstest.MapFS{"0001_a.sql": {Data: []byte("-- +goose Up\nCREATE TABLE probe_a (x TEXT);\nCREATE INDEX probe_a_x ON probe_a (x);\n" +
		"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 2000) INSERT INTO probe_a SELECT hex(randomblob(40)) FROM n;\n")}}); err != nil {
		t.Fatal(err)
	}
	if err := db.QuickCheck(ctx); err != nil {
		t.Fatalf("a sound database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // the test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	junk := make([]byte, 4096*8)
	for i := range junk {
		junk[i] = 0xA5
	}
	if _, err := f.WriteAt(junk, 4096*4); err != nil { // pages in the middle of the table and its index
		t.Fatal(err)
	}
	_ = f.Close()
	db, err = store.Open(ctx, path, slog.New(slog.DiscardHandler))
	if err != nil {
		return // too damaged to open is refused as well
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.QuickCheck(ctx); !errors.Is(err, store.ErrDamaged) && err == nil {
		t.Fatal("a damaged database passed QuickCheck")
	}
}
