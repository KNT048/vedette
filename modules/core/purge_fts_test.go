package core

import (
	"database/sql"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/store"
)

// A purge leaves every FTS5 index whole: before, wipe deleted the shadow tables row by row and every later insert failed
// with "fts5: corruption found" (ai knowledge base, #323). External-content (the ai_knowledge_chunk_fts shape, with its sync
// triggers), regular and contentless tables are all covered, and the virtual and shadow tables are not data tables.
func TestPurgeKeepsFTS5IndexesWhole(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "v.db"), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	schema := []string{
		`CREATE TABLE doc (id INTEGER PRIMARY KEY, body TEXT NOT NULL)`,
		`CREATE VIRTUAL TABLE doc_fts USING fts5(body, content='doc', content_rowid='id', tokenize='unicode61 remove_diacritics 2')`,
		`CREATE TRIGGER doc_ai AFTER INSERT ON doc BEGIN INSERT INTO doc_fts(rowid, body) VALUES (new.id, new.body); END`,
		`CREATE TRIGGER doc_ad AFTER DELETE ON doc BEGIN INSERT INTO doc_fts(doc_fts, rowid, body) VALUES ('delete', old.id, old.body); END`,
		`CREATE VIRTUAL TABLE own_fts USING fts5(body)`,
		`CREATE VIRTUAL TABLE bare_fts USING fts5(body, content = '')`,
	}
	write := func(stmts ...string) {
		t.Helper()
		if err := db.Write(ctx, func(tx *sql.Tx) error {
			for _, s := range stmts {
				if _, err := tx.ExecContext(ctx, s); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	write(schema...)
	write(`INSERT INTO doc (body) VALUES ('Tường lửa FortiGate'), ('cấu hình VPN')`,
		`INSERT INTO own_fts (body) VALUES ('old text')`, `INSERT INTO bare_fts (rowid, body) VALUES (1, 'old text')`)

	_, names, err := dataTables(ctx, db.Reader())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if n != "doc" {
			t.Errorf("data table %q: a virtual or shadow table must not be one", n)
		}
	}

	// A seed row of the content table (a migration INSERT) must be in the external index after the purge: rebuild, not
	// delete-all. integrity-check with rank=1 also compares the index with the content table.
	seeds := []seedRow{{table: "doc", cols: []string{"id", "body"}, vals: []any{int64(7), "seed firewall"}}}
	if err := db.Write(ctx, func(tx *sql.Tx) error { _, err := wipe(ctx, tx, seeds, nil); return err }); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	check := func() {
		t.Helper()
		write(`INSERT INTO doc_fts(doc_fts, rank) VALUES ('integrity-check', 1)`, `INSERT INTO own_fts(own_fts) VALUES ('integrity-check')`,
			`INSERT INTO bare_fts(bare_fts) VALUES ('integrity-check')`)
	}
	check()
	count := func(q string) int {
		t.Helper()
		var n int
		if err := db.Reader().QueryRowContext(ctx, q).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	if n := count(`SELECT count(*) FROM doc_fts WHERE doc_fts MATCH 'seed'`); n != 1 {
		t.Errorf("the seed row of the content table: %d matches, want 1", n)
	}
	if n := count(`SELECT count(*) FROM doc_fts WHERE doc_fts MATCH 'tuong'`) + count(`SELECT count(*) FROM own_fts WHERE own_fts MATCH 'old'`) + count(`SELECT count(*) FROM bare_fts WHERE bare_fts MATCH 'old'`); n != 0 {
		t.Errorf("%d index entries survived the purge", n)
	}
	// The box works after the purge: new rows are indexed and found, the triggers are back.
	write(`INSERT INTO doc (body) VALUES ('Tường lửa mới')`, `INSERT INTO own_fts (body) VALUES ('new text')`, `INSERT INTO bare_fts (rowid, body) VALUES (2, 'new text')`)
	if n := count(`SELECT count(*) FROM doc_fts WHERE doc_fts MATCH 'tuong'`); n != 1 {
		t.Errorf("external-content index after the purge: %d matches, want 1", n)
	}
	if n := count(`SELECT count(*) FROM own_fts WHERE own_fts MATCH 'new'`) + count(`SELECT count(*) FROM bare_fts WHERE bare_fts MATCH 'new'`); n != 2 {
		t.Errorf("regular + contentless indexes after the purge: %d matches, want 2", n)
	}
	write(`DELETE FROM doc`)
	check()
}

// A virtual table the purge does not know how to empty (anything but FTS5) fails it closed: nothing is deleted.
func TestPurgeRefusesAVirtualTableItCannotEmpty(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "v.db"), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Write(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{`CREATE TABLE doc (id INTEGER PRIMARY KEY, body TEXT)`, `INSERT INTO doc (body) VALUES ('kept')`,
			`CREATE VIRTUAL TABLE box USING rtree(id, x0, x1)`, `INSERT INTO box VALUES (1, 0, 1)`} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	err = db.Write(ctx, func(tx *sql.Tx) error { _, err := wipe(ctx, tx, nil, nil); return err })
	if err == nil || !strings.Contains(err.Error(), "not FTS5") {
		t.Fatalf("wipe with an rtree table = %v, want a refusal", err)
	}
	var n int
	if err := db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM doc`).Scan(&n); err != nil || n != 1 {
		t.Errorf("rows after a refused purge = %d (%v), want 1", n, err)
	}
}
