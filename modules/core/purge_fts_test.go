package core

import (
	"database/sql"
	"log/slog"
	"path/filepath"
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

	if err := db.Write(ctx, func(tx *sql.Tx) error { _, err := wipe(ctx, tx, nil, nil); return err }); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	for _, f := range []string{"doc_fts", "own_fts", "bare_fts"} {
		write(`INSERT INTO ` + f + `(` + f + `) VALUES ('integrity-check')`)
	}
	count := func(q string) int {
		t.Helper()
		var n int
		if err := db.Reader().QueryRowContext(ctx, q).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
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
	for _, f := range []string{"doc_fts", "own_fts", "bare_fts"} {
		write(`INSERT INTO ` + f + `(` + f + `) VALUES ('integrity-check')`)
	}
}
