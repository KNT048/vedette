package store

import (
	"bytes"
	"database/sql"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"modernc.org/sqlite"
)

// Only SQLite's "no transaction is active" after its own rollback is quiet (debug); every other rollback failure is an ERROR, another
// SQLITE_ERROR (code 1) included. The two SQLite errors are the driver's real ones.
func TestLogRollbackQuietsOnlyAnAlreadyEndedTransaction(t *testing.T) {
	ctx := t.Context()
	var buf bytes.Buffer
	db, err := Open(ctx, filepath.Join(t.TempDir(), "r.db"), slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, noTx := db.w.ExecContext(ctx, "ROLLBACK")
	_, noTable := db.w.ExecContext(ctx, "DELETE FROM nope")
	for _, e := range []error{noTx, noTable} {
		if se := (*sqlite.Error)(nil); !errors.As(e, &se) || se.Code() != sqliteError {
			t.Fatalf("not an SQLITE_ERROR of the driver: %v", e)
		}
	}
	const quiet, loud = `level=DEBUG msg="rollback: SQLite had already rolled the transaction back"`, `level=ERROR msg="rollback failed"`
	for _, c := range []struct {
		name string
		err  error
		want string // "" = nothing logged
	}{
		{"committed or rolled back", nil, ""},
		{"ended by database/sql", sql.ErrTxDone, ""},
		{"already rolled back by SQLite", noTx, quiet},
		{"another SQLITE_ERROR", noTable, loud},
		{"any other error", errors.New("disk I/O error"), loud},
	} {
		buf.Reset()
		db.logRollback(ctx, c.err)
		if got := strings.TrimSpace(buf.String()); (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: logged %q, want %q", c.name, got, c.want)
		}
	}
}
