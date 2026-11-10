package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// POST /core/data/purge (S-CORE-1, INV-14, D-154): the box goes back to a fresh install. Every row of every table is deleted
// in one transaction, except the migration records (the schema stays); then the rows a fresh install has (the seeds of the
// migrations, the default state of the modules) are put back; the module data files and the snapshots are removed with it;
// one audit row says it happened. The encryption key (vedette.key) and the TLS certificate are not touched: the box must still
// start and be reachable.

// CodeConfirmMismatch is the 400 of a purge whose typed name is not the organization's (API_CONVENTIONS 3.3).
const CodeConfirmMismatch = "confirm_mismatch"

// restartDelay is how long after the answer the process is asked to restart (HandlersConfig.Restart): enough for the response
// to leave and the browser to see the end of the session.
const restartDelay = 500 * time.Millisecond

// SchemaSet is the migrations of one module, in the order main applies them. The purge builds a scratch database from them
// to learn what a fresh install holds (seed rows) instead of keeping a second list that would go stale.
type SchemaSet struct {
	Module string
	FS     fs.FS
}

// dataFileRE is what cmd/vedette may name as a module data file: a plain file name in core_data, never a path (D-151).
var dataFileRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// dataFileSuffixes are the files SQLite keeps beside a database.
var dataFileSuffixes = []string{"", "-wal", "-shm", "-journal"}

func checkDataFiles(names []string) error {
	for _, n := range names {
		if !dataFileRE.MatchString(n) || strings.HasPrefix(n, "vedette") || n == snapshotsDir || n == "tmp" {
			return fmt.Errorf("core: data file %q is not a plain module file name (^[a-z0-9][a-z0-9_.-]{0,63}$; not vedette*, snapshots or tmp)", n)
		}
	}
	return nil
}

// CorePostCoreDataPurge implements POST /core/data/purge (admin). A wrong name answers 400 confirm_mismatch and deletes nothing:
// the check runs before the scratch database, the file removal and the transaction, and again inside the transaction. The reply
// lists how many rows each table lost (tables that were empty are left out); the session ends with the users.
func (h *APIHandlers) CorePostCoreDataPurge(ctx context.Context, req *oas.CorePostCoreDataPurgeReq) (*oas.CorePostCoreDataPurgeOK, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	if len(h.schema) == 0 {
		return nil, errors.New("core: purge needs HandlersConfig.Schema")
	}
	org, err := coredb.New(h.db.Reader()).GetOrg(ctx)
	if err != nil && !isNoRows(err) {
		return nil, fmt.Errorf("core: read org: %w", err)
	}
	if req.Confirm != org.Name || org.Name == "" {
		return nil, confirmMismatch()
	}
	seeds, err := h.freshRows(ctx)
	if err != nil {
		return nil, err
	}
	var removed map[string]float64
	var publish func() // applies the module Change to the registry's cache once the transaction has committed
	err = h.db.Write(ctx, func(tx *sql.Tx) error {
		if err := h.auth.CheckAdmin(ctx, tx, c.ID, c.SessionID); err != nil {
			return err
		}
		cur, err := coredb.New(tx).GetOrg(ctx)
		if err != nil {
			return fmt.Errorf("core: read org: %w", err)
		}
		if req.Confirm != cur.Name {
			return confirmMismatch()
		}
		if removed, err = wipe(ctx, tx, seeds); err != nil {
			return err
		}
		// The files go while the transaction is still open: a failure here rolls the rows back, so a retry finds everything.
		if err := h.removeDataFiles(); err != nil {
			return err
		}
		ch, err := h.reg.Reset(ctx, tx)
		if err != nil {
			return err
		}
		publish = func() { h.reg.Publish(ch) }
		// No name of a person: the account is gone with the rest, and the new box's first log row says only that it was wiped.
		return h.audit.Append(ctx, tx, audit.Entry{User: "system", Action: "data.purge", Target: "all data", Detail: "deleted by an administrator; the box is back to first-run setup"})
	})
	if err != nil {
		return nil, err
	}
	publish()
	if err := h.db.Compact(ctx); err != nil { // the deleted rows must not stay in the free pages or the log of the file
		h.log.ErrorContext(ctx, "compacting the database after a purge failed", "error", err)
	}
	// The box is open for first-run setup again: it needs its one-time code, printed in the log like at every start (D-75).
	if code, err := h.EnsureSetupCode(ctx); err != nil {
		h.log.ErrorContext(ctx, "making the setup code after a purge failed", "error", err)
	} else if code != "" {
		h.log.InfoContext(ctx, "first-run setup is open: enter this one-time setup code on the setup page", "setup_code", code)
	}
	if x, ok := server.ExchangeFrom(ctx); ok {
		for _, ck := range auth.ClearCookies() {
			x.SetCookie(ck)
		}
	}
	if h.restart != nil {
		time.AfterFunc(restartDelay, h.restart)
	}
	return &oas.CorePostCoreDataPurgeOK{Ok: true, Removed: oas.CorePostCoreDataPurgeOKRemoved(removed)}, nil
}

func confirmMismatch() *apierr.Error {
	return apierr.New(400, CodeConfirmMismatch, "The organization name does not match. Type it exactly to confirm deletion.")
}

// seedRow is one row of a fresh install: the values of one table row, by column.
type seedRow struct {
	table string
	cols  []string
	vals  []any
}

// freshRows builds a scratch database from the migrations of every module and reads what a fresh install holds in the tables
// (the INSERTs of the migrations: singleton settings, the default honeytrap services, the AI job list). It is a few rows; the
// scratch file lives in core_data/tmp (the data volume; the rest of the container may be read-only) and is removed before return.
func (h *APIHandlers) freshRows(ctx context.Context) ([]seedRow, error) {
	base := os.TempDir()
	if h.dataDir != "" {
		base = filepath.Join(h.dataDir, "tmp")
		if err := os.MkdirAll(base, 0o700); err != nil {
			return nil, fmt.Errorf("core: purge scratch dir: %w", err)
		}
	}
	dir, err := os.MkdirTemp(base, "purge-fresh-")
	if err != nil {
		return nil, fmt.Errorf("core: purge scratch dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	db, err := store.Open(ctx, filepath.Join(dir, "fresh.db"), slog.New(slog.DiscardHandler))
	if err != nil {
		return nil, fmt.Errorf("core: purge scratch database: %w", err)
	}
	defer func() { _ = db.Close() }()
	for _, s := range h.schema {
		if err := store.Migrate(ctx, db, s.Module, s.FS); err != nil {
			return nil, fmt.Errorf("core: purge scratch database: %w", err)
		}
	}
	tables, names, err := dataTables(ctx, db.Reader())
	if err != nil {
		return nil, err
	}
	var out []seedRow
	for _, name := range names {
		cols := make([]string, len(tables[name]))
		quoted := make([]string, len(cols))
		for i, c := range tables[name] {
			cols[i], quoted[i] = c.Name, quoteIdent(c.Name)
		}
		rows, err := db.Reader().QueryContext(ctx, "SELECT "+strings.Join(quoted, ", ")+" FROM "+quoteIdent(name))
		if err != nil {
			return nil, fmt.Errorf("core: purge scratch database: %w", err)
		}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("core: purge scratch database: %w", err)
			}
			out = append(out, seedRow{table: name, cols: cols, vals: vals})
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return nil, fmt.Errorf("core: purge scratch database: %w", err)
		}
	}
	return out, nil
}

// wipe deletes every row of every data table inside tx and puts the seeds back. The append-only triggers (core_audit,
// resp_log, ...) are dropped for the deletion and created again from the text SQLite kept, in the same transaction: DDL is
// transactional, so a failure leaves them in place. Foreign keys are checked at commit, so the order of the tables does not
// matter. The result is how many rows each table lost beyond its seeds; empty tables are left out.
func wipe(ctx context.Context, tx *sql.Tx, seeds []seedRow) (map[string]float64, error) {
	if _, err := tx.ExecContext(ctx, "PRAGMA defer_foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("core: purge: %w", err)
	}
	tables, names, err := dataTables(ctx, tx)
	if err != nil {
		return nil, err
	}
	type trigger struct{ name, sql string }
	var triggers []trigger
	rows, err := tx.QueryContext(ctx, `SELECT name, sql FROM sqlite_master WHERE type = 'trigger' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("core: purge: list triggers: %w", err)
	}
	for rows.Next() {
		var t trigger
		if err := rows.Scan(&t.name, &t.sql); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("core: purge: list triggers: %w", err)
		}
		triggers = append(triggers, t)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("core: purge: list triggers: %w", err)
	}
	for _, t := range triggers {
		if _, err := tx.ExecContext(ctx, "DROP TRIGGER "+quoteIdent(t.name)); err != nil {
			return nil, fmt.Errorf("core: purge: drop trigger %s: %w", t.name, err)
		}
	}
	removed := make(map[string]float64, len(names))
	for _, n := range names {
		res, err := tx.ExecContext(ctx, "DELETE FROM "+quoteIdent(n)) //nolint:gosec // the name comes from sqlite_master and is quoted
		if err != nil {
			return nil, fmt.Errorf("core: purge: delete from %s: %w", n, err)
		}
		cnt, err := res.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("core: purge: count %s: %w", n, err)
		}
		removed[n] = float64(cnt)
	}
	var hasSeq int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name = 'sqlite_sequence'`).Scan(&hasSeq); err != nil {
		return nil, fmt.Errorf("core: purge: %w", err)
	}
	if hasSeq > 0 { // AUTOINCREMENT counters start again, like a new file's
		if _, err := tx.ExecContext(ctx, "DELETE FROM sqlite_sequence"); err != nil {
			return nil, fmt.Errorf("core: purge: %w", err)
		}
	}
	for _, s := range seeds {
		if _, ok := tables[s.table]; !ok {
			continue // a table the scratch database has and this one has not cannot happen with the same migrations; be quiet if it does
		}
		quoted := make([]string, len(s.cols))
		for i, c := range s.cols {
			quoted[i] = quoteIdent(c)
		}
		q := "INSERT INTO " + quoteIdent(s.table) + " (" + strings.Join(quoted, ", ") + ") VALUES (?" + strings.Repeat(", ?", len(s.cols)-1) + ")" //nolint:gosec // identifiers from sqlite_master, quoted
		if _, err := tx.ExecContext(ctx, q, s.vals...); err != nil {
			return nil, fmt.Errorf("core: purge: seed %s: %w", s.table, err)
		}
		removed[s.table]--
	}
	for _, t := range triggers {
		if _, err := tx.ExecContext(ctx, t.sql); err != nil {
			return nil, fmt.Errorf("core: purge: restore trigger %s: %w", t.name, err)
		}
	}
	for n, v := range removed {
		if v <= 0 {
			delete(removed, n)
		}
	}
	return removed, nil
}

// removeDataFiles deletes what lives next to the database and is data: the module data files that cmd/vedette named (and the
// -wal, -shm and -journal files SQLite keeps beside them) and the snapshots of the backups (a "delete all data" must not leave
// a copy that can be restored). The key and the certificate stay. A file that is already gone is not an error.
func (h *APIHandlers) removeDataFiles() error {
	if h.dataDir == "" {
		return nil
	}
	for _, n := range h.dataFiles {
		for _, suf := range dataFileSuffixes {
			if err := os.Remove(filepath.Join(h.dataDir, n+suf)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("core: purge: remove %s: %w", n+suf, err)
			}
		}
	}
	if err := os.RemoveAll(filepath.Join(h.dataDir, snapshotsDir)); err != nil {
		return fmt.Errorf("core: purge: remove snapshots: %w", err)
	}
	return nil
}
