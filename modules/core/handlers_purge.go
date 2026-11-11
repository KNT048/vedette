package core

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
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
	// Step-up (H2, D-76, D-98): the current password, counted against the re-auth limiter, then a fresh two-step code when it is on.
	if err := h.auth.VerifyOwnPassword(ctx, c.ID, req.Password, "Wrong password. The password is needed to delete all data."); err != nil {
		return nil, err
	}
	if u, err := h.auth.GetUser(ctx, c.ID); err != nil {
		return nil, fmt.Errorf("core: read user: %w", err)
	} else if u.TwofaMethod != "" {
		if _, err := h.auth.VerifyTwoStep(ctx, c.ID, req.Code.Or(""), "core.data_purge", "Delete all data of "+cutAtRune(org.Name, 80)); err != nil {
			return nil, err
		}
	}
	// A trace that survives the data: the journal, never the database (it is about to be deleted). The user id alone points to nobody
	// once the users are gone, so the email goes in too.
	if x, ok := server.ExchangeFrom(ctx); ok {
		h.log.WarnContext(ctx, "data purge requested", "user_id", c.ID, "email", c.Email, "ip", x.ClientAddr().String())
	}
	// N4: from here core's own endpoints that start host work (OS update, backup, network change) answer 409 busy, so nothing new can
	// start between the busy checks below and the wipe. It is cleared when the purge fails; after a success the process stops.
	if !h.gate.TryBegin() {
		return nil, apierr.New(409, codeBusy, "A data purge is already running.")
	}
	done := false
	defer func() {
		if !done {
			h.gate.End()
		}
	}()
	if h.osBusy != nil && h.osBusy(ctx) { // M2: core's own OS update (INV-12)
		return nil, apierr.New(409, codeBusy, "An update run is in progress. Wait for it to finish, then try again.")
	}
	// N3: everything local and reversible comes first, the host's irreversible deletion of the backups last, just before the transaction.
	// A failure before it leaves the box as it was; after it the answer says the backups are already gone.
	var kept []oas.CorePostCoreDataPurgeOKKeptItem
	if h.beforeWipe != nil {
		if err := h.beforeWipe(ctx); err != nil {
			return nil, fmt.Errorf("core: before the purge: %w", err)
		}
	}
	seeds, err := h.freshRows(ctx)
	if err != nil {
		return nil, err
	}
	stagedKey := ""
	if h.keyPath != "" {
		if stagedKey, err = secrets.StageKeyFile(h.keyPath); err != nil {
			return nil, err
		}
	}
	trash, err := h.newTrash()
	if err != nil {
		_ = os.Remove(stagedKey)
		return nil, err
	}
	// The other databases (logs.db) are frozen under their own write lock before their files move: a write in flight finishes first, and
	// nothing can land in the moved file (or in a file made after) until the process has stopped. Thawed when the purge fails.
	thaw := func() {
		for _, x := range h.freezes {
			x.Unfreeze()
		}
	}
	for _, x := range h.freezes {
		if err := x.Write(ctx, func(*sql.Tx) error { x.Freeze(); return nil }); err != nil {
			thaw()
			_ = os.Remove(stagedKey)
			trash.discard()
			return nil, fmt.Errorf("core: purge: freeze a database: %w", err)
		}
	}
	abandon := func() { // nothing irreversible has happened: put the local prep away
		thaw()
		trash.discard()
		if stagedKey != "" {
			_ = os.Remove(stagedKey)
		}
	}
	hostDone := false
	if skipped, err := h.purgeHostBackups(ctx, c); err != nil {
		abandon()
		return nil, err
	} else if skipped {
		kept = append(kept, oas.CorePostCoreDataPurgeOKKeptItemHostBackups)
	} else {
		hostDone = true
	}
	kept = append(kept, h.alsoKept...)
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
		if removed, err = wipe(ctx, tx, seeds, h.keepRows); err != nil {
			return err
		}
		// The files are moved into the trash while the transaction is still open and moved back when it does not commit (M3):
		// a failure anywhere leaves rows and files as they were, so a retry finds everything.
		if err := h.takeDataFiles(trash); err != nil {
			return err
		}
		if err := h.markCompactPending(); err != nil {
			return err
		}
		ch, err := h.reg.Reset(ctx, tx)
		if err != nil {
			return err
		}
		publish = func() { h.reg.Publish(ch) }
		// No name of a person: the account is gone with the rest, and the new box's first log row says only that it was wiped.
		if err := h.audit.Append(ctx, tx, audit.Entry{User: "system", Action: "data.purge", Target: "all data", Detail: "deleted by an administrator; the box is back to first-run setup"}); err != nil {
			return err
		}
		h.db.Freeze() // M5: from the commit on nothing can write until the process has stopped (the box starts fresh)
		return nil
	})
	if err != nil {
		h.db.Unfreeze()
		thaw()
		if rerr := trash.restore(); rerr != nil {
			h.log.ErrorContext(ctx, "purge failed and the files could not be put back", "error", rerr, "trash", trash.dir)
		} else {
			h.unmarkCompactPending()
			trash.discard()
		}
		if stagedKey != "" {
			_ = os.Remove(stagedKey)
		}
		if hostDone { // the helper's backups are gone and this box's data is not: say so, whatever went wrong
			h.log.ErrorContext(ctx, "data purge failed after the helper deleted the backups", "error", err)
			return nil, apierr.New(500, CodeBackupsDeleted, "The backups held by the operating system helper were already deleted, but the data on this box could not be deleted. The data on this box is still there. Fix the problem described in the box log and delete all data again.")
		}
		return nil, err
	}
	done = true // the box is wiped: the gate stays shut until the process stops
	publish()
	trash.discard() // the old data is gone for good
	if stagedKey != "" {
		// H1 (a): every old copy of the key (archives, snapshots) now opens nothing this box holds.
		if err := secrets.PromoteKeyFile(stagedKey, h.keyPath); err != nil {
			h.log.ErrorContext(ctx, "the purge could not replace the encryption key", "error", err)
			kept = append(kept, oas.CorePostCoreDataPurgeOKKeptItemKeyNotReplaced)
		}
	}
	if x, ok := server.ExchangeFrom(ctx); ok {
		for _, ck := range auth.ClearCookies() {
			x.SetCookie(ck)
		}
	}
	if h.restart != nil { // the compaction and the new setup code come with the next start
		time.AfterFunc(restartDelay, h.restart)
	}
	if kept == nil {
		kept = []oas.CorePostCoreDataPurgeOKKeptItem{}
	}
	return &oas.CorePostCoreDataPurgeOK{Ok: true, Removed: oas.CorePostCoreDataPurgeOKRemoved(removed), Kept: kept}, nil
}

// PurgeHost is the part of vedette-host the purge needs: the runs in progress and the deletion of every backup it holds
// (host command backup.purge, D-156; the host client's method may be named differently, cmd/vedette adapts it).
type PurgeHost interface {
	ListRuns(ctx context.Context, limit int) ([]api.Run, error)
	BackupPurge(ctx context.Context, requestID, actor string) (deleted int, err error)
}

// CodeBackupsDeleted is the 500 of a purge that failed after the helper had deleted its backups (API_CONVENTIONS 3.3).
const CodeBackupsDeleted = "backups_already_deleted"

// PurgeGate keeps a factory reset and core's own host work apart, in both directions (N4, L1). Host work (an OS update, a backup, a
// network change) takes the read side for the whole of its call (Enter); the purge takes the write side (TryBegin). Neither waits: a
// purge that finds host work running, and host work that finds a purge running, answer 409 busy. One gate is shared by the handlers of
// core; a nil gate is never shut.
type PurgeGate struct {
	mu      sync.RWMutex
	purging atomic.Bool
}

// TryBegin takes the write side; false when host work is running or another purge is.
func (g *PurgeGate) TryBegin() bool {
	if g == nil {
		return true
	}
	if !g.mu.TryLock() {
		return false
	}
	g.purging.Store(true)
	return true
}

// End gives the write side back (a purge that failed; after a success the process stops with the gate shut).
func (g *PurgeGate) End() {
	if g != nil && g.purging.CompareAndSwap(true, false) {
		g.mu.Unlock()
	}
}

// Enter takes the read side for one piece of host work; ok is false while a purge runs. Call leave when the work is done.
func (g *PurgeGate) Enter() (leave func(), ok bool) {
	if g == nil {
		return func() {}, true
	}
	if !g.mu.TryRLock() {
		return nil, false
	}
	return g.mu.RUnlock, true
}

// Active reports whether a purge is running.
func (g *PurgeGate) Active() bool { return g != nil && g.purging.Load() }

// errPurging is what an endpoint that starts host work answers while a purge runs.
func errPurging() *apierr.Error {
	return apierr.New(409, codeBusy, "All data on this box is being deleted. Wait for it to finish.")
}

// CodeTransitionPending is the 412 of a purge while core's update journal is pending or unrecoverable (host answer transition_pending).
const CodeTransitionPending = "transition_pending"

// purgeHostBackups asks the helper for its running commands (409 busy when one is not finished: an update or a backup would race
// the purge) and has it delete every backup. skipped is true when this box is configured without a helper (purgeHost nil, the container-only install): there is nothing to
// delete and the answer says so. A configured helper that does not answer, or refuses, stops the purge (502 host_unreachable or the
// mapped error); the caller has deleted nothing yet.
func (h *APIHandlers) purgeHostBackups(ctx context.Context, c caller) (skipped bool, err error) {
	if h.purgeHost == nil {
		return true, nil
	}
	// Fail closed (N1): a helper that is configured and does not answer, a missing socket file included (it is missing while vedette-host
	// restarts), is 502 and nothing is wiped. Only a box configured without a helper (purgeHost nil) skips the call.
	noHelper := func(err error) (bool, error) {
		switch {
		case errors.Is(err, client.ErrUnreachable) || errors.Is(err, client.ErrDenied):
			h.log.WarnContext(ctx, "data purge: vedette-host does not answer", "error", err)
			return false, apierr.New(502, CodeHostUnreachable, "The operating system helper (vedette-host) is not answering, so its backups cannot be deleted. Nothing was deleted. Try again in a minute.")
		}
		var he *client.Error
		if errors.As(err, &he) && he.Code == CodeTransitionPending {
			return false, apierr.New(412, CodeTransitionPending, "An update of Vedette is waiting to be completed or could not be recovered, so the box cannot be wiped now. Nothing was deleted. See the RUNBOOK (update journal) and finish or roll back the update first.")
		}
		return false, hostErr(ctx, h.log, err)
	}
	runs, err := h.purgeHost.ListRuns(ctx, 50)
	if err != nil {
		return noHelper(err)
	}
	for _, r := range runs {
		if !r.Status.Terminal() {
			return false, apierr.New(409, codeBusy, "The operating system helper is running a command. Wait for it to finish, then try again.")
		}
	}
	requestID, err := newRequestID()
	if err != nil {
		return false, err
	}
	n, err := h.purgeHost.BackupPurge(ctx, requestID, actorLabel(c.Email, c.ID))
	if err != nil {
		return noHelper(err)
	}
	h.log.InfoContext(ctx, "data purge: backups deleted by the helper", "deleted", n)
	return false, nil
}

func confirmMismatch() *apierr.Error {
	return apierr.New(400, CodeConfirmMismatch, "The organization name does not match. Type it exactly to confirm deletion.")
}

// KeepRow names rows that survive the purge: the rows of Table whose Column equals Value. They describe something the purge leaves on
// the box (the honeypot's read position in its raw log, which the honeypot container owns), so that the fresh box does not read old
// events as new. The identifiers come from cmd/vedette, never from a request.
type KeepRow struct{ Table, Column, Value string }

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
func wipe(ctx context.Context, tx *sql.Tx, seeds []seedRow, keep []KeepRow) (map[string]float64, error) {
	if _, err := tx.ExecContext(ctx, "PRAGMA defer_foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("core: purge: %w", err)
	}
	tables, names, err := dataTables(ctx, tx)
	if err != nil {
		return nil, err
	}
	// Rows that describe what the purge leaves on the box (KeepRow) are read before the delete and put back with the seeds.
	for _, k := range keep {
		cols, ok := tables[k.Table]
		if !ok {
			continue
		}
		names := make([]string, len(cols))
		quoted := make([]string, len(cols))
		for i, c := range cols {
			names[i], quoted[i] = c.Name, quoteIdent(c.Name)
		}
		rows, err := tx.QueryContext(ctx, "SELECT "+strings.Join(quoted, ", ")+" FROM "+quoteIdent(k.Table)+" WHERE "+quoteIdent(k.Column)+" = ?", k.Value) //nolint:gosec // identifiers from sqlite_master or cmd/vedette's own list, quoted
		if err != nil {
			return nil, fmt.Errorf("core: purge: read the rows to keep of %s: %w", k.Table, err)
		}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("core: purge: read the rows to keep of %s: %w", k.Table, err)
			}
			seeds = append(slices.Clone(seeds), seedRow{table: k.Table, cols: names, vals: vals})
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return nil, fmt.Errorf("core: purge: read the rows to keep of %s: %w", k.Table, err)
		}
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
	fts, err := ftsTables(ctx, tx)
	if err != nil {
		return nil, err
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
	if err := resetFTS(ctx, tx, fts); err != nil {
		return nil, err
	}
	for n, v := range removed {
		if v <= 0 {
			delete(removed, n)
		}
	}
	return removed, nil
}

// ftsTable is an FTS5 index and how it keeps its text (https://sqlite.org/fts5.html#external_content_and_contentless_tables).
type ftsTable struct {
	name string
	mode string // "regular" (its own content), "external" (content=<table>) or "contentless" (content='')
}

// ftsTables lists the FTS5 virtual tables. The mode is read from the CREATE statement SQLite kept: a regular table has a
// <name>_content shadow table, content='' (or "") is contentless, any other content= option names an external table.
func ftsTables(ctx context.Context, tx *sql.Tx) ([]ftsTable, error) {
	rows, err := tx.QueryContext(ctx, `SELECT m.name, m.sql, EXISTS (SELECT 1 FROM sqlite_master c WHERE c.type = 'table' AND c.name = m.name || '_content')
		FROM sqlite_master m JOIN pragma_table_list l ON l.schema = 'main' AND l.name = m.name
		WHERE m.type = 'table' AND l.type = 'virtual' AND lower(m.sql) LIKE '%using%fts5%' ORDER BY m.name`)
	if err != nil {
		return nil, fmt.Errorf("core: purge: list FTS5 tables: %w", err)
	}
	var out []ftsTable
	for rows.Next() {
		var (
			t        ftsTable
			text     string
			hasOwned bool
		)
		if err := rows.Scan(&t.name, &text, &hasOwned); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("core: purge: list FTS5 tables: %w", err)
		}
		opts := strings.ToLower(strings.Join(strings.Fields(text), ""))
		switch {
		case hasOwned:
			t.mode = "regular"
		case strings.Contains(opts, "content=''") || strings.Contains(opts, `content=""`):
			t.mode = "contentless"
		default:
			t.mode = "external"
		}
		out = append(out, t)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("core: purge: list FTS5 tables: %w", err)
	}
	return out, nil
}

// resetFTS empties every FTS5 index through FTS5's own commands, after the data tables are emptied, the seeds put back and
// the triggers restored: deleting rows of its shadow tables directly (what wipe did before) corrupts the index for good
// ("fts5: corruption found"). A regular table holds its own text and is emptied with DELETE; an external-content table is
// rebuilt from its content table, which then holds only seeds; a contentless one is emptied with delete-all.
func resetFTS(ctx context.Context, tx *sql.Tx, tables []ftsTable) error {
	for _, t := range tables {
		q := "DELETE FROM " + quoteIdent(t.name) //nolint:gosec // the name comes from sqlite_master and is quoted
		switch t.mode {
		case "external":
			q = "INSERT INTO " + quoteIdent(t.name) + "(" + quoteIdent(t.name) + ") VALUES ('rebuild')" //nolint:gosec // as above
		case "contentless":
			q = "INSERT INTO " + quoteIdent(t.name) + "(" + quoteIdent(t.name) + ") VALUES ('delete-all')" //nolint:gosec // as above
		}
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("core: purge: reset the FTS5 index %s: %w", t.name, err)
		}
	}
	return nil
}

// The trash (M3): what the purge deletes from the disk is first moved into core_data/tmp/purge-trash-<id>/, so that a failure
// before the commit can move it back, and deleted for good after the commit. A leftover of a crash is swept at the next start
// (sweepPurgeLeftovers): a crash before the commit loses the module files in it, the database being untouched, which is harmless.
const (
	trashPrefix     = "purge-trash-"
	freshPrefix     = "purge-fresh-"
	compactMarker   = "purge-compact-pending"
	stagedKeySuffix = ".new"
	purgeScratchDir = "tmp"
)

type trash struct {
	dir   string
	moved [][2]string // from, to
}

// newTrash makes the trash directory (mode 0700). With no data directory it is empty and moves nothing.
func (h *APIHandlers) newTrash() (*trash, error) {
	if h.dataDir == "" {
		return &trash{}, nil
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("core: purge trash id: %w", err)
	}
	dir := filepath.Join(h.dataDir, purgeScratchDir, trashPrefix+hex.EncodeToString(raw[:]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("core: purge trash: %w", err)
	}
	return &trash{dir: dir}, nil
}

// take moves src into the trash; a file that is not there is not an error.
func (t *trash) take(src string) error {
	if t.dir == "" {
		return nil
	}
	if _, err := os.Lstat(src); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	dst := filepath.Join(t.dir, fmt.Sprintf("%03d-%s", len(t.moved), filepath.Base(src)))
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("core: purge: move %s aside: %w", filepath.Base(src), err)
	}
	t.moved = append(t.moved, [2]string{src, dst})
	return nil
}

// restore moves everything back, newest first. It stops at the first failure and says which.
func (t *trash) restore() error {
	for i := len(t.moved) - 1; i >= 0; i-- {
		if err := os.Rename(t.moved[i][1], t.moved[i][0]); err != nil {
			return fmt.Errorf("core: purge: put %s back: %w", filepath.Base(t.moved[i][0]), err)
		}
		t.moved = t.moved[:i]
	}
	return nil
}

// discard deletes the trash.
func (t *trash) discard() {
	if t.dir != "" {
		_ = os.RemoveAll(t.dir)
	}
}

// takeDataFiles moves what lives next to the database and is data into the trash: the module data files that cmd/vedette named
// (and the -wal, -shm and -journal files SQLite keeps beside them) and the snapshots of the backups (a "delete all data" must not
// leave a copy that can be restored). The key and the certificate stay (the key is replaced after the commit).
func (h *APIHandlers) takeDataFiles(t *trash) error {
	if h.dataDir == "" {
		return nil
	}
	for _, n := range h.dataFiles {
		for _, suf := range dataFileSuffixes {
			if err := t.take(filepath.Join(h.dataDir, n+suf)); err != nil {
				return err
			}
		}
	}
	if err := t.take(filepath.Join(h.dataDir, snapshotsDir)); err != nil {
		return err
	}
	// Old data the helper's backup purge never touches (restore and rollback leftovers, quarantined files): exact name patterns, regular
	// files and directories only. DirEntry.Type does not follow symbolic links, so a link with such a name is neither moved nor followed.
	entries, err := os.ReadDir(h.dataDir)
	if err != nil {
		return fmt.Errorf("core: purge: read the data directory: %w", err)
	}
	for _, e := range entries {
		if oldDataRE.MatchString(e.Name()) && (e.Type().IsRegular() || e.IsDir()) {
			if err := t.take(filepath.Join(h.dataDir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// oldDataRE names what core_data keeps of earlier states: a partly restored database or key (.vedette-restore-*), what a rollback keeps
// (vedette.db.rollback, vedette.key.rollback) and files quarantined by name (*.quarantine-*).
var oldDataRE = regexp.MustCompile(`^(\.vedette-restore-[A-Za-z0-9._-]*|vedette\.db\.rollback|vedette\.key\.rollback|[A-Za-z0-9][A-Za-z0-9._-]*\.quarantine-[A-Za-z0-9._-]+)$`)

// markCompactPending leaves a file that tells the next start to compact the database (VACUUM): the purge cannot, because it
// freezes the database at its commit. Written inside the transaction, so a crash after the commit still finds it.
func (h *APIHandlers) markCompactPending() error {
	if h.dataDir == "" {
		return nil
	}
	if err := os.WriteFile(filepath.Join(h.dataDir, compactMarker), []byte("compact the database at the next start\n"), 0o600); err != nil {
		return fmt.Errorf("core: purge: compaction marker: %w", err)
	}
	return nil
}

func (h *APIHandlers) unmarkCompactPending() {
	if h.dataDir != "" {
		_ = os.Remove(filepath.Join(h.dataDir, compactMarker))
	}
}

// CompactIfPending is called at start (cmd/vedette, before the scheduler): when a purge left its marker, the database is compacted so
// the deleted rows are no longer in the bytes of the file or its log. The marker goes only after a success, so a failure is
// retried at every start until it works (L4); the error is returned for the caller to log, not to stop the box.
func CompactIfPending(ctx context.Context, db *store.DB, dataDir string) error {
	marker := filepath.Join(dataDir, compactMarker)
	if _, err := os.Stat(marker); err != nil {
		return nil //nolint:nilerr // no marker: nothing to do
	}
	if err := db.Compact(ctx); err != nil {
		return err //nolint:wrapcheck // already store-prefixed
	}
	if err := os.Remove(marker); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("core: remove compaction marker: %w", err)
	}
	return nil
}

// sweepPurgeLeftovers removes what an interrupted purge left: trash directories, scratch databases and a staged key.
func sweepPurgeLeftovers(dataDir, keyPath string) {
	dir := filepath.Join(dataDir, purgeScratchDir)
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), trashPrefix) || strings.HasPrefix(e.Name(), freshPrefix) {
				_ = os.RemoveAll(filepath.Join(dir, e.Name()))
			}
		}
	}
	if keyPath != "" {
		_ = os.Remove(keyPath + stagedKeySuffix)
	}
}
