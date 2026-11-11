// Package store opens the SQLite database (WAL, one writer plus a reader pool),
// runs module migrations and provides the transaction helper every write goes through
// (docs/DATA_MODEL.md section 6 and 7). Pure Go driver (modernc.org/sqlite), no cgo.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pressly/goose/v3"
	"modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// DB is the application database: one writer connection and a pool of read-only connections.
type DB struct {
	w    *sql.DB
	r    *sql.DB
	path string // absolute path of the database file
	log  *slog.Logger
	// frozen makes every later Write fail: the factory reset sets it inside its own transaction, so nothing (a job, a request) can
	// write between the wipe and the process stopping (D-154). It is not a lock for normal use.
	frozen atomic.Bool
}

// ErrFrozen is what Write answers while the database is frozen.
var ErrFrozen = errors.New("store: the database is frozen: the box is being reset")

// Freeze makes every Write that starts after the current one commits fail with ErrFrozen. Call it from inside a Write callback; if
// that transaction then fails to commit, call Unfreeze.
func (db *DB) Freeze() { db.frozen.Store(true) }

// Unfreeze undoes Freeze.
func (db *DB) Unfreeze() { db.frozen.Store(false) }

// Open opens the database at path. A missing file is created with mode 0600; an existing file
// with any group or other permission bit is refused (it holds audit data and encrypted secrets).
// The parent directory must exist. log must not be nil.
func Open(ctx context.Context, path string, log *slog.Logger) (*DB, error) {
	if path == "" {
		return nil, errors.New("store: open: empty path")
	}
	if log == nil {
		return nil, errors.New("store: open: nil logger")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("store: resolve path: %w", err)
	}
	if err := ensurePrivateFile(abs); err != nil {
		return nil, err
	}
	w, err := openPool(abs, true)
	if err != nil {
		return nil, fmt.Errorf("store: open writer: %w", err)
	}
	w.SetMaxOpenConns(1)
	if err := verifyWAL(ctx, w); err != nil {
		_ = w.Close()
		return nil, err
	}
	r, err := openPool(abs, false)
	if err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("store: open reader: %w", err)
	}
	if err := r.PingContext(ctx); err != nil {
		_ = w.Close()
		_ = r.Close()
		return nil, fmt.Errorf("store: ping reader: %w", err)
	}
	return &DB{w: w, r: r, path: abs, log: log}, nil
}

// ensurePrivateFile creates path with mode 0600 if it does not exist, and otherwise refuses a
// file that is not a regular file or is accessible to group or others. SQLite gives the -wal and
// -shm files the mode of the main file.
func ensurePrivateFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // path comes from configuration, not from a request
	if err == nil {
		if err := f.Close(); err != nil {
			return fmt.Errorf("store: create database file: %w", err)
		}
		return nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("store: create database file: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("store: stat database file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("store: %s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("store: database file %s has mode %#o; group and other access must be off (chmod 600)", path, perm)
	}
	return nil
}

func openPool(abs string, writer bool) (*sql.DB, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	if writer {
		q.Set("_txlock", "immediate") // BEGIN IMMEDIATE: take the write lock up front, no upgrade deadlocks
	} else {
		q.Set("mode", "ro") // read-only at the file level: even PRAGMA query_only=0 cannot enable writes
		q.Add("_pragma", "query_only(1)")
	}
	u := url.URL{Scheme: "file", Path: abs, RawQuery: q.Encode()}
	return sql.Open("sqlite", u.String())
}

// verifyWAL reads the journal mode back: a DSN pragma that the driver ignored must not go unnoticed.
func verifyWAL(ctx context.Context, w *sql.DB) error {
	var mode string
	if err := w.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return fmt.Errorf("store: read journal_mode: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("store: journal_mode is %q, want wal", mode)
	}
	return nil
}

// Close closes both pools.
func (db *DB) Close() error {
	return errors.Join(db.r.Close(), db.w.Close())
}

// Reader returns the read-only pool. Writes through it fail (query_only).
func (db *DB) Reader() *sql.DB { return db.r }

// RequestWriteWait is how long a request waits for the writer connection before it is refused with ErrBusy (D-246). The HTTP
// servers set it on every request context with LimitWriteWait; jobs and other background work wait on their own context. (BEGIN
// IMMEDIATE may then still wait up to the busy_timeout of 5 s if another process held the file's write lock; nothing in the
// box does that in normal running.)
const RequestWriteWait = 5 * time.Second

// SlowWrite is the time holding the writer past which Write logs a warning with its caller (D-246): every other write waits
// that long.
const SlowWrite = time.Second

// ErrBusy is what Write answers when ctx carries a write wait limit (LimitWriteWait) and the writer stayed taken by another
// transaction for that long. Nothing was written. The HTTP layer answers it with 503 server_busy and Retry-After.
var ErrBusy = errors.New("store: the database writer is busy")

type waitKey struct{}

type waitLimit struct {
	d    time.Duration
	done <-chan struct{} // of the request: once it is closed, the limit no longer applies
}

// LimitWriteWait returns ctx with a limit of d on the time a Write waits for the writer connection; past it Write answers
// ErrBusy. The limit binds only while the request behind ctx is live and only on contexts that still end with it: a context
// detached with context.WithoutCancel (whose Done is nil: "this write must happen even if the caller leaves") waits on its own,
// and so does any write once the request has ended, also one that was already waiting (D-246).
func LimitWriteWait(ctx context.Context, d time.Duration) context.Context {
	return context.WithValue(ctx, waitKey{}, waitLimit{d: d, done: ctx.Done()})
}

// writeWait is the wait limit in force for ctx, if any, and the Done channel of its request.
func writeWait(ctx context.Context) (waitLimit, bool) {
	l, ok := ctx.Value(waitKey{}).(waitLimit)
	if !ok || l.d <= 0 {
		return waitLimit{}, false
	}
	if ctx.Done() == nil && l.done != nil { // detached from a cancellable request with WithoutCancel
		return waitLimit{}, false
	}
	select {
	case <-l.done: // nil (never closes) for a request context that cannot be cancelled: the limit stays
		return waitLimit{}, false
	default:
		return l, true
	}
}

var errWaitLimit = errors.New("store: write wait limit")

// writer takes the single writer connection, within the wait limit of ctx when one is in force.
func (db *DB) writer(ctx context.Context) (*sql.Conn, error) {
	l, limited := writeWait(ctx)
	if !limited {
		c, err := db.w.Conn(ctx)
		if err != nil {
			return nil, fmt.Errorf("store: begin: %w", err)
		}
		return c, nil
	}
	// The context only bounds the wait for the connection: sql.Conn does not keep it. At the limit the wait is cut only if the
	// request is still live; a request that ended while this write waited leaves it waiting on ctx alone.
	wctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	t := time.AfterFunc(l.d, func() {
		select {
		case <-l.done:
		default:
			cancel(errWaitLimit)
		}
	})
	defer t.Stop()
	c, err := db.w.Conn(wctx)
	if err == nil {
		return c, nil
	}
	if ctx.Err() == nil && errors.Is(context.Cause(wctx), errWaitLimit) {
		mod, fn := caller()
		db.log.WarnContext(ctx, "store: request refused, the database writer stayed busy", "module", mod, "caller", fn, "waited", l.d)
		return nil, ErrBusy
	}
	return nil, fmt.Errorf("store: begin: %w", err)
}

const repoPrefix = "github.com/knt048/vedette/"

// caller names the function that called Write (the frame below the last (*DB).Write on the stack, so also during a panic
// unwinding through Write) and its module: "feeds" for modules/feeds, else the package path in the repository ("core/jobs").
// Only names, never arguments.
func caller() (module, fn string) {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	next := false
	for {
		f, more := frames.Next()
		switch {
		case f.Function == repoPrefix+"core/store.(*DB).Write":
			next = true
		case next:
			next = false
			fn = f.Function
		}
		if !more {
			break
		}
	}
	pkg := fn
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		if j := strings.Index(pkg[i:], "."); j >= 0 {
			pkg = pkg[:i+j]
		}
	}
	return strings.TrimPrefix(strings.TrimPrefix(pkg, repoPrefix), "modules/"), fn
}

// Write runs fn in a BEGIN IMMEDIATE transaction on the single writer connection.
// It commits only when fn returns nil. On an error, a panic (re-raised) or runtime.Goexit
// (t.FailNow in a test) the transaction is rolled back, so the writer connection is never leaked.
// When ctx carries a wait limit (LimitWriteWait) and the writer stays taken past it, Write answers ErrBusy without running fn.
// A transaction that holds the writer longer than SlowWrite is logged with its caller (no SQL, no values).
func (db *DB) Write(ctx context.Context, fn func(tx *sql.Tx) error) error {
	conn, err := db.writer(ctx)
	if err != nil {
		return err
	}
	start := time.Now()
	defer func() { // runs last: after the commit or the rollback below, also on a panic
		_ = conn.Close() // back to the pool
		if held := time.Since(start); held > SlowWrite {
			mod, fn := caller()
			db.log.WarnContext(ctx, "store: a write transaction held the database writer", "module", mod, "caller", fn, "held", held.Round(time.Millisecond))
		}
	}()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	if db.frozen.Load() { // checked with the write lock held: a writer that queued behind the purge lands here
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			db.log.ErrorContext(ctx, "rollback failed", "error", rbErr)
		}
		return ErrFrozen
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		p := recover() // nil on a normal error return and on Goexit
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			db.log.ErrorContext(ctx, "rollback failed", "error", rbErr)
		}
		if p != nil {
			panic(p)
		}
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	committed = true
	return nil
}

// ErrDamaged is a database that SQLite's own check finds broken.
var ErrDamaged = errors.New("store: the database is damaged")

// Check runs PRAGMA integrity_check and foreign_key_check (DATA_MODEL section 6 rule 7).
func (db *DB) Check(ctx context.Context) error {
	if err := db.pragmaCheck(ctx, "integrity_check"); err != nil {
		return err
	}
	return db.foreignKeyCheck(ctx)
}

// QuickCheck runs PRAGMA quick_check (at most 20 problems): the structure of every page and index, without the slow comparison of
// index contents. The process runs it at start, before the migrations (D-87, host-api 6.11): a damaged database is refused (ErrDamaged),
// so the program stops and the host's health check reverts to the snapshot instead of a box writing on top of the damage.
func (db *DB) QuickCheck(ctx context.Context) error { return db.pragmaCheck(ctx, "quick_check(20)") }

func (db *DB) pragmaCheck(ctx context.Context, pragma string) error {
	name, _, _ := strings.Cut(pragma, "(")
	rows, err := db.r.QueryContext(ctx, "PRAGMA "+pragma)
	if err != nil {
		return fmt.Errorf("store: %s: %w", name, err)
	}
	var problems []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: %s: %w", name, err)
		}
		if line != "ok" {
			problems = append(problems, line)
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("store: %s: %w", name, err)
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s failed: %s", ErrDamaged, name, strings.Join(problems, "; "))
	}
	return nil
}

func (db *DB) foreignKeyCheck(ctx context.Context) error {
	rows, err := db.r.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("store: foreign_key_check: %w", err)
	}
	violations := 0
	for rows.Next() {
		violations++
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("store: foreign_key_check: %w", err)
	}
	if violations > 0 {
		return fmt.Errorf("store: foreign_key_check: %d violating rows", violations)
	}
	return nil
}

// SnapshotTo writes a consistent, self-contained copy of the database to path with VACUUM INTO: one file, no
// -wal or -shm (the copy is one read transaction, so the data is one moment). It runs on its own short-lived
// connection, opened read-only at the file level but without query_only (VACUUM INTO only reads the source),
// so on the WAL database the copy is a reader and writes made by others go on while it runs. path is created
// here with mode 0600 and must not exist; the caller owns the directory around it.
func (db *DB) SnapshotTo(ctx context.Context, path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // path is built by the caller from its own data directory
	if err != nil {
		return fmt.Errorf("store: snapshot: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("store: snapshot: %w", err)
	}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "busy_timeout(5000)")
	src, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: db.path, RawQuery: q.Encode()}).String())
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("store: snapshot: %w", err)
	}
	defer func() { _ = src.Close() }()
	src.SetMaxOpenConns(1)
	if _, err := src.ExecContext(ctx, "VACUUM INTO ?", path); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("store: snapshot: %w", err)
	}
	return nil
}

// Compact rewrites the database file without its free pages and truncates the write-ahead log, so rows that were
// deleted are no longer in the bytes on disk (the factory reset, D-154). It is VACUUM on the writer connection, outside
// a transaction, so it waits for the writer like any write. A reader that is still open holds the truncate back: the log
// is then shortened at its next checkpoint, and that is not an error.
func (db *DB) Compact(ctx context.Context) error {
	if _, err := db.w.ExecContext(ctx, "VACUUM"); err != nil {
		return fmt.Errorf("store: compact: %w", err)
	}
	if _, err := db.w.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("store: compact: %w", err)
	}
	return nil
}

// Size is the space the database takes on disk: the main file and the write-ahead log. A VACUUM INTO copy is
// never bigger than this.
func (db *DB) Size() (int64, error) {
	var total int64
	for _, name := range []string{db.path, db.path + "-wal"} {
		info, err := os.Stat(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("store: size: %w", err)
		}
		total += info.Size()
	}
	return total, nil
}

var migrationTableRE = regexp.MustCompile(`^core_migration_[a-z][a-z0-9_]{0,40}$`)

// SchemaVersions reports the highest applied migration of every module as "module=version,..." sorted by
// module, in the grammar of the backup manifest (docs/specs/host-api.md 6.11): the module is the part of the
// goose table name after core_migration_ (a module id has hyphens, the table has underscores).
func (db *DB) SchemaVersions(ctx context.Context) (string, error) {
	rows, err := db.r.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type = 'table' AND name GLOB 'core_migration_*' ORDER BY name")
	if err != nil {
		return "", fmt.Errorf("store: list migration tables: %w", err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			_ = rows.Close()
			return "", fmt.Errorf("store: list migration tables: %w", err)
		}
		tables = append(tables, n)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return "", fmt.Errorf("store: list migration tables: %w", err)
	}
	var pairs []string
	for _, t := range tables {
		if !migrationTableRE.MatchString(t) {
			continue // not a goose table of ours
		}
		var v sql.NullInt64
		// t matched migrationTableRE: lower-case letters, digits and underscores, safe to quote as an identifier.
		if err := db.r.QueryRowContext(ctx, `SELECT max(version_id) FROM "`+t+`" WHERE is_applied`).Scan(&v); err != nil {
			return "", fmt.Errorf("store: read %s: %w", t, err)
		}
		if v.Valid && v.Int64 > 0 {
			pairs = append(pairs, fmt.Sprintf("%s=%d", strings.TrimPrefix(t, "core_migration_"), v.Int64))
		}
	}
	return strings.Join(pairs, ","), nil
}

var moduleRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// ErrMigration is wrapped by migration failures caused by bad input (module id, Down sections).
var ErrMigration = errors.New("store: invalid migration")

// Migrate applies the pending migrations of one module. The version table is
// core_migration_<module>. Migrations are forward-only: a file with a Down section is refused.
// Running it again changes nothing.
func Migrate(ctx context.Context, db *DB, module string, fsys fs.FS) error {
	if !moduleRE.MatchString(module) {
		return fmt.Errorf("%w: module id %q must match %s", ErrMigration, module, moduleRE)
	}
	if err := rejectDown(fsys); err != nil {
		return err
	}
	table := "core_migration_" + strings.ReplaceAll(module, "-", "_")
	p, err := goose.NewProvider(goose.DialectSQLite3, db.w, fsys, goose.WithTableName(table))
	if err != nil {
		return fmt.Errorf("store: migrate %s: %w", module, err)
	}
	results, err := p.Up(ctx)
	for _, r := range results {
		db.log.InfoContext(ctx, "migration applied", "module", module, "version", r.Source.Version,
			"file", r.Source.Path, "duration", r.Duration.Round(time.Millisecond))
	}
	if err != nil {
		return fmt.Errorf("store: migrate %s: %w", module, err)
	}
	return nil
}

func rejectDown(fsys fs.FS) error {
	return fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("store: scan migrations: %w", err)
		}
		if d.IsDir() || !strings.HasSuffix(name, ".sql") {
			return nil
		}
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("store: scan migrations: %w", err)
		}
		if downRE.Match(b) {
			return fmt.Errorf("%w: %s has a Down section (forward-only, DATA_MODEL section 6)", ErrMigration, name)
		}
		return nil
	})
}

var downRE = regexp.MustCompile(`(?mi)^\s*--\s*\+goose\s+down\b`)

var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

var idPrefixRE = regexp.MustCompile(`^[a-z][a-z0-9]{0,31}$`)

// NewID returns "<prefix>-<26 lowercase base32 chars>" from 16 random bytes; it matches ^[\w.-]{1,96}$.
// prefix must match ^[a-z][a-z0-9]{0,31}$; anything else is a programming error and panics.
func NewID(prefix string) string {
	if !idPrefixRE.MatchString(prefix) {
		panic("store: NewID: invalid prefix " + prefix)
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error (Go 1.24+)
	return prefix + "-" + strings.ToLower(idEncoding.EncodeToString(b))
}

// FormatTS formats t as UTC ISO-8601 with milliseconds and a Z suffix (DATA_MODEL section 1).
func FormatTS(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// Extended SQLite result codes for a violated UNIQUE constraint and PRIMARY KEY.
const (
	sqliteConstraintPrimaryKey = 1555
	sqliteConstraintUnique     = 2067
)

// IsUniqueViolation reports whether err is the driver's error for a UNIQUE or PRIMARY KEY constraint
// (two writers inserting the same key), so callers can answer 409 instead of 500.
func IsUniqueViolation(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	return se.Code() == sqliteConstraintUnique || se.Code() == sqliteConstraintPrimaryKey
}
