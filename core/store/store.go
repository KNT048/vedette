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
	"strings"
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
}

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

// Write runs fn in a BEGIN IMMEDIATE transaction on the single writer connection.
// It commits only when fn returns nil. On an error, a panic (re-raised) or runtime.Goexit
// (t.FailNow in a test) the transaction is rolled back, so the writer connection is never leaked.
func (db *DB) Write(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := db.w.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
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

// Check runs PRAGMA integrity_check and foreign_key_check (DATA_MODEL section 6 rule 7).
func (db *DB) Check(ctx context.Context) error {
	rows, err := db.r.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return fmt.Errorf("store: integrity_check: %w", err)
	}
	var problems []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: integrity_check: %w", err)
		}
		if line != "ok" {
			problems = append(problems, line)
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("store: integrity_check: %w", err)
	}
	if len(problems) > 0 {
		return fmt.Errorf("store: integrity_check failed: %s", strings.Join(problems, "; "))
	}

	rows, err = db.r.QueryContext(ctx, "PRAGMA foreign_key_check")
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
