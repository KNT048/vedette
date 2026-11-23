package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/pressly/goose/v3"
)

// The schema epoch is the generation of the migration history. Epoch 2 started again from one baseline file per module
// (0001_<module>.sql); a database made by an earlier history cannot be migrated to it. The epoch is a file of its own so that
// the release tooling reads it at any git revision (scripts/release, migrations.go).
//
//go:embed SCHEMA_EPOCH
var epochFile string

// SchemaEpoch is the epoch this build writes and accepts.
var SchemaEpoch = mustEpoch(epochFile)

func mustEpoch(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 1 {
		panic("store: SCHEMA_EPOCH must hold a positive integer")
	}
	return n
}

// EpochTable is the one-row table that records the epoch a database was made with. FilesTable records the SHA-256 of every
// migration file the database has applied. Like the core_migration_* tables both are bookkeeping of the schema, not data: a
// purge or an export leaves them out (IsBookkeeping).
const (
	EpochTable = "core_schema_epoch"
	FilesTable = "core_schema_file"
)

// IsBookkeeping reports whether table belongs to the migration bookkeeping (goose's version tables, the epoch, the applied
// files) rather than to a module's data.
func IsBookkeeping(table string) bool {
	return table == EpochTable || table == FilesTable || strings.HasPrefix(table, "core_migration_")
}

// ErrPreRelease is the refusal of a database this build cannot run on because it was made by a build of another migration
// history: one made before the epoch started, one of another epoch, or one stamped by a pre-release build whose baseline files
// differ from this build's. No in-place path exists: the box is installed fresh.
var ErrPreRelease = errors.New("this database was made by a pre-release build of Vedette and this build cannot use it; " +
	"install fresh: run install.sh --uninstall --yes without --keep-data, then install again")

// ErrMigrationChanged is the refusal of a database that applied a migration file whose contents differ from this build's copy.
// goose never runs an applied file again, so the database does not have the schema this build expects. Releases never edit an
// applied migration (the release guard refuses it), so this is a build that should not exist; the database is left untouched.
var ErrMigrationChanged = errors.New("this database applied a migration that differs from this build's copy, so this build " +
	"cannot run on it; go back to the version that made the database (roll back the update), or on a pre-release build " +
	"install fresh (install.sh --uninstall --yes without --keep-data, then install again)")

// MigrationSet is the migration files of one module, applied under its module id.
type MigrationSet struct {
	Module string
	FS     fs.FS
}

// migFile is one migration file of a set.
type migFile struct {
	name    string // path inside the set's FS
	version int64  // goose's version: the number the file name starts with
	data    []byte
}

// files reads the .sql files of s, sorted by path.
func (s MigrationSet) files() ([]migFile, error) {
	var names []string
	err := fs.WalkDir(s.FS, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(name, ".sql") {
			names = append(names, name)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: schema files of %s: %w", s.Module, err)
	}
	slices.Sort(names)
	out := make([]migFile, 0, len(names))
	for _, n := range names {
		b, err := fs.ReadFile(s.FS, n)
		if err != nil {
			return nil, fmt.Errorf("store: schema files of %s: %w", s.Module, err)
		}
		v, err := goose.NumericComponent(path.Base(n))
		if err != nil {
			return nil, fmt.Errorf("store: schema files of %s: %s: %w", s.Module, n, err)
		}
		out = append(out, migFile{name: n, version: v, data: b})
	}
	return out, nil
}

func fileSum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// FileKey names one applied migration file: the module and goose's version.
type FileKey struct {
	Module  string
	Version int64
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func hasTable(ctx context.Context, q queryer, name string) (bool, error) {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n); err != nil {
		return false, fmt.Errorf("store: read the schema bookkeeping: %w", err)
	}
	return n > 0, nil
}

// EpochOf reads the epoch of a database; ok is false when it has none (no table, or no row).
func EpochOf(ctx context.Context, q queryer) (epoch int64, ok bool, err error) {
	if has, err := hasTable(ctx, q, EpochTable); err != nil || !has {
		return 0, false, err
	}
	err = q.QueryRowContext(ctx, `SELECT epoch FROM `+EpochTable+` WHERE id = 1`).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("store: read the schema epoch: %w", err)
	}
	return epoch, true, nil
}

// AppliedFilesOf reads the SHA-256 of every migration file the database recorded as applied; ok is false when it has no
// FilesTable (a database made before the table existed, which only pre-release builds made).
func AppliedFilesOf(ctx context.Context, q queryer) (files map[FileKey]string, ok bool, err error) {
	if has, err := hasTable(ctx, q, FilesTable); err != nil || !has {
		return nil, false, err
	}
	rows, err := q.QueryContext(ctx, `SELECT module, version, sha256 FROM `+FilesTable)
	if err != nil {
		return nil, false, fmt.Errorf("store: read the applied migration files: %w", err)
	}
	files = map[FileKey]string{}
	for rows.Next() {
		var k FileKey
		var sum string
		if err := rows.Scan(&k.Module, &k.Version, &sum); err != nil {
			_ = rows.Close()
			return nil, false, fmt.Errorf("store: read the applied migration files: %w", err)
		}
		files[k] = sum
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, false, fmt.Errorf("store: read the applied migration files: %w", err)
	}
	return files, true, nil
}

// appliedVersions is the versions goose recorded as applied for module (none when its table does not exist yet).
func appliedVersions(ctx context.Context, q queryer, module string) (map[int64]bool, error) {
	table := "core_migration_" + strings.ReplaceAll(module, "-", "_")
	if has, err := hasTable(ctx, q, table); err != nil || !has {
		return nil, err
	}
	// table is built from a module id that Migrate checked against moduleRE: safe to quote as an identifier.
	rows, err := q.QueryContext(ctx, `SELECT version_id FROM "`+table+`" WHERE is_applied AND version_id > 0`)
	if err != nil {
		return nil, fmt.Errorf("store: read %s: %w", table, err)
	}
	out := map[int64]bool{}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: read %s: %w", table, err)
		}
		out[v] = true
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("store: read %s: %w", table, err)
	}
	return out, nil
}

// MigrateAll makes db the schema of sets. It checks the database first (CheckSchema: the epoch, and that no applied migration
// changed), then applies every set's migrations in order and records the files each one applied. A build with more migrations
// than the one that made the database applies the new ones (add-only update); a build with fewer (a rollback that kept the
// database) runs on it as long as the files both have are the same.
func MigrateAll(ctx context.Context, db *DB, sets []MigrationSet) error {
	files := make([][]migFile, len(sets))
	for i, s := range sets {
		var err error
		if files[i], err = s.files(); err != nil {
			return err
		}
	}
	if err := checkSchema(ctx, db, sets, files); err != nil {
		return err
	}
	for i, s := range sets {
		if err := Migrate(ctx, db, s.Module, s.FS); err != nil {
			return err
		}
		if err := recordApplied(ctx, db, s.Module, files[i]); err != nil {
			return err
		}
	}
	return nil
}

// CheckSchema refuses a database this build cannot run on and stamps a new one, before any migration runs:
//   - a database with an epoch row is accepted when the row is this build's epoch (ErrPreRelease otherwise);
//   - a database without one is accepted only when it holds no table at all: it then gets the row and an empty FilesTable, in the
//     same transaction, so a first start that stops halfway is resumed by the next one. Any other database (tables but no row) was
//     made before the epoch existed (ErrPreRelease);
//   - every migration file of sets that the database recorded as applied must have the same contents (ErrMigrationChanged).
//
// A database stamped by a pre-release build before FilesTable existed carries instead the SHA-256 of all the migration files of
// that build (the rev column). It is accepted when the files of this build that it applied hash to that value, which holds
// exactly when that build's files are unchanged in this one, and then gets its FilesTable.
func CheckSchema(ctx context.Context, db *DB, sets []MigrationSet) error {
	files := make([][]migFile, len(sets))
	for i, s := range sets {
		var err error
		if files[i], err = s.files(); err != nil {
			return err
		}
	}
	return checkSchema(ctx, db, sets, files)
}

func checkSchema(ctx context.Context, db *DB, sets []MigrationSet, files [][]migFile) error {
	return db.Write(ctx, func(tx *sql.Tx) error {
		epoch, ok, err := EpochOf(ctx, tx)
		if err != nil {
			return err
		}
		if !ok {
			var tables int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT GLOB 'sqlite_*'`).Scan(&tables); err != nil {
				return fmt.Errorf("store: read the schema epoch: %w", err)
			}
			if tables > 0 {
				return ErrPreRelease
			}
			if _, err := tx.ExecContext(ctx, `CREATE TABLE `+EpochTable+` (
    id    INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    epoch INTEGER NOT NULL CHECK (epoch >= 1)
)`); err != nil {
				return fmt.Errorf("store: write the schema epoch: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO `+EpochTable+` (id, epoch) VALUES (1, ?)`, SchemaEpoch); err != nil {
				return fmt.Errorf("store: write the schema epoch: %w", err)
			}
			return createFilesTable(ctx, tx)
		}
		if epoch != SchemaEpoch {
			return ErrPreRelease
		}
		recorded, ok, err := AppliedFilesOf(ctx, tx)
		if err != nil {
			return err
		}
		if !ok {
			return adoptStamped(ctx, tx, sets, files)
		}
		for i, s := range sets {
			for _, f := range files[i] {
				if sum, there := recorded[FileKey{s.Module, f.version}]; there && sum != fileSum(f.data) {
					return fmt.Errorf("%w (%s %s)", ErrMigrationChanged, s.Module, f.name)
				}
			}
		}
		return nil
	})
}

func createFilesTable(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `CREATE TABLE `+FilesTable+` (
    module  TEXT    NOT NULL CHECK (length(module) BETWEEN 1 AND 32),
    version INTEGER NOT NULL CHECK (version >= 1),
    sha256  TEXT    NOT NULL CHECK (length(sha256) = 64),
    PRIMARY KEY (module, version)
) WITHOUT ROWID`); err != nil {
		return fmt.Errorf("store: write the applied migration files: %w", err)
	}
	return nil
}

// adoptStamped moves a database stamped with the rev of a pre-release build to FilesTable (see CheckSchema). rev was the SHA-256
// over every set in order: for each file, sorted by path, the module id, the path, the length and the contents.
func adoptStamped(ctx context.Context, tx *sql.Tx, sets []MigrationSet, files [][]migFile) error {
	var rev sql.NullString
	var cols int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('`+EpochTable+`') WHERE name = 'rev'`).Scan(&cols); err != nil {
		return fmt.Errorf("store: read the schema epoch: %w", err)
	}
	if cols == 1 {
		if err := tx.QueryRowContext(ctx, `SELECT rev FROM `+EpochTable+` WHERE id = 1`).Scan(&rev); err != nil {
			return fmt.Errorf("store: read the schema epoch: %w", err)
		}
	}
	if !rev.Valid {
		return ErrPreRelease
	}
	h := sha256.New()
	applied := make([]map[int64]bool, len(sets))
	for i, s := range sets {
		var err error
		if applied[i], err = appliedVersions(ctx, tx, s.Module); err != nil {
			return err
		}
		for _, f := range files[i] {
			if applied[i][f.version] {
				_, _ = fmt.Fprintf(h, "%s\x00%s\x00%d\x00", s.Module, f.name, len(f.data))
				_, _ = h.Write(f.data)
			}
		}
	}
	if hex.EncodeToString(h.Sum(nil)) != rev.String {
		return ErrPreRelease
	}
	if err := createFilesTable(ctx, tx); err != nil {
		return err
	}
	for i, s := range sets {
		if err := insertApplied(ctx, tx, s.Module, files[i], applied[i]); err != nil {
			return err
		}
	}
	return nil
}

// recordApplied adds to FilesTable the files of module that goose has applied and the table does not hold yet. A file already
// recorded was compared by CheckSchema before the migrations ran.
func recordApplied(ctx context.Context, db *DB, module string, files []migFile) error {
	return db.Write(ctx, func(tx *sql.Tx) error {
		applied, err := appliedVersions(ctx, tx, module)
		if err != nil {
			return err
		}
		return insertApplied(ctx, tx, module, files, applied)
	})
}

func insertApplied(ctx context.Context, tx *sql.Tx, module string, files []migFile, applied map[int64]bool) error {
	for _, f := range files {
		if !applied[f.version] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO `+FilesTable+` (module, version, sha256) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`,
			module, f.version, fileSum(f.data)); err != nil {
			return fmt.Errorf("store: write the applied migration files: %w", err)
		}
	}
	return nil
}
