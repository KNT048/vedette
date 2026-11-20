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
	"slices"
	"strconv"
	"strings"
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

// EpochTable is the one-row table that records the epoch and the migration files a database was made with. Like the
// core_migration_* tables it is bookkeeping of the schema, not data: a purge or an export leaves it out.
const EpochTable = "core_schema_epoch"

// ErrPreRelease is the refusal of a database this build cannot run on: one made before the epoch started, or one made by a
// build whose migration files differ (the baseline files are edited in place until the first public release, so two
// pre-release builds never share a database). No in-place path exists: the box is installed fresh.
var ErrPreRelease = errors.New("this database was made by a pre-release build of Vedette and this build cannot use it; " +
	"install fresh: run install.sh --uninstall --yes without --keep-data, then install again")

// MigrationSet is the migration files of one module, applied under its module id.
type MigrationSet struct {
	Module string
	FS     fs.FS
}

// SchemaRev is the SHA-256 (hex) of the migration files of sets, in order: every module id, file name and content.
func SchemaRev(sets []MigrationSet) (string, error) {
	h := sha256.New()
	for _, s := range sets {
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
			return "", fmt.Errorf("store: schema files of %s: %w", s.Module, err)
		}
		slices.Sort(names)
		for _, n := range names {
			b, err := fs.ReadFile(s.FS, n)
			if err != nil {
				return "", fmt.Errorf("store: schema files of %s: %w", s.Module, err)
			}
			_, _ = fmt.Fprintf(h, "%s\x00%s\x00%d\x00", s.Module, n, len(b))
			_, _ = h.Write(b)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Epoch is the row of core_schema_epoch.
type Epoch struct {
	Epoch int64
	Rev   string
}

// EpochOf reads the epoch row of a database; ok is false when it has none (no table, or no row).
func EpochOf(ctx context.Context, q interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}) (e Epoch, ok bool, err error) {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, EpochTable).Scan(&n); err != nil {
		return e, false, fmt.Errorf("store: read the schema epoch: %w", err)
	}
	if n == 0 {
		return e, false, nil
	}
	err = q.QueryRowContext(ctx, `SELECT epoch, rev FROM `+EpochTable+` WHERE id = 1`).Scan(&e.Epoch, &e.Rev)
	if errors.Is(err, sql.ErrNoRows) {
		return e, false, nil
	}
	if err != nil {
		return e, false, fmt.Errorf("store: read the schema epoch: %w", err)
	}
	return e, true, nil
}

// MigrateAll makes db the schema of sets: it checks the epoch (CheckEpoch), then applies every set's migrations in order.
func MigrateAll(ctx context.Context, db *DB, sets []MigrationSet) error {
	rev, err := SchemaRev(sets)
	if err != nil {
		return err
	}
	if err := CheckEpoch(ctx, db, rev); err != nil {
		return err
	}
	for _, s := range sets {
		if err := Migrate(ctx, db, s.Module, s.FS); err != nil {
			return err
		}
	}
	return nil
}

// CheckEpoch refuses a database this build cannot run on (ErrPreRelease) and stamps a new one. A database with an epoch row is
// accepted when the row is this build's epoch and rev. A database without one is accepted only when it holds no table at all:
// it then gets the row, in the same transaction, before any migration runs, so a first start that stops halfway is resumed by
// the next one. Any other database (tables but no row) was made before the epoch existed.
func CheckEpoch(ctx context.Context, db *DB, rev string) error {
	return db.Write(ctx, func(tx *sql.Tx) error {
		e, ok, err := EpochOf(ctx, tx)
		if err != nil {
			return err
		}
		if ok {
			if e.Epoch != SchemaEpoch || e.Rev != rev {
				return ErrPreRelease
			}
			return nil
		}
		var tables int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT GLOB 'sqlite_*'`).Scan(&tables); err != nil {
			return fmt.Errorf("store: read the schema epoch: %w", err)
		}
		if tables > 0 {
			return ErrPreRelease
		}
		if _, err := tx.ExecContext(ctx, `CREATE TABLE `+EpochTable+` (
    id    INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    epoch INTEGER NOT NULL CHECK (epoch >= 1),
    rev   TEXT    NOT NULL CHECK (length(rev) = 64)
)`); err != nil {
			return fmt.Errorf("store: write the schema epoch: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO `+EpochTable+` (id, epoch, rev) VALUES (1, ?, ?)`, SchemaEpoch, rev); err != nil {
			return fmt.Errorf("store: write the schema epoch: %w", err)
		}
		return nil
	})
}
