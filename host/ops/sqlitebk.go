package ops

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"modernc.org/sqlite" // registers the "sqlite" database/sql driver and exposes the backup API
)

// sqliteDSN builds a file: URI the driver understands for an absolute path.
func sqliteDSN(path string, readOnly bool) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	if readOnly {
		q.Set("mode", "ro")
		q.Add("_pragma", "query_only(1)")
	}
	return (&url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}).String()
}

// backupSQLite writes a consistent copy of the live database src to dst with the SQLite online
// backup API, reached through database/sql's Conn.Raw on the modernc.org/sqlite driver (it is
// reachable, so VACUUM INTO is not needed). The source is opened read-only: core keeps running and
// writing (WAL readers do not block the writer); the copy is a snapshot taken in steps.
// dst must not exist.
func backupSQLite(ctx context.Context, src, dst string) error {
	db, err := sql.Open("sqlite", sqliteDSN(src, true))
	if err != nil {
		return fmt.Errorf("ops: open database: %w", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("ops: open database: %w", err)
	}
	defer func() { _ = conn.Close() }()
	return conn.Raw(func(dc any) error {
		bc, ok := dc.(interface {
			NewBackup(dstURI string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("ops: the sqlite driver has no backup API")
		}
		b, err := bc.NewBackup(dst)
		if err != nil {
			return fmt.Errorf("ops: start backup: %w", err)
		}
		// One step for the whole database: a read transaction on a WAL database sees one consistent
		// snapshot and does not block core's writer. Stepping page by page would restart the copy
		// every time core commits in between, and a busy core could starve the backup forever.
		// ponytail: the copy cannot be interrupted midway (the run's deadline applies after it);
		// a database large enough for that to matter needs the stepped copy with a restart cap.
		if _, err := b.Step(-1); err != nil {
			_ = b.Finish()
			return fmt.Errorf("ops: backup step: %w", err)
		}
		if err := ctx.Err(); err != nil {
			_ = b.Finish()
			return err
		}
		if err := b.Finish(); err != nil {
			return fmt.Errorf("ops: finish backup: %w", err)
		}
		return nil
	})
}

var migrationTableRE = regexp.MustCompile(`^core_migration_([a-z][a-z0-9_]{0,40})$`)

// inspectDB opens the database file at path (read-write when rw, to be able to switch a backup
// copy out of WAL mode) and returns its schema string. With check it also runs PRAGMA quick_check.
// The schema string is "module=version" pairs, sorted, from the goose version tables
// core_migration_<module> (the highest applied version of each).
func inspectDB(ctx context.Context, path string, readOnly, check, leaveJournalDelete bool) (schema string, err error) {
	db, err := sql.Open("sqlite", sqliteDSN(path, readOnly))
	if err != nil {
		return "", fmt.Errorf("ops: open database: %w", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	if leaveJournalDelete {
		// A copy that is archived must be one self-contained file: leave WAL mode first, which
		// also folds any WAL content into the main file.
		var mode string
		if err := db.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&mode); err != nil || !strings.EqualFold(mode, "delete") {
			return "", errors.New("ops: could not make the copy self-contained")
		}
	}
	if check {
		var res string
		if err := db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&res); err != nil || res != "ok" {
			return "", errors.New("ops: the database failed its integrity check")
		}
	}
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'core\_migration\_%' ESCAPE '\'`)
	if err != nil {
		return "", fmt.Errorf("ops: read schema: %w", err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			_ = rows.Close()
			return "", fmt.Errorf("ops: read schema: %w", err)
		}
		tables = append(tables, n)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return "", fmt.Errorf("ops: read schema: %w", err)
	}
	_ = rows.Close()
	var parts []string
	for _, t := range tables {
		m := migrationTableRE.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		var v sql.NullInt64
		// The table name passed the pattern above (lowercase letters, digits, underscore).
		q := `SELECT MAX(version_id) FROM "` + t + `" WHERE is_applied = 1`
		if err := db.QueryRowContext(ctx, q).Scan(&v); err != nil {
			return "", fmt.Errorf("ops: read schema: %w", err)
		}
		parts = append(parts, m[1]+"="+strconv.FormatInt(v.Int64, 10))
	}
	slices.Sort(parts)
	return strings.Join(parts, ","), nil
}

// countSecrets is how many rows core_secret holds (0 when the table does not exist). It is the one
// look the host takes at core's data: whether a database without its key file would be unusable.
func countSecrets(ctx context.Context, path string) (int64, error) {
	db, err := sql.Open("sqlite", sqliteDSN(path, true))
	if err != nil {
		return 0, fmt.Errorf("ops: open database: %w", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	var n int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM core_secret`).Scan(&n); err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return 0, nil
		}
		return 0, fmt.Errorf("ops: read secrets: %w", err)
	}
	return n, nil
}

// schemaNewer reports whether the backup's schema is ahead of the live one: some module has a
// higher version in the backup, or exists only there.
func schemaNewer(backup, live string) bool {
	l := parseSchema(live)
	for mod, v := range parseSchema(backup) {
		if v > l[mod] {
			return true
		}
	}
	return false
}

func parseSchema(s string) map[string]int {
	m := map[string]int{}
	for _, p := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		if n, err := strconv.Atoi(v); err == nil {
			m[k] = n
		}
	}
	return m
}

// matchSidecars gives -wal, -shm and -journal files next to db the owner and mode of db itself.
// Opening a WAL database as root can create them root-owned, and a rootless core could then no
// longer open its own database. Files that already belong to the right owner are left alone.
func matchSidecars(db string) {
	st, err := os.Lstat(db)
	if err != nil {
		return
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		p := db + suffix
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if fs, ok := fi.Sys().(*syscall.Stat_t); ok && (fs.Uid != sys.Uid || fs.Gid != sys.Gid) {
			_ = os.Lchown(p, int(sys.Uid), int(sys.Gid))
		}
		if fi.Mode().Perm() != st.Mode().Perm() {
			_ = os.Chmod(p, st.Mode().Perm())
		}
	}
}

// removeSidecars deletes the -wal, -shm and -journal files of a database that is about to be
// replaced: a stale WAL applied to a different database file would corrupt it.
func removeSidecars(db string) error {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err := os.Remove(db + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("ops: remove %s: %w", filepath.Base(db+suffix), err)
		}
	}
	return nil
}
