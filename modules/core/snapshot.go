package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// Snapshot producer of the host contract (docs/specs/host-api.md 6.11, D-87). Before every host command that
// needs a backup, core writes a consistent copy of its own state to <core_data>/snapshots/<id>/ and names the
// id in the call. The host never opens the database: it copies these bytes. core_data is the directory of
// core's database (the -db flag, whose file the installer names vedette.db, next to vedette.key).
const (
	snapshotsDir     = "snapshots"
	snapshotDBFile   = "vedette.db"
	snapshotKeyFile  = "vedette.key"
	snapshotMetaFile = "snapshot.json"
	maxSnapshotKey   = 4096 // the host refuses a bigger key file
	// snapshotMaxAge is how old a leftover directory must be for the start-up sweep to remove it.
	snapshotMaxAge = time.Hour
)

var snapshotIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// snapshotter writes and removes the snapshots of one core.
type snapshotter struct {
	db      *store.DB
	dir     string // <core_data>/snapshots
	keyPath string
	now     func() time.Time
}

// snapshot is one directory written by snapshotter.create.
type snapshot struct {
	ID  string
	dir string
}

// remove deletes the snapshot directory; a failure is the sweep's job at the next start.
func (s snapshot) remove() {
	if s.dir != "" {
		_ = os.RemoveAll(s.dir)
	}
}

func newSnapshotter(db *store.DB, dataDir, keyPath string, now func() time.Time) *snapshotter {
	return &snapshotter{db: db, dir: filepath.Join(dataDir, snapshotsDir), keyPath: keyPath, now: now}
}

// create writes snapshots/<id>/ with vedette.db (VACUUM INTO: one file, no -wal or -shm, taken while the
// writer keeps going), vedette.key when withKey, and snapshot.json LAST: the host reads it first, and a
// directory without it is "no snapshot yet". Files are 0600 and owned by core's uid (core writes them).
// A failure leaves nothing behind.
func (s *snapshotter) create(ctx context.Context, withKey bool) (snap snapshot, err error) {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return snapshot{}, fmt.Errorf("core: snapshot directory: %w", err)
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return snapshot{}, fmt.Errorf("core: snapshot id: %w", err)
	}
	id := hex.EncodeToString(raw[:])
	dir := filepath.Join(s.dir, id)
	meta := filepath.Join(s.dir, id+".meta") // written beside the directory, renamed in as the last step: the host never sees half a file
	if err := os.Mkdir(dir, 0o700); err != nil {
		return snapshot{}, fmt.Errorf("core: snapshot directory: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dir)
			_ = os.Remove(meta)
		}
	}()
	if err := s.db.SnapshotTo(ctx, filepath.Join(dir, snapshotDBFile)); err != nil {
		return snapshot{}, err
	}
	if withKey {
		if err := s.copyKey(filepath.Join(dir, snapshotKeyFile)); err != nil {
			return snapshot{}, err
		}
	}
	schema, err := s.db.SchemaVersions(ctx)
	if err != nil {
		return snapshot{}, err
	}
	b, err := json.Marshal(struct {
		CreatedAt   string `json:"created_at"`
		DBSchema    string `json:"db_schema"`
		IncludesKey bool   `json:"includes_key"`
	}{s.now().UTC().Truncate(time.Second).Format(time.RFC3339), schema, withKey})
	if err != nil {
		return snapshot{}, fmt.Errorf("core: snapshot metadata: %w", err)
	}
	if err := os.WriteFile(meta, b, 0o600); err != nil {
		return snapshot{}, fmt.Errorf("core: snapshot metadata: %w", err)
	}
	if err := os.Rename(meta, filepath.Join(dir, snapshotMetaFile)); err != nil {
		return snapshot{}, fmt.Errorf("core: snapshot metadata: %w", err)
	}
	return snapshot{ID: id, dir: dir}, nil
}

// copyKey copies the master key file (at most 4096 bytes) with mode 0600. The key never goes into a snapshot
// that backs a download: the caller passes withKey false for that.
func (s *snapshotter) copyKey(dst string) error {
	src, err := os.Open(s.keyPath)
	if err != nil {
		return fmt.Errorf("core: snapshot key: %w", err)
	}
	defer func() { _ = src.Close() }()
	b, err := io.ReadAll(io.LimitReader(src, maxSnapshotKey+1))
	if err != nil || len(b) == 0 || len(b) > maxSnapshotKey {
		return errors.New("core: snapshot key: the key file is empty, unreadable or larger than 4096 bytes")
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // dst is inside the snapshot directory made just above
	if err != nil {
		return fmt.Errorf("core: snapshot key: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("core: snapshot key: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("core: snapshot key: %w", err)
	}
	return nil
}

// ours reports whether a name in snapshots/ was made by create: an id, or an id with the .meta of a half-done one.
func ours(name string) bool {
	id, _ := strings.CutSuffix(name, ".meta")
	return snapshotIDRE.MatchString(id)
}

// sweep removes what an earlier run left behind: snapshot directories (and half-written metadata files) older
// than snapshotMaxAge. It runs once at start-up, when no call of this process can be using one.
func (s *snapshotter) sweep() (removed int, err error) {
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("core: sweep snapshots: %w", err)
	}
	var errs []error
	for _, e := range entries {
		name := e.Name()
		if !ours(name) {
			continue // not ours: leave it
		}
		info, err := e.Info()
		if err != nil || s.now().Sub(info.ModTime()) < snapshotMaxAge {
			continue
		}
		if err := os.RemoveAll(filepath.Join(s.dir, name)); err != nil {
			errs = append(errs, err)
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}
