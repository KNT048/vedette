package core

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/host/ops"
)

func snapshotTestDB(t *testing.T) *store.DB {
	t.Helper()
	db := storetest.New(t)
	if err := store.Migrate(t.Context(), db, "core", Migrations); err != nil {
		t.Fatal(err)
	}
	return db
}

func putRow(ctx context.Context, db *store.DB, n int) error {
	return db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO core_setting (key, value, updated_at, updated_by) VALUES (?, '{}', '2026-11-09T08:00:00.000Z', 'test')`, fmt.Sprintf("k%06d", n))
		return err
	})
}

func newTestSnapshotter(t *testing.T, db *store.DB, now func() time.Time) (*snapshotter, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")
	keyPath := filepath.Join(dir, "vedette.key")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	return newSnapshotter(db, dir, keyPath, now), dir, key
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	slices.Sort(out)
	return out
}

// The snapshot has exactly the files and rules of host-api 6.11, and the host's own parser accepts its
// snapshot.json. It is taken while a writer commits rows all the time (WAL): the copy is one consistent file.
func TestSnapshotFollowsTheHostContractUnderAConcurrentWriter(t *testing.T) {
	t.Parallel()
	db := snapshotTestDB(t)
	now := time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
	s, dir, key := newTestSnapshotter(t, db, func() time.Time { return now })
	ctx := t.Context()
	for i := range 50 {
		if err := putRow(ctx, db, i); err != nil {
			t.Fatal(err)
		}
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1000; ; i++ {
			select {
			case <-stop:
				return
			default:
				if err := putRow(ctx, db, i); err != nil {
					t.Error(err)
					return
				}
			}
		}
	}()
	defer func() { close(stop); wg.Wait() }()

	for round := range 5 {
		withKey := round%2 == 0
		snap, err := s.create(ctx, withKey)
		if err != nil {
			t.Fatal(err)
		}
		if !snapshotIDRE.MatchString(snap.ID) {
			t.Fatalf("id %q is not 32 lower-case hex", snap.ID)
		}
		d := filepath.Join(dir, snapshotsDir, snap.ID)
		want := []string{snapshotMetaFile, snapshotDBFile} // sorted by name
		if withKey {
			want = []string{snapshotMetaFile, snapshotDBFile, snapshotKeyFile}
		}
		if got := names(t, d); !slices.Equal(got, want) {
			t.Fatalf("files = %v, want %v (no -wal, no -shm, no stray file)", got, want)
		}
		for _, n := range want {
			st, err := os.Lstat(filepath.Join(d, n))
			if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
				t.Errorf("%s: %v %v, want a regular file, mode 0600", n, st, err)
			}
		}
		if st, _ := os.Stat(d); st.Mode().Perm() != 0o700 {
			t.Errorf("directory mode %o", st.Mode().Perm())
		}
		raw, _ := os.ReadFile(filepath.Join(d, snapshotMetaFile)) //nolint:gosec // the test reads what it just wrote
		created, schema, inc, err := ops.ParseSnapshotMeta(raw)   // the host's own parser
		if err != nil {
			t.Fatalf("the host refuses snapshot.json %s: %v", raw, err)
		}
		if !created.Equal(now) || schema != "core=4" || inc != withKey {
			t.Errorf("meta = %v %q %v (%s)", created, schema, inc, raw)
		}
		k, kerr := os.ReadFile(filepath.Join(d, snapshotKeyFile)) //nolint:gosec // the test reads what it just wrote
		if withKey && (kerr != nil || !bytes.Equal(k, key)) {
			t.Errorf("key copy = %q %v", k, kerr)
		}
		if !withKey && kerr == nil {
			t.Error("a snapshot without the key holds the key")
		}
		// The copy is a whole database of its own.
		cp, err := sql.Open("sqlite", "file:"+filepath.Join(d, snapshotDBFile)+"?mode=ro&immutable=1")
		if err != nil {
			t.Fatal(err)
		}
		var check string
		var rows int
		if err := cp.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&check); err != nil || check != "ok" {
			t.Errorf("integrity_check = %q %v", check, err)
		}
		if err := cp.QueryRowContext(ctx, "SELECT count(*) FROM core_setting").Scan(&rows); err != nil || rows < 50 {
			t.Errorf("rows in the copy = %d %v", rows, err)
		}
		_ = cp.Close()
		snap.remove()
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Errorf("remove left %s", d)
		}
	}
}

// A failure halfway leaves nothing behind, and snapshot.json is the last file: a directory without it is "not
// ready" to the host.
func TestSnapshotFailureLeavesNothingBehind(t *testing.T) {
	t.Parallel()
	db := snapshotTestDB(t)
	s, dir, _ := newTestSnapshotter(t, db, time.Now)
	s.keyPath = filepath.Join(dir, "missing.key")
	if _, err := s.create(t.Context(), true); err == nil {
		t.Fatal("a missing key file did not fail the snapshot")
	}
	if got := names(t, filepath.Join(dir, snapshotsDir)); len(got) != 0 {
		t.Errorf("left behind: %v", got)
	}
	s.keyPath = filepath.Join(dir, "huge.key")
	if err := os.WriteFile(s.keyPath, bytes.Repeat([]byte{1}, maxSnapshotKey+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.create(t.Context(), true); err == nil {
		t.Fatal("a key file the host would refuse was copied")
	}
	if got := names(t, filepath.Join(dir, snapshotsDir)); len(got) != 0 {
		t.Errorf("left behind: %v", got)
	}
	// Without the key the key file is not even read.
	snap, err := s.create(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	snap.remove()
}

func TestSnapshotSweepRemovesOnlyOldOnesOfOurs(t *testing.T) {
	t.Parallel()
	db := snapshotTestDB(t)
	s, dir, _ := newTestSnapshotter(t, db, time.Now)
	root := filepath.Join(dir, snapshotsDir)
	old, fresh := strings.Repeat("a", 32), strings.Repeat("b", 32)
	for _, n := range []string{old, fresh, "foreign"} {
		if err := os.MkdirAll(filepath.Join(root, n), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	oldMeta := filepath.Join(root, old+".meta")
	if err := os.WriteFile(oldMeta, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * time.Hour)
	for _, p := range []string{filepath.Join(root, old), oldMeta, filepath.Join(root, "foreign")} {
		if err := os.Chtimes(p, past, past); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.sweep()
	if err != nil || n != 2 {
		t.Fatalf("sweep = %d %v, want 2", n, err)
	}
	if got := names(t, root); !slices.Equal(got, []string{fresh, "foreign"}) {
		t.Errorf("left: %v", got)
	}
	// Nothing to sweep before the first snapshot ever.
	s2, _, _ := newTestSnapshotter(t, db, time.Now)
	if n, err := s2.sweep(); n != 0 || err != nil {
		t.Errorf("sweep without a directory = %d %v", n, err)
	}
}
