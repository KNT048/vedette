package ops

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const maxStateFile = 8 << 20

// randomHex returns n random bytes as 2n lowercase hex characters.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("ops: random id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// privDir makes sure path is a real directory (not a symlink) owned by owner and closed to group
// and others, creating it 0700 when absent. It looks at the directory through a descriptor opened
// with O_NOFOLLOW (and chmods through it), not at the path.
func privDir(path string, owner int) error {
	f, err := openDirNoFollow(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("ops: create %s: %w", path, err)
		}
		if f, err = openDirNoFollow(path); err == nil {
			if err = f.Chmod(0o700); err != nil {
				_ = f.Close()
				return fmt.Errorf("ops: chmod %s: %w", path, err)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("ops: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("ops: stat %s: %w", path, err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	switch {
	case !st.IsDir():
		return fmt.Errorf("ops: %s is not a directory", path)
	case !ok || int(sys.Uid) != owner:
		return fmt.Errorf("ops: %s must be owned by uid %d", path, owner)
	case st.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("ops: %s has mode %o, group and others must have no access", path, st.Mode().Perm())
	}
	return nil
}

// openDirNoFollow opens a directory refusing a symlink as the last component.
func openDirNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0) //nolint:gosec // a directory under the host's own state directory
}

// writeFileAtomic writes data to path through a temp file in the same directory (fsync, rename).
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("ops: write %s: %w", filepath.Base(path), err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(perm); err != nil {
		return fmt.Errorf("ops: write %s: %w", filepath.Base(path), err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("ops: write %s: %w", filepath.Base(path), err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("ops: write %s: %w", filepath.Base(path), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("ops: write %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("ops: write %s: %w", filepath.Base(path), err)
	}
	ok = true
	syncDir(filepath.Dir(path))
	return nil
}

// syncDir makes a rename durable; failing to is not fatal.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil { //nolint:gosec // a directory the host created
		_ = d.Sync()
		_ = d.Close()
	}
}

// writeJSONAtomic stores v as JSON, mode 0600, through a temp file and a rename.
func writeJSONAtomic(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("ops: encode %s: %w", filepath.Base(path), err)
	}
	if len(b) > maxStateFile {
		return fmt.Errorf("ops: %s is too large", filepath.Base(path))
	}
	return writeFileAtomic(path, b, 0o600)
}

// readJSONFile decodes one JSON value from a file the host wrote. A missing file is os.ErrNotExist.
func readJSONFile(path string, v any) error {
	f, err := os.Open(path) //nolint:gosec // path built from a fixed name or a validated hex id inside the state dir
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxStateFile+1))
	if err != nil {
		return err
	}
	if len(data) > maxStateFile {
		return errors.New("file too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// freeBytes is the space a non-root writer could still use on the filesystem holding path.
func freeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("ops: statfs %s: %w", path, err)
	}
	return nonNegative(st.Bavail) * nonNegative(st.Bsize), nil
}

// nonNegative widens a Statfs field (its type differs per OS) to uint64, treating a negative as 0.
func nonNegative[T ~int32 | ~int64 | ~uint32 | ~uint64](v T) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// openRegularNoFollow opens path for reading, refusing a symlink and anything but a regular file.
// It returns the file and its size. Used for the host's own files (archives, exports); core's tree
// is only ever opened through a coreTree.
func openRegularNoFollow(path string) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // path = fixed core data dir + fixed file name
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("ops: %s is not a regular file", filepath.Base(path))
	}
	return f, st, nil
}

// privateTempDir makes a temp directory under parent (the host's own state) and returns it with
// the function that removes it. It exists so that functions that hold a handle on core's tree
// never call a path-based function themselves (INV-14).
func privateTempDir(parent, prefix string) (string, func(), error) {
	d, err := os.MkdirTemp(parent, prefix)
	if err != nil {
		return "", func() {}, err
	}
	return d, func() { _ = os.RemoveAll(d) }, nil
}

// createNew creates path for writing, failing when it exists; the caller owns a fresh private temp
// directory, so there is nobody to race with.
func createNew(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // inside a fresh private temp dir
}
