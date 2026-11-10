package pki

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/knt048/vedette/core/sensorlink"
)

// BundleName is the file a role reads in its own directory.
const BundleName = "sensor.pem"

// ErrCredsPath means something at the name or on the way to it is not what the writer will touch: a symlink, a FIFO or a
// directory where the file or the role directory should be.
var ErrCredsPath = errors.New("pki: credentials path is not a plain directory and file")

// WriteBundle puts data at <dir>/<role>/sensor.pem the way the D-89 files are written, so that a reader sees the old bundle or
// the whole new one and never half of one: os.OpenRoot (no component can leave dir), a new file with a random name opened
// O_EXCL|O_NOFOLLOW at mode 0640, fsync, Rename, fsync of the directory. Core never reads the file back.
//
// It refuses a dir or a role directory that is a symlink, and a name that is a symlink, a FIFO or a directory: the volume is
// shared with a container that is being attacked, and a rename over a planted link would be a write through it. Ownership
// is core's uid (the volume's owner) and the group of the role folder (the sensor group: the file is chowned to it before the rename,
// SP-6 L3, because core's new files would otherwise carry core's own group); the mode is 0640.
func WriteBundle(dir string, role sensorlink.Role, data []byte) error {
	root, sub, err := openRole(dir, role, true)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	defer func() { _ = sub.Close() }()
	name := string(role)
	switch fi, err := sub.Lstat(BundleName); {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return fmt.Errorf("pki: look at %s: %w", BundleName, err)
	case !fi.Mode().IsRegular():
		return fmt.Errorf("%w: %s/%s is not a regular file", ErrCredsPath, name, BundleName)
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("pki: random: %w", err)
	}
	tmp := tempPrefix + hex.EncodeToString(rnd[:])
	f, err := sub.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o640)
	if err != nil {
		return fmt.Errorf("pki: write %s: %w", BundleName, err)
	}
	defer func() { _ = sub.Remove(tmp) }() // a no-op once renamed
	if err := f.Chmod(0o640); err != nil { // the umask may have taken bits off
		_ = f.Close()
		return fmt.Errorf("pki: write %s: %w", BundleName, err)
	}
	// The file gets the group of the role folder (the sensor group, SP-6 L3): a file core creates has core's own group unless the
	// folder is setgid, and the unit that makes the volume cannot set that bit. core is in the folder's group (the unit adds it), so
	// the chown is allowed; the mode stays 0640.
	st, err := sub.Stat(".")
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("pki: look at the folder of %s: %w", BundleName, err)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		if err := f.Chown(-1, int(sys.Gid)); err != nil {
			_ = f.Close()
			return fmt.Errorf("pki: give %s the group of its folder: %w", BundleName, err)
		}
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("pki: write %s: %w", BundleName, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("pki: write %s: %w", BundleName, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("pki: write %s: %w", BundleName, err)
	}
	if err := sub.Rename(tmp, BundleName); err != nil {
		return fmt.Errorf("pki: write %s: %w", BundleName, err)
	}
	if d, err := sub.Open("."); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// tempPrefix starts the name of the temporary file of a write; cleanTemps removes what a crash left.
const tempPrefix = "." + BundleName + "."

// testHookAfterDirCheck, set by an internal test, runs between a directory having been checked and it being opened: the moment
// a racing process could swap the directory for a link.
var testHookAfterDirCheck func()

// openRole returns the root of the creds directory and the root of the role's directory below it. Both directories are checked
// to be plain (not symlinks) and, after they are opened, to be the very directory that was checked (os.SameFile on the opened
// handle against the Lstat that came first): a swap in between is refused rather than followed. create makes a missing role
// directory.
func openRole(dir string, role sensorlink.Role, create bool) (*os.Root, *os.Root, error) {
	if !role.Valid() {
		return nil, nil, fmt.Errorf("pki: unknown role %q", role)
	}
	dirInfo, err := plainDir(dir)
	if err != nil {
		return nil, nil, err
	}
	if testHookAfterDirCheck != nil {
		testHookAfterDirCheck()
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: open creds dir: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = root.Close()
		}
	}()
	if st, err := root.Stat("."); err != nil || !os.SameFile(st, dirInfo) {
		return nil, nil, fmt.Errorf("%w: the creds directory changed while it was being opened", ErrCredsPath)
	}
	name := string(role)
	fi, err := root.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist) && create:
		if err := root.Mkdir(name, 0o750); err != nil {
			return nil, nil, fmt.Errorf("pki: make %s directory: %w", name, err)
		}
		if fi, err = root.Lstat(name); err != nil {
			return nil, nil, fmt.Errorf("pki: look at %s directory: %w", name, err)
		}
	case err != nil:
		return nil, nil, err
	case !fi.IsDir(): // Lstat: a symlink is not a directory here
		return nil, nil, fmt.Errorf("%w: %s is not a directory", ErrCredsPath, name)
	}
	if testHookAfterDirCheck != nil {
		testHookAfterDirCheck()
	}
	sub, err := root.OpenRoot(name)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: open %s directory: %w", name, err)
	}
	if st, err := sub.Stat("."); err != nil || !os.SameFile(st, fi) {
		_ = sub.Close()
		return nil, nil, fmt.Errorf("%w: the %s directory changed while it was being opened", ErrCredsPath, name)
	}
	ok = true
	return root, sub, nil
}

// cleanTemps removes the temporary files a crash left in the role's directory (".sensor.pem.<hex>", regular files only). A
// directory that does not exist yet is not an error.
func cleanTemps(dir string, role sensorlink.Role) error {
	root, sub, err := openRole(dir, role, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	defer func() { _ = sub.Close() }()
	d, err := sub.Open(".")
	if err != nil {
		return err
	}
	names, err := d.Readdirnames(-1)
	_ = d.Close()
	if err != nil {
		return err
	}
	for _, n := range names {
		if !strings.HasPrefix(n, tempPrefix) {
			continue
		}
		if fi, err := sub.Lstat(n); err == nil && fi.Mode().IsRegular() {
			_ = sub.Remove(n)
		}
	}
	return nil
}

// plainDir makes dir if it is missing and refuses it when it is a symlink or not a directory. (os.OpenRoot follows a link at
// dir itself, so the check is made first; the tree below it cannot escape the root.)
func plainDir(dir string) (os.FileInfo, error) {
	dir = filepath.Clean(dir)
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("pki: make creds dir: %w", err)
		}
		fi, err = os.Lstat(dir)
	}
	if err != nil {
		return nil, fmt.Errorf("pki: look at creds dir: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%w: %s", ErrCredsPath, dir)
	}
	return fi, nil
}
