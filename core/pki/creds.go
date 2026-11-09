package pki

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
// (core's uid, the sensor group) comes from the volume (a setgid directory made by the host unit, SP-6), not from a chown here.
func WriteBundle(dir string, role sensorlink.Role, data []byte) error {
	if !role.Valid() {
		return fmt.Errorf("pki: unknown role %q", role)
	}
	if err := plainDir(dir); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("pki: open creds dir: %w", err)
	}
	defer func() { _ = root.Close() }()
	name := string(role)
	switch fi, err := root.Lstat(name); {
	case errors.Is(err, fs.ErrNotExist):
		if err := root.Mkdir(name, 0o750); err != nil {
			return fmt.Errorf("pki: make %s directory: %w", name, err)
		}
	case err != nil:
		return fmt.Errorf("pki: look at %s directory: %w", name, err)
	case !fi.IsDir(): // Lstat: a symlink is not a directory here
		return fmt.Errorf("%w: %s is not a directory", ErrCredsPath, name)
	}
	sub, err := root.OpenRoot(name)
	if err != nil {
		return fmt.Errorf("pki: open %s directory: %w", name, err)
	}
	defer func() { _ = sub.Close() }()
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
	tmp := "." + BundleName + "." + hex.EncodeToString(rnd[:])
	f, err := sub.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o640)
	if err != nil {
		return fmt.Errorf("pki: write %s: %w", BundleName, err)
	}
	defer func() { _ = sub.Remove(tmp) }() // a no-op once renamed
	if err := f.Chmod(0o640); err != nil { // the umask may have taken bits off
		_ = f.Close()
		return fmt.Errorf("pki: write %s: %w", BundleName, err)
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

// plainDir makes dir if it is missing and refuses it when it is a symlink or not a directory. (os.OpenRoot follows a link at
// dir itself, so the check is made first; the tree below it cannot escape the root.)
func plainDir(dir string) error {
	dir = filepath.Clean(dir)
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("pki: make creds dir: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("pki: look at creds dir: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s", ErrCredsPath, dir)
	}
	return nil
}
