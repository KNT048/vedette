package ops

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// The files the network commands write (spec 18, "Tệp hệ thống host ghi"): the netplan file in
// /etc and its overlay in /run, and chrony's vedette.sources. Every write goes through an os.Root
// on the directory (temp file O_CREATE|O_EXCL|O_NOFOLLOW, fsync, rename inside the root, fsync of
// the directory), so a link planted at the file name or at the temp name is never followed. The
// directory itself must be a real directory (not a link), owned by the host's owner and closed to
// group and others for writing.
//
// ponytail: only the directory the file is in is checked, not every parent up to "/" (the parents
// are /, /etc, /run, /etc/chrony: root-owned system directories); the check after OpenRoot is on
// the descriptor, the Lstat before it is on the path. Upgrade path: the ChainTop walk of coredata.go.

// prepNetDir makes (with create) and checks by path that <root>/<rel> is a plain directory, and
// returns its path. It holds no descriptor: the checks on the descriptor follow in netDir.
func (o *Ops) prepNetDir(rel string, create bool) (string, error) {
	p := o.path(rel)
	if create {
		if err := os.MkdirAll(p, 0o755); err != nil { //nolint:gosec // a system directory (/etc/netplan, /run/netplan, /etc/chrony/sources.d): netplan and chrony read it as other users
			return "", fmt.Errorf("ops: create /%s: %w", rel, err)
		}
	}
	lst, err := os.Lstat(p)
	if err != nil {
		return "", err
	}
	if !lst.IsDir() {
		return "", fmt.Errorf("ops: /%s is not a plain directory", rel)
	}
	return p, nil
}

// netDir opens <root>/<rel> as an os.Root. With create the directory is made (0755) when absent.
func (o *Ops) netDir(rel string, create bool) (*os.Root, error) {
	p, err := o.prepNetDir(rel, create)
	if err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(p)
	if err != nil {
		return nil, err
	}
	st, err := r.Stat(".")
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	switch {
	case !st.IsDir() || !ok || int(sys.Uid) != o.cfg.OwnerUID:
		_ = r.Close()
		return nil, fmt.Errorf("ops: /%s must be a directory owned by uid %d", rel, o.cfg.OwnerUID)
	case st.Mode().Perm()&0o022 != 0:
		_ = r.Close()
		return nil, fmt.Errorf("ops: /%s is writable by group or others", rel)
	}
	return r, nil
}

// writeAtomicIn writes data as name in r through a temp file and a rename.
func writeAtomicIn(r *os.Root, name string, data []byte, perm os.FileMode) error {
	id, err := randomHex(8)
	if err != nil {
		return err
	}
	tmp := ".tmp-" + id
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("ops: write %s: %w", name, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = r.Remove(tmp)
		}
	}()
	if err := f.Chmod(perm); err != nil {
		return fmt.Errorf("ops: write %s: %w", name, err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("ops: write %s: %w", name, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("ops: write %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("ops: write %s: %w", name, err)
	}
	if err := r.Rename(tmp, name); err != nil {
		return fmt.Errorf("ops: write %s: %w", name, err)
	}
	ok = true
	if d, err := r.Open("."); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// writeIn writes <root>/<rel>/<name> (the directory is created when absent).
func (o *Ops) writeIn(rel, name string, data []byte, perm os.FileMode) error {
	r, err := o.netDir(rel, true)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	return writeAtomicIn(r, name, data, perm)
}

// removeIn deletes <root>/<rel>/<name>; a missing file or directory is success. It removes a link
// at that name without following it.
func (o *Ops) removeIn(rel, name string) error {
	r, err := o.netDir(rel, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	if err := r.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ops: remove %s: %w", name, err)
	}
	return nil
}

type fileState int

const (
	fileAbsent fileState = iota
	fileOK
	fileBroken // a link, directory, FIFO, too large, or unreadable
)

// readNoFollowIn reads <root>/<rel>/<name> (at most limit bytes) when it is a regular file; a FIFO
// is never opened blocking and a symlink is never followed.
func (o *Ops) readNoFollowIn(rel, name string, limit int64) ([]byte, fileState) {
	r, err := os.OpenRoot(o.path(rel))
	if err != nil {
		return nil, fileAbsent
	}
	defer func() { _ = r.Close() }()
	return readNoFollow(r, name, limit)
}

func readNoFollow(r *os.Root, name string, limit int64) ([]byte, fileState) {
	st, err := r.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fileAbsent
		}
		return nil, fileBroken
	}
	if !st.Mode().IsRegular() {
		return nil, fileBroken
	}
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fileBroken
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, fileBroken
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, fileBroken
	}
	return b, fileOK
}
