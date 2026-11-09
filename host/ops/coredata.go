package ops

import (
	"bytes"
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
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// D-87: the root host never opens, parses or runs SQL on core's data. Core makes its own consistent
// snapshot, the host copies bytes by file descriptor. This file is the only place the host touches
// core's directory, and it does so through one os.Root handle (openat, no path walking), checking
// every file on its descriptor (regular file, one link, owned by core, size cap) and doing every
// chmod and chown on a descriptor, never on a path. A file core swaps for a symlink, a FIFO, a
// hardlink to someone else's file or a device after the host looked is refused by the fstat of the
// descriptor it actually opened.

// Names inside core's data directory (fixed: cmd/vedette's defaults are vedette.db and vedette.key
// in /var/lib/vedette). The host never takes a path from a request.
const (
	coreDBFile        = "vedette.db"
	coreKeyFile       = "vedette.key"
	coreSnapshotsDir  = "snapshots"
	coreSnapshotMeta  = "snapshot.json"
	restoreTempPrefix = ".vedette-restore-"
)

// The snapshot contract (docs/specs/host-api.md section 6.11).
const (
	coreSnapshotMaxAge = 10 * time.Minute
	coreSnapshotFuture = time.Minute // a created_at this far ahead of the host's clock is invalid
	maxSnapshotMeta    = 4 << 10
	restoreSpaceFactor = 1.1 // free space a restore wants, times what the archive declares
	nonBlockNoFollow   = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
)

// sidecars are the files SQLite keeps next to a database while it is open; a database that is put
// back must not be read together with the old ones.
var sidecars = []string{"-wal", "-shm", "-journal"}

// errNotFound means the name does not exist in core's tree (as opposed to existing wrongly).
var errNotFound = errors.New("not found")

// coreTree is core's data directory opened for one operation.
type coreTree struct {
	root *os.Root
	uid  int // owner every file must have: core_uid
	gid  int // group restored files get: core_gid
}

// fdPath is the path through which a process opens one of its own descriptors.
func fdPath(fd int) string {
	if runtime.GOOS == "linux" {
		return "/proc/self/fd/" + strconv.Itoa(fd)
	}
	return "/dev/fd/" + strconv.Itoa(fd)
}

// sameInode reports whether st (from Lstat) and the descriptor's stat are one directory.
func sameInode(st os.FileInfo, fd *syscall.Stat_t) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && s.Dev == fd.Dev && s.Ino == fd.Ino
}

// freeBytes is the space a non-root writer could still use on the filesystem of core's tree,
// asked of the root handle's descriptor.
func (t *coreTree) freeBytes() (uint64, error) {
	d, err := t.root.Open(".")
	if err != nil {
		return 0, fmt.Errorf("ops: open core_data: %w", err)
	}
	defer func() { _ = d.Close() }()
	var st syscall.Statfs_t
	if err := syscall.Fstatfs(int(d.Fd()), &st); err != nil {
		return 0, fmt.Errorf("ops: fstatfs core_data: %w", err)
	}
	return nonNegative(st.Bavail) * nonNegative(st.Bsize), nil
}

func (t *coreTree) close() { _ = t.root.Close() }

// openCore checks and opens core_data. The directory must be a real directory (not a symlink)
// owned by core or by root, and every directory above it must belong to root (or the host's own
// uid in tests) and be closed to group and others, sticky or not (like sshd StrictModes): otherwise
// a user who can rename a parent could point the host somewhere else. Called at start-up and at
// the start of every run that touches core's data.
func (o *Ops) openCore() (*coreTree, error) {
	if o.cfg.CoreData == "" {
		return nil, refuse412(api.CodeDBUnreadable, "The host does not know where core's data is (core_data is not set in host.conf).")
	}
	resolved, st, err := o.checkChain(o.cfg.CoreData)
	if err != nil {
		o.log.Warn("core's data directory is not safe to use", "error", err.Error())
		return nil, refuse412(api.CodeDBUnreadable, "Core's data directory is not safe to read: it must be a real directory under root-owned directories that nobody else can write.")
	}
	// os.OpenRoot is open(2) without O_DIRECTORY or O_NONBLOCK: a FIFO in the place of the
	// directory would block the root host in the kernel. So open the directory first with flags
	// that cannot block and require a directory, check it is the one that was checked, and give
	// OpenRoot the descriptor's own path (/proc/self/fd/N, /dev/fd/N), which cannot be swapped.
	pfd, err := syscall.Open(resolved, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, refuse412(api.CodeDBUnreadable, "Core's data directory cannot be opened.")
	}
	defer func() { _ = syscall.Close(pfd) }()
	var pst syscall.Stat_t
	if syscall.Fstat(pfd, &pst) != nil || !sameInode(st, &pst) {
		return nil, refuse412(api.CodeDBUnreadable, "Core's data directory changed while it was being opened.")
	}
	root, err := os.OpenRoot(fdPath(pfd))
	if err != nil {
		return nil, refuse412(api.CodeDBUnreadable, "Core's data directory cannot be opened.")
	}
	// The directory must still be the one that was checked (it could have been renamed and replaced).
	if rst, err := root.Stat("."); err != nil || !os.SameFile(st, rst) {
		_ = root.Close()
		return nil, refuse412(api.CodeDBUnreadable, "Core's data directory changed while it was being opened.")
	}
	return &coreTree{root: root, uid: o.cfg.CoreUID, gid: o.cfg.CoreGID}, nil
}

// checkChain validates core_data and its parents and returns the path to open (parents resolved)
// and the directory's FileInfo. It is the one function that looks at the tree by path, to decide
// whether to trust it at all; nothing it returns is acted on without the descriptor checks above.
func (o *Ops) checkChain(path string) (string, os.FileInfo, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return "", nil, errors.New("core_data is not a real directory")
	}
	trusted := func(uid uint32) bool { return int(uid) == 0 || int(uid) == o.cfg.OwnerUID }
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || (int(sys.Uid) != o.cfg.CoreUID && !trusted(sys.Uid)) {
		return "", nil, errors.New("core_data is owned by neither core nor root")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", nil, err
	}
	top := ""
	if o.d.ChainTop != "" {
		if top, err = filepath.EvalSymlinks(o.d.ChainTop); err != nil {
			return "", nil, err
		}
	}
	for d := parent; ; d = filepath.Dir(d) {
		pst, err := os.Lstat(d)
		if err != nil {
			return "", nil, err
		}
		psys, ok := pst.Sys().(*syscall.Stat_t)
		switch {
		case !pst.IsDir() || pst.Mode()&os.ModeSymlink != 0:
			return "", nil, fmt.Errorf("%s is not a directory", d)
		case !ok || !trusted(psys.Uid):
			return "", nil, fmt.Errorf("%s is not owned by root", d)
		case pst.Mode().Perm()&0o022 != 0:
			// No sticky exception (sshd StrictModes has none): in a sticky directory the owner of
			// an entry may still rename it, and core owns core_data.
			return "", nil, fmt.Errorf("%s can be written by group or others", d)
		}
		if d == filepath.Dir(d) || (top != "" && d == top) {
			break
		}
	}
	return filepath.Join(parent, filepath.Base(path)), st, nil
}

// openFile opens name in core's tree for reading and checks the descriptor: a regular file with
// one link, owned by core, at most limit bytes. Root.OpenFile ignores O_NOFOLLOW and follows a
// final symlink that stays inside the tree, so the Lstat/SameFile check below is what refuses a
// symlink; O_NONBLOCK means a FIFO swapped in cannot block the open (and then fails the regular
// file check). The returned size is the size at the time of the check.
func (t *coreTree) openFile(name string, limit int64) (*os.File, int64, error) {
	f, err := t.root.OpenFile(name, os.O_RDONLY|nonBlockNoFollow, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, errNotFound
		}
		return nil, 0, fmt.Errorf("open %s: %w", filepath.Base(name), err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("stat %s: %w", filepath.Base(name), err)
	}
	// os.Root does not stop a symlink that points inside the tree, so look at the name itself
	// (Lstat does not follow) and require it to be the very file the descriptor is: the check is on
	// the descriptor, this only turns a link into a refusal.
	if lst, err := t.root.Lstat(name); err != nil || lst.Mode()&os.ModeSymlink != 0 || !os.SameFile(lst, st) {
		_ = f.Close()
		return nil, 0, fmt.Errorf("%s is a symbolic link or changed while it was opened", filepath.Base(name))
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	switch {
	case !st.Mode().IsRegular():
		_ = f.Close()
		return nil, 0, fmt.Errorf("%s is not a regular file", filepath.Base(name))
	case !ok || int(sys.Uid) != t.uid:
		_ = f.Close()
		return nil, 0, fmt.Errorf("%s is not owned by core", filepath.Base(name))
	case uint64(sys.Nlink) != 1: //nolint:unconvert // Nlink is uint16 on macOS and uint64 on Linux
		_ = f.Close()
		return nil, 0, fmt.Errorf("%s has more than one link", filepath.Base(name))
	case st.Size() > limit:
		_ = f.Close()
		return nil, 0, fmt.Errorf("%s is larger than %d bytes", filepath.Base(name), limit)
	}
	return f, st.Size(), nil
}

// snapshotMeta is snapshot.json, which core writes next to the database copy.
type snapshotMeta struct {
	CreatedAt   string `json:"created_at"`   // RFC 3339
	DBSchema    string `json:"db_schema"`    // "module=version,..." as core reports it; informational for the host
	IncludesKey bool   `json:"includes_key"` // whether the snapshot directory holds vedette.key

	created time.Time // CreatedAt, parsed
}

// parseSnapshotMeta validates the text of snapshot.json: untrusted bytes from core, strict (no
// unknown field, no trailing data, a real time, the schema grammar of the manifest).
func parseSnapshotMeta(raw []byte) (snapshotMeta, error) {
	var m snapshotMeta
	if len(raw) > maxSnapshotMeta {
		return m, errors.New("snapshot.json is too large")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return snapshotMeta{}, errors.New("snapshot.json is not valid")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return snapshotMeta{}, errors.New("snapshot.json has trailing data")
	}
	created, err := time.Parse(time.RFC3339, m.CreatedAt)
	if err != nil || !validSchema(m.DBSchema) {
		return snapshotMeta{}, errors.New("snapshot.json has a bad field")
	}
	m.created = created
	return m, nil
}

// coreSnapshot is a snapshot core wrote, opened and checked: descriptors the host reads from.
type coreSnapshot struct {
	meta    snapshotMeta
	db      *os.File
	dbSize  int64
	key     *os.File // nil unless asked for and present
	keySize int64
}

func (s *coreSnapshot) close() {
	if s == nil {
		return
	}
	_ = s.db.Close()
	if s.key != nil {
		_ = s.key.Close()
	}
}

// openSnapshot opens <core_data>/snapshots/<id>/ (id is 32 hex, validated by the caller): the
// small snapshot.json, the database copy and, when wantKey and the metadata says so, the key.
// Missing or too old is snapshot_required (core must write a fresh one); anything wrong in what is
// there is snapshot_invalid. Nothing here reads the database: it is bytes.
func (o *Ops) openSnapshot(t *coreTree, id string, wantKey bool) (snap *coreSnapshot, err error) {
	base := coreSnapshotsDir + "/" + id + "/"
	mf, msize, err := t.openFile(base+coreSnapshotMeta, maxSnapshotMeta)
	if errors.Is(err, errNotFound) {
		return nil, refuse412(api.CodeSnapshotRequired, "Core has not written that snapshot. Write one to snapshots/<id>/ and call again.")
	}
	if err != nil {
		return nil, o.invalidSnapshot(err)
	}
	raw, err := io.ReadAll(io.LimitReader(mf, msize+1))
	_ = mf.Close()
	if err != nil || int64(len(raw)) != msize {
		return nil, o.invalidSnapshot(errors.New("snapshot.json could not be read"))
	}
	meta, err := parseSnapshotMeta(raw)
	if err != nil {
		return nil, o.invalidSnapshot(err)
	}
	created := meta.created
	now := o.d.Now()
	switch {
	case created.After(now.Add(coreSnapshotFuture)):
		return nil, o.invalidSnapshot(errors.New("snapshot.json is dated in the future"))
	case now.Sub(created) > coreSnapshotMaxAge:
		return nil, refuse412(api.CodeSnapshotRequired, "The snapshot is older than 10 minutes. Write a fresh one and call again.")
	}
	snap = &coreSnapshot{meta: meta}
	defer func() {
		if err != nil {
			snap.close()
			snap = nil
		}
	}()
	snap.db, snap.dbSize, err = t.openFile(base+coreDBFile, maxDBBytes)
	if err == nil && snap.dbSize == 0 {
		_ = snap.db.Close()
		err = errors.New("the database copy is empty")
	}
	if err != nil {
		snap.db = nil // closed above or never opened
		return nil, o.invalidSnapshot(err)
	}
	if wantKey && meta.IncludesKey {
		snap.key, snap.keySize, err = t.openFile(base+coreKeyFile, maxKeyBytes)
		if err == nil && snap.keySize == 0 {
			_ = snap.key.Close()
			err = errors.New("the key copy is empty")
		}
		if err != nil {
			snap.key = nil
			return nil, o.invalidSnapshot(err)
		}
	}
	return snap, nil
}

func (o *Ops) invalidSnapshot(err error) error {
	o.log.Warn("a snapshot of core was refused", "error", err.Error())
	return refuse412(api.CodeSnapshotInvalid, "The snapshot is not what the contract requires: regular files owned by core, one link each, within the size caps.")
}

// ctxReader stops a copy when the run's context ends.
type ctxReader struct {
	ctx context.Context //nolint:containedctx // a reader that is only ever used inside one call
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// install replaces name in core's tree with the content of in (a file of the host's private temp
// directory, opened by the caller so no path of the host's own is mixed with core's here): written to a random name made with O_EXCL|O_NOFOLLOW through the root handle, given
// core_uid:core_gid and 0600 on the descriptor, fsynced, then renamed over the target inside the
// handle. A directory that core planted at the target is removed first (rename cannot replace it).
func (t *coreTree) install(in io.Reader, name string) error {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("ops: random name: %w", err)
	}
	tmp := restoreTempPrefix + hex.EncodeToString(rnd[:])
	out, err := t.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("ops: create %s: %w", name, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = out.Close()
			_ = t.root.Remove(tmp)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("ops: copy %s: %w", name, err)
	}
	if err := out.Chown(t.uid, t.gid); err != nil {
		return fmt.Errorf("ops: chown %s: %w", name, err)
	}
	if err := out.Chmod(0o600); err != nil {
		return fmt.Errorf("ops: chmod %s: %w", name, err)
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("ops: sync %s: %w", name, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("ops: close %s: %w", name, err)
	}
	if st, err := t.root.Lstat(name); err == nil && st.IsDir() {
		if err := t.root.RemoveAll(name); err != nil {
			return fmt.Errorf("ops: clear %s: %w", name, err)
		}
	}
	if err := t.root.Rename(tmp, name); err != nil {
		return fmt.Errorf("ops: replace %s: %w", name, err)
	}
	ok = true
	t.syncDir()
	return nil
}

// removeSidecars deletes the -wal, -shm and -journal files of a database that is about to be
// replaced: a stale WAL applied to a different database file would corrupt it.
func (t *coreTree) removeSidecars() error {
	for _, suffix := range sidecars {
		if err := t.root.RemoveAll(coreDBFile + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("ops: remove %s: %w", coreDBFile+suffix, err)
		}
	}
	return nil
}

func (t *coreTree) syncDir() {
	if d, err := t.root.Open("."); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// restoreTempRE is the name of a temp file putFile makes: the prefix and 16 hex digits.
var restoreTempRE = regexp.MustCompile(`^\.vedette-restore-[0-9a-f]{16}$`)

// maxSweepEntries bounds how much of core's directory one sweep reads: core can fill it as fast as
// the host reads it, so the work must not depend on how many names core makes.
const maxSweepEntries = 4096

// sweepRestoreTemps removes temp files a restore that died left in core's tree. It deletes only
// regular files with the exact temp name, one by one with Root.Remove (never RemoveAll, which
// rereads a directory until it is empty and so can be held forever), among at most
// maxSweepEntries names.
func (t *coreTree) sweepRestoreTemps() {
	d, err := t.root.Open(".")
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	ents, _ := d.ReadDir(maxSweepEntries)
	for _, e := range ents {
		if restoreTempRE.MatchString(e.Name()) && e.Type().IsRegular() {
			_ = t.root.Remove(e.Name())
		}
	}
}

// checkCoreAtStart looks at core_data once when the host starts. A bad tree is not fatal (the
// installer may create it later); every command that needs it checks again and refuses.
func (o *Ops) checkCoreAtStart() {
	if o.cfg.CoreData == "" {
		return
	}
	t, err := o.openCore()
	if err != nil {
		var ref *server.Refusal
		if errors.As(err, &ref) {
			o.note("backup.create", "core_data_untrusted", map[string]any{})
		}
		return
	}
	defer t.close()
	t.sweepRestoreTemps()
}
