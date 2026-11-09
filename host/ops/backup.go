package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// Names inside core's data directory (fixed: cmd/vedette's defaults are vedette.db and vedette.key
// in /var/lib/vedette). The host never takes a path from a request.
const (
	coreDBFile  = "vedette.db"
	coreKeyFile = "vedette.key"
)

// Retention (spec 6.11).
const (
	keepPre    = 3
	keepManual = 10
)

var hexIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

var (
	backupKinds = []string{"manual", "pre_update", "pre_os_update", "pre_restore"}
	labelRE     = regexp.MustCompile(`^[\p{L}\p{N} ._:()+@-]{0,64}$`)
)

func isPreKind(kind string) bool { return strings.HasPrefix(kind, "pre_") }

// backupRecord is one entry of backups/index.json. Only archives listed here are served or restored.
type backupRecord struct {
	ID              string    `json:"backup_id"`
	Kind            string    `json:"kind"`
	Label           string    `json:"label,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	Size            int64     `json:"size"`
	SHA256          string    `json:"sha256"`
	Version         int       `json:"version"`
	DBSchema        string    `json:"db_schema"`
	IncludesSecrets bool      `json:"includes_secrets"`
}

type backupIndex struct {
	Backups []backupRecord `json:"backups"`
}

func (o *Ops) backupDir() string { return o.stateFile("backups") }

func (o *Ops) archivePath(id string) string { return filepath.Join(o.backupDir(), id+".tar.gz") }

func (o *Ops) loadIndexLocked() (backupIndex, error) {
	var ix backupIndex
	err := readJSONFile(filepath.Join(o.backupDir(), "index.json"), &ix)
	if errors.Is(err, os.ErrNotExist) {
		return backupIndex{}, nil
	}
	return ix, err
}

func (o *Ops) saveIndexLocked(ix backupIndex) error {
	if ix.Backups == nil {
		ix.Backups = []backupRecord{}
	}
	return writeJSONAtomic(filepath.Join(o.backupDir(), "index.json"), ix)
}

func (o *Ops) lookupBackup(id string) (backupRecord, bool) {
	o.bkMu.Lock()
	defer o.bkMu.Unlock()
	ix, err := o.loadIndexLocked()
	if err != nil {
		return backupRecord{}, false
	}
	for _, r := range ix.Backups {
		if r.ID == id {
			return r, true
		}
	}
	return backupRecord{}, false
}

// cmdBackupCreate is backup.create (spec 6.11).
func (o *Ops) cmdBackupCreate() server.Command {
	return server.Define(server.Spec[api.BackupCreateArgs]{
		Name: api.CmdBackupCreate, Write: true, Timeout: 15 * time.Minute,
		Validate: func(a *api.BackupCreateArgs) error {
			if !slices.Contains(backupKinds, a.Kind) {
				return server.Invalid("kind", "must be manual, pre_update, pre_os_update or pre_restore")
			}
			if !labelRE.MatchString(a.Label) {
				return server.Invalid("label", "must be at most 64 letters, digits, spaces or . _ : ( ) + @ -")
			}
			if isPreKind(a.Kind) {
				a.IncludeSecrets = true // a pre_* backup must be restorable, so it carries the key (and is never downloadable)
			}
			return nil
		},
		Check: func(_ context.Context, a api.BackupCreateArgs) error {
			return o.backupPreflight(a.IncludeSecrets, isPreKind(a.Kind))
		},
		Run: func(ctx context.Context, rc *server.RunContext, a api.BackupCreateArgs) (any, error) {
			if a.Label != "" {
				rc.Log("Backup: " + a.Label)
			}
			res, err := o.createBackup(ctx, rc, a.Kind, a.IncludeSecrets, a.Label)
			if err != nil {
				return nil, err
			}
			return res, nil
		},
	})
}

// backupPreflight checks that core's database (and key, when wanted) can be read and that there
// is room for a copy and its archive. It only reads.
func (o *Ops) backupPreflight(withKey, keyMayBeAbsent bool) error {
	if o.cfg.CoreData == "" {
		return refuse412(api.CodeDBUnreadable, "The host does not know where core's data is (core_data is not set in host.conf).")
	}
	f, st, err := openRegularNoFollow(filepath.Join(o.cfg.CoreData, coreDBFile))
	if err != nil {
		return refuse412(api.CodeDBUnreadable, "Core's database cannot be read.")
	}
	_ = f.Close()
	size := st.Size()
	if wal, werr := os.Lstat(filepath.Join(o.cfg.CoreData, coreDBFile+"-wal")); werr == nil && wal.Mode().IsRegular() {
		size += wal.Size()
	}
	if withKey {
		kf, kst, kerr := openRegularNoFollow(filepath.Join(o.cfg.CoreData, coreKeyFile))
		switch {
		case kerr != nil && keyMayBeAbsent && errors.Is(kerr, os.ErrNotExist):
			// a box whose core never ran has no key yet: a pre_* backup then holds none, and says so
		case kerr != nil || kst.Size() == 0 || kst.Size() > maxKeyBytes:
			return refuse412("key_unreadable", "Core's secrets key file cannot be read, so a backup with secrets cannot be made.")
		default:
			_ = kf.Close()
		}
	}
	free, err := o.d.FreeBytes(o.backupDir())
	if err != nil {
		return err
	}
	if free < 2*uint64(size) { //nolint:gosec // size is a file size, never negative
		return refuse412(api.CodeLowDisk, "There is less free space than twice the size of the database.")
	}
	return nil
}

// createBackup is the work of backup.create, also called by os.install and backup.restore inside
// their own run (the write lock is already held by that run).
func (o *Ops) createBackup(ctx context.Context, rc *server.RunContext, kind string, withSecrets bool, label string) (api.BackupResult, error) {
	if isPreKind(kind) {
		withSecrets = true
	}
	if err := o.backupPreflight(withSecrets, isPreKind(kind)); err != nil {
		return api.BackupResult{}, err
	}
	id, err := randomHex(16)
	if err != nil {
		return api.BackupResult{}, err
	}
	tmp, err := os.MkdirTemp(o.stateFile("tmp"), "bk-")
	if err != nil {
		return api.BackupResult{}, fail("backup_failed", "The backup could not be started.")
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	rc.Log("Copying the database")
	dbCopy := filepath.Join(tmp, memberDB)
	liveDB := filepath.Join(o.cfg.CoreData, coreDBFile)
	err = backupSQLite(ctx, liveDB, dbCopy)
	matchSidecars(liveDB) // opening a WAL database can leave root-owned -shm/-wal behind
	if err != nil {
		if ctx.Err() != nil {
			return api.BackupResult{}, ctx.Err()
		}
		o.log.WarnContext(ctx, "database backup failed", "error", err.Error())
		return api.BackupResult{}, refuse412(api.CodeDBUnreadable, "Core's database could not be copied.")
	}
	_ = os.Chmod(dbCopy, 0o600)
	rc.Progress(40)
	schema, err := inspectDB(ctx, dbCopy, false, true, true)
	if err != nil {
		if ctx.Err() != nil {
			return api.BackupResult{}, ctx.Err()
		}
		o.log.WarnContext(ctx, "backup copy failed its check", "error", err.Error())
		return api.BackupResult{}, fail("backup_corrupt", "The copy of the database failed its integrity check, so no backup was kept.")
	}
	now := o.d.Now().UTC().Truncate(time.Second)
	files := []archiveFile{{Name: memberManifest}, {Name: memberDB, Path: dbCopy}}
	if withSecrets {
		key, err := readKey(filepath.Join(o.cfg.CoreData, coreKeyFile))
		switch {
		case err != nil && isPreKind(kind) && errors.Is(err, os.ErrNotExist):
			withSecrets = false // no key on this box yet; the manifest records that
		case err != nil:
			return api.BackupResult{}, refuse412("key_unreadable", "Core's secrets key file cannot be read, so a backup with secrets cannot be made.")
		default:
			files = append(files, archiveFile{Name: memberKey, Data: key})
		}
	}
	man := Manifest{Version: manifestVersion, DBSchema: schema, CreatedAt: now.Format(time.RFC3339), IncludesSecrets: withSecrets}
	files[0].Data = mustJSON(man)

	rc.Log("Writing the archive")
	archive := filepath.Join(tmp, "archive.tar.gz")
	out, err := os.OpenFile(archive, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // inside a fresh private temp dir
	if err != nil {
		return api.BackupResult{}, fail("backup_failed", "The archive could not be created.")
	}
	sum, size, werr := writeArchive(out, files, now)
	if cerr := out.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		o.log.WarnContext(ctx, "could not write the backup archive", "error", werr.Error())
		return api.BackupResult{}, fail("backup_failed", "The archive could not be written.")
	}
	if err := ctx.Err(); err != nil {
		return api.BackupResult{}, err
	}
	rec := backupRecord{
		ID: id, Kind: kind, Label: label, CreatedAt: now, Size: size, SHA256: sum,
		Version: manifestVersion, DBSchema: schema, IncludesSecrets: withSecrets,
	}
	if err := o.commitBackup(archive, rec); err != nil {
		o.log.WarnContext(ctx, "could not store the backup", "error", err.Error())
		return api.BackupResult{}, fail("backup_failed", "The backup could not be stored.")
	}
	rc.Progress(100)
	return api.BackupResult{BackupID: id, Size: size, SHA256: sum}, nil
}

func readKey(path string) ([]byte, error) {
	f, st, err := openRegularNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if st.Size() == 0 || st.Size() > maxKeyBytes {
		return nil, errors.New("key file has an unexpected size")
	}
	buf := make([]byte, st.Size())
	n, err := f.ReadAt(buf, 0)
	if n != len(buf) {
		return nil, fmt.Errorf("read key: %w", err)
	}
	return buf, nil
}

// commitBackup moves the finished archive into place, adds it to the index and applies retention.
// The index is written after the file exists, so a crash in between leaves an orphan file (removed
// at start-up), never an index entry without a file.
func (o *Ops) commitBackup(archive string, rec backupRecord) error {
	o.bkMu.Lock()
	defer o.bkMu.Unlock()
	ix, err := o.loadIndexLocked()
	if err != nil {
		return err
	}
	dst := o.archivePath(rec.ID)
	if err := os.Rename(archive, dst); err != nil {
		return err
	}
	syncDir(o.backupDir())
	ix.Backups = append(ix.Backups, rec)
	dropped := retain(&ix)
	if err := o.saveIndexLocked(ix); err != nil {
		_ = os.Remove(dst)
		return err
	}
	for _, id := range dropped {
		if err := os.Remove(o.archivePath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
			o.log.Warn("could not remove an old backup")
		}
	}
	return nil
}

// retain applies the retention rule to the index and returns the ids to delete: the newest 3
// pre_* backups, at most 10 manual ones (oldest dropped first).
func retain(ix *backupIndex) []string {
	byAge := func(a, b backupRecord) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(b.ID, a.ID)
	}
	slices.SortFunc(ix.Backups, byAge) // newest first
	var kept []backupRecord
	var dropped []string
	pre, manual := 0, 0
	for _, r := range ix.Backups {
		switch {
		case isPreKind(r.Kind):
			if pre++; pre > keepPre {
				dropped = append(dropped, r.ID)
				continue
			}
		default:
			if manual++; manual > keepManual {
				dropped = append(dropped, r.ID)
				continue
			}
		}
		kept = append(kept, r)
	}
	ix.Backups = kept
	return dropped
}

// readBackups is GET /v1/state/backups.
func (o *Ops) readBackups(context.Context) (any, error) {
	o.bkMu.Lock()
	ix, err := o.loadIndexLocked()
	o.bkMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("read backup index: %w", err)
	}
	out := api.BackupList{Backups: make([]api.Backup, 0, len(ix.Backups))}
	for _, r := range ix.Backups {
		out.Backups = append(out.Backups, api.Backup{
			BackupID: r.ID, Kind: r.Kind, Label: r.Label, CreatedAt: r.CreatedAt, Size: r.Size, SHA256: r.SHA256,
			Version: r.Version, DBSchema: r.DBSchema, IncludesSecrets: r.IncludesSecrets, Downloadable: downloadable(r),
		})
	}
	return out, nil
}

// downloadable: only backups without secrets that are not pre_* leave the box (spec 6.11).
func downloadable(r backupRecord) bool { return !isPreKind(r.Kind) && !r.IncludesSecrets }

// backupContent is GET /v1/backups/{id}/content: only host-created, indexed, secret-free archives.
func (o *Ops) backupContent(id string) (server.File, error) {
	r, ok := o.lookupBackup(id)
	if !ok {
		return server.File{}, server.NewReadError(404, api.CodeBackupUnknown, "There is no such backup.")
	}
	if !downloadable(r) {
		return server.File{}, server.NewReadError(403, api.CodeContainsSecrets, "This backup contains secrets and does not leave the box.")
	}
	f, st, err := openRegularNoFollow(o.archivePath(id))
	if err != nil {
		return server.File{}, server.NewReadError(404, api.CodeBackupUnknown, "There is no such backup.")
	}
	if st.Size() != r.Size {
		_ = f.Close()
		return server.File{}, errors.New("backup file does not match its index entry")
	}
	return server.File{Body: f, Size: r.Size, Name: "vedette-backup-" + r.CreatedAt.Format("20060102T150405Z") + ".tar.gz", Type: "application/gzip"}, nil
}

// sweepBackups removes archives that are not in the index (a crash between the rename and the
// index write) and temp directories left by an interrupted run.
func (o *Ops) sweepBackups() {
	o.bkMu.Lock()
	defer o.bkMu.Unlock()
	ix, err := o.loadIndexLocked()
	if err != nil {
		o.log.Warn("backup index is unreadable; keeping every archive")
		return
	}
	known := map[string]bool{}
	for _, r := range ix.Backups {
		known[r.ID+".tar.gz"] = true
	}
	ents, err := os.ReadDir(o.backupDir())
	if err != nil {
		return
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tar.gz") && !known[e.Name()] {
			_ = os.Remove(filepath.Join(o.backupDir(), e.Name()))
		}
	}
	if tmps, err := os.ReadDir(o.stateFile("tmp")); err == nil {
		for _, e := range tmps {
			_ = os.RemoveAll(filepath.Join(o.stateFile("tmp"), e.Name()))
		}
	}
}
