package ops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// Retention (spec 6.11): pre_restore has a group of its own, so restores never push out the backups an update or an
// OS install made, and those never push out the copy that holds the data a restore replaced.
const (
	keepPre        = 3
	keepPreRestore = 3
	keepManual     = 10
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

// lookupBackup finds id in the index. found is false with a nil error when the index was read (or does not
// exist yet) and has no such entry; an index that cannot be read or parsed is an error, never "not found":
// a caller that gives up on a backup (revertDatabase) must not do so for an I/O error that may pass.
func (o *Ops) lookupBackup(id string) (rec backupRecord, found bool, err error) {
	o.bkMu.Lock()
	defer o.bkMu.Unlock()
	ix, err := o.loadIndexLocked()
	if err != nil {
		return backupRecord{}, false, err
	}
	for _, r := range ix.Backups {
		if r.ID == id {
			return r, true, nil
		}
	}
	return backupRecord{}, false, nil
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
			if !hexIDRE.MatchString(a.Snapshot) {
				return server.Invalid("snapshot", "must be the 32 lowercase hex characters of a snapshot core wrote")
			}
			if isPreKind(a.Kind) {
				a.IncludeSecrets = true // a pre_* backup must be restorable, so it carries the key (and is never downloadable)
			}
			return nil
		},
		Check: func(_ context.Context, a api.BackupCreateArgs) error {
			if err := o.coreFree(); err != nil {
				return err
			}
			return o.backupPreflight(a.Snapshot, a.IncludeSecrets, isPreKind(a.Kind))
		},
		Run: func(ctx context.Context, rc *server.RunContext, a api.BackupCreateArgs) (any, error) {
			if a.Label != "" {
				rc.Log("Backup: " + a.Label)
			}
			res, err := o.createBackup(ctx, rc, a.Kind, a.IncludeSecrets, a.Label, a.Snapshot)
			if err != nil {
				return nil, err
			}
			return res, nil
		},
	})
}

// backupPreflight checks that core's snapshot can be read and that there is room for the archive
// (twice the database copy). It only reads.
func (o *Ops) backupPreflight(snapshot string, withKey, keyMayBeAbsent bool) error {
	t, err := o.openCore()
	if err != nil {
		return err
	}
	defer t.close()
	snap, err := o.openSnapshot(t, snapshot, withKey)
	if err != nil {
		return err
	}
	defer snap.close()
	if withKey && !keyMayBeAbsent && snap.key == nil {
		return refuse412("key_unreadable", "Core's snapshot has no secrets key, so a backup with secrets cannot be made.")
	}
	free, err := o.d.FreeBytes(o.backupDir())
	if err != nil {
		return err
	}
	if free < 2*uint64(snap.dbSize) { //nolint:gosec // a file size, never negative
		return refuse412(api.CodeLowDisk, "There is less free space than twice the size of the database.")
	}
	return nil
}

// createBackup is the work of backup.create, also called by os.install and backup.restore inside
// their own run (the write lock is already held by that run). It reads the snapshot core wrote
// through descriptors and streams it into the archive: no SQLite, no path of core's tree walked.
func (o *Ops) createBackup(ctx context.Context, rc *server.RunContext, kind string, withSecrets bool, label, snapshot string) (api.BackupResult, error) {
	if isPreKind(kind) {
		withSecrets = true
	}
	t, err := o.openCore()
	if err != nil {
		return api.BackupResult{}, err
	}
	defer t.close()
	snap, err := o.openSnapshot(t, snapshot, withSecrets)
	if err != nil {
		return api.BackupResult{}, err
	}
	defer snap.close()
	var key []byte
	if withSecrets {
		switch {
		case snap.key != nil:
			if key, err = io.ReadAll(io.LimitReader(snap.key, snap.keySize)); err != nil || int64(len(key)) != snap.keySize {
				return api.BackupResult{}, refuse412("key_unreadable", "Core's secrets key cannot be read, so a backup with secrets cannot be made.")
			}
		case isPreKind(kind):
			withSecrets = false // no key on this box yet (core never ran); the manifest records that
		default:
			return api.BackupResult{}, refuse412("key_unreadable", "Core's snapshot has no secrets key, so a backup with secrets cannot be made.")
		}
	}
	free, err := o.d.FreeBytes(o.backupDir())
	if err != nil {
		return api.BackupResult{}, err
	}
	if free < 2*uint64(snap.dbSize) { //nolint:gosec // a file size, never negative
		return api.BackupResult{}, refuse412(api.CodeLowDisk, "There is less free space than twice the size of the database.")
	}
	id, err := randomHex(16)
	if err != nil {
		return api.BackupResult{}, err
	}
	tmp, cleanup, err := privateTempDir(o.stateFile("tmp"), "bk-")
	if err != nil {
		return api.BackupResult{}, fail("backup_failed", "The backup could not be started.")
	}
	defer cleanup()

	now := o.d.Now().UTC().Truncate(time.Second)
	man := Manifest{Version: manifestVersion, DBSchema: snap.meta.DBSchema, CreatedAt: now.Format(time.RFC3339), IncludesSecrets: withSecrets}
	files := []archiveFile{
		{Name: memberManifest, Data: mustJSON(man)},
		{Name: memberDB, Src: ctxReader{ctx: ctx, r: snap.db}, Size: snap.dbSize},
	}
	if withSecrets {
		files = append(files, archiveFile{Name: memberKey, Data: key})
	}
	rc.Log("Writing the archive")
	archive := filepath.Join(tmp, "archive.tar.gz")
	out, err := createNew(archive)
	if err != nil {
		return api.BackupResult{}, fail("backup_failed", "The archive could not be created.")
	}
	sum, size, werr := writeArchive(out, files, now)
	if cerr := out.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		if ctx.Err() != nil {
			return api.BackupResult{}, ctx.Err()
		}
		o.log.WarnContext(ctx, "could not write the backup archive", "error", werr.Error())
		return api.BackupResult{}, fail("backup_failed", "The archive could not be written.")
	}
	rc.Progress(80)
	if err := ctx.Err(); err != nil {
		return api.BackupResult{}, err
	}
	rec := backupRecord{
		ID: id, Kind: kind, Label: label, CreatedAt: now, Size: size, SHA256: sum,
		Version: manifestVersion, DBSchema: snap.meta.DBSchema, IncludesSecrets: withSecrets,
	}
	if err := o.commitBackup(archive, rec); err != nil {
		o.log.WarnContext(ctx, "could not store the backup", "error", err.Error())
		return api.BackupResult{}, fail("backup_failed", "The backup could not be stored.")
	}
	rc.Progress(100)
	return api.BackupResult{BackupID: id, Size: size, SHA256: sum}, nil
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
	keep, known := o.referencedBackups()
	if !known {
		// A record of what needs a backup cannot be read: fail closed (D-157). Only a pre_update backup is ever
		// referenced (a version's backup_id, the rollback journal's), so every pre_update is kept this time and
		// the other kinds age out as usual: the store does not grow without bound while the file stays damaged.
		o.log.Warn("could not tell which backups are still needed; keeping every pre_update backup")
		o.noteLimited("retention_unknown", api.CmdBackupCreate, "backup_retention_unknown", map[string]any{"backup_id": rec.ID, "kept": "every pre_update backup"})
		for _, r := range ix.Backups {
			if r.Kind == "pre_update" {
				keep[r.ID] = true
			}
		}
	}
	dropped := retain(&ix, keep, rec.ID)
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

// referencedBackups is the set of backup ids that something still needs: the pre_update backup a service's
// current or previous version was entered with (container.rollback restores it for rollback.safe=false), and
// the backup of a transition journal (the revert after a failed or interrupted start). Retention never drops
// these (D-157, WP-31 M4). known is false when a versions file or a journal exists but cannot be read or
// parsed: then the set is incomplete and the caller must not drop anything.
func (o *Ops) referencedBackups() (ref map[string]bool, known bool) {
	ref, known = map[string]bool{}, true
	for _, svc := range api.Services {
		var s versionState
		if exists, err := readStrict(o.stateFile("containers", versionsName(svc)), &s); exists && (err != nil || !s.valid(svc)) {
			known = false
		}
		for _, r := range []*versionRecord{s.Current, s.Previous} {
			if r != nil && r.BackupID != "" {
				ref[r.BackupID] = true
			}
		}
		switch t, st, _ := o.loadJournal(svc); st {
		case jOK:
			if t.BackupID != "" {
				ref[t.BackupID] = true
			}
		case jInvalid, jUnreadable:
			known = false
		}
	}
	return ref, known
}

// retain applies the retention rule to the index and returns the ids to delete: the newest 3
// pre_update/pre_os_update backups, the newest 3 pre_restore ones, at most 10 manual ones (oldest dropped first). A backup in keep is never dropped and
// does not count toward the quota; keep is bounded (three ids per service), so the total stays bounded.
// The backup just made (newest) is always kept and does count, even when a clock stepped back makes it
// look the oldest: it is sorted first, so it is the oldest other backup that ages out (D-157). Refusing
// it instead would stop backup.restore, the way out of core_data_unrecoverable (D-142).
func retain(ix *backupIndex, keep map[string]bool, newest string) []string {
	byAge := func(a, b backupRecord) int {
		if a.ID != b.ID && (a.ID == newest || b.ID == newest) {
			if a.ID == newest {
				return -1
			}
			return 1
		}
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(b.ID, a.ID)
	}
	slices.SortFunc(ix.Backups, byAge) // newest first
	var kept []backupRecord
	var dropped []string
	pre, preRestore, manual := 0, 0, 0
	for _, r := range ix.Backups {
		switch {
		case keep[r.ID]:
		case r.Kind == "pre_restore":
			if preRestore++; preRestore > keepPreRestore {
				dropped = append(dropped, r.ID)
				continue
			}
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
	r, ok, err := o.lookupBackup(id)
	if err != nil {
		return server.File{}, fmt.Errorf("read backup index: %w", err)
	}
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
	if err := o.noteDownload("backup.download", "backup_downloaded", map[string]any{"backup_id": id, "size": r.Size}); err != nil {
		_ = f.Close()
		return server.File{}, err
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

// cmdBackupPurge is backup.purge (spec 6.11a, D-156): delete every archive and the index. There is
// still no way to delete one archive (D-85). It is a run like every command (the framework has no
// synchronous kind), so it holds the write lock and a second write is busy.
func (o *Ops) cmdBackupPurge() server.Command {
	return server.Define(server.Spec[struct{}]{
		Name: api.CmdBackupPurge, Write: true, Timeout: time.Minute,
		// A pending or unrecoverable core transition refuses, as backup.create does (spec 6.11): the
		// journal may name a backup the recovery still needs.
		Check: func(context.Context, struct{}) error { return o.coreFree() },
		Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
			n, err := o.purgeBackups()
			if err != nil {
				o.log.Warn("could not purge the backups", "error", err.Error())
				return nil, fail("purge_failed", "The backups could not all be deleted.")
			}
			o.note(api.CmdBackupPurge, "backups_purged", map[string]any{"deleted": n})
			return api.BackupPurgeResult{Deleted: n}, nil
		},
	})
}

// Names the purge deletes. Each is a name the host itself writes; anything else stays.
var (
	archiveNameRE = regexp.MustCompile(`^[0-9a-f]{32}\.tar\.gz$`)
	exportNameRE  = regexp.MustCompile(`^[0-9a-f]{32}\.jsonl\.gz$`)
	hostTempRE    = regexp.MustCompile(`^\.tmp-[0-9]+$`)            // writeFileAtomic's leftover
	runTempFileRE = regexp.MustCompile(`^ex-[0-9]+$`)               // an export's temp file
	runTempDirRE  = regexp.MustCompile(`^(bk|rs|rb|rv|rl)-[0-9]+$`) // a backup, restore, rollback (rb, rl) or revert temp directory
)

// purgeBackups deletes the host's own backup store and what hangs off it, under the write lock the
// run holds: the archives and their index, the exports and theirs, and the temp files and
// directories of finished or interrupted runs. Deleted, not overwritten. It returns the number of
// archives deleted. The systemd journal is not the host's and is not touched.
func (o *Ops) purgeBackups() (int, error) {
	o.bkMu.Lock()
	defer o.bkMu.Unlock()
	o.exMu.Lock()
	defer o.exMu.Unlock()
	n, err := purgeDir(o.backupDir(), true, archiveNameRE, archiveNameRE, hostTempRE)
	if _, e := purgeDir(o.exportDir(), true, nil, exportNameRE, hostTempRE); err == nil {
		err = e
	}
	if _, e := purgeDir(o.stateFile("tmp"), false, nil, runTempFileRE, runTempDirRE); err == nil {
		err = e
	}
	return n, err
}

// purgeDir deletes from one directory of the host's state, through an os.Root on it (no path is
// walked, no link followed). With hasIndex the index.json goes first and is synced before anything
// else, so a crash never leaves an index entry without its file (sweepBackups removes the orphans
// at start-up). Then every regular file whose name matches one of files, and (os.Root.RemoveAll)
// every directory whose name matches dirs; a link or any other name stays. It returns how many
// regular files matching count it deleted. A directory that does not exist is nothing to do.
func purgeDir(dir string, hasIndex bool, count *regexp.Regexp, files ...*regexp.Regexp) (int, error) {
	r, err := openRootOf(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer func() { _ = r.Close() }()
	if hasIndex {
		if err := r.Remove("index.json"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
		syncDir(dir)
	}
	d, err := r.Open(".")
	if err != nil {
		return 0, err
	}
	ents, err := d.ReadDir(-1)
	_ = d.Close()
	if err != nil {
		return 0, err
	}
	n := 0
	var first error
	for _, e := range ents {
		var rerr error
		switch {
		case e.Type().IsRegular() && matchesAny(e.Name(), files):
			if rerr = r.Remove(e.Name()); rerr == nil && count != nil && count.MatchString(e.Name()) {
				n++
			}
		case e.IsDir() && e.Type()&os.ModeSymlink == 0 && matchesAny(e.Name(), files):
			rerr = r.RemoveAll(e.Name())
		}
		if rerr != nil && !errors.Is(rerr, os.ErrNotExist) && first == nil {
			first = rerr
		}
	}
	syncDir(dir)
	return n, first
}

func matchesAny(name string, res []*regexp.Regexp) bool {
	for _, re := range res {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}
