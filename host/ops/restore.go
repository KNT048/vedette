package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// cmdBackupRestore is backup.restore (spec 6.12).
func (o *Ops) cmdBackupRestore() server.Command {
	return server.Define(server.Spec[api.BackupRestoreArgs]{
		Name: api.CmdBackupRestore, Write: true, Timeout: 30 * time.Minute,
		Validate: func(a *api.BackupRestoreArgs) error {
			if !hexIDRE.MatchString(a.BackupID) {
				return server.Invalid("backup_id", "must be 32 lowercase hex characters")
			}
			return nil
		},
		Check: func(_ context.Context, a api.BackupRestoreArgs) error {
			if _, ok := o.lookupBackup(a.BackupID); !ok {
				return server.Refuse(404, api.CodeBackupUnknown, "There is no such backup.")
			}
			if o.cfg.CoreUnit == "" {
				return refuse412(api.CodeRestoreFailed, "The host does not know core's unit.")
			}
			return o.backupPreflight(true, true)
		},
		Run: func(ctx context.Context, rc *server.RunContext, a api.BackupRestoreArgs) (any, error) {
			return o.restore(ctx, rc, a.BackupID)
		},
	})
}

// extracted is a backup unpacked into a private temp directory.
type extracted struct {
	Dir      string
	Manifest Manifest
	HasKey   bool
}

func (e extracted) db() string  { return filepath.Join(e.Dir, memberDB) }
func (e extracted) key() string { return filepath.Join(e.Dir, memberKey) }

// extract verifies the archive against the index (size and SHA-256 of the file, so a file that
// changed on disk is refused) and unpacks it into dir. Members are written by this function under
// fixed names, never under names from the archive.
func (o *Ops) extract(rec backupRecord, dir string) (extracted, error) {
	path := o.archivePath(rec.ID)
	sum, size, err := fileSHA256(path)
	if err != nil {
		return extracted{}, refuse412(api.CodeChecksumMismatch, "The backup file cannot be read.")
	}
	if sum != rec.SHA256 || size != rec.Size {
		return extracted{}, refuse412(api.CodeChecksumMismatch, "The backup file does not match its recorded checksum.")
	}
	f, err := os.Open(path) //nolint:gosec // archive path built from a validated hex id
	if err != nil {
		return extracted{}, refuse412(api.CodeChecksumMismatch, "The backup file cannot be read.")
	}
	defer func() { _ = f.Close() }()
	var ex extracted
	ex.Dir = dir
	var manifestSeen, dbSeen bool
	err = readArchive(f, func(name string, r io.Reader, n int64) error {
		switch name {
		case memberManifest:
			b, err := io.ReadAll(r)
			if err != nil || int64(len(b)) != n {
				return fmt.Errorf("%w: manifest is cut short", ErrArchive)
			}
			m, err := parseManifest(b)
			if err != nil {
				return fmt.Errorf("%w: %s", ErrArchive, err.Error())
			}
			ex.Manifest, manifestSeen = m, true
		case memberDB:
			if !manifestSeen {
				return fmt.Errorf("%w: manifest must come first", ErrArchive)
			}
			if err := writeNew(filepath.Join(dir, name), r, n); err != nil {
				return err
			}
			dbSeen = true
		case memberKey:
			if !manifestSeen || !ex.Manifest.IncludesSecrets {
				return fmt.Errorf("%w: a key that the manifest does not declare", ErrArchive)
			}
			if err := writeNew(filepath.Join(dir, name), r, n); err != nil {
				return err
			}
			ex.HasKey = true
		}
		return nil
	})
	if err != nil {
		return extracted{}, fail(api.CodeRestoreFailed, "The backup archive is not a valid Vedette backup.")
	}
	if !manifestSeen || !dbSeen || ex.Manifest.IncludesSecrets != ex.HasKey {
		return extracted{}, fail(api.CodeRestoreFailed, "The backup archive is incomplete.")
	}
	return ex, nil
}

// writeNew creates path (it must not exist, never through a symlink) and copies exactly n bytes.
func writeNew(path string, r io.Reader, n int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // fixed member name inside a fresh private temp dir
	if err != nil {
		return fail(api.CodeRestoreFailed, "The backup could not be unpacked.")
	}
	copied, err := io.Copy(f, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil || copied != n {
		return fail(api.CodeRestoreFailed, "The backup archive is cut short.")
	}
	return nil
}

type restoreMarker struct {
	PreRestoreID string    `json:"pre_restore_backup_id"`
	BackupID     string    `json:"backup_id"`
	StartedAt    time.Time `json:"started_at"`
}

func (o *Ops) markerPath() string { return o.stateFile("restore.json") }

// restore is backup.restore: check, take pre_restore, stop core, swap, start, health; on failure
// put the pre_restore copy back (status reverted).
func (o *Ops) restore(ctx context.Context, rc *server.RunContext, id string) (any, error) {
	rec, ok := o.lookupBackup(id)
	if !ok {
		return nil, server.Refuse(404, api.CodeBackupUnknown, "There is no such backup.")
	}
	tmp, err := os.MkdirTemp(o.stateFile("tmp"), "rs-")
	if err != nil {
		return nil, fail(api.CodeRestoreFailed, "The restore could not be started.")
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	rc.Log("Checking the backup")
	ex, err := o.extract(rec, tmp)
	if err != nil {
		return nil, err
	}
	// The backup's database must be sound, not from a newer schema than the running one, and
	// usable with the key the box will have afterwards.
	schema, err := inspectDB(ctx, ex.db(), true, true, false)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fail(api.CodeRestoreFailed, "The database inside the backup failed its integrity check.")
	}
	live, err := inspectDB(ctx, filepath.Join(o.cfg.CoreData, coreDBFile), true, false, false)
	matchSidecars(filepath.Join(o.cfg.CoreData, coreDBFile))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, refuse412(api.CodeDBUnreadable, "Core's current database cannot be read.")
	}
	if schemaNewer(schema, live) {
		return nil, refuse409(api.CodeSchemaNewer, "The backup comes from a newer version of Vedette than the one running.")
	}
	if !ex.HasKey {
		_, kerr := os.Lstat(filepath.Join(o.cfg.CoreData, coreKeyFile))
		if errors.Is(kerr, os.ErrNotExist) {
			n, err := countSecrets(ctx, ex.db())
			if err != nil {
				return nil, fail(api.CodeRestoreFailed, "The backup could not be inspected.")
			}
			if n > 0 {
				return nil, refuse412(api.CodeSecretsMissing, "The backup holds secrets but has no key and this box has none either.")
			}
		}
	}
	rc.Progress(15)

	rc.Log("Backing up the current state first")
	pre, err := o.createBackup(ctx, rc, "pre_restore", true, "before restore")
	if err != nil {
		return nil, err
	}
	rc.Progress(30)

	if err := writeJSONAtomic(o.markerPath(), restoreMarker{PreRestoreID: pre.BackupID, BackupID: id, StartedAt: o.d.Now().UTC()}); err != nil {
		return nil, fail(api.CodeRestoreFailed, "The restore could not record that it started, so core was not touched.")
	}
	defer func() { _ = os.Remove(o.markerPath()) }()

	// From here core is stopped, which is the only place the host does that (spec 6.9, 6.12). The
	// context of the run may end meanwhile; the put-back below must still happen, so it gets its own.
	rc.Log("Stopping core")
	if err := o.stopCore(ctx); err != nil {
		o.startCoreBestEffort(ctx)
		return nil, fail(api.CodeRestoreFailed, "Core could not be stopped; nothing was changed.")
	}
	rc.Progress(45)
	rc.Log("Replacing the database")
	swapErr := o.swap(ex)
	if swapErr == nil {
		rc.Log("Starting core")
		swapErr = o.startCoreHealthy(ctx)
	}
	health := []api.Health{{Name: unitName(o.cfg.CoreUnit), OK: swapErr == nil}}
	if swapErr != nil {
		o.log.WarnContext(ctx, "restore failed; putting the previous state back", "error", swapErr.Error())
		rc.Log("The restore did not work: putting the previous state back")
		if err := o.putBack(ctx, pre.BackupID); err != nil {
			o.log.ErrorContext(ctx, "could not put the previous state back", "error", err.Error())
			return nil, &server.Failure{Code: "restore_revert_failed", Message: "The restore failed and the previous state could not be put back. Core is stopped; backup " + pre.BackupID + " holds the previous state."}
		}
		return nil, &server.Reverted{
			Code: api.CodeRestoreHealthFailed, Message: "The restored database did not work; the previous state was put back.",
			Result: api.BackupRestoreResult{RestoredBackupID: id, PreRestoreBackupID: pre.BackupID, Version: rec.Version, Health: health},
		}
	}
	rc.Progress(100)
	return api.BackupRestoreResult{RestoredBackupID: id, PreRestoreBackupID: pre.BackupID, Version: ex.Manifest.Version, Health: health}, nil
}

// swap puts the extracted database (and key, when the backup has one) in core's data directory.
func (o *Ops) swap(ex extracted) error {
	liveDB := filepath.Join(o.cfg.CoreData, coreDBFile)
	if err := removeSidecars(liveDB); err != nil {
		return err
	}
	if err := o.installFile(ex.db(), coreDBFile); err != nil {
		return err
	}
	if ex.HasKey {
		return o.installFile(ex.key(), coreKeyFile)
	}
	return nil
}

// installFile replaces core_data/name with the content of src: written under a random name made
// with O_EXCL|O_NOFOLLOW (core owns the directory and could plant a symlink), given the owner of the
// file it replaces (else of the directory) and mode 0600, fsynced, then renamed over the target.
// rename replaces a symlink at the target instead of following it.
func (o *Ops) installFile(src, name string) error {
	target := filepath.Join(o.cfg.CoreData, name)
	uid, gid, err := o.ownerFor(target)
	if err != nil {
		return err
	}
	in, err := os.Open(src) //nolint:gosec // a file this run just extracted
	if err != nil {
		return fmt.Errorf("ops: open %s: %w", name, err)
	}
	defer func() { _ = in.Close() }()
	suffix, err := randomHex(8)
	if err != nil {
		return err
	}
	tmp := filepath.Join(o.cfg.CoreData, ".vedette-restore-"+suffix)
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // random name, O_EXCL
	if err != nil {
		return fmt.Errorf("ops: create %s: %w", name, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = out.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("ops: copy %s: %w", name, err)
	}
	if err := out.Chown(uid, gid); err != nil {
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
	if err := os.Rename(tmp, target); err != nil {
		return fmt.Errorf("ops: replace %s: %w", name, err)
	}
	ok = true
	syncDir(o.cfg.CoreData)
	return nil
}

// ownerFor is the uid and gid a restored file gets: those of the file it replaces, else of the
// data directory (the installer made it for core).
func (o *Ops) ownerFor(target string) (uid, gid int, err error) {
	st, err := os.Lstat(target)
	if err != nil {
		st, err = os.Lstat(o.cfg.CoreData)
	}
	if err != nil {
		return 0, 0, fmt.Errorf("ops: stat core data: %w", err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("ops: no owner information")
	}
	return int(sys.Uid), int(sys.Gid), nil
}

// putBack restores the pre_restore backup over core's data and starts core. It uses its own
// context: the run's may already be over.
func (o *Ops) putBack(ctx context.Context, preID string) error {
	rec, ok := o.lookupBackup(preID)
	if !ok {
		return errors.New("pre_restore backup is not in the index")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), o.d.CoreWait*2+time.Minute)
	defer cancel()
	tmp, err := os.MkdirTemp(o.stateFile("tmp"), "rb-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	ex, err := o.extract(rec, tmp)
	if err != nil {
		return err
	}
	if err := o.stopCore(ctx); err != nil {
		return err
	}
	if err := o.swap(ex); err != nil {
		return err
	}
	return o.startCoreHealthy(ctx)
}

// stopCore stops core's unit and waits until it is not active.
func (o *Ops) stopCore(ctx context.Context) error {
	if _, code, err := o.exec(ctx, binSystemctl, "stop", o.cfg.CoreUnit); err != nil {
		return fmt.Errorf("ops: systemctl stop: %w", err)
	} else if code != 0 {
		return fmt.Errorf("ops: systemctl stop exited %d", code)
	}
	// Real time, not Deps.Now: the injected clock only stamps records and may stand still in tests.
	wait, cancel := context.WithTimeout(ctx, o.d.CoreWait)
	defer cancel()
	for o.coreActive(wait) {
		if !sleepCtx(wait, o.d.CorePoll) {
			return errors.New("ops: core did not stop")
		}
	}
	if wait.Err() != nil { // the last probe failed because time ran out, not because core stopped
		return errors.New("ops: core did not stop")
	}
	return nil
}

// startCoreHealthy starts core's unit and waits until it is active and stays active for the settle time.
func (o *Ops) startCoreHealthy(ctx context.Context) error {
	if _, code, err := o.exec(ctx, binSystemctl, "start", o.cfg.CoreUnit); err != nil {
		return fmt.Errorf("ops: systemctl start: %w", err)
	} else if code != 0 {
		return fmt.Errorf("ops: systemctl start exited %d", code)
	}
	wait, cancel := context.WithTimeout(ctx, o.d.CoreWait)
	defer cancel()
	for !o.coreActive(wait) {
		if !sleepCtx(wait, o.d.CorePoll) {
			return errors.New("ops: core did not become active")
		}
	}
	if !sleepCtx(ctx, o.d.HealthSettle) || !o.coreActive(ctx) {
		return errors.New("ops: core did not stay active")
	}
	return nil
}

func (o *Ops) startCoreBestEffort(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	_, _, _ = o.exec(ctx, binSystemctl, "start", o.cfg.CoreUnit)
}

// recoverRestore runs at host start-up. A marker file means a restore was cut short (the host
// died between stopping core and finishing): if core is not running, the pre_restore backup is put
// back and core started; if it is running, the marker is only cleared. Both are audited.
func (o *Ops) recoverRestore(ctx context.Context) {
	var m restoreMarker
	if err := readJSONFile(o.markerPath(), &m); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			o.log.WarnContext(ctx, "restore marker is unreadable; removing it")
			_ = os.Remove(o.markerPath())
		}
		return
	}
	defer func() { _ = os.Remove(o.markerPath()) }()
	rctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if o.cfg.CoreUnit == "" || o.coreActive(rctx) {
		o.note(api.CmdBackupRestore, "restore_interrupted", map[string]any{"action": "none", "backup_id": m.BackupID})
		return
	}
	if err := o.putBack(ctx, m.PreRestoreID); err != nil {
		o.log.ErrorContext(ctx, "could not recover an interrupted restore", "error", err.Error())
		o.note(api.CmdBackupRestore, "restore_recovery_failed", map[string]any{"backup_id": m.BackupID, "pre_restore_backup_id": m.PreRestoreID})
		return
	}
	o.note(api.CmdBackupRestore, "restore_interrupted", map[string]any{"action": "reverted", "backup_id": m.BackupID, "pre_restore_backup_id": m.PreRestoreID})
}
