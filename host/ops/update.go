package ops

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/internal/release"
)

// container.start with a version and container.rollback (spec 6.8, 6.10, D-104, D-105, D-138).
//
// Both are one unit swap, journaled like every unit change (containers.go): the journal first, then
// for core the pre_update backup (start) or the moving aside of core's database files (rollback),
// then the unit with the other digest, daemon-reload, restart, and the effect check (the digest and
// "healthy" within 120 s). A swap that does not get healthy is undone in the same run: the old unit
// bytes back and a restart (status reverted, unit_failed); for a core release that says
// rollback.safe=false the database goes back too. The host never decides by itself to roll back
// because of a revocation: core does (update-manifest.md section 8).
//
// Every refusal is decided in Check (planStartVersion, planRollback), with the same function the run
// calls again on what is true then: the stored index is re-verified, the record of the pulled (or
// previous) version is verified again against it (signature, key, release and digest revocation,
// cosign), and nothing is believed because the host wrote it earlier.

const (
	// backupLimit bounds the pre_update backup inside a start: at least backup.create's own 15 minutes (D-138 L2).
	backupLimit = 15 * time.Minute
	// dbWork covers the file work on core's database in one step (unpacking a backup, moving files).
	dbWork = 3 * time.Minute

	// startTimeout and rollbackTimeout are the Spec.Timeout of the two commands: one number each
	// (D-138); TestTimeLimitsAreConsistent checks they cover the worst run.
	//
	// ponytail: unpackBackup, extract and swap do not watch the run's context, so a run's timeout cuts
	// the commands around them but not a copy in progress; their time is bounded by dbWork (3 min) in
	// the sums below, and by the size caps of backups. Upgrade path: pass ctx to extract and swap.
	startTimeout    = 45 * time.Minute
	rollbackTimeout = 30 * time.Minute
)

// dbRevertLimit bounds putting core's database and unit back: stop core, the file work, the unit, a
// restart and the health wait.
func (o *Ops) dbRevertLimit() time.Duration {
	return o.d.CoreWait + dbWork + revertLimitFor(api.ServiceCore) + o.d.HealthWait + probeLimit
}

// unpackBackup unpacks a backup into a private temp directory of the host (extract verifies the
// checksum and the space first) and returns what to call when the files are no longer needed. It never
// touches core's tree; only the swap does, by descriptor.
func (o *Ops) unpackBackup(rec backupRecord, prefix string) (extracted, func(), error) {
	tmp, err := os.MkdirTemp(o.stateFile("tmp"), prefix)
	if err != nil {
		return extracted{}, func() {}, fail(api.CodeUnitFailed, "The backup could not be unpacked.")
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	ex, err := o.extract(rec, tmp)
	if err != nil {
		cleanup()
		return extracted{}, func() {}, err
	}
	return ex, cleanup, nil
}

// archiveThere says whether the archive file of an indexed backup is still on disk.
func (o *Ops) archiveThere(id string) bool {
	st, err := os.Lstat(o.archivePath(id))
	return err == nil && st.Mode().IsRegular()
}

var errRecord = errors.New("ops: a recorded manifest does not match its record")

// loadStoredIndex re-verifies the stored index. nil, nil is "none was ever stored". A stored index that
// no longer verifies is refused (release_state_invalid), never taken as "none" (D-130 (2)).
func (o *Ops) loadStoredIndex(trust release.Trust) (*release.Index, error) {
	idx, err := o.loadIndex(trust)
	if err != nil {
		o.log.Error("the stored release index cannot be used; every pull and every version change is refused until it is dealt with", "error", err.Error())
		return nil, refuse412(api.CodeReleaseStateInvalid, "The index the host stored earlier is damaged or no longer verifies, so the host will not pull or change versions. An operator must remove "+
			o.stateFile("releases", indexStateFile)+" (the host then forgets its replay and revocation memory).")
	}
	return idx, nil
}

// storedRelease is the trust of this build and the stored index, which must exist for a version
// change: it is where the revocations are.
func (o *Ops) storedRelease() (release.Trust, *release.Index, error) {
	trust, err := o.trust()
	if err != nil {
		return trust, nil, refusePull(err, "index")
	}
	idx, err := o.loadStoredIndex(trust)
	if err != nil {
		return trust, nil, err
	}
	if idx == nil {
		return trust, nil, refuse412(api.CodeNotPulled, "The host has no stored release index (container.pull stores it), so it cannot check revocations. Pull the version again.")
	}
	return trust, idx, nil
}

// verifyRecord verifies the manifest a record holds against idx, and the cosign signature of the image,
// and that both say what the record says. The error is the raw one of internal/release (or errRecord).
func (o *Ops) verifyRecord(rec pulledRecord, trust release.Trust, idx *release.Index) (*release.Manifest, error) {
	raw, e1 := decodeDoc(rec.Manifest, maxPullDoc)
	sig, e2 := decodeDoc(rec.ManifestSig, maxPullSig)
	if err := errors.Join(e1, e2); err != nil {
		return nil, errRecord
	}
	man, err := release.VerifyManifest(raw, sig, trust, idx)
	if err != nil {
		return nil, err
	}
	im, ok := man.Image(rec.Service)
	if man.Version != rec.Version || !ok || im.Digest != rec.Digest {
		return nil, errRecord
	}
	if err := release.VerifyImage(man, rec.Service, rec.Digest, trust); err != nil {
		return nil, err
	}
	return man, nil
}

// startPlan is what a start with a version settled.
type startPlan struct {
	rec       pulledRecord
	man       *release.Manifest
	idx       *release.Index
	oldUnit   []byte
	oldDigest string
	change    bool // the digest differs from the one the unit pins
	expired   bool // the index is past its expires_at
}

// planStartVersion is every refusal of container.start with a version except the snapshot ones (D-104 (4)).
func (o *Ops) planStartVersion(ctx context.Context, a api.ContainerStartArgs) (*startPlan, error) {
	old, digest, err := o.currentUnit(a.Service)
	if err != nil {
		return nil, err
	}
	rec, ok := o.loadPulled(a.Service)
	if !ok || rec.Version != a.Version {
		return nil, refuse412(api.CodeNotPulled, "That version has not been pulled on this machine (a newer pull replaces the record of an older one).")
	}
	trust, idx, err := o.storedRelease()
	if err != nil {
		return nil, err
	}
	man, err := o.verifyRecord(rec, trust, idx)
	switch {
	case errors.Is(err, errRecord):
		return nil, refuse412(api.CodeNotPulled, "The record of the pulled version does not match its signed manifest. Pull it again.")
	case err != nil:
		return nil, refusePull(err, "manifest")
	}
	p := &startPlan{rec: rec, man: man, idx: idx, oldUnit: old, oldDigest: digest, change: rec.Digest != digest, expired: idx.Expired(o.d.Now())}
	if !p.change {
		return p, nil
	}
	ref, err := pullRef(a.Service, rec.Digest)
	if err != nil || !o.imageIs(ctx, ref, a.Service, rec.Digest) {
		return nil, refuse412(api.CodeNotPulled, "The image of that version is no longer on this machine. Pull it again.")
	}
	running := ""
	if cur := o.loadVersions(a.Service).Current; cur != nil && cur.Digest == digest {
		running = cur.Version
	}
	if running == "" {
		// Fail closed (D-138 M4): without the running version the downgrade and min_upgrade_from rules have
		// nothing to compare, so a replayed old release would pass. The bootstrap (3-8b) writes the first record;
		// a start with the version of the digest the unit already pins records it (no switch).
		return nil, refuse412(api.CodeCurrentVersionUnknown, "The host does not know which version is running, so it cannot judge this change. Start the version that is running first (container.start with its version), or reinstall.")
	}
	switch err := release.CheckUpgrade(man, running); {
	case errors.Is(err, release.ErrDowngrade):
		return nil, refuse412(api.CodeDowngradeNotAllowed, "That version is lower than the one running. Going back is container.rollback.")
	case errors.Is(err, release.ErrUpgradePath):
		return nil, refuse412(api.CodeUpgradePathRequired, "The running version is below the oldest this release can be installed over (min_upgrade_from). Install an intermediate release first.")
	case err != nil:
		return nil, refusePull(err, "manifest")
	}
	return p, nil
}

// noteExpired says, in the run's log and the audit trail, that the index a version was checked
// against is past its expiry (D-104: an old index only warns; the result carries it too).
func (o *Ops) noteExpired(rc *server.RunContext, command string, p *startPlan) {
	if !p.expired {
		return
	}
	rcLog(rc, "the index is past its expiry; going on, an old index only warns (D-104)")
	o.note(command, "index_expired", map[string]any{"sequence": p.idx.Sequence, "expires_at": p.idx.ExpiresAt.UTC().Format(time.RFC3339), "run_id": rcID(rc)})
}

// putUnitBack writes the old unit text, reloads, restarts, and looks for the old release to be healthy:
// the second half of undoing a swap that moved core's database.
func (o *Ops) putUnitBack(ctx context.Context, rc *server.RunContext, service string, old []byte, oldDigest string) error {
	if err := o.writeUnit(service, old, false); err != nil {
		return err
	}
	if !o.sctl(ctx, reloadLimit, "daemon-reload") {
		return errors.New("ops: systemd would not reload the previous unit")
	}
	if !o.sctl(ctx, restartLimitFor(service), "restart", unitOf(service)) {
		return errors.New("ops: systemd would not restart the previous unit")
	}
	if !o.waitHealthy(ctx, rc, service, oldDigest, o.d.HealthWait) {
		return errors.New("ops: the previous release did not become healthy")
	}
	return nil
}

// revertDatabase stops core and puts its database back as the change found it: "backup" restores the
// pre_update backup of the change, "aside" brings back the files the change moved aside. It is the same
// descriptor path as backup.restore (extract, swap; D-87).
func (o *Ops) revertDatabase(ctx context.Context, t transition) error {
	if err := o.stopCore(ctx); err != nil {
		return err
	}
	switch t.DBRevert {
	case dbAside:
		tree, err := o.openCore()
		if err != nil {
			return err
		}
		defer tree.close()
		return tree.putAsideBack(t.Aside)
	case dbBackup:
		rec, ok := o.lookupBackup(t.BackupID)
		if !ok {
			return errors.New("ops: the pre_update backup is not in the index")
		}
		ex, cleanup, err := o.unpackBackup(rec, "rv-")
		if err != nil {
			return err
		}
		defer cleanup()
		if err := o.swap(ex); err != nil {
			return err
		}
		o.note(api.CmdBackupRestore, "backup_restored", map[string]any{"backup_id": t.BackupID, "service": t.Service, "run_id": t.RunID})
		return nil
	}
	return nil
}

// ---- container.start with a version --------------------------------------------------------------

// runSwitch moves a service to the pulled version whose digest differs from the unit's.
func (o *Ops) runSwitch(ctx context.Context, rc *server.RunContext, a api.ContainerStartArgs, p *startPlan) (any, error) {
	svc, rec := a.Service, p.rec
	want, err := o.renderFor(svc, rec.Digest)
	if err != nil {
		return nil, err
	}
	wasActive := o.unitActive(ctx, svc) == api.UnitActive
	ver, from := rec.Version, p.oldDigest
	res := api.ContainerStartResult{Service: svc, Version: &ver, Digest: rec.Digest, PreviousDigest: &from, Healthy: true, Restarted: true, IndexExpired: p.expired}
	o.noteExpired(rc, api.CmdContainerStart, p)

	tr := o.newJournal(rc, opStart, svc, rec.Digest, p.oldUnit, want, wasActive)
	tr.Version, tr.FromDigest = ver, from
	if err := o.saveJournal(tr); err != nil {
		return nil, fail(api.CodeUnitUnwritable, "The host could not write its journal.")
	}
	o.note(api.CmdContainerStart, "version_switch", map[string]any{"service": svc, "version": ver, "from_digest": from, "to_digest": rec.Digest, "run_id": rcID(rc)})

	if svc == api.ServiceCore {
		rcLog(rc, "making the pre_update backup of core before the switch")
		bctx, cancel := context.WithTimeout(ctx, backupLimit)
		bk, err := o.createBackup(bctx, rc, "pre_update", true, "Before update to "+ver, a.Snapshot)
		cancel()
		if err != nil {
			o.removeJournal(svc) // nothing was changed
			return nil, err
		}
		o.note(api.CmdBackupCreate, "pre_update_backup_made", map[string]any{"backup_id": bk.BackupID, "for_version": ver, "run_id": rcID(rc)})
		tr.BackupID = bk.BackupID
		if !p.man.Rollback.Safe {
			tr.DBRevert = dbBackup // the new release may migrate the database for good: a failed start restores the backup
		}
		if err := o.saveJournal(tr); err != nil {
			o.removeJournal(svc)
			return nil, fail(api.CodeUnitUnwritable, "The host could not write its journal.")
		}
		id := bk.BackupID
		res.BackupID = &id
	}
	if err := o.writeUnit(svc, want, true); err != nil {
		o.removeJournal(svc)
		return nil, unitWriteFailure(err)
	}
	rcLog(rc, "unit written with the digest of "+ver+", reloading systemd and restarting "+unitOf(svc))
	ok := o.sctl(ctx, reloadLimit, "daemon-reload") && o.sctl(ctx, restartLimitFor(svc), "restart", unitOf(svc))
	if ok && o.waitHealthy(ctx, rc, svc, rec.Digest, o.d.HealthWait) {
		if err := o.finishApplied(tr); err != nil {
			return nil, &server.Failure{Code: api.CodeUnitUnwritable, Message: "The new version runs, but the host could not record it, so it will put the previous unit back at its next start.", Result: res}
		}
		o.retainImages(ctx, rc, api.CmdContainerStart, svc)
		return res, nil
	}
	rcLog(rc, "the new version did not become healthy; putting the previous unit back")
	res.Healthy = false
	var rerr error
	if tr.DBRevert == dbBackup {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), o.dbRevertLimit())
		if rerr = o.revertDatabase(rctx, tr); rerr == nil {
			rerr = o.putUnitBack(rctx, rc, svc, p.oldUnit, p.oldDigest)
		}
		cancel()
	} else {
		rerr = o.revertUnit(ctx, svc, p.oldUnit, wasActive)
	}
	if rerr != nil {
		o.log.ErrorContext(ctx, "could not put the previous release back", "service", svc, "error", rerr.Error())
		// The journal stays (pending): the retry loop (started once this run has released the lock) puts the bytes
		// back and then the database; a restart of the host does the same.
		o.kickRestore(ctx)
		return nil, &server.Failure{Code: api.CodeUnitFailed, Message: "The new version did not become healthy and the previous release could not be put back.", Result: res}
	}
	o.finishJournal(tr)
	return nil, &server.Reverted{Code: api.CodeUnitFailed, Message: "The new version did not become healthy; the previous release was put back.", Result: res}
}

// ---- container.rollback --------------------------------------------------------------------------

// rollbackPlan is what a rollback settled.
type rollbackPlan struct {
	prev, cur versionRecord
	oldUnit   []byte
	oldDigest string
	restoreDB bool // core, going down from a release that says rollback.safe=false: restore its pre_update backup
	backup    backupRecord
}

// planRollback is every refusal of container.rollback (spec 6.10, D-104 (5)).
func (o *Ops) planRollback(ctx context.Context, service string) (*rollbackPlan, error) {
	if err := o.checkCommon(service); err != nil {
		return nil, err
	}
	if _, _, err := o.unitDirChain(); err != nil {
		return nil, refuse412(api.CodeUnitUnsafe, "The Quadlet directory is not safe to write as root.")
	}
	old, digest, err := o.currentUnit(service)
	if err != nil {
		return nil, err
	}
	none := refuse412(api.CodeNoPrevious, "There is no previous version of that service to go back to.")
	vs := o.loadVersions(service)
	if vs.Previous == nil || vs.Current == nil || vs.Current.Digest != digest {
		return nil, none
	}
	p := &rollbackPlan{prev: *vs.Previous, cur: *vs.Current, oldUnit: old, oldDigest: digest}
	trust, idx, err := o.storedRelease()
	if err != nil {
		return nil, err
	}
	if _, err := o.verifyRecord(p.prev.pulledRecord, trust, idx); err != nil {
		switch {
		case errors.Is(err, release.ErrKeyRevoked), errors.Is(err, release.ErrReleaseRevoked):
			return nil, refuse412(api.CodePreviousRevoked, "The previous version, its image or the key that signed it is revoked.")
		case errors.Is(err, errRecord):
			return nil, none
		}
		return nil, refusePull(err, "manifest")
	}
	// The running release's own manifest says what may be rolled back to; a revocation of the running release
	// is no reason to refuse (going back is the way out), so it is verified against an index that revokes nothing.
	curMan, err := o.verifyRecord(p.cur.pulledRecord, trust, &release.Index{})
	switch {
	case errors.Is(err, errRecord):
		return nil, none
	case err != nil:
		return nil, refusePull(err, "manifest")
	}
	// core never rolls forward: the backup a roll-forward would need is the one made when the running release
	// was installed, which belongs to another point in time (D-138 H1). Moving core up is container.start with a
	// version and a snapshot, which makes a fresh pre_update backup. Other services keep roll-forward (no data).
	if c, err := release.CompareVersions(p.prev.Version, p.cur.Version); service == api.ServiceCore && (err != nil || c >= 0) {
		return nil, refuse412(api.CodeRollbackIsUpgrade, "The previous version of core is newer than the one running. Use container.start with that version and a snapshot (it makes a fresh backup first).")
	}
	if floor := curMan.Rollback.MinVersion; floor != "" {
		if c, err := release.CompareVersions(p.prev.Version, floor); err != nil || c < 0 {
			return nil, refuse412(api.CodeRollbackNotAllowed, "The previous version is below the oldest this release can be rolled back to (rollback.min_version).")
		}
	}
	// Going down from a core release that is not safe to roll back restores the pre_update backup made when
	// the service moved into the running release.
	if service == api.ServiceCore && !curMan.Rollback.Safe {
		p.restoreDB = true
		rec, ok := o.lookupBackup(p.cur.BackupID)
		if p.cur.BackupID == "" || !ok {
			return nil, refuse412(api.CodeRollbackBackupMissing, "This release cannot be rolled back without the backup made before it was installed, and that backup is gone.")
		}
		if !o.archiveThere(rec.ID) {
			return nil, refuse412(api.CodeRollbackBackupMissing, "This release cannot be rolled back without the backup made before it was installed, and that backup is gone.")
		}
		p.backup = rec
		t, err := o.openCore() // core's data directory must be one the host may write (db_unreadable otherwise)
		if err != nil {
			return nil, err
		}
		err = t.checkAsidable() // before core is stopped: a directory or link where a database file belongs is a refusal (N1)
		t.close()
		if err != nil {
			return nil, refuse412(api.CodeCoreDataInvalid, "Core's data directory holds something that is not a regular file where the database, its key or a leftover of an earlier rollback belongs. An operator must look at it; nothing was changed.")
		}
	}
	ref, err := pullRef(service, p.prev.Digest)
	if err != nil || !o.imageIs(ctx, ref, service, p.prev.Digest) {
		return nil, refuse412(api.CodeNoPrevious, "The image of the previous version is no longer on this machine.")
	}
	return p, nil
}

func (o *Ops) checkContainerRollback(ctx context.Context, a api.ContainerRollbackArgs) error {
	_, err := o.planRollback(ctx, a.Service)
	return err
}

func (o *Ops) runContainerRollback(ctx context.Context, rc *server.RunContext, a api.ContainerRollbackArgs) (any, error) {
	p, err := o.planRollback(ctx, a.Service) // the same rules as Check, on what is true now
	if err != nil {
		return nil, err
	}
	svc := a.Service
	want, err := o.renderFor(svc, p.prev.Digest)
	if err != nil {
		return nil, err
	}
	wasActive := o.unitActive(ctx, svc) == api.UnitActive
	res := api.ContainerRollbackResult{Digest: p.prev.Digest, FromDigest: p.oldDigest}

	var ex extracted
	if p.restoreDB {
		// Unpack the backup first: a backup that cannot be unpacked (checksum, disk) stops the rollback
		// before anything was touched.
		var cleanup func()
		if ex, cleanup, err = o.unpackBackup(p.backup, "rl-"); err != nil {
			return nil, err
		}
		defer cleanup()
		id := p.backup.ID
		res.RestoredBackupID = &id
	}

	tr := o.newJournal(rc, opRollback, svc, p.prev.Digest, p.oldUnit, want, wasActive)
	tr.Version, tr.FromDigest = p.prev.Version, p.oldDigest
	if p.restoreDB {
		tr.BackupID, tr.DBRevert = p.cur.BackupID, dbAside
	}
	if err := o.saveJournal(tr); err != nil {
		return nil, fail(api.CodeUnitUnwritable, "The host could not write its journal.")
	}
	o.note(api.CmdContainerRollback, "rollback_start", map[string]any{"service": svc, "version": p.prev.Version, "from_digest": p.oldDigest, "to_digest": p.prev.Digest, "restore_backup": p.restoreDB, "run_id": rcID(rc)})

	if p.restoreDB {
		rcLog(rc, "stopping core to restore the backup made before the release that is running")
		if err := o.stopCore(ctx); err != nil {
			o.startCoreBestEffort(ctx)
			o.removeJournal(svc) // nothing was changed
			return nil, fail(api.CodeUnitFailed, "Core could not be stopped; nothing was changed.")
		}
	}
	err = o.rollbackSteps(ctx, rc, p, &tr, want, ex)
	if err == nil {
		if err := o.finishApplied(tr); err != nil {
			return nil, &server.Failure{Code: api.CodeUnitUnwritable, Message: "The rollback worked, but the host could not record it, so it will put the running release back at its next start.", Result: res}
		}
		o.retainImages(ctx, rc, api.CmdContainerRollback, svc)
		return res, nil
	}
	o.log.WarnContext(ctx, "the rollback did not work; putting the running release back", "service", svc, "error", err.Error())
	rcLog(rc, "the rollback did not work; putting the running release back")
	var rerr error
	if p.restoreDB {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), o.dbRevertLimit())
		if rerr = o.revertDatabase(rctx, tr); rerr == nil {
			rerr = o.putUnitBack(rctx, rc, svc, p.oldUnit, p.oldDigest)
		}
		cancel()
	} else {
		rerr = o.revertUnit(ctx, svc, p.oldUnit, wasActive)
	}
	if rerr != nil {
		// This run does not loop: it ends here and says so. The journal stays (pending); the retry loop (started
		// once this run has released the lock) and, failing that, the next start of the host put the unit bytes
		// and core's database back.
		o.log.ErrorContext(ctx, "could not put the running release back after a failed rollback", "service", svc, "error", rerr.Error())
		o.kickRestore(ctx)
		return nil, &server.Failure{Code: api.CodeRollbackRevertFailed, Message: "The rollback failed and the running release could not be put back. The host stopped; look at the service and the audit log.", Result: res}
	}
	o.finishJournal(tr)
	return nil, &server.Reverted{Code: api.CodeUnitFailed, Message: "The rollback did not work; the running release was put back.", Result: res}
}

// rollbackSteps does the swap of a rollback after core (when it has to) is stopped: move core's database
// aside and restore the backup, then the unit with the previous digest, reload, restart and look for health.
func (o *Ops) rollbackSteps(ctx context.Context, rc *server.RunContext, p *rollbackPlan, tr *transition, want []byte, ex extracted) error {
	if p.restoreDB {
		tree, err := o.openCore()
		if err != nil {
			return err
		}
		defer tree.close()
		// Clear the stale asides, journal exactly the names about to move, and only then move them (D-138 M1): a
		// crash is undone for these names and no others.
		names, err := tree.planAside(ex.HasKey)
		if err != nil {
			return err
		}
		tr.Aside = names
		if err := o.saveJournal(*tr); err != nil {
			return err
		}
		if err := tree.moveAside(names); err != nil {
			return err
		}
		rcLog(rc, "restoring the backup into core's data")
		if err := o.swap(ex); err != nil {
			return err
		}
		o.note(api.CmdBackupRestore, "backup_restored", map[string]any{"backup_id": p.backup.ID, "service": api.ServiceCore, "run_id": rcID(rc)})
	}
	if err := o.writeUnit(p.prev.Service, want, true); err != nil {
		return err
	}
	rcLog(rc, "unit written with the digest of "+p.prev.Version+", reloading systemd and restarting "+unitOf(p.prev.Service))
	if !o.sctl(ctx, reloadLimit, "daemon-reload") || !o.sctl(ctx, restartLimitFor(p.prev.Service), "restart", unitOf(p.prev.Service)) {
		return errors.New("ops: systemd would not restart the unit")
	}
	if !o.waitHealthy(ctx, rc, p.prev.Service, p.prev.Digest, o.d.HealthWait) {
		return errors.New("ops: the previous version did not become healthy")
	}
	return nil
}
