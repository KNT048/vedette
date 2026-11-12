package ops

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// The first install (docs/specs/host-api.md "Khởi động lần đầu", D-138 M4, D-142): vedette-host
// -bootstrap runs once, as root, from the installer, and never from the socket. It is the only way to get
// the first unit onto the box, because the installer is not core and cannot pass the peer check.
//
// It verifies exactly as container.pull does (verifyPull: the one implementation: embedded keys, the
// stored index and its sequence floor, revocation, platform, install mode, the manifest's hash and the
// cosign signature of every image, which travels inside the manifest), pulls by digest through the same
// podman grammar (pullAndRecord), and then writes what container.start of a version would leave:
// containers/pulled-<service>.json, the unit from the constant template (the D-105 writer) and
// containers/versions-<service>.json with current = the verified record, so that the next
// container.start with a newer version is judged against it (no current_version_unknown).
//
// Order: everything is verified and every refusal is decided before the first write (the one exception is
// the release index: like container.pull, verifyPull stores a newer verified index at once, so a revocation
// it carries is not lost when the manifest is then refused; the audit chain gets release_index_stored); the images are then
// pulled; the units and versions are written only after the last pull worked. A failure part-way leaves
// at most verified images and records of pulled versions, never a unit for a service that was not
// verified, and a rerun with the same documents finishes the job. Rerunning on a finished box changes
// nothing. A different release on a box that already runs one is refused (already_installed): upgrades go
// through container.pull and container.start. It does not start anything: the installer reloads systemd,
// starts the services and looks at their health itself (D-142).

// Codes of the bootstrap that are not in spec section 11 (the command is not on the socket).
const (
	BootstrapAlreadyInstalled = "already_installed" // a release is recorded, or a unit pins another image
	BootstrapUnitForeign      = "unit_foreign"      // a unit the host did not write; -force-units replaces it
	BootstrapBadArgs          = "invalid_args"
	BootstrapFailed           = "bootstrap_failed"
	BootstrapDaemonRunning    = "daemon_running" // another vedette-host or bootstrap holds the state lock
	BootstrapMixedVersions    = "mixed_versions" // a service outside -services runs another release than this one
)

const (
	stateLockWait = 2 * time.Second
	stateLockPoll = 25 * time.Millisecond
)

// ErrStateLocked is LockState's answer when another holder has the lock.
var ErrStateLocked = errors.New("ops: the state directory is locked by another vedette-host")

// LockState takes the one lock of the state directory (<state>/host.lock, flock, non-blocking). The daemon
// holds it for its whole life and the bootstrap for its run, so a bootstrap never runs beside a daemon or
// beside another bootstrap (D-142). The returned function lets it go.
func (o *Ops) LockState(ctx context.Context) (unlock func(), err error) {
	f, err := os.OpenFile(o.stateFile("host.lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("ops: open the state lock: %w", err)
	}
	if st, serr := f.Stat(); serr != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, errors.New("ops: the state lock is not a regular file")
	}
	// Non-blocking, retried for a moment: a lock let go a little late (a child process forked by another
	// holder keeps the descriptor until it execs) is not a second daemon.
	for deadline := time.Now().Add(stateLockWait); ; {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("ops: lock the state directory: %w", err)
		}
		if time.Now().After(deadline) || !sleepCtx(ctx, stateLockPoll) {
			_ = f.Close()
			return nil, ErrStateLocked
		}
	}
	return func() { _ = f.Close() }, nil // closing the descriptor drops the flock
}

// AuditTo gives an Ops that runs no server (the bootstrap) the audit chain to write its lines to.
func (o *Ops) AuditTo(w interface {
	Note(command, code string, detail map[string]any) error
}) {
	o.mu.Lock()
	o.noteOnly = w
	o.mu.Unlock()
}

// BootstrapError is a refusal or failure of the bootstrap with a stable code and a one-line message that is
// safe to print (no file content, no secret).
type BootstrapError struct {
	Code, Message string
}

func (e *BootstrapError) Error() string { return e.Code + ": " + e.Message }

// BootstrapCode names the code of an error of Bootstrap: its own, the refusal's of container.pull, or
// bootstrap_failed. The message is the one safe to show.
func BootstrapCode(err error) (code, message string) {
	var be *BootstrapError
	var rf *server.Refusal
	var fl *server.Failure
	switch {
	case errors.As(err, &be):
		return be.Code, be.Message
	case errors.As(err, &rf):
		return rf.Code, rf.Message
	case errors.As(err, &fl):
		return fl.Code, fl.Message
	}
	return BootstrapFailed, "the bootstrap could not finish"
}

func bsErr(code, msg string) *BootstrapError { return &BootstrapError{Code: code, Message: msg} }

// BootstrapArgs are the four documents the installer holds (raw bytes, as downloaded) and what to do
// with them. Services empty means all four with a unit (core, sensor, scan, honeypot).
type BootstrapArgs struct {
	Index, IndexSig, Manifest, ManifestSig []byte
	Services                               []string
	// ForceUnits lets the bootstrap replace a unit the host did not write (or one that pins another image
	// on a box with no recorded release). Every file replaced is reported, and its old bytes are kept as
	// containers/units/<service>.prev.
	ForceUnits bool
	// LockHeld says the caller already holds LockState (the command line takes it before it reads the head of
	// the audit chain, so no other writer moves it in between).
	LockHeld bool
}

// LockError turns an error of LockState into the bootstrap's refusal.
func LockError(err error) error {
	if errors.Is(err, ErrStateLocked) {
		return bsErr(BootstrapDaemonRunning, "another vedette-host or bootstrap holds the state directory")
	}
	return bsErr(BootstrapFailed, "the state lock could not be taken")
}

type bsStep struct {
	plan    *pullPlan
	want    []byte
	replace bool   // a unit is there and is replaced (forced)
	write   bool   // the unit file is to be written
	versOK  bool   // versions already say current = this digest
	reason  string // why a unit is replaced, for the line printed
	// late: the image the unit pins does not exist yet (scan: it is built on the box after the pull, D-147), so the rest of the decision
	// is made again, with the image's ID, after the pulls and before anything is written.
	late bool
}

// Bootstrap is the whole first install (see above). logf receives one line per step.
func (o *Ops) Bootstrap(ctx context.Context, a BootstrapArgs, logf func(string)) error {
	if logf == nil {
		logf = func(string) {}
	}
	if !a.LockHeld {
		unlock, err := o.LockState(ctx)
		if err != nil {
			return LockError(err)
		}
		defer unlock()
	}
	// OS assumption: Debian or Ubuntu of the support table (as every container command).
	if _, err := o.platform(); err != nil {
		return err
	}
	svcs, err := bootstrapServices(a.Services)
	if err != nil {
		return err
	}
	var head struct {
		Version string `json:"version"`
	}
	// The version is read from the (still unverified) manifest only to name what to ask of verifyPull,
	// which refuses a manifest whose signed version differs.
	if len(a.Manifest) == 0 || len(a.Manifest) > maxPullDoc {
		return bsErr(BootstrapBadArgs, "the manifest is empty or over its limit")
	}
	if json.Unmarshal(a.Manifest, &head) != nil { // what pull would say of a document that is not the signed one
		return refuse412(api.CodeSignatureInvalid, "The manifest does not verify.")
	}
	if len(a.Index) == 0 || len(a.Index) > maxPullDoc || len(a.IndexSig) == 0 || len(a.IndexSig) > maxPullSig || len(a.ManifestSig) == 0 || len(a.ManifestSig) > maxPullSig {
		return bsErr(BootstrapBadArgs, "a document or signature is empty or over its limit")
	}
	b64 := base64.StdEncoding.EncodeToString

	// 1. Verify everything and decide every refusal, before the first write of any kind.
	steps := make([]*bsStep, 0, len(svcs))
	for _, svc := range svcs {
		pa := api.ContainerPullArgs{
			Service: svc, Version: head.Version, Source: api.PullSourceRegistry,
			Index: b64(a.Index), IndexSig: b64(a.IndexSig), Manifest: b64(a.Manifest), ManifestSig: b64(a.ManifestSig),
		}
		if err := validatePullArgs(&pa); err != nil {
			return bsErr(BootstrapBadArgs, "the manifest has no usable version")
		}
		plan, err := o.verifyPull(pa)
		if err != nil {
			var rf *server.Refusal
			if errors.As(err, &rf) {
				return err
			}
			return bsErr(BootstrapFailed, "the host could not store the release index")
		}
		st, err := o.bootstrapDecide(svc, plan, a.ForceUnits)
		if err != nil {
			return err
		}
		steps = append(steps, st)
		logf(fmt.Sprintf("verified %s %s (index sequence %d, signed by %s)", svc, plan.version, plan.idx.Sequence, plan.keyID))
	}
	// A subset must not sit beside services that run another release: the units of one install are one release.
	for _, other := range unitServices {
		if slices.Contains(svcs, other) {
			continue
		}
		if cur := o.loadVersions(other).Current; cur != nil && cur.Version != head.Version {
			return bsErr(BootstrapMixedVersions, other+" runs release "+cur.Version+", not "+head.Version+"; install the same release for every service")
		}
	}
	if _, _, err := o.unitDirChain(); err != nil {
		return bsErr(api.CodeUnitUnsafe, "the Quadlet directory is not safe to write as root")
	}
	// The credential .volume units are written with the first unit of core, sensor or scan: a link or odd file at their names is refused
	// now, before any unit of any service is written (INV-22).
	if slices.ContainsFunc(steps, func(s *bsStep) bool { return s.plan.service != api.ServiceHoneypot }) {
		for _, role := range credsRoles {
			if _, st := o.readNoFollowIn(unitsRel, volumeFileName(role), maxUnitSize); st == fileBroken {
				return bsErr(api.CodeUnitUnsafe, volumeFileName(role)+" is not a regular file the host can trust")
			}
		}
	}
	// The honeypot log volume unit is written with the first unit of core or honeypot (D-318): same refusal.
	if slices.ContainsFunc(steps, func(s *bsStep) bool {
		return s.plan.service == api.ServiceCore || s.plan.service == api.ServiceHoneypot
	}) {
		if _, st := o.readNoFollowIn(unitsRel, hpLogVolumeFileName, maxUnitSize); st == fileBroken {
			return bsErr(api.CodeUnitUnsafe, hpLogVolumeFileName+" is not a regular file the host can trust")
		}
	}
	// core and honeypot share the log volume (D-318): one on the new template and the other on the old bind would make core read an
	// empty tmpfs while the honeypot writes to disk, and every hit would be lost without an error. So when one of them is written, the
	// other must be written too or already mount the volume.
	for _, pair := range [][2]string{{api.ServiceCore, api.ServiceHoneypot}, {api.ServiceHoneypot, api.ServiceCore}} {
		if !slices.Contains(svcs, pair[0]) || slices.Contains(svcs, pair[1]) {
			continue
		}
		if b, st := o.readNoFollowIn(unitsRel, unitFileName(pair[1]), maxUnitSize); st == fileOK && !bytes.Contains(b, []byte(hpLogVolumeFileName+":")) {
			return bsErr(BootstrapBadArgs, "the unit of "+pair[1]+" still binds the old log directory and would no longer see the honeypot log: pass core and honeypot together")
		}
	}
	if err := o.bootstrapSpace(ctx, steps); err != nil {
		return err
	}
	if err := o.ensureCoreData(logf); err != nil {
		return err
	}

	// 2. Pull every image (nothing that is already pulled and tagged is touched). The scan image is built on the box from its base
	// (D-147), which needs the Debian package mirror: a box that cannot reach it must still get core, sensor and honeypot, so a failed
	// build skips scan (no unit, no version, no record) and a later container.pull of scan tries again. Any other failure stops here.
	// The build runs on vedette-int (#467). On a box with Docker its traffic passes only by the DOCKER-USER rules of D-267, which the
	// daemon keeps but which are not there yet on a first install (the daemon starts after this): put them in place now, the same sync the
	// daemon runs (no Docker or no network file: it changes nothing). The daemon is not running (the state lock), so nothing races it.
	if slices.ContainsFunc(steps, func(s *bsStep) bool { return s.plan.service == api.ServiceScan }) {
		fctx, cancel := context.WithTimeout(ctx, dockerFwdLimit)
		switch state, added := o.dockerFwdSync(fctx); {
		case added > 0:
			logf(fmt.Sprintf("added %d DOCKER-USER rules for the vedette-int bridge so the scan build can reach the Debian package mirror (D-267)", added))
		case state == "failed" || state == "iptables_unavailable" || state == "unexpected" || state == "no_bridge":
			logf("the DOCKER-USER rules for the vedette-int bridge are not in place (" + state + "); on a box with Docker the scan build may not reach the Debian package mirror")
		}
		cancel()
	}
	var skipped []string
	var skipErr error
	kept := steps[:0:0]
	for _, s := range steps {
		if o.pulledAndTagged(ctx, s.plan) {
			logf("image of " + s.plan.service + " is already on this machine")
			kept = append(kept, s)
			continue
		}
		if err := o.pullAndRecord(ctx, logf, s.plan); err != nil {
			var fl *server.Failure
			if errors.As(err, &fl) && fl.Code == api.CodeScanBuildFailed && s.plan.service == api.ServiceScan {
				logf("skipped scan: " + fl.Message + " No unit was written for it; run container.pull for scan again once the box reaches deb.debian.org.")
				skipped = append(skipped, s.plan.service)
				skipErr = err
				o.note("bootstrap", "service_skipped", map[string]any{"service": s.plan.service, "version": s.plan.version, "code": fl.Code})
				continue
			}
			return err
		}
		kept = append(kept, s)
	}
	steps = kept
	if len(steps) == 0 && skipErr != nil {
		return skipErr // everything that was asked for was skipped: nothing was installed, so this is a failure (scan_build_failed)
	}

	// 3a. The decisions that needed an image that did not exist before the pulls (scan's ID), all of them before the first write.
	for _, s := range steps {
		if s.late {
			ns, err := o.bootstrapDecide(s.plan.service, s.plan, a.ForceUnits) // the image now exists: the same refusals as for any service
			if err != nil {
				return err
			}
			*s = *ns
		}
	}

	// 3b. Only now the units and the versions.
	for _, s := range steps {
		svc := s.plan.service
		if s.write {
			if s.replace {
				logf(fmt.Sprintf("replacing %s (%s); the old bytes are kept as containers/units/%s", unitFileName(svc), s.reason, o.prevName(svc)))
			}
			if err := o.writeUnitForStart(svc, s.want); err != nil {
				if errors.Is(err, errBadFill) {
					return bsErr(api.CodeHostConfIncomplete, "host.conf does not give the uid and gid the credential volumes need")
				}
				if errors.Is(err, errUnitUnsafe) {
					return bsErr(api.CodeUnitUnsafe, "the Quadlet directory or the unit of "+svc+" is not safe to write as root")
				}
				return bsErr(api.CodeUnitUnwritable, "the unit of "+svc+" could not be written")
			}
			logf("wrote " + unitFileName(svc))
		}
		if !s.versOK {
			rec, ok := o.loadPulled(svc)
			if !ok || rec.Digest != s.plan.unitDigest() {
				return bsErr(BootstrapFailed, "the record of the pulled version of "+svc+" is missing")
			}
			if err := o.saveVersions(versionState{Service: svc, Current: &versionRecord{pulledRecord: rec}}); err != nil {
				return bsErr(BootstrapFailed, "the version of "+svc+" could not be recorded")
			}
			logf("recorded " + svc + " " + rec.Version + " as the running version")
		}
		if s.write || !s.versOK {
			o.note("bootstrap", "installed", map[string]any{"service": svc, "version": s.plan.version, "digest": s.plan.unitDigest(), "unit_written": s.write, "unit_replaced": s.replace})
		}
	}
	if len(skipped) > 0 {
		logf("skipped: " + strings.Join(skipped, ", ") + " (not installed; see above)")
	}
	if !slices.ContainsFunc(steps, func(s *bsStep) bool { return s.write || !s.versOK }) {
		if len(skipped) > 0 {
			logf("nothing more to install: the rest of this release is already installed; " + strings.Join(skipped, ", ") + " was skipped")
			return nil
		}
		logf("nothing to do: this release is already installed")
		return nil
	}
	logf("done; run systemctl daemon-reload and start the services")
	return nil
}

// bootstrapServices checks the list: only services with a unit, once each; none given means all.
func bootstrapServices(in []string) ([]string, error) {
	if len(in) == 0 {
		return slices.Clone(unitServices), nil
	}
	var out []string
	for _, s := range in {
		if !slices.Contains(unitServices, s) {
			return nil, bsErr(BootstrapBadArgs, "services must be from core, sensor, scan, honeypot")
		}
		if slices.Contains(out, s) {
			return nil, bsErr(BootstrapBadArgs, "a service is named twice")
		}
		out = append(out, s)
	}
	// Recovery order of the host (core first), whatever order the installer wrote.
	slices.SortFunc(out, func(a, b string) int { return slices.Index(unitServices, a) - slices.Index(unitServices, b) })
	return out, nil
}

// bootstrapDecide settles, without writing, what the bootstrap does for one service.
func (o *Ops) bootstrapDecide(svc string, plan *pullPlan, force bool) (*bsStep, error) {
	want, err := o.renderUnitFor(svc, plan.unitDigest()) // core_data itself is vetted (or made) by ensureCoreData next
	if err != nil {
		return nil, err // host_conf_incomplete or unit_unknown
	}
	if _, st, _ := o.loadJournal(svc); st != jAbsent {
		return nil, refuse412(api.CodeTransitionPending, "An earlier change of the unit of "+svc+" was never settled; this is not a first install.")
	}
	s := &bsStep{plan: plan, want: want, write: true}
	if services[svc].byID && plan.pin == "" {
		// Before the pull the render above only proved that host.conf fits; the pin comes with the build, so the comparison with the
		// image of a unit or a version waits for it (late). Everything that does not need the pin is refused here, before any pull
		// or write (INV-22): a different release already recorded, a unit that is not a regular file or not ours without -force-units.
		if vs := o.loadVersions(svc); vs.Current != nil && vs.Current.Version != plan.version {
			return nil, bsErr(BootstrapAlreadyInstalled, svc+" already runs release "+vs.Current.Version+"; upgrades go through container.pull and container.start")
		}
		switch text, fs := o.readUnit(svc); fs {
		case fileBroken:
			return nil, bsErr(api.CodeUnitUnsafe, "the unit of "+svc+" is not a regular file the host can trust")
		case fileOK:
			if _, _, perr := o.ourUnit(svc, text); perr != nil && !force {
				return nil, bsErr(BootstrapUnitForeign, "the unit of "+svc+" is not what this host writes; remove it or pass -force-units")
			}
		}
		s.late = true
		return s, nil
	}
	vs := o.loadVersions(svc)
	if vs.Current != nil {
		if vs.Current.Digest != plan.unitDigest() {
			return nil, bsErr(BootstrapAlreadyInstalled, svc+" already runs release "+vs.Current.Version+"; upgrades go through container.pull and container.start")
		}
		s.versOK = true
	}
	text, fs := o.readUnit(svc)
	switch fs {
	case fileBroken:
		return nil, bsErr(api.CodeUnitUnsafe, "the unit of "+svc+" is not a regular file the host can trust")
	case fileAbsent:
		return s, nil
	}
	digest, _, perr := o.ourUnit(svc, text)
	switch {
	case perr == nil && digest == plan.unitDigest():
		s.write = false // the unit is ours and pins this image: left as it is (it may have lost [Install] by a stop with persist)
	case !force && perr == nil:
		if s.plan.pin != "" && services[svc].byID {
			// The image was just built, so its ID is new: the unit pins an older build (for example one that was pruned and rebuilt).
			return nil, bsErr(BootstrapAlreadyInstalled, "the unit of "+svc+" pins another build of the image (a rebuilt image has a new ID); run the bootstrap again with -force-units to replace the unit, or use container.start with the version to switch to the new image")
		}
		return nil, bsErr(BootstrapAlreadyInstalled, "the unit of "+svc+" already pins another image; upgrades go through container.pull and container.start")
	case !force:
		return nil, bsErr(BootstrapUnitForeign, "the unit of "+svc+" is not what this host writes; remove it or pass -force-units")
	default:
		s.replace = true
		s.reason = "forced: it pins another image"
		if perr != nil {
			s.reason = "forced: it is not what this host writes"
		}
	}
	return s, nil
}

// pulledAndTagged says the image of the plan is on this machine under its local name and the record of
// the pulled version is this one: then the pull has nothing left to do.
func (o *Ops) pulledAndTagged(ctx context.Context, p *pullPlan) bool {
	rec, ok := o.loadPulled(p.service)
	if !ok || rec.manifestDigest() != p.digest || rec.Version != p.version {
		return false
	}
	if p.service == api.ServiceScan {
		// The image that runs is the one built on this machine: it must still be there under the ID the record names.
		if ref, err := localRef(p.service, rec.Digest); err != nil || !o.imageIs(ctx, ref, p.service, rec.Digest) {
			return false
		}
		p.pin = rec.Digest
		return true
	}
	tag, err := localTag(p.service, p.version)
	return err == nil && o.imageIs(ctx, tag, p.service, p.digest)
}

// bootstrapSpace is the low_disk rule of container.pull over all the images that are still to come.
func (o *Ops) bootstrapSpace(ctx context.Context, steps []*bsStep) error {
	var need uint64
	for _, s := range steps {
		if !o.imageIs(ctx, s.plan.ref, s.plan.service, s.plan.digest) {
			need += uint64(max(s.plan.size, 0)) * lowDiskFactor
		}
	}
	if need == 0 {
		return nil
	}
	free, err := o.freeForImages()
	if err != nil {
		return refuse412(api.CodeLowDisk, "The host could not measure the free space where images are stored.")
	}
	if free < need {
		return refuse412(api.CodeLowDisk, fmt.Sprintf("Not enough free space for the images: %d MiB free, %d MiB needed (twice their size).", free>>20, need>>20))
	}
	return nil
}

// ensureCoreData makes core's data directory when host.conf names one and it is not there: 0700, owned by
// core_uid:core_gid, under parents that are root's and closed (D-87 checkChain demands that of every
// command that opens it). The key is not made here: it lives in this directory as vedette.key, which is
// what backup.* reads and restores, and core creates it with mode 0600 at its first start (D-142). An
// existing directory is core's own and is left as it is.
func (o *Ops) ensureCoreData(logf func(string)) error {
	dir := o.cfg.CoreData
	if dir == "" {
		logf("host.conf has no core_data: backups and restores will refuse until the installer writes it")
		return nil
	}
	if o.coreDataForbidden(dir) {
		return bsErr(api.CodeCoreDataInvalid, "core_data names a place the host keeps for itself (its state, the units, the audit log or a system directory)")
	}
	st, err := os.Lstat(dir)
	switch {
	case err == nil:
		return o.vetCoreData(dir, st, logf)
	case !errors.Is(err, os.ErrNotExist):
		return bsErr(BootstrapFailed, "core_data could not be looked at")
	}
	// Absent: its parent must be a real directory that is root's and closed (the same rule checkChain applies
	// to every parent of core_data), and the new directory is made relative to the opened parent, so nothing
	// along the path is followed after it was vetted.
	parent := filepath.Dir(dir)
	pst, err := os.Lstat(parent)
	if err != nil {
		return bsErr(api.CodeCoreDataInvalid, "the parent directory of core_data does not exist; the installer makes it")
	}
	if _, err := o.checkParents(dir); err != nil || pst.Mode()&os.ModeSymlink != 0 || !pst.IsDir() {
		return bsErr(api.CodeCoreDataInvalid, "the parent of core_data is not a real directory under root-owned directories that nobody else can write")
	}
	if err := o.mkCoreDataIn(parent, pst, filepath.Base(dir)); err != nil {
		return err
	}
	logf("made core_data (0700, owned by core)")
	return nil
}

// systemDirs are places core_data may never be, hold or sit under: it is bound into core's unit and given to
// core, which would then own part of the system.
var systemDirs = []string{"/etc", "/run", "/proc", "/sys", "/dev", "/boot", "/usr"}

// coreDataForbidden says p is, holds or sits under the Quadlet directory, the host's state directory, the
// audit directory or one of systemDirs.
func (o *Ops) coreDataForbidden(p string) bool {
	places := append([]string{o.path(unitsRel), o.cfg.StateDir, o.cfg.AuditDir}, systemDirs...)
	for _, f := range places {
		if f == "" {
			continue
		}
		f = filepath.Clean(f)
		if p == f || strings.HasPrefix(p, f+"/") || strings.HasPrefix(f, p+"/") {
			return true
		}
	}
	return false
}

// vetCoreData looks at an existing core_data: checkChain (a real directory under root's closed parents, owned
// by core or root), then through its descriptor: owned by core with mode 0700 is what core's own directory
// is; an empty directory of anyone else is given to core; anything else is refused and left as it is.
func (o *Ops) vetCoreData(dir string, st os.FileInfo, logf func(string)) error {
	bad := bsErr(api.CodeCoreDataInvalid, "core_data must be a real directory owned by core with mode 0700 (or an empty one that the bootstrap gives to core), under root-owned directories")
	if _, _, err := o.checkChain(dir); err != nil {
		return bad
	}
	f, err := openDirNoFollow(dir)
	if err != nil {
		return bad
	}
	defer func() { _ = f.Close() }()
	fst, err := f.Stat()
	if err != nil || !os.SameFile(st, fst) {
		return bad
	}
	sys, ok := fst.Sys().(*syscall.Stat_t)
	switch {
	case !ok:
		return bad
	case int(sys.Uid) == o.cfg.CoreUID && fst.Mode().Perm() == 0o700:
		return nil
	case int(sys.Uid) == o.cfg.CoreUID:
		return bad
	}
	if names, err := f.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) || len(names) != 0 {
		return bad
	}
	if err := f.Chown(o.cfg.CoreUID, o.cfg.CoreGID); err != nil || f.Chmod(0o700) != nil {
		return bsErr(BootstrapFailed, "core_data could not be given to core")
	}
	logf("gave the empty core_data to core (0700)")
	return nil
}

// mkCoreDataIn makes name (0700, core_uid:core_gid) inside parent through an os.Root of parent, after checking
// through the descriptor that it is the directory that was vetted and that nobody else can write it.
func (o *Ops) mkCoreDataIn(parent string, vetted os.FileInfo, name string) error {
	r, err := os.OpenRoot(parent)
	if err != nil {
		return bsErr(BootstrapFailed, "the parent of core_data could not be opened")
	}
	defer func() { _ = r.Close() }()
	rst, err := r.Stat(".")
	if err != nil || !os.SameFile(vetted, rst) {
		return bsErr(api.CodeCoreDataInvalid, "the parent of core_data changed while it was opened")
	}
	if sys, ok := rst.Sys().(*syscall.Stat_t); !ok || (int(sys.Uid) != 0 && int(sys.Uid) != o.cfg.OwnerUID) || rst.Mode().Perm()&0o022 != 0 {
		return bsErr(api.CodeCoreDataInvalid, "the parent of core_data is not root's or can be written by others")
	}
	if err := r.Mkdir(name, 0o700); err != nil {
		return bsErr(BootstrapFailed, "core_data could not be made")
	}
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return bsErr(BootstrapFailed, "core_data could not be opened")
	}
	defer func() { _ = f.Close() }()
	if err := f.Chown(o.cfg.CoreUID, o.cfg.CoreGID); err != nil || f.Chmod(0o700) != nil {
		return bsErr(BootstrapFailed, "core_data could not be given to core")
	}
	return nil
}

// ---- the files of the command line ------------------------------------------------------------------

// ReadBootstrapFile reads one of the installer's documents: a regular file (no link), at most limit bytes.
func ReadBootstrapFile(path string, limit int64) ([]byte, error) {
	f, st, err := openRegularNoFollow(path)
	if err != nil {
		return nil, errors.New("not a readable regular file")
	}
	defer func() { _ = f.Close() }()
	if st.Size() > limit {
		return nil, errors.New("over its size limit")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("not readable or over its size limit")
	}
	return b, nil
}

// BootstrapDocLimits are the limits of the documents (the same as container.pull's).
func BootstrapDocLimits() (doc, sig int64) { return maxPullDoc, maxPullSig }

// SplitServices reads "core,sensor" as a list ("" is none).
func SplitServices(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Split(s, ",")
}
