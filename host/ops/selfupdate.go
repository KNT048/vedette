package ops

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/internal/release"
)

// host.self_update (docs/specs/host-api.md section 6.14, D-316, plan docs/plans/2026-11-12-host-self-update.md
// slice 2). Check decides every refusal; Run copies core's file into the root-only staged/ while it hashes it,
// asks dpkg-deb what the copy is, simulates the apt install, copies the running binary to selfupdate/applier,
// writes the journal (staged, attempt 0) and returns server.Parked: park first, dispatch after. The settle
// goroutine (its first round starts the applier with systemd-run) and the applier come with slice 2b.

// Time limits (spec 6.14 "Thời hạn"; TestTimeLimitsAreConsistent checks they agree).
const (
	// suPreParkTimeout is Spec.Timeout: Check, the copy of up to 256 MiB, apt-get update (suAptUpdateLimit),
	// the simulation and dpkg-deb. It no longer applies once the run is parked.
	suPreParkTimeout = 10 * time.Minute
	suAptUpdateLimit = 5 * time.Minute
	// suRunWindow is journal.deadline - journal.started_at: before parking, two applier runs, and slack.
	suRunWindow = 130 * time.Minute
	// applierRuntimeMax is the RuntimeMaxSec of one applier run, and the margin a second dispatch needs
	// before the deadline.
	applierRuntimeMax = 60 * time.Minute
	// applierLockBudget is the dpkg lock wait of one install: apt's DPkg::Lock::Timeout=600, or the F_GETLK
	// wait before dpkg -i including its one retry.
	applierLockBudget = 10 * time.Minute
	// hostStartLimit is TimeoutStartSec of vedette-host.service: postinst's try-restart waits up to this.
	hostStartLimit = 16 * time.Minute
	// suHealthWindow and suStableWindow: started.json of the new version within 120 s, then 30 s unchanged.
	suHealthWindow = 120 * time.Second
	suStableWindow = 30 * time.Second
	// coreWaitPastDeadline is how long core waits past the deadline before it gives the run up (slice 5,
	// modules/core selfUpdateGrace): past the host's own safety net (suSafetyMargin) plus 5 minutes, so core never
	// calls a run stopped half way that the host still settles.
	coreWaitPastDeadline = 20 * time.Minute
)

// usrLibVedette is where the package puts the binary: low_disk looks at its filesystem too.
const usrLibVedette = "usr/lib/vedette"

// corePackagesDir is the folder of core_data where core writes the downloaded package.
const corePackagesDir = "host-packages"

func (o *Ops) cmdHostSelfUpdate() server.Command {
	return server.Define(server.Spec[api.HostSelfUpdateArgs]{
		Name: api.CmdHostSelfUpdate, Write: true, Parks: true, Timeout: suPreParkTimeout, MaxBody: pullBody,
		Validate: validateSelfUpdateArgs,
		Check: func(ctx context.Context, a api.HostSelfUpdateArgs) error {
			_, err := o.checkSelfUpdate(ctx, a)
			return err
		},
		Run: o.runSelfUpdate,
	})
}

func validateSelfUpdateArgs(a *api.HostSelfUpdateArgs) error {
	if _, err := release.CompareVersions(a.Version, a.Version); err != nil || !tagVersionRE.MatchString(a.Version) {
		return server.Invalid("version", "must be a release version such as 1.4.0")
	}
	for _, f := range []struct {
		name, v string
		limit   int
	}{
		{"index", a.Index, maxPullDoc}, {"index_sig", a.IndexSig, maxPullSig}, {"manifest", a.Manifest, maxPullDoc}, {"manifest_sig", a.ManifestSig, maxPullSig},
	} {
		if _, err := decodeDoc(f.v, f.limit); err != nil {
			return server.Invalid(f.name, fmt.Sprintf("must be base64 of 1 byte to %d KiB", f.limit>>10))
		}
	}
	if !hexIDRE.MatchString(a.Package) {
		return server.Invalid("package", "must be the 32 lowercase hex characters of the file core wrote")
	}
	return nil
}

// suPlan is what Check settled.
type suPlan struct {
	to   string           // host.version of the manifest
	file release.HostFile // its file for this architecture
	same bool             // to is the running version: nothing to do
	from suPkg            // versions.json current (= the running version), when not same
}

// checkSelfUpdate is Check (spec 6.14, in its order). It only reads, except that verifyRelease stores a newer
// verified index as container.pull does (D-130).
func (o *Ops) checkSelfUpdate(ctx context.Context, a api.HostSelfUpdateArgs) (*suPlan, error) {
	// 1. the box, the running build, nothing else open, no applier alive.
	if _, err := o.platform(); err != nil {
		return nil, err
	}
	if !validHostVersion(o.cfg.Version) {
		return nil, refuse412(api.CodeHostVersionUnknown, "This host is a development build without a release version; it cannot update itself.")
	}
	if err := o.noOpenRecovery(); err != nil {
		return nil, err
	}
	if o.applierAlive(ctx) {
		return nil, refuse409(api.CodeBusy, "The transient unit of an earlier self-update is still running.")
	}
	// 2. the documents, with exactly the checks of container.pull.
	docs, err := o.verifyRelease(api.CmdHostSelfUpdate, a.Version, a.Index, a.IndexSig, a.Manifest, a.ManifestSig)
	if err != nil {
		return nil, err
	}
	// 3. the package in the manifest.
	h := docs.man.Host
	if h == nil || !validHostVersion(h.Version) {
		return nil, refuse412(api.CodeNoHostPackage, "The release has no package of the system helper.")
	}
	arch := o.arch()
	if arch != "amd64" && arch != "arm64" {
		return nil, refuse412(api.CodePlatformMismatch, "The release has no package of the system helper for this machine's platform.")
	}
	p := &suPlan{to: h.Version}
	want := hostPkgName(h.Version, arch)
	found := false
	for _, f := range h.Files {
		if f.Name == want {
			p.file, found = f, true
		}
	}
	if !found {
		return nil, refuse412(api.CodePlatformMismatch, "The release has no package of the system helper for this machine's platform.")
	}
	if p.file.Size < 1 || p.file.Size > maxHostPackage {
		return nil, refuse412(api.CodeNoHostPackage, "The release names a package of the system helper of a size the host does not accept.")
	}
	// 4. upgrade only; a test build only on a test host; the same version is a no-op.
	if refuseTestBuild(h.Version, o.cfg.Version, docs.trust.TestOnly) {
		return nil, refuse412(api.CodeTestVersionRefused, "The release's system helper is a test build, and this host does not trust the test keys.")
	}
	c, err := release.CompareVersions(h.Version, o.cfg.Version)
	if err != nil {
		return nil, refuse412(api.CodeNoHostPackage, "The release names a version of the system helper that cannot be compared.")
	}
	if c < 0 {
		return nil, refuse412(api.CodeDowngradeNotAllowed, "The release's system helper "+h.Version+" is older than the running "+o.cfg.Version+"; the helper only goes up.")
	}
	if c == 0 {
		p.same = true
		return p, nil
	}
	// 5. the way back: the running version must be recorded, installed and kept.
	if p.from, err = o.currentPackage(ctx); err != nil {
		return nil, err
	}
	// 6. core's file.
	if err := o.checkCorePackage(a.Package, p.file.Size); err != nil {
		return nil, err
	}
	// 7. room for the copy and for the unpacked package.
	if err := o.suDiskRoom(p.file.Size); err != nil {
		return nil, err
	}
	// 8. dpkg.
	if o.dpkgLocked() {
		return nil, lockedRefusal()
	}
	res, code, err := o.exec(ctx, binDpkg, "--audit")
	if err != nil {
		return nil, err
	}
	if code != 0 || len(bytes.TrimSpace(res.Stdout)) > 0 {
		return nil, refuse412(api.CodeDpkgInconsistent, "dpkg --audit reports packages in a broken state; fix them before updating the system helper.")
	}
	return p, nil
}

// noOpenRecovery refuses with transition_pending while anything else is being put right: the journal of a
// unit change of any service, a restore, or a self-update (one recovery at a time).
func (o *Ops) noOpenRecovery() error {
	for _, svc := range unitServices {
		if t, st, _ := o.loadJournal(svc); st != jAbsent {
			return refuse412(api.CodeTransitionPending, transitionPendingText(t, st == jOK))
		}
	}
	if _, err := os.Lstat(o.markerPath()); !errors.Is(err, os.ErrNotExist) {
		return refuse412(api.CodeTransitionPending, "A restore of core's data is still being put right. Try again later.")
	}
	if _, st := o.readSU(suJournalName); st != jAbsent {
		return refuse412(api.CodeTransitionPending, "An earlier update of the system helper has not ended; see the RUNBOOK if it does not end by itself.")
	}
	return nil
}

// applierAlive says whether the transient unit still runs: systemctl is-active prints anything but
// inactive, failed or unknown (activating, active, deactivating, reloading). A systemctl that cannot be
// asked counts as alive: better a busy than two appliers.
func (o *Ops) applierAlive(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	res, _, err := o.exec(ctx, binSystemctl, "is-active", upgradeUnit)
	if err != nil {
		return true
	}
	switch strings.TrimSpace(string(res.Stdout)) {
	case "inactive", "failed", "unknown":
		return false
	}
	return true
}

// currentPackage is Check 5: versions.json current = the binary's version = what dpkg-query says is
// installed (Debian form), and the kept .deb of it has the recorded hash.
func (o *Ops) currentPackage(ctx context.Context) (suPkg, error) {
	missing := func(why string) (suPkg, error) {
		return suPkg{}, refuse412(api.CodeCurrentPackageMissing, "The host cannot go back to the running version "+o.cfg.Version+" if the update fails ("+why+"), so it does not update. Run install.sh of the running release to put the package back.")
	}
	v, st := o.loadSUVersions()
	if st != jOK || v.Current.Version != o.cfg.Version {
		return missing("no record of the running package")
	}
	res, code, err := o.exec(ctx, binDpkgQuery, argsDpkgQueryHost...)
	if err != nil {
		return suPkg{}, err
	}
	if code != 0 || strings.TrimSpace(string(res.Stdout)) != debVersion(o.cfg.Version)+"|installed" {
		return missing("dpkg does not show it installed")
	}
	sha, size, err := o.keptFile(hostPkgName(o.cfg.Version, o.arch()))
	if err != nil || sha != v.Current.SHA256 || size != v.Current.Size {
		return missing("its kept package is gone or changed")
	}
	return v.Current, nil
}

func corePkgName(id string) string { return corePackagesDir + "/" + id + ".deb" }

// checkCorePackage is Check 6: core's file opened through the descriptor-checked handle of core_data
// (D-87): a regular file of core with one link and exactly the manifest's size.
func (o *Ops) checkCorePackage(id string, size int64) error {
	t, err := o.openCore()
	if err != nil {
		return err
	}
	defer t.close()
	f, n, err := t.openFile(corePkgName(id), size)
	if errors.Is(err, errNotFound) {
		return refuse412(api.CodePackageMissing, "Core has not written the package of the system helper the host was asked to install.")
	}
	if err != nil || n != size {
		if f != nil {
			_ = f.Close()
		}
		return refuse412(api.CodePackageInvalid, "The package core wrote is not a plain file of core of the size the release names.")
	}
	return f.Close()
}

// suDiskRoom is Check 7: twice the package size free where the state lives and where the binary goes.
func (o *Ops) suDiskRoom(size int64) error {
	for _, p := range []string{o.cfg.StateDir, o.path(usrLibVedette)} {
		free, err := o.freeNear(p)
		if err != nil {
			return err
		}
		if free < 2*uint64(size) { //nolint:gosec // size is 1..256 MiB (checked above)
			return refuse412(api.CodeLowDisk, "There is not enough free disk space to update the system helper.")
		}
	}
	return nil
}

// freeNear is the free space of the filesystem that holds p, or its nearest parent when p is not there
// (ENOENT, ENOTDIR only), through the FreeBytes seam.
func (o *Ops) freeNear(p string) (uint64, error) {
	for {
		free, err := o.d.FreeBytes(p)
		if err == nil {
			return free, nil
		}
		parent := filepath.Dir(p)
		if parent == p || (!errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR)) {
			return 0, err
		}
		p = parent
	}
}

// runSelfUpdate is Run (spec 6.14 Run 1-6).
func (o *Ops) runSelfUpdate(ctx context.Context, rc *server.RunContext, a api.HostSelfUpdateArgs) (any, error) {
	started := o.d.Now().UTC()
	p, err := o.checkSelfUpdate(ctx, a)
	if err != nil {
		return nil, err
	}
	if p.same {
		rc.Log("The system helper already runs " + p.to + "; nothing to do")
		return api.HostSelfUpdateResult{From: o.cfg.Version, To: p.to, Changed: false, SHA256: p.file.SHA256}, nil
	}
	o.clearStaged() // what a run cut short before parking may have left
	parked := false
	defer func() {
		if !parked {
			o.cleanSelfUpdate()
		}
	}()
	rc.Log("Copying the package of the system helper " + p.to)
	staged, err := o.stageHostPackage(ctx, a.Package, p.file)
	if err != nil {
		return nil, err
	}
	rc.Progress(20)
	if err := o.checkDebFields(ctx, staged, p.to); err != nil {
		return nil, err
	}
	if err := o.simulateHostInstall(ctx, rc, staged); err != nil {
		return nil, err
	}
	rc.Progress(60)
	applierSHA, err := o.copyApplier()
	if err != nil {
		o.log.ErrorContext(ctx, "could not copy the running binary for the applier", "error", err.Error())
		return nil, fail(api.CodeApplierFailed, "The host could not prepare the copy of itself that installs the update. Nothing was changed.")
	}
	bootID := o.bootID()
	if bootID == "" {
		return nil, fail(api.CodeApplierFailed, "The host could not read the boot id. Nothing was changed.")
	}
	j := suJournal{
		RunID: rc.RunID, RequestID: rc.RequestID,
		From: suRef{Version: p.from.Version, SHA256: p.from.SHA256}, To: suTo{Version: p.to, SHA256: p.file.SHA256, Size: p.file.Size},
		ApplierSHA256: applierSHA, Phase: phStaged, Attempt: 0, BootID: bootID,
		StartedAt: started, Deadline: started.Add(suRunWindow), Log: []string{},
	}
	if err := j.validate(); err != nil {
		o.log.ErrorContext(ctx, "the self-update journal would not be valid", "error", err.Error())
		return nil, fail(api.CodeApplierFailed, "The host could not record the update. Nothing was changed.")
	}
	if err := o.saveSU(suJournalName, j); err != nil {
		o.log.ErrorContext(ctx, "could not write the self-update journal", "error", err.Error())
		return nil, fail(api.CodeApplierFailed, "The host could not record the update. Nothing was changed.")
	}
	o.note(api.CmdHostSelfUpdate, "self_update_staged", map[string]any{"from": j.From.Version, "to": j.To.Version, "sha256": j.To.SHA256})
	// A run that does not park after all (an invalid Parked, or SIGTERM in the window before parking) ends
	// failed: nothing was dispatched, so the staged journal of this very run is cleaned at once. A journal a
	// crash left (AfterFinish does not survive a restart) is for the orphan-journal step at Start (slice 2b).
	runID := rc.RunID
	rc.AfterFinish(func(context.Context, api.Status) { o.dropStagedJournal(runID) })
	rc.OnParked(func() { o.startSettle(runID) }) // its first round dispatches the applier: park first, dispatch after
	parked = true
	rc.Log("Staged; the update goes on outside the host process")
	return server.Parked{Deadline: j.Deadline, Result: api.HostSelfUpdateResult{From: j.From.Version, To: j.To.Version, Changed: true, SHA256: j.To.SHA256}}, nil
}

// stageHostPackage is Run 2: core's file, opened through the checked handle, copied byte for byte (exactly
// the manifest's size, stopping there) into staged/ while it is hashed in the same pass; renamed to
// staged/<sha256>.deb only when the hash is the manifest's. apt and dpkg only ever see this copy (INV-26).
func (o *Ops) stageHostPackage(ctx context.Context, id string, f release.HostFile) (string, error) {
	t, err := o.openCore()
	if err != nil {
		return "", err
	}
	defer t.close()
	src, n, err := t.openFile(corePkgName(id), f.Size)
	if errors.Is(err, errNotFound) {
		return "", fail(api.CodePackageMissing, "Core's package file is gone. Nothing was changed.")
	}
	if err != nil || n != f.Size {
		if src != nil {
			_ = src.Close()
		}
		return "", fail(api.CodePackageInvalid, "Core's package file is not a plain file of the size the release names. Nothing was changed.")
	}
	defer func() { _ = src.Close() }()
	return o.writeStaged(ctx, src, f)
}

// writeStaged is the second half of stageHostPackage, in a function of its own because it works by path in the
// host's own state and must not hold core's tree (INV-14): src is the descriptor of core's file.
func (o *Ops) writeStaged(ctx context.Context, src io.Reader, f release.HostFile) (string, error) {
	tmp, err := os.CreateTemp(stagedDir(o.cfg.StateDir), ".tmp-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	kept := false
	defer func() {
		if !kept {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	h := sha256.New()
	copied, err := io.Copy(io.MultiWriter(tmp, h), ctxReader{ctx: ctx, r: io.LimitReader(src, f.Size)})
	if err != nil {
		return "", err
	}
	if copied != f.Size {
		return "", fail(api.CodePackageInvalid, "Core's package file is shorter than the release says. Nothing was changed.")
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if sum != f.SHA256 {
		return "", fail(api.CodeChecksumMismatch, "The package's SHA-256 is not the one the signed release names. Nothing was changed.")
	}
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	dst := stagedPath(o.cfg.StateDir, sum)
	if err := os.Rename(tmpName, dst); err != nil {
		return "", err
	}
	kept = true
	syncDir(stagedDir(o.cfg.StateDir))
	return dst, nil
}

// checkDebFields is Run 3 (and the check of adoption): dpkg-deb --field of the staged copy (or of a kept file) names vedette-host, the Debian form of the
// version and this architecture.
func (o *Ops) checkDebFields(ctx context.Context, staged, version string) error {
	res, code, err := o.exec(ctx, binDpkgDeb, dpkgDebFieldArgv(staged)...)
	if err != nil {
		return err
	}
	want := "Package: " + hostPkg + "\nVersion: " + debVersion(version) + "\nArchitecture: " + o.arch()
	if code != 0 || strings.TrimRight(string(res.Stdout), "\n") != want {
		return fail(api.CodePackageMismatch, "The package is not vedette-host "+version+" for "+o.arch()+"; the release is wrong. Nothing was changed.")
	}
	return nil
}

// simulateHostInstall is Run 3b: refresh apt's lists when the last os.check is older than 24 hours (or
// missing), then simulate the install of the staged file. apt must be able to install it without removing
// anything and without upgrading any other installed package (a new dependency may be added).
func (o *Ops) simulateHostInstall(ctx context.Context, rc *server.RunContext, staged string) error {
	snap, serr := o.loadSnapshot()
	if now := o.d.Now(); serr != nil || now.Sub(snap.LastCheck) >= snapshotMaxAge || snap.LastCheck.After(now.Add(time.Hour)) {
		rc.Log("Refreshing the package lists")
		uctx, cancel := context.WithTimeout(ctx, suAptUpdateLimit)
		_, code, err := o.exec(uctx, binAptGet, argsUpdate...)
		cancel()
		if err != nil || code != 0 {
			rc.Log("The package lists could not be refreshed; the simulation uses the lists the box has")
		}
	}
	res, code, err := o.exec(ctx, binAptGet, aptSimInstallArgv(staged)...)
	if err != nil {
		return err
	}
	added, ok := SelfUpdateSim(res.Stdout)
	if code != 0 || !ok {
		return fail(api.CodeDependenciesUnavailable, "apt cannot install the new system helper without removing or upgrading other packages, or a dependency is missing from the mirror. Install the pending OS updates, then try again. Nothing was changed.")
	}
	if err := o.recordAddedPackages(added); err != nil {
		o.log.ErrorContext(ctx, "could not record the packages the self-update adds", "error", err.Error())
		return fail(api.CodeApplierFailed, "The host could not record the packages the update adds. Nothing was changed.")
	}
	return nil
}

// SelfUpdateSim reads the simulated install of the host package (apt-get -s ... install <file>): ok when it
// installs vedette-host, removes or purges nothing, and upgrades no other installed package (an "Inst" line
// with "[old version]" for another name); new dependencies (no brackets) are allowed and returned in added,
// in apt's order. A new package whose name is not a Debian package name, or a line over 4 KiB, ends the
// reading as a refusal. It never panics (fuzzed).
func SelfUpdateSim(out []byte) (added []string, ok bool) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 4096), maxSimLine)
	sawHost := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Remv ") || strings.HasPrefix(line, "Purg ") {
			return nil, false
		}
		rest, found := strings.CutPrefix(line, "Inst ")
		if !found {
			continue
		}
		name, after, _ := strings.Cut(rest, " ")
		if isHostPkg(name) {
			sawHost = true
			continue
		}
		if strings.HasPrefix(after, "[") || !pkgNameRE.MatchString(name) {
			return nil, false
		}
		added = append(added, name)
	}
	if sc.Err() != nil || !sawHost {
		return nil, false
	}
	return added, true
}

// recordAddedPackages is Run 3c (D-316 (9)): the packages the simulation says apt will newly install for the
// new host (a Depends it added), merged into selfupdate/installed-by-us BEFORE anything is installed, like
// install.sh's record_new_packages. install.sh --uninstall reads this file next to its own
// /var/lib/vedette-install/installed-by-us and purges a name only when apt's autoremove then finds it unneeded
// and it is not marked manual. One name per line, sorted, no duplicate; a name stays after a rollback (apt
// keeps the dependency installed) and after a run that ends before the install (uninstall checks that the
// package is installed). Nothing new → no write. A file that does not read (a link, too large) stops the run
// before any change: never install what --uninstall would not know.
func (o *Ops) recordAddedPackages(added []string) error {
	if len(added) == 0 {
		return nil
	}
	b, st := o.readSU(suAddedName)
	if st != jOK && st != jAbsent {
		return fmt.Errorf("ops: %s does not read", suAddedName)
	}
	names := slices.Clone(added)
	for l := range strings.Lines(string(b)) {
		if n := strings.TrimSuffix(l, "\n"); pkgNameRE.MatchString(n) {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	out := strings.Join(names, "\n") + "\n"
	if bytes.Equal([]byte(out), b) {
		return nil
	}
	if len(out) > maxSUFile {
		return fmt.Errorf("ops: %s would be over %d bytes", suAddedName, maxSUFile)
	}
	return writeFileAtomic(filepath.Join(suDir(o.cfg.StateDir), suAddedName), []byte(out), 0o600)
}

// copyApplier is Run 4: the running binary (/proc/self/exe; Deps.SelfExe in tests) copied to
// selfupdate/applier through a new temp file (O_EXCL, 0700), hashed in the same pass, fsynced and renamed.
// The transient unit runs this copy, never /usr/lib/vedette/vedette-host, which dpkg replaces at unpack.
func (o *Ops) copyApplier() (string, error) {
	src, err := os.Open(o.d.SelfExe)
	if err != nil {
		return "", err
	}
	defer func() { _ = src.Close() }()
	suffix, err := randomHex(8)
	if err != nil {
		return "", err
	}
	tmpName := filepath.Join(suDir(o.cfg.StateDir), ".tmp-applier-"+suffix)
	tmp, err := os.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o700) //nolint:gosec // a fresh name in the host's own state
	if err != nil {
		return "", err
	}
	kept := false
	defer func() {
		if !kept {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(src, maxHostPackage+1))
	switch {
	case err != nil:
		return "", err
	case n == 0 || n > maxHostPackage:
		return "", errors.New("the running binary is empty or too large")
	}
	if err := tmp.Chmod(0o700); err != nil {
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, applierPath(o.cfg.StateDir)); err != nil {
		return "", err
	}
	kept = true
	syncDir(suDir(o.cfg.StateDir))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// clearStaged removes every file of staged/ (only regular files and leftover temp files; nothing else is there).
func (o *Ops) clearStaged() {
	es, err := os.ReadDir(stagedDir(o.cfg.StateDir))
	if err != nil {
		return
	}
	for _, e := range es {
		if e.Type().IsRegular() {
			_ = removeIfThere(filepath.Join(stagedDir(o.cfg.StateDir), e.Name()))
		}
	}
}

// cleanSelfUpdate removes what a self-update that changed nothing leaves: staged/, the applier and the journal.
func (o *Ops) cleanSelfUpdate() {
	o.clearStaged()
	for _, p := range []string{applierPath(o.cfg.StateDir), filepath.Join(suDir(o.cfg.StateDir), suJournalName)} {
		if err := removeIfThere(p); err != nil {
			o.log.Warn("could not remove a file of a self-update", "file", filepath.Base(p))
		}
	}
	syncDir(suDir(o.cfg.StateDir))
}

// dropStagedJournal cleans up after runID when its journal is still staged (attempt 0): the run ended
// without parking, so no applier was ever started and nothing changed.
func (o *Ops) dropStagedJournal(runID string) {
	j, st := o.loadSUJournal()
	if st != jOK || j.RunID != runID || j.Attempt != 0 {
		return
	}
	o.cleanSelfUpdate()
	o.note(api.CmdHostSelfUpdate, "self_update_abandoned", map[string]any{"run_id": runID, "phase": j.Phase})
}
