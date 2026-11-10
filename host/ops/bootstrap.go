package ops

import (
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
// Order: everything is verified and every refusal is decided before the first write; the images are then
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
)

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
}

type bsStep struct {
	plan    *pullPlan
	want    []byte
	replace bool   // a unit is there and is replaced (forced)
	write   bool   // the unit file is to be written
	versOK  bool   // versions already say current = this digest
	reason  string // why a unit is replaced, for the line printed
}

// Bootstrap is the whole first install (see above). logf receives one line per step.
func (o *Ops) Bootstrap(ctx context.Context, a BootstrapArgs, logf func(string)) error {
	if logf == nil {
		logf = func(string) {}
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
	if _, _, err := o.unitDirChain(); err != nil {
		return bsErr(api.CodeUnitUnsafe, "the Quadlet directory is not safe to write as root")
	}
	if err := o.bootstrapSpace(ctx, steps); err != nil {
		return err
	}
	if err := o.ensureCoreData(logf); err != nil {
		return err
	}

	// 2. Pull every image (nothing that is already pulled and tagged is touched).
	for _, s := range steps {
		if o.pulledAndTagged(ctx, s.plan) {
			logf("image of " + s.plan.service + " is already on this machine")
			continue
		}
		if err := o.pullAndRecord(ctx, logf, s.plan); err != nil {
			return err
		}
	}

	// 3. Only now the units and the versions.
	for _, s := range steps {
		svc := s.plan.service
		if s.write {
			if s.replace {
				logf(fmt.Sprintf("replacing %s (%s); the old bytes are kept as containers/units/%s", unitFileName(svc), s.reason, o.prevName(svc)))
			}
			if err := o.writeUnit(svc, s.want, true); err != nil {
				if errors.Is(err, errUnitUnsafe) {
					return bsErr(api.CodeUnitUnsafe, "the Quadlet directory or the unit of "+svc+" is not safe to write as root")
				}
				return bsErr(api.CodeUnitUnwritable, "the unit of "+svc+" could not be written")
			}
			logf("wrote " + unitFileName(svc))
		}
		if !s.versOK {
			rec, ok := o.loadPulled(svc)
			if !ok || rec.Digest != s.plan.digest {
				return bsErr(BootstrapFailed, "the record of the pulled version of "+svc+" is missing")
			}
			if err := o.saveVersions(versionState{Service: svc, Current: &versionRecord{pulledRecord: rec}}); err != nil {
				return bsErr(BootstrapFailed, "the version of "+svc+" could not be recorded")
			}
			logf("recorded " + svc + " " + rec.Version + " as the running version")
		}
	}
	if !slices.ContainsFunc(steps, func(s *bsStep) bool { return s.write || !s.versOK }) {
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
	want, err := o.renderFor(svc, plan.digest)
	if err != nil {
		return nil, err // host_conf_incomplete or unit_unknown
	}
	if _, st, _ := o.loadJournal(svc); st != jAbsent {
		return nil, refuse412(api.CodeTransitionPending, "An earlier change of the unit of "+svc+" was never settled; this is not a first install.")
	}
	s := &bsStep{plan: plan, want: want, write: true}
	vs := o.loadVersions(svc)
	if vs.Current != nil {
		if vs.Current.Digest != plan.digest {
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
	case perr == nil && digest == plan.digest:
		s.write = false // the unit is ours and pins this image: left as it is (it may have lost [Install] by a stop with persist)
	case !force && perr == nil:
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
	if !ok || rec.Digest != p.digest || rec.Version != p.version {
		return false
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
	if st, err := os.Lstat(dir); err == nil {
		if !st.IsDir() {
			return bsErr(api.CodeCoreDataInvalid, "core_data is not a directory")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return bsErr(BootstrapFailed, "core_data could not be looked at")
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil { //nolint:gosec // parents are root's, world-readable like /var/lib
		return bsErr(BootstrapFailed, "the parent of core_data could not be made")
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return bsErr(BootstrapFailed, "core_data could not be made")
	}
	f, err := openDirNoFollow(dir)
	if err != nil {
		return bsErr(BootstrapFailed, "core_data could not be opened")
	}
	defer func() { _ = f.Close() }()
	if err := f.Chown(o.cfg.CoreUID, o.cfg.CoreGID); err != nil || f.Chmod(0o700) != nil {
		return bsErr(BootstrapFailed, "core_data could not be given to core")
	}
	logf("made core_data (0700, owned by core)")
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
