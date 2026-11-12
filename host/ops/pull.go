package ops

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/internal/release"
)

// container.pull (spec 6.7, D-103, D-104, D-130). The host verifies everything itself, before any
// byte is pulled, with internal/release: the index against the stored one (sequence never goes
// back; a newer index is stored and is the only source of revocation), the manifest, the platform
// and the install mode, and the cosign signature of the image. Only then does it run
//
//	podman pull -q ghcr.io/knt048/vedette-<service>@sha256:<64 hex>
//
// where the registry is a compile-time constant and the digest is the manifest's, never a string of
// the request. Podman's answer is not believed either: podman image inspect must show that digest
// before the image is tagged localhost/vedette-<service>:<version>, the tag is looked at again, and
// only then is the pulled version recorded. A failure leaves no record. A half-pulled image is
// not removed (no rmi): a pull by digest creates the image only when its content matched the digest,
// so what may be left is verified content that a retry finds at once (idempotency), and an image
// that a running container uses must never be removed by a failed pull; the retention that follows
// a successful start or rollback (retain.go, slice 3-8a) removes images that nothing keeps.
//
// The refusals are all decided in Check, so core gets them as 412 at once and no run starts. Check
// also stores a newer verified index even when the manifest is then refused: a revocation must not be
// lost because the same index is the reason for the refusal (D-130).

const (
	// maxPullDoc caps each of the two documents once decoded (spec 6.7); a minisign signature file is at
	// most release.MaxSigBytes.
	maxPullDoc = release.MaxDocBytes
	maxPullSig = release.MaxSigBytes
	// pullBody is the request body limit of container.pull: two documents and two signatures as base64
	// come to about 700 KiB (spec 6.7).
	pullBody = 1 << 20
	// pullTimeout is the command's timeout (spec 6.7); the pull itself gets a little less so the checks
	// after it still have time.
	// 45 minutes: the pull (up to pullCallLimit) and, for scan, the build on the box (buildLimit) and its check (D-147).
	pullTimeout   = 45 * time.Minute
	pullCallLimit = 25 * time.Minute
	// storageProbe is where Podman keeps images (its default graph root): the free space of the filesystem
	// that holds it is what low_disk looks at. The appliance installs the default storage.conf (installer,
	// WP-08); a moved graph root would be measured wrongly (deferred: ask podman info in a later slice).
	storageProbe = "var/lib/containers"
	// lowDiskFactor: twice the image size (spec 6.7: layers are stored compressed and then unpacked).
	lowDiskFactor = 2
)

// verified is what both documents of a pull proved.
var pullVerified = []string{"minisign", "cosign"}

func (o *Ops) cmdContainerPull() server.Command {
	return server.Define(server.Spec[api.ContainerPullArgs]{
		Name: api.CmdContainerPull, Write: true, Timeout: pullTimeout, MaxBody: pullBody,
		Validate: validatePullArgs,
		Check:    o.checkContainerPull,
		Run:      o.runContainerPull,
	})
}

// decodeDoc decodes standard padded base64 without line breaks to between 1 and limit bytes.
func decodeDoc(s string, limit int) ([]byte, error) {
	if s == "" || len(s) > base64.StdEncoding.EncodedLen(limit) || strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("not base64 within the limit")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) == 0 || len(b) > limit {
		return nil, errors.New("not base64 within the limit")
	}
	return b, nil
}

func validatePullArgs(a *api.ContainerPullArgs) error {
	if err := serviceArg(a.Service); err != nil {
		return err
	}
	if _, err := release.CompareVersions(a.Version, a.Version); err != nil || !tagVersionRE.MatchString(a.Version) {
		return server.Invalid("version", "must be a release version such as 1.4.0")
	}
	switch a.Source {
	case api.PullSourceBundle:
		if !hexIDRE.MatchString(a.BundleID) {
			return server.Invalid("bundle_id", "must be 32 lowercase hex characters")
		}
		return nil // refused by Check: bundle_unsupported
	case api.PullSourceRegistry:
	default:
		return server.Invalid("source", "must be registry or bundle")
	}
	if a.BundleID != "" {
		return server.Invalid("bundle_id", "only a bundle source takes a bundle id")
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
	return nil
}

// pullPlan is what verification settled: the digest to pull and what to record.
type pullPlan struct {
	service string
	version string
	digest  string
	ref     string
	size    int64
	// pin is, for scan only, the "digest" of the image built on the box ("sha256:" + its ID), set by pullAndRecord once the build passed:
	// digest is the base image's, which the manifest signed, and pin is what the unit pins and the records hold (D-147).
	pin         string
	keyID       string
	idx         *release.Index
	manifest    []byte
	manifestSig []byte
}

// unitDigest is the "digest" the unit pins for the plan's image: the verified digest, or for scan the ID of the image built from it.
func (p *pullPlan) unitDigest() string {
	if p.pin != "" {
		return p.pin
	}
	return p.digest
}

// trust returns the keys this build verifies with: the embedded ones, or a test's.
func (o *Ops) trust() (release.Trust, error) {
	if o.d.Keys != nil {
		return o.d.Keys()
	}
	return release.Embedded()
}

func (o *Ops) arch() string {
	if o.d.Arch != "" {
		return o.d.Arch
	}
	return runtime.GOARCH
}

// refusePull maps an error of internal/release to the refusal of spec 6.7. what names the document
// for the messages that say "which one". The text of err never reaches the answer: it may hold a
// clipped piece of what the caller sent.
func refusePull(err error, what string) error {
	switch {
	case errors.Is(err, release.ErrNoTrustKeys):
		return refuse412(api.CodeNoTrustedKeys, "This build of the host has no release keys embedded, so it cannot verify anything and refuses every pull.")
	case errors.Is(err, release.ErrKeyRevoked):
		return refuse412(api.CodeKeyRevoked, "The key that signed the "+what+" is revoked.")
	case errors.Is(err, release.ErrReleaseRevoked):
		return refuse412(api.CodeReleaseRevoked, "This release or one of its images is revoked.")
	case errors.Is(err, release.ErrSequenceRegress):
		return refuse412(api.CodeSequenceRegress, "The index is older than the one the host already accepted.")
	case errors.Is(err, release.ErrRegistryNotAllowed):
		return refuse412(api.CodeRegistryNotAllowed, "An image in the manifest does not come from the fixed registry.")
	case errors.Is(err, release.ErrDigestNotInManifest):
		return refuse412(api.CodeDigestNotInManifest, "The manifest has no image for that service.")
	case errors.Is(err, release.ErrPlatform):
		return refuse412(api.CodePlatformMismatch, "The release has no image for this machine's platform.")
	case errors.Is(err, release.ErrInstallMode):
		return refuse412(api.CodeNotAppliance, "This release is not built for the appliance install mode.")
	case errors.Is(err, release.ErrManifestHash):
		return refuse412(api.CodeManifestMismatch, "The manifest is not the one the index names for its version.")
	case errors.Is(err, release.ErrUnknownSchema):
		return refuse412(api.CodeSignatureInvalid, "The "+what+" has a schema this host does not know; update the box through a bundle or reinstall.")
	}
	return refuse412(api.CodeSignatureInvalid, "The "+what+" does not verify.")
}

// releaseDocs is what verifyRelease proved: the keys it trusted, the accepted index and the manifest.
type releaseDocs struct {
	trust          release.Trust
	idx            *release.Index
	man            *release.Manifest
	manRaw, manSig []byte
}

// verifyRelease is the part of spec 6.7 that container.pull, -bootstrap and host.self_update share (D-316
// (1)): the index against the stored one (stored atomically as soon as it is accepted, and audited under
// command), the manifest, its version, its hash in every channel that names it as latest, and the appliance
// install mode. It returns a *server.Refusal for each refusal and a plain error for what the host itself
// could not do (a state file it could not write).
func (o *Ops) verifyRelease(command, version, index, indexSig, manifest, manifestSig string) (*releaseDocs, error) {
	idxRaw, e1 := decodeDoc(index, maxPullDoc)
	idxSig, e2 := decodeDoc(indexSig, maxPullSig)
	manRaw, e3 := decodeDoc(manifest, maxPullDoc)
	manSig, e4 := decodeDoc(manifestSig, maxPullSig)
	if err := errors.Join(e1, e2, e3, e4); err != nil {
		return nil, refuse412(api.CodeSignatureInvalid, "A document or signature is not valid base64.")
	}
	trust, err := o.trust()
	if err != nil {
		return nil, refusePull(err, "index")
	}
	stored, err := o.loadStoredIndex(trust)
	if err != nil {
		return nil, err
	}
	idx, err := release.VerifyIndex(idxRaw, idxSig, trust, stored)
	if err != nil {
		return nil, refusePull(err, "index")
	}
	if stored == nil || idx.RawSHA256 != stored.RawSHA256 || idx.KeyID != stored.KeyID {
		if err := o.saveIndex(idxRaw, idxSig, idx); err != nil {
			return nil, fmt.Errorf("ops: could not store the index: %w", err)
		}
		o.noteIndexStored(command, trust, stored, idx)
	}
	man, err := release.VerifyManifest(manRaw, manSig, trust, idx)
	if err != nil {
		return nil, refusePull(err, "manifest")
	}
	if man.Version != version {
		return nil, refuse412(api.CodeManifestMismatch, "The manifest is for another version than the one asked for.")
	}
	// Every channel that names this version as its latest names this manifest's hash (§5.3 step 4). A
	// manifest that is no channel's latest has no hash to compare: a superseded manifest is stopped by
	// revoking its image digest (kind image_digest), not by the hash.
	for name, c := range idx.Channels {
		if c.Latest != man.Version {
			continue
		}
		if err := release.CheckManifestSHA256(idx, name, manRaw); err != nil {
			return nil, refusePull(err, "manifest")
		}
	}
	if err := man.CheckInstallMode("appliance"); err != nil {
		return nil, refusePull(err, "manifest")
	}
	return &releaseDocs{trust: trust, idx: idx, man: man, manRaw: manRaw, manSig: manSig}, nil
}

// verifyPull is every check of spec 6.7 that comes before a pull: verifyRelease, then the platform, the
// image of the service and its cosign signature. It returns a *server.Refusal for each refusal and a plain
// error for what the host itself could not do (a state file it could not write).
func (o *Ops) verifyPull(a api.ContainerPullArgs) (*pullPlan, error) {
	docs, err := o.verifyRelease(api.CmdContainerPull, a.Version, a.Index, a.IndexSig, a.Manifest, a.ManifestSig)
	if err != nil {
		return nil, err
	}
	trust, idx, man, manRaw, manSig := docs.trust, docs.idx, docs.man, docs.manRaw, docs.manSig
	if err := man.CheckPlatform(a.Service, "linux/"+o.arch()); err != nil {
		return nil, refusePull(err, "manifest")
	}
	im, ok := man.Image(a.Service)
	if !ok {
		return nil, refusePull(release.ErrDigestNotInManifest, "manifest")
	}
	if err := release.VerifyImage(man, a.Service, im.Digest, trust); err != nil {
		return nil, refusePull(err, "image signature")
	}
	ref, err := pullRef(a.Service, im.Digest)
	if err != nil {
		return nil, refuse412(api.CodeSignatureInvalid, "The manifest holds an image digest that is not well formed.")
	}
	return &pullPlan{
		service: a.Service, version: man.Version, digest: im.Digest, ref: ref, size: im.Size, keyID: man.KeyID,
		idx: idx, manifest: manRaw, manifestSig: manSig,
	}, nil
}

// noteIndexStored leaves the trail of a change of what the host knows about releases: a warning in
// the log and an audit line with the old and new sequence, the signer, whether the backup key signed
// it, and the revocations added and dropped (at most 16 of each are named). Check calls this, so it
// happens even when the pull is then refused (D-130).
func (o *Ops) noteIndexStored(command string, trust release.Trust, old, idx *release.Index) {
	var oldSeq uint64
	var before []release.Revocation
	if old != nil {
		oldSeq, before = old.Sequence, old.Revoked
	}
	added, dropped := revocationDiff(before, idx.Revoked)
	detail := map[string]any{
		"old_sequence": oldSeq, "new_sequence": idx.Sequence, "signer": idx.KeyID, "backup_signed": idx.KeyID == trust.Backup.KeyID(),
		"revoked_added": clipNames(added), "revoked_dropped": clipNames(dropped), "revoked_added_count": len(added), "revoked_dropped_count": len(dropped),
	}
	o.log.Warn("release index stored", "old_sequence", oldSeq, "new_sequence", idx.Sequence, "signer", idx.KeyID,
		"backup_signed", detail["backup_signed"], "revoked_added", len(added), "revoked_dropped", len(dropped))
	o.note(command, "release_index_stored", detail)
}

// revocationDiff names ("kind:id") what after has and before lacks, and the reverse.
func revocationDiff(before, after []release.Revocation) (added, dropped []string) {
	key := func(r release.Revocation) string { return r.Kind + ":" + r.ID }
	had, has := map[string]bool{}, map[string]bool{}
	for _, r := range before {
		had[key(r)] = true
	}
	for _, r := range after {
		has[key(r)] = true
		if !had[key(r)] {
			added = append(added, key(r))
		}
	}
	for _, r := range before {
		if !has[key(r)] {
			dropped = append(dropped, key(r))
		}
	}
	slices.Sort(added)
	slices.Sort(dropped)
	return added, dropped
}

func clipNames(l []string) []string {
	if len(l) > 16 {
		l = l[:16]
	}
	return append([]string{}, l...)
}

// freeForImages is the free space of the filesystem that holds Podman's storage: storageProbe, or
// its nearest parent when a path is not there (ENOENT, ENOTDIR only: any other error is a failure to
// measure, not a reason to measure something else), through the FreeBytes seam.
func (o *Ops) freeForImages() (uint64, error) {
	p := o.path(storageProbe)
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

func (o *Ops) checkContainerPull(ctx context.Context, a api.ContainerPullArgs) error {
	if _, err := o.platform(); err != nil {
		return err
	}
	if a.Source == api.PullSourceBundle {
		return refuse412(api.CodeBundleUnsupported, "Pulling from a bundle is not available yet; use the registry source.")
	}
	plan, err := o.verifyPull(a)
	if err != nil {
		return err
	}
	if o.imageIs(ctx, plan.ref, plan.service, plan.digest) {
		return nil // already here: it needs no space (the run finds it again and pulls nothing)
	}
	free, err := o.freeForImages()
	if err != nil {
		return refuse412(api.CodeLowDisk, "The host could not measure the free space where images are stored.")
	}
	if need := uint64(max(plan.size, 0)) * lowDiskFactor; free < need {
		return refuse412(api.CodeLowDisk, fmt.Sprintf("Not enough free space for the image: %d MiB free, %d MiB needed (twice its size).", free>>20, need>>20))
	}
	return nil
}

// ---- podman image inspect -----------------------------------------------------------------------

type imageDoc struct {
	ID           string   `json:"Id"`
	Digest       string   `json:"Digest"`
	RepoDigests  []string `json:"RepoDigests"`
	Architecture string   `json:"Architecture"`
	Os           string   `json:"Os"`
}

var (
	errImage  = errors.New("ops: podman image inspect output is not usable")
	imageIDRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const maxRepoDigests = 256

// ParseImageInspect reads the output of "podman image inspect --format json <ref>" and reports
// whether it describes exactly one image whose manifest digest is digest, for service, on this arch:
// a JSON array of one object (nothing after it, 1 MiB at most) with a 64-hex Id, and either Digest
// equal to digest or RepoDigests holding the pull reference. A Digest of another value, an Os or
// Architecture that is given and differs, or any other shape is an error. Exported for fuzzing.
func ParseImageInspect(out []byte, service, digest, arch string) error {
	return parseImageInspect(out, service, digest, arch)
}

func parseImageInspect(out []byte, service, digest, arch string) error {
	ref, err := pullRef(service, digest)
	if err != nil {
		return errImage
	}
	if len(out) == 0 || len(out) > maxInspectOutput {
		return errImage
	}
	var docs []imageDoc
	dec := json.NewDecoder(bytes.NewReader(out))
	if err := dec.Decode(&docs); err != nil {
		return errImage
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errImage
	}
	if len(docs) != 1 {
		return errImage
	}
	d := docs[0]
	if !imageIDRE.MatchString(d.ID) || len(d.RepoDigests) > maxRepoDigests {
		return errImage
	}
	if (d.Os != "" && d.Os != "linux") || (d.Architecture != "" && d.Architecture != arch) {
		return errImage
	}
	if d.Digest != digest && !slices.Contains(d.RepoDigests, ref) {
		return errImage
	}
	return nil
}

// imageIs asks podman about ref (the pull reference or the local tag) and checks the answer.
func (o *Ops) imageIs(ctx context.Context, ref, service, digest string) bool {
	args, err := inspectImageArgv(ref)
	if err != nil {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, probeLimit)
	defer cancel()
	res, code, err := o.exec(cctx, binPodman, args...)
	if err != nil || code != 0 || res.Truncated {
		return false
	}
	if service == api.ServiceScan && imageIDRE.MatchString(ref) {
		return parseBuiltInspect(res.Stdout, digest, o.arch()) == nil
	}
	return parseImageInspect(res.Stdout, service, digest, o.arch()) == nil
}

// parseBuiltInspect is parseImageInspect for the image built on the box: it has no registry digest, so the answer must be exactly one
// image whose ID is the one the unit pins (digest is "sha256:" + the ID).
func parseBuiltInspect(out []byte, digest, arch string) error {
	if len(out) == 0 || len(out) > maxInspectOutput {
		return errImage
	}
	var docs []imageDoc
	dec := json.NewDecoder(bytes.NewReader(out))
	if err := dec.Decode(&docs); err != nil {
		return errImage
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) || len(docs) != 1 {
		return errImage
	}
	d := docs[0]
	if !imageIDRE.MatchString(d.ID) || "sha256:"+d.ID != digest || (d.Os != "" && d.Os != "linux") || (d.Architecture != "" && d.Architecture != arch) {
		return errImage
	}
	return nil
}

// ---- the run --------------------------------------------------------------------------------------

func (o *Ops) runContainerPull(ctx context.Context, rc *server.RunContext, a api.ContainerPullArgs) (any, error) {
	plan, err := o.verifyPull(a)
	if err != nil {
		var ref *server.Refusal
		if errors.As(err, &ref) {
			return nil, err
		}
		return nil, fail(api.CodePullFailed, "The host could not store the release index.")
	}
	expired := plan.idx.Expired(o.d.Now())
	if expired {
		rcLog(rc, "the index is past its expiry; going on, an old index only warns (D-104)")
		o.note(api.CmdContainerPull, "index_expired", map[string]any{"sequence": plan.idx.Sequence, "expires_at": plan.idx.ExpiresAt.UTC().Format(time.RFC3339)})
	}
	rcLog(rc, fmt.Sprintf("verified: index sequence %d, manifest %s signed by %s, cosign signature of %s", plan.idx.Sequence, plan.version, plan.keyID, plan.service))
	res := api.ContainerPullResult{Digest: plan.digest, Size: plan.size, Verified: slices.Clone(pullVerified), IndexExpired: expired}

	if err := o.pullAndRecord(ctx, func(s string) { rcLog(rc, s) }, plan); err != nil {
		return nil, err
	}
	return res, nil
}

// pullAndRecord is what a verified plan does: pull by digest unless the image is here, tag it, look at
// both, and only then record the version. container.pull and the bootstrap (D-142) both end here, so
// there is one implementation of the podman side. The error is a *server.Failure.
func (o *Ops) pullAndRecord(ctx context.Context, logf func(string), plan *pullPlan) error {
	if o.imageIs(ctx, plan.ref, plan.service, plan.digest) {
		logf("the image is already on this machine; nothing to pull")
	} else {
		argv, err := pullArgv(plan.service, plan.digest)
		if err != nil {
			return fail(api.CodePullFailed, "The host could not build the pull command.")
		}
		logf("pulling " + plan.ref)
		pctx, cancel := context.WithTimeout(ctx, pullCallLimit)
		pres, code, perr := o.exec(pctx, binPodman, argv...)
		cancel()
		if perr != nil || code != 0 || pres.Truncated {
			logf("podman pull failed; no tag and no record were made")
			return fail(api.CodePullFailed, "Podman could not pull the image.")
		}
		if !o.imageIs(ctx, plan.ref, plan.service, plan.digest) {
			return fail(api.CodeEffectNotVerified, "After the pull, podman did not show the verified digest for the image.")
		}
	}

	targv, err := tagArgv(plan.service, plan.digest, plan.version)
	if err != nil {
		return fail(api.CodePullFailed, "The host could not build the tag command.")
	}
	tag, _ := localTag(plan.service, plan.version)
	logf("tagging " + tag)
	tctx, cancel := context.WithTimeout(ctx, probeLimit)
	_, code, terr := o.exec(tctx, binPodman, targv...)
	cancel()
	if terr != nil || code != 0 {
		return fail(api.CodePullFailed, "Podman could not tag the image.")
	}
	if !o.imageIs(ctx, tag, plan.service, plan.digest) {
		return fail(api.CodeEffectNotVerified, "After the tag, podman did not show the verified digest under the local name.")
	}

	rec := pulledRecord{
		Service: plan.service, Version: plan.version, Digest: plan.digest, KeyID: plan.keyID, Size: plan.size,
		PulledAt: o.d.Now().UTC(), Manifest: base64.StdEncoding.EncodeToString(plan.manifest), ManifestSig: base64.StdEncoding.EncodeToString(plan.manifestSig),
	}
	if plan.service == api.ServiceScan {
		// D-147: the base is pulled, verified and tagged; the image the unit runs is the one built from it on this machine.
		built, err := o.buildScan(ctx, logf, plan)
		if err != nil {
			return err
		}
		plan.pin = built.digest
		rec.Digest, rec.BaseDigest, rec.NmapVersion = built.digest, plan.digest, built.nmap
	}
	if err := o.savePulled(rec); err != nil {
		return fail(api.CodePullFailed, "The image was pulled and tagged but the host could not record the version.")
	}
	logf("recorded " + plan.service + " " + plan.version)
	return nil
}
