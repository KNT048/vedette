package ops

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/internal/release"
)

// container.pull with source=bundle (spec 6.7, update-manifest.md §11, D-452): the offline path of a box with no registry.
//
// Core streams the uploaded bundle to <core_data>/bundles/<bundle_id>.tar (bundle_id: 32 random hex chosen by core, like a snapshot
// id) and names only that id. The host opens the file through core's tree (INV-14: os.Root, the descriptor must be a regular file of
// core with one link, at most 8 GiB, never a link) and treats every byte of it as untrusted:
//
//   - The tar is read for its headers (members are skipped by seeking): a closed list of names, regular files and the two folders
//     only (no link, device, FIFO or sparse entry), no duplicate, at most 64 members, each under its own cap. Nothing is ever
//     extracted by its name: the four signed documents are read into memory, the image archive of the asked service is streamed
//     into a directory the host makes, and everything else (bundle.json, sbom.json, host/*.deb) is allowed but never read.
//   - The documents go through the very same verifyPull as a registry pull (same refusals in Check, same order). bundle.json is a
//     list of hashes for core to spot damage early; the host does not need it: what it uses is either signed or hashed against
//     something signed.
//   - In the run, images/<service>.oci.tar (an OCI image layout as a tar) is copied blob by blob into a fresh private directory;
//     each blob must hash to its name (blobs/sha256/<hex>); the archive's index.json must name exactly one image, the signed digest;
//     that image, its manifest for linux/<arch>, and that manifest's config and layers must be there at their declared sizes.
//     The host then writes the layout's index.json itself (the verified digest, named ghcr.io/knt048/vedette-<service>:<version>),
//     so nothing unsigned decides what Podman loads or what it calls it.
//   - podman pull -q oci:<dir>:ghcr.io/knt048/vedette-<service>:<version> stores the image under the registry repository with
//     the signed digest among its digests, so it answers to its pull reference like a registry pull, and the rest (image inspect,
//     tag, record, the scan build, start, rollback, retention) is the registry path unchanged.

const (
	// coreBundlesDir is the folder of core_data where core writes uploaded bundles.
	coreBundlesDir = "bundles"
	// maxBundleBytes is the bundle cap of update-manifest.md §12 (8 GiB).
	maxBundleBytes = 8 << 30
	// maxBundleMembers bounds the entries of the bundle tar (5 documents, sbom, 5 images, a few .deb files, 2 folders).
	maxBundleMembers = 64
	maxBundleList    = 1 << 20  // bundle.json (not read by the host)
	maxBundleSBOM    = 64 << 20 // sbom.json (not read by the host)
	// bundleSpaceFactor: free space needed, times the image archive's size, where images live and where the host stages the
	// layout: the staged copy, then Podman's copy of the layers and their unpacked form (twice, as for a registry pull).
	bundleSpaceFactor = 3

	maxLayoutBlobs  = 4096
	maxLayoutIndex  = 256 << 10 // the archive's index.json
	maxLayoutMarker = 4 << 10   // the archive's oci-layout (read past, the host writes its own)
	maxLayoutDoc    = 4 << 20   // an image index or manifest blob the host parses
	maxLayoutLayers = 256
	// layoutParent is the folder of the host's state that holds the layout of the run under way (removed after the run, and at
	// the next bundle pull and at Start if a run was cut short).
	layoutParent = "bundle"
	// refNameAnnotation names the image in an OCI layout's index.json; Podman stores the image under it.
	refNameAnnotation = "org.opencontainers.image.ref.name"
)

// The four signed documents of a bundle.
const (
	bundleIndex       = "index.json"
	bundleIndexSig    = "index.json.minisig"
	bundleManifest    = "release-manifest.json"
	bundleManifestSig = "release-manifest.json.minisig"
)

var bundleDocNames = []string{bundleIndex, bundleIndexSig, bundleManifest, bundleManifestSig}

// Media types of what an image archive may hold at its top: an index (multi-platform) or a single manifest.
const (
	mtOCIIndex       = "application/vnd.oci.image.index.v1+json"
	mtDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	mtOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	mtDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
)

var (
	// errBundle: the bundle or its image archive breaks the contract (name, type, size, duplicate, missing piece).
	errBundle = errors.New("ops: the bundle is not what the contract allows")
	// errArchiveDigest: the image archive is not the signed image (another digest, or a blob that does not hash to its name).
	errArchiveDigest = errors.New("ops: the image archive is not the signed image")

	debMemberRE = regexp.MustCompile(`^host/[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}\.deb$`)
	blobNameRE  = regexp.MustCompile(`^blobs/sha256/([0-9a-f]{64})$`)
)

func imageMemberName(service string) string { return "images/" + service + ".oci.tar" }

// bundleMemberCap is the size cap of a regular member of the bundle, or -1 when the name is not one a bundle may hold.
func bundleMemberCap(name string) int64 {
	switch name {
	case bundleIndex, bundleManifest:
		return release.MaxDocBytes
	case bundleIndexSig, bundleManifestSig:
		return release.MaxSigBytes
	case "bundle.json":
		return maxBundleList
	case "sbom.json":
		return maxBundleSBOM
	}
	if svc, ok := strings.CutPrefix(name, "images/"); ok {
		if svc, ok = strings.CutSuffix(svc, ".oci.tar"); ok && knownService(svc) {
			return maxBundleBytes
		}
		return -1
	}
	if debMemberRE.MatchString(name) {
		return maxHostPackage
	}
	return -1
}

// walkBundle reads the bundle tar from r and checks every entry against the contract. visit is called for each regular member with
// a reader of its bytes; a member it does not read is skipped (by seeking, when r can seek). The error wraps errBundle for anything
// the contract refuses, or is the error visit returned.
func walkBundle(r io.Reader, visit func(name string, size int64, body io.Reader) error) error {
	tr := tar.NewReader(r)
	seen := map[string]bool{}
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			if n == 0 {
				return fmt.Errorf("%w: not a tar, or an empty one", errBundle)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %w", errBundle, err)
		}
		if n >= maxBundleMembers {
			return fmt.Errorf("%w: more than %d entries", errBundle, maxBundleMembers)
		}
		name := strings.TrimSuffix(h.Name, "/")
		if seen[name] {
			return fmt.Errorf("%w: a duplicate entry", errBundle)
		}
		seen[name] = true
		switch h.Typeflag {
		case tar.TypeDir:
			if name != "images" && name != "host" {
				return fmt.Errorf("%w: a folder that is not images/ or host/", errBundle)
			}
			continue
		case tar.TypeReg:
		default:
			return fmt.Errorf("%w: an entry that is not a plain file (a link, a device, a FIFO or a sparse file)", errBundle)
		}
		if limit := bundleMemberCap(h.Name); limit < 0 || h.Size > limit {
			return fmt.Errorf("%w: a name outside the list, or a member over its size cap", errBundle)
		}
		if err := visit(h.Name, h.Size, tr); err != nil {
			return err
		}
	}
}

// bundleHead is what the headers of a bundle say: the four documents, and the size of the asked service's image (-1: none).
type bundleHead struct {
	docs      map[string][]byte
	imageSize int64
}

func readBundleHead(r io.Reader, service string) (*bundleHead, error) {
	head := &bundleHead{docs: map[string][]byte{}, imageSize: -1}
	err := walkBundle(r, func(name string, size int64, body io.Reader) error {
		if slices.Contains(bundleDocNames, name) {
			b, err := io.ReadAll(body) // at most MaxDocBytes: the header was checked against the cap
			if err != nil || int64(len(b)) != size || size == 0 {
				return fmt.Errorf("%w: a document could not be read", errBundle)
			}
			head.docs[name] = b
		}
		if name == imageMemberName(service) {
			head.imageSize = size
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, n := range bundleDocNames {
		if head.docs[n] == nil {
			return nil, fmt.Errorf("%w: %s is missing", errBundle, n)
		}
	}
	return head, nil
}

// openBundle opens <core_data>/bundles/<id>.tar (id is 32 hex, validated) through core's tree and returns it with its size.
func (o *Ops) openBundle(id string) (*os.File, int64, error) {
	t, err := o.openCore()
	if err != nil {
		return nil, 0, refuse412(api.CodeBundleNotFound, "The host cannot read core's data directory, where core writes uploaded bundles.")
	}
	defer t.close()
	f, n, err := t.openFile(coreBundlesDir+"/"+id+".tar", maxBundleBytes)
	if errors.Is(err, errNotFound) {
		return nil, 0, refuse412(api.CodeBundleNotFound, "Core has not written that bundle. Upload it again.")
	}
	if err != nil {
		o.log.Warn("a bundle file was refused", "error", err.Error())
		return nil, 0, refuse412(api.CodeBundleInvalid, "The bundle file is not what the contract requires: a regular file of core, one link, at most 8 GiB.")
	}
	return f, n, nil
}

// bundleSource is where a pull from a bundle reads its image.
type bundleSource struct {
	id        string
	imageSize int64 // the size of images/<service>.oci.tar in the bundle
}

// planPull is verifyPull for either source. For a bundle the four documents are the bundle's (the request carries none), they go
// through the same checks in the same order, and then the bundle must hold the service's image.
func (o *Ops) planPull(a api.ContainerPullArgs) (*pullPlan, error) {
	if a.Source != api.PullSourceBundle {
		return o.verifyPull(a)
	}
	f, size, err := o.openBundle(a.BundleID)
	if err != nil {
		return nil, err
	}
	head, err := readBundleHead(io.NewSectionReader(f, 0, size), a.Service)
	_ = f.Close()
	if err != nil {
		o.log.Warn("a bundle was refused", "error", err.Error())
		return nil, refuse412(api.CodeBundleInvalid, "The bundle is not a valid Vedette bundle: an entry outside the list, a link or device, a member over its cap, or a missing document.")
	}
	enc := base64.StdEncoding.EncodeToString
	a.Index, a.IndexSig = enc(head.docs[bundleIndex]), enc(head.docs[bundleIndexSig])
	a.Manifest, a.ManifestSig = enc(head.docs[bundleManifest]), enc(head.docs[bundleManifestSig])
	plan, err := o.verifyPull(a)
	if err != nil {
		return nil, err
	}
	if head.imageSize <= 0 {
		return nil, refuse412(api.CodeBundleInvalid, "The bundle holds no image for that service.")
	}
	plan.bundle = &bundleSource{id: a.BundleID, imageSize: head.imageSize}
	return plan, nil
}

// bundleRoom is low_disk for a bundle: three times the image archive free where images live and where the host stages it.
func (o *Ops) bundleRoom(size int64) error {
	need := uint64(max(size, 0)) * bundleSpaceFactor
	images, err := o.freeForImages()
	if err != nil {
		return refuse412(api.CodeLowDisk, "The host could not measure the free space where images are stored.")
	}
	state, err := o.freeNear(o.cfg.StateDir)
	if err != nil {
		return refuse412(api.CodeLowDisk, "The host could not measure the free space of its own state.")
	}
	if free := min(images, state); free < need {
		return refuse412(api.CodeLowDisk, fmt.Sprintf("Not enough free space to load the image from the bundle: %d MiB free, %d MiB needed (three times its archive).", free>>20, need>>20))
	}
	return nil
}

// stageBundleImage copies the service's image archive out of the bundle into a private directory of the host (an OCI layout),
// checking every blob against its name on the way, checks that the archive is the signed image, and writes the layout's index.json
// itself. The returned function removes the directory; it is safe to call when an error is returned. The error is a
// *server.Failure, or a *server.Refusal when the bundle can no longer be opened.
func (o *Ops) stageBundleImage(ctx context.Context, logf func(string), plan *pullPlan) (string, func(), error) {
	root := o.stateFile(layoutParent)
	cleanup := func() { _ = os.RemoveAll(root) }
	if err := os.RemoveAll(root); err != nil {
		return "", cleanup, fail(api.CodePullFailed, "The host could not clear its staging directory for bundle images.")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", cleanup, fail(api.CodePullFailed, "The host could not make a private directory for the image.")
	}
	dir, err := os.MkdirTemp(root, "img-")
	if err != nil {
		return "", cleanup, fail(api.CodePullFailed, "The host could not make a private directory for the image.")
	}
	f, size, err := o.openBundle(plan.bundle.id)
	if err != nil {
		return "", cleanup, err
	}
	defer func() { _ = f.Close() }()
	logf("copying the image of " + plan.service + " out of the bundle and checking every blob")
	var index []byte
	found := false
	err = walkBundle(io.NewSectionReader(f, 0, size), func(name string, n int64, body io.Reader) error {
		if name != imageMemberName(plan.service) {
			return nil
		}
		found = true
		var lerr error
		index, lerr = extractLayout(ctxReader{ctx: ctx, r: body}, dir, n)
		return lerr
	})
	if err == nil && !found {
		err = fmt.Errorf("%w: the image is not in the bundle any more", errBundle)
	}
	if err == nil {
		var top ociDescriptor
		if top, err = checkLayout(dir, index, plan.digest, o.arch()); err == nil {
			err = writeLayoutIndex(dir, top, plan.service, plan.version)
		}
	}
	if err != nil {
		return "", cleanup, o.bundleFailure(ctx, logf, err)
	}
	return dir, cleanup, nil
}

// bundleFailure turns what went wrong while staging into the run's code. The text of err goes to the log only.
func (o *Ops) bundleFailure(ctx context.Context, logf func(string), err error) error {
	o.log.WarnContext(ctx, "the image of a bundle was not loaded", "error", err.Error())
	switch {
	case ctx.Err() != nil: // first: a stopped copy makes the tar reader fail too, which is not the bundle's fault
		return fail(api.CodePullFailed, "The copy of the image out of the bundle was stopped.")
	case errors.Is(err, errArchiveDigest):
		logf("the image archive in the bundle is not the image the signed manifest names; nothing was loaded")
		return fail(api.CodeArchiveDigestMismatch, "The image archive in the bundle is not the image the signed manifest names.")
	case errors.Is(err, errBundle):
		logf("the image archive in the bundle breaks the contract; nothing was loaded")
		return fail(api.CodeBundleInvalid, "The image archive in the bundle is not a complete OCI image layout of plain files.")
	}
	return fail(api.CodePullFailed, "The host could not copy the image out of the bundle.")
}

// extractLayout reads an OCI image layout as a tar from r into dir: only blobs/sha256/<64 hex> files (each written to a new file
// and hashed on the way, and it must hash to its name), the folders above them, oci-layout (read past) and index.json (returned,
// not written). Anything else, a link, a device, a duplicate or a short entry is errBundle; a blob of other content is
// errArchiveDigest. The blobs together may not be larger than limit, the archive's own size: a sparse entry (PAX or GNU, which
// the tar reader expands) cannot make the host write more than core uploaded and low_disk measured.
func extractLayout(r io.Reader, dir string, limit int64) ([]byte, error) {
	blobs := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobs, 0o700); err != nil {
		return nil, err
	}
	tr := tar.NewReader(r)
	seen := map[string]bool{}
	var index []byte
	n, written := 0, int64(0)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errBundle, err)
		}
		name := strings.TrimSuffix(h.Name, "/")
		if seen[name] {
			return nil, fmt.Errorf("%w: a duplicate entry in the image archive", errBundle)
		}
		seen[name] = true
		switch {
		case h.Typeflag == tar.TypeDir && (name == "blobs" || name == "blobs/sha256"):
		case h.Typeflag != tar.TypeReg:
			return nil, fmt.Errorf("%w: an entry of the image archive that is not a plain file", errBundle)
		case name == "oci-layout":
			if h.Size > maxLayoutMarker {
				return nil, fmt.Errorf("%w: oci-layout is over its cap", errBundle)
			}
		case name == "index.json":
			if h.Size > maxLayoutIndex {
				return nil, fmt.Errorf("%w: index.json is over its cap", errBundle)
			}
			if index, err = io.ReadAll(tr); err != nil {
				return nil, fmt.Errorf("%w: %w", errBundle, err)
			}
		default:
			m := blobNameRE.FindStringSubmatch(name)
			if m == nil {
				return nil, fmt.Errorf("%w: a name in the image archive outside oci-layout, index.json and blobs/sha256/<hex>", errBundle)
			}
			if n++; n > maxLayoutBlobs {
				return nil, fmt.Errorf("%w: more than %d blobs", errBundle, maxLayoutBlobs)
			}
			if written += h.Size; h.Size < 0 || written > limit {
				return nil, fmt.Errorf("%w: the blobs are larger than the archive", errBundle)
			}
			if err := copyBlob(tr, filepath.Join(blobs, m[1]), m[1], h.Size); err != nil {
				return nil, err
			}
		}
	}
	if index == nil {
		return nil, fmt.Errorf("%w: the image archive has no index.json", errBundle)
	}
	return index, nil
}

// copyBlob writes r to a new file at path and checks that its SHA-256 is want and its length size.
func copyBlob(r io.Reader, path, want string, size int64) error {
	out, err := createNew(path)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), r)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF):
		return fmt.Errorf("%w: a blob is cut short", errBundle)
	case err != nil:
		return err
	case n != size:
		return fmt.Errorf("%w: a blob is cut short", errBundle)
	case hex.EncodeToString(h.Sum(nil)) != want:
		return fmt.Errorf("%w: a blob does not hash to its name", errArchiveDigest)
	}
	return nil
}

// ociDescriptor and ociDoc are the parts of the OCI image spec the host reads (unknown fields, such as annotations, are ignored).
type ociDescriptor struct {
	MediaType string       `json:"mediaType"`
	Digest    string       `json:"digest"`
	Size      int64        `json:"size"`
	Platform  *ociPlatform `json:"platform,omitempty"`
}

type ociPlatform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

type ociDoc struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []ociDescriptor `json:"manifests"`
	Config        *ociDescriptor  `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
}

func isIndexType(mt string) bool    { return mt == mtOCIIndex || mt == mtDockerList }
func isManifestType(mt string) bool { return mt == mtOCIManifest || mt == mtDockerManifest }

// checkLayout checks the layout extractLayout wrote: the archive's index.json names exactly one image and it is digest (the signed
// one); that image is there; when it is an index, it has a manifest for linux/arch and that manifest is there; and the manifest's
// config and layers are there at their declared sizes. Every blob already hashed to its name, so presence and size are what is left.
// It returns the descriptor of the image for the layout index the host writes.
func checkLayout(dir string, indexRaw []byte, digest, arch string) (ociDescriptor, error) {
	var idx ociDoc
	if err := json.Unmarshal(indexRaw, &idx); err != nil || idx.SchemaVersion != 2 {
		return ociDescriptor{}, fmt.Errorf("%w: the archive's index.json is not an OCI index", errBundle)
	}
	if len(idx.Manifests) != 1 || idx.Manifests[0].Digest != digest {
		return ociDescriptor{}, fmt.Errorf("%w: the archive's index.json does not name exactly the signed digest", errArchiveDigest)
	}
	top := idx.Manifests[0]
	doc, err := readLayoutDoc(dir, top)
	if err != nil {
		return ociDescriptor{}, err
	}
	if isIndexType(top.MediaType) {
		i := slices.IndexFunc(doc.Manifests, func(d ociDescriptor) bool {
			return d.Platform != nil && d.Platform.OS == "linux" && d.Platform.Architecture == arch && isManifestType(d.MediaType)
		})
		if i < 0 {
			return ociDescriptor{}, fmt.Errorf("%w: the image has no manifest for linux/%s", errBundle, arch)
		}
		if doc, err = readLayoutDoc(dir, doc.Manifests[i]); err != nil {
			return ociDescriptor{}, err
		}
	}
	if doc.Config == nil || len(doc.Layers) > maxLayoutLayers {
		return ociDescriptor{}, fmt.Errorf("%w: the manifest has no config or too many layers", errBundle)
	}
	for _, d := range append([]ociDescriptor{*doc.Config}, doc.Layers...) {
		if _, err := layoutBlob(dir, d); err != nil {
			return ociDescriptor{}, err
		}
	}
	return ociDescriptor{MediaType: top.MediaType, Digest: top.Digest, Size: top.Size}, nil
}

// layoutBlob opens the blob d names in dir and checks that it is a plain file of d's size.
func layoutBlob(dir string, d ociDescriptor) (*os.File, error) {
	if !digestRE.MatchString(d.Digest) || d.Size < 0 {
		return nil, fmt.Errorf("%w: a descriptor with a bad digest or size", errBundle)
	}
	f, st, err := openRegularNoFollow(filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix(d.Digest, "sha256:")))
	if err != nil {
		return nil, fmt.Errorf("%w: a blob the image needs is missing", errBundle)
	}
	if st.Size() != d.Size {
		_ = f.Close()
		return nil, fmt.Errorf("%w: a blob is not the size its descriptor says", errBundle)
	}
	return f, nil
}

// readLayoutDoc reads and parses the index or manifest blob d names (its media type must be one of the four the host knows, and the
// blob's own mediaType, when it has one, must agree).
func readLayoutDoc(dir string, d ociDescriptor) (ociDoc, error) {
	if !isIndexType(d.MediaType) && !isManifestType(d.MediaType) || d.Size < 1 || d.Size > maxLayoutDoc {
		return ociDoc{}, fmt.Errorf("%w: an image index or manifest of an unknown type or size", errBundle)
	}
	f, err := layoutBlob(dir, d)
	if err != nil {
		return ociDoc{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, d.Size))
	_ = f.Close()
	var doc ociDoc
	if err != nil || json.Unmarshal(raw, &doc) != nil || doc.SchemaVersion != 2 || doc.MediaType != "" && doc.MediaType != d.MediaType {
		return ociDoc{}, fmt.Errorf("%w: an image index or manifest that does not parse", errBundle)
	}
	return doc, nil
}

// layoutIndex is the index.json the host writes into the staged layout: one image, the verified one, named by its registry ref.
type layoutIndex struct {
	SchemaVersion int                `json:"schemaVersion"`
	Manifests     []layoutIndexEntry `json:"manifests"`
}

type layoutIndexEntry struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations"`
}

func writeLayoutIndex(dir string, top ociDescriptor, service, version string) error {
	idx, err := json.Marshal(layoutIndex{SchemaVersion: 2, Manifests: []layoutIndexEntry{{
		MediaType: top.MediaType, Digest: top.Digest, Size: top.Size,
		Annotations: map[string]string{refNameAnnotation: release.ImageRef(service, version)},
	}}})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "index.json"), idx, 0o600)
}
