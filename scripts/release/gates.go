package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/internal/jsonstrict"
	"github.com/knt048/vedette/internal/release"
)

// The release gates (WP-08k part B, step 3 of docs/plans/2026-11-12-wp08k-release-job.md; D-457, D-401). `make release-gates` runs
// vuln-scan, sbom and notices-check, then this command: the checks that need the built artifacts and nothing else. Nothing here
// signs, pushes or publishes; every external command is a fixed argv through runFunc.

// minSequenceLabel is the label the core Containerfile sets from MIN_SEQUENCE, the floor linked into core (D-347, D-401).
const minSequenceLabel = "io.github.knt048.vedette.min-sequence"

// hostBinaryInDeb is where deploy/deb/nfpm.yaml installs vedette-host.
const hostBinaryInDeb = "usr/lib/vedette/vedette-host"

// debArchs are the two packages of a release (release-in reads both).
var debArchs = []string{"amd64", "arm64"}

// gatesOpts says what the gates check.
type gatesOpts struct {
	Version     string
	MinSequence string // the floor the release is built with: the sequence of RELEASE_PREV_INDEX, 0 only for the very first release
	Platforms   []string
	PrevIndex   string        // RELEASE_PREV_INDEX: the published index; its verified sequence must be MinSequence ("" only for the very first release: 0)
	Trust       release.Trust // the keys PrevIndex is verified with
	DebDir      string        // where make host-deb wrote the two packages
	Repo        string        // git repository root
	Rules       BinaryRules
	Preflight   bool        // only the version, floor and tree checks (make runs them before the long scans); writes nothing
	Out         string      // where the final run writes gates.json, the record push and in compare with (dist/release)
	VulnDir     string      // where make vuln-scan RELEASE=1 wrote the trivy reports <local>-<arch>.json (dist/vuln)
	SBOMDir     string      // where make sbom RELEASE=1 wrote <local>-<arch>.cdx.json (dist/sbom)
	Expect      imageExpect // what the files inside core and scan-base must be (D-410); Expect.Keys are Rules.Keys
}

// checkVulnReport refuses a trivy JSON report (rel, inside dir) that is missing, not a regular file reached without a symlink, or not
// of the image whose config digest is config: trivy's Metadata.ImageID, the value it also writes as the SBOM's
// aquasecurity:trivy:ImageID (checkSBOM; measured there on an OCI layout as podman's image ID).
func checkVulnReport(dir, rel, config string) error {
	if err := noSymlinks(dir, rel); err != nil {
		return fmt.Errorf("vulnerability report %s: %w", rel, err)
	}
	p := filepath.Join(dir, rel)
	fi, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("vulnerability report: %w (make vuln-scan RELEASE=1 IMAGE_TAG=<version> writes it)", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("vulnerability report %s is not a regular file", p)
	}
	raw, err := readSmall(p, maxSBOM)
	if err != nil {
		return err
	}
	var rep struct {
		Metadata struct {
			ImageID string `json:"ImageID"`
		} `json:"Metadata"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		return fmt.Errorf("vulnerability report %s is not trivy JSON: %w", p, err)
	}
	if rep.Metadata.ImageID != config {
		return fmt.Errorf("vulnerability report %s is of image %q, not %s", p, rep.Metadata.ImageID, config)
	}
	return nil
}

// gatesFile is the record of a passed `release gates` run, next to images.json: what push and in ship must be what it names.
const gatesFile = "gates.json"

// GatesDoc is <out>/gates.json: exactly what the final `release gates` run checked. `release push` refuses a local list whose platform
// images are not these, `release in` a .deb whose bytes are not these, so a make images / make host-deb run after step 3 is caught.
type GatesDoc struct {
	Version     string       `json:"version"`
	MinSequence string       `json:"min_sequence"`
	Debs        []GatedDeb   `json:"debs"`
	Images      []GatedImage `json:"images"`
}

// GatedDeb is one package the gates checked: its file name then (nfpm's ~ spelling until release-deb-name renames it; the bytes are
// what counts), SHA-256 (hex) and size.
type GatedDeb struct {
	Arch   string `json:"arch"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// GatedImage is one local list of publishedImages and the identity of each of its platform images.
type GatedImage struct {
	Service   string          `json:"service"`
	Local     string          `json:"local"`
	Platforms []GatedPlatform `json:"platforms"`
}

// GatedPlatform identifies a platform image by its config digest (podman's image ID, localPlatform.Config). Chosen over the local
// manifest digest because it is the identity the rest of the chain already uses: push compares it with a list already in the
// registry, images.json records it, and part C requires the SBOM's trivy ImageID to equal it. A re-read of the same local list gives
// the same ID; a rebuild gives another one, except a bit-for-bit identical rebuild (same layers, same config), which is the same image.
type GatedPlatform struct {
	Platform string `json:"platform"`
	Config   string `json:"config"`
}

// gatesPreflight refuses a version that is not a release, a floor that is not the sequence of the published index (0 only without
// one: the very first release), and a tree that is not the clean tag v<version>: the packages are rebuilt from this tree below.
func gatesPreflight(ctx context.Context, run runFunc, o gatesOpts) error {
	if _, err := release.CompareVersions(o.Version, o.Version); err != nil {
		return fmt.Errorf("version %q is not SemVer (no v, no build metadata)", o.Version)
	}
	if err := refuseTestVersion(o.Version); err != nil {
		return err
	}
	if n, err := strconv.ParseUint(o.MinSequence, 10, 64); err != nil || strconv.FormatUint(n, 10) != o.MinSequence {
		return fmt.Errorf("min-sequence %q is not a plain decimal number", o.MinSequence)
	}
	// make lets a MIN_SEQUENCE from the command line or the environment win over RELEASE_PREV_INDEX: the floor is checked here
	if o.PrevIndex != "" {
		idx, err := LoadPrevIndex(o.PrevIndex, o.Trust)
		if err != nil {
			return err
		}
		if seq := strconv.FormatUint(idx.Sequence, 10); seq != o.MinSequence {
			return fmt.Errorf("MIN_SEQUENCE is %s but the published index %s has sequence %s: unset MIN_SEQUENCE (make takes the floor from RELEASE_PREV_INDEX) and build the images and packages with that index", o.MinSequence, o.PrevIndex, seq)
		}
	} else if o.MinSequence != "0" {
		return fmt.Errorf("MIN_SEQUENCE=%s without RELEASE_PREV_INDEX: the floor is the sequence of the published index (pass RELEASE_PREV_INDEX), 0 only for the very first release", o.MinSequence)
	}
	if len(o.Platforms) == 0 {
		return errors.New("no platforms")
	}
	for _, p := range o.Platforms {
		if !platformRE.MatchString(p) {
			return fmt.Errorf("platform %q: a release is built for linux/amd64 and linux/arm64", p)
		}
	}
	return checkReleaseTree(ctx, run, o.Repo, o.Version)
}

// Gates runs, in order and stopping at the first failure: check-binaries -release on the vedette-host inside each .deb; the
// version label of every platform of the four local lists (and core's floor label), and the files inside core and scan-base
// (checkImageFiles: core's /vedette holds the production keys, scan-base's nuclei, pack and no nmap; D-410); the floor of each .deb, by building it again
// from this tree with MinSequence and comparing the bytes (the .deb is reproducible: SOURCE_DATE_EPOCH, -trimpath). Only when all
// passed does it write <Out>/gates.json (GatesDoc); a record left by an earlier run is removed first, so a failed run leaves none.
func Gates(ctx context.Context, run runFunc, o gatesOpts, stdout io.Writer) error {
	if !o.Preflight {
		if o.Out == "" {
			return errors.New("no -out: the directory of gates.json (dist/release)")
		}
		if err := os.Remove(filepath.Join(o.Out, gatesFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove the earlier gates record: %w", err)
		}
	}
	if err := gatesPreflight(ctx, run, o); err != nil {
		return err
	}
	if o.Preflight {
		say(stdout, "ok: %s is a release version, the floor is %s and the tree is the clean tag v%s", o.Version, o.MinSequence, o.Version)
		return nil
	}
	rec := &GatesDoc{Version: o.Version, MinSequence: o.MinSequence}
	debs := make([]string, len(debArchs))
	for i, arch := range debArchs {
		deb, err := shippedDeb(o.DebDir, o.Version, arch)
		if err != nil {
			return err
		}
		bin, err := debMember(deb)
		if err != nil {
			return err
		}
		if err := checkBinaryData(deb+": "+hostBinaryInDeb, bin, o.Rules); err != nil {
			return err
		}
		debs[i] = deb
		say(stdout, "ok: check-binaries -release %s (%s)", deb, hostBinaryInDeb)
	}
	for _, im := range publishedImages {
		name := "localhost/vedette-" + im.local + ":" + o.Version
		lp, err := localPlatforms(ctx, run, name, o.Platforms)
		if err != nil {
			return err
		}
		gi := GatedImage{Service: im.service, Local: im.local}
		for _, p := range lp {
			gi.Platforms = append(gi.Platforms, GatedPlatform{Platform: p.Platform, Config: p.Config})
			if p.Version != o.Version {
				return fmt.Errorf("%s %s has label %s=%q, not %s: build with make images IMAGE_TAG=%s IMAGE_VERSION=%s RELEASE_PREV_INDEX=<prev> (MIN_SEQUENCE=0 for the very first release only)", name, p.Platform, versionLabel, p.Version, o.Version, o.Version, o.Version)
			}
			if im.local == "core" && p.MinSequence != o.MinSequence {
				return fmt.Errorf("%s %s was built with MIN_SEQUENCE %q (label %s), the release floor is %s: build the images again with make images IMAGE_TAG=%s IMAGE_VERSION=%s RELEASE_PREV_INDEX=<prev> (MIN_SEQUENCE=0 for the very first release only)", name, p.Platform, p.MinSequence, minSequenceLabel, o.MinSequence, o.Version, o.Version)
			}
			// vuln-scan and sbom read the lists minutes before this: the record names only images they scanned
			base := im.local + "-" + strings.TrimPrefix(p.Platform, "linux/")
			if err := checkVulnReport(o.VulnDir, base+".json", p.Config); err != nil {
				return fmt.Errorf("%s %s: %w; run make release-gates again (the images changed during the scans?)", name, p.Platform, err)
			}
			if err := checkSBOM(o.SBOMDir, base+".cdx.json", p.Config); err != nil {
				return fmt.Errorf("%s %s: %w; run make release-gates again (the images changed during the scans?)", name, p.Platform, err)
			}
			// the files inside, of the very platform image recorded (its config digest): what push publishes and cosign signs (D-410)
			if imageKinds[im.local] {
				if err := checkImageFiles(ctx, run, "podman", p.Config, im.local, o.Expect); err != nil {
					return fmt.Errorf("%s %s: %w", name, p.Platform, err)
				}
				say(stdout, "ok: %s %s: %s", name, p.Platform, imageOK(im.local, o.Expect))
			}
		}
		rec.Images = append(rec.Images, gi)
		say(stdout, "ok: %s: %s=%s on %s%s", name, versionLabel, o.Version, strings.Join(o.Platforms, ", "), map[bool]string{true: ", floor " + o.MinSequence}[im.local == "core"])
	}
	for i, arch := range debArchs {
		sum, size, err := sameAsRebuilt(ctx, run, o, arch, debs[i])
		if err != nil {
			return err
		}
		rec.Debs = append(rec.Debs, GatedDeb{Arch: arch, File: filepath.Base(debs[i]), SHA256: sum, Size: size})
		say(stdout, "ok: %s is what this commit builds with MIN_SEQUENCE=%s", debs[i], o.MinSequence)
	}
	p, err := writeGates(o.Out, rec)
	if err != nil {
		return err
	}
	say(stdout, "wrote %s: release-push, release-in and release-manifest ship only these images and packages", p)
	return nil
}

// writeGates writes the record atomically (a temporary file in dir, then rename), mode 0644 like images.json.
func writeGates(dir string, g *GatesDoc) (string, error) {
	b, err := marshal(g)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // build output, not secret
		return "", err
	}
	f, err := os.CreateTemp(dir, ".gates-*.json")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // nothing left after the rename
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(0o644)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, gatesFile)
	return p, os.Rename(tmp, p)
}

// readGates reads the record strictly (like readImages): known fields only, both packages and every image of publishedImages
// exactly once, well-formed digests. A missing record is refused: push and in ship only what the gates checked.
func readGates(p string) (*GatesDoc, error) {
	raw, err := readSmall(p, 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no gates record %s: run make release-gates (step 3) first; release-push, release-in and release-manifest ship only what it checked", p)
	}
	if err != nil {
		return nil, fmt.Errorf("gates record: %w", err)
	}
	var g GatesDoc
	if err := jsonstrict.Decode(raw, &g); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if _, err := release.CompareVersions(g.Version, g.Version); err != nil {
		return nil, fmt.Errorf("%s: version %q is not SemVer", p, g.Version)
	}
	if n, err := strconv.ParseUint(g.MinSequence, 10, 64); err != nil || strconv.FormatUint(n, 10) != g.MinSequence {
		return nil, fmt.Errorf("%s: min_sequence %q is not a plain decimal number", p, g.MinSequence)
	}
	if len(g.Debs) != len(debArchs) {
		return nil, fmt.Errorf("%s lists %d packages, a release has %d", p, len(g.Debs), len(debArchs))
	}
	for _, d := range g.Debs {
		if !slices.Contains(debArchs, d.Arch) {
			return nil, fmt.Errorf("%s: unknown package arch %q", p, d.Arch)
		}
		if n := countFunc(g.Debs, func(o GatedDeb) bool { return o.Arch == d.Arch }); n != 1 {
			return nil, fmt.Errorf("%s: package %s is listed %d times", p, d.Arch, n)
		}
		if d.File == "" || d.File != filepath.Base(d.File) || !sha256HexRE.MatchString(d.SHA256) || d.Size <= 0 {
			return nil, fmt.Errorf("%s: package %s has a malformed file name, sha256 or size", p, d.Arch)
		}
	}
	if len(g.Images) != len(publishedImages) {
		return nil, fmt.Errorf("%s lists %d images, a release has %d", p, len(g.Images), len(publishedImages))
	}
	for _, im := range g.Images {
		if localName(im.Service) == "" || localName(im.Service) != im.Local {
			return nil, fmt.Errorf("%s: unknown image %q (local %q)", p, im.Service, im.Local)
		}
		if n := countFunc(g.Images, func(o GatedImage) bool { return o.Service == im.Service }); n != 1 {
			return nil, fmt.Errorf("%s: image %s is listed %d times", p, im.Service, n)
		}
		if len(im.Platforms) == 0 {
			return nil, fmt.Errorf("%s: image %s has no platform", p, im.Service)
		}
		for _, pl := range im.Platforms {
			if !platformRE.MatchString(pl.Platform) || !serviceDigestRE.MatchString(pl.Config) {
				return nil, fmt.Errorf("%s: %s has a malformed platform %q or config digest", p, im.Service, pl.Platform)
			}
			if n := countFunc(im.Platforms, func(o GatedPlatform) bool { return o.Platform == pl.Platform }); n != 1 {
				return nil, fmt.Errorf("%s: %s lists platform %s %d times", p, im.Service, pl.Platform, n)
			}
		}
	}
	return &g, nil
}

func countFunc[T any](s []T, f func(T) bool) int {
	n := 0
	for _, x := range s {
		if f(x) {
			n++
		}
	}
	return n
}

// gatesAgain is the remedy every refusal against the record names.
func gatesAgain(version string) string {
	return "run make release-gates VERSION=" + version + " again (it checks what is there now)"
}

// checkVersion refuses a record of another release.
func (g *GatesDoc) checkVersion(version string) error {
	if g.Version != version {
		return fmt.Errorf("the gates record is of version %s, not %s: %s", g.Version, version, gatesAgain(version))
	}
	return nil
}

// checkImage refuses when the platform images of service (platform -> config digest, now) are not exactly the ones the gates
// checked (readGates made sure the record has every service once). what names the list for the message.
func (g *GatesDoc) checkImage(service, what string, now map[string]string) error {
	rec := map[string]string{}
	for _, im := range g.Images {
		if im.Service == service {
			for _, p := range im.Platforms {
				rec[p.Platform] = p.Config
			}
		}
	}
	plats := slices.Sorted(maps.Keys(rec))
	for _, p := range slices.Sorted(maps.Keys(now)) {
		if _, ok := rec[p]; !ok {
			plats = append(plats, p)
		}
	}
	for _, p := range plats {
		if now[p] != rec[p] {
			return fmt.Errorf("%s %s is %s now, the gates checked %s: the images changed after the gates; %s", what, p, orNone(now[p]), orNone(rec[p]), gatesAgain(g.Version))
		}
	}
	return nil
}

// checkDeb refuses a package of arch (at path) whose bytes are not the ones the gates checked.
func (g *GatesDoc) checkDeb(arch, path, sum string, size int64) error {
	for _, d := range g.Debs {
		if d.Arch == arch && d.SHA256 == sum && d.Size == size {
			return nil
		}
	}
	var d GatedDeb
	for _, x := range g.Debs {
		if x.Arch == arch {
			d = x
		}
	}
	return fmt.Errorf("%s has sha256 %s (%d bytes) now, the gates checked %s (%s, %d bytes): it was built again after the gates; %s", path, sum, size, orNone(d.SHA256), d.File, d.Size, gatesAgain(g.Version))
}

// checkHost refuses host packages whose recorded hashes (h, as release-manifest or release-in computed them from paths, in the same
// order) are not the bytes the gates checked.
func (g *GatesDoc) checkHost(h *release.HostPart, paths []string) error {
	for i, f := range h.Files {
		_, arch, _ := release.ParseHostPackageName(f.Name) // buildHostPart parsed it
		if err := g.checkDeb(arch, paths[i], f.SHA256, f.Size); err != nil {
			return err
		}
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "absent"
	}
	return s
}

// shippedDeb is the package of arch in dir: the SemVer name release-in reads, else nfpm's (a prerelease is spelled 1.0.0~rc.1 by
// nfpm until it is renamed, plan §4).
func shippedDeb(dir, version, arch string) (string, error) {
	names := []string{release.HostPackageName(version, arch)}
	if v := strings.Replace(version, "-", "~", 1); v != version {
		names = append(names, release.HostPackageName(v, arch))
	}
	for _, n := range names {
		p := filepath.Join(dir, n)
		if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() {
			return p, nil
		}
	}
	return "", fmt.Errorf("no %s in %s (a regular file): build it with make host-deb VERSION=%s ARCH=%s RELEASE_PREV_INDEX=<prev>", names[0], dir, version, arch)
}

// sameAsRebuilt builds the package of arch again with make host-deb, from this tree and with the release floor, into a temporary
// directory, and refuses a shipped package whose bytes differ: it was built from another commit, another floor or another version.
// It returns the SHA-256 (hex) and size of the bytes it compared: what the gates record.
func sameAsRebuilt(ctx context.Context, run runFunc, o gatesOpts, arch, deb string) (string, int64, error) {
	tmp, err := os.MkdirTemp("", "vedette-gates-")
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	if _, err := run(ctx, "make", "-C", o.Repo, "--no-print-directory", "host-deb", "VERSION="+o.Version, "ARCH="+arch, "MIN_SEQUENCE="+o.MinSequence, "DEB_OUT="+tmp); err != nil {
		return "", 0, fmt.Errorf("rebuild of the %s package: %w", arch, err)
	}
	built, err := filepath.Glob(filepath.Join(tmp, "*.deb"))
	if err != nil || len(built) != 1 {
		return "", 0, fmt.Errorf("rebuild of the %s package: want one .deb in %s, got %v", arch, tmp, built)
	}
	a, err := readSmall(deb, maxBinary)
	if err != nil {
		return "", 0, err
	}
	b, err := readSmall(built[0], maxBinary)
	if err != nil {
		return "", 0, err
	}
	if bytes.Equal(a, b) {
		sum := sha256.Sum256(a)
		return hex.EncodeToString(sum[:]), int64(len(a)), nil
	}
	why := "built differently: another floor (MIN_SEQUENCE) or version, or GOFLAGS, SOURCE_DATE_EPOCH or the Go toolchain set by hand for one of the two builds (host-deb pins GOAMD64=v1, GOARM64=v8.0)"
	if ra, rb := debRevision(a), debRevision(b); ra != rb {
		why = fmt.Sprintf("its vedette-host is from commit %q, this tree is %q", ra, rb)
	}
	return "", 0, fmt.Errorf("%s is not what this commit builds with MIN_SEQUENCE=%s (%s): build it again with make host-deb VERSION=%s ARCH=%s RELEASE_PREV_INDEX=<prev> (MIN_SEQUENCE=0 for the very first release only) from the clean tag, with GOFLAGS unset", deb, o.MinSequence, why, o.Version, arch)
}

// debRevision is the vcs.revision of the vedette-host inside a package, or "" when it cannot be read (only for the message).
func debRevision(deb []byte) string {
	bin, err := readDebMember(bytes.NewReader(deb), "package")
	if err != nil {
		return ""
	}
	bi, err := buildinfo.Read(bytes.NewReader(bin))
	if err != nil {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return ""
}

// debMember returns vedette-host (hostBinaryInDeb, a regular file) from the data.tar.gz of a .deb: an ar archive whose members are
// debian-binary, control.tar.* and data.tar.*. nfpm.yaml builds gzip (deb.compression); any other compression is refused.
func debMember(deb string) ([]byte, error) {
	f, err := os.Open(deb) //nolint:gosec // the package the maintainer built, named by make
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readDebMember(bufio.NewReader(f), deb)
}

func readDebMember(r io.Reader, deb string) ([]byte, error) {
	magic := make([]byte, 8)
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != "!<arch>\n" {
		return nil, fmt.Errorf("%s is not a .deb (no ar header)", deb)
	}
	hdr := make([]byte, 60)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("%s has no data.tar.gz", deb)
			}
			return nil, fmt.Errorf("%s: %w", deb, err)
		}
		size, err := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		if string(hdr[58:]) != "`\n" || err != nil || size < 0 {
			return nil, fmt.Errorf("%s: malformed ar member header", deb)
		}
		name := strings.TrimSuffix(strings.TrimSpace(string(hdr[:16])), "/")
		if strings.HasPrefix(name, "data.tar") {
			if name != "data.tar.gz" {
				return nil, fmt.Errorf("%s: %s, but deploy/deb/nfpm.yaml builds data.tar.gz (deb.compression: gzip)", deb, name)
			}
			return tarMember(io.LimitReader(r, size), deb)
		}
		if _, err := io.CopyN(io.Discard, r, size+size%2); err != nil {
			return nil, fmt.Errorf("%s: %w", deb, err)
		}
	}
}

func tarMember(gz io.Reader, deb string) ([]byte, error) {
	const member = hostBinaryInDeb
	zr, err := gzip.NewReader(gz)
	if err != nil {
		return nil, fmt.Errorf("%s: data.tar.gz: %w", deb, err)
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("%s has no %s", deb, member)
			}
			return nil, fmt.Errorf("%s: data.tar.gz: %w", deb, err)
		}
		if path.Clean("/" + h.Name)[1:] != member {
			continue
		}
		if h.Typeflag != tar.TypeReg || h.Size > maxBinary {
			return nil, fmt.Errorf("%s: %s is not a regular file of at most %d MB", deb, member, maxBinary>>20)
		}
		return io.ReadAll(tr)
	}
}

func cmdGates(ctx context.Context, args []string, stdout io.Writer) error {
	fs := newFlags("gates")
	version := fs.String("version", "", "release version (SemVer, no v): the local lists localhost/vedette-<image>:<version> and the two packages")
	minSeq := fs.String("min-sequence", "", "the release floor: the sequence of the published index (make computes it from RELEASE_PREV_INDEX), 0 for the very first release")
	plats := fs.String("platforms", "linux/amd64,linux/arm64", "platforms every list must hold, comma separated (PLATFORMS of make images)")
	debDir := fs.String("deb-dir", "dist", "directory of vedette-host_<version>_<arch>.deb (DEB_OUT of make host-deb)")
	repo := fs.String("repo", ".", "repository root")
	prev := fs.String("prev-index", "", "directory of the published index (RELEASE_PREV_INDEX); omit for the very first release only (then -min-sequence 0)")
	keys := fs.String("keys-dir", "", "directory with the public keys -prev-index is verified with (default: the keys compiled in)")
	pre := fs.Bool("preflight", false, "only the version, floor and tree checks (before the long scans); writes nothing")
	out := fs.String("out", "dist/release", "directory gates.json is written to when every check passed (release push, in and manifest read it)")
	vulnDir := fs.String("vuln-dir", "dist/vuln", "the trivy reports of make vuln-scan RELEASE=1: each must be of the image recorded")
	sbomDir := fs.String("sbom-dir", "dist/sbom", "the SBOMs of make sbom RELEASE=1: each must be of the image recorded")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o := gatesOpts{Version: *version, MinSequence: *minSeq, Platforms: strings.Split(*plats, ","), PrevIndex: *prev, DebDir: *debDir, Repo: *repo, Preflight: *pre, Out: *out, VulnDir: *vulnDir, SBOMDir: *sbomDir}
	if *prev != "" {
		var err error
		if o.Trust, err = LoadTrust(*keys); err != nil {
			return err
		}
	}
	if !*pre {
		active, backup, testOnly := release.EmbeddedMinisignKeys()
		if testOnly || active == "" || backup == "" {
			return errors.New("this checker was built with the throwaway keys or none: run it with GOFLAGS= and without -tags")
		}
		o.Rules = BinaryRules{Release: true, Keys: []string{active, backup}}
		var err error
		if o.Expect, err = loadImageExpect(*repo, o.Rules.Keys); err != nil {
			return err
		}
	}
	return Gates(ctx, execRun, o, stdout)
}
