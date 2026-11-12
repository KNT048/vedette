package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	Preflight   bool // only the version, floor and tree checks (make runs them before the long scans)
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
// version label of every platform of the four local lists (and core's floor label); the floor of each .deb, by building it again
// from this tree with MinSequence and comparing the bytes (the .deb is reproducible: SOURCE_DATE_EPOCH, -trimpath).
func Gates(ctx context.Context, run runFunc, o gatesOpts, stdout io.Writer) error {
	if err := gatesPreflight(ctx, run, o); err != nil {
		return err
	}
	if o.Preflight {
		say(stdout, "ok: %s is a release version, the floor is %s and the tree is the clean tag v%s", o.Version, o.MinSequence, o.Version)
		return nil
	}
	debs := make([]string, len(debArchs))
	for i, arch := range debArchs {
		deb, err := shippedDeb(o.DebDir, o.Version, arch)
		if err != nil {
			return err
		}
		bin, err := debMember(deb, hostBinaryInDeb)
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
		for _, p := range lp {
			if p.Version != o.Version {
				return fmt.Errorf("%s %s has label %s=%q, not %s: build with make images IMAGE_TAG=%s IMAGE_VERSION=%s RELEASE_PREV_INDEX=<prev> (MIN_SEQUENCE=0 for the very first release only)", name, p.Platform, versionLabel, p.Version, o.Version, o.Version, o.Version)
			}
			if im.local == "core" && p.MinSequence != o.MinSequence {
				return fmt.Errorf("%s %s was built with MIN_SEQUENCE %q (label %s), the release floor is %s: build the images again with make images IMAGE_TAG=%s IMAGE_VERSION=%s RELEASE_PREV_INDEX=<prev> (MIN_SEQUENCE=0 for the very first release only)", name, p.Platform, p.MinSequence, minSequenceLabel, o.MinSequence, o.Version, o.Version)
			}
		}
		say(stdout, "ok: %s: %s=%s on %s%s", name, versionLabel, o.Version, strings.Join(o.Platforms, ", "), map[bool]string{true: ", floor " + o.MinSequence}[im.local == "core"])
	}
	for i, arch := range debArchs {
		if err := sameAsRebuilt(ctx, run, o, arch, debs[i]); err != nil {
			return err
		}
		say(stdout, "ok: %s is what this commit builds with MIN_SEQUENCE=%s", debs[i], o.MinSequence)
	}
	return nil
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
func sameAsRebuilt(ctx context.Context, run runFunc, o gatesOpts, arch, deb string) error {
	tmp, err := os.MkdirTemp("", "vedette-gates-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	if _, err := run(ctx, "make", "-C", o.Repo, "--no-print-directory", "host-deb", "VERSION="+o.Version, "ARCH="+arch, "MIN_SEQUENCE="+o.MinSequence, "DEB_OUT="+tmp); err != nil {
		return fmt.Errorf("rebuild of the %s package: %w", arch, err)
	}
	built, err := filepath.Glob(filepath.Join(tmp, "*.deb"))
	if err != nil || len(built) != 1 {
		return fmt.Errorf("rebuild of the %s package: want one .deb in %s, got %v", arch, tmp, built)
	}
	a, err := readSmall(deb, maxBinary)
	if err != nil {
		return err
	}
	b, err := readSmall(built[0], maxBinary)
	if err != nil {
		return err
	}
	if bytes.Equal(a, b) {
		return nil
	}
	why := "built differently: another floor (MIN_SEQUENCE) or version, or GOFLAGS, GOAMD64/GOARM64, SOURCE_DATE_EPOCH or the Go toolchain set by hand for one of the two builds"
	if ra, rb := debRevision(a), debRevision(b); ra != rb {
		why = fmt.Sprintf("its vedette-host is from commit %q, this tree is %q", ra, rb)
	}
	return fmt.Errorf("%s is not what this commit builds with MIN_SEQUENCE=%s (%s): build it again with make host-deb VERSION=%s ARCH=%s RELEASE_PREV_INDEX=<prev> (MIN_SEQUENCE=0 for the very first release only) from the clean tag, with GOFLAGS unset", deb, o.MinSequence, why, o.Version, arch)
}

// debRevision is the vcs.revision of the vedette-host inside a package, or "" when it cannot be read (only for the message).
func debRevision(deb []byte) string {
	bin, err := readDebMember(bytes.NewReader(deb), hostBinaryInDeb, "package")
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

// debMember returns the regular file member (a path without ./) of the data.tar.gz of a .deb: an ar archive whose members are
// debian-binary, control.tar.* and data.tar.*. nfpm.yaml builds gzip (deb.compression); any other compression is refused.
func debMember(deb, member string) ([]byte, error) {
	f, err := os.Open(deb) //nolint:gosec // the package the maintainer built, named by make
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readDebMember(bufio.NewReader(f), member, deb)
}

func readDebMember(r io.Reader, member, deb string) ([]byte, error) {
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
			return tarMember(io.LimitReader(r, size), member, deb)
		}
		if _, err := io.CopyN(io.Discard, r, size+size%2); err != nil {
			return nil, fmt.Errorf("%s: %w", deb, err)
		}
	}
}

func tarMember(gz io.Reader, member, deb string) ([]byte, error) {
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
	pre := fs.Bool("preflight", false, "only the version, floor and tree checks (before the long scans)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o := gatesOpts{Version: *version, MinSequence: *minSeq, Platforms: strings.Split(*plats, ","), PrevIndex: *prev, DebDir: *debDir, Repo: *repo, Preflight: *pre}
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
	}
	return Gates(ctx, execRun, o, stdout)
}
