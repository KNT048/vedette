package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/modfile"

	"github.com/knt048/vedette/internal/release"
)

// What the release gates check INSIDE the platform images they record (D-410), by reading files out of the image and never running
// it (the arm64 image on an amd64 machine, and the reverse, would need CPU emulation): core's /vedette links internal/release, so it
// must hold the production keys and not the throwaway ones (D-108 (2)); scan-base holds a nuclei built with the pinned Go and exactly
// the module versions of the patched go.mod (D-319; its source version is the SHA-256-checked archive of NUCLEI_VERSION, which the
// build info cannot show: a build from an archive is "(devel)"), the pack of SCAN_PACK_VERSION, and no nmap anywhere
// (D-4, D-113 (7)). `make images-check` runs the same scan-base check on its dev build (`release check-image`).

const (
	coreBinaryInImage  = "vedette"                                        // core's ENTRYPOINT ["/vedette"]
	nucleiInImage      = "usr/local/bin/nuclei"                           // scan-base/Containerfile
	packIndexInImage   = "usr/local/share/vedette/nuclei-pack/index.json" // the default of vedette-sensor active --nuclei-index
	pinsFile           = "deploy/containers/pins.env"
	nucleiGoMod        = "deploy/containers/scan-base/nuclei/go.mod"
	committedPackIndex = "content/nucleipack/index.json" // the copy make scan-pack commits; the image's index.json is the same file
)

// imageExpect is what the images of this tree must hold, read from the tree (the gates already checked it is the clean tag).
type imageExpect struct {
	Keys        []string      // the production minisign key lines core must contain
	GoVersion   string        // "go1.26.11": the Go of GOLANG_IMAGE, which builds nuclei
	NucleiMod   *modfile.File // the patched go.mod nuclei is built with
	PackVersion string        // SCAN_PACK_VERSION
	PackSHA256  string        // the "sha256" label of the pack index (committed copy)
}

// parsePins reads pins.env: KEY=VALUE lines, comments and blank lines (the Makefile includes it, so no quotes or spaces).
func parsePins(raw []byte) (map[string]string, error) {
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok || k == "" || strings.ContainsAny(v, " \t\"'$") {
			return nil, fmt.Errorf("%s: line %q is not KEY=VALUE", pinsFile, l)
		}
		m[k] = v
	}
	return m, sc.Err()
}

// packLabel is the version and the sha256 label of a pack index (scripts/scanpack).
func packLabel(raw []byte, what string) (version, sum string, err error) {
	var idx struct {
		Version string `json:"version"`
		SHA256  string `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		return "", "", fmt.Errorf("%s is not a pack index: %w", what, err)
	}
	if idx.Version == "" || !sha256HexRE.MatchString(idx.SHA256) {
		return "", "", fmt.Errorf("%s has no version or no sha256 label", what)
	}
	return idx.Version, idx.SHA256, nil
}

// loadImageExpect reads the expectations from the repository at repo; keys are the production key lines (nil: core is not checked).
func loadImageExpect(repo string, keys []string) (imageExpect, error) {
	e := imageExpect{Keys: keys}
	raw, err := readSmall(filepath.Join(repo, pinsFile), 64<<10)
	if err != nil {
		return e, err
	}
	pins, err := parsePins(raw)
	if err != nil {
		return e, err
	}
	// GOLANG_IMAGE=docker.io/library/golang:1.26.11-trixie@sha256:… -> go1.26.11
	_, tag, _ := strings.Cut(pins["GOLANG_IMAGE"], "golang:")
	tag, _, _ = strings.Cut(tag, "@")
	ver, _, _ := strings.Cut(tag, "-")
	if ver == "" || strings.Trim(ver, "0123456789.") != "" {
		return e, fmt.Errorf("%s: cannot read the Go version of GOLANG_IMAGE %q", pinsFile, pins["GOLANG_IMAGE"])
	}
	e.GoVersion = "go" + ver
	if e.PackVersion = pins["SCAN_PACK_VERSION"]; e.PackVersion == "" {
		return e, fmt.Errorf("%s has no SCAN_PACK_VERSION", pinsFile)
	}
	if raw, err = readSmall(filepath.Join(repo, committedPackIndex), 64<<20); err != nil {
		return e, err
	}
	v, sum, err := packLabel(raw, committedPackIndex)
	if err != nil {
		return e, err
	}
	if v != e.PackVersion {
		return e, fmt.Errorf("%s is pack %s, pins.env says %s: run make scan-pack", committedPackIndex, v, e.PackVersion)
	}
	e.PackSHA256 = sum
	if raw, err = readSmall(filepath.Join(repo, nucleiGoMod), 1<<20); err != nil {
		return e, err
	}
	if e.NucleiMod, err = modfile.Parse(nucleiGoMod, raw, nil); err != nil {
		return e, err
	}
	if e.NucleiMod.Module == nil {
		return e, fmt.Errorf("%s has no module line", nucleiGoMod)
	}
	return e, nil
}

// checkNucleiBuild refuses a nuclei whose build information is not the pinned build: the Go of GOLANG_IMAGE, the module of the patched
// go.mod, and every linked module at exactly the version that go.mod requires (no substring match: go1.27.1 is not go1.27.10).
func checkNucleiBuild(what string, bi *buildinfo.BuildInfo, e imageExpect) error {
	if bi.GoVersion != e.GoVersion {
		return fmt.Errorf("%s was built with %s, the pinned Go is %s (GOLANG_IMAGE)", what, bi.GoVersion, e.GoVersion)
	}
	if bi.Main.Path != e.NucleiMod.Module.Mod.Path {
		return fmt.Errorf("%s is module %q, not %s of %s", what, bi.Main.Path, e.NucleiMod.Module.Mod.Path, nucleiGoMod)
	}
	req := map[string]string{}
	for _, r := range e.NucleiMod.Require {
		req[r.Mod.Path] = r.Mod.Version
	}
	repl := map[string]string{} // a replace applies to the required version only when it names one (`x v1.2.3 => y`)
	for _, r := range e.NucleiMod.Replace {
		if r.Old.Version == "" || r.Old.Version == req[r.Old.Path] {
			repl[r.Old.Path] = r.New.Path + "@" + r.New.Version
		}
	}
	for _, d := range bi.Deps {
		want, ok := req[d.Path]
		if !ok {
			return fmt.Errorf("%s links %s %s, which %s does not require", what, d.Path, d.Version, nucleiGoMod)
		}
		if d.Version != want {
			return fmt.Errorf("%s links %s %s, %s requires %s", what, d.Path, d.Version, nucleiGoMod, want)
		}
		got := ""
		if d.Replace != nil {
			got = d.Replace.Path + "@" + d.Replace.Version
		}
		if got != repl[d.Path] {
			return fmt.Errorf("%s links %s replaced by %q, %s says %q", what, d.Path, got, nucleiGoMod, repl[d.Path])
		}
	}
	return nil
}

// imageKinds are the images whose files are checked, by local name.
var imageKinds = map[string]bool{"core": true, "scan-base": true}

// checkImageTar checks the exported filesystem (a tar, as `podman export` writes it) of one platform image of kind.
func checkImageTar(tarPath, what, kind string, e imageExpect) error {
	want := map[string]bool{}
	switch kind {
	case "core":
		want[coreBinaryInImage] = true
	case "scan-base":
		want[nucleiInImage], want[packIndexInImage] = true, true
	default:
		return fmt.Errorf("no file check for image %q", kind)
	}
	f, err := os.Open(tarPath) //nolint:gosec // the temporary export this tool wrote
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	files := map[string][]byte{}
	tr := tar.NewReader(bufio.NewReader(f))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%s: reading the exported filesystem: %w", what, err)
		}
		name := strings.TrimPrefix(path.Clean("/"+h.Name), "/")
		if kind == "scan-base" && path.Base(name) == "nmap" && h.Typeflag != tar.TypeDir { // a file, link or symlink named nmap, wherever it is
			return fmt.Errorf("%s holds /%s: nmap is never in a published image (D-4, D-113 (7))", what, name)
		}
		if !want[name] {
			continue
		}
		if h.Typeflag != tar.TypeReg || h.Size > maxBinary {
			return fmt.Errorf("%s: /%s is not a regular file of at most %d MB", what, name, maxBinary>>20)
		}
		if files[name], err = io.ReadAll(tr); err != nil {
			return fmt.Errorf("%s: /%s: %w", what, name, err)
		}
	}
	for name := range want {
		if files[name] == nil {
			return fmt.Errorf("%s has no /%s", what, name)
		}
	}
	switch kind {
	case "core":
		p := what + ": /" + coreBinaryInImage
		// The image build context has no .git (.containerignore), so /vedette records no VCS state; the version label, the floor label
		// and the config digest the gates record tie it to the tree. What the binary itself must show: no throwaway keys, the real ones.
		if err := checkBinaryData(p, files[coreBinaryInImage], BinaryRules{}); err != nil {
			return err
		}
		return keysIn(p, files[coreBinaryInImage], e.Keys)
	default: // scan-base
		bi, err := buildinfo.Read(bytes.NewReader(files[nucleiInImage]))
		if err != nil {
			return fmt.Errorf("%s: /%s has no Go build information: %w", what, nucleiInImage, err)
		}
		if err := checkNucleiBuild(what+": /"+nucleiInImage, bi, e); err != nil {
			return err
		}
		v, sum, err := packLabel(files[packIndexInImage], what+": /"+packIndexInImage)
		if err != nil {
			return err
		}
		if v != e.PackVersion || sum != e.PackSHA256 {
			return fmt.Errorf("%s: the pack is %s (sha256 %s), this tree pins %s (sha256 %s): a stale pack (make scan-pack, then make images)", what, v, sum, e.PackVersion, e.PackSHA256)
		}
		return nil
	}
}

// checkImageFiles exports the filesystem of image (a name or an image ID; a platform image for the gates) with container (podman or
// docker) into a temporary directory, checks it (checkImageTar) and removes the container and the export on every path.
func checkImageFiles(ctx context.Context, run runFunc, container, image, kind string, e imageExpect) error {
	tmp, err := os.MkdirTemp("", "vedette-image-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	var id [6]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	name := "vedette-check-" + hex.EncodeToString(id[:])
	// removed on every path, a create killed half way (timeout, Ctrl-C) included: rm of a name that does not exist is harmless
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		_, _ = run(rctx, container, "rm", "-f", "-v", name)
	}()
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	// create only: nothing runs, so another platform's image needs no emulation; --pull=never: a missing image is an error, not a download
	if _, err := run(cctx, container, "create", "--pull=never", "--name", name, image); err != nil {
		return fmt.Errorf("%s: %w", image, err)
	}
	// ponytail: the whole filesystem lands in TMPDIR (a few hundred MB for scan-base, bounded per wanted file by maxBinary, not in total);
	// stream `export` into the tar reader if an image ever outgrows the disk.
	ectx, cancel2 := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel2()
	out := filepath.Join(tmp, "fs.tar")
	if _, err := run(ectx, container, "export", "-o", out, name); err != nil {
		return fmt.Errorf("%s: %w", image, err)
	}
	return checkImageTar(out, image, kind, e)
}

// cmdCheckImage is the scan-base (or core) file check of the gates on one local image, for make images-check.
func cmdCheckImage(ctx context.Context, args []string, stdout io.Writer) error {
	fs := newFlags("check-image")
	image := fs.String("image", "", "local image name or ID (one platform)")
	kind := fs.String("kind", "", "scan-base or core")
	container := fs.String("container", "podman", "podman or docker")
	repo := fs.String("repo", ".", "repository root (pins.env, the patched nuclei go.mod, the committed pack index)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *image == "" || !imageKinds[*kind] || (*container != "podman" && *container != "docker") {
		return errors.New("check-image needs -image, -kind scan-base|core and -container podman|docker")
	}
	var keys []string
	if *kind == "core" {
		active, backup, testOnly := release.EmbeddedMinisignKeys()
		if testOnly || active == "" || backup == "" {
			return errors.New("this checker was built with the throwaway keys or none: run it with GOFLAGS= and without -tags")
		}
		keys = []string{active, backup}
	}
	e, err := loadImageExpect(*repo, keys)
	if err != nil {
		return err
	}
	if err := checkImageFiles(ctx, execRun, *container, *image, *kind, e); err != nil {
		return err
	}
	say(stdout, "ok: %s: %s", *image, imageOK(*kind, e))
	return nil
}

// imageOK says what a passed file check proved.
func imageOK(kind string, e imageExpect) string {
	if kind == "core" {
		return "/vedette holds the production release keys, no -tags " + testKeysTag
	}
	return fmt.Sprintf("nuclei built with %s and exactly the modules of %s, pack %s, no nmap", e.GoVersion, nucleiGoMod, e.PackVersion)
}
