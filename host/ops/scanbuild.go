package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/host/api"
)

// The scan image is built on the box (D-57 (2), D-113 (7), D-147). Vedette never builds or publishes an image with nmap in it (D-4,
// docs/LEGAL.md): the signed image ghcr.io/knt048/vedette-scan is a base (Debian slim, vedette-sensor, nuclei, the template pack), and
// after container.pull has pulled it by the verified digest and tagged it, the host runs one podman build over a context that holds only
// the Containerfile below, with the fixed argv of podmanargv.go. The result is localhost/vedette-scan-nmap:<version>; the unit pins it by
// image ID (there is no registry digest for a local build), and the effect check of every start compares the container's image ID.
//
// The build runs the RUN step as the root of the container, with the network (apt needs it: the host's apt mirror does not apply, the
// container contacts deb.debian.org; PRIVACY.md flow 6) and with trust in the apt keys of the base image: the base is signed by us, the
// package index is signed by Debian. It is the one place where the host runs code that a third party's package archive supplies, which is
// why it is a constant text, a fixed argv, a context made for this run and nothing else, and a check by effect afterwards.
//
// A failed build, or a built image whose "nmap --version" does not print a version at or above the floor, leaves the previous
// localhost/vedette-scan-nmap image as it was (the tag is put back on it) and ends the pull as scan_build_failed. The pull of the base
// still counts: it stays on the machine, tagged, and a retry pulls nothing.

const (
	// buildLimit bounds one podman build (a package index and one package, so a minute or two on a slow link).
	buildLimit = 15 * time.Minute
	// nmapCheckLimit bounds the run of "nmap --version" in the new image.
	nmapCheckLimit = time.Minute
	// maxNmapOutput bounds what "nmap --version" may print before the answer is not believed.
	maxNmapOutput = 4 << 10
)

// scanContainerfile is deploy/containers/scan/Containerfile.onbox without its comment header (a test keeps the two equal).
const scanContainerfile = `ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG NMAP_MIN_VERSION
USER 0
RUN set -eu; \
    [ -n "${NMAP_MIN_VERSION}" ] || exit 1; \
    apt-get update; \
    apt-get install -y --no-install-recommends nmap; \
    rm -rf /var/lib/apt/lists/*; \
    have="$(nmap --version | sed -n 's/^Nmap version \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')"; \
    [ -n "${have}" ] || { echo "cannot read the nmap version" >&2; exit 1; }; \
    dpkg --compare-versions "${have}" ge "${NMAP_MIN_VERSION}" || { echo "nmap ${have} is older than the floor ${NMAP_MIN_VERSION}" >&2; exit 1; }
USER 65532:65532
ENTRYPOINT ["/vedette-sensor"]
`

// nmapVersionLineRE is the first line of "nmap --version": "Nmap version 7.95 ( https://nmap.org )".
var nmapVersionLineRE = regexp.MustCompile(`^Nmap version ([0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?[A-Za-z0-9.+~-]{0,16})( .{0,80})?$`)

// ParseNmapVersion reads the output of "nmap --version" (4 KiB at most) and returns the version of its first line, which must have the
// form of nmap's own and be at least the floor (major.minor). Anything else is an error. Exported for fuzzing.
func ParseNmapVersion(out []byte) (string, error) { return parseNmapVersion(out) }

func parseNmapVersion(out []byte) (string, error) {
	if len(out) == 0 || len(out) > maxNmapOutput {
		return "", errors.New("ops: nmap printed no usable version")
	}
	line, _, _ := strings.Cut(string(out), "\n")
	m := nmapVersionLineRE.FindStringSubmatch(line)
	if m == nil {
		return "", errors.New("ops: the first line of nmap --version is not nmap's own")
	}
	if !atLeast(m[1], nmapFloor) {
		return "", fmt.Errorf("ops: nmap %s is below the floor %s", m[1], nmapFloor)
	}
	return m[1], nil
}

// atLeast compares the major.minor of two versions that passed nmapVersionLineRE (the floor is "N.M").
func atLeast(v, floor string) bool {
	num := func(s string) (int, int) {
		p := strings.SplitN(s, ".", 3)
		a, _ := strconv.Atoi(p[0])
		b, _ := strconv.Atoi(strings.TrimRightFunc(p[1], func(r rune) bool { return r < '0' || r > '9' }))
		return a, b
	}
	va, vb := num(v)
	fa, fb := num(floor)
	return va > fa || va == fa && vb >= fb
}

// builtScan is what a build leaves: the ID of the image as the "digest" the unit pins, and the nmap version it holds.
type builtScan struct{ digest, nmap string }

// buildContext makes the directory a build runs over: private to the host, empty before the Containerfile (and an earlier run's leftovers
// are removed first: commands run under the write lock, so no build is running), holding nothing else.
func (o *Ops) buildContext() (string, error) {
	root := o.stateFile("build")
	if err := os.RemoveAll(root); err != nil {
		return "", err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(root, "scan-")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "Containerfile"), []byte(scanContainerfile), 0o600); err != nil {
		_ = os.RemoveAll(root)
		return "", err
	}
	return dir, nil
}

// imageIDOf asks podman for the ID of the one image a reference names ("" when there is none or the answer is not usable).
func (o *Ops) imageIDOf(ctx context.Context, ref string) string {
	args, err := inspectImageArgv(ref)
	if err != nil {
		return ""
	}
	cctx, cancel := context.WithTimeout(ctx, probeLimit)
	defer cancel()
	res, code, err := o.exec(cctx, binPodman, args...)
	if err != nil || code != 0 || res.Truncated || len(res.Stdout) > maxInspectOutput {
		return ""
	}
	var docs []imageDoc
	dec := json.NewDecoder(bytes.NewReader(res.Stdout))
	if dec.Decode(&docs) != nil {
		return ""
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) || len(docs) != 1 {
		return ""
	}
	d := docs[0]
	if !imageIDRE.MatchString(d.ID) || (d.Os != "" && d.Os != "linux") || (d.Architecture != "" && d.Architecture != o.arch()) {
		return ""
	}
	return d.ID
}

// buildScan builds localhost/vedette-scan-nmap:<version> from the verified base and checks it by running nmap in it. The error is a
// *server.Failure (scan_build_failed). On any failure the tag points where it did before.
func (o *Ops) buildScan(ctx context.Context, logf func(string), plan *pullPlan) (builtScan, error) {
	tag, err := nmapTag(plan.version)
	if err != nil {
		return builtScan{}, fail(api.CodeScanBuildFailed, "The host could not build the build command.")
	}
	prev := o.imageIDOf(ctx, tag) // the image that has the tag now, put back if this build does not pass
	dir, err := o.buildContext()
	if err != nil {
		return builtScan{}, fail(api.CodeScanBuildFailed, "The host could not prepare the build directory.")
	}
	defer func() { _ = os.RemoveAll(filepath.Dir(dir)) }()
	argv, err := buildArgv(plan.digest, plan.version, dir)
	if err != nil {
		return builtScan{}, fail(api.CodeScanBuildFailed, "The host could not build the build command.")
	}
	logf("building " + tag + " from the verified base image; the build contacts the Debian package mirror (deb.debian.org) to install nmap")
	bctx, cancel := context.WithTimeout(ctx, buildLimit)
	_, code, berr := o.exec(bctx, binPodman, argv...) // the output is not read: the exit code and the checks below decide
	cancel()
	if berr != nil || code != 0 {
		logf("podman build failed; active scanning stays as it was (the box may not reach the Debian package mirror)")
		return builtScan{}, fail(api.CodeScanBuildFailed, "The image with nmap could not be built on this machine (podman build failed; the Debian package mirror may be unreachable). The base image was pulled and verified; the previous scan image is unchanged.")
	}
	id := o.imageIDOf(ctx, tag)
	if id == "" || id == prev {
		o.undoBuild(ctx, logf, tag, plan.version, prev, id)
		return builtScan{}, fail(api.CodeScanBuildFailed, "After the build, podman did not show a new image under the local name.")
	}
	ver, cerr := o.nmapVersionIn(ctx, id)
	if cerr != nil {
		logf("the built image did not pass the nmap check: " + cerr.Error())
		o.undoBuild(ctx, logf, tag, plan.version, prev, id)
		return builtScan{}, fail(api.CodeScanBuildFailed, "The built image does not run nmap at or above the minimum version; the previous scan image is unchanged.")
	}
	logf("built " + tag + " (image " + id + ", nmap " + ver + ")")
	return builtScan{digest: "sha256:" + id, nmap: ver}, nil
}

// nmapVersionIn runs "nmap --version" in the image (no network, no capability, read-only root) and returns the version it printed.
func (o *Ops) nmapVersionIn(ctx context.Context, id string) (string, error) {
	argv, err := nmapCheckArgv(id)
	if err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, nmapCheckLimit)
	defer cancel()
	res, code, err := o.exec(cctx, binPodman, argv...)
	if err != nil || code != 0 || res.Truncated {
		return "", errors.New("nmap did not run")
	}
	return parseNmapVersion(res.Stdout)
}

// undoBuild puts the tag back on the image that had it and removes the image this build made (by ID: it has no other name once the tag
// moved, and rmi has no force flag). Failures are logged; nothing here fails the run, which is already failed.
func (o *Ops) undoBuild(ctx context.Context, logf func(string), tag, version, prev, built string) {
	rctx := context.WithoutCancel(ctx)
	if prev != "" && prev != built {
		if argv, err := tagIDArgv(prev, version); err == nil {
			cctx, cancel := context.WithTimeout(rctx, probeLimit)
			if _, code, err := o.exec(cctx, binPodman, argv...); err != nil || code != 0 {
				logf("could not put " + tag + " back on the previous image")
			}
			cancel()
		}
	}
	if built != "" && built != prev {
		if argv, err := rmiArgv(built); err == nil {
			cctx, cancel := context.WithTimeout(rctx, rmiLimit)
			if _, code, err := o.exec(cctx, binPodman, argv...); err != nil || code != 0 {
				logf("could not remove the image that failed the check; retention removes it later")
			}
			cancel()
		}
	}
}
