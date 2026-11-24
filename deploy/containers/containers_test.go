// Package containers checks the text of the Containerfiles and their pins. It builds nothing: the effect (the image runs, the
// binaries are the pinned ones) is checked by `make images-check`, which builds and runs them.
package containers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec" //nolint:depguard // the test runs go and make with fixed argv, no shell; SYS-1 is about the product
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/ops"
)

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func pins(t *testing.T) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, l := range strings.Split(read(t, "pins.env"), "\n") {
		if l = strings.TrimSpace(l); l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok || strings.ContainsAny(v, " \t\"'$") {
			t.Fatalf("pins.env line %q: KEY=VALUE only, no spaces, quotes or $ (make includes the file)", l)
		}
		m[k] = v
	}
	return m
}

var (
	digestRef = regexp.MustCompile(`^[a-z0-9./-]+(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$`)
	sha256RE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Every pin is a version or a hash, never "latest", and every image is named by digest: a rebuilt tag cannot change what we ship.
func TestPinsAreExact(t *testing.T) {
	t.Parallel()
	p := pins(t)
	for _, k := range []string{"DEBIAN_IMAGE", "GOLANG_IMAGE", "DISTROLESS_IMAGE", "ZAP_IMAGE"} {
		if !digestRef.MatchString(p[k]) {
			t.Errorf("%s=%q must be repo[:tag]@sha256:<64 hex>", k, p[k])
		}
	}
	for _, k := range []string{"NUCLEI_SRC_SHA256", "NUCLEI_TEMPLATES_SHA256"} {
		if !sha256RE.MatchString(p[k]) {
			t.Errorf("%s=%q must be a lower-case SHA-256", k, p[k])
		}
	}
	for _, k := range []string{"NUCLEI_VERSION", "NUCLEI_TEMPLATES_VERSION"} {
		if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(p[k]) {
			t.Errorf("%s=%q must be MAJOR.MINOR.PATCH", k, p[k])
		}
	}
	if !regexp.MustCompile(`^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,4}$`).MatchString(p["SCAN_PACK_VERSION"]) {
		t.Errorf("SCAN_PACK_VERSION=%q must be AAAA.M.N (modules/scan/pack)", p["SCAN_PACK_VERSION"])
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(p["OPENCANARY_VERSION"]) {
		t.Errorf("OPENCANARY_VERSION=%q must be MAJOR.MINOR.PATCH", p["OPENCANARY_VERSION"])
	}
	if !regexp.MustCompile(`^[0-9]+:[0-9]+\.[0-9]+$`).MatchString(p["SAMBA_MIN_VERSION"]) {
		t.Errorf("SAMBA_MIN_VERSION=%q is the Debian floor, epoch:major.minor, of the Samba the build takes from the repository", p["SAMBA_MIN_VERSION"])
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(p["NMAP_MIN_VERSION"]) {
		t.Errorf("NMAP_MIN_VERSION=%q is the floor, major.minor, of the nmap the box installs", p["NMAP_MIN_VERSION"])
	}
	// A Debian security update laid over the base: an exact Debian version, a debian-security snapshot time, a hash per architecture
	if !regexp.MustCompile(`^[0-9]+:[A-Za-z0-9.+~-]+$`).MatchString(p["ZLIB1G_VERSION"]) {
		t.Errorf("ZLIB1G_VERSION=%q must be the exact Debian version, epoch included", p["ZLIB1G_VERSION"])
	}
	if !regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`).MatchString(p["ZLIB1G_SNAPSHOT"]) {
		t.Errorf("ZLIB1G_SNAPSHOT=%q must be a snapshot.debian.org timestamp (yyyymmddThhmmssZ)", p["ZLIB1G_SNAPSHOT"])
	}
	for _, k := range []string{"ZLIB1G_SHA256_AMD64", "ZLIB1G_SHA256_ARM64"} {
		if !sha256RE.MatchString(p[k]) {
			t.Errorf("%s=%q must be a lower-case SHA-256", k, p[k])
		}
	}
	if _, has := p["NMAP_VERSION"]; has {
		t.Error("nmap is not pinned to an exact version: security fixes must flow in")
	}
	// the golang build image is the Go of go.mod
	goMod := read(t, "../../go.mod")
	m := regexp.MustCompile(`(?m)^go ([0-9]+\.[0-9]+\.[0-9]+)$`).FindStringSubmatch(goMod)
	if m == nil || !strings.HasPrefix(p["GOLANG_IMAGE"], "docker.io/library/golang:"+m[1]+"-") {
		t.Errorf("GOLANG_IMAGE=%q must be the Go of go.mod (%v)", p["GOLANG_IMAGE"], m)
	}
	for k, v := range p {
		if strings.Contains(strings.ToLower(v), "latest") {
			t.Errorf("%s=%q: nothing is pinned to latest", k, v)
		}
	}
}

// No Containerfile has a FROM that is not an ARG filled from pins.env (digest-pinned) or an earlier stage, and none runs as root at the
// end: the unit says User= with the host's sensor uid, and the image's own default is the same kind of user.
func TestContainerfilesUsePinnedBasesAndEndNonRoot(t *testing.T) {
	t.Parallel()
	for _, f := range []string{"sensor/Containerfile", "scan-base/Containerfile", "core/Containerfile", "scan/Containerfile.onbox", "honeypot/Containerfile"} {
		text := read(t, f)
		stages := map[string]bool{}
		lastUser := ""
		for _, l := range strings.Split(text, "\n") {
			fields := strings.Fields(l)
			if len(fields) == 0 {
				continue
			}
			switch strings.ToUpper(fields[0]) {
			case "FROM":
				if strings.HasPrefix(fields[1], "--") { // --platform=$BUILDPLATFORM
					fields = append(fields[:1], fields[2:]...)
				}
				if !strings.HasPrefix(fields[1], "${") && !stages[fields[1]] {
					t.Errorf("%s: %q is not an ARG from pins.env or an earlier stage", f, l)
				}
				if len(fields) == 4 && strings.EqualFold(fields[2], "AS") {
					stages[fields[3]] = true
				}
				lastUser = ""
			case "USER":
				lastUser = fields[1]
			}
		}
		if lastUser == "" || lastUser == "0" || strings.HasPrefix(lastUser, "0:") || lastUser == "root" {
			t.Errorf("%s: the last stage must end with a numeric non-root USER, got %q", f, lastUser)
		}
	}
}

// The sensor image: the binary at the path the unit's HealthCmd runs, started in exec form (no shell in the image), built static
// with the SemVer version put in by -ldflags.
func TestSensorImageFitsItsUnit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ file, svc string }{{"sensor/Containerfile", "sensor"}, {"scan-base/Containerfile", "scan"}} {
		text := read(t, tc.file)
		unit, err := ops.RenderUnit(tc.svc, "sha256:"+strings.Repeat("a", 64), true, 10001, 10002, 10003, 10004)
		if err != nil {
			t.Fatal(err)
		}
		var health []string
		for _, l := range strings.Split(string(unit), "\n") {
			if v, ok := strings.CutPrefix(l, "HealthCmd="); ok {
				if err := json.Unmarshal([]byte(v), &health); err != nil {
					t.Fatalf("%s: %v", tc.svc, err)
				}
			}
		}
		if len(health) == 0 || !strings.Contains(text, "COPY --from=build /out/vedette-sensor "+health[0]+"\n") {
			t.Errorf("%s: the image must hold the binary at %q, the path of the unit's HealthCmd", tc.file, health)
		}
		for _, want := range []string{`ENTRYPOINT ["/vedette-sensor"]`, "CGO_ENABLED=0", "-X main.version=${VERSION}", "-trimpath"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: missing %q", tc.file, want)
			}
		}
		if strings.Contains(text, "ENTRYPOINT /") || strings.Contains(text, "CMD /") {
			t.Errorf("%s: shell form of ENTRYPOINT or CMD", tc.file)
		}
	}
}

// docs/LEGAL.md: nmap is never in an image the project builds and publishes. The published scan-base holds the
// sensor binary, nuclei and the template pack only; vedette-host adds nmap on the box (scan/Containerfile.onbox, slice SP-6).
func TestNmapIsOnlyInTheOnBoxContainerfile(t *testing.T) {
	t.Parallel()
	nmap := regexp.MustCompile(`(?i)\bnmap\b`)
	for _, f := range []string{"sensor/Containerfile", "scan-base/Containerfile", "core/Containerfile"} {
		for _, l := range strings.Split(read(t, f), "\n") {
			if t := strings.TrimSpace(l); strings.HasPrefix(t, "#") {
				continue
			}
			if nmap.MatchString(l) {
				t.Errorf("%s installs or names nmap: %q", f, l)
			}
		}
	}
	on := read(t, "scan/Containerfile.onbox")
	if !strings.Contains(on, "apt-get install -y --no-install-recommends nmap;") || !strings.Contains(on, "FROM ${BASE_IMAGE}") ||
		!strings.Contains(on, "dpkg --compare-versions") || !strings.Contains(on, "NMAP_MIN_VERSION") {
		t.Error("the on-box Containerfile must be FROM the signed scan-base, install the current nmap and check the version floor by effect")
	}
	if strings.Contains(on, "nmap=") {
		t.Error("the on-box Containerfile must not pin an exact nmap version")
	}
}

// nuclei is built from the source archive of the pinned tag, checked against the pinned SHA-256 before it is unpacked, with our
// patched go.mod/go.sum, and lands where the worker looks for it; the pack lands where the worker (index) and nucleiargv (templates) expect it.
func TestScanBaseVerifiesNucleiAndPlacesThePack(t *testing.T) {
	t.Parallel()
	text := read(t, "scan-base/Containerfile")
	for _, want := range []string{"sha256sum -c", "NUCLEI_SRC_SHA256", "scan-base/nuclei/go.mod", "scan-base/nuclei/go.sum", "GOFLAGS=-mod=readonly", "./cmd/nuclei", "/usr/local/bin/nuclei",
		"/usr/share/vedette/nuclei-templates", "/usr/local/share/vedette/nuclei-pack/index.json"} {
		if !strings.Contains(text, want) {
			t.Errorf("scan-base/Containerfile: missing %q", want)
		}
	}
	if !strings.Contains(text, "ARG SCAN_PACK_VERSION") || !strings.Contains(text, `index.json is not pack version ${SCAN_PACK_VERSION}`) {
		t.Error("scan-base must fail when index.json is not the pinned pack version (a stale pack)")
	}
	// The worker's own-IP fence speaks HTTPS, so the image carries the CA bundle and its copyright, checked present
	// in the pinned Go image when it is built.
	for _, want := range []string{"COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt",
		"COPY --from=build /usr/share/doc/ca-certificates/copyright", "test -s /etc/ssl/certs/ca-certificates.crt"} {
		if !strings.Contains(text, want) {
			t.Errorf("scan-base/Containerfile: missing %q (the CA bundle of the own-IP fence)", want)
		}
	}
	if strings.Contains(text, "nuclei -update") || strings.Contains(text, "-ut") {
		t.Error("no template download or update in the image")
	}
}

// containerStage is one FROM ... of a Containerfile: its FROM line and the text after it.
type containerStage struct{ from, body string }

func stagesOf(text string) []containerStage {
	var out []containerStage
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(l)), "FROM ") {
			out = append(out, containerStage{from: l})
			continue
		}
		if len(out) > 0 {
			out[len(out)-1].body += l + "\n"
		}
	}
	return out
}

func (s containerStage) hasRun() bool {
	for _, l := range strings.Split(s.body, "\n") {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(l)), "RUN ") {
			return true
		}
	}
	return false
}

// Multi-arch without CPU emulation: a stage that runs anything (RUN) is on the build machine, so cross-compiling needs
// no qemu; the last stage, the one of the target architecture, only COPYs. A Go build stage compiles for TARGETOS/TARGETARCH.
func TestPublishedImagesBuildWithoutEmulation(t *testing.T) {
	t.Parallel()
	for _, f := range []string{"sensor/Containerfile", "scan-base/Containerfile", "core/Containerfile", "honeypot/Containerfile"} {
		stages := stagesOf(read(t, f))
		if len(stages) < 2 {
			t.Fatalf("%s: expected a build stage and a final stage", f)
		}
		for i, s := range stages {
			last := i == len(stages)-1
			if last {
				if s.hasRun() {
					t.Errorf("%s: the final (target-arch) stage has a RUN, which would need CPU emulation on a foreign architecture: %q", f, s.from)
				}
				if strings.Contains(s.from, "BUILDPLATFORM") {
					t.Errorf("%s: the final stage must be the target platform: %q", f, s.from)
				}
				continue
			}
			// a stage with no RUN (the honeypot's `base`, read only for its dpkg status) runs nothing, so it needs no emulation either
			if s.hasRun() && !strings.Contains(s.from, "--platform=$BUILDPLATFORM ") {
				t.Errorf("%s: stage %q runs on the target platform; every stage before the last must be --platform=$BUILDPLATFORM", f, s.from)
			}
			if strings.Contains(s.body, "go build") {
				for _, want := range []string{"ARG TARGETOS\n", "ARG TARGETARCH\n", `GOOS="${TARGETOS}"`, `GOARCH="${TARGETARCH}"`, "CGO_ENABLED=0"} {
					if !strings.Contains(s.body, want) {
						t.Errorf("%s: Go stage %q is missing %q", f, s.from, want)
					}
				}
			}
		}
	}
	// nuclei is one source archive for every architecture, compiled for the target (checked above with the other Go stages)
	scan := read(t, "scan-base/Containerfile")
	if strings.Contains(scan, "nuclei_${NUCLEI_VERSION}_linux_") || !strings.Contains(scan, "archive/refs/tags/v${NUCLEI_VERSION}.tar.gz") {
		t.Error("scan-base: nuclei must be built from the tag archive, not taken from the release binaries")
	}
}

// The index sequence floor goes only where internal/release is linked: vedette-host, and core (the signed mitigation
// packs), which takes MIN_SEQUENCE too (Containerfile, Makefile core-image and images, compose). The sensor does not link it.
func TestOnlyHostLinksTheReleasePackage(t *testing.T) {
	t.Parallel()
	for bin, want := range map[string]bool{"vedette": true, "vedette-sensor": false, "vedette-host": true} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "list", "-deps", "./cmd/"+bin) //nolint:gosec // test: fixed argv
		cmd.Dir = "../.."
		cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list %s: %v", bin, err)
		}
		if got := strings.Contains(string(out), "\ngithub.com/knt048/vedette/internal/release\n"); got != want {
			t.Errorf("%s links internal/release = %v, want %v: the Makefile and the Containerfiles pass MIN_SEQUENCE to vedette-host and core only", bin, got, want)
		}
	}
}

// MIN_SEQUENCE: a plain decimal, validated by make, and put on the vedette-host link line next to main.version.
func TestMinSequenceFlag(t *testing.T) {
	t.Parallel()
	run := func(args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "make", append([]string{"--no-print-directory"}, args...)...) //nolint:gosec // test: fixed argv
		cmd.Dir = "../.."
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	for _, bad := range []string{"", "-1", "007", "1.5", "0x10", "1 2", "1234567890123456789", "7;id", "$(id)"} {
		if out, err := run("check-min-sequence", "MIN_SEQUENCE="+bad); err == nil {
			t.Errorf("MIN_SEQUENCE=%q was accepted: %s", bad, out)
		}
	}
	for _, good := range []string{"0", "7", "1234567890123456"} {
		if out, err := run("check-min-sequence", "MIN_SEQUENCE="+good); err != nil {
			t.Errorf("MIN_SEQUENCE=%q was refused: %v %s", good, err, out)
		}
	}
	// core links internal/release too: both image targets hand the floor to its build, the other images get none
	for _, target := range []string{"core-image", "images"} {
		out, err := run("-n", target, "MIN_SEQUENCE=7")
		if err != nil {
			t.Fatal(target, err, out)
		}
		for _, line := range strings.FieldsFunc(out, func(r rune) bool { return r == '\n' || r == '&' }) { // images: one recipe line, builds joined by &&
			core := strings.Contains(line, "deploy/containers/core/Containerfile")
			if has := strings.Contains(line, "--build-arg MIN_SEQUENCE=7"); core != has && (core || strings.Contains(line, "/Containerfile")) {
				t.Errorf("make %s: MIN_SEQUENCE on a build line: core=%v has=%v: %s", target, core, has, line)
			}
		}
		if !strings.Contains(out, "core/Containerfile") || !strings.Contains(out, "--build-arg MIN_SEQUENCE=7") {
			t.Errorf("make %s does not pass MIN_SEQUENCE to the core build:\n%s", target, out)
		}
	}
	out, err := run("-n", "host-deb", "VERSION=1.2.3", "MIN_SEQUENCE=7")
	if err != nil {
		t.Fatal(err, out)
	}
	if !strings.Contains(out, "-X main.version=1.2.3 -X github.com/knt048/vedette/internal/release.MinSequenceText=7\"") {
		t.Errorf("host-deb does not pass MIN_SEQUENCE to the linker:\n%s", out)
	}
	// by effect: a binary linked with exactly that -X token (cut from the make output) holds the number
	_, tail, _ := strings.Cut(out, "-X github.com/knt048/vedette/internal/release.MinSequenceText=")
	token := "github.com/knt048/vedette/internal/release.MinSequenceText=" + strings.SplitN(tail, "\"", 2)[0]
	bin := filepath.Join(t.TempDir(), "release.test")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "test", "-c", "-ldflags", "-X "+token, "-o", bin, "./internal/release") //nolint:gosec // test: the token is cut from our own make output
	build.Dir = "../.."
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go test -c: %v\n%s", err, b)
	}
	runBin := exec.CommandContext(ctx, bin, "-test.run", "^TestMinSequenceTextIsWhatTheLinkerSet$", "-test.v") //nolint:gosec // test: the binary we just built
	runBin.Env = append(os.Environ(), "VEDETTE_WANT_MIN_SEQUENCE=7")
	if b, err := runBin.CombinedOutput(); err != nil || !strings.Contains(string(b), "--- PASS") {
		t.Errorf("the linker flag did not reach MinSequenceText: %v\n%s", err, b)
	}
	if out, err = run("-n", "host-deb", "VERSION=1.2.3"); err != nil || !strings.Contains(out, "MinSequenceText=0\"") {
		t.Errorf("host-deb must default MIN_SEQUENCE to 0: %v\n%s", err, out)
	}
}

// The release preflight is wired into the targets (the effects are tested in scripts/release): host-deb checks the binary it built and
// gives nfpm a fixed file time; release-manifest passes the floor of the host to the index step.
func TestHostDebPreflightWiring(t *testing.T) {
	t.Parallel()
	run := func(args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "make", append([]string{"--no-print-directory", "-n"}, args...)...) //nolint:gosec // test: fixed argv
		cmd.Dir = "../.."
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	out, err := run("host-deb", "VERSION=1.2.3", "SOURCE_DATE_EPOCH=1700000000", "MIN_SEQUENCE=0")
	if err != nil {
		t.Fatal(err, out)
	}
	for _, want := range []string{"GOFLAGS= go run ./scripts/release check-binaries -release dist/host-deb/amd64/vedette-host", "SOURCE_DATE_EPOCH=1700000000 VERSION=1.2.3"} {
		if !strings.Contains(out, want) {
			t.Errorf("host-deb: %q missing:\n%s", want, out)
		}
	}
	if strings.Index(out, "go build") > strings.Index(out, "check-binaries") {
		t.Error("host-deb checks the binary before it is built")
	}
	// Refusals run for real: they stop before anything is built, so they are cheap.
	runReal := func(env []string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "make", append([]string{"--no-print-directory", "host-deb", "DEB_OUT=" + t.TempDir()}, args...)...) //nolint:gosec // test: fixed argv
		cmd.Dir = "../.."
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	refused := func(why string, env []string, args ...string) {
		t.Helper()
		if out, err := runReal(env, args...); err == nil || !strings.Contains(out, why) || strings.Contains(out, "go build") {
			t.Errorf("%v %v: want a refusal with %q before the build: %v\n%s", env, args, why, err, out)
		}
	}
	refused("SOURCE_DATE_EPOCH must be Unix seconds", nil, "VERSION=1.2.3", "SOURCE_DATE_EPOCH=yesterday", "MIN_SEQUENCE=0")
	refused("needs the sequence floor", []string{"MIN_SEQUENCE="}, "VERSION=1.2.3", "SOURCE_DATE_EPOCH=1700000000")
	refused("-overlay or -tags", []string{"GOFLAGS=-overlay=/nonexistent.json"}, "VERSION=1.2.3", "SOURCE_DATE_EPOCH=1700000000", "MIN_SEQUENCE=0")
	refused("-overlay or -tags", []string{"GOFLAGS=-p=2 -tags=releasetestkeys"}, "VERSION=1.2.3", "SOURCE_DATE_EPOCH=1700000000", "MIN_SEQUENCE=0")
	// a test version needs none of it (checked without building: the dry run prints the recipe the shell would run)
	if out, err = run("host-deb", "VERSION=1.2.3-test.1", "SOURCE_DATE_EPOCH=1700000000"); err != nil || strings.Contains(out, "needs the sequence floor") || strings.Contains(out, "check-binaries -release") {
		t.Errorf("a -test. version must skip the release preflight: %v\n%s", err, out)
	}
	if out, err = run("release-manifest", "RELEASE_PREV_INDEX=/nonexistent", "MIN_SEQUENCE=4"); err != nil || !strings.Contains(out, "-prev-index /nonexistent -min-sequence 4") {
		t.Errorf("release-manifest must pass MIN_SEQUENCE to the index step: %v\n%s", err, out)
	}
}

// make release-gates: the floor rule of host-deb before anything runs, then the gates in order, the floor and its index
// handed to the Go checks (which compare them, since make lets an environment MIN_SEQUENCE win), sbom and vuln kept (RELEASE=1).
func TestReleaseGatesWiring(t *testing.T) {
	t.Parallel()
	run := func(env []string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "make", append([]string{"--no-print-directory"}, args...)...) //nolint:gosec // test: fixed argv
		cmd.Dir = "../.."
		cmd.Env = append(os.Environ(), append([]string{"CONTAINER=podman", "RELEASE_PREV_INDEX=", "MAKEFLAGS=", "MAKELEVEL="}, env...)...) // not the caller's
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	out, err := run(nil, "-n", "release-gates", "VERSION=1.0.0", "RELEASE_PREV_INDEX=/nonexistent", "MIN_SEQUENCE=4")
	if err != nil {
		t.Fatal(err, out)
	}
	last := -1
	for _, want := range []string{
		"gates -preflight -version '1.0.0' -min-sequence '4' -prev-index '/nonexistent'",
		"vuln-scan IMAGE_TAG='1.0.0' RELEASE=1", "RELEASE=1 scripts/dev/supply-chain.sh scan",
		"sbom IMAGE_TAG='1.0.0' RELEASE=1", "RELEASE=1 scripts/dev/supply-chain.sh sbom",
		"go run ./scripts/noticescheck",
		"GOFLAGS= go run ./scripts/release gates -version '1.0.0' -min-sequence '4' -prev-index '/nonexistent'",
	} {
		i := strings.Index(out, want)
		if i <= last {
			t.Errorf("release-gates: %q missing or out of order:\n%s", want, out)
		}
		last = i
	}
	// refusals run for real and stop before any scan
	for _, c := range []struct {
		why  string
		env  []string
		args []string
	}{
		{"the release floor", []string{"MIN_SEQUENCE="}, []string{"VERSION=1.0.0"}},
		{"VERSION must be SemVer", nil, []string{"VERSION=v1.0.0", "MIN_SEQUENCE=0"}},
		{"CONTAINER=docker is not supported", []string{"CONTAINER=docker"}, []string{"VERSION=1.0.0", "MIN_SEQUENCE=0"}},
	} {
		if out, err := run(c.env, append([]string{"release-gates"}, c.args...)...); err == nil || !strings.Contains(out, c.why) || strings.Contains(out, "trivy") || strings.Contains(out, "go run") {
			t.Errorf("%v %v: want a refusal with %q before anything runs: %v\n%s", c.env, c.args, c.why, err, out)
		}
	}
}

// The release tools are pinned like the images: trivy by tag and by the digest of the multi-arch index, never "latest".
func TestToolPinsAreExact(t *testing.T) {
	t.Parallel()
	got := map[string]string{}
	for _, l := range strings.Split(read(t, "../tools.env"), "\n") {
		if l = strings.TrimSpace(l); l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok || strings.ContainsAny(v, " \t\"'$") {
			t.Fatalf("tools.env line %q: KEY=VALUE only, no spaces, quotes or $ (make includes the file)", l)
		}
		got[k] = v
	}
	if !regexp.MustCompile(`^docker\.io/aquasec/trivy:[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$`).MatchString(got["TRIVY_IMAGE"]) {
		t.Errorf("TRIVY_IMAGE=%q must be docker.io/aquasec/trivy:<MAJOR.MINOR.PATCH>@sha256:<64 hex>", got["TRIVY_IMAGE"])
	}
}

// The core image carries the pinned osquery packages: the build stage reads deploy/osquery/PINS (not a copy of the
// numbers), downloads from the official release, checks each file against its pinned SHA-256 before anything is copied, and the final stage
// copies the folder to the default of -osquery-dir. Nothing is downloaded when the box runs.
func TestCoreImageShipsThePinnedOsqueryPackages(t *testing.T) {
	t.Parallel()
	text := read(t, "core/Containerfile")
	stages := stagesOf(text)
	var osq, final string
	for _, s := range stages {
		if strings.Contains(s.from, " AS osquery") {
			osq = s.body
		}
	}
	final = stages[len(stages)-1].body
	if osq == "" {
		t.Fatal("core/Containerfile has no osquery stage")
	}
	for _, want := range []string{
		"COPY deploy/osquery/PINS /pins/osquery.pins", ". /pins/osquery.pins", "https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/",
		"${OSQUERY_DEB_AMD64_SHA256}  /out/${deb}\" | sha256sum -c -", "${OSQUERY_RPM_X86_64_SHA256}  /out/${rpm}\" | sha256sum -c -", "${OSQUERY_MSI_SHA256}  /out/${msi}\" | sha256sum -c -",
		"${OSQUERY_DEB_ARM64_SHA256}  /out/${deba}\" | sha256sum -c -", "${OSQUERY_RPM_AARCH64_SHA256}  /out/${rpma}\" | sha256sum -c -",
		"set -eu", "curl -fsSL --proto '=https' --proto-redir '=https' --max-time 600 -o",
		// the names the box serves (modules/agent-intake install.go mirrorFiles) and the scripts ask for
		`deb="osquery_${OSQUERY_VERSION}-1.linux_amd64.deb"`, `rpm="osquery-${OSQUERY_VERSION}-1.linux.x86_64.rpm"`, `msi="osquery-${OSQUERY_VERSION}.msi"`,
		`deba="osquery_${OSQUERY_VERSION}-1.linux_arm64.deb"`, `rpma="osquery-${OSQUERY_VERSION}-1.linux.aarch64.rpm"`,
	} {
		if !strings.Contains(osq, want) {
			t.Errorf("core/Containerfile osquery stage: missing %q", want)
		}
	}
	if strings.Contains(osq, "|| true") || regexp.MustCompile(`(?m)^ARG OSQUERY`).MatchString(text) {
		t.Error("core/Containerfile osquery stage: the pins come from deploy/osquery/PINS only, and a failed check must fail the build")
	}
	if !strings.Contains(final, "COPY --from=osquery /out/ /usr/share/vedette/osquery/\n") {
		t.Error("core/Containerfile: the final stage must copy the verified osquery folder to /usr/share/vedette/osquery/")
	}
	if !strings.Contains(read(t, "../../.dockerignore"), "\n!deploy/osquery\n") {
		t.Error(".dockerignore must let deploy/osquery into the build context")
	}
	if _, err := os.Stat("../osquery/PINS"); err != nil {
		t.Error("deploy/osquery/PINS is missing")
	}
}

// Every image carries the third-party license file: the build stage runs scripts/hostlicenses over the main package of the binary in
// the same RUN as the go build, the final stage copies it to /usr/share/doc/vedette/, the build context lets the generator in, and the core image
// ships the osquery license texts pinned by hash.
func TestEveryImageShipsItsThirdPartyLicenses(t *testing.T) {
	t.Parallel()
	for _, f := range []string{"core", "sensor", "scan-base", "honeypot"} {
		text := read(t, f+"/Containerfile")
		if !strings.Contains(text, "go run ./scripts/hostlicenses ") || !strings.Contains(text, "-out /out/licenses/third-party-licenses") {
			t.Errorf("%s/Containerfile: the build stage does not generate the third-party license file", f)
		}
		if !strings.Contains(text, "COPY --from=build /out/licenses/ /usr/share/doc/vedette/\n") {
			t.Errorf("%s/Containerfile: the final stage does not copy the license file to /usr/share/doc/vedette/", f)
		}
	}
	// scan-base also lists the modules linked into nuclei: the same generator, inside the nuclei source tree, offline from the
	// modules of its go.sum, shipped next to nuclei-LICENSE.md in both licence folders.
	scan := read(t, "scan-base/Containerfile")
	for _, want := range []string{
		"COPY --from=build /tools/hostlicenses /usr/local/bin/hostlicenses",
		"GOFLAGS=-mod=readonly GOPROXY=off \\\n    hostlicenses -goos \"${TARGETOS}\" -goarch \"${TARGETARCH}\" -pkg ./cmd/nuclei -name nuclei -out /out/third-party-licenses",
		"COPY --from=nuclei /out/third-party-licenses /usr/local/share/vedette/licenses/nuclei-third-party-licenses\n",
		"COPY --from=nuclei /out/third-party-licenses /usr/share/doc/vedette/nuclei-third-party-licenses\n",
	} {
		if !strings.Contains(scan, want) {
			t.Errorf("scan-base/Containerfile: the licences of nuclei's modules lack %q", want)
		}
	}
	core, pins := read(t, "core/Containerfile"), read(t, "../osquery/PINS")
	if !strings.Contains(core, "-name vedette-core -tags webui") {
		t.Error("core/Containerfile: the license list must be made with the same -tags webui as the binary")
	}
	if !strings.Contains(read(t, "../../.dockerignore"), "\n!scripts/hostlicenses\n") {
		t.Error(".dockerignore must let scripts/hostlicenses into the build context")
	}
	for _, n := range []string{"LICENSE", "LICENSE-Apache-2.0", "LICENSE-GPL-2.0"} {
		b, err := os.ReadFile("../osquery/" + n) //nolint:gosec // test: fixed file names
		if err != nil {
			t.Fatal(err)
		}
		if sum := fmt.Sprintf("%x", sha256.Sum256(b)); !strings.Contains(pins, sum) {
			t.Errorf("deploy/osquery/PINS does not pin the SHA-256 of %s (%s)", n, sum)
		}
		if !strings.Contains(core, "deploy/osquery/"+n) {
			t.Errorf("core/Containerfile does not copy deploy/osquery/%s", n)
		}
	}
}

// The core image carries its data and credentials directories, owned by the user it runs as, so the container-only compose can mount
// new named volumes on them without a root step. The directories are made in the build stage (the final stage has no RUN),
// 0750 each, and copied as the contents of /out/dirs/var/lib/ into /var/lib, so they keep that mode on buildah too. The parent
// /var/lib/vedette-creds is 0755: on the appliance core runs as core_uid (not 65532) and must traverse it to the creds volumes below.
func TestCoreImageOwnsItsVolumeDirectories(t *testing.T) {
	t.Parallel()
	text := read(t, "core/Containerfile")
	stages := stagesOf(text)
	build, final := stages[0].body, stages[len(stages)-1].body
	for _, d := range []string{
		"mkdir -p -m 0750 /out/dirs/var/lib/vedette /out/dirs/var/lib/vedette-creds/passive /out/dirs/var/lib/vedette-creds/active;",
		"chmod 0755 /out/dirs/var/lib/vedette-creds /out/dirs/var/lib\n",
	} {
		if !strings.Contains(build, d) {
			t.Errorf("core/Containerfile: the build stage does not contain %q", strings.TrimSpace(d))
		}
	}
	if l := "COPY --from=build --chown=65532:65532 /out/dirs/var/lib/ /var/lib/\n"; !strings.Contains(final, l) {
		t.Errorf("core/Containerfile: the final stage must contain %q (the directories are entries of the copy and keep 0750)", strings.TrimSpace(l))
	}
	if regexp.MustCompile(`(?m)chmod 07[0-4]0 [^\n]*/out/dirs/var/lib/vedette-creds( |;|\\|$)`).MatchString(build) {
		t.Error("core/Containerfile: /var/lib/vedette-creds must stay traversable (0755) for core_uid on the appliance")
	}
	if strings.Contains(final, "--chmod=0750 /out/dirs/") {
		t.Error("core/Containerfile: a COPY --chmod of a directory to a new destination gives that destination 0755 on buildah")
	}
	if regexp.MustCompile(`(?m)^COPY .* /$`).MatchString(final) {
		t.Error("core/Containerfile: a COPY to / rewrites the owner of the existing parents (/var, /var/lib)")
	}
	if !strings.Contains(final, "USER 65532:65532\n") {
		t.Error("core/Containerfile: the image's user is 65532:65532, the owner of the directories and the uid of the compose file")
	}
}

// The dev compose builds the images too (make dev-sensors): every build argument without a default in the Containerfiles must be
// passed by its x-build-args, or the build fails there and nowhere else.
func TestDevComposePassesEveryBuildArg(t *testing.T) {
	compose := read(t, "../compose/compose.yaml")
	for _, f := range []string{"scan-base/Containerfile", "sensor/Containerfile", "core/Containerfile"} {
		for _, m := range regexp.MustCompile(`(?m)^ARG ([A-Z0-9_]+)$`).FindAllStringSubmatch(read(t, f), -1) {
			if strings.HasPrefix(m[1], "TARGET") { // set by the builder
				continue
			}
			if !strings.Contains(compose, "  "+m[1]+": ") {
				t.Errorf("%s: ARG %s is not in deploy/compose/compose.yaml x-build-args", f, m[1])
			}
		}
	}
}

// The two published images on DEBIAN_IMAGE (scan-base, honeypot) lay the pinned zlib1g security update over the base, on the
// build machine (security-deb.sh checks the hash and writes the dpkg status), with every pin of pins.env passed by make, and scan-base's
// final stage copies the result; the build context lets the script in.
func TestDebianImagesTakeThePinnedSecurityUpdate(t *testing.T) {
	t.Parallel()
	call := `sh /usr/local/bin/security-deb.sh zlib1g zlib "${ZLIB1G_VERSION}" "${ZLIB1G_SNAPSHOT}" "$z" "${TARGETARCH}" /target/status `
	for _, f := range []string{"scan-base/Containerfile", "honeypot/Containerfile"} {
		text := read(t, f)
		for _, want := range []string{
			"ARG ZLIB1G_VERSION\n", "ARG ZLIB1G_SNAPSHOT\n", "ARG ZLIB1G_SHA256_AMD64\n", "ARG ZLIB1G_SHA256_ARM64\n",
			`amd64) z="${ZLIB1G_SHA256_AMD64}" ;; arm64) z="${ZLIB1G_SHA256_ARM64}" ;;`, call,
			"COPY deploy/containers/security-deb.sh /usr/local/bin/security-deb.sh\n", "COPY --from=base /var/lib/dpkg/status /target/status\n",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: missing %q", f, want)
			}
		}
	}
	stages := stagesOf(read(t, "scan-base/Containerfile"))
	if final := stages[len(stages)-1]; final.from != "FROM base" || !strings.Contains(final.body, "COPY --from=security /overlay/ /\n") {
		t.Errorf("scan-base: the final stage must be FROM base and copy the security overlay, got %q", final.from)
	}
	hp := read(t, "honeypot/Containerfile")
	if !strings.Contains(hp, call+"/rootfs; \\\n    cp /rootfs/var/lib/dpkg/status /target/updated-status; \\\n") ||
		!strings.Contains(hp, "-o Dir::State::status=/target/updated-status ") || !strings.Contains(hp, "assemble.py debs /dl /target/updated-status /rootfs") {
		t.Error("honeypot: apt and assemble.py must work from the updated status, /target/status stays the base's (for the inventory)")
	}
	mk := read(t, "../../Makefile")
	for _, k := range []string{"ZLIB1G_VERSION", "ZLIB1G_SNAPSHOT", "ZLIB1G_SHA256_AMD64", "ZLIB1G_SHA256_ARM64"} {
		if !regexp.MustCompile(`(?m)^PIN_ARGS := .* ` + k + `[ ,]`).MatchString(mk) {
			t.Errorf("Makefile PIN_ARGS does not pass %s", k)
		}
	}
	if !strings.Contains(read(t, "../../.dockerignore"), "\n!deploy/containers/security-deb.sh\n") {
		t.Error(".dockerignore must let deploy/containers/security-deb.sh into the build context")
	}
}

// security-deb.sh refuses, before any download and without creating its output, a base that already has the pinned version or a
// newer one (the overlay must be retired, never downgrade the base), a base of another architecture, a package the base lacks, and an
// argument with a newline. Offline: every case fails before the network is reached. Needs dpkg (--compare-versions), as on CI's Ubuntu.
func TestSecurityDebRefusesBeforeDownloading(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("dpkg is not installed (Debian/Ubuntu only)")
	}
	p := pins(t)
	ver, sha := p["ZLIB1G_VERSION"], p["ZLIB1G_SHA256_AMD64"]
	stanza := func(pkg, arch, v string) string {
		return "Package: " + pkg + "\nStatus: install ok installed\nArchitecture: " + arch + "\nVersion: " + v + "\n\n"
	}
	for _, c := range []struct{ name, status, version, want string }{
		{"base at the pinned version", stanza("zlib1g-dev", "amd64", "1:1.0") + stanza("zlib1g", "amd64", ver), ver, "DEBIAN_IMAGE carries the fix"},
		{"base newer than the pin", stanza("zlib1g", "amd64", strings.Replace(ver, "deb13u1", "deb13u2", 1)), ver, "DEBIAN_IMAGE carries the fix"},
		{"base of another architecture", stanza("zlib1g", "arm64", "1:1.0"), ver, "is not for amd64"},
		{"package matched as text, not as a regex", stanza("zlib1gX", "amd64", "1:1.0"), ver, "not in the base image's dpkg status"},
		{"newline in an argument", stanza("zlib1g", "amd64", "1:1.0"), ver + "\nx", "holds a newline"},
	} {
		dir := t.TempDir()
		status, out := filepath.Join(dir, "status"), filepath.Join(dir, "out")
		if err := os.WriteFile(status, []byte(c.status), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		//nolint:gosec // fixed argv: the repository's script, the pins and paths this test made
		cmd := exec.CommandContext(ctx, "sh", "security-deb.sh", "zlib1g", "zlib", c.version, p["ZLIB1G_SNAPSHOT"], sha, "amd64", status, out)
		b, err := cmd.CombinedOutput()
		cancel()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 || !strings.Contains(string(b), c.want) {
			t.Errorf("%s: want exit 1 and %q, got %v: %s", c.name, c.want, err, b)
		}
		if strings.Contains(string(b), "http://") {
			t.Errorf("%s: tried a download: %s", c.name, b)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Errorf("%s: the output folder exists (%v)", c.name, err)
		}
	}
	// the refusal of a fixed base names every place to clean up: the nine of pins.env's comment
	for _, place := range []string{"(1) deploy/containers/pins.env", "(2) scan-base/Containerfile", "(3) honeypot/Containerfile", "(4) Makefile PIN_ARGS",
		"(5) deploy/compose/compose.yaml", "(6) .dockerignore", "(7) deploy/containers/containers_test.go", "(8) scripts/dev/images-check.sh", "(9) THIRD_PARTY_NOTICES.md"} {
		if !strings.Contains(read(t, "security-deb.sh"), place) || !strings.Contains(read(t, "pins.env"), place) {
			t.Errorf("security-deb.sh's refusal and the pins.env comment must both name %q", place)
		}
	}
}
