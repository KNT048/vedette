// Package containers checks the text of the Containerfiles and their pins (D-146). It builds nothing: the effect (the image runs, the
// binaries are the pinned ones) is checked by `make images-check`, which builds and runs them.
package containers

import (
	"context"
	"encoding/json"
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
	for _, k := range []string{"DEBIAN_IMAGE", "GOLANG_IMAGE", "DISTROLESS_IMAGE"} {
		if !digestRef.MatchString(p[k]) {
			t.Errorf("%s=%q must be repo[:tag]@sha256:<64 hex>", k, p[k])
		}
	}
	for _, k := range []string{"NUCLEI_ZIP_SHA256_AMD64", "NUCLEI_ZIP_SHA256_ARM64", "NUCLEI_BIN_SHA256_AMD64", "NUCLEI_BIN_SHA256_ARM64", "NUCLEI_TEMPLATES_SHA256"} {
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
	if _, has := p["NMAP_VERSION"]; has {
		t.Error("nmap is not pinned to an exact version (D-146 (11)): security fixes must flow in")
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
				if strings.HasPrefix(fields[1], "--") { // --platform=$BUILDPLATFORM (D-158)
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

// D-113 (7), D-4, docs/LEGAL.md: nmap is never in an image the project builds and publishes. The published scan-base holds the
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
		t.Error("the on-box Containerfile must not pin an exact nmap version (D-146 (11))")
	}
}

// nuclei is downloaded once, checked against the pinned SHA-256 before it is unpacked and again after, and lands where the worker
// looks for it; the pack lands where the worker (index) and nucleiargv (templates) expect it.
func TestScanBaseVerifiesNucleiAndPlacesThePack(t *testing.T) {
	t.Parallel()
	text := read(t, "scan-base/Containerfile")
	for _, want := range []string{"sha256sum -c", "NUCLEI_ZIP_SHA256_", "NUCLEI_BIN_SHA256_", "/usr/local/bin/nuclei",
		"/usr/share/vedette/nuclei-templates", "/usr/local/share/vedette/nuclei-pack/index.json"} {
		if !strings.Contains(text, want) {
			t.Errorf("scan-base/Containerfile: missing %q", want)
		}
	}
	if !strings.Contains(text, "ARG SCAN_PACK_VERSION") || !strings.Contains(text, `index.json is not pack version ${SCAN_PACK_VERSION}`) {
		t.Error("scan-base must fail when index.json is not the pinned pack version (a stale pack)")
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

// Multi-arch without CPU emulation (WP-08d, D-158): a stage that runs anything (RUN) is on the build machine, so cross-compiling needs
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
	// the nuclei asset follows the target architecture, with its own pinned hashes
	scan := read(t, "scan-base/Containerfile")
	if !strings.Contains(scan, "nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip") || !strings.Contains(scan, "arm64) zip_sha=") {
		t.Error("scan-base: the nuclei asset and its hashes must be picked by TARGETARCH (amd64 and arm64)")
	}
}

// The index sequence floor goes only where internal/release is linked. Core does not link it; if that changes, core must take
// MIN_SEQUENCE too (Containerfile, Makefile) and this test is updated with it.
func TestOnlyHostLinksTheReleasePackage(t *testing.T) {
	t.Parallel()
	for bin, want := range map[string]bool{"vedette": false, "vedette-sensor": false, "vedette-host": true} {
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
			t.Errorf("%s links internal/release = %v, want %v: the Makefile and the Containerfiles pass MIN_SEQUENCE to vedette-host only", bin, got, want)
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

// The release tools (D-159) are pinned like the images: trivy by tag and by the digest of the multi-arch index, never "latest".
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

// The core image carries its data and credentials directories, owned by the user it runs as, so the container-only compose can mount
// new named volumes on them without a root step (D-168 (5)). The directories are made in the build stage (the final stage has no RUN).
func TestCoreImageOwnsItsVolumeDirectories(t *testing.T) {
	t.Parallel()
	text := read(t, "core/Containerfile")
	stages := stagesOf(text)
	build, final := stages[0].body, stages[len(stages)-1].body
	for _, d := range []string{"/out/dirs/var/lib/vedette ", "/out/dirs/var/lib/vedette-creds/passive ", "/out/dirs/var/lib/vedette-creds/active\n"} {
		if !strings.Contains(build, d) {
			t.Errorf("core/Containerfile: the build stage does not make %q", strings.TrimSpace(d))
		}
	}
	for _, l := range []string{
		"COPY --from=build --chown=65532:65532 --chmod=0750 /out/dirs/var/lib/vedette/ /var/lib/vedette/\n",
		"COPY --from=build --chown=65532:65532 --chmod=0750 /out/dirs/var/lib/vedette-creds/ /var/lib/vedette-creds/\n",
	} {
		if !strings.Contains(final, l) {
			t.Errorf("core/Containerfile: the final stage must contain %q (one COPY per leaf, owner 65532, the user of the image)", strings.TrimSpace(l))
		}
	}
	if regexp.MustCompile(`(?m)^COPY .* /$`).MatchString(final) {
		t.Error("core/Containerfile: a COPY to / rewrites the owner of the existing parents (/var, /var/lib)")
	}
	if !strings.Contains(final, "USER 65532:65532\n") {
		t.Error("core/Containerfile: the image's user is 65532:65532, the owner of the directories and the uid of the compose file")
	}
}
