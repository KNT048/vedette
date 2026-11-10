// Package containers checks the text of the Containerfiles and their pins (D-146). It builds nothing: the effect (the image runs, the
// binaries are the pinned ones) is checked by `make images-check`, which builds and runs them.
package containers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

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
	for _, f := range []string{"sensor/Containerfile", "scan-base/Containerfile", "core/Containerfile", "scan/Containerfile.onbox"} {
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
