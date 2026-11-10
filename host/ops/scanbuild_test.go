package ops

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// The Containerfile the host builds with is a copy, in the binary, of the file under deploy/ (D-147): a test keeps them equal, and the
// floor the host enforces is the one pins.env gives to `make scan-image`.
func TestScanContainerfileIsTheDeployFileAndTheFloorIsThePin(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "containers", "scan", "Containerfile.onbox"))
	if err != nil {
		t.Fatal(err)
	}
	head, body, found := strings.Cut(string(b), "ARG BASE_IMAGE\n")
	if !found || "ARG BASE_IMAGE\n"+body != scanContainerfile {
		t.Fatalf("the Containerfile in host/ops/scanbuild.go differs from deploy/containers/scan/Containerfile.onbox:\n%s", body)
	}
	for _, l := range strings.Split(strings.TrimRight(head, "\n"), "\n") {
		if !strings.HasPrefix(l, "#") {
			t.Errorf("a line before ARG BASE_IMAGE that is not a comment: %q", l)
		}
	}
	pins, err := os.ReadFile(filepath.Join("..", "..", "deploy", "containers", "pins.env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains("\n"+string(pins), "\nNMAP_MIN_VERSION="+nmapFloor+"\n") {
		t.Errorf("pins.env does not say NMAP_MIN_VERSION=%s", nmapFloor)
	}
}

func TestBuildContextHoldsOnlyTheContainerfile(t *testing.T) {
	t.Parallel()
	o := &Ops{d: Deps{Root: t.TempDir()}, cfg: Config{StateDir: t.TempDir()}}
	dir, err := o.buildContext()
	if err != nil {
		t.Fatal(err)
	}
	if !validBuildDir(dir) {
		t.Fatalf("the context %q would be refused by the build grammar", dir)
	}
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) != 1 || ents[0].Name() != "Containerfile" {
		t.Fatalf("the build context holds %v (%v)", ents, err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "Containerfile")) //nolint:gosec // test: a file in the directory this test just made
	if string(got) != scanContainerfile {
		t.Error("the Containerfile of the context is not the constant")
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("the context is %v, want 0700", st.Mode().Perm())
	}
}

var (
	baseDig = "sha256:" + strings.Repeat("c", 64)
	buildID = strings.Repeat("d", 64)
)

func goodBuild(t *testing.T) []string {
	t.Helper()
	a, err := buildArgv(baseDig, "1.4.0", "/var/lib/vedette-host/build/scan-123")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestPodmanGrammarOfTheScanBuild(t *testing.T) {
	t.Parallel()
	b := goodBuild(t)
	want := []string{"build", "--pull=never", "--no-cache", "--iidfile", "/var/lib/vedette-host/build/scan-123/iid", "--build-arg", "BASE_IMAGE=ghcr.io/knt048/vedette-scan@" + baseDig, "--build-arg", "NMAP_MIN_VERSION=" + nmapFloor,
		"--tag", "localhost/vedette-scan-nmap:1.4.0", "/var/lib/vedette-host/build/scan-123"}
	if strings.Join(b, " ") != strings.Join(want, " ") {
		t.Fatalf("build argv %q, want %q", b, want)
	}
	check, err := nmapCheckArgv(buildID)
	if err != nil {
		t.Fatal(err)
	}
	retag, err := tagIDArgv(buildID, "1.4.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range [][]string{b, check, retag, {"image", "inspect", "--format", "json", buildID}, {"image", "inspect", "--format", "json", "localhost/vedette-scan-nmap:1.4.0"}, {"rmi", buildID}} {
		if err := validatePodman(a); err != nil {
			t.Errorf("%q refused: %v", a, err)
		}
	}
	mut := func(i int, v string) []string { c := append([]string{}, b...); c[i] = v; return c }
	bad := [][]string{
		mut(1, "--pull=always"), mut(1, "--pull"), mut(2, "--cache-from=x"), mut(3, "--output"), mut(4, "/etc/passwd"), mut(4, "/var/lib/vedette-host/build/scan-123/other"),
		mut(4, "/var/lib/vedette-host/build/scan-123/iid "), mut(4, "/var/lib/vedette-host/build/scan-124/iid"), mut(4, "iid"),
		mut(5, "--build-arg=X"), mut(6, "BASE_IMAGE=ghcr.io/knt048/vedette-core@"+baseDig),
		mut(6, "BASE_IMAGE=ghcr.io/knt048/vedette-scan:latest"), mut(6, "BASE_IMAGE=docker.io/library/debian@"+baseDig), mut(6, "BASE_IMAGE=localhost/vedette-scan-nmap@"+baseDig),
		mut(6, "BASE_IMAGE=ghcr.io/knt048/vedette-scan@"+baseDig+"\nUSER 0"), mut(6, "BASE_IMAGE=ghcr.io/knt048/vedette-scan@sha256:abc"), mut(6, "APT_PROXY=http://x"),
		mut(8, "NMAP_MIN_VERSION=1.0"), mut(8, "NMAP_MIN_VERSION="+nmapFloor+" x"), mut(9, "-t"), mut(10, "localhost/vedette-scan:1.4.0"), mut(10, "localhost/vedette-scan-nmap:latest"),
		mut(10, "localhost/vedette-scan-nmap:-1.4.0"), mut(10, "docker.io/x/y:1.4.0"), mut(10, "localhost/vedette-scan-nmap"),
		mut(11, "relative/dir"), mut(11, "/"), mut(11, "/var/../etc"), mut(11, "/var/lib/./x"), mut(11, "/var/lib/vedette-host/build/scan-1 "), mut(11, "/a\nb"), mut(11, "-f"), mut(11, "/var/lib/x/.hidden"),
		mut(11, "/"+strings.Repeat("a", 300)), mut(11, "https://example.com/x.git"), mut(11, "/a:b"), mut(11, "/a//b"),
		append(append([]string{}, b...), "--network=host"), append([]string{"--root", "/x"}, b...), b[:11], append(append([]string{}, b[:11]...), "-"), {"build"}, {"build", "-"},
		{"run", "--rm", "--privileged", "--entrypoint", "nmap", buildID, "--version"},
		append(append([]string{}, check[:15]...), "-A"), append(append([]string{}, check[:14]...), "x", "--version"), append(append([]string{}, check[:13]...), "sh", buildID, "--version"),
		{"run", "--rm", "--pull=never", "--network", "host", "--cap-drop", "ALL", "--read-only", "--security-opt", "no-new-privileges", "--memory=256m", "--pids-limit=64", "--entrypoint", "nmap", buildID, "--version"},
		{"run", "--rm", "--pull=never", "--network", "none", "--cap-drop", "ALL", "--read-only", "--security-opt", "no-new-privileges", "--entrypoint", "nmap", buildID, "--version"},
		{"run", "--rm", "--pull=never", "--network", "none", "--cap-drop", "ALL", "--read-only", "--security-opt", "no-new-privileges", "--memory=2g", "--pids-limit=64", "--entrypoint", "nmap", buildID, "--version"},
		{"run", "--rm", "--pull=never", "--network", "none", "--cap-drop", "ALL", "--read-only", "--security-opt", "no-new-privileges", "--memory=256m", "--pids-limit=0", "--entrypoint", "nmap", buildID, "--version"},
		{"tag", "localhost/vedette-scan:1.4.0", "localhost/vedette-scan-nmap:1.4.0"}, {"tag", buildID, "localhost/vedette-scan:1.4.0"}, {"tag", buildID, "ghcr.io/knt048/vedette-scan:1.4.0"},
		{"tag", buildID, "localhost/vedette-scan-nmap:1.4.0", "x"}, {"tag", buildID[:63], "localhost/vedette-scan-nmap:1.4.0"},
		{"image", "inspect", "--format", "json", buildID[:63]}, {"image", "inspect", "--format", "json", strings.ToUpper(buildID)}, {"rmi", "-f", buildID},
	}
	for _, a := range bad {
		if err := validatePodman(a); err == nil {
			t.Errorf("%q was accepted", a)
		}
	}
	for _, v := range []string{"", "1.4", "-1.0.0", "1.4.0+b", "latest", "1.4.0\n", strings.Repeat("1", 70) + ".0.0"} {
		if _, err := buildArgv(baseDig, v, "/var/lib/vedette-host/build/scan-1"); err == nil {
			t.Errorf("a build for the version %q was made", v)
		}
	}
	if _, err := buildArgv("sha256:xyz", "1.4.0", "/var/lib/vedette-host/build/scan-1"); err == nil {
		t.Error("a build from a bad digest was made")
	}
}

// FuzzValidatePodmanBuild: whatever the validator accepts as a build or a check of the scan image has exactly the fixed shape (so no
// piece of free text reached it), and the builders only make what it accepts.
func FuzzValidatePodmanBuild(f *testing.F) {
	f.Add("build\x00--pull=never\x00--no-cache\x00--iidfile\x00/var/lib/x/y/iid\x00--build-arg\x00BASE_IMAGE=ghcr.io/knt048/vedette-scan@" + baseDig + "\x00--build-arg\x00NMAP_MIN_VERSION=" + nmapFloor + "\x00--tag\x00localhost/vedette-scan-nmap:1.4.0\x00/var/lib/x/y")
	f.Add("run\x00--rm\x00--pull=never\x00--network\x00none\x00--cap-drop\x00ALL\x00--read-only\x00--security-opt\x00no-new-privileges\x00--memory=256m\x00--pids-limit=64\x00--entrypoint\x00nmap\x00" + buildID + "\x00--version")
	f.Add("tag\x00" + buildID + "\x00localhost/vedette-scan-nmap:1.4.0")
	f.Add("")
	f.Fuzz(func(t *testing.T, joined string) {
		args := strings.Split(joined, "\x00")
		if validatePodman(args) != nil || (args[0] != "build" && args[0] != "run") {
			return
		}
		for _, a := range args {
			if a == "" || strings.IndexFunc(a, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
				t.Fatalf("an accepted argv has a piece with a space or control character: %q", args)
			}
		}
		switch args[0] {
		case "build":
			if len(args) != 12 || args[4] != args[11]+"/iid" || !strings.HasPrefix(args[6], "BASE_IMAGE=ghcr.io/knt048/vedette-scan@sha256:") || !validBuildDir(args[11]) || strings.Contains(args[11], "..") {
				t.Fatalf("an accepted build has the wrong shape: %q", args)
			}
		case "run":
			if len(args) != 16 || args[3] != "--network" || args[4] != "none" || args[10] != "--memory=256m" || args[11] != "--pids-limit=64" || args[13] != "nmap" {
				t.Fatalf("an accepted run has the wrong shape: %q", args)
			}
		}
	})
}

// L1: the ID of the built image is read from the file podman wrote, and only an ID is believed.
func TestReadImageIDReadsOnlyAnID(t *testing.T) {
	t.Parallel()
	for content, want := range map[string]string{
		"sha256:" + buildID: buildID, buildID: buildID, "sha256:" + buildID + "\n": buildID,
		"": "", "sha256:" + buildID[:63]: "", "sha256:" + strings.ToUpper(buildID): "", "x" + buildID: "", buildID + buildID: "", "sha256:" + buildID + "\nUSER 0": "",
		"sha512:" + buildID: "", " " + buildID: "", "not an id": "", strings.Repeat("a", 500): "",
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, iidName), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := readImageID(dir); got != want {
			t.Errorf("%q: %q, want %q", content, got, want)
		}
	}
	if got := readImageID(t.TempDir()); got != "" {
		t.Errorf("a missing file gave %q", got)
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, iidName), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := readImageID(dir); got != "" {
		t.Errorf("a directory gave %q", got)
	}
}

func TestParseNmapVersion(t *testing.T) {
	t.Parallel()
	good := map[string]string{
		"Nmap version 7.95 ( https://nmap.org )\nPlatform: x86_64-pc-linux-gnu\nCompiled with: nmap-liblua-5.4.6\n": "7.95",
		"Nmap version 7.95 ( https://nmap.org )":      "7.95",
		"Nmap version 7.100 ( https://nmap.org )\n":   "7.100",
		"Nmap version 8.0 ( https://nmap.org )\n":     "8.0",
		"Nmap version 7.95.1 ( https://nmap.org )\n":  "7.95.1",
		"Nmap version 7.96SVN ( https://nmap.org )\n": "7.96SVN",
	}
	good["\nNmap version 7.95 ( https://nmap.org )\n"] = "7.95"
	good["\n\n \nNmap version 7.96 ( https://nmap.org )\nPlatform: x\n"] = "7.96"
	for out, want := range good {
		if got, err := ParseNmapVersion([]byte(out)); err != nil || got != want {
			t.Errorf("%q: %q, %v; want %q", out, got, err, want)
		}
	}
	for name, out := range map[string]string{
		"empty": "", "only blank lines": "\n\n  \n", "junk after a blank line": "\nhello\nNmap version 7.95 ( https://nmap.org )\n", "below the floor": "Nmap version 7.94 ( https://nmap.org )\n", "far below": "Nmap version 6.47 ( http://nmap.org )\n",
		"not nmap": "hello\n", "lower case": "nmap version 7.95 ( https://nmap.org )\n", "the line is not first": "x\nNmap version 7.95 ( https://nmap.org )\n",
		"no version": "Nmap version ( https://nmap.org )\n", "a command in the version": "Nmap version 7.95$(id) ( https://nmap.org )\n", "a newline in it": "Nmap version 7.9\n5 ( https://nmap.org )\n",
		"huge": "Nmap version 7.95 ( https://nmap.org )\n" + strings.Repeat("x", 5000), "long tail on the line": "Nmap version 7.95 " + strings.Repeat("x", 200) + "\n",
		"only major": "Nmap version 8 ( https://nmap.org )\n", "a minus": "Nmap version -7.95 ( https://nmap.org )\n", "a space first": " Nmap version 7.95\n",
	} {
		if got, err := ParseNmapVersion([]byte(out)); err == nil {
			t.Errorf("%s: %q accepted as %q", name, out, got)
		}
	}
}

func FuzzParseNmapVersion(f *testing.F) {
	f.Add([]byte("Nmap version 7.95 ( https://nmap.org )\nPlatform: x\n"))
	f.Add([]byte("Nmap version 7.9 ( https://nmap.org )"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := ParseNmapVersion(b)
		if err != nil {
			return
		}
		if !nmapVersionRE.MatchString(v) || !atLeast(v, nmapFloor) || !bytes.Contains(b, []byte("Nmap version "+v)) {
			t.Fatalf("accepted %q as %q", b, v)
		}
	})
}

// The two credential volumes are written from constant text (D-147): owner core_uid, group sensor_gid, nothing else.
func TestVolumeUnitsAreConstantTextWithTheHostConfIds(t *testing.T) {
	t.Parallel()
	for _, role := range credsRoles {
		got, err := renderVolume(role, 10001, 10004)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join("testdata", "units", volumeFileName(role))
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			if err := os.WriteFile(path, got, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path) //nolint:gosec // a golden file under testdata
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s differs from its golden file (%v):\n%s", volumeFileName(role), err, got)
		}
	}
	for _, c := range []struct {
		role     string
		uid, gid int
	}{{"", 1, 1}, {"core", 1, 1}, {"passive\n", 1, 1}, {"../passive", 1, 1}, {"passive", 0, 1}, {"passive", 1, 0}, {"passive", -1, 1}, {"active", 1, 1 << 31}} {
		if b, err := renderVolume(c.role, c.uid, c.gid); err == nil {
			t.Errorf("%+v accepted: %s", c, b)
		}
	}
	if got := strings.Join(credsRoles, ","); got != "passive,active" {
		t.Errorf("roles %s", got)
	}
}

// The effect looks of a scan container and image read the image ID (D-147): the container's "Image", the image's "Id".
func TestScanLooksReadTheImageID(t *testing.T) {
	t.Parallel()
	insp := func(svc string) string {
		return `[{"Name":"vedette-` + svc + `","ImageDigest":"` + goldA + `","Image":"` + buildID + `","State":{"Running":true,"Health":{"Status":"healthy"}}}]`
	}
	if d, running, health, err := ParseInspect([]byte(insp("scan")), api.ServiceScan); err != nil || d != "sha256:"+buildID || !running || health != api.HealthHealthy {
		t.Errorf("scan: %q %t %q %v", d, running, health, err)
	}
	if d, _, _, err := ParseInspect([]byte(insp("core")), api.ServiceCore); err != nil || d != goldA {
		t.Errorf("core still reads ImageDigest: %q %v", d, err)
	}
	for _, bad := range []string{
		`[{"Name":"vedette-scan","ImageDigest":"` + goldA + `","State":{"Running":true}}]`,
		`[{"Name":"vedette-scan","Image":"` + buildID[:63] + `","State":{"Running":true}}]`,
		`[{"Name":"vedette-scan","Image":"sha256:` + buildID + `","State":{"Running":true}}]`,
		`[{"Name":"vedette-scan","Image":"` + strings.ToUpper(buildID) + `","State":{"Running":true}}]`,
	} {
		if _, _, _, err := ParseInspect([]byte(bad), api.ServiceScan); err == nil {
			t.Errorf("accepted: %s", bad)
		}
	}
	img := func(id, extra string) []byte {
		return []byte(`[{"Id":"` + id + `","Architecture":"amd64","Os":"linux"` + extra + `}]`)
	}
	if err := parseBuiltInspect(img(buildID, ""), "sha256:"+buildID, "amd64"); err != nil {
		t.Error(err)
	}
	for name, c := range map[string]struct {
		out    []byte
		digest string
		arch   string
	}{
		"another image":      {img(strings.Repeat("e", 64), ""), "sha256:" + buildID, "amd64"},
		"another arch":       {img(buildID, ""), "sha256:" + buildID, "arm64"},
		"two images":         {append(img(buildID, "")[:len(img(buildID, ""))-2], []byte(`,{"Id":"`+buildID+`"}]`)...), "sha256:" + buildID, "amd64"},
		"not an ID":          {img("latest", ""), "sha256:latest", "amd64"},
		"trailing data":      {append(img(buildID, ""), []byte(" x")...), "sha256:" + buildID, "amd64"},
		"the digest differs": {img(buildID, ""), goldA, "amd64"},
	} {
		if err := parseBuiltInspect(c.out, c.digest, c.arch); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Retention treats the built image like the service's other images: owned by its name, kept by its ID (D-147).
func TestRetentionKnowsTheBuiltScanImage(t *testing.T) {
	t.Parallel()
	list := `[{"Id":"` + buildID + `","Digest":"` + goldA + `","Names":["localhost/vedette-scan-nmap:1.4.0"],"RepoDigests":[],"Containers":0},
	{"Id":"` + strings.Repeat("e", 64) + `","Digest":"` + goldB + `","Names":["localhost/vedette-scan-nmap:1.3.0","docker.io/library/x:1"],"Containers":0}]`
	imgs, err := parseImageList([]byte(list), api.ServiceScan)
	if err != nil || len(imgs) != 1 || imgs[0].ID != buildID || !slicesContain(imgs[0].Digests, "sha256:"+buildID) {
		t.Fatalf("%+v %v", imgs, err)
	}
	if got, _ := parseImageList([]byte(list), api.ServiceSensor); len(got) != 0 {
		t.Errorf("another service owns the built image: %+v", got)
	}
}

func slicesContain(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// L5: ids that host.conf does not give are host_conf_incomplete, not an unsafe directory.
func TestAVolumeWithBadIdsIsHostConfIncomplete(t *testing.T) {
	t.Parallel()
	_, err := renderVolume("passive", 0, 10004)
	if !errors.Is(err, errBadFill) || errors.Is(err, errUnitUnsafe) {
		t.Fatalf("%v", err)
	}
	var fl *server.Failure
	if !errors.As(unitWriteFailure(err), &fl) || fl.Code != api.CodeHostConfIncomplete {
		t.Errorf("mapped to %v", unitWriteFailure(err))
	}
	if !errors.As(unitWriteFailure(errUnitUnsafe), &fl) || fl.Code != api.CodeUnitUnsafe {
		t.Errorf("an unsafe directory is mapped to %v", fl)
	}
}

// A scan unit pins the image by its ID: the unit text, the digest the host reads back, and the retention name all agree (D-147).
func TestScanUnitPinsTheImageByIDAndReadsItBack(t *testing.T) {
	t.Parallel()
	f := goldFill(true)
	f.Digest = "sha256:" + buildID
	b, err := renderUnit(api.ServiceScan, f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\nImage="+buildID+"\n") || strings.Contains(string(b), "@sha256") {
		t.Fatalf("the scan unit does not pin the image ID:\n%s", b)
	}
	d, install, err := parseUnit(api.ServiceScan, b)
	if err != nil || d != f.Digest || !install {
		t.Errorf("parse: %q %t %v", d, install, err)
	}
	// Only a scan unit has an ID line; the others still need repository@digest, and a scan unit needs the ID.
	if _, _, err := parseUnit(api.ServiceCore, b); err == nil {
		t.Error("a scan unit parsed as core's")
	}
	for _, bad := range []string{"Image=" + buildID[:63], "Image=" + strings.ToUpper(buildID), "Image=localhost/vedette-scan-nmap@" + goldA, "Image=" + buildID + " ", "Image=localhost/vedette-scan-nmap:1.4.0"} {
		if _, _, err := parseUnit(api.ServiceScan, []byte(strings.Replace(string(b), "Image="+buildID, bad, 1))); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	two := strings.Replace(string(b), "Pull=never", "Image="+buildID+"\nPull=never", 1)
	if _, _, err := parseUnit(api.ServiceScan, []byte(two)); err == nil {
		t.Error("a unit with two Image= lines parsed")
	}
	if !ownedName("localhost/vedette-scan-nmap:1.4.0", api.ServiceScan) || ownedName("localhost/vedette-scan-nmap:1.4.0", api.ServiceSensor) || ownedName("localhost/vedette-scan-nmapx:1.4.0", api.ServiceScan) {
		t.Error("retention does not own the built image's name for scan only")
	}
}
