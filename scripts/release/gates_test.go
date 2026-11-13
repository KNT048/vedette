package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/mod/modfile"
)

// arMember is one member of an ar archive (a .deb), with the 60-byte header dpkg and nfpm write.
func arMember(b *bytes.Buffer, name string, body []byte) {
	fmt.Fprintf(b, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 1700000000, 0, 0, "100644", len(body))
	b.Write(body)
	if len(body)%2 == 1 {
		b.WriteByte('\n')
	}
}

// tgz is a gzip tar of the given entries (name -> body; a body "->target" is a symlink).
func tgz(t *testing.T, entries [][2]string) []byte {
	t.Helper()
	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		h := &tar.Header{Name: e[0], Mode: 0o755, Size: int64(len(e[1])), Typeflag: tar.TypeReg}
		if target, ok := strings.CutPrefix(e[1], "->"); ok {
			h = &tar.Header{Name: e[0], Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: target}
		} else if target, ok := strings.CutPrefix(e[1], "=>"); ok {
			h = &tar.Header{Name: e[0], Mode: 0o755, Typeflag: tar.TypeLink, Linkname: target}
		} else if strings.HasSuffix(e[0], "/") {
			h = &tar.Header{Name: e[0], Mode: 0o755, Typeflag: tar.TypeDir}
		}
		must(t, tw.WriteHeader(h))
		if h.Typeflag == tar.TypeReg {
			_, err := tw.Write([]byte(e[1]))
			must(t, err)
		}
	}
	must(t, tw.Close())
	must(t, zw.Close())
	return raw.Bytes()
}

// fakeDeb writes a .deb shaped like nfpm's (debian-binary, control.tar.gz, data.tar.gz) holding bin as vedette-host.
func fakeDeb(t *testing.T, p string, bin []byte) {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	arMember(&b, "debian-binary", []byte("2.0\n"))
	arMember(&b, "control.tar.gz", tgz(t, [][2]string{{"./control", "Package: vedette-host\n"}}))
	arMember(&b, "data.tar.gz", tgz(t, [][2]string{{"./usr/lib/vedette/apparmor-containers.conf", "x"}, {"./" + hostBinaryInDeb, string(bin)}}))
	must(t, os.WriteFile(p, b.Bytes(), 0o600))
}

// gatesFake answers git (a clean tree at the tag), podman (the four local lists of version 0.2.0 with labels) and make host-deb
// (rebuilt: a copy of the file rebuilt names into DEB_OUT).
type gatesFake struct {
	labels  func(local, arch string) map[string]string
	rebuilt string // the package make host-deb writes
	status  string
	tag     string
	// files is the filesystem `podman export` writes for the platform image local/arch (name -> body, as tgz takes them)
	files func(local, arch string) [][2]string
	ctrs  map[string]string // container name -> image ID, between create and rm
	t     *testing.T
}

func (g *gatesFake) fn(argv []string) ([]byte, error) {
	a := strings.Join(argv, " ")
	switch {
	case strings.HasPrefix(a, "git -C repo status"):
		return []byte(g.status), nil
	case strings.HasPrefix(a, "git -C repo rev-parse --verify HEAD"):
		return []byte("abc\n"), nil
	case strings.HasPrefix(a, "git -C repo rev-parse --verify --quiet refs/tags/v0.2.0"):
		return []byte(g.tag + "\n"), nil
	case a == "podman images --all --format json":
		var all []string
		for _, l := range localNames {
			for _, arch := range []string{"amd64", "arm64"} {
				var lb []string
				for k, v := range g.labels(l, arch) {
					lb = append(lb, fmt.Sprintf("%q:%q", k, v))
				}
				all = append(all, fmt.Sprintf(`{"Id":%q,"Digest":%q,"Size":1000,"Labels":{%s}}`, cfgID(l, arch), digestOf("local "+l+arch), strings.Join(lb, ",")))
			}
		}
		return []byte("[" + strings.Join(all, ",") + "]"), nil
	case strings.HasPrefix(a, "podman manifest exists localhost/vedette-"):
		return nil, nil
	case strings.HasPrefix(a, "podman manifest inspect localhost/vedette-"):
		l := strings.TrimSuffix(strings.TrimPrefix(argv[3], "localhost/vedette-"), ":0.2.0")
		return listJSON(both("local " + l)), nil
	case len(argv) == 6 && a == "podman create --pull=never --name "+argv[4]+" "+argv[5]:
		if g.ctrs == nil {
			g.ctrs = map[string]string{}
		}
		g.ctrs[argv[4]] = argv[5]
		return nil, nil
	case len(argv) == 5 && a == "podman export -o "+argv[3]+" "+argv[4] && g.ctrs[argv[4]] != "":
		for _, l := range localNames {
			for _, arch := range []string{"amd64", "arm64"} {
				if g.ctrs[argv[4]] == "sha256:"+cfgID(l, arch) {
					return nil, os.WriteFile(argv[3], plainTar(g.t, g.files(l, arch)), 0o600)
				}
			}
		}
		return nil, fmt.Errorf("export: unknown image %s", g.ctrs[argv[4]])
	case len(argv) == 5 && a == "podman rm -f -v "+argv[4]:
		delete(g.ctrs, argv[4])
		return nil, nil
	case strings.HasPrefix(a, "make -C repo --no-print-directory host-deb "):
		out := strings.TrimPrefix(argv[len(argv)-1], "DEB_OUT=")
		arch := strings.TrimPrefix(argv[6], "ARCH=")
		b, err := os.ReadFile(g.rebuilt)
		if err != nil {
			return nil, err
		}
		return nil, os.WriteFile(filepath.Join(out, "vedette-host_0.2.0_"+arch+".deb"), b, 0o600) //nolint:gosec // test: out is the temporary directory the code under test made
	}
	return nil, fmt.Errorf("unexpected %q", a)
}

// plainTar is an uncompressed tar of entries, as `podman export` writes it (tgz without the gzip).
func plainTar(t *testing.T, entries [][2]string) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(tgz(t, entries)))
	must(t, err)
	b, err := io.ReadAll(zr)
	must(t, err)
	return b
}

// keyMark stands for the production key lines core must contain (gatesRig's Expect.Keys).
const keyMark = "RWTESTPRODUCTIONKEYLINE"

// goodFiles are the files of a platform image the file check passes: core's /vedette is bin with the key inside, scan-base has bin as
// nuclei (module probe, no dependency, built with bin's Go), the pack index of version 2026.11.1, and a folder named nmap (only a
// file, link or symlink of that name is nmap).
func goodFiles(bin []byte) func(local, arch string) [][2]string {
	return func(local, _ string) [][2]string {
		switch local {
		case "core":
			return [][2]string{{"./etc/passwd", "x"}, {"./" + coreBinaryInImage, string(bin) + keyMark}}
		case "scan-base":
			return [][2]string{{"usr/share/nmap/", ""}, {nucleiInImage, string(bin)}, {packIndexInImage, `{"version": "2026.11.1", "sha256": "` + strings.Repeat("c", 64) + `"}`}}
		}
		return nil
	}
}

func goodLabels(local, _ string) map[string]string {
	m := map[string]string{versionLabel: "0.2.0"}
	if local == "core" {
		m[minSequenceLabel] = "1"
	}
	return m
}

// gatesRig is a release directory with the two packages, both holding bin, a published index of sequence 1 (the floor), and a
// fake that rebuilds the same bytes.
func gatesRig(t *testing.T, bin []byte) (gatesOpts, *gatesFake) {
	t.Helper()
	r := newRig(t)
	prev, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	must(t, err)
	dir := t.TempDir()
	for _, arch := range debArchs {
		fakeDeb(t, filepath.Join(dir, "vedette-host_0.2.0_"+arch+".deb"), bin)
	}
	// what make vuln-scan and make sbom (RELEASE=1) leave: a trivy report and an SBOM of each platform image
	vuln, sbom := t.TempDir(), t.TempDir()
	for _, local := range localNames {
		for _, arch := range []string{"amd64", "arm64"} {
			writeJSON(t, filepath.Join(vuln, local+"-"+arch+".json"), map[string]any{"SchemaVersion": 2, "ArtifactType": "container_image",
				"Metadata": map[string]any{"ImageID": "sha256:" + cfgID(local, arch), "DiffIDs": []string{digestOf("layer")}}, "Results": []any{}})
			writeSBOM(t, filepath.Join(sbom, local+"-"+arch+".cdx.json"), "sha256:"+cfgID(local, arch))
		}
	}
	bi, err := buildinfo.Read(bytes.NewReader(bin))
	must(t, err)
	mod, err := modfile.Parse("go.mod", []byte("module probe\n\ngo 1.21\n"), nil)
	must(t, err)
	e := imageExpect{Keys: []string{keyMark}, GoVersion: bi.GoVersion, NucleiMod: mod, PackVersion: "2026.11.1", PackSHA256: strings.Repeat("c", 64)}
	writeJSON(t, filepath.Join(vuln, "source.json"), map[string]any{"SchemaVersion": 2, "ArtifactType": "filesystem"})
	return gatesOpts{Version: "0.2.0", MinSequence: "1", PrevIndex: prev, Trust: r.trust, Platforms: allPlatforms, DebDir: dir, Repo: "repo", Out: t.TempDir(), VulnDir: vuln, SBOMDir: sbom, Expect: e},
		&gatesFake{labels: goodLabels, rebuilt: filepath.Join(dir, "vedette-host_0.2.0_amd64.deb"), tag: "abc", files: goodFiles(bin), t: t}
}

func TestGatesPassInOrder(t *testing.T) {
	bin, err := os.ReadFile(buildProbe(t, ""))
	must(t, err)
	o, g := gatesRig(t, bin)
	fr := &fakeRun{fn: g.fn}
	var out bytes.Buffer
	if err := Gates(context.Background(), fr.run, o, &out); err != nil {
		t.Fatal(err, fr.joined())
	}
	if len(g.ctrs) > 0 {
		t.Errorf("containers left: %v", g.ctrs)
	}
	got := out.String()
	for _, want := range []string{"check-binaries -release " + filepath.Join(o.DebDir, "vedette-host_0.2.0_arm64.deb"), "localhost/vedette-core:0.2.0: org.opencontainers.image.version=0.2.0 on linux/amd64, linux/arm64, floor 1", "localhost/vedette-honeypot:0.2.0", "is what this commit builds with MIN_SEQUENCE=1",
		"localhost/vedette-core:0.2.0 linux/arm64: /vedette holds the production release keys", "localhost/vedette-scan-base:0.2.0 linux/amd64: nuclei built with " + o.Expect.GoVersion} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if i, j := strings.Index(got, "check-binaries"), strings.Index(got, "image.version"); i > j || j > strings.Index(got, "MIN_SEQUENCE") {
		t.Errorf("order: binaries, labels, floor:\n%s", got)
	}
	calls := fr.joined()
	if !strings.HasPrefix(calls[0], "git -C repo status") {
		t.Errorf("the tree is checked first: %v", calls)
	}
	var makes [][]string
	for _, c := range fr.calls {
		if c[0] == "make" {
			makes = append(makes, c)
		}
	}
	if len(makes) != 2 {
		t.Fatalf("want two rebuilds, got %v", makes)
	}
	for i, arch := range debArchs {
		want := []string{"make", "-C", "repo", "--no-print-directory", "host-deb", "VERSION=0.2.0", "ARCH=" + arch, "MIN_SEQUENCE=1"}
		if !slices.Equal(makes[i][:8], want) || !strings.HasPrefix(makes[i][8], "DEB_OUT=") || len(makes[i]) != 9 {
			t.Errorf("rebuild argv %v, want %v DEB_OUT=<tmp>", makes[i], want)
		}
		if _, err := os.Stat(strings.TrimPrefix(makes[i][8], "DEB_OUT=")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the rebuild directory is left behind: %v", err)
		}
	}
	// the record: exactly what was checked, read back by the strict reader push and in use
	rp := filepath.Join(o.Out, gatesFile)
	rec, err := readGates(rp)
	if err != nil {
		t.Fatal(err)
	}
	want := gatesDoc(t, "0.2.0", o.DebDir)
	if a, b := mustJSON(t, rec), mustJSON(t, want); string(a) != string(b) {
		t.Errorf("gates.json:\n%s\nwant:\n%s", a, b)
	}
	if fi, err := os.Stat(rp); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("gates.json mode: %v %v", fi, err)
	}
	if left, _ := filepath.Glob(filepath.Join(o.Out, ".gates-*")); len(left) > 0 {
		t.Errorf("temporary file left: %v", left)
	}
	if !strings.Contains(got, "wrote "+rp) {
		t.Errorf("output does not name the record:\n%s", got)
	}
	// the very first release: no published index, floor 0
	fr = &fakeRun{fn: g.fn}
	o.PrevIndex, o.MinSequence, o.Preflight = "", "0", true
	if err := Gates(context.Background(), fr.run, o, &out); err != nil {
		t.Errorf("first release (floor 0, no index): %v", err)
	}
	// -preflight stops after the version, floor and tree checks, and neither writes nor removes the record
	fr = &fakeRun{fn: g.fn}
	o.Preflight = true
	if err := Gates(context.Background(), fr.run, o, &out); err != nil || slices.ContainsFunc(fr.calls, func(c []string) bool { return c[0] != "git" }) {
		t.Errorf("preflight: %v %v", err, fr.joined())
	}
	if again, err := readGates(rp); err != nil || again.MinSequence != "1" {
		t.Errorf("preflight changed the record: %v %v", again, err)
	}
}

// A timeout or Ctrl-C kills the whole process group of a command (make host-deb's go build and nfpm), not only its first process:
// the grandchild sleep must be gone afterwards (state, not elapsed time; D-373: a 30 s bound on a hang).
func TestExecRunKillsTheGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pidFile := filepath.Join(t.TempDir(), "pid")
	// poll calls done every 50 ms for at most 30 s and says whether it returned true
	poll := func(done func() bool) bool {
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for range 600 {
			if done() {
				return true
			}
			<-tick.C
		}
		return false
	}
	go func() { // cancel once the grandchild exists
		defer cancel()
		poll(func() bool { b, _ := os.ReadFile(pidFile); return len(b) > 0 && b[len(b)-1] == '\n' }) //nolint:gosec // the test's own temporary file
	}()
	if _, err := execRun(ctx, "sh", "-c", `sleep 60 & echo $! > "$1"; wait`, "sh", pidFile); err == nil {
		t.Fatal("a cancelled command reported success")
	}
	b, err := os.ReadFile(pidFile) //nolint:gosec // the test's own temporary file
	must(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	must(t, err)
	if poll(func() bool { // init reaps the killed sleep; a zombie is dead too
		st, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) || strings.Contains(string(st), ") Z ")
	}) {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("the grandchild %d outlived the cancel", pid)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := marshal(v)
	must(t, err)
	return b
}

func TestReadGatesRefusals(t *testing.T) {
	good := mustJSON(t, gatesDoc(t, "0.2.0", ""))
	cases := map[string]struct{ from, to, want string }{
		"unknown field":      {`"version"`, `"skip": true, "version"`, "unknown field"},
		"repeated key":       {`"version": "0.2.0"`, `"version": "0.2.0", "version": "0.2.1"`, "repeated key"},
		"image twice":        {`"service": "honeypot",` + "\n      \"local\": \"honeypot\"", `"service": "core",` + "\n      \"local\": \"core\"", "image core is listed 2 times"},
		"unknown image":      {`"service": "honeypot"`, `"service": "greenbone"`, "unknown image"},
		"local mismatch":     {`"local": "scan-base"`, `"local": "scan"`, "unknown image"},
		"package twice":      {`"arch": "arm64"`, `"arch": "amd64"`, "package amd64 is listed 2 times"},
		"bad sha256":         {`"sha256": "aaaa`, `"sha256": "AAAA`, "malformed file name, sha256 or size"},
		"path as file name":  {`"file": "vedette-host_0.2.0_amd64.deb"`, `"file": "../vedette-host_0.2.0_amd64.deb"`, "malformed file name"},
		"bad config":         {`"config": "sha256:`, `"config": "sha512:`, "malformed platform"},
		"platform twice":     {`"platform": "linux/arm64"`, `"platform": "linux/amd64"`, "lists platform linux/amd64 2 times"},
		"version not SemVer": {`"version": "0.2.0"`, `"version": "v0.2.0"`, "not SemVer"},
		"floor not decimal":  {`"min_sequence": "1"`, `"min_sequence": "01"`, "plain decimal"},
		"trailing data":      {"  ]\n}\n", "  ]\n}\n{}\n", "after the value"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(string(good), c.from) {
				t.Fatalf("%q not in the record", c.from)
			}
			p := filepath.Join(t.TempDir(), gatesFile)
			must(t, os.WriteFile(p, []byte(strings.Replace(string(good), c.from, c.to, 1)), 0o600))
			if _, err := readGates(p); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
	p := filepath.Join(t.TempDir(), gatesFile)
	must(t, os.WriteFile(p, good, 0o600))
	if _, err := readGates(p); err != nil {
		t.Fatal(err)
	}
	g := gatesDoc(t, "0.2.0", "")
	g.Images = g.Images[:3]
	must(t, os.WriteFile(p, mustJSON(t, g), 0o600))
	if _, err := readGates(p); err == nil || !strings.Contains(err.Error(), "lists 3 images, a release has 4") {
		t.Errorf("an image missing: %v", err)
	}
}

func TestGatesRefuse(t *testing.T) {
	bin, err := os.ReadFile(buildProbe(t, ""))
	must(t, err)
	testKeys, err := os.ReadFile(buildProbe(t, "releasetestkeys"))
	must(t, err)
	other := filepath.Join(t.TempDir(), "other.deb")
	fakeDeb(t, other, append(slices.Clone(bin), 'x'))
	for _, c := range []struct {
		name, want string
		change     func(o *gatesOpts, g *gatesFake)
		makes      bool // the rebuild ran (the failure is the last gate)
	}{
		{"test version", "-test. prerelease", func(o *gatesOpts, _ *gatesFake) { o.Version = "0.2.0-test.1" }, false},
		{"not semver", "not SemVer", func(o *gatesOpts, _ *gatesFake) { o.Version = "v0.2.0" }, false},
		{"floor not decimal", "plain decimal", func(o *gatesOpts, _ *gatesFake) { o.MinSequence = "07" }, false},
		{"floor without the published index", "without RELEASE_PREV_INDEX", func(o *gatesOpts, _ *gatesFake) { o.PrevIndex = "" }, false},
		{"floor not the index's", "has sequence 1", func(o *gatesOpts, _ *gatesFake) { o.MinSequence = "0" }, false},
		{"index does not verify", "published index: ", func(o *gatesOpts, _ *gatesFake) {
			must(t, os.WriteFile(filepath.Join(o.PrevIndex, indexFile), []byte(`{"sequence":1}`), 0o600))
		}, false},
		{"dirty tree", "uncommitted", func(_ *gatesOpts, g *gatesFake) { g.status = " M Makefile" }, false},
		{"not the tag", "is not v0.2.0", func(_ *gatesOpts, g *gatesFake) { g.tag = "def" }, false},
		{"no deb", "no vedette-host_0.2.0_arm64.deb", func(o *gatesOpts, _ *gatesFake) {
			must(t, os.Remove(filepath.Join(o.DebDir, "vedette-host_0.2.0_arm64.deb")))
		}, false},
		{"test keys in the deb", "releasetestkeys", func(o *gatesOpts, _ *gatesFake) {
			fakeDeb(t, filepath.Join(o.DebDir, "vedette-host_0.2.0_arm64.deb"), testKeys)
		}, false},
		{"version label", `org.opencontainers.image.version="0.1.9", not 0.2.0`, func(_ *gatesOpts, g *gatesFake) {
			g.labels = func(l, arch string) map[string]string {
				m := goodLabels(l, arch)
				if l == "honeypot" && arch == "arm64" {
					m[versionLabel] = "0.1.9"
				}
				return m
			}
		}, false},
		{"core floor label", `built with MIN_SEQUENCE "0"`, func(_ *gatesOpts, g *gatesFake) {
			g.labels = func(l, arch string) map[string]string {
				m := goodLabels(l, arch)
				if l == "core" && arch == "amd64" {
					m[minSequenceLabel] = "0"
				}
				return m
			}
		}, false},
		{"core floor label missing", `built with MIN_SEQUENCE ""`, func(_ *gatesOpts, g *gatesFake) {
			g.labels = func(l, arch string) map[string]string {
				m := goodLabels(l, arch)
				delete(m, minSequenceLabel)
				return m
			}
		}, false},
		{"vuln-scan read another image", `localhost/vedette-sensor:0.2.0 linux/arm64: vulnerability report`, func(o *gatesOpts, _ *gatesFake) {
			writeJSON(t, filepath.Join(o.VulnDir, "sensor-arm64.json"), map[string]any{"Metadata": map[string]any{"ImageID": digestOf("before the rebuild")}})
		}, false},
		{"source gate red", "vulnerability report of the source", func(o *gatesOpts, _ *gatesFake) {
			must(t, os.Rename(filepath.Join(o.VulnDir, "source.json"), filepath.Join(o.VulnDir, "source.gate-failed.json")))
		}, false},
		{"hard-linked nmap in scan-base", "holds /usr/sbin/nmap", func(_ *gatesOpts, g *gatesFake) {
			good := g.files
			g.files = func(l, arch string) [][2]string {
				if l == "scan-base" {
					return append(good(l, arch), [2]string{"usr/lib/x/scanner", "x"}, [2]string{"usr/sbin/nmap", "=>usr/lib/x/scanner"})
				}
				return good(l, arch)
			}
		}, false},
		{"no vulnerability report", "make vuln-scan RELEASE=1", func(o *gatesOpts, _ *gatesFake) {
			must(t, os.Remove(filepath.Join(o.VulnDir, "core-amd64.json")))
		}, false},
		{"sbom of another image", `localhost/vedette-scan-base:0.2.0 linux/amd64: SBOM scan-base-amd64.cdx.json is of image`, func(o *gatesOpts, _ *gatesFake) {
			writeSBOM(t, filepath.Join(o.SBOMDir, "scan-base-amd64.cdx.json"), digestOf("before the rebuild"))
		}, false},
		{"core with the throwaway keys", "releasetestkeys", func(_ *gatesOpts, g *gatesFake) {
			good := g.files
			g.files = func(l, arch string) [][2]string {
				if l == "core" && arch == "arm64" {
					return [][2]string{{coreBinaryInImage, string(testKeys) + keyMark}}
				}
				return good(l, arch)
			}
		}, false},
		{"core without the production keys", "does not contain the production release key", func(_ *gatesOpts, g *gatesFake) {
			good := g.files
			g.files = func(l, arch string) [][2]string {
				if l == "core" {
					return [][2]string{{coreBinaryInImage, string(bin)}}
				}
				return good(l, arch)
			}
		}, false},
		{"core binary is a symlink", "is not a regular file", func(_ *gatesOpts, g *gatesFake) {
			good := g.files
			g.files = func(l, arch string) [][2]string {
				if l == "core" {
					return [][2]string{{coreBinaryInImage, "->/bin/sh"}}
				}
				return good(l, arch)
			}
		}, false},
		{"nmap in scan-base", "holds /usr/bin/nmap", func(_ *gatesOpts, g *gatesFake) {
			good := g.files
			g.files = func(l, arch string) [][2]string {
				if l == "scan-base" && arch == "arm64" {
					return append(good(l, arch), [2]string{"usr/bin/nmap", "->/usr/lib/nmap/nmap"})
				}
				return good(l, arch)
			}
		}, false},
		{"nuclei of another Go", "the pinned Go is go1.27.10", func(o *gatesOpts, _ *gatesFake) { o.Expect.GoVersion = "go1.27.10" }, false},
		{"stale pack", "a stale pack", func(o *gatesOpts, _ *gatesFake) { o.Expect.PackVersion = "2026.12.1" }, false},
		{"no pack index", "has no /" + packIndexInImage, func(_ *gatesOpts, g *gatesFake) {
			g.files = func(string, string) [][2]string {
				return [][2]string{{coreBinaryInImage, string(bin) + keyMark}, {nucleiInImage, string(bin)}}
			}
		}, false},
		{"deb built with another floor", "is not what this commit builds with MIN_SEQUENCE=1", func(_ *gatesOpts, g *gatesFake) { g.rebuilt = other }, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			o, g := gatesRig(t, bin)
			c.change(&o, g)
			stale := gatesPath(t, gatesDoc(t, "0.2.0", ""))
			o.Out = filepath.Dir(stale) // an earlier pass, of other bytes
			fr := &fakeRun{fn: g.fn}
			var out bytes.Buffer
			err := Gates(context.Background(), fr.run, o, &out)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error with %q, got %v", c.want, err)
			}
			if left, _ := filepath.Glob(filepath.Join(o.Out, "*")); len(left) > 0 {
				t.Errorf("a failed run leaves %v: push would ship on an earlier pass", left)
			}
			if len(g.ctrs) > 0 {
				t.Errorf("containers left: %v", g.ctrs)
			}
			if ran := slices.ContainsFunc(fr.calls, func(a []string) bool { return a[0] == "make" }); ran != c.makes {
				t.Errorf("rebuild ran = %v, want %v (fail fast, in order): %v", ran, c.makes, fr.joined())
			}
		})
	}
}

// Before part A renames it, a prerelease package has nfpm's spelling (1.0.0~rc.1); the SemVer name wins when both exist.
func TestShippedDebNames(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "vedette-host_1.0.0~rc.1_amd64.deb"), nil, 0o600))
	if p, err := shippedDeb(dir, "1.0.0-rc.1", "amd64"); err != nil || filepath.Base(p) != "vedette-host_1.0.0~rc.1_amd64.deb" {
		t.Errorf("nfpm name: %q %v", p, err)
	}
	must(t, os.WriteFile(filepath.Join(dir, "vedette-host_1.0.0-rc.1_amd64.deb"), nil, 0o600))
	if p, err := shippedDeb(dir, "1.0.0-rc.1", "amd64"); err != nil || filepath.Base(p) != "vedette-host_1.0.0-rc.1_amd64.deb" {
		t.Errorf("SemVer name: %q %v", p, err)
	}
	must(t, os.Symlink(filepath.Join(dir, "vedette-host_1.0.0-rc.1_amd64.deb"), filepath.Join(dir, "vedette-host_1.0.0_amd64.deb")))
	if _, err := shippedDeb(dir, "1.0.0", "amd64"); err == nil {
		t.Error("a symlink accepted as the package")
	}
}

func TestDebMember(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, members ...[2]string) string {
		var b bytes.Buffer
		b.WriteString("!<arch>\n")
		for _, m := range members {
			arMember(&b, m[0], []byte(m[1]))
		}
		p := filepath.Join(dir, name)
		must(t, os.WriteFile(p, b.Bytes(), 0o600))
		return p
	}
	good := write("good.deb", [2]string{"debian-binary", "2.0\n"}, [2]string{"control.tar.gz", "odd"}, [2]string{"data.tar.gz", string(tgz(t, [][2]string{{"usr/lib/vedette/vedette-host", "BIN"}}))})
	if b, err := debMember(good); err != nil || string(b) != "BIN" {
		t.Errorf("member without ./: %q %v", b, err)
	}
	for name, c := range map[string]struct {
		path string
		want string
	}{
		"xz":      {write("xz.deb", [2]string{"debian-binary", "2.0\n"}, [2]string{"data.tar.xz", "x"}), "builds data.tar.gz"},
		"absent":  {write("absent.deb", [2]string{"data.tar.gz", string(tgz(t, [][2]string{{"./usr/bin/other", "x"}}))}), "has no " + hostBinaryInDeb},
		"symlink": {write("link.deb", [2]string{"data.tar.gz", string(tgz(t, [][2]string{{"./" + hostBinaryInDeb, "->/bin/sh"}}))}), "not a regular file"},
		"no data": {write("nodata.deb", [2]string{"debian-binary", "2.0\n"}), "has no data.tar.gz"},
	} {
		if _, err := debMember(c.path); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", name, c.want, err)
		}
	}
	notAr := filepath.Join(dir, "x.deb")
	must(t, os.WriteFile(notAr, []byte("PK\x03\x04"), 0o600))
	if _, err := debMember(notAr); err == nil {
		t.Error("a file that is not an ar archive accepted")
	}
}

// The core Containerfile labels the floor it links (D-401) under the name the gate reads, from the same MIN_SEQUENCE.
func TestCoreImageLabelsItsFloor(t *testing.T) {
	cf, err := os.ReadFile("../../deploy/containers/core/Containerfile")
	must(t, err)
	final := string(cf[bytes.LastIndex(cf, []byte("\nFROM ")):])
	if !strings.Contains(final, "\nARG MIN_SEQUENCE\n") || !strings.Contains(final, minSequenceLabel+`="${MIN_SEQUENCE}"`) {
		t.Errorf("the final stage of core/Containerfile must declare ARG MIN_SEQUENCE and set the label %s from it", minSequenceLabel)
	}
}
