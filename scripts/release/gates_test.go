package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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
	return gatesOpts{Version: "0.2.0", MinSequence: "1", PrevIndex: prev, Trust: r.trust, Platforms: allPlatforms, DebDir: dir, Repo: "repo", Out: t.TempDir()},
		&gatesFake{labels: goodLabels, rebuilt: filepath.Join(dir, "vedette-host_0.2.0_amd64.deb"), tag: "abc"}
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
	got := out.String()
	for _, want := range []string{"check-binaries -release " + filepath.Join(o.DebDir, "vedette-host_0.2.0_arm64.deb"), "localhost/vedette-core:0.2.0: org.opencontainers.image.version=0.2.0 on linux/amd64, linux/arm64, floor 1", "localhost/vedette-honeypot:0.2.0", "is what this commit builds with MIN_SEQUENCE=1"} {
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
// here the grandchild sleep holds the output pipe, so without the group kill execRun would wait for it (or for WaitDelay, 10 s).
func TestExecRunKillsTheGroup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := execRun(ctx, "sh", "-c", "sleep 30 & wait")
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("returned %v after %v", err, time.Since(start))
	}
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
