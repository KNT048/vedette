//nolint:gosec // test code: every path is in a directory the test made, and the script it writes is a fake of the signing tool
package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/internal/release"
)

func realInstaller(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../install.sh")
	must(t, err)
	return b
}

func bakeManifest(version string) *release.Manifest {
	return &release.Manifest{Version: version, Host: &release.HostPart{Version: version, Files: []release.HostFile{
		{Name: release.HostPackageName(version, "amd64"), SHA256: strings.Repeat("a", 64), Size: 1},
		{Name: release.HostPackageName(version, "arm64"), SHA256: strings.Repeat("b", 64), Size: 1},
	}}}
}

// The repository's install.sh: exactly its three lines change, to the manifest's values, and the result passes publish's rule.
func TestBakeInstallerOnTheRealScript(t *testing.T) {
	src := realInstaller(t)
	m := bakeManifest("1.0.0-beta.1")
	out, err := BakeInstaller(src, m)
	must(t, err)
	a, b := strings.Split(string(src), "\n"), strings.Split(string(out), "\n")
	if len(a) != len(b) {
		t.Fatalf("%d lines became %d", len(a), len(b))
	}
	var changed []string
	for i := range a {
		if a[i] != b[i] {
			changed = append(changed, b[i])
		}
	}
	want := []string{`VEDETTE_VERSION="1.0.0-beta.1"`, `VEDETTE_DEB_SHA256_AMD64="` + strings.Repeat("a", 64) + `"`, `VEDETTE_DEB_SHA256_ARM64="` + strings.Repeat("b", 64) + `"`}
	if strings.Join(changed, "\n") != strings.Join(want, "\n") {
		t.Fatalf("changed lines:\n%s", strings.Join(changed, "\n"))
	}
	if _, err := BakeInstaller(out, m); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("a baked script was baked again: %v", err)
	}
}

func TestBakeInstallerRefusals(t *testing.T) {
	src := string(realInstaller(t))
	cases := map[string]struct {
		src  string
		m    func(*release.Manifest)
		want string
	}{
		"a -test. version":         {src, func(m *release.Manifest) { m.Version = "1.0.0-test.1" }, "-test."},
		"build metadata":           {src, func(m *release.Manifest) { m.Version = "1.0.0+b1" }, "cannot name a host package"},
		"one architecture":         {src, func(m *release.Manifest) { m.Host.Files = m.Host.Files[:1] }, "amd64 and arm64"},
		"no host part":             {src, func(m *release.Manifest) { m.Host = nil }, "no host part"},
		"a shell string as sha256": {src, func(m *release.Manifest) { m.Host.Files[0].SHA256 = `"; rm -rf / #` }, "64 lower-case hex"},
		"upper-case sha256":        {src, func(m *release.Manifest) { m.Host.Files[1].SHA256 = strings.Repeat("A", 64) }, "64 lower-case hex"},
		"package of another version": {src, func(m *release.Manifest) {
			m.Host.Files[1].Name = release.HostPackageName("0.9.0", "arm64")
		}, "is not vedette-host_1.0.0_"},
		"template line filled":  {strings.Replace(src, "\nVEDETTE_VERSION=\"\"\n", "\nVEDETTE_VERSION=\"0.9.0\"\n", 1), nil, "empty"},
		"template line missing": {strings.Replace(src, "\nVEDETTE_DEB_SHA256_ARM64=\"\"\n", "\n", 1), nil, "0 times"},
		"template line twice":   {src + "VEDETTE_VERSION=\"\"\n", nil, "2 times"},
		"another assignment":    {src + "export VEDETTE_VERSION=\"9.9.9\"\n", nil, "sets VEDETTE_VERSION"},
		"a CRLF template line":  {strings.Replace(src, "\nVEDETTE_VERSION=\"\"\n", "\nVEDETTE_VERSION=\"\"\r\n", 1), nil, "sets VEDETTE_VERSION"},
		"too large":             {src + strings.Repeat("#", release.MaxDocBytes), nil, "larger than"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			m := bakeManifest("1.0.0")
			if c.m != nil {
				c.m(m)
			}
			if _, err := BakeInstaller([]byte(c.src), m); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

// What the bake writes and signs is what release-publish accepts: checkInstaller and planPublish on a signed release directory.
func TestBakeAndSignIsWhatPublishAccepts(t *testing.T) {
	r := newRig(t)
	dir, s, in := signedRelease(t, r, "0.2.0", "")
	// a symlink at install.sh is replaced, never written through
	victim := filepath.Join(t.TempDir(), "victim")
	must(t, os.WriteFile(victim, []byte("keep"), 0o600))
	must(t, os.Remove(filepath.Join(dir, installer)))
	must(t, os.Symlink(victim, filepath.Join(dir, installer)))
	id, err := BakeAndSign(t.Context(), bakeOpts{Dir: dir, Inputs: *in, Src: realInstaller(t), Signer: testSigner{t, r.active}, Trust: r.trust})
	must(t, err)
	if id != r.trust.Active.KeyID() {
		t.Errorf("signed by %s", id)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Error("the bake wrote through a symlink")
	}
	raw, _, err := checkInstaller(dir, mustManifest(t, dir), r.trust.Active.KeyID(), r.trust)
	must(t, err)
	if !bytes.Contains(raw, []byte("\nREPO_URL=")) {
		t.Error("install.sh is not the repository's script")
	}
	_, err = planPublish(dir, s, in, r.trust)
	must(t, err)
}

func TestBakeAndSignRefusesAndLeavesNothing(t *testing.T) {
	r := newRig(t)
	other := newRig(t)
	gone := func(t *testing.T, dir string) {
		t.Helper()
		for _, n := range []string{installer, installerSig} {
			if _, err := os.Lstat(filepath.Join(dir, n)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s was left: %v", n, err)
			}
		}
	}
	cases := map[string]struct {
		mut  func(dir string, o *bakeOpts)
		want string
	}{
		"package rebuilt after the manifest": {func(_ string, o *bakeOpts) { must(t, os.WriteFile(o.Inputs.Host.Files[0], []byte("rebuilt"), 0o600)) }, "rebuilt after release-manifest"},
		"description of another release":     {func(_ string, o *bakeOpts) { o.Inputs.Version = "0.2.1" }, "release.in.json is for"},
		"no manifest":                        {func(d string, _ *bakeOpts) { must(t, os.Remove(filepath.Join(d, manifestFile))) }, "run release-manifest first"},
		"a key the release keys do not know": {func(_ string, o *bakeOpts) { o.Signer = testSigner{t, other.active} }, "does not verify"},
		"the signer fails": {func(_ string, o *bakeOpts) {
			o.Signer = &failingSigner{inner: testSigner{t, r.active}, failOn: 1}
		}, "signer failed"},
		"template already filled": {func(_ string, o *bakeOpts) {
			o.Src = bytes.Replace(o.Src, []byte("\nVEDETTE_VERSION=\"\"\n"), []byte("\nVEDETTE_VERSION=\"0.2.0\"\n"), 1)
		}, "empty"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir, _, in := signedRelease(t, r, "0.2.0", "") // holds a signed install.sh of an earlier bake: it must go too
			o := bakeOpts{Dir: dir, Inputs: *in, Src: realInstaller(t), Signer: testSigner{t, r.active}, Trust: r.trust}
			x := *in.Host
			x.Files = append([]string(nil), in.Host.Files...)
			o.Inputs.Host = &x
			c.mut(dir, &o)
			if _, err := BakeAndSign(t.Context(), o); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			gone(t, dir)
		})
	}
}

// The command reads install.sh from git at the release tag (never the working tree) and signs it through the minisign command line,
// here a fake that writes the signature the test made over the expected bytes; the signature is then checked with -keys-dir.
func TestBakeInstallCommand(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	r := newRig(t)
	dir, _, in := signedRelease(t, r, "0.2.0", "")
	repo := t.TempDir()
	must(t, os.WriteFile(filepath.Join(repo, installer), realInstaller(t), 0o600))
	gitT(t, repo, "init", "-q")
	gitT(t, repo, "add", "-A")
	gitT(t, repo, "commit", "-q", "-m", "release")
	gitT(t, repo, "tag", "v0.2.0")
	// an edit after the tag is not what ships
	must(t, os.WriteFile(filepath.Join(repo, installer), append(realInstaller(t), "echo edited after the tag\n"...), 0o600))

	work := t.TempDir()
	inPath := filepath.Join(work, "release.in.json")
	b, err := marshal(*in)
	must(t, err)
	must(t, os.WriteFile(inPath, b, 0o600))
	keys := filepath.Join(work, "keys")
	must(t, os.MkdirAll(keys, 0o700))
	writeKeys(t, r, keys)
	secret := filepath.Join(work, "minisign.key")
	must(t, os.WriteFile(secret, []byte("not a real key"), 0o600))
	want, err := BakeInstaller(realInstaller(t), mustManifest(t, dir))
	must(t, err)
	presig := filepath.Join(work, "presig")
	must(t, os.WriteFile(presig, r.active.SignComment(want, "file:install.sh version:0.2.0"), 0o600))
	fake := filepath.Join(work, "minisign")
	must(t, os.WriteFile(fake, []byte("#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = -x ]; then cp '"+presig+"' \"$2\"; fi; shift; done\n"), 0o755))

	do := func(extra ...string) (int, string) {
		var o, e bytes.Buffer
		code := run(append([]string{"bake-install", "-dir", dir, "-in", inPath, "-repo", repo, "-key", secret, "-minisign", fake, "-keys-dir", keys}, extra...), nil, &o, &e)
		return code, o.String() + e.String()
	}
	if code, msg := do(); code != 0 || !strings.Contains(msg, "the active key") {
		t.Fatalf("%d %s", code, msg)
	}
	got, err := os.ReadFile(filepath.Join(dir, installer))
	must(t, err)
	if !bytes.Equal(got, want) {
		t.Error("install.sh is not the tagged script baked")
	}
	_, _, err = checkInstaller(dir, mustManifest(t, dir), r.trust.Active.KeyID(), r.trust)
	must(t, err)
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"a tag that does not exist": {[]string{"-ref", "v9.9.9"}, "v9.9.9"},
		"a range as ref":            {[]string{"-ref", "v0.2.0..HEAD"}, "plain"},
		"no key":                    {[]string{"-key", ""}, "-key and -minisign"},
	} {
		if code, msg := do(c.args...); code == 0 || !strings.Contains(msg, c.want) {
			t.Errorf("%s: %d %s", name, code, msg)
		}
	}
}

func TestRenameDebs(t *testing.T) {
	dir := t.TempDir()
	for _, arch := range []string{"amd64", "arm64"} {
		must(t, os.WriteFile(filepath.Join(dir, "vedette-host_1.0.0~beta.1_"+arch+".deb"), []byte(arch), 0o600))
	}
	done, err := RenameDebs(dir, "1.0.0-beta.1")
	must(t, err)
	if len(done) != 2 {
		t.Fatalf("%v", done)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		if b, err := os.ReadFile(filepath.Join(dir, release.HostPackageName("1.0.0-beta.1", arch))); err != nil || string(b) != arch {
			t.Errorf("%s: %q %v", arch, b, err)
		}
	}
	// again: nothing to do
	if done, err := RenameDebs(dir, "1.0.0-beta.1"); err != nil || len(done) != 0 {
		t.Errorf("a second run: %v %v", done, err)
	}
	if _, err := RenameDebs(dir, "1.0.0"); !errors.Is(err, errNoPrerelease) {
		t.Errorf("a release without a prerelease: %v", err)
	}
	// a rebuild next to the renamed package, a package not built, a version that names no package
	must(t, os.WriteFile(filepath.Join(dir, "vedette-host_1.0.0~beta.1_arm64.deb"), []byte("again"), 0o600))
	if _, err := RenameDebs(dir, "1.0.0-beta.1"); err == nil || !strings.Contains(err.Error(), "both") {
		t.Errorf("both names: %v", err)
	}
	if _, err := RenameDebs(dir, "1.0.0-rc.1"); err == nil || !strings.Contains(err.Error(), "make host-deb") {
		t.Errorf("not built: %v", err)
	}
	if _, err := RenameDebs(dir, "1.0.0-rc-1"); err == nil || !strings.Contains(err.Error(), "cannot name") {
		t.Errorf("a prerelease with a dash: %v", err)
	}
	var o, e bytes.Buffer
	if code := run([]string{"deb-name", "-version", "1.0.0", "-dir", dir}, nil, &o, &e); code != 0 || !strings.Contains(o.String(), "no prerelease") {
		t.Errorf("%d %s %s", code, o.String(), e.String())
	}
}
