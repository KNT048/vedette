// Package deb checks the vedette-host .deb (WP-08g, D-155) by building it: nfpm runs for real (go tool -modfile=tools/go.mod nfpm, pinned,
// a few seconds) over a placeholder binary, and the control fields, the file list with modes and owners, the unit bytes and the maintainer scripts
// are read back from the package. Nothing is installed here: what the scripts do to a system (users, directories, /etc/subuid, enabled and not
// started, data kept on remove) is checked by scripts/dev/host-deb-check.sh in a systemd container (`make host-deb-check`, opt-in).
package deb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec" //nolint:depguard // the test builds the package with the pinned nfpm: fixed argv, no shell; SYS-1 is about the product
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

const root = "../.."

// pkg is a built package, read back.
type pkg struct {
	control string
	scripts map[string]file // by name in the control archive (postinst, ...)
	members []string        // names in the control archive
	files   map[string]file // by path in the data archive, without the leading ./
}

type file struct {
	mode  int64
	uid   int
	gid   int
	uname string
	gname string
	isDir bool
	data  []byte
}

// build runs nfpm for version and arch and reads the .deb: an ar archive of debian-binary, control.tar.gz and data.tar.gz (the nfpm.yaml pins gzip).
func build(t *testing.T, version, arch string) pkg {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go is not on PATH: %v", err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "vedette-host")
	if err := os.WriteFile(bin, []byte("\x7fELF placeholder, not run"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBin, "tool", "-modfile=tools/go.mod", "nfpm", "pkg", "--packager", "deb", "--config", "deploy/deb/nfpm.yaml", "--target", out) //nolint:gosec // test: fixed argv
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "VERSION="+version, "ARCH="+arch, "BINARY="+bin)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nfpm: %v\n%s", err, b)
	}
	names, _ := filepath.Glob(filepath.Join(out, "*.deb"))
	if len(names) != 1 {
		t.Fatalf("want exactly one .deb, got %v", names)
	}
	raw, err := os.ReadFile(names[0])
	if err != nil {
		t.Fatal(err)
	}
	members := readAr(t, raw)
	if string(members["debian-binary"]) != "2.0\n" {
		t.Fatalf("debian-binary = %q", members["debian-binary"])
	}
	for _, need := range []string{"control.tar.gz", "data.tar.gz"} {
		if members[need] == nil {
			t.Fatalf("the package has no %s (members: %v)", need, keys(members))
		}
	}
	p := pkg{scripts: map[string]file{}, files: map[string]file{}}
	for name, f := range readTarGz(t, members["control.tar.gz"]) {
		name = strings.TrimPrefix(name, "./")
		p.members = append(p.members, name)
		if name == "control" {
			p.control = string(f.data)
		}
		p.scripts[name] = f
	}
	for name, f := range readTarGz(t, members["data.tar.gz"]) {
		p.files[strings.TrimSuffix(strings.TrimPrefix(name, "./"), "/")] = f
	}
	return p
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// readAr reads the members of an ar archive (the deb container): "!<arch>\n", then 60-byte headers (name 16, ..., size 10 at offset 48, "`\n").
func readAr(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	if !bytes.HasPrefix(b, []byte("!<arch>\n")) {
		t.Fatal("not an ar archive")
	}
	out := map[string][]byte{}
	b = b[8:]
	for len(b) > 0 {
		if len(b) < 60 || string(b[58:60]) != "`\n" {
			t.Fatal("bad ar header")
		}
		name := strings.TrimRight(strings.TrimSpace(string(b[:16])), "/")
		var size int
		for _, c := range strings.TrimSpace(string(b[48:58])) {
			size = size*10 + int(c-'0')
		}
		b = b[60:]
		if size > len(b) {
			t.Fatal("ar member is cut off")
		}
		out[name] = b[:size]
		b = b[size:]
		if size%2 == 1 && len(b) > 0 {
			b = b[1:]
		}
	}
	return out
}

func readTarGz(t *testing.T, gz []byte) map[string]file {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	out := map[string]file{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[h.Name] = file{mode: h.Mode & 0o7777, uid: h.Uid, gid: h.Gid, uname: h.Uname, gname: h.Gname, isDir: h.Typeflag == tar.TypeDir, data: data}
	}
}

// fields parses the control file (one paragraph; continuation lines start with a space).
func fields(control string) map[string]string {
	out := map[string]string{}
	last := ""
	for l := range strings.SplitSeq(strings.TrimRight(control, "\n"), "\n") {
		if strings.HasPrefix(l, " ") && last != "" {
			out[last] += "\n" + l
			continue
		}
		k, v, _ := strings.Cut(l, ": ")
		out[k] = v
		last = k
	}
	return out
}

func repoFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // test: fixed paths inside the repository
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPackage_ControlFields(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		f := fields(build(t, "0.1.0", arch).control)
		if f["Package"] != "vedette-host" || f["Version"] != "0.1.0" || f["Architecture"] != arch {
			t.Errorf("%s: Package/Version/Architecture = %q %q %q", arch, f["Package"], f["Version"], f["Architecture"])
		}
		if !regexp.MustCompile(`^[^<>]+ <[^<>@ ]+@[^<> ]+>$`).MatchString(f["Maintainer"]) {
			t.Errorf("%s: Maintainer %q is not 'Name <address>' (Debian Policy 5.6.2)", arch, f["Maintainer"])
		}
		if f["Section"] != "admin" || f["Priority"] != "optional" || f["Homepage"] != "https://github.com/KNT048/vedette" {
			t.Errorf("%s: Section/Priority/Homepage = %q %q %q", arch, f["Section"], f["Priority"], f["Homepage"])
		}
	}
}

// A release candidate must sort before the release: dpkg writes it with a tilde.
func TestPackage_PrereleaseSortsBeforeRelease(t *testing.T) {
	if got := fields(build(t, "0.2.0-rc.1", "amd64").control)["Version"]; got != "0.2.0~rc.1" {
		t.Errorf("Version of 0.2.0-rc.1 = %q, want 0.2.0~rc.1", got)
	}
}

// Depends: minimums, not exact versions (D-155). Every entry is named here on purpose, with the reason in deploy/deb/nfpm.yaml.
func TestPackage_Depends(t *testing.T) {
	want := []string{"podman (>= 4.4)", "systemd (>= 254)", "nftables", "iproute2", "procps", "chrony", "netplan.io", "unattended-upgrades", "passwd"}
	var got []string
	for d := range strings.SplitSeq(fields(build(t, "0.1.0", "amd64").control)["Depends"], ", ") {
		got = append(got, d)
	}
	if !slices.Equal(got, want) {
		t.Errorf("Depends = %q, want %q", got, want)
	}
	for _, d := range got {
		if strings.Contains(d, "(=") || strings.Contains(d, "<<") {
			t.Errorf("Depends %q pins an exact or an upper version", d)
		}
	}
}

func TestPackage_Files(t *testing.T) {
	p := build(t, "0.1.0", "amd64")
	want := map[string]int64{
		"usr/lib/vedette/vedette-host":                0o755,
		"usr/lib/systemd/system/vedette-host.service": 0o644,
		"usr/share/doc/vedette-host/copyright":        0o644,
		"usr/share/doc/vedette-host/NOTICE":           0o644,
	}
	for path, f := range p.files {
		if f.isDir {
			if f.mode != 0o755 || f.uid != 0 || f.gid != 0 {
				t.Errorf("directory %s: mode %o owner %d:%d, want 755 0:0", path, f.mode, f.uid, f.gid)
			}
			// the package owns no directory of the data it must keep
			for _, kept := range []string{"var", "etc"} {
				if path == kept || strings.HasPrefix(path, kept+"/") {
					t.Errorf("the package owns %s: data and configuration directories are made by the postinst and kept on purge", path)
				}
			}
			continue
		}
		mode, ok := want[path]
		if !ok {
			t.Errorf("unexpected file %s", path)
			continue
		}
		if f.mode != mode || f.uid != 0 || f.gid != 0 || f.uname != "root" || f.gname != "root" {
			t.Errorf("%s: mode %o owner %s:%s (%d:%d), want %o root:root", path, f.mode, f.uname, f.gname, f.uid, f.gid, mode)
		}
		delete(want, path)
	}
	for path := range want {
		t.Errorf("missing file %s", path)
	}
	// no conffiles: host.conf is the installer's, not shipped; nothing here is meant to be edited by an administrator
	if got := strings.TrimSpace(string(p.scripts["conffiles"].data)); got != "" {
		t.Errorf("the package lists conffiles: %q", got)
	}
}

func TestPackage_UnitIsTheRepoFileByteForByte(t *testing.T) {
	p := build(t, "0.1.0", "amd64")
	if !bytes.Equal(p.files["usr/lib/systemd/system/vedette-host.service"].data, repoFile(t, "deploy/systemd/vedette-host.service")) {
		t.Error("the unit in the package differs from deploy/systemd/vedette-host.service")
	}
	if c := p.files["usr/share/doc/vedette-host/copyright"].data; !bytes.Contains(c, []byte("Apache License")) || !bytes.Contains(c, []byte("Version 2.0")) {
		t.Error("the copyright file is not the Apache License 2.0 text")
	}
}

var codeLine = regexp.MustCompile(`^[^#]`)

func TestPackage_Scripts(t *testing.T) {
	p := build(t, "0.1.0", "amd64")
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"postinst", "prerm", "postrm"} {
		s, ok := p.scripts[name]
		if !ok {
			t.Fatalf("no %s in the package", name)
		}
		if s.mode != 0o755 {
			t.Errorf("%s mode %o, want 755", name, s.mode)
		}
		text := string(s.data)
		if !strings.HasPrefix(text, "#!/bin/sh\n") || !strings.Contains(text, "\nset -eu\n") {
			t.Errorf("%s must be POSIX sh with set -eu", name)
		}
		if strings.Contains(text, "bash") || strings.Contains(text, "[[") {
			t.Errorf("%s uses a bashism", name)
		}
		syntax := exec.CommandContext(t.Context(), sh, "-n") //nolint:gosec // test: the shell of the machine, fixed argv
		syntax.Stdin = bytes.NewReader(s.data)
		if b, err := syntax.CombinedOutput(); err != nil {
			t.Errorf("sh -n %s: %v\n%s", name, err, b)
		}
		// the package files and the repo files are the same bytes
		if !bytes.Equal(s.data, repoFile(t, "deploy/deb/"+name)) {
			t.Errorf("%s in the package differs from deploy/deb/%s", name, name)
		}
	}
}

// The postinst enables the unit and never starts it (the installer starts it once host.conf exists), creates the users with
// ids the system allocates, and never deletes anything; the postrm never deletes data, users or subuid lines.
func TestScripts_Rules(t *testing.T) {
	code := func(name string) string {
		var out []string
		for l := range strings.SplitSeq(string(repoFile(t, "deploy/deb/"+name)), "\n") {
			if codeLine.MatchString(strings.TrimSpace(l)) {
				out = append(out, l)
			}
		}
		return strings.Join(out, "\n")
	}
	post := code("postinst")
	for _, bad := range []string{"deb-systemd-invoke", "systemctl start", "systemctl restart", "try-restart", "--now", "--uid", "userdel", "groupdel", "rm -"} {
		if strings.Contains(post, bad) {
			t.Errorf("postinst contains %q", bad)
		}
	}
	if !regexp.MustCompile(`useradd --system --gid "\$1" `).MatchString(post) {
		t.Error("postinst must create users with useradd --system and no fixed --uid (ids are allocated by the system; the installer reads them with getent)")
	}
	for _, need := range []string{"groupadd --system", "containers:2147483647:2147483648", "daemon-reload", "was-enabled", "install -d -m 0700 -o \"$CORE\" -g \"$CORE\" /var/lib/vedette"} {
		if !strings.Contains(post, need) {
			t.Errorf("postinst lacks %q", need)
		}
	}
	for _, name := range []string{"prerm", "postrm"} {
		c := code(name)
		for _, bad := range []string{"rm ", "userdel", "groupdel", "rmdir", "subuid", "subgid"} {
			if strings.Contains(c, bad) {
				t.Errorf("%s contains %q: remove and purge never delete data, users or subuid lines", name, bad)
			}
		}
	}
	// stop and disable only on remove, never on upgrade
	pre := code("prerm")
	if !strings.Contains(pre, "remove | deconfigure)") || !strings.Contains(pre, "upgrade | failed-upgrade) ;;") {
		t.Error("prerm must stop the unit on remove and deconfigure, and do nothing on upgrade")
	}
}
