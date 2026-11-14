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
	"debug/elf"
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

	"github.com/knt048/vedette/host/ops"
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
	// the license file is generated like `make host-deb` does it
	lic := filepath.Join(dir, "third-party-licenses")
	gen := exec.CommandContext(ctx, goBin, "run", "./scripts/hostlicenses", "-goos", "linux", "-goarch", arch, "-out", lic) //nolint:gosec // test: fixed argv
	gen.Dir = root
	if b, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("hostlicenses: %v\n%s", err, b)
	}
	cmd.Env = append(os.Environ(), "VERSION="+version, "ARCH="+arch, "BINARY="+bin, "LICENSES="+lic)
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
		if f["Bugs"] != "https://github.com/KNT048/vedette/issues" {
			t.Errorf("%s: Bugs = %q, want GitHub Issues (D-541)", arch, f["Bugs"])
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
	want := []string{"podman (>= 4.8)", "systemd (>= 254)", "nftables", "iproute2", "procps", "conntrack", "chrony", "netplan.io", "unattended-upgrades", "passwd"}
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
		"usr/lib/vedette/vedette-host":                    0o755,
		"usr/lib/systemd/system/vedette-host.service":     0o644,
		"usr/lib/vedette/honeypot-containers.conf":        0o644,
		"usr/lib/vedette/apparmor-containers.conf":        0o644,
		"etc/apparmor.d/vedette-container":                0o644,
		"usr/share/doc/vedette-host/copyright":            0o644,
		"usr/share/doc/vedette-host/NOTICE":               0o644,
		"usr/share/doc/vedette-host/third-party-licenses": 0o644,
	}
	for path, f := range p.files {
		if f.isDir {
			if f.mode != 0o755 || f.uid != 0 || f.gid != 0 {
				t.Errorf("directory %s: mode %o owner %d:%d, want 755 0:0", path, f.mode, f.uid, f.gid)
			}
			// the package owns no directory of the data it must keep; /etc and /etc/apparmor.d are shared system directories
			// (the AppArmor profile, D-458), which dpkg never removes while another package or a file is in them
			for _, kept := range []string{"var", "etc"} {
				if path == "etc" || path == "etc/apparmor.d" {
					continue
				}
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
	// one conffile, the AppArmor profile (D-458: every profile under /etc/apparmor.d is one, as dh_apparmor ships them; apt runs
	// with --force-confold, so an administrator's edit is kept without a prompt). host.conf is the installer's, not shipped.
	if got := strings.TrimSpace(string(p.scripts["conffiles"].data)); got != "/etc/apparmor.d/vedette-container" {
		t.Errorf("the package lists conffiles %q, want only /etc/apparmor.d/vedette-container", got)
	}
}

func TestPackage_UnitIsTheRepoFileByteForByte(t *testing.T) {
	p := build(t, "0.1.0", "amd64")
	if !bytes.Equal(p.files["usr/lib/systemd/system/vedette-host.service"].data, repoFile(t, "deploy/systemd/vedette-host.service")) {
		t.Error("the unit in the package differs from deploy/systemd/vedette-host.service")
	}
	// the honeypot unit names this file (ContainersConfModule=, #486): same path, and it clears default_sysctls
	if c := p.files[strings.TrimPrefix(ops.HoneypotConfModule, "/")].data; !bytes.Equal(c, repoFile(t, "deploy/deb/honeypot-containers.conf")) ||
		!bytes.Contains(c, []byte("\n[containers]\ndefault_sysctls = [{append=false}]\n")) {
		t.Errorf("the package has no %s that clears default_sysctls", ops.HoneypotConfModule)
	}
	// every unit names this module (D-458): same path, the profile the package installs, by its name
	if c := p.files[strings.TrimPrefix(ops.AppArmorConfModule, "/")].data; !bytes.Equal(c, repoFile(t, "deploy/deb/apparmor-containers.conf")) ||
		!bytes.Contains(c, []byte("\n[containers]\napparmor_profile = \""+ops.AppArmorProfile+"\"\n")) {
		t.Errorf("the package has no %s that selects the AppArmor profile %s", ops.AppArmorConfModule, ops.AppArmorProfile)
	}
	if c := p.files["etc/apparmor.d/"+ops.AppArmorProfile].data; !bytes.Equal(c, repoFile(t, "deploy/deb/vedette-container.apparmor")) {
		t.Errorf("/etc/apparmor.d/%s differs from deploy/deb/vedette-container.apparmor", ops.AppArmorProfile)
	}
	if c := p.files["usr/share/doc/vedette-host/copyright"].data; !bytes.Contains(c, []byte("Apache License")) || !bytes.Contains(c, []byte("Version 2.0")) {
		t.Error("the copyright file is not the Apache License 2.0 text")
	}
	tp := string(p.files["usr/share/doc/vedette-host/third-party-licenses"].data)
	if !strings.Contains(tp, "== Go standard library and runtime (LICENSE)") || !strings.Contains(tp, "== golang.org/x/sys ") {
		t.Error("third-party-licenses lacks the Go license or a linked module (scripts/hostlicenses tests the full list)")
	}
	if n := string(p.files["usr/share/doc/vedette-host/NOTICE"].data); !strings.Contains(n, "third-party-licenses") {
		t.Error("NOTICE does not point at third-party-licenses")
	}
}

// Opt-in (host-deb-check sets VEDETTE_HOST_BINARY to the binary `make host-deb` built): the binary is static, with no program
// interpreter, so it runs on every supported distribution whatever libc it has.
func TestBinaryIsStatic(t *testing.T) {
	path := os.Getenv("VEDETTE_HOST_BINARY")
	if path == "" {
		t.Skip("VEDETTE_HOST_BINARY is not set (opt-in, make host-deb-check)")
	}
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			t.Error("the binary has a PT_INTERP: it is dynamically linked")
		}
	}
	if libs, _ := f.ImportedLibraries(); len(libs) != 0 {
		t.Errorf("the binary needs shared libraries: %v", libs)
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
// The honeypot's log/ is the volume vedette-hp-log (D-318): the postinst neither makes nor checks /var/lib/vedette-honeypot/log (D-412).
// A box installed before D-412 has one that podman's :U gave to the container (D-162): an upgrade must not stop at it, which a
// `once` check would do, and must not make an unused folder on a new box (lab L1).
func TestPostinst_NoHoneypotLogFolder(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("postinst")
	if err != nil {
		t.Fatal(err)
	}
	for l := range strings.SplitSeq(string(b), "\n") {
		if codeLine.MatchString(strings.TrimSpace(l)) && strings.Contains(l, "/var/lib/vedette-honeypot/log") {
			t.Errorf("the postinst touches the honeypot's old log folder: %q", strings.TrimSpace(l))
		}
	}
}

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
	for _, bad := range []string{"systemctl start", "systemctl restart", "deb-systemd-invoke start", "deb-systemd-invoke restart", "--now", "--uid", "userdel", "groupdel", "rm -"} {
		if strings.Contains(post, bad) {
			t.Errorf("postinst contains %q", bad)
		}
	}
	if !regexp.MustCompile(`useradd --system --gid "\$1" `).MatchString(post) {
		t.Error("postinst must create users with useradd --system and no fixed --uid (ids are allocated by the system; the installer reads them with getent)")
	}
	for _, need := range []string{"groupadd --system", "containers:2147483647:2147483648", "daemon-reload", "was-enabled", "once 700 \"$CORE\" /var/lib/vedette", "check_account", "check_dirs", "check_subid", "SYS_UID_MIN", "[ ! -L"} {
		if !strings.Contains(post, need) {
			t.Errorf("postinst lacks %q", need)
		}
	}
	// the one removal: the AppArmor cache file of the profile on purge (D-458, as dh_apparmor), exactly this line
	cacheRm := "rm -f /var/cache/apparmor/*/vedette-container /var/cache/apparmor/vedette-container"
	if !strings.Contains(code("postrm"), "\t\t"+cacheRm+"\n") {
		t.Error("postrm must remove the AppArmor cache file of vedette-container on purge")
	}
	for _, name := range []string{"prerm", "postrm"} {
		c := strings.Replace(code(name), cacheRm, "", 1)
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

// M2: an upgrade restarts a vedette-host that is running (try-restart: a stopped unit stays stopped, a first install starts
// nothing); the old daemon must not outlive the new package. This runs the real restart_after_upgrade of the postinst with
// deb-systemd-invoke and systemctl replaced by recorders on PATH, and reads the configure branch to see it is called after the
// reload, inside the systemd check, with the previous version ($2). host-deb-check proves the effect in a systemd container.
func TestPostinst_UpgradeRestartsARunningHost(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("postinst")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	i := strings.Index(text, "restart_after_upgrade() {")
	if i < 0 {
		t.Fatal("the postinst has no restart_after_upgrade")
	}
	j := strings.Index(text[i:], "\n}\n")
	if j < 0 {
		t.Fatal("restart_after_upgrade has no end")
	}
	fn := text[i : i+j+3]
	if !strings.Contains(text, "daemon-reload >/dev/null || true\n\t\trestart_after_upgrade \"${2:-}\"\n\tfi") {
		t.Error("configure must call restart_after_upgrade \"${2:-}\" right after the daemon-reload, inside the systemd check")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	run := func(t *testing.T, withInvoke bool, old string) string {
		t.Helper()
		bin := t.TempDir()
		log := filepath.Join(bin, "calls")
		rec := "#!/bin/sh\necho \"${0##*/} $*\" >> " + log + "\n"
		names := []string{"systemctl"}
		if withInvoke {
			names = append(names, "deb-systemd-invoke")
		}
		for _, n := range names {
			if err := os.WriteFile(filepath.Join(bin, n), []byte(rec), 0o755); err != nil { //nolint:gosec // test: a recorder script in a temp dir
				t.Fatal(err)
			}
		}
		// command -v must not find the real deb-systemd-invoke of the machine: PATH is the recorders and the shell's own dir only
		cmd := exec.CommandContext(t.Context(), sh, "-c", "set -eu\nUNIT=vedette-host.service\n"+fn+"restart_after_upgrade \""+old+"\"\n") //nolint:gosec // test: the postinst's own function
		cmd.Env = []string{"PATH=" + bin}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("restart_after_upgrade: %v %s", err, out)
		}
		got, _ := os.ReadFile(log) //nolint:gosec // test: the recorder file this test created
		return string(got)
	}
	if got := run(t, true, "0.1.0"); got != "deb-systemd-invoke try-restart vedette-host.service\n" {
		t.Errorf("upgrade with the Debian helper: %q", got)
	}
	if got := run(t, false, "0.1.0"); got != "systemctl --system try-restart vedette-host.service\n" {
		t.Errorf("upgrade without the helper: %q", got)
	}
	if got := run(t, true, ""); got != "" {
		t.Errorf("a first install must start or restart nothing: %q", got)
	}
}
