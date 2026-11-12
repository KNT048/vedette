package main

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
	"slices"
	"strings"

	"github.com/knt048/vedette/internal/release"
)

// Part A of the release job (WP-08k, D-457): install.sh with its three baked lines and its signature, and the SemVer name of a
// prerelease .deb.

var sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// bakedValues are the values of install.sh's three baked lines for the release m describes: its version and the SHA-256 of its two
// vedette-host packages. It refuses a -test. version, a version that cannot name a host package, a manifest without both packages,
// and any value outside its strict form (each is written between double quotes into a shell script).
func bakedValues(m *release.Manifest) (map[string]string, error) {
	if err := refuseTestVersion(m.Version); err != nil {
		return nil, err
	}
	if _, _, ok := release.ParseHostPackageName(release.HostPackageName(m.Version, "amd64")); !ok {
		return nil, fmt.Errorf("version %q cannot name a host package (SemVer, a prerelease of letters, digits and dots, no build metadata)", m.Version)
	}
	if m.Host == nil {
		return nil, errors.New("the manifest has no host part: install.sh installs vedette-host of the release")
	}
	want := map[string]string{"VEDETTE_VERSION": m.Version}
	for _, f := range m.Host.Files {
		v, arch, ok := release.ParseHostPackageName(f.Name)
		if !ok || v != m.Version {
			return nil, fmt.Errorf("host file %q is not vedette-host_%s_<amd64|arm64>.deb", f.Name, m.Version)
		}
		if !sha256HexRE.MatchString(f.SHA256) {
			return nil, fmt.Errorf("host file %s: sha256 %q is not 64 lower-case hex", f.Name, f.SHA256)
		}
		want["VEDETTE_DEB_SHA256_"+strings.ToUpper(arch)] = f.SHA256
	}
	for _, k := range bakedNames {
		if want[k] == "" { // install.sh serves both architectures
			return nil, fmt.Errorf("the manifest gives no value for %s: a release ships vedette-host for amd64 and arm64", k)
		}
	}
	return want, nil
}

// checkBakedLines: every line of raw that can set a baked variable (assignBakedRE, any shell form) is exactly the baked line
// NAME="want[NAME]", and each baked line is there once. release-publish (checkInstaller) and the bake use this one rule.
func checkBakedLines(raw []byte, want map[string]string) error {
	seen := map[string]int{}
	for i, l := range strings.Split(string(raw), "\n") {
		for _, mm := range assignBakedRE.FindAllStringSubmatch(l, -1) {
			if l != mm[1]+`="`+want[mm[1]]+`"` {
				return fmt.Errorf("%s line %d %q sets %s: only the one baked line %s=%q may (the signed manifest)", installer, i+1, l, mm[1], mm[1], want[mm[1]])
			}
			seen[mm[1]]++
		}
	}
	for _, k := range bakedNames {
		if seen[k] != 1 {
			return fmt.Errorf("%s: the baked line %s is there %d times, want once", installer, k, seen[k])
		}
	}
	return nil
}

// BakeInstaller fills install.sh of the repository (src, read from git at the release tag) for the release m describes: each of the
// three lines NAME="" becomes NAME="<value>", and nothing else changes. It refuses a script in which any line that can set a baked
// variable is not exactly the empty NAME="" (a filled, indented, exported or second assignment), a baked line missing or there twice,
// and a script larger than a signed document may be. The result passes the check release-publish makes.
func BakeInstaller(src []byte, m *release.Manifest) ([]byte, error) {
	want, err := bakedValues(m)
	if err != nil {
		return nil, err
	}
	if len(src) > release.MaxDocBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", installer, release.MaxDocBytes)
	}
	empty := map[string]string{}
	for _, k := range bakedNames {
		empty[k] = ""
	}
	if err := checkBakedLines(src, empty); err != nil {
		return nil, fmt.Errorf("the repository's %s must have each baked line once and empty (NAME=\"\"): %w", installer, err)
	}
	lines := strings.Split(string(src), "\n")
	for i, l := range lines {
		for _, k := range bakedNames {
			if l == k+`=""` {
				lines[i] = k + `="` + want[k] + `"`
			}
		}
	}
	out := []byte(strings.Join(lines, "\n"))
	if err := checkBakedLines(out, want); err != nil {
		return nil, err
	}
	return out, nil
}

// bakeOpts are the inputs of BakeAndSign.
type bakeOpts struct {
	Dir    string // the release directory: release-manifest.json is read from it, install.sh and its .minisig are written to it
	Inputs Inputs // release.in.json: the .deb files, hashed again and compared with the manifest
	Src    []byte // install.sh at the release tag
	Signer Signer
	Trust  release.Trust // the keys the signature is checked with right after signing
}

// BakeAndSign writes Dir/install.sh baked for the release of Dir/release-manifest.json and signs it into install.sh.minisig with the
// trusted comment "file:install.sh version:<v>" (what release-publish requires). The manifest is not signed yet at this step; the
// .deb files of release.in.json must still be the ones it names (a package rebuilt after release-manifest is refused here, not at
// publish). After signing, the signature is verified with Trust and its comment read back. On any failure neither file is left,
// not even those of an earlier run.
// It returns the key id that signed.
func BakeAndSign(ctx context.Context, o bakeOpts) (keyID string, err error) {
	p, sigPath := filepath.Join(o.Dir, installer), filepath.Join(o.Dir, installerSig)
	defer func() {
		if err != nil {
			_ = os.Remove(p)
			_ = os.Remove(sigPath)
		}
	}()
	raw, err := readDoc(filepath.Join(o.Dir, manifestFile))
	if err != nil {
		return "", fmt.Errorf("install.sh is baked from the release's manifest (run release-manifest first): %w", err)
	}
	var m release.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("manifest: %w", err)
	}
	if o.Inputs.Version != m.Version {
		return "", fmt.Errorf("release.in.json is for %q, the manifest for %q", o.Inputs.Version, m.Version)
	}
	if o.Inputs.Host == nil {
		return "", errors.New("release.in.json has no host part (the two .deb files)")
	}
	h, err := buildHostPart(*o.Inputs.Host, o.Inputs.Version, o.Inputs.Images)
	if err != nil {
		return "", err
	}
	if m.Host == nil || !slices.Equal(h.Files, m.Host.Files) {
		return "", errors.New("the vedette-host packages of release.in.json are not the ones the manifest names (rebuilt after release-manifest?): run release-manifest again")
	}
	values, err := bakedValues(&m)
	if err != nil {
		return "", err
	}
	baked, err := BakeInstaller(o.Src, &m)
	if err != nil {
		return "", err
	}
	// A signature of an earlier run must not sit next to new bytes, even for a moment; and a file (or a symlink, which WriteFile
	// would follow) already at install.sh is replaced, never written through.
	for _, f := range []string{sigPath, p} {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	if err := writeNew(p, baked); err != nil {
		return "", err
	}
	want := containerAssetComment(installer, m.Version)
	if err := o.Signer.SignFile(ctx, p, sigPath, want); err != nil {
		return "", err
	}
	got, sig, err := readSigned(p)
	if err != nil {
		return "", err
	}
	if err := release.VerifyContent(got, sig, o.Trust); err != nil {
		return "", fmt.Errorf("%s: the signature does not verify with the release keys (the wrong secret key?): %w", installer, err)
	}
	tc, keyID, err := minisigCommentAndKey(sig, o.Trust)
	if err != nil {
		return "", fmt.Errorf("%s: %w", installer, err)
	}
	if tc != want {
		return "", fmt.Errorf("%s: trusted comment %q, want %q", installer, tc, want)
	}
	if !bytes.Equal(got, baked) { // what was signed is what was baked
		return "", fmt.Errorf("%s changed while it was signed", installer)
	}
	if err := checkBakedLines(got, values); err != nil {
		return "", err
	}
	return keyID, nil
}

// writeNew creates p (it must not exist) with b, mode 0644: a release asset, not secret.
func writeNew(p string, b []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // a path under the release directory
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// cmdBakeInstall: bake-install -dir dist/release -in release.in.json -key K -minisign BIN [-ref v<version>] [-repo .] [-keys-dir DIR]
// [-passphrase-stdin]. install.sh is read from git at the release tag, never from the working tree.
func cmdBakeInstall(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	fs := newFlags("bake-install")
	dir := fs.String("dir", "dist/release", "release directory (release-manifest.json in, install.sh and install.sh.minisig out)")
	in := fs.String("in", "release.in.json", "release description (the .deb files)")
	ref := fs.String("ref", "", "git ref install.sh is read at (default v<version>)")
	repo := fs.String("repo", ".", "repository root")
	key := fs.String("key", "", "minisign secret key file of the key that signs the manifest (mode 600, outside the repository)")
	bin := fs.String("minisign", "", "absolute path of the pinned minisign (scripts/release/minisign.sh prints it)")
	keys := fs.String("keys-dir", "", "directory with the public keys the signature is checked with (default: the keys compiled in)")
	pass := fs.Bool("passphrase-stdin", false, "read the key's passphrase from the first line of stdin (default: minisign asks on the terminal)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *key == "" || *bin == "" {
		return errors.New("-key and -minisign are required")
	}
	inputs, err := readInputs(*in)
	if err != nil {
		return err
	}
	trust, err := LoadTrust(*keys)
	if err != nil {
		return err
	}
	if *ref == "" {
		*ref = "v" + inputs.Version
	}
	if !gitRefRE.MatchString(*ref) || strings.Contains(*ref, "..") {
		return fmt.Errorf("git ref %q is not a plain tag, branch or commit name", *ref)
	}
	src, err := gitRun(ctx, *repo, "show", *ref+":"+installer)
	if err != nil {
		return fmt.Errorf("%s at %s: %w", installer, *ref, err)
	}
	s := MinisignCLI{Bin: *bin, KeyPath: *key, Interactive: true}
	if root, err := RepoRoot(ctx, *repo); err == nil {
		s.RepoRoot = root
	}
	if *pass {
		line, err := readLine(stdin)
		if err != nil {
			return fmt.Errorf("passphrase: %w", err)
		}
		defer clear(line)
		s.Passphrase, s.Interactive = line, false
	}
	id, err := BakeAndSign(ctx, bakeOpts{Dir: *dir, Inputs: inputs, Src: src, Signer: s, Trust: trust})
	if err != nil {
		return err
	}
	slot := "active"
	if id == trust.Backup.KeyID() {
		slot = "backup (only for a rescue, D-259)"
	}
	say(stdout, "wrote %s and %s: release %s, signed by %s, the %s key", filepath.Join(*dir, installer), filepath.Join(*dir, installerSig), inputs.Version, id, slot)
	return nil
}

// errNoPrerelease: the version has no prerelease, so nfpm's names are the SemVer ones already.
var errNoPrerelease = errors.New("no prerelease")

// debianVersion is how nfpm (dpkg) spells a SemVer version: its first "-" becomes "~", so a prerelease sorts before the release
// (D-155 (1)). A version without a prerelease is the same.
func debianVersion(v string) string { return strings.Replace(v, "-", "~", 1) }

// RenameDebs gives the two packages host-deb built for version their SemVer names (release.HostPackageName): nfpm writes
// vedette-host_1.0.0~beta.1_amd64.deb, the release asset, release.in.json and install.sh use vedette-host_1.0.0-beta.1_amd64.deb
// (and GitHub does not keep "~" in an asset name). A version without a prerelease needs nothing. It is idempotent: a package already
// under its SemVer name is left; both names present, or neither, is refused. It returns what it renamed.
func RenameDebs(dir, version string) ([]string, error) {
	if _, _, ok := release.ParseHostPackageName(release.HostPackageName(version, "amd64")); !ok {
		return nil, fmt.Errorf("version %q cannot name a host package (SemVer without v, a prerelease of letters, digits and dots, no build metadata)", version)
	}
	if debianVersion(version) == version {
		return nil, errNoPrerelease
	}
	var done []string
	for _, arch := range []string{"amd64", "arm64"} {
		from := filepath.Join(dir, "vedette-host_"+debianVersion(version)+"_"+arch+".deb")
		to := filepath.Join(dir, release.HostPackageName(version, arch))
		fromFI, fromErr := os.Lstat(from)
		_, toErr := os.Lstat(to)
		for _, e := range []error{fromErr, toErr} {
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				return done, e
			}
		}
		switch {
		case fromErr == nil && toErr == nil:
			return done, fmt.Errorf("both %s and %s are there: remove the one that is not the build to release", filepath.Base(from), filepath.Base(to))
		case fromErr != nil && toErr != nil:
			return done, fmt.Errorf("no %s: build it with make host-deb VERSION=%s ARCH=%s", filepath.Base(from), version, arch)
		case fromErr != nil:
			continue // renamed by an earlier run
		case !fromFI.Mode().IsRegular():
			return done, fmt.Errorf("%s is not a regular file", from)
		}
		if err := os.Rename(from, to); err != nil {
			return done, err
		}
		done = append(done, to)
	}
	return done, nil
}

func cmdDebName(args []string, stdout io.Writer) error {
	fs := newFlags("deb-name")
	version := fs.String("version", "", "release version, SemVer without v")
	dir := fs.String("dir", "dist", "directory host-deb wrote the packages to")
	if err := fs.Parse(args); err != nil {
		return err
	}
	done, err := RenameDebs(*dir, *version)
	if errors.Is(err, errNoPrerelease) {
		say(stdout, "%s has no prerelease: the names host-deb wrote are the SemVer ones", *version)
		return nil
	}
	for _, d := range done {
		say(stdout, "renamed to %s", d)
	}
	if err == nil && len(done) == 0 {
		say(stdout, "nothing to rename: the packages of %s have their SemVer names already", *version)
	}
	return err
}
