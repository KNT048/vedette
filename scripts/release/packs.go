package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/knt048/vedette/internal/release"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/mitigation"
)

// Limits of the pack directory before signing: the ones mitigation.ReadPackDir holds the box to (maxDocBytes, maxPackTotal in
// modules/mitigation), checked again by that reader over the signed result.
const (
	maxPackDoc   = 256 << 10
	maxPackTotal = 32 << 20
)

// packVersionRE is the version of a pack set: dotted numbers (2026.12.2.1), which findings.CompareVersions orders as the box does.
// A date with hyphens is refused: CompareVersions("2026-12-02.1", "2026-12-02.2") is 0, so the second set would never install.
var packVersionRE = regexp.MustCompile(`^[0-9]{1,9}(\.[0-9]{1,9}){1,5}$`)

// SignPacks signs the confirmed mitigation packs of dir in place (D-345, D-346): the *.json packs are put into
// mitigation.Statement with version, the statement is signed with s, the signature is checked with release.VerifyContent and the
// keys of trust, and only then are VERSION, packs.list and packs.minisig written into dir. The result is read back with the box's
// reader (mitigation.ReadPackDir) and verified again. It returns the number of packs signed.
//
// It refuses: no pack, a link, a sub-directory or a file that is neither a pack, VERSION, packs.list, packs.minisig nor a README
// (all of dir ships in the core image), a version the box cannot order, and a version not newer than the VERSION already in dir
// (the box installs only a newer one). When signing or the check fails, dir is left as it was; when a write fails half way, VERSION
// (written last) still names the old set, the box refuses the mix (fail closed) and the same command run again finishes it.
func SignPacks(ctx context.Context, s Signer, dir, version string, trust release.Trust) (int, error) {
	if !packVersionRE.MatchString(version) {
		return 0, fmt.Errorf("-version %q cannot be ordered by the box: use dotted numbers such as 2026.12.2.1", version)
	}
	if _, ok := findings.CompareVersions(version, version); !ok {
		return 0, fmt.Errorf("-version %q cannot be ordered by the box: use dotted numbers such as 2026.12.2.1", version)
	}
	docs, err := readPackSources(dir)
	if err != nil {
		return 0, err
	}
	switch old, err := os.ReadFile(filepath.Join(dir, mitigation.PackVersionFile)); { //nolint:gosec // the maintainer's pack directory
	case err == nil:
		prev := strings.TrimSuffix(string(old), "\n")
		if order, ok := findings.CompareVersions(version, prev); !ok || order <= 0 {
			return 0, fmt.Errorf("-version %s is not newer than the packs' current %s: boxes install only a newer version", version, prev)
		}
	case !errors.Is(err, os.ErrNotExist):
		return 0, err
	}
	stmt, err := mitigation.Statement(version, docs)
	if err != nil {
		return 0, err
	}
	// Signed in a directory of its own, so a failed or refused signature never lands next to the packs.
	work, err := os.MkdirTemp("", "vedette-packs-*")
	if err != nil {
		return 0, err
	}
	defer func() { _ = os.RemoveAll(work) }()
	list, sigPath := filepath.Join(work, mitigation.PackStatementFile), filepath.Join(work, mitigation.PackSignatureFile)
	if err := os.WriteFile(list, stmt, 0o600); err != nil {
		return 0, err
	}
	if err := s.SignFile(ctx, list, sigPath, "file:"+mitigation.PackStatementFile+" version:"+version); err != nil {
		return 0, err
	}
	sig, err := readSmall(sigPath, release.MaxSigBytes)
	if err != nil {
		return 0, err
	}
	if err := release.VerifyContent(stmt, sig, trust); err != nil {
		return 0, fmt.Errorf("the pack signature does not verify with these keys, nothing was written: %w", err)
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{mitigation.PackStatementFile, stmt}, {mitigation.PackSignatureFile, sig}, {mitigation.PackVersionFile, []byte(version + "\n")}} { // VERSION last: see below
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, 0o644); err != nil { //nolint:gosec // shipped in the image, not secret
			return 0, err
		}
	}
	// What the box will do with the directory: its reader, its statement, its check.
	u, err := mitigation.ReadPackDir(dir)
	if err != nil {
		return 0, fmt.Errorf("the box would not read the signed directory: %w", err)
	}
	again, err := mitigation.Statement(u.Version, u.Docs)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(again, stmt) {
		return 0, errors.New("the box reads a different statement from the signed directory (did a file change while signing?)")
	}
	if err := release.VerifyContent(again, u.Signature, trust); err != nil {
		return 0, fmt.Errorf("the signed directory does not verify: %w", err)
	}
	return len(docs), nil
}

// readPackSources reads the packs of dir: every *.json file (the name rule is mitigation.Statement's), with the box's size limits.
// The files SignPacks writes and README files are skipped; anything else refuses the directory, since all of it ships in the image.
func readPackSources(dir string) ([]mitigation.Doc, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var docs []mitigation.Doc
	total := 0
	for _, e := range entries {
		name := e.Name()
		switch {
		case e.IsDir():
			return nil, fmt.Errorf("%s/%s is a directory: the box reads no sub-directory of the packs", dir, name)
		case !e.Type().IsRegular():
			return nil, fmt.Errorf("%s/%s is not a regular file (a link?): only plain files are signed", dir, name)
		case name == mitigation.PackVersionFile || name == mitigation.PackSignatureFile || name == mitigation.PackStatementFile ||
			strings.HasPrefix(name, "README") || strings.HasPrefix(name, "."):
			continue // the image leaves hidden files out and the box skips them
		case !strings.HasSuffix(name, ".json"):
			return nil, fmt.Errorf("unexpected file %s/%s: the pack directory holds *.json packs and a README only", dir, name)
		}
		data, err := readSmall(filepath.Join(dir, name), maxPackDoc)
		if err != nil {
			return nil, err
		}
		cve, err := mitigation.CheckPack(data) // the box's own parser: a pack it would reject is not signed
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if name != cve+".json" { // the box loads one pack per CVE: two files for one CVE would lose one, so a file is named after its CVE
			return nil, fmt.Errorf("%s holds the pack of %s: name it %s.json", name, cve, cve)
		}
		if total += len(data); total > maxPackTotal {
			return nil, fmt.Errorf("the packs are larger than %d bytes together", maxPackTotal)
		}
		docs = append(docs, mitigation.Doc{Name: name, Data: data})
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("no *.json pack in %s: nothing to sign", dir)
	}
	return docs, nil
}

// cmdPacks signs the confirmed mitigation packs that ship in the core image (D-345): `release packs -dir content/mitigation/packs
// -version <v> -key <minisign secret key> -minisign <pinned minisign>`. It runs before the core image is built.
func cmdPacks(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	fs := newFlags("packs")
	dir := fs.String("dir", "content/mitigation/packs", "directory of the confirmed packs (*.json)")
	version := fs.String("version", "", "version of this pack set: dotted numbers newer than the current VERSION, such as 2026.12.2.1")
	key := fs.String("key", "", "minisign secret key file (mode 600, outside the repository)")
	bin := fs.String("minisign", "", "absolute path of the pinned minisign (scripts/release/minisign.sh prints it)")
	keys := fs.String("keys-dir", "", "directory with the public keys to check the signature with (default: the keys compiled in)")
	pass := fs.Bool("passphrase-stdin", false, "read the key's passphrase from the first line of stdin (default: minisign asks on the terminal)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *key == "" || *bin == "" || *version == "" {
		return errors.New("-version, -key and -minisign are required")
	}
	trust, err := LoadTrust(*keys)
	if err != nil {
		return err
	}
	if *keys != "" {
		say(stdout, "warning: checked with the keys in %s, not the keys compiled into the box: boxes accept only a signature by the compiled release keys", *keys)
	}
	s := MinisignCLI{Bin: *bin, KeyPath: *key, Interactive: true}
	if root, err := RepoRoot(ctx, "."); err == nil {
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
	n, err := SignPacks(ctx, s, *dir, *version, trust)
	if err != nil {
		return err
	}
	say(stdout, "signed %d confirmed pack(s) as version %s in %s (VERSION, packs.list, packs.minisig): commit them, then build the core image", n, *version, *dir)
	return nil
}
