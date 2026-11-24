package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/internal/release"
	"github.com/knt048/vedette/modules/mitigation"
)

// The release tool signs the pack set the box verifies, and refuses what the box would not load.

func packFile(t *testing.T, cve string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../content/mitigation/testdata/CVE-2022-27593.json")
	if err != nil {
		t.Fatal(err)
	}
	return bytes.ReplaceAll(b, []byte("CVE-2022-27593"), []byte(cve))
}

func packSrc(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for n, b := range files {
		must(t, os.WriteFile(filepath.Join(dir, n), b, 0o600))
	}
	return dir
}

func TestSignPacksMakesWhatTheBoxVerifies(t *testing.T) {
	r := newRig(t)
	s := testSigner{t, r.active}
	dir := packSrc(t, map[string][]byte{"CVE-2026-1001.json": packFile(t, "CVE-2026-1001"), "CVE-2026-1002.json": packFile(t, "CVE-2026-1002"), "README.md": []byte("x"), ".DS_Store": []byte("finder")})
	n, err := SignPacks(t.Context(), s, dir, "2026.12.2.1", r.trust)
	if err != nil || n != 2 {
		t.Fatalf("signed %d: %v", n, err)
	}
	u, err := mitigation.ReadPackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := mitigation.Statement(u.Version, u.Docs)
	if err != nil || u.Version != "2026.12.2.1" || len(u.Docs) != 2 {
		t.Fatalf("read back: %+v %v", u, err)
	}
	if err := release.VerifyContent(stmt, u.Signature, r.trust); err != nil {
		t.Fatalf("the box does not verify it: %v", err)
	}
	if list, _ := os.ReadFile(filepath.Join(dir, "packs.list")); !bytes.Equal(list, stmt) { //nolint:gosec // test: a file the test wrote
		t.Fatal("packs.list is not the signed statement")
	}
	if sig, _ := os.ReadFile(filepath.Join(dir, "packs.minisig")); !strings.Contains(string(sig), "file:packs.list version:2026.12.2.1") { //nolint:gosec // test: a file the test wrote
		t.Fatalf("trusted comment: %s", sig)
	}
	// The next set must be newer; the same version again is refused, as the box would.
	if _, err := SignPacks(t.Context(), s, dir, "2026.12.2.1", r.trust); err == nil || !strings.Contains(err.Error(), "not newer") {
		t.Fatalf("same version: %v", err)
	}
	if _, err := SignPacks(t.Context(), s, dir, "2026.12.2.2", r.trust); err != nil {
		t.Fatalf("newer version: %v", err)
	}
}

func TestSignPacksRefusesAndLeavesTheDirectory(t *testing.T) {
	r := newRig(t)
	good := packFile(t, "CVE-2026-1001")
	draft := bytes.Replace(good, []byte(`"status": "confirmed"`), []byte(`"status": "draft"`), 1)
	for name, c := range map[string]struct {
		files   map[string][]byte
		version string
		signer  Signer
		want    string
	}{
		"no pack":         {map[string][]byte{"README.md": []byte("x")}, "1.0", testSigner{t, r.active}, "nothing to sign"},
		"draft pack":      {map[string][]byte{"CVE-2026-1001.json": draft}, "1.0", testSigner{t, r.active}, "confirmed"},
		"stray file":      {map[string][]byte{"CVE-2026-1001.json": good, "run.sh": []byte("x")}, "1.0", testSigner{t, r.active}, "unexpected file"},
		"dated version":   {map[string][]byte{"CVE-2026-1001.json": good}, "2026-12-02.1", testSigner{t, r.active}, "cannot be ordered"},
		"untrusted key":   {map[string][]byte{"CVE-2026-1001.json": good}, "1.0", testSigner{t, newRig(t).active}, "does not verify"},
		"bad file name":   {map[string][]byte{"a b.json": good}, "1.0", testSigner{t, r.active}, "name it CVE-2026-1001.json"},
		"other cve name":  {map[string][]byte{"CVE-2026-1002.json": good}, "1.0", testSigner{t, r.active}, "name it CVE-2026-1001.json"},
		"version newline": {map[string][]byte{"CVE-2026-1001.json": good}, "1\n2", testSigner{t, r.active}, "cannot be ordered"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := packSrc(t, c.files)
			_, err := SignPacks(t.Context(), c.signer, dir, c.version, r.trust)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			for _, f := range []string{"VERSION", "packs.list", "packs.minisig"} {
				if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
					t.Errorf("%s was written after a refusal", f)
				}
			}
		})
	}
}

// The confirmed packs of the repository go through the release signing path as they are: the box's parser accepts each one, the
// signature verifies and the box reads the signed directory back. The test signs with a key of its own; a release signs with the
// release key (make release-packs).
func TestSignPacksSignsTheShippedPacks(t *testing.T) {
	r := newRig(t)
	names, err := filepath.Glob("../../content/mitigation/packs/*.json")
	if err != nil || len(names) == 0 {
		t.Fatalf("no shipped packs: %v", err)
	}
	files := map[string][]byte{}
	for _, n := range names {
		b, err := os.ReadFile(n) //nolint:gosec // test: a file of the repository
		if err != nil {
			t.Fatal(err)
		}
		files[filepath.Base(n)] = b
	}
	dir := packSrc(t, files)
	n, err := SignPacks(t.Context(), testSigner{t, r.active}, dir, "2026.11.24.1", r.trust)
	if err != nil || n != len(names) {
		t.Fatalf("signed %d of %d: %v", n, len(names), err)
	}
	u, err := mitigation.ReadPackDir(dir)
	if err != nil || len(u.Docs) != len(names) {
		t.Fatalf("read back: %d docs, %v", len(u.Docs), err)
	}
}

// The committed pack directory carries a signature of the release key over exactly the packs it holds. A pack edited after signing
// (or a pack added without running make release-packs) makes the box refuse the whole set at load-packs, so it fails here instead.
func TestShippedPacksCarryAReleaseSignature(t *testing.T) {
	if _, _, testOnly := release.EmbeddedMinisignKeys(); testOnly {
		t.Skip("built with the throwaway release keys; the committed packs are signed with the real ones")
	}
	trust, err := release.Embedded() // the production keys of keys.go, as the box verifies the packs
	if err != nil {
		t.Fatal(err)
	}
	u, err := mitigation.ReadPackDir("../../content/mitigation/packs")
	if err != nil {
		t.Fatalf("the shipped packs carry no signed set: %v", err)
	}
	stmt, err := mitigation.Statement(u.Version, u.Docs)
	if err != nil {
		t.Fatal(err)
	}
	if err := release.VerifyContent(stmt, u.Signature, trust); err != nil {
		t.Fatalf("packs.minisig does not verify the committed packs (version %q): run make release-packs with a newer version: %v", u.Version, err)
	}
}
