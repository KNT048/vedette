package main

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/knt048/vedette/internal/release"
	"github.com/knt048/vedette/internal/release/releasetest"
	"github.com/knt048/vedette/modules/mitigation"
)

// D-345..D-349: a box loads the confirmed packs shipped in its image only when the release key signed them, and the finding page
// then shows the pack. Throwaway keys stand in for the release keys (deps.PackTrust).

type packKeys struct {
	sign  *releasetest.Minisign
	trust func() (release.Trust, error)
}

func newPackKeys(t *testing.T) packKeys {
	t.Helper()
	active, backup := releasetest.NewMinisign(t), releasetest.NewMinisign(t)
	tr, err := release.NewTrust(active.PubLine(), backup.PubLine(), releasetest.NewCosign(t).PubPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	return packKeys{sign: active, trust: func() (release.Trust, error) { return tr, nil }}
}

// writePackDir writes a pack directory as the release job does: the pack files, VERSION and packs.minisig over the statement.
func writePackDir(t *testing.T, k packKeys, version string, docs map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	var list []mitigation.Doc
	for n, b := range docs {
		list = append(list, mitigation.Doc{Name: n, Data: b})
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stmt, err := mitigation.Statement(version, list)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte(version+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "packs.minisig"), k.sign.Sign(stmt), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// testPack is the QNAP test pack of content/mitigation/testdata with its CVE changed.
func testPack(t *testing.T, cve string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../content/mitigation/testdata/CVE-2022-27593.json")
	if err != nil {
		t.Fatal(err)
	}
	return bytes.ReplaceAll(b, []byte("CVE-2022-27593"), []byte(cve))
}

func TestWiringSignedPacksLoadAndShowOnTheFinding(t *testing.T) {
	t.Parallel()
	k := newPackKeys(t)
	pack := testPack(t, "CVE-2026-1001")
	dir := writePackDir(t, k, "2026.11.12.1", map[string][]byte{"CVE-2026-1001.json": pack})
	s := newStackWith(t, func(d *deps) { d.PackDir, d.PackTrust = dir, k.trust })
	s.kev("CVE-2026-1001", "Fortinet", "FortiOS")
	s.addFortiGate()
	_, list := s.do("GET", "/findings", "viewer", "")
	fid := at(list, "items", 0, "id").(string)
	if _, b := s.do("GET", "/findings/"+fid, "viewer", ""); at(b, "pack") != nil {
		t.Fatalf("a pack before any was loaded: %v", at(b, "pack"))
	}
	jobs := mitigationJobs(*s.d)
	if len(jobs) != 1 || jobs[0].Name != "load-packs" || jobs[0].Module != "mitigation" {
		t.Fatalf("jobs: %+v", jobs)
	}
	if err := jobs[0].Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, b := s.do("GET", "/findings/"+fid, "viewer", ""); at(b, "pack") == nil || at(b, "pack", "confirmed_by") != "a Vedette maintainer" {
		t.Fatalf("the finding does not show the loaded pack: %v", at(b, "pack"))
	}
	if n := s.count(`SELECT count(*) FROM core_audit WHERE action = 'mitigation.packs_loaded' AND target = '2026.11.12.1'`); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
	// The same version again (the daily run, a restart): nothing changes, nothing fails.
	if err := jobs[0].Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := s.count(`SELECT count(*) FROM core_audit WHERE action = 'mitigation.packs_loaded'`); n != 1 {
		t.Fatalf("loaded again: %d audit rows", n)
	}
}

func TestPacksAreRefusedUnlessTheReleaseKeySignedEveryByte(t *testing.T) {
	t.Parallel()
	k, other := newPackKeys(t), newPackKeys(t)
	pack := testPack(t, "CVE-2026-1001")
	good := map[string][]byte{"CVE-2026-1001.json": pack}
	cases := map[string]func(t *testing.T) string{
		"other key": func(t *testing.T) string { return writePackDir(t, other, "2", good) },
		"pack byte changed": func(t *testing.T) string {
			d := writePackDir(t, k, "2", good)
			if err := os.WriteFile(filepath.Join(d, "CVE-2026-1001.json"), bytes.Replace(pack, []byte("QNAP"), []byte("QNAQ"), 1), 0o600); err != nil {
				t.Fatal(err)
			}
			return d
		},
		"version changed": func(t *testing.T) string {
			d := writePackDir(t, k, "2", good)
			if err := os.WriteFile(filepath.Join(d, "VERSION"), []byte("3\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return d
		},
		"pack added": func(t *testing.T) string {
			d := writePackDir(t, k, "2", good)
			if err := os.WriteFile(filepath.Join(d, "CVE-2026-1002.json"), testPack(t, "CVE-2026-1002"), 0o600); err != nil {
				t.Fatal(err)
			}
			return d
		},
		"pack removed": func(t *testing.T) string {
			d := writePackDir(t, k, "2", map[string][]byte{"CVE-2026-1001.json": pack, "CVE-2026-1002.json": testPack(t, "CVE-2026-1002")})
			if err := os.Remove(filepath.Join(d, "CVE-2026-1002.json")); err != nil {
				t.Fatal(err)
			}
			return d
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			dir := mk(t)
			s := newStackWith(t, func(d *deps) { d.PackDir, d.PackTrust = dir, k.trust })
			err := mitigationJobs(*s.d)[0].Run(t.Context())
			if !errors.Is(err, mitigation.ErrUnsigned) {
				t.Fatalf("err = %v, want ErrUnsigned", err)
			}
			if n := s.count(`SELECT count(*) FROM mit_pack`); n != 0 {
				t.Fatalf("%d packs loaded", n)
			}
		})
	}
	// No directory (a build without packs): nothing to do, no failure.
	if err := loadPacks(t.Context(), mitigation.NewLoader(nil, nil, packVerifier{trust: k.trust}, slog.New(slog.DiscardHandler), nil), filepath.Join(t.TempDir(), "none"), slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("no directory: %v", err)
	}
	// The binary's own keys are used when no test keys are given: a pack signed by anyone else is refused.
	if err := (packVerifier{}).Verify(t.Context(), mitigation.Update{Version: "1", Docs: []mitigation.Doc{{Name: "CVE-2026-1001.json", Data: pack}}, Signature: other.sign.Sign([]byte("x"))}); err == nil {
		t.Fatal("a pack was accepted with the embedded keys")
	}
}
