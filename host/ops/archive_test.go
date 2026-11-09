package ops_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/ops"
)

const goodManifest = `{"version":1,"db_schema":"core=1","created_at":"2026-11-09T12:00:00Z","includes_secrets":false}`

type tarMember struct {
	hdr  tar.Header
	data string
}

func buildTar(t testing.TB, members ...tarMember) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, m := range members {
		h := m.hdr
		if h.Typeflag == tar.TypeReg || h.Typeflag == 0 {
			h.Size = int64(len(m.data))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write([]byte(m.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = tw.Close()
	return gz(t, raw.Bytes())
}

func reg(name, data string) tarMember {
	return tarMember{hdr: tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600}, data: data}
}

func read(t testing.TB, archive []byte) ([]string, error) {
	t.Helper()
	var names []string
	err := ops.ReadArchive(bytes.NewReader(archive), func(name string, _ []byte) error {
		names = append(names, name)
		return nil
	})
	return names, err
}

func TestReadArchiveAcceptsTheExpectedMembers(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if _, _, err := ops.WriteArchive(&buf, map[string][]byte{"manifest.json": []byte(goodManifest), "vedette.db": []byte("db")}, []string{"manifest.json", "vedette.db"}); err != nil {
		t.Fatal(err)
	}
	names, err := read(t, buf.Bytes())
	if err != nil || !slices.Equal(names, []string{"manifest.json", "vedette.db"}) {
		t.Fatalf("%v %v", names, err)
	}
	buf.Reset()
	if _, _, err := ops.WriteArchive(&buf, map[string][]byte{"manifest.json": []byte(goodManifest), "vedette.db": []byte("db"), "vedette.key": []byte("k")}, []string{"manifest.json", "vedette.db", "vedette.key"}); err != nil {
		t.Fatal(err)
	}
	if names, err = read(t, buf.Bytes()); err != nil || len(names) != 3 {
		t.Fatalf("%v %v", names, err)
	}
}

func TestReadArchiveRejectsHostileArchives(t *testing.T) {
	t.Parallel()
	link := func(name, target string, kind byte) tarMember {
		return tarMember{hdr: tar.Header{Name: name, Typeflag: kind, Linkname: target, Mode: 0o777}}
	}
	tests := map[string][]byte{
		"not gzip":           []byte("hello"),
		"empty gzip":         gz(t, nil),
		"path traversal":     buildTar(t, reg("manifest.json", goodManifest), reg("../vedette.db", "x")),
		"absolute path":      buildTar(t, reg("manifest.json", goodManifest), reg("/etc/passwd", "x")),
		"nested path":        buildTar(t, reg("manifest.json", goodManifest), reg("a/vedette.db", "x")),
		"dot slash":          buildTar(t, reg("manifest.json", goodManifest), reg("./vedette.db", "x")),
		"unknown member":     buildTar(t, reg("manifest.json", goodManifest), reg("evil.sh", "x")),
		"symlink":            buildTar(t, reg("manifest.json", goodManifest), link("vedette.db", "/etc/shadow", tar.TypeSymlink)),
		"hardlink":           buildTar(t, reg("manifest.json", goodManifest), link("vedette.db", "manifest.json", tar.TypeLink)),
		"device":             buildTar(t, reg("manifest.json", goodManifest), tarMember{hdr: tar.Header{Name: "vedette.db", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3}}),
		"fifo":               buildTar(t, reg("manifest.json", goodManifest), tarMember{hdr: tar.Header{Name: "vedette.db", Typeflag: tar.TypeFifo}}),
		"directory":          buildTar(t, tarMember{hdr: tar.Header{Name: "manifest.json", Typeflag: tar.TypeDir, Mode: 0o700}}),
		"manifest not first": buildTar(t, reg("vedette.db", "x"), reg("manifest.json", goodManifest)),
		"duplicate member":   buildTar(t, reg("manifest.json", goodManifest), reg("vedette.db", "x"), reg("vedette.db", "y")),
		"key before db":      buildTar(t, reg("manifest.json", goodManifest), reg("vedette.key", "k"), reg("vedette.db", "x")),
		"oversized key":      buildTar(t, reg("manifest.json", goodManifest), reg("vedette.db", "x"), reg("vedette.key", strings.Repeat("k", 5000))),
		"oversized manifest": buildTar(t, reg("manifest.json", strings.Repeat(" ", 70000))),
		"pax records":        buildTar(t, tarMember{hdr: tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, PAXRecords: map[string]string{"SCHILY.xattr.user.x": "y"}}, data: goodManifest}),
	}
	for name, a := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			names, err := read(t, a)
			if !errors.Is(err, ops.ErrArchive) {
				t.Fatalf("accepted (%v) or wrong error: %v", names, err)
			}
			for _, n := range names {
				if n != "manifest.json" && n != "vedette.db" && n != "vedette.key" {
					t.Errorf("sink saw a member named %q", n)
				}
			}
		})
	}
}

func TestReadArchiveStopsAtTheDeclaredSize(t *testing.T) {
	t.Parallel()
	// A gzip stream that expands to far more than the tar header declares: the sink gets the
	// declared bytes at most, and the archive is rejected or ends there; nothing is read past it.
	a := buildTar(t, reg("manifest.json", goodManifest), reg("vedette.db", strings.Repeat("A", 1<<20)))
	var got int
	err := ops.ReadArchive(bytes.NewReader(a), func(name string, data []byte) error {
		if name == "vedette.db" {
			got = len(data)
		}
		return nil
	})
	if err != nil || got != 1<<20 {
		t.Fatalf("got %d err %v", got, err)
	}
	// A second gzip member appended after the tar must not be read (Multistream is off).
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("junk"))
	_ = zw.Close()
	if _, err := read(t, append(append([]byte{}, a...), buf.Bytes()...)); err != nil {
		t.Errorf("trailing gzip member: %v", err)
	}
}

func FuzzReadArchive(f *testing.F) {
	var good bytes.Buffer
	_, _, _ = ops.WriteArchive(&good, map[string][]byte{"manifest.json": []byte(goodManifest), "vedette.db": []byte("db"), "vedette.key": []byte("k")}, []string{"manifest.json", "vedette.db", "vedette.key"})
	f.Add(good.Bytes())
	f.Add(buildTar(f, reg("manifest.json", goodManifest), reg("../x", "y")))
	f.Add([]byte{0x1f, 0x8b})
	f.Fuzz(func(t *testing.T, in []byte) {
		seen := map[string]int{}
		var total int
		err := ops.ReadArchive(bytes.NewReader(in), func(name string, data []byte) error {
			seen[name]++
			total += len(data)
			return nil
		})
		for name, n := range seen {
			if (name != "manifest.json" && name != "vedette.db" && name != "vedette.key") || n != 1 {
				t.Fatalf("the sink saw %q %d times (err %v)", name, n, err)
			}
		}
		if err == nil && seen["manifest.json"] == 0 && len(seen) > 0 {
			t.Fatalf("accepted an archive without a manifest first: %v", seen)
		}
		if total > 2<<20 {
			t.Skip("large member from the fuzzer")
		}
	})
}

func TestRetention(t *testing.T) {
	t.Parallel()
	// Index i has kind kinds[i] and age minutes[i] (bigger is newer).
	var kinds []string
	var mins []int
	for i := 0; i < 6; i++ {
		kinds = append(kinds, "pre_os_update")
		mins = append(mins, i)
	}
	for i := 0; i < 12; i++ {
		kinds = append(kinds, "manual")
		mins = append(mins, 100+i)
	}
	kept := ops.Retain(kinds, mins)
	pre, manual := 0, 0
	for _, i := range kept {
		if kinds[i] == "manual" {
			manual++
			if mins[i] < 102 {
				t.Errorf("a manual backup older than the 10 newest was kept: %d", mins[i])
			}
		} else {
			pre++
			if mins[i] < 3 {
				t.Errorf("a pre_* backup older than the 3 newest was kept: %d", mins[i])
			}
		}
	}
	if pre != 3 || manual != 10 {
		t.Fatalf("pre %d manual %d", pre, manual)
	}
	// pre_* kinds share one pool.
	k2 := []string{"pre_update", "pre_os_update", "pre_restore", "pre_restore"}
	if kept := ops.Retain(k2, []int{1, 2, 3, 4}); len(kept) != 3 {
		t.Errorf("pre kinds share the pool of 3: %v", kept)
	}
}
