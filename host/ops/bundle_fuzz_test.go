package ops_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
)

// The bundle readers (D-452) against hand-built PAX GNU sparse entries (review M2) and fuzzing, seeded with those entries.

func hexOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// sparseIsWhatGoExpands proves the premise: Go's reader hands the hand-built entry on as a plain file of the expanded size.
func TestSparseEntryReadsBackAsAPlainFileOfTheExpandedSize(t *testing.T) {
	t.Parallel()
	b := opstest.WithRaw(opstest.Tar(t, opstest.TarEntry{Name: "index.json", Body: []byte("{}")}), opstest.SparseEntry(t, "images/core.oci.tar", 8<<30))
	tr := tar.NewReader(bytes.NewReader(b))
	if _, err := tr.Next(); err != nil {
		t.Fatal(err)
	}
	h, err := tr.Next()
	if err != nil || h.Typeflag != tar.TypeReg || h.Size != 8<<30 || h.Name != "images/core.oci.tar" {
		t.Fatalf("%+v %v", h, err)
	}
}

func TestBundleReadersRefuseSparseEntries(t *testing.T) {
	t.Parallel()
	docs := opstest.Tar(t, opstest.TarEntry{Name: "index.json", Body: []byte("{}")})
	// The outer tar: refused even with a limit that would let 8 GiB through, and with a small realsize under every cap.
	for _, rs := range []int64{8 << 30, 600} {
		b := opstest.WithRaw(docs, opstest.SparseEntry(t, "images/core.oci.tar", rs))
		err := ops.WalkBundle(bytes.NewReader(b), 1<<40, func(string, int64, io.Reader) error { return nil })
		if !errors.Is(err, ops.ErrBundle) {
			t.Errorf("outer, realsize %d: %v", rs, err)
		}
	}
	// The members together may not claim more than the file holds (the expansion is caught even without the sparse check).
	plain := opstest.Tar(t, opstest.TarEntry{Name: "index.json", Body: bytes.Repeat([]byte("x"), 100)})
	if err := ops.WalkBundle(bytes.NewReader(plain), 99, func(string, int64, io.Reader) error { return nil }); !errors.Is(err, ops.ErrBundle) {
		t.Errorf("over the file size: %v", err)
	}
	// The image archive: a sparse blob is refused before a byte is written.
	blobName := "blobs/sha256/" + hexOf(make([]byte, 600))
	inner := opstest.WithRaw(opstest.Tar(t, opstest.TarEntry{Name: "index.json", Body: []byte("{}")}), opstest.SparseEntry(t, blobName, 600))
	dir := t.TempDir()
	if _, err := ops.ExtractLayout(bytes.NewReader(inner), dir, 1<<40); !errors.Is(err, ops.ErrBundle) {
		t.Errorf("inner: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, blobName)); err == nil {
		t.Error("the sparse blob was written")
	}
}

// FuzzWalkBundle: whatever the bytes, walking them does not panic, and every member it hands on is one of the closed list, a regular
// file under its cap, and together they claim no more than the input holds.
func FuzzWalkBundle(f *testing.F) {
	ok := opstest.Tar(f, opstest.TarEntry{Name: "index.json", Body: []byte("{}")}, opstest.TarEntry{Name: "images/", Type: tar.TypeDir},
		opstest.TarEntry{Name: "images/core.oci.tar", Body: []byte("x")})
	f.Add(ok)
	f.Add(opstest.WithRaw(ok, opstest.SparseEntry(f, "images/sensor.oci.tar", 8<<30)))
	f.Add(opstest.Tar(f, opstest.TarEntry{Name: "../x", Body: []byte("y")}))
	f.Add([]byte("not a tar"))
	f.Fuzz(func(t *testing.T, b []byte) {
		var total int64
		_ = ops.WalkBundle(bytes.NewReader(b), int64(len(b)), func(name string, size int64, _ io.Reader) error {
			total += size
			if c := ops.BundleMemberCap(name); c < 0 || size > c || total > int64(len(b)) {
				t.Fatalf("handed on %q (%d bytes, %d in all)", name, size, total)
			}
			return nil
		})
	})
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// FuzzExtractLayout: whatever the bytes, nothing is written outside dir/blobs/sha256, every file there has a 64-hex name, no more is
// written than the limit, and when the layout is accepted every file hashes to its name (on an error the run removes the directory).
func FuzzExtractLayout(f *testing.F) {
	f.Add(opstest.Tar(f, opstest.TarEntry{Name: "blobs/sha256/" + hexOf([]byte("a")), Body: []byte("a")}, opstest.TarEntry{Name: "index.json", Body: []byte("{}")}))
	f.Add(opstest.WithRaw(opstest.Tar(f, opstest.TarEntry{Name: "index.json", Body: []byte("{}")}), opstest.SparseEntry(f, "blobs/sha256/"+hexOf(make([]byte, 600)), 600)))
	f.Add(opstest.Tar(f, opstest.TarEntry{Name: "../../escaped", Body: []byte("a")}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		dir := t.TempDir()
		_, xerr := ops.ExtractLayout(bytes.NewReader(b), dir, 4096)
		var total int64
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(dir, p)
			raw, rerr := os.ReadFile(p) //nolint:gosec // test: a file the fuzzed reader wrote under its temp dir
			if rerr != nil {
				return rerr
			}
			total += int64(len(raw))
			name, ok := strings.CutPrefix(rel, filepath.Join("blobs", "sha256")+string(filepath.Separator))
			if !ok || !hex64.MatchString(name) || xerr == nil && hexOf(raw) != name {
				t.Fatalf("wrote %s", rel)
			}
			return nil
		})
		if err != nil || total > 4096 {
			t.Fatalf("walk: %v, %d bytes", err, total)
		}
	})
}

// FuzzCheckLayout: whatever the archive's index.json and the top blob say, checkLayout does not panic, and it accepts only a layout
// whose index names the signed digest (review L3, optional).
func FuzzCheckLayout(f *testing.F) {
	top := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"x","digest":"sha256:` + hexOf([]byte("c")) + `","size":1},"layers":[]}`)
	f.Add([]byte(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:`+hexOf(top)+`","size":`+strconv.Itoa(len(top))+`}]}`), top)
	f.Add([]byte(`{"schemaVersion":2,"manifests":[]}`), []byte(`{}`))
	f.Add([]byte(`[`), []byte(``))
	f.Fuzz(func(t *testing.T, index, blob []byte) {
		dir := t.TempDir()
		blobs := filepath.Join(dir, "blobs", "sha256")
		if err := os.MkdirAll(blobs, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, b := range [][]byte{blob, []byte("c")} {
			if err := os.WriteFile(filepath.Join(blobs, hexOf(b)), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		want := "sha256:" + hexOf(blob)
		if _, err := ops.CheckLayout(dir, index, want, "amd64"); err == nil && !bytes.Contains(index, []byte(want)) {
			t.Fatalf("accepted an index that does not name %s: %q", want, index)
		}
	})
}
