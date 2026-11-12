package ops

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
	"strings"
	"testing"
)

// The two tar readers of a bundle (D-452) read untrusted bytes: they are fuzzed, and what they accept or write is bounded.

func tarOf(t testing.TB, entries ...[2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e[0], Mode: 0o644, Typeflag: tar.TypeReg, Size: int64(len(e[1]))}
		if strings.HasSuffix(e[0], "/") {
			h.Typeflag, h.Size = tar.TypeDir, 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func hashHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func sha(s string) string { return hashHex([]byte(s)) }

func TestExtractLayoutWritesOnlyBlobsThatHashToTheirNamesWithinTheArchiveSize(t *testing.T) {
	t.Parallel()
	blob := "some layer bytes"
	good := tarOf(t, [2]string{"blobs/", ""}, [2]string{"blobs/sha256/", ""}, [2]string{"blobs/sha256/" + sha(blob), blob},
		[2]string{"oci-layout", "{}"}, [2]string{"index.json", `{"schemaVersion":2}`})
	dir := t.TempDir()
	idx, err := extractLayout(bytes.NewReader(good), dir, int64(len(good)))
	if err != nil || string(idx) != `{"schemaVersion":2}` {
		t.Fatalf("%q %v", idx, err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "blobs", "sha256", sha(blob))); err != nil || string(b) != blob { //nolint:gosec // test: the temp dir it made
		t.Fatalf("%q %v", b, err)
	}
	// The blobs may not add up to more than the archive (a sparse entry expands past what was uploaded).
	if _, err := extractLayout(bytes.NewReader(good), t.TempDir(), int64(len(blob)-1)); !errors.Is(err, errBundle) {
		t.Errorf("over the limit: %v", err)
	}
	// Another content under the name: errArchiveDigest; a name that is not a sha256 blob: errBundle.
	if _, err := extractLayout(bytes.NewReader(tarOf(t, [2]string{"blobs/sha256/" + sha("x"), "y"}, [2]string{"index.json", "{}"})), t.TempDir(), 1<<20); !errors.Is(err, errArchiveDigest) {
		t.Errorf("wrong content: %v", err)
	}
	for _, name := range []string{"blobs/sha256/" + strings.ToUpper(sha("x")), "blobs/sha512/" + sha("x"), "./index.json", "x/../index.json", "manifest.json"} {
		if _, err := extractLayout(bytes.NewReader(tarOf(t, [2]string{name, "x"}, [2]string{"index.json", "{}"})), t.TempDir(), 1<<20); !errors.Is(err, errBundle) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestBundleMemberCapIsAClosedList(t *testing.T) {
	t.Parallel()
	for name, ok := range map[string]bool{
		"index.json": true, "index.json.minisig": true, "release-manifest.json": true, "release-manifest.json.minisig": true,
		"bundle.json": true, "sbom.json": true, "images/core.oci.tar": true, "images/greenbone.oci.tar": true, "host/vedette-host_1.4.0_amd64.deb": true,
		"images/nope.oci.tar": false, "images/core.tar": false, "images/../core.oci.tar": false, "host/../x.deb": false, "host/.x.deb": false,
		"host/x.deb/y": false, "./index.json": false, "/index.json": false, "INDEX.json": false, "notes.txt": false, "images/core.oci.tar/": false,
	} {
		if got := bundleMemberCap(name) >= 0; got != ok {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// FuzzWalkBundle: whatever the bytes, walking them does not panic, and every member it hands on is one of the closed list, a regular
// file under its cap.
func FuzzWalkBundle(f *testing.F) {
	f.Add(tarOf(f, [2]string{"index.json", "{}"}, [2]string{"images/", ""}, [2]string{"images/core.oci.tar", "x"}))
	f.Add(tarOf(f, [2]string{"../x", "y"}))
	f.Add([]byte("not a tar"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = walkBundle(bytes.NewReader(b), func(name string, size int64, _ io.Reader) error {
			if c := bundleMemberCap(name); c < 0 || size > c {
				t.Fatalf("handed on %q (%d bytes)", name, size)
			}
			return nil
		})
	})
}

// FuzzExtractLayout: whatever the bytes, nothing is written outside dir/blobs/sha256, every file there has a 64-hex name, no more is
// written than the limit, and when the layout is accepted every file hashes to its name (on an error the run removes the directory).
func FuzzExtractLayout(f *testing.F) {
	f.Add(tarOf(f, [2]string{"blobs/sha256/" + sha("a"), "a"}, [2]string{"index.json", "{}"}))
	f.Add(tarOf(f, [2]string{"../../escaped", "a"}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		dir := t.TempDir()
		_, xerr := extractLayout(bytes.NewReader(b), dir, 4096)
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
			if !ok || !imageIDRE.MatchString(name) || xerr == nil && hashHex(raw) != name {
				t.Fatalf("wrote %s", rel)
			}
			return nil
		})
		if err != nil || total > 4096 {
			t.Fatalf("walk: %v, %d bytes", err, total)
		}
	})
}
