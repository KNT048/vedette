package opstest

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Offline bundles (D-452): what core writes at <core_data>/bundles/<id>.tar, built in the test.

// TarEntry is one entry of a tar the test builds. Type defaults to a regular file.
type TarEntry struct {
	Name     string
	Body     []byte
	Type     byte
	Linkname string
}

// Tar builds a tar of the entries, in order.
func Tar(t testing.TB, entries ...TarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.Name, Mode: 0o644, Typeflag: e.Type, Linkname: e.Linkname}
		switch h.Typeflag {
		case 0, tar.TypeReg:
			h.Typeflag, h.Size = tar.TypeReg, int64(len(e.Body))
		case tar.TypeDir:
			h.Mode = 0o755
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write(e.Body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// SparseEntry is the raw tar bytes of one PAX "GNU sparse 1.0" entry named name: a PAX header with GNU.sparse.major/minor/name/realsize,
// then a plain header for a 513-byte body (a one-entry sparse map and one data byte). Go's archive/tar reads it back as a TypeReg of
// realsize bytes (mostly zeros) and will not write one, so it is built by hand (review M2). Splice it into a tar with WithRaw.
func SparseEntry(t testing.TB, name string, realsize int64) []byte {
	t.Helper()
	recs := ""
	for _, kv := range [][2]string{{"GNU.sparse.major", "1"}, {"GNU.sparse.minor", "0"}, {"GNU.sparse.name", name}, {"GNU.sparse.realsize", strconv.FormatInt(realsize, 10)}} {
		rec := " " + kv[0] + "=" + kv[1] + "\n"
		n := len(rec) + 1
		for len(strconv.Itoa(n))+len(rec) != n {
			n++
		}
		recs += strconv.Itoa(n) + rec
	}
	body := make([]byte, 513)
	copy(body, "1\n0\n1\n")
	body[512] = 'A'
	var out bytes.Buffer
	out.Write(rawHeader(t, "PaxHeaders/x", tar.TypeXHeader, int64(len(recs))))
	out.Write(padBlock([]byte(recs)))
	out.Write(rawHeader(t, name, tar.TypeReg, int64(len(body))))
	out.Write(padBlock(body))
	return out.Bytes()
}

// WithRaw puts raw entries (as SparseEntry makes) at the end of the tar b, before its two-block trailer.
func WithRaw(b []byte, raw ...[]byte) []byte {
	out := bytes.Clone(b[:len(b)-1024])
	for _, r := range raw {
		out = append(out, r...)
	}
	return append(out, make([]byte, 1024)...)
}

func padBlock(b []byte) []byte {
	if r := len(b) % 512; r != 0 {
		b = append(b, make([]byte, 512-r)...)
	}
	return b
}

// rawHeader is one USTAR header block of the given type (the writer makes a regular one; the type byte and checksum are then set).
func rawHeader(t testing.TB, name string, typ byte, size int64) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	if err := w.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Size: size, Mode: 0o644, Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	blk := bytes.Clone(b.Bytes()[:512])
	blk[156] = typ
	copy(blk[148:156], "        ")
	sum := 0
	for _, c := range blk {
		sum += int(c)
	}
	copy(blk[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return blk
}

// OCIImage is a small image as an OCI image layout: one layer, a config and a manifest for linux/<arch>, and an image index over that
// manifest (the multi-platform form a release pushes). Digest is the index's: what the signed manifest names. Tests change the
// fields before calling Tar to break it.
type OCIImage struct {
	Layer, Config, Manifest, Index []byte
	Digest                         string
	// LayoutIndex is the layout's index.json (by default one descriptor: the index, Digest, annotated with a ref name).
	LayoutIndex []byte
	// Leave names blobs (by hex) Tar leaves out.
	Leave map[string]bool
	// Extra entries are appended to the tar.
	Extra []TarEntry
}

// Hex is the SHA-256 of b in hex.
func Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func desc(mt string, b []byte) map[string]any {
	return map[string]any{"mediaType": mt, "digest": "sha256:" + Hex(b), "size": len(b)}
}

// NewOCIImage builds the image for linux/arch; salt makes two images differ.
func NewOCIImage(t testing.TB, arch, salt string) *OCIImage {
	t.Helper()
	im := &OCIImage{Layer: []byte("layer of " + salt), Leave: map[string]bool{}}
	im.Config = JSON(t, map[string]any{"architecture": arch, "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + Hex(im.Layer)}}})
	im.Manifest = JSON(t, map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": desc("application/vnd.oci.image.config.v1+json", im.Config),
		"layers": []any{desc("application/vnd.oci.image.layer.v1.tar", im.Layer)},
	})
	md := desc("application/vnd.oci.image.manifest.v1+json", im.Manifest)
	md["platform"] = map[string]any{"os": "linux", "architecture": arch}
	im.Index = JSON(t, map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []any{md}})
	im.Digest = "sha256:" + Hex(im.Index)
	top := desc("application/vnd.oci.image.index.v1+json", im.Index)
	top["annotations"] = map[string]string{"org.opencontainers.image.ref.name": "ghcr.io/knt048/vedette-core:1.4.0"}
	im.LayoutIndex = JSON(t, map[string]any{"schemaVersion": 2, "manifests": []any{top}})
	return im
}

// Tar is the image archive (images/<service>.oci.tar of a bundle): oci-layout, index.json and the blobs, with folder entries as
// podman writes them.
func (im *OCIImage) Tar(t testing.TB) []byte {
	t.Helper()
	entries := []TarEntry{
		{Name: "blobs/", Type: tar.TypeDir}, {Name: "blobs/sha256/", Type: tar.TypeDir},
	}
	for _, b := range [][]byte{im.Layer, im.Config, im.Manifest, im.Index} {
		if !im.Leave[Hex(b)] {
			entries = append(entries, TarEntry{Name: "blobs/sha256/" + Hex(b), Body: b})
		}
	}
	entries = append(entries, TarEntry{Name: "index.json", Body: im.LayoutIndex}, TarEntry{Name: "oci-layout", Body: []byte(`{"imageLayoutVersion":"1.0.0"}`)})
	return Tar(t, append(entries, im.Extra...)...)
}

// BundleDocs are the four signed documents of a bundle as tar entries: the index and manifest signed by the active key.
func (r *Release) BundleDocs(indexRaw, manifestRaw []byte) []TarEntry {
	return []TarEntry{
		{Name: "bundle.json", Body: []byte(`{"schema":1}`)},
		{Name: "index.json", Body: indexRaw}, {Name: "index.json.minisig", Body: r.Sign(indexRaw)},
		{Name: "release-manifest.json", Body: manifestRaw}, {Name: "release-manifest.json.minisig", Body: r.Sign(manifestRaw)},
	}
}

// CoreBundle writes core's upload <core_data>/bundles/<id>.tar (0600, core's owner) and returns the id.
func (m *Machine) CoreBundle(content []byte) string {
	m.t.Helper()
	b := make([]byte, 16)
	_, err := rand.Read(b)
	m.must(err)
	id := hex.EncodeToString(b)
	dir := filepath.Join(m.CoreData, "bundles")
	m.must(os.MkdirAll(dir, 0o700))
	m.must(os.WriteFile(m.CoreBundlePath(id), content, 0o600))
	return id
}

// CoreBundlePath is the path of core's upload.
func (m *Machine) CoreBundlePath(id string) string {
	return filepath.Join(m.CoreData, "bundles", id+".tar")
}

// OCIPulls are the "oci:<dir>:<ref>" references the fake podman loaded (StatefulImages).
func (m *Machine) OCIPulls() []string {
	b, _ := os.ReadFile(filepath.Join(m.Rec, "img", "ocipulls"))
	var out []string
	for _, l := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		if len(l) > 0 {
			out = append(out, string(l))
		}
	}
	return out
}
