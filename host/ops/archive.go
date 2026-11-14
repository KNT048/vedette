package ops

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"time"

	"github.com/knt048/vedette/host/archive"
)

// A backup is one tar.gz with fixed member names (host/archive, shared with core, which reads uploaded backups back,
// D-518). The archive is untrusted when read back, even though the host wrote it: a restore must never extract anything
// but these members, with size caps, no matter what the file holds.
const (
	memberManifest = archive.MemberManifest
	memberDB       = archive.MemberDB
	memberKey      = archive.MemberKey

	manifestVersion = archive.ManifestVersion

	maxKeyBytes = archive.MaxKeyBytes
	maxDBBytes  = archive.MaxDBBytes
)

// Manifest is the small description inside every backup.
type Manifest = archive.Manifest

// validSchema accepts "" or up to 64 comma-separated module=version pairs.
func validSchema(s string) bool { return archive.ValidSchema(s) }

// parseManifest validates the manifest text. It is a pure function over untrusted bytes.
func parseManifest(b []byte) (Manifest, error) { return archive.ParseManifest(b) }

// archiveFile is one member to write: Data, or exactly Size bytes read from Src (a descriptor the
// host already checked).
type archiveFile struct {
	Name string
	Src  io.Reader
	Size int64
	Data []byte
}

// writeArchive writes the members as tar inside gzip to w and returns the SHA-256 and size of the
// compressed bytes written.
func writeArchive(w io.Writer, files []archiveFile, mtime time.Time) (sum string, size int64, err error) {
	h := sha256.New()
	cw := &countWriter{w: io.MultiWriter(w, h)}
	zw := gzip.NewWriter(cw)
	tw := tar.NewWriter(zw)
	for _, f := range files {
		if err := addMember(tw, f, mtime); err != nil {
			return "", 0, err
		}
	}
	if err := tw.Close(); err != nil {
		return "", 0, fmt.Errorf("ops: close tar: %w", err)
	}
	if err := zw.Close(); err != nil {
		return "", 0, fmt.Errorf("ops: close gzip: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), cw.n, nil
}

func addMember(tw *tar.Writer, f archiveFile, mtime time.Time) error {
	hdr := &tar.Header{Name: f.Name, Typeflag: tar.TypeReg, Mode: 0o600, ModTime: mtime, Format: tar.FormatUSTAR}
	if f.Src == nil {
		hdr.Size = int64(len(f.Data))
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("ops: write %s: %w", f.Name, err)
		}
		if _, err := tw.Write(f.Data); err != nil {
			return fmt.Errorf("ops: write %s: %w", f.Name, err)
		}
		return nil
	}
	hdr.Size = f.Size
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("ops: write %s: %w", f.Name, err)
	}
	// Exactly Size bytes: a file that grew after the check is cut at the checked size, one that
	// shrank is an error (the member would not match its header).
	if n, err := io.Copy(tw, io.LimitReader(f.Src, f.Size)); err != nil || n != f.Size {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("ops: copy %s: %w", f.Name, err)
	}
	return nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// ErrArchive means the archive is not a valid Vedette backup. The text never carries archive content.
var ErrArchive = archive.ErrArchive

// memberSink receives the content of one accepted member (at most size bytes).
type memberSink = archive.Sink

// readArchive is archive.Read: only the three member names, in order, regular files within their caps.
func readArchive(r io.Reader, sink memberSink) error { return archive.Read(r, sink) }

// hashingReader sums what passes through.
type hashingReader struct {
	r io.Reader
	h hash.Hash
	n int64
}

func (h *hashingReader) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	h.h.Write(p[:n])
	h.n += int64(n)
	return n, err
}

// fileSHA256 is the SHA-256 and size of a file.
func fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path) //nolint:gosec // path built from a validated hex id inside the state dir
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	hr := &hashingReader{r: f, h: sha256.New()}
	if _, err := io.Copy(io.Discard, hr); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hr.h.Sum(nil)), hr.n, nil
}
