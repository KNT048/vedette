package ops

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

// A backup is one tar.gz (Go standard library) with fixed member names:
//
//	manifest.json   small JSON, see Manifest
//	vedette.db      core's SQLite database (consistent copy from the SQLite backup API)
//	vedette.key     core's secrets master key, only when include_secrets
//
// The archive is untrusted when read back, even though the host wrote it: a restore must never
// extract anything but these members, with size caps, no matter what the file holds.
const (
	memberManifest = "manifest.json"
	memberDB       = "vedette.db"
	memberKey      = "vedette.key"

	manifestVersion = 1

	maxManifestBytes = 64 << 10
	maxKeyBytes      = 4 << 10
	maxDBBytes       = 64 << 30 // 64 GiB of database inside an archive; the appliance is far below it
)

// Manifest is the small description inside every backup.
type Manifest struct {
	Version         int    `json:"version"`
	DBSchema        string `json:"db_schema"`
	CreatedAt       string `json:"created_at"`
	IncludesSecrets bool   `json:"includes_secrets"`
}

var schemaPairRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}=[0-9]{1,9}$`)

// validSchema accepts "" or up to 64 comma-separated module=version pairs.
func validSchema(s string) bool {
	if s == "" {
		return true
	}
	pairs := strings.Split(s, ",")
	if len(pairs) > 64 {
		return false
	}
	for _, p := range pairs {
		if !schemaPairRE.MatchString(p) {
			return false
		}
	}
	return true
}

// parseManifest validates the manifest text. It is a pure function over untrusted bytes.
func parseManifest(b []byte) (Manifest, error) {
	var m Manifest
	if len(b) > maxManifestBytes {
		return m, errors.New("manifest is too large")
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, errors.New("manifest is not valid")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return m, errors.New("manifest has trailing data")
	}
	if m.Version != manifestVersion {
		return m, fmt.Errorf("manifest version %d is not supported", m.Version)
	}
	if !validSchema(m.DBSchema) {
		return m, errors.New("manifest db_schema is not valid")
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		return m, errors.New("manifest created_at is not valid")
	}
	return m, nil
}

// archiveFile is one member to write.
type archiveFile struct {
	Name string
	Path string // file to copy; empty when Data is used
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
	if f.Path == "" {
		hdr.Size = int64(len(f.Data))
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("ops: write %s: %w", f.Name, err)
		}
		if _, err := tw.Write(f.Data); err != nil {
			return fmt.Errorf("ops: write %s: %w", f.Name, err)
		}
		return nil
	}
	in, err := os.Open(f.Path)
	if err != nil {
		return fmt.Errorf("ops: open %s: %w", f.Name, err)
	}
	defer func() { _ = in.Close() }()
	st, err := in.Stat()
	if err != nil {
		return fmt.Errorf("ops: stat %s: %w", f.Name, err)
	}
	hdr.Size = st.Size()
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("ops: write %s: %w", f.Name, err)
	}
	if n, err := io.Copy(tw, io.LimitReader(in, hdr.Size)); err != nil || n != hdr.Size {
		return fmt.Errorf("ops: copy %s: %w", f.Name, errors.Join(err, io.ErrUnexpectedEOF))
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
var ErrArchive = errors.New("ops: not a valid backup archive")

// memberSink receives the content of one accepted member (at most size bytes).
type memberSink func(name string, r io.Reader, size int64) error

// memberLimit is the size cap of a member, 0 for a name that is not allowed.
func memberLimit(name string) int64 {
	switch name {
	case memberManifest:
		return maxManifestBytes
	case memberKey:
		return maxKeyBytes
	case memberDB:
		return maxDBBytes
	}
	return 0
}

// readArchive walks the archive and hands each accepted member to sink. It accepts only the three
// member names, once each, as regular files, in the order manifest, db, key (the key is
// optional), with the declared size within the cap, and stops at the declared size however much
// the compressed stream would expand to (no zip bombs). Absolute paths, "..", links, devices,
// directories, PAX records and anything else are rejected before any byte of that member is read.
// It never writes anywhere itself: the sink decides, and the names it sees are constants.
func readArchive(r io.Reader, sink memberSink) error {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("%w: not gzip", ErrArchive)
	}
	defer func() { _ = zr.Close() }()
	zr.Multistream(false)
	tr := tar.NewReader(zr)
	want := []string{memberManifest, memberDB, memberKey}
	next := 0
	first := true
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: unreadable tar", ErrArchive)
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("%w: a member is not a regular file", ErrArchive)
		}
		limit := memberLimit(hdr.Name)
		if limit == 0 {
			return fmt.Errorf("%w: unexpected member", ErrArchive)
		}
		if first && hdr.Name != memberManifest {
			return fmt.Errorf("%w: the manifest must come first", ErrArchive)
		}
		first = false
		for next < len(want) && want[next] != hdr.Name {
			next++ // the key may be absent
		}
		if next == len(want) {
			return fmt.Errorf("%w: members out of order or repeated", ErrArchive)
		}
		next++
		if hdr.Size < 0 || hdr.Size > limit {
			return fmt.Errorf("%w: a member is too large", ErrArchive)
		}
		if len(hdr.PAXRecords) > 0 {
			return fmt.Errorf("%w: extended records are not allowed", ErrArchive)
		}
		if err := sink(hdr.Name, io.LimitReader(tr, hdr.Size), hdr.Size); err != nil {
			return err
		}
	}
	if next == 0 {
		return fmt.Errorf("%w: empty", ErrArchive)
	}
	return nil
}

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
