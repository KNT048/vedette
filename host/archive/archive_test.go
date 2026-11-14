package archive_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"testing"

	"github.com/knt048/vedette/host/archive"
)

func backup(t *testing.T) []byte {
	t.Helper()
	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	tw := tar.NewWriter(zw)
	for _, m := range []struct{ name, data string }{
		{archive.MemberManifest, `{"version":1,"db_schema":"core=1","created_at":"2026-11-01T08:30:00Z","includes_secrets":false}`},
		{archive.MemberDB, "SQLite format 3\x00 and more"},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o600, Size: int64(len(m.data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(m.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

func drain(string, io.Reader, int64) error { return nil }

// A whole archive reads; one whose gzip trailer (CRC-32) is damaged is refused, though every member read fine (D-518, L4).
func TestReadChecksTheGzipTrailer(t *testing.T) {
	t.Parallel()
	good := backup(t)
	if err := archive.Read(bytes.NewReader(good), drain); err != nil {
		t.Fatalf("good archive: %v", err)
	}
	bad := bytes.Clone(good)
	bad[len(bad)-8] ^= 0xff // first byte of the CRC-32
	if err := archive.Read(bytes.NewReader(bad), drain); !errors.Is(err, archive.ErrArchive) {
		t.Fatalf("damaged trailer = %v, want ErrArchive", err)
	}
}

// errCut stands for the request body's size cap: it must stay visible through ErrArchive (L3), so the caller answers 413.
var errCut = errors.New("cut by the cap")

type cutReader struct {
	r io.Reader
	n int
}

func (c *cutReader) Read(p []byte) (int, error) {
	if c.n <= 0 {
		return 0, errCut
	}
	if len(p) > c.n {
		p = p[:c.n]
	}
	n, err := c.r.Read(p)
	c.n -= n
	return n, err
}

func TestReadKeepsTheCauseOfAReadError(t *testing.T) {
	t.Parallel()
	good := backup(t)
	for _, at := range []int{4, 30} { // inside the gzip header, inside the tar stream
		err := archive.Read(&cutReader{r: bytes.NewReader(good), n: at}, drain)
		if !errors.Is(err, archive.ErrArchive) || !errors.Is(err, errCut) {
			t.Errorf("cut at %d = %v, want ErrArchive and the cause", at, err)
		}
	}
}
