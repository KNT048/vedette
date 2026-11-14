package core

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
)

// An upload whose database needs more than half the free space is refused before a byte of it is written (409 low_disk), and
// nothing stays in snapshots/.
func TestStageUploadRefusesALowDisk(t *testing.T) {
	t.Parallel()
	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	tw := tar.NewWriter(zw)
	for _, m := range []struct{ name, data string }{
		{"manifest.json", `{"version":1,"db_schema":"core=1","created_at":"2026-11-01T08:30:00Z","includes_secrets":false}`},
		{"vedette.db", "SQLite format 3\x00 and a little more"},
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
	s := &snapshotter{dir: t.TempDir(), now: time.Now, free: func(string) (uint64, error) { return 40, nil }}
	_, err := s.stageUpload(t.Context(), bytes.NewReader(raw.Bytes()))
	if ae, ok := apierr.As(err); !ok || ae.Status != 409 || ae.Code != CodeLowDisk {
		t.Fatalf("stage = %v, want 409 low_disk", err)
	}
	if ents, _ := os.ReadDir(s.dir); len(ents) != 0 {
		t.Fatalf("left %d entries", len(ents))
	}
}

// capped stands for the request body's size cap (http.MaxBytesReader) hit while the gzip or tar headers are read.
type capped struct{}

func (capped) Read([]byte) (int, error) { return 0, &http.MaxBytesError{Limit: maxUploadBytes} }

// A body cut by the size cap is 413, not "not a backup", wherever the cut falls (L3).
func TestStageUploadOverTheCapIs413(t *testing.T) {
	t.Parallel()
	s := &snapshotter{dir: t.TempDir(), now: time.Now, free: func(string) (uint64, error) { return 1 << 40, nil }}
	_, err := s.stageUpload(t.Context(), capped{})
	if ae, ok := apierr.As(err); !ok || ae.Status != 413 {
		t.Fatalf("stage = %v, want 413", err)
	}
}
